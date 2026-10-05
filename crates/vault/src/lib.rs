//! Password-protected vault keystore: Argon2id + AES-256-GCM.
//!
//! # What this protects, and against whom
//!
//! A vault holds secret bytes - a node operator's signing keys, a wallet's
//! SPHINCS+ spend keys - encrypted under a user password. The threat model is
//! a *stolen file*: an attacker who copies the vault but does not have the
//! password must not be able to read the keys, and must not be able to *forge*
//! a vault that the owner will happily decrypt.
//!
//! Two primitives, each doing one job:
//!
//! * **Argon2id** (RFC 9106) turns the password into a 256-bit key. It is
//!   memory-hard, which is what makes an offline brute-force attack cost
//!   ~64 MiB *per guess* rather than being GPU-cheap. This is the current
//!   OWASP / Password-Hashing-Cheatsheet recommendation for exactly this
//!   shape of problem (local vault, attacker holds the ciphertext).
//! * **AES-256-GCM** (AEAD) encrypts the payload under that key. The GCM tag
//!   gives integrity: a tampered vault fails to decrypt rather than yielding
//!   garbage keys. We never see a "successfully decrypted" wrong key.
//!
//! # Why a salt, and why it is stored
//!
//! Each vault gets a fresh 16-byte random salt, stored in the clear in the
//! vault header. The salt is not a secret - its job is to make every vault's
//! derived key different, so one precomputed rainbow table cannot cover many
//! vaults, and so re-encrypting the same key under the same password
//! produces a different ciphertext.
//!
//! # Nonce discipline
//!
//! GCM's safety breaks if a (key, nonce) pair is ever reused. [`seal_with_rng`]
//! draws a fresh 12-byte nonce from the caller's CSPRNG on every call, and the
//! nonce is stored with the ciphertext. Because the key is itself derived
//! per-vault from a random salt, the (key, nonce) space is never reused across
//! vaults, and within one vault each seal is a fresh random nonce. There is
//! deliberately no incremental-encryption API where a caller could reuse a
//! nonce by accident.
//!
//! # Why the RNG is a parameter
//!
//! The browser cannot hand this crate an OS CSPRNG handle the way a native
//! process can: wasm gets its entropy from `crypto.getRandomValues` through JS
//! glue. So the crate is generic over the bit source and the *caller* decides
//! where entropy comes from - `SysRng` in the node, the `WebCrypto` bridge in
//! the wallet. One format, one implementation, both environments.
//!
//! # Key material lifetime
//!
//! The derived key is a [`Zeroizing<Vec<u8>>`]: it is wiped on drop. The
//! plaintext payload is likewise zeroized after use. A wrong password never
//! leaves a partially-derived key lying around - the Argon2 output buffer is
//! zeroized before the AEAD error propagates.
//!
//! # What this is NOT
//!
//! This is not a hardware security module. If the host is compromised while
//! the vault is *unlocked* (the derived key is in RAM), the keys are exposed.
//! The vault protects the at-rest file, not a live process.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::TryRng;
use zeroize::Zeroizing;

/// Length of the AES-256 key derived from the password.
const KEY_LEN: usize = 32;
/// Length of the Argon2 salt.
pub const SALT_LEN: usize = 16;
/// Length of the AES-GCM nonce.
pub const NONCE_LEN: usize = 12;

/// Argon2 `m_cost`: memory in KiB. 65536 KiB = 64 MiB.
///
/// Chosen for a *human waiting on a vault unlock*: latency matters less there
/// than in a login server, so we can spend more per unlock to make offline
/// cracking more expensive. `p_cost = 1` keeps the memory cost honest for an
/// attacker: raising parallelism would speed up the honest unlock without
/// raising the per-guess memory floor an attacker must pay.
pub const KDF_M_COST: u32 = 65_536;
/// Argon2 `t_cost`: passes over the memory.
pub const KDF_T_COST: u32 = 3;
/// Argon2 `p_cost`: parallelism lanes.
pub const KDF_P_COST: u32 = 1;

/// The Argon2id parameter set, validated at COMPILE time.
///
/// `Params::new` is a `const fn` that rejects `m_cost` below `MIN_M_COST`, a
/// zero `t_cost`, a zero `p_cost` and an output length over `u32::MAX`.
/// Evaluating it in a const item makes a bad constant a BUILD error instead of
/// a runtime panic on the unlock path - which is the point, because this KDF
/// runs in front of a user waiting for their vault, and because the parameters
/// cannot drift into an invalid state without the crate failing to compile.
/// There is therefore no `expect` to justify and no failure branch to test.
const KDF_PARAMS: Params = match Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(KEY_LEN)) {
    Ok(params) => params,
    Err(_) => {
        panic!("Argon2id constants must satisfy Params::new; see KDF_M_COST/KDF_T_COST/KDF_P_COST")
    }
};

/// The shared Argon2id context.
///
/// Built once and cached because constructing it allocates the scratch
/// buffers. The parameters are already checked by `KDF_PARAMS`, so this cannot
/// fail.
fn kdf() -> &'static Argon2<'static> {
    static KDF: std::sync::OnceLock<Argon2<'static>> = std::sync::OnceLock::new();
    KDF.get_or_init(|| Argon2::new(Algorithm::Argon2id, Version::V0x13, KDF_PARAMS.clone()))
}

/// Errors from a vault operation.
///
/// The variants distinguish *why* a decrypt failed, which matters for the
/// caller: a wrong password is a user error, a corrupt blob is a storage
/// problem, and a version mismatch means the vault was written by an
/// incompatible build.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The password did not unlock the vault (AEAD tag mismatch).
    ///
    /// This is the *only* signal a wrong password produces. We do not
    /// distinguish "wrong password" from "corrupt ciphertext" at the API level
    /// beyond the tag check, because doing so would leak whether a given
    /// salt/nonce pair is "close" to valid.
    #[error("incorrect password or corrupt vault (AEAD tag mismatch)")]
    WrongPassword,
    /// The vault is too short to contain a header.
    #[error("vault truncated: {0} bytes, expected at least {1}")]
    Truncated(usize, usize),
    /// The vault's format version is not one this crate understands.
    #[error("unsupported vault format version {0} (this crate writes version {1})")]
    UnsupportedVersion(u8, u8),
    /// The KDF failed.
    ///
    /// The parameter set itself is validated at compile time by `KDF_PARAMS`,
    /// so this variant carries only `hash_password_into` failures - an
    /// allocation error under memory pressure, chiefly. Surfaced rather than
    /// swallowed because reporting it as a wrong password would send the user
    /// to the wrong remedy.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// The caller's CSPRNG failed to deliver entropy.
    ///
    /// Distinct from every other variant because it says "this entropy source
    /// cannot make random bytes right now", which a caller needs to see rather
    /// than have retried as a password problem.
    #[error("entropy source failed: {0}")]
    Entropy(String),
    /// The payload exceeded the configured size cap.
    #[error("payload too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
    /// A vault cannot be serialized because a field does not fit its length
    /// prefix. See [`SealedVault::to_bytes`].
    #[error("vault cannot be encoded: {0}")]
    Unencodable(&'static str),
}

/// The on-disk vault format version this crate writes.
///
/// Bumped only on a breaking format change. A reader that sees a higher
/// version refuses rather than guessing, so a future format cannot be
/// silently misread by an old build.
pub const VAULT_VERSION: u8 = 1;

/// A sealed vault: the encrypted payload plus everything needed to attempt a
/// decrypt (salt, nonce, version).
///
/// This is a value type - it is what gets serialized to disk (or to
/// `chrome.storage.local` in the wallet). It carries no key material; the key
/// is derived on demand from the password.
#[derive(Clone, Debug)]
pub struct SealedVault {
    /// Format version.
    pub version: u8,
    /// Argon2 salt (random, stored in the clear).
    pub salt: Vec<u8>,
    /// AES-GCM nonce (random, stored with the ciphertext).
    pub nonce: Vec<u8>,
    /// The AES-GCM ciphertext (includes the 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
}

/// Draw `n` bytes from a caller-supplied CSPRNG.
///
/// # Errors
///
/// [`VaultError::Entropy`] if the CSPRNG call fails. This is not a theoretical
/// branch: every backend wraps a syscall or a host call, and those fail.
/// Returning is the only safe response, because the alternative is a salt or
/// nonce drawn from a buffer that was never filled - a vault whose secrecy
/// rests on bytes that may be all zero, indistinguishable from a healthy
/// vault. Panicking is not better: this is a library, and a caller that wants
/// to abort can do so on the `Err`.
fn rng_bytes<R: TryRng + ?Sized>(rng: &mut R, n: usize) -> Result<Vec<u8>, VaultError> {
    let mut buf = vec![0u8; n];
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| VaultError::Entropy(e.to_string()))?;
    Ok(buf)
}

/// Derive the AES-256 key from a password and salt using Argon2id.
///
/// Returns the key wrapped in [`Zeroizing`] so it is wiped when dropped.
///
/// # Errors
///
/// Returns [`VaultError::Kdf`] if the Argon2 parameters are rejected.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut key = vec![0u8; KEY_LEN];
    kdf()
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(Zeroizing::new(key))
}

/// Encrypt `plaintext` under `password` into a [`SealedVault`], drawing salt
/// and nonce from `rng`.
///
/// Fresh salt and nonce are drawn on every call, so sealing the same payload
/// twice produces two unrelated vaults.
///
/// # Errors
///
/// Returns [`VaultError::TooLarge`] if `plaintext` exceeds `max_payload`,
/// [`VaultError::Entropy`] if the CSPRNG fails, or [`VaultError::Kdf`] if the
/// KDF fails.
pub fn seal_with_rng<R: TryRng + ?Sized>(
    password: &[u8],
    plaintext: &[u8],
    max_payload: usize,
    rng: &mut R,
) -> Result<SealedVault, VaultError> {
    if plaintext.len() > max_payload {
        return Err(VaultError::TooLarge(plaintext.len(), max_payload));
    }
    let salt = rng_bytes(rng, SALT_LEN)?;
    let nonce_bytes = rng_bytes(rng, NONCE_LEN)?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Kdf(format!("cipher init: {e}")))?;
    let nonce = Nonce::try_from(&nonce_bytes[..])
        .map_err(|e| VaultError::Kdf(format!("bad nonce length: {e}")))?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| VaultError::Kdf(format!("encrypt: {e}")))?;
    Ok(SealedVault {
        version: VAULT_VERSION,
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

impl SealedVault {
    /// Decrypt this vault under `password`, returning the plaintext.
    ///
    /// The plaintext is wrapped in [`Zeroizing`]: the caller should drop it
    /// promptly and not copy it into long-lived structures.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::WrongPassword`] on a tag mismatch (wrong password
    /// or tampered ciphertext), [`VaultError::Truncated`] if a field is too
    /// short, or [`VaultError::UnsupportedVersion`] if the version is not
    /// [`VAULT_VERSION`].
    pub fn open(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if self.version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(self.version, VAULT_VERSION));
        }
        if self.salt.len() < SALT_LEN {
            return Err(VaultError::Truncated(self.salt.len(), SALT_LEN));
        }
        if self.nonce.len() < NONCE_LEN {
            return Err(VaultError::Truncated(self.nonce.len(), NONCE_LEN));
        }
        let key = derive_key(password, &self.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VaultError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::try_from(&self.nonce[..])
            .map_err(|e| VaultError::Kdf(format!("bad nonce length: {e}")))?;
        cipher
            .decrypt(&nonce, self.ciphertext.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| VaultError::WrongPassword)
    }

    /// Serialize the vault to a self-describing byte string.
    ///
    /// Layout: `version(1) || salt_len(1) || salt || nonce_len(1) || nonce ||
    /// ct_len(4, LE) || ciphertext`. Length-prefixed so a truncated blob is
    /// detected rather than silently misparsed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unencodable`] if the salt or nonce does not fit a `u8`
    /// length prefix, or the ciphertext exceeds `u32::MAX`. Unreachable through
    /// [`seal_with_rng`], which always writes the fixed 16- and 12-byte sizes.
    ///
    /// Returned rather than panicked because the fields are public, so a caller
    /// can build a `SealedVault` by hand - for instance by parsing a hostile
    /// blob straight into the struct. Truncating a length prefix silently would
    /// produce a vault that parses back as something else; panicking would let
    /// a crafted vault take down whatever serialized it. Rejecting is the only
    /// outcome that is neither.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let salt_len = u8::try_from(self.salt.len())
            .map_err(|_| VaultError::Unencodable("salt length exceeds u8 prefix"))?;
        let nonce_len = u8::try_from(self.nonce.len())
            .map_err(|_| VaultError::Unencodable("nonce length exceeds u8 prefix"))?;
        let ct_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| VaultError::Unencodable("ciphertext exceeds u32 length"))?;
        let mut out = Vec::with_capacity(
            1 + 1 + self.salt.len() + 1 + self.nonce.len() + 4 + self.ciphertext.len(),
        );
        out.push(self.version);
        out.push(salt_len);
        out.extend_from_slice(&self.salt);
        out.push(nonce_len);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parse a vault from [`Self::to_bytes`] output.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Truncated`] if the byte string is shorter than
    /// the header claims.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        // Minimum: version + salt_len + salt(16) + nonce_len + nonce(12) + ct_len(4).
        const MIN: usize = 1 + 1 + SALT_LEN + 1 + NONCE_LEN + 4;
        if bytes.len() < MIN {
            return Err(VaultError::Truncated(bytes.len(), MIN));
        }
        let version = bytes[0];
        let salt_len = bytes[1] as usize;
        let mut pos = 2;
        let salt = read_slice(bytes, &mut pos, salt_len)?;
        let nonce_len = bytes[pos] as usize;
        pos += 1;
        let nonce = read_slice(bytes, &mut pos, nonce_len)?;
        let ct_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;
        let ciphertext = read_slice(bytes, &mut pos, ct_len)?;
        Ok(Self {
            version,
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Read `len` bytes from `bytes` at `*pos`, advancing `*pos`.
fn read_slice(bytes: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, VaultError> {
    let end = *pos + len;
    if end > bytes.len() {
        return Err(VaultError::Truncated(bytes.len(), end));
    }
    let out = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn pw() -> Vec<u8> {
        b"correct horse battery staple".to_vec()
    }

    fn rng(seed: u64) -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(seed)
    }

    /// Seal with a deterministic RNG. The seed is a parameter so a test that
    /// seals twice can give each call its own stream - two seals from the same
    /// seed would (correctly!) produce identical salt/nonce, which is exactly
    /// the reuse the production API is designed to prevent with `SysRng`.
    fn seal_s(
        seed: u64,
        password: &[u8],
        plaintext: &[u8],
        cap: usize,
    ) -> Result<SealedVault, VaultError> {
        seal_with_rng(password, plaintext, cap, &mut rng(seed))
    }

    fn seal(password: &[u8], plaintext: &[u8], cap: usize) -> Result<SealedVault, VaultError> {
        seal_s(0x5eed, password, plaintext, cap)
    }

    #[test]
    fn seal_open_round_trips_the_plaintext() {
        let secret = b"0xDEADBEEF spending key".to_vec();
        let vault = seal(&pw(), &secret, 4096).expect("seal");
        let opened = vault.open(&pw()).expect("open");
        assert_eq!(&opened[..], &secret[..]);
    }

    #[test]
    fn a_wrong_password_fails_to_open() {
        let vault = seal(&pw(), b"payload", 4096).expect("seal");
        let err = vault
            .open(b"wrong password")
            .expect_err("wrong password must not open");
        assert_eq!(err, VaultError::WrongPassword);
    }

    #[test]
    fn sealing_twice_produces_different_ciphertext() {
        let a = seal_s(1, &pw(), b"same payload", 4096).expect("seal a");
        let b = seal_s(2, &pw(), b"same payload", 4096).expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext, "fresh nonce/salt each seal");
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn tampering_with_the_ciphertext_is_rejected() {
        let mut vault = seal(&pw(), b"payload", 4096).expect("seal");
        // Flip one bit in the ciphertext body.
        let last = vault.ciphertext.len() - 1;
        vault.ciphertext[last] ^= 0x01;
        assert_eq!(vault.open(&pw()).err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn tampering_with_the_salt_is_rejected() {
        let mut vault = seal(&pw(), b"payload", 4096).expect("seal");
        vault.salt[0] ^= 0x80;
        // A different salt derives a different key -> tag mismatch.
        assert_eq!(vault.open(&pw()).err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn bytes_round_trip_through_to_bytes_from_bytes() {
        let vault = seal(&pw(), b"payload", 4096).expect("seal");
        let bytes = vault.to_bytes().expect("encode");
        let back = SealedVault::from_bytes(&bytes).expect("parse");
        assert_eq!(back.version, vault.version);
        assert_eq!(back.salt, vault.salt);
        assert_eq!(back.nonce, vault.nonce);
        assert_eq!(back.ciphertext, vault.ciphertext);
        // And it still opens.
        assert_eq!(&back.open(&pw()).expect("open")[..], b"payload");
    }

    #[test]
    fn a_truncated_vault_is_rejected_not_misparsed() {
        let bytes = seal(&pw(), b"payload", 4096)
            .expect("seal")
            .to_bytes()
            .expect("encode");
        for cut in 0..bytes.len() {
            let r = SealedVault::from_bytes(&bytes[..cut]);
            assert!(
                matches!(r, Err(VaultError::Truncated(..))),
                "cut {cut} should be truncated, got {r:?}"
            );
        }
    }

    /// The `to_bytes` limits that replaced the node keystore's three `expect`
    /// calls. `SealedVault` fields are public, so these shapes are
    /// constructible by anyone who parses a blob into the struct. Each must be
    /// `Err`, not a panic.
    #[test]
    fn an_oversized_field_is_refused_not_panicked() {
        let good = seal(&pw(), b"payload", 4096).expect("seal");

        // Salt too long for a u8 length prefix.
        let mut big_salt = good.clone();
        big_salt.salt = vec![0u8; 256];
        assert!(matches!(
            big_salt.to_bytes(),
            Err(VaultError::Unencodable(_))
        ));

        // Nonce too long for a u8 length prefix.
        let mut big_nonce = good.clone();
        big_nonce.nonce = vec![0u8; 256];
        assert!(matches!(
            big_nonce.to_bytes(),
            Err(VaultError::Unencodable(_))
        ));

        // And a valid vault still encodes, so the checks did not become
        // over-broad.
        assert!(good.to_bytes().is_ok());
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let mut vault = seal(&pw(), b"payload", 4096).expect("seal");
        vault.version = VAULT_VERSION + 1;
        assert_eq!(
            vault.open(&pw()).err(),
            Some(VaultError::UnsupportedVersion(
                VAULT_VERSION + 1,
                VAULT_VERSION
            ))
        );
    }

    #[test]
    fn an_oversized_payload_is_rejected_before_encryption() {
        let big = vec![0u8; 8192];
        assert_eq!(
            seal(&pw(), &big, 4096).err(),
            Some(VaultError::TooLarge(8192, 4096))
        );
    }

    #[test]
    fn an_empty_password_still_works_but_is_a_different_key() {
        // Empty password is a valid (if weak) password; the point is it is a
        // *different* key than any non-empty one, not that it is accepted.
        let vault = seal(b"", b"payload", 4096).expect("seal");
        assert_eq!(&vault.open(b"").expect("open")[..], b"payload");
        assert_eq!(vault.open(b" ").err(), Some(VaultError::WrongPassword));
    }
}
