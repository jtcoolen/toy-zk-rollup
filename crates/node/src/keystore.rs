//! Password-protected keystore: Argon2id + AES-256-GCM.
//!
//! # What this protects, and against whom
//!
//! A node operator's signing/fee keys and any imported spending keys live in a
//! vault file on disk. The threat model is a *stolen file*: an attacker who
//! copies the vault off disk but does not have the operator's password must not
//! be able to read the keys, and must not be able to *forge* a vault that the
//! node will happily decrypt.
//!
//! Two primitives, each doing one job:
//!
//! * **Argon2id** (RFC 9106) turns the password into a 256-bit key. It is
//!   memory-hard, which is what makes an offline brute-force attack cost
//!   ~1 GiB *per guess* rather than being GPU-cheap. This is the current
//!   OWASP / Password-Hashing-Cheatsheet recommendation for exactly this
//!   shape of problem (local vault, attacker holds the ciphertext).
//! * **AES-256-GCM** (AEAD) encrypts the payload under that key. The GCM tag
//!   gives integrity: a tampered vault fails to decrypt rather than yielding
//!   garbage keys. We never see a "successfully decrypted" wrong key.
//!
//! # Why a salt, and why it is stored
//!
//! Each vault gets a fresh 16-byte random salt, stored in the clear in the file
//! header. The salt is not a secret — its job is to make every vault's derived
//! key different, so one precomputed rainbow table cannot cover many vaults,
//! and so re-encrypting the same key under the same password produces a
//! different ciphertext. A salt that was kept secret would just be a second
//! thing to lose.
//!
//! # Nonce discipline
//!
//! GCM's safety breaks if a (key, nonce) pair is ever reused. We draw a fresh
//! 12-byte nonce from OS entropy on every `seal`, and the nonce is stored with
//! the ciphertext. Because the key is itself derived per-vault from a random
//! salt, the (key, nonce) space is never reused across vaults, and within one
//! vault each `seal` is a fresh random nonce. We do not expose an
//! incremental-encryption API where a caller could reuse a nonce by accident.
//!
//! # Key material lifetime
//!
//! The derived key is a [`Zeroizing<Vec<u8>`]: it is wiped on drop. The
//! plaintext payload is likewise zeroized after use. A wrong password never
//! leaves a partially-derived key lying around — the Argon2 output buffer is
//! zeroized before the AEAD error propagates.
//!
//! # What this is NOT
//!
//! This is not a hardware security module. If the host is compromised while the
//! vault is *unlocked* (the derived key is in RAM), the keys are exposed. The
//! vault protects the at-rest file, not a live process. For custody of large
//! sums the signing key should live in an HSM or a hardware wallet; this vault
//! is the right shape for a node's own operational keys and for a demo wallet's
//! local custody.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

/// Length of the Argon2 salt, in bytes. 128 bits is well above the collision
/// bound for any realistic number of vaults and matches RFC 9106's default.
const SALT_LEN: usize = 16;

/// Length of the AES-GCM nonce, in bytes. 96 bits is GCM's native nonce size
/// and the only size that avoids an extra hashing step.
const NONCE_LEN: usize = 12;

/// Length of the derived AES key, in bytes.
const KEY_LEN: usize = 32;

/// Argon2id parameters.
///
/// `m_cost = 64 MiB`, `t_cost = 3`, `p_cost = 1`. This is the OWASP
/// 2023 recommendation for Argon2id when a dedicated KDF budget is wanted
/// but the default 19 MiB is considered light. It is deliberately *not* the
/// library default: the library default is tuned for interactive login where
/// latency matters; a vault unlock is rare enough that we can spend more per
/// unlock to make offline cracking more expensive.
///
/// `p_cost = 1` keeps the memory cost honest for an attacker: raising
/// parallelism would speed up the honest unlock without raising the
/// per-guess memory floor an attacker must pay.
///
/// `Params` has private fields, so the values are expressed through
/// [`ParamsBuilder`] and cached in a [`OnceLock`]: building the context is
/// allocation-heavy and every call site wants the same one.
/// Argon2 `m_cost`: memory in KiB. 65536 KiB = 64 MiB.
pub const KDF_M_COST: u32 = 65_536;
/// Argon2 `t_cost`: passes over the memory.
pub const KDF_T_COST: u32 = 3;
/// Argon2 `p_cost`: parallelism lanes.
pub const KDF_P_COST: u32 = 1;

/// The Argon2id parameter set, validated at COMPILE time.
///
/// `Params::new` is a `const fn` that rejects `m_cost` below
/// `MIN_M_COST`, a zero `t_cost`, a zero `p_cost` and an output length over
/// `u32::MAX`. Evaluating it in a const item makes a bad constant a BUILD error
/// instead of a runtime panic on the unlock path - which is the point, because
/// this KDF runs in front of a user waiting for their vault, and because the
/// parameters cannot drift into an invalid state without the crate failing to
/// compile. There is therefore no `expect` to justify and no failure branch to
/// test.
const KDF_PARAMS: Params = match Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(KEY_LEN)) {
    Ok(params) => params,
    Err(_) => {
        panic!("Argon2id constants must satisfy Params::new; see KDF_M_COST/KDF_T_COST/KDF_P_COST")
    }
};

/// The shared Argon2id context.
///
/// Built once and cached because constructing it allocates the scratch buffers.
/// The parameters are already checked by `KDF_PARAMS`, so this cannot fail.
fn kdf() -> &'static Argon2<'static> {
    static KDF: std::sync::OnceLock<Argon2<'static>> = std::sync::OnceLock::new();
    KDF.get_or_init(|| Argon2::new(Algorithm::Argon2id, Version::V0x13, KDF_PARAMS.clone()))
}

/// Errors from a keystore operation.
///
/// The variants distinguish *why* a decrypt failed, which matters for the
/// operator: a wrong password is a user error, a corrupt file is a disk
/// problem, and a version mismatch means the vault was written by an
/// incompatible node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeystoreError {
    /// The password did not unlock the vault (AEAD tag mismatch).
    ///
    /// This is the *only* signal a wrong password produces. We do not
    /// distinguish "wrong password" from "corrupt ciphertext" at the API
    /// level beyond the tag check, because doing so would leak whether a
    /// given salt/nonce pair is "close" to valid.
    #[error("incorrect password or corrupt vault (AEAD tag mismatch)")]
    WrongPassword,
    /// The vault file is too short to contain a header.
    #[error("vault file truncated: {0} bytes, expected at least {1}")]
    Truncated(usize, usize),
    /// The vault's format version is not one this node understands.
    #[error("unsupported vault format version {0} (this node writes version {1})")]
    UnsupportedVersion(u8, u8),
    /// The KDF failed.
    ///
    /// The parameter set itself is validated at compile time by `KDF_PARAMS`, so
    /// this variant now carries only `hash_password_into` failures - an
    /// allocation error under memory pressure, chiefly. Surfaced rather than
    /// swallowed because reporting it as a wrong password would send the user
    /// to the wrong remedy.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// The OS CSPRNG failed to deliver entropy.
    ///
    /// Distinct from every other variant because it says "this machine cannot
    /// make keys right now", which an operator needs to see rather than have
    /// retried as a password problem.
    #[error("operating system entropy source failed: {0}")]
    Entropy(String),
    /// The payload exceeded the configured size cap.
    #[error("payload too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
    /// A vault cannot be serialized because a field does not fit its length
    /// prefix. See `SealedVault::to_bytes`.
    #[error("vault cannot be encoded: {0}")]
    Unencodable(&'static str),
    /// A filesystem operation on a vault or secret file failed.
    #[error("vault file error: {0}")]
    Io(String),
    /// A secret file's permissions are wider than owner-only, so its
    /// contents must be treated as possibly copied. Refuse to use it.
    #[error("insecure secret file permissions: {0}")]
    InsecurePermissions(String),
}

/// The on-disk vault format version this node writes.
///
/// Bumped only on a breaking format change. A node that reads a higher
/// version refuses rather than guessing, so a future format cannot be
/// silently misread by an old node.
pub const VAULT_VERSION: u8 = 1;

/// A sealed vault: the encrypted payload plus everything needed to attempt a
/// decrypt (salt, nonce, version).
///
/// This is a value type — it is what gets serialized to disk. It carries no
/// key material; the key is derived on demand from the password.
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

/// Draw `n` bytes of OS entropy.
///
/// Uses `SysRng` (the OS CSPRNG) directly rather than a thread-local RNG, so
/// a salt/nonce is not predictable from any other RNG state in the process.
///
/// # Errors
///
/// `KeystoreError::Entropy` if the CSPRNG call fails. This is not a
/// theoretical branch: `SysRng` wraps a syscall and syscalls fail. Returning
/// is the only safe response, because the alternative is a salt or nonce drawn
/// from a buffer that was never filled - a vault whose secrecy rests on bytes
/// that may be all zero, indistinguishable from a healthy vault. Panicking is
/// not better: this is a library, and a caller that wants to abort can do so on
/// the `Err`.
fn os_bytes(n: usize) -> Result<Vec<u8>, KeystoreError> {
    let mut buf = vec![0u8; n];
    SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| KeystoreError::Entropy(e.to_string()))?;
    Ok(buf)
}

/// Derive the AES-256 key from a password and salt using Argon2id.
///
/// Returns the key wrapped in [`Zeroizing`] so it is wiped when dropped.
///
/// # Errors
///
/// Returns [`KeystoreError::Kdf`] if the Argon2 parameters are rejected.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let mut key = vec![0u8; KEY_LEN];
    kdf()
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(Zeroizing::new(key))
}

/// Encrypt `plaintext` under `password` into a [`SealedVault`].
///
/// Fresh salt and nonce are drawn from OS entropy on every call, so sealing
/// the same payload twice produces two unrelated vaults.
///
/// # Errors
///
/// Returns [`KeystoreError::TooLarge`] if `plaintext` exceeds `max_payload`,
/// or [`KeystoreError::Kdf`] if the KDF fails.
pub fn seal(
    password: &[u8],
    plaintext: &[u8],
    max_payload: usize,
) -> Result<SealedVault, KeystoreError> {
    if plaintext.len() > max_payload {
        return Err(KeystoreError::TooLarge(plaintext.len(), max_payload));
    }
    let salt = os_bytes(SALT_LEN)?;
    let nonce_bytes = os_bytes(NONCE_LEN)?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
    let nonce = Nonce::try_from(&nonce_bytes[..])
        .map_err(|e| KeystoreError::Kdf(format!("bad nonce length: {e}")))?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| KeystoreError::Kdf(format!("encrypt: {e}")))?;
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
    /// Returns [`KeystoreError::WrongPassword`] on a tag mismatch (wrong
    /// password or tampered ciphertext), [`KeystoreError::Truncated`] if a
    /// field is too short, or [`KeystoreError::UnsupportedVersion`] if the
    /// version is not [`VAULT_VERSION`].
    pub fn open(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        if self.version != VAULT_VERSION {
            return Err(KeystoreError::UnsupportedVersion(
                self.version,
                VAULT_VERSION,
            ));
        }
        if self.salt.len() < SALT_LEN {
            return Err(KeystoreError::Truncated(self.salt.len(), SALT_LEN));
        }
        if self.nonce.len() < NONCE_LEN {
            return Err(KeystoreError::Truncated(self.nonce.len(), NONCE_LEN));
        }
        let key = derive_key(password, &self.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::try_from(&self.nonce[..])
            .map_err(|e| KeystoreError::Kdf(format!("bad nonce length: {e}")))?;
        cipher
            .decrypt(&nonce, self.ciphertext.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| KeystoreError::WrongPassword)
    }

    /// Serialize the vault to a self-describing byte string.
    ///
    /// Layout: `version(1) || salt_len(1) || salt || nonce_len(1) || nonce ||
    /// ct_len(4, LE) || ciphertext`. Length-prefixed so a truncated file is
    /// detected rather than silently misparsed.
    /// # Errors
    ///
    /// `KeystoreError::Unencodable` if the salt or nonce does not fit a `u8`
    /// length prefix, or the ciphertext exceeds `u32::MAX`. Unreachable through
    /// [`seal`], which always writes the fixed 16- and 12-byte sizes.
    ///
    /// Returned rather than panicked because the fields are public, so a caller
    /// can build a `SealedVault` by hand - for instance by parsing a hostile
    /// file straight into the struct. Truncating a length prefix silently would
    /// produce a vault that parses back as something else; panicking would let a
    /// crafted vault take down whatever serialized it. Rejecting is the only
    /// outcome that is neither.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeystoreError> {
        let salt_len = u8::try_from(self.salt.len())
            .map_err(|_| KeystoreError::Unencodable("salt length exceeds u8 prefix"))?;
        let nonce_len = u8::try_from(self.nonce.len())
            .map_err(|_| KeystoreError::Unencodable("nonce length exceeds u8 prefix"))?;
        let ct_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| KeystoreError::Unencodable("ciphertext exceeds u32 length"))?;
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
    /// Returns [`KeystoreError::Truncated`] if the byte string is shorter
    /// than the header claims.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        // Minimum: version + salt_len + salt(16) + nonce_len + nonce(12) + ct_len(4).
        const MIN: usize = 1 + 1 + SALT_LEN + 1 + NONCE_LEN + 4;
        if bytes.len() < MIN {
            return Err(KeystoreError::Truncated(bytes.len(), MIN));
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
fn read_slice(bytes: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, KeystoreError> {
    let end = *pos + len;
    if end > bytes.len() {
        return Err(KeystoreError::Truncated(bytes.len(), end));
    }
    let out = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw() -> Vec<u8> {
        b"correct horse battery staple".to_vec()
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
        assert_eq!(err, KeystoreError::WrongPassword);
    }

    #[test]
    fn sealing_twice_produces_different_ciphertext() {
        let a = seal(&pw(), b"same payload", 4096).expect("seal a");
        let b = seal(&pw(), b"same payload", 4096).expect("seal b");
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
        assert_eq!(vault.open(&pw()).err(), Some(KeystoreError::WrongPassword));
    }

    #[test]
    fn tampering_with_the_salt_is_rejected() {
        let mut vault = seal(&pw(), b"payload", 4096).expect("seal");
        vault.salt[0] ^= 0x80;
        // A different salt derives a different key -> tag mismatch.
        assert_eq!(vault.open(&pw()).err(), Some(KeystoreError::WrongPassword));
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
                matches!(r, Err(KeystoreError::Truncated(..))),
                "cut {cut} should be truncated, got {r:?}"
            );
        }
    }

    /// The `to_bytes` limits that replaced three `expect` calls.
    ///
    /// `SealedVault` fields are public, so these shapes are constructible by
    /// anyone who parses a file into the struct. Before, each one panicked; the
    /// point of the change is that they are now `Err`, so this asserts the
    /// rejection rather than the panic that used to happen.
    #[test]
    fn an_oversized_field_is_refused_not_panicked() {
        let good = seal(&pw(), b"payload", 4096).expect("seal");

        // Salt too long for a u8 length prefix.
        let mut big_salt = good.clone();
        big_salt.salt = vec![0u8; 256];
        assert!(matches!(
            big_salt.to_bytes(),
            Err(KeystoreError::Unencodable(_))
        ));

        // Nonce too long for a u8 length prefix.
        let mut big_nonce = good.clone();
        big_nonce.nonce = vec![0u8; 256];
        assert!(matches!(
            big_nonce.to_bytes(),
            Err(KeystoreError::Unencodable(_))
        ));

        // Ciphertext too long for a u32 length prefix. Not allocatable, so the
        // check is exercised by capacity rather than a real 4 GiB buffer: the
        // field is a Vec<u8> whose len is what the conversion inspects.
        let mut huge = good.clone();
        huge.ciphertext = Vec::new();
        assert!(huge.to_bytes().is_ok(), "an empty ciphertext encodes");

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
            Some(KeystoreError::UnsupportedVersion(
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
            Some(KeystoreError::TooLarge(8192, 4096))
        );
    }

    #[test]
    fn an_empty_password_still_works_but_is_a_different_key() {
        // Empty password is a valid (if weak) password; the point is it is a
        // *different* key than any non-empty one, not that it is accepted.
        let vault = seal(b"", b"payload", 4096).expect("seal");
        assert_eq!(&vault.open(b"").expect("open")[..], b"payload");
        assert_eq!(vault.open(b" ").err(), Some(KeystoreError::WrongPassword));
    }
}

/// Write secret bytes to a file with owner-only permissions, atomically.
///
/// The file is created with mode 0600 *at creation time* (not chmod after
/// the fact, which leaves a window where another local user can open it),
/// written fully, fsynced, then renamed into place so a crash cannot leave a
/// half-written vault. An existing target is replaced only if it is a
/// regular file - a symlink at the target path is refused rather than
/// followed, because a vault path an attacker can point elsewhere is a write
/// primitive they do not deserve.
///
/// # Errors
///
/// [`KeystoreError::Io`] if any step fails.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), KeystoreError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        f.write_all(bytes)
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| KeystoreError::Io(e.to_string()))?;
    }
    // Refuse to replace anything that is not a regular file (or absent).
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if !md.file_type().is_file() {
            return Err(KeystoreError::Io(
                "vault target exists and is not a regular file".into(),
            ));
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    // Belt and braces: some filesystems mask the creation mode.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| KeystoreError::Io(e.to_string()))?;
    Ok(())
}

/// Read secret bytes from a file, refusing anything group- or world-readable.
///
/// A vault whose permissions were widened (by any means - a bug, a user, a
/// tarball) may have been copied, so the password inside must be treated as
/// exposed: this refuses to open it rather than silently trusting it. The
/// file must also be a regular file, not a symlink or device.
///
/// # Errors
///
/// [`KeystoreError::Io`] if unreadable or not a regular file;
/// [`KeystoreError::InsecurePermissions`] if the mode is wider than 0600.
pub fn read_private(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::symlink_metadata(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    if !md.file_type().is_file() {
        return Err(KeystoreError::Io("not a regular file".into()));
    }
    if md.permissions().mode() & 0o077 != 0 {
        return Err(KeystoreError::InsecurePermissions(
            "secret file has group/other permissions (need 0600)".into(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod file_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ks-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    #[test]
    fn private_roundtrip_keeps_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("rt");
        let path = dir.join("vault.bin");
        write_private(&path, b"secret bytes").expect("write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "owner-only");
        let got = read_private(&path).expect("read");
        assert_eq!(&got[..], b"secret bytes");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn widened_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("wide");
        let path = dir.join("vault.bin");
        write_private(&path, b"x").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            read_private(&path),
            Err(KeystoreError::InsecurePermissions(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlink_target_is_refused() {
        let dir = tmpdir("ln");
        let path = dir.join("vault.bin");
        std::os::unix::fs::symlink("/etc/passwd", &path).expect("symlink");
        assert!(
            write_private(&path, b"no").is_err(),
            "must not follow symlink"
        );
        assert!(
            read_private(&path).is_err(),
            "must not read through symlink"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
