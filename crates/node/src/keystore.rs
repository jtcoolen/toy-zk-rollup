//! Node-side keystore: file IO around the shared `vault` crate.
//!
//! The vault *format* - Argon2id password KDF, AES-256-GCM AEAD, salt/nonce
//! discipline, the sealed-byte layout - lives in the `vault` crate, which is
//! wasm-safe so the browser wallet seals and opens the identical format. This
//! module keeps only what is node-specific:
//!
//! * `seal`: the vault API with the OS CSPRNG (`SysRng`) wired in, so callers
//!   do not each decide where entropy comes from.
//! * `write_private` / `read_private`: the 0600-only, no-symlink file discipline
//!   for vault files on disk.
//!
//! The security rationale for the crypto itself is documented on the
//! `vault` crate; duplicating it here is how the two copies drift.
//!
//! # What this is NOT
//!
//! This is not a hardware security module. If the host is compromised while
//! the vault is *unlocked* (the derived key is in RAM), the keys are exposed.
//! The vault protects the at-rest file, not a live process. For custody of
//! large sums the signing key should live in an HSM or a hardware wallet; this
//! vault is the right shape for a node's own operational keys and for a demo
//! wallet's local custody.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub use vault::{SealedVault, VaultError, VAULT_VERSION};

use rand::rngs::SysRng;
use zeroize::Zeroizing;

/// Errors from a keystore operation: the vault crypto errors plus file errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeystoreError {
    /// The vault crypto layer refused the operation (wrong password, truncated
    /// blob, unsupported version, ...). See [`VaultError`] for the cases.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// A filesystem operation on a vault or secret file failed.
    #[error("vault file error: {0}")]
    Io(String),
    /// A secret file's permissions are wider than owner-only, so its
    /// contents must be treated as possibly copied. Refuse to use it.
    #[error("insecure secret file permissions: {0}")]
    InsecurePermissions(String),
}

/// Encrypt `plaintext` under `password` into a [`SealedVault`].
///
/// Fresh salt and nonce are drawn from OS entropy on every call, so sealing
/// the same payload twice produces two unrelated vaults.
///
/// # Errors
///
/// Returns [`VaultError::TooLarge`] if `plaintext` exceeds `max_payload`,
/// [`VaultError::Entropy`] if the OS CSPRNG fails, or [`VaultError::Kdf`]
/// if the KDF fails.
pub fn seal(
    password: &[u8],
    plaintext: &[u8],
    max_payload: usize,
) -> Result<SealedVault, KeystoreError> {
    // SysRng, not a thread-local RNG: a salt/nonce must not be predictable
    // from any other RNG state in the process.
    vault::seal_with_rng(password, plaintext, max_payload, &mut SysRng).map_err(Into::into)
}

/// Write secret bytes to `path` atomically, owner-only.
///
/// Writes to a sibling `*.tmp` with mode 0600, fsyncs, then renames over the
/// target. Rename is atomic on POSIX, so a crash mid-write leaves either the
/// old file or the new one, never a half-written vault. The target is refused
/// if it exists and is not a regular file (a symlink planted at the vault path
/// would otherwise send the secret through to wherever it points).
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
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips_through_the_vault_crate() {
        let secret = b"node operator key".to_vec();
        let vault = seal(b"pw", &secret, 4096).expect("seal");
        let opened = vault.open(b"pw").expect("open");
        assert_eq!(&opened[..], &secret[..]);
    }

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
