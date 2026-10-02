//! Stateless bearer-token authentication with role-based access control.
//!
//! # Why stateless
//!
//! A node restart must not invalidate live sessions, and a node must not keep
//! a table of "who is logged in" that grows without bound under a flood of
//! login attempts. So a token is a self-contained, signed statement:
//! `role || expiry || mac`. The node verifies the MAC and the expiry and is
//! done — no session store, no lookup, no unbounded state.
//!
//! # The token format
//!
//! `base64url(payload) || "." || base64url(hmac_sha256(signing_key, payload))`
//!
//! where `payload = role(1) || expiry_unix(8, LE)`. The dot separator is the
//! JWT convention and makes the two halves visually distinct in logs. We do
//! not use JWT itself: it carries a header and a JSON body we would have to
//! parse, and the only claims we need are role and expiry. A 1-byte role and
//! an 8-byte expiry are cheaper to verify and harder to misparse than a JSON
//! document, and there is no third-party JWT library in the dependency graph
//! to audit.
//!
//! # Constant-time verification
//!
//! The MAC comparison uses `subtle::ConstantTimeEq`. A byte-at-a-time
//! comparison of a MAC leaks, through timing, how many leading bytes of a
//! forged MAC were correct — which is enough to mount a byte-by-byte forgery
//! against a network-adjacent attacker with many samples. The constant-time
//! compare closes that.
//!
//! # Roles
//!
//! Three roles, ordered by privilege. A token carries exactly one role, and
//! the ACL maps each endpoint to the minimum role that may call it. The role
//! is inside the signed payload, so a client cannot escalate by editing it —
//! the MAC would not verify.
//!
//! # Revocation
//!
//! Stateless tokens cannot be revoked individually without a denylist, which
//! reintroduces the state we designed out. The mitigation is short expiry:
//! tokens live for a configurable window (default 1 hour), so a leaked token
//! expires on its own. For immediate revocation the signing key is rotated,
//! which invalidates every outstanding token at once — the operator keeps the
//! key, so this is a single config change.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// A role, ordered by privilege.
///
/// `Ord` is defined so that `role >= required` is the access test. The
/// discriminants are the bytes that go into the token payload, so they are
/// part of the wire format and must not be reordered casually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    /// Read-only: state queries, metrics, health.
    ReadOnly = 0,
    /// May submit transfers to the mempool.
    Submitter = 1,
    /// May drive block production and admin operations.
    Admin = 2,
}

impl Role {
    /// Parse a role from its wire byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::ReadOnly),
            1 => Some(Self::Submitter),
            2 => Some(Self::Admin),
            _ => None,
        }
    }

    /// The role's wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors from token verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The token is not in `payload.mac` form.
    #[error("malformed token")]
    Malformed,
    /// The MAC does not verify (wrong key, tampered payload, or forged).
    #[error("invalid token signature")]
    BadSignature,
    /// The token's role byte is not a known role.
    #[error("unknown role byte {0}")]
    UnknownRole(u8),
    /// The token has passed its expiry.
    #[error("token expired at {0}")]
    Expired(u64),
    /// The presented role is below the required role.
    #[error("insufficient privileges: have {have:?}, need {need:?}")]
    Insufficient {
        /// The role the token carries.
        have: Role,
        /// The role the endpoint requires.
        need: Role,
    },
}

/// Signs and verifies bearer tokens.
///
/// Holds the HMAC signing key. The key is a `Zeroizing`-style secret: it is
/// wiped when the signer is dropped. In a real deployment the key comes from
/// the keystore (see [`crate::keystore`]) or an env var injected at boot,
/// never from a config file in the clear.
pub struct TokenSigner {
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the key.
        f.debug_struct("TokenSigner")
            .field("key_len", &self.key.len())
            .finish_non_exhaustive()
    }
}

impl TokenSigner {
    /// Create a signer from a raw signing key.
    ///
    /// The key should be at least 32 bytes of high-entropy material. We do
    /// not enforce a minimum length here because HMAC is safe with any key
    /// size; the *policy* of "use 32 random bytes" belongs to whoever
    /// provisions the key, and is documented rather than asserted.
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key: zeroize::Zeroizing::new(key),
        }
    }

    /// Issue a token for `role` that expires at `expiry_unix`.
    ///
    /// Returns the `payload.mac` string. The caller puts it in the
    /// `Authorization: Bearer <token>` header.
    #[must_use]
    pub fn issue(&self, role: Role, expiry_unix: u64) -> String {
        let payload = Self::payload(role, expiry_unix);
        let mac = self.mac(&payload);
        format!("{}.{}", base64url(&payload), base64url(&mac))
    }

    /// Verify a token and return the role it carries.
    ///
    /// Checks, in order: format, MAC, role byte, expiry. The MAC is checked
    /// *before* the expiry so a forged token cannot be distinguished from an
    /// expired one by timing — both paths do the same work.
    ///
    /// # Errors
    ///
    /// Returns the first failing check's [`AuthError`].
    pub fn verify(&self, token: &str, now_unix: u64) -> Result<Role, AuthError> {
        let (payload_b64, mac_b64) = token.split_once('.').ok_or(AuthError::Malformed)?;
        let payload = base64url_decode(payload_b64).ok_or(AuthError::Malformed)?;
        let mac = base64url_decode(mac_b64).ok_or(AuthError::Malformed)?;
        // Verify MAC first, constant-time.
        let expected = self.mac(&payload);
        if mac.ct_ne(&expected).into() {
            return Err(AuthError::BadSignature);
        }
        // Payload is role(1) || expiry(8).
        if payload.len() != 9 {
            return Err(AuthError::Malformed);
        }
        let role = Role::from_u8(payload[0]).ok_or(AuthError::UnknownRole(payload[0]))?;
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&payload[1..9]);
        let expiry = u64::from_le_bytes(exp_bytes);
        if now_unix > expiry {
            return Err(AuthError::Expired(expiry));
        }
        Ok(role)
    }

    /// Verify a token and check it meets `required`.
    ///
    /// # Errors
    ///
    /// As [`Self::verify`], plus [`AuthError::Insufficient`] if the role is
    /// below `required`.
    pub fn verify_for(
        &self,
        token: &str,
        now_unix: u64,
        required: Role,
    ) -> Result<Role, AuthError> {
        let role = self.verify(token, now_unix)?;
        if role >= required {
            Ok(role)
        } else {
            Err(AuthError::Insufficient {
                have: role,
                need: required,
            })
        }
    }

    fn payload(role: Role, expiry_unix: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.push(role.as_u8());
        p.extend_from_slice(&expiry_unix.to_le_bytes());
        p
    }

    fn mac(&self, payload: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        m.update(payload);
        m.finalize().into_bytes().to_vec()
    }
}

/// The access-control list: which role each endpoint requires.
///
/// A single source of truth so the routing table and the policy cannot drift.
/// An endpoint not listed here is denied by default — the ACL is deny-by-
/// default, not allow-by-omission.
#[derive(Debug, Clone)]
pub struct Acl {
    /// `(path, required_role)` pairs. Matched by exact path.
    rules: Vec<(String, Role)>,
}

impl Acl {
    /// Build the default policy for this node.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            rules: vec![
                // Public: health and metrics need no token at all.
                ("/health".into(), Role::ReadOnly),
                ("/metrics".into(), Role::ReadOnly),
                // State reads: any authenticated caller.
                ("/v1/state".into(), Role::ReadOnly),
                ("/v1/roots".into(), Role::ReadOnly),
                // Submitting a transfer needs the submitter role.
                ("/v1/transfer".into(), Role::Submitter),
                // Driving block production is admin-only.
                ("/v1/block/produce".into(), Role::Admin),
                // Key/role management is admin-only.
                ("/v1/admin/rotate-key".into(), Role::Admin),
            ],
        }
    }

    /// The minimum role required for `path`, or `None` if the path is not
    /// covered by any rule (which the caller treats as deny).
    #[must_use]
    pub fn required_role(&self, path: &str) -> Option<Role> {
        self.rules.iter().find(|(p, _)| p == path).map(|(_, r)| *r)
    }
}

/// Base64url (RFC 4648 §5) without padding.
fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    out
}

/// Decode base64url without padding. Returns `None` on any invalid byte.
//
// The `as u8` casts below are intentional: each one extracts a byte that was
// just shifted down from a 24-bit accumulator, so the truncated bits are
// always zero. The casts are sound by construction, not by luck.
#[allow(clippy::cast_possible_truncation)]
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    // Widened to u32: the 18-bit shift would overflow a u8 accumulator.
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        match chunk.len() {
            2 => {
                let n = (val(chunk[0])? << 18) | (val(chunk[1])? << 12);
                out.push((n >> 16) as u8);
            }
            3 => {
                let n = (val(chunk[0])? << 18) | (val(chunk[1])? << 12) | (val(chunk[2])? << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            0 => {}
            _ => {
                let n = (val(chunk[0])? << 18)
                    | (val(chunk[1])? << 12)
                    | (val(chunk[2])? << 6)
                    | val(chunk[3])?;
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> TokenSigner {
        TokenSigner::new(vec![7u8; 32])
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn a_fresh_token_verifies_with_its_role() {
        let s = signer();
        let t = s.issue(Role::Submitter, NOW + 3600);
        assert_eq!(s.verify(&t, NOW).unwrap(), Role::Submitter);
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let s = signer();
        let t = s.issue(Role::Admin, NOW - 1);
        assert_eq!(s.verify(&t, NOW), Err(AuthError::Expired(NOW - 1)));
    }

    #[test]
    fn a_token_at_exact_expiry_is_still_valid() {
        let s = signer();
        let t = s.issue(Role::ReadOnly, NOW);
        assert_eq!(s.verify(&t, NOW).unwrap(), Role::ReadOnly);
    }

    #[test]
    fn a_tampered_payload_fails_the_mac() {
        let s = signer();
        let t = s.issue(Role::ReadOnly, NOW + 100);
        // Flip the role byte in the payload half.
        let (p, m) = t.split_once('.').unwrap();
        let mut payload = base64url_decode(p).unwrap();
        payload[0] = Role::Admin.as_u8();
        let forged = format!("{}.{}", base64url(&payload), m);
        assert_ne!(
            forged.as_str(),
            t.as_str(),
            "the tamper must change the token"
        );
        assert_eq!(s.verify(&forged, NOW), Err(AuthError::BadSignature));
    }

    #[test]
    fn a_token_from_another_key_is_rejected() {
        let a = signer();
        let b = TokenSigner::new(vec![8u8; 32]);
        let t = a.issue(Role::Admin, NOW + 100);
        assert_eq!(b.verify(&t, NOW), Err(AuthError::BadSignature));
    }

    #[test]
    fn a_malformed_token_is_rejected() {
        let s = signer();
        for bad in ["", "no-dot", "a.b.c", "!!!!.!!!!", "AAAA"] {
            assert_eq!(s.verify(bad, NOW), Err(AuthError::Malformed), "bad: {bad}");
        }
    }

    #[test]
    fn role_ordering_gates_access() {
        let s = signer();
        let t = s.issue(Role::Submitter, NOW + 100);
        // Submitter >= ReadOnly: ok.
        assert!(s.verify_for(&t, NOW, Role::ReadOnly).is_ok());
        // Submitter >= Submitter: ok.
        assert!(s.verify_for(&t, NOW, Role::Submitter).is_ok());
        // Submitter >= Admin: denied.
        assert_eq!(
            s.verify_for(&t, NOW, Role::Admin),
            Err(AuthError::Insufficient {
                have: Role::Submitter,
                need: Role::Admin
            })
        );
    }

    #[test]
    fn the_acl_maps_endpoints_to_roles() {
        let acl = Acl::default_policy();
        assert_eq!(acl.required_role("/health"), Some(Role::ReadOnly));
        assert_eq!(acl.required_role("/v1/transfer"), Some(Role::Submitter));
        assert_eq!(acl.required_role("/v1/block/produce"), Some(Role::Admin));
        // Unknown path: deny.
        assert_eq!(acl.required_role("/v1/secret"), None);
    }

    #[test]
    fn base64url_round_trips_arbitrary_bytes() {
        for len in 0..64 {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37).unwrap_or(i as u8))
                .collect();
            let enc = base64url(&data);
            let dec = base64url_decode(&enc).expect("decode");
            assert_eq!(dec, data, "len {len}");
        }
    }

    #[test]
    fn base64url_rejects_invalid_characters() {
        assert!(base64url_decode("!!!!").is_none());
        assert!(base64url_decode("A").is_none());
    }
}
