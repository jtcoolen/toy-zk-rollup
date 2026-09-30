//! A non-verifying spend authorization for pipeline bring-up only.
//!
//! **This is not secure.** It accepts every signature. It exists so the note
//! lifecycle, Merkle tree, batch driver and wallet can be exercised end to end
//! before the SPHINCS+ verifier is wired in.
//!
//! It is compiled only under the non-default `insecure-stub` feature, and
//! `assert_stub_absent_in_release` below fails the build if a release profile ever
//! selects it.

#![cfg(feature = "insecure-stub")]

use crate::spend_auth::{SpendAuth, SpendAuthError};

/// A spend authorization that always verifies.
///
/// See the module docs. Never wire this into anything that holds value.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubSpendAuth;

/// A signature that is always accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StubSignature(pub Vec<u8>);

impl SpendAuth for StubSpendAuth {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = StubSignature;

    fn generate_keypair<R: rand::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::SecretKey, Self::PublicKey) {
        let mut sk = vec![0u8; 32];
        rng.fill_bytes(&mut sk);
        // The "public key" is a tagged copy so it is at least distinguishable in logs.
        let vk = [b"STUB::".as_slice(), sk.as_slice()].concat();
        (sk, vk)
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        StubSignature([sk.as_slice(), message].concat())
    }

    fn verify(
        _vk: &Self::PublicKey,
        _message: &[u8],
        _sig: &Self::Signature,
    ) -> Result<(), SpendAuthError> {
        // Deliberately accepts everything.
        Ok(())
    }

    fn public_key_to_bytes(vk: &Self::PublicKey) -> Vec<u8> {
        vk.clone()
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, SpendAuthError> {
        if bytes.starts_with(b"STUB::") {
            Ok(bytes.to_vec())
        } else {
            Err(SpendAuthError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    /// The stub must never be reachable from a release build.
    ///
    /// `debug_assertions` is off in release; if someone enables `insecure-stub`
    /// there, this test fires.
    #[test]
    #[cfg(not(debug_assertions))]
    fn stub_must_not_be_enabled_in_release() {
        compile_error!("insecure-stub must never be enabled in a release build");
    }

    #[test]
    #[cfg(debug_assertions)]
    fn stub_accepts_anything_in_debug_only() {
        let (sk, vk) =
            super::StubSpendAuth::generate_keypair(&mut rand::rngs::StdRng::seed_from_u64(1));
        let sig = super::StubSpendAuth::sign(&sk, b"anything");
        assert!(super::StubSpendAuth::verify(&vk, b"anything", &sig).is_ok());
    }
}
