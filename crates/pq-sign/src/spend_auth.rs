//! The spend-authorization trait and its SPHINCS+ implementation.

use slh_dsa::signature::{Keypair as _, Signer, Verifier};
use slh_dsa::{Sha2_128f, Signature, SigningKey, VerifyingKey};

/// An error from spend authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendAuthError {
    /// The signature did not verify against the key and message.
    InvalidSignature,
    /// A byte string could not be parsed as a key or signature.
    Malformed,
}

impl core::fmt::Display for SpendAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "spend authorization signature invalid"),
            Self::Malformed => write!(f, "key or signature malformed"),
        }
    }
}

impl std::error::Error for SpendAuthError {}

/// Authorization to spend a note.
///
/// This is the seam between the shielded domain and whatever proves "the owner
/// approved this". The domain layer holds a `Box<dyn SpendAuth>`-style generic and
/// never learns the scheme.
///
/// # Contract
///
/// `verify` must return `Ok(())` **only** for signatures produced by the
/// matching `sign` under the same key. It must never panic on adversarial input.
pub trait SpendAuth: Clone + Send + Sync + 'static {
    /// The public key type that authorizes spends.
    type PublicKey;
    /// The secret key type that produces authorizations.
    type SecretKey;
    /// The serialized signature.
    type Signature;

    /// Generate a fresh keypair from a CSPRNG.
    fn generate_keypair<R: rand::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::SecretKey, Self::PublicKey);

    /// Produce an authorization over `message`.
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    /// Verify an authorization.
    ///
    /// # Errors
    ///
    /// Returns [`SpendAuthError::InvalidSignature`] if `sig` is not a valid
    /// authorization by `vk` over `message`.
    fn verify(
        vk: &Self::PublicKey,
        message: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), SpendAuthError>;

    /// Serialize a public key to bytes.
    fn public_key_to_bytes(vk: &Self::PublicKey) -> Vec<u8>;

    /// Parse a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SpendAuthError::Malformed`] if `bytes` is not a well-formed
    /// public key for this scheme.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, SpendAuthError>;
}

/// SPHINCS+ (FIPS-205) spend authorization using the `Sha2_128f` parameter set.
#[derive(Clone, Copy, Debug, Default)]
pub struct SphincsPlusAuth;

impl SpendAuth for SphincsPlusAuth {
    type PublicKey = VerifyingKey<Sha2_128f>;
    type SecretKey = SigningKey<Sha2_128f>;
    type Signature = Signature<Sha2_128f>;

    fn generate_keypair<R: rand::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::SecretKey, Self::PublicKey) {
        let sk = SigningKey::<Sha2_128f>::new(rng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        // SPHINCS+ is deterministic given the key and message; `try_sign` goes
        // through the `Signer` trait so there is one code path.
        <SigningKey<Sha2_128f> as Signer<Signature<Sha2_128f>>>::sign(sk, message)
    }

    fn verify(
        vk: &Self::PublicKey,
        message: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), SpendAuthError> {
        <VerifyingKey<Sha2_128f> as Verifier<Signature<Sha2_128f>>>::verify(vk, message, sig)
            .map_err(|_| SpendAuthError::InvalidSignature)
    }

    fn public_key_to_bytes(vk: &Self::PublicKey) -> Vec<u8> {
        vk.to_bytes().to_vec()
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, SpendAuthError> {
        VerifyingKey::<Sha2_128f>::try_from(bytes).map_err(|_| SpendAuthError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: u64) -> rand::rngs::StdRng {
        rand::SeedableRng::seed_from_u64(seed)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, vk) = SphincsPlusAuth::generate_keypair(&mut rng(0x5eed));
        let msg = b"spend note 42 for 7 units";
        let sig = SphincsPlusAuth::sign(&sk, msg);
        assert!(SphincsPlusAuth::verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, vk) = SphincsPlusAuth::generate_keypair(&mut rng(0x5eed));
        let sig = SphincsPlusAuth::sign(&sk, b"spend note 42");
        assert_eq!(
            SphincsPlusAuth::verify(&vk, b"spend note 43", &sig),
            Err(SpendAuthError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_other_key() {
        // Distinct seeds, or the two "different" keypairs would be identical and
        // this test would pass for the wrong reason.
        let (sk, _) = SphincsPlusAuth::generate_keypair(&mut rng(0xa1));
        let (_, other_vk) = SphincsPlusAuth::generate_keypair(&mut rng(0xb2));
        let sig = SphincsPlusAuth::sign(&sk, b"hello");
        assert_eq!(
            SphincsPlusAuth::verify(&other_vk, b"hello", &sig),
            Err(SpendAuthError::InvalidSignature)
        );
    }

    #[test]
    fn public_key_roundtrips_through_bytes() {
        let (_, vk) = SphincsPlusAuth::generate_keypair(&mut rng(0x5eed));
        let bytes = SphincsPlusAuth::public_key_to_bytes(&vk);
        let parsed = SphincsPlusAuth::public_key_from_bytes(&bytes).expect("parses");
        assert_eq!(parsed, vk);
    }

    #[test]
    fn malformed_key_is_an_error_not_a_panic() {
        assert_eq!(
            SphincsPlusAuth::public_key_from_bytes(&[1, 2, 3]),
            Err(SpendAuthError::Malformed)
        );
    }

    #[test]
    fn signature_is_large_but_bounded() {
        // Sha2_128f signatures are ~8KB. Pin the order of magnitude so a
        // parameter-set change that balloons this is caught.
        let (sk, _) = SphincsPlusAuth::generate_keypair(&mut rng(0x5eed));
        let sig = SphincsPlusAuth::sign(&sk, b"x");
        let len = sig.to_bytes().len();
        assert!(len > 7_000 && len < 20_000, "unexpected sig len {len}");
    }
}
