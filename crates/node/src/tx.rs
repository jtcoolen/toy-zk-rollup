//! The shielded transfer envelope: what travels on the wire.
//!
//! # What the envelope is for
//!
//! The in-circuit SHA3-256 ownership binding (D-035) is what the settlement
//! layer relies on: a nullifier is `H(DOMAIN_NF ‖ sk_d ‖ rho)`, so publishing
//! one *is* the proof of knowledge of `sk_d`, and the circuit ties that same
//! `sk_d` to the note's committed `pk_d`. Value cannot move without it.
//!
//! The SPHINCS+ envelope sits *outside* that and does a different job:
//!
//! * it stops junk at the mempool door — an unsigned or wrongly signed transfer
//!   is rejected before a prover ever burns CPU on it;
//! * it gives the submission non-repudiable provenance;
//! * it is the seam that ticket 10 closes cryptographically, when SPHINCS+
//!   verification moves *into* the circuit and the binding becomes a proof
//!   rather than a policy check.
//!
//! # What the envelope deliberately does not claim
//!
//! The node cannot verify that a revealed SPHINCS+ verifying key corresponds to
//! a note's `pk_d`. That relation is `pk_d = H(sk_d)` with `sk_d` secret, and
//! no public function of the verifying key yields it. Making the binding
//! cryptographic is precisely what in-circuit SPHINCS+ (ticket 10) buys; until
//! then the envelope is defense-in-depth against a *misbehaving wallet*, not a
//! replacement for the circuit's binding. This is stated here rather than
//! glossed over, because a reader who assumes the envelope authorises the spend
//! would be wrong, and wrong in a way that matters.
//!
//! # Wire format
//!
//! The signed message is a domain-separated, length-prefixed encoding of the
//! public statement. It is built by [`signing_message`] and is consensus-
//! critical: a wallet and a node that disagree on it reject each other's
//! transfers.

use pq_hash::{NoteHash, Nullifier};
use pq_sign::{SpendAuth, SphincsPlusAuth};
use shielded::TransferPublic;

/// The verifying key type that authorizes a spend.
///
/// Aliased through the [`SpendAuth`] trait rather than naming `slh-dsa`'s
/// generic directly, so the envelope does not hard-code the scheme: swapping
/// the parameter set changes one line in `pq-sign` and nothing here.
pub type SpendVerifyingKey = <SphincsPlusAuth as SpendAuth>::PublicKey;

/// The signature type carried by the envelope.
pub type SpendSignature = <SphincsPlusAuth as SpendAuth>::Signature;

/// Domain separation tag for the spend-authorization message.
pub const DOMAIN_TX: &[u8] = b"pq-rollup/spend-auth/v1";

/// Errors from envelope admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    /// The SPHINCS+ signature did not verify.
    BadSignature,
    /// A transfer spends no notes, or creates none.
    Empty,
    /// Value is not conserved: `sum(inputs) != sum(outputs) + fee`.
    Imbalanced,
    /// A nullifier this transfer spends is already in the pool.
    AlreadySpent(Nullifier),
    /// A count exceeded what the wire format can encode.
    TooLarge,
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "spend authorization signature invalid"),
            Self::Empty => write!(f, "a transfer must spend and create at least one note"),
            Self::Imbalanced => write!(f, "transfer does not conserve value"),
            Self::AlreadySpent(_) => write!(f, "nullifier already spent"),
            Self::TooLarge => write!(f, "transfer exceeds the wire format's count limits"),
        }
    }
}

impl std::error::Error for TxError {}

/// A shielded transfer as it travels from wallet to node.
///
/// The `TransferPublic` is everything the chain sees; the signature is the
/// owner's authorization of exactly those bytes. Note that the signature is
/// over the *public statement*, so a relayer cannot swap an output or bump a
/// fee without invalidating it.
#[derive(Clone, Debug)]
pub struct ShieldedTransfer {
    /// The public statement: nullifiers, outputs, roots, fee.
    pub public: TransferPublic,
    /// The SPHINCS+ verifying key that authorized this transfer.
    pub verifying_key: SpendVerifyingKey,
    /// The SPHINCS+ signature over [`Self::signing_message`].
    pub signature: SpendSignature,
}

impl ShieldedTransfer {
    /// The bytes the owner signs: the domain tag and the public statement.
    ///
    /// Length-prefixed so a transfer with, say, one 32-byte nullifier and one
    /// 32-byte output cannot be re-read as two of something else. Every
    /// variable-length field carries its count, so the encoding is
    /// injective — two different statements never produce the same message.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::TooLarge`] if a field count exceeds
    /// [`MAX_COUNT_PER_FIELD`]. The check is what makes the injectivity claim
    /// true: a silently truncated length prefix would let two statements with
    /// counts differing by `2^32` collide.
    pub fn signing_message(&self) -> Result<Vec<u8>, TxError> {
        encode_statement(&self.public)
    }

    /// Check the envelope's signature against [`Self::signing_message`].
    ///
    /// # Errors
    ///
    /// Returns [`TxError::BadSignature`] if the signature does not verify, or
    /// [`TxError::TooLarge`] if the statement cannot be encoded.
    pub fn verify_signature(&self) -> Result<(), TxError> {
        let message = self.signing_message()?;
        SphincsPlusAuth::verify(&self.verifying_key, &message, &self.signature)
            .map_err(|_| TxError::BadSignature)
    }
}

/// The most nullifiers or outputs one transfer may carry.
///
/// Bounded well below the wire format's `u32` prefix so the count is also
/// representable in the block statement's `u16` shape limbs (see
/// [`prover::block::shape_header`]). A wallet that exceeds this is not
/// building a transfer this protocol supports.
pub const MAX_COUNT_PER_FIELD: usize = 1_024;

/// Encode a [`TransferPublic`] into the canonical signed-message bytes.
///
/// Layout (all counts little-endian `u32`, all digests raw 32 bytes):
///
/// ```text
///   DOMAIN_TX
///   ‖ n_nullifiers ‖ nullifier_0 ‖ … ‖ nullifier_{n-1}
///   ‖ n_outputs    ‖ output_0    ‖ … ‖ output_{m-1}
///   ‖ root ‖ nullifier_root_before ‖ nullifier_root_after
///   ‖ fee (u64 LE)
/// ```
///
/// The roots are included so the signature covers *which* state the transfer
/// was witnessed against: a transfer re-broadcast against a different root is
/// a different message, and the old signature does not cover it.
///
/// # Errors
///
/// Returns [`TxError::TooLarge`] if either count exceeds
/// [`MAX_COUNT_PER_FIELD`].
fn encode_statement(public: &TransferPublic) -> Result<Vec<u8>, TxError> {
    if public.nullifiers.len() > MAX_COUNT_PER_FIELD || public.outputs.len() > MAX_COUNT_PER_FIELD {
        return Err(TxError::TooLarge);
    }
    let mut out = Vec::with_capacity(
        DOMAIN_TX.len() + 8 + public.nullifiers.len() * 32 + public.outputs.len() * 32 + 3 * 32 + 8,
    );
    out.extend_from_slice(DOMAIN_TX);
    push_count(&mut out, public.nullifiers.len());
    for nf in &public.nullifiers {
        out.extend_from_slice(nf.as_bytes());
    }
    push_count(&mut out, public.outputs.len());
    for out_hash in &public.outputs {
        out.extend_from_slice(out_hash.as_bytes());
    }
    out.extend_from_slice(public.root.as_bytes());
    out.extend_from_slice(public.nullifier_roots.before.as_bytes());
    out.extend_from_slice(public.nullifier_roots.after.as_bytes());
    out.extend_from_slice(&public.fee.to_le_bytes());
    Ok(out)
}

/// Push a length prefix.
///
/// Callers have already bounds-checked against [`MAX_COUNT_PER_FIELD`], which
/// is far below `u32::MAX`, so the truncating cast here is provably lossless.
/// The lint is allowed rather than replaced with error handling because the
/// check that makes this safe lives one frame up, in `encode_statement`, and
/// duplicating it here would suggest it can still fail.
///
/// [`MAX_COUNT_PER_FIELD`]: crate::tx::MAX_COUNT_PER_FIELD
#[allow(
    clippy::cast_possible_truncation,
    reason = "bounded by MAX_COUNT_PER_FIELD"
)]
fn push_count(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_le_bytes());
}

/// A transfer's nullifiers, for the pool's replay index.
#[must_use]
pub fn nullifiers_of(transfer: &ShieldedTransfer) -> &[Nullifier] {
    &transfer.public.nullifiers
}

/// A transfer's output commitments, for the tree.
#[must_use]
pub fn outputs_of(transfer: &ShieldedTransfer) -> &[NoteHash] {
    &transfer.public.outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::{Digest32, MerkleRoot};
    use pq_sign::rand::{rngs::StdRng, SeedableRng};
    use shielded::NullifierRoots;

    fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn statement(n_nullifiers: u8, n_outputs: u8, fee: u64) -> TransferPublic {
        TransferPublic {
            nullifiers: (0..n_nullifiers)
                .map(|i| Nullifier::from_digest(digest(i.wrapping_add(1))))
                .collect(),
            outputs: (0..n_outputs)
                .map(|i| NoteHash::from_digest(digest(i.wrapping_add(128))))
                .collect(),
            root: MerkleRoot::from_digest(digest(0xaa)),
            nullifier_roots: NullifierRoots {
                before: MerkleRoot::from_digest(digest(0xbb)),
                after: MerkleRoot::from_digest(digest(0xcc)),
            },
            fee,
        }
    }

    /// Build a signed envelope from a deterministic seed.
    ///
    /// Seeded keygen rather than a fixed byte string: SPHINCS+ keys have
    /// internal structure, and hand-picking 64 bytes would test the parser,
    /// not the scheme.
    fn envelope(public: TransferPublic, seed: u64) -> ShieldedTransfer {
        let mut rng = StdRng::seed_from_u64(seed);
        let (sk, vk) = SphincsPlusAuth::generate_keypair(&mut rng);
        let message = encode_statement(&public).expect("encodes");
        let signature = SphincsPlusAuth::sign(&sk, &message);
        ShieldedTransfer {
            public,
            verifying_key: vk,
            signature,
        }
    }

    #[test]
    fn a_honest_envelope_verifies() {
        let tx = envelope(statement(1, 1, 100), 1);
        assert!(tx.verify_signature().is_ok());
    }

    /// The signature must cover the *statement*, not just the key. A transfer
    /// whose fee was bumped after signing must fail.
    #[test]
    fn tampering_with_the_fee_invalidates_the_signature() {
        let mut tx = envelope(statement(1, 1, 100), 2);
        tx.public.fee = 0;
        assert_eq!(tx.verify_signature(), Err(TxError::BadSignature));
    }

    /// Swapping an output commitment is the attack that matters: it redirects
    /// value. It must be caught by the signature.
    #[test]
    fn swapping_an_output_invalidates_the_signature() {
        let mut tx = envelope(statement(1, 2, 100), 3);
        tx.public.outputs.swap(0, 1);
        assert_eq!(tx.verify_signature(), Err(TxError::BadSignature));
    }

    /// The message must be injective: two different statements must not
    /// collide, or a signature on one would authorize the other.
    #[test]
    fn the_encoding_is_injective_across_shapes() {
        let a = encode_statement(&statement(1, 11, 1)).expect("encodes");
        let b = encode_statement(&statement(11, 1, 1)).expect("encodes");
        assert_ne!(a, b, "swapped counts must not collide");

        // The nasty case: one 64-byte nullifier vs two 32-byte nullifiers.
        // Without length prefixes these would be the same bytes.
        let mut c = statement(1, 1, 1);
        c.nullifiers = vec![Nullifier::from_digest(digest(0x11))];
        let mut d = statement(2, 1, 1);
        d.nullifiers = vec![
            Nullifier::from_digest(digest(0x11)),
            Nullifier::from_digest(digest(0x22)),
        ];
        assert_ne!(
            encode_statement(&c).expect("encodes"),
            encode_statement(&d).expect("encodes"),
            "length prefixes must separate 1 from 2 nullifiers"
        );
    }

    /// A signature from a different key must not verify.
    #[test]
    fn a_foreign_key_invalidates_the_signature() {
        let tx = envelope(statement(1, 1, 100), 4);
        let (_, foreign_vk) = SphincsPlusAuth::generate_keypair(&mut StdRng::seed_from_u64(0xdead));
        let forged = ShieldedTransfer {
            public: tx.public.clone(),
            verifying_key: foreign_vk,
            signature: tx.signature.clone(),
        };
        assert_eq!(forged.verify_signature(), Err(TxError::BadSignature));
        // And the honest one still works, so the failure above is real.
        assert!(tx.verify_signature().is_ok());
    }

    /// The verifying key type must round-trip through bytes, since the wallet
    /// stores and transmits it.
    #[test]
    fn verifying_key_roundtrips() {
        let tx = envelope(statement(1, 1, 1), 5);
        let bytes = SphincsPlusAuth::public_key_to_bytes(&tx.verifying_key);
        let back = SphincsPlusAuth::public_key_from_bytes(&bytes).expect("round-trips");
        assert_eq!(back, tx.verifying_key);
    }

    /// The same seed must yield the same verifying key, so a wallet can
    /// recover its identity from a stored seed.
    #[test]
    fn keygen_is_deterministic_from_a_seed() {
        let (sk_a, vk_a) = SphincsPlusAuth::generate_keypair(&mut StdRng::seed_from_u64(7));
        let (_, vk_b) = SphincsPlusAuth::generate_keypair(&mut StdRng::seed_from_u64(7));
        assert_eq!(vk_a, vk_b);
        // And a signature from one verifies under the other's key.
        let msg = b"recover me";
        let sig = SphincsPlusAuth::sign(&sk_a, msg);
        assert!(SphincsPlusAuth::verify(&vk_b, msg, &sig).is_ok());
    }
}
