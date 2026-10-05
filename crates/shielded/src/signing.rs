//! The canonical signing message for a shielded transfer.
//!
//! This is *the* bytes a spend-authorization signature covers. It lives here,
//! next to the statement type it encodes, because prover, node and wallet must
//! all derive the identical message from the identical statement - any drift
//! between signer and verifier is a lost or forged transfer. The node's
//! envelope code and the browser wallet's wasm both call into this module, so
//! there is exactly one implementation to audit.
//!
//! # Why the encoding is injective
//!
//! Every variable-length field carries an explicit little-endian `u32` count,
//! and the counts are bounds-checked against `MAX_COUNT_PER_FIELD` before
//! encoding. Without the bounds check, two statements whose counts differed by
//! `2^32` would truncate to the same length prefix and collide; with it, two
//! different statements never produce the same message. That matters because
//! the signature is the *only* thing separating a valid transfer from a
//! relayer's edit: if two statements shared a message, one signature would
//! authorize both.
//!
//! # Why the roots are in the message
//!
//! `root`, `nullifier_root_before` and `nullifier_root_after` pin the
//! signature to a state witness. A transfer re-broadcast against a different
//! chain state is a different message, so an old signature simply does not
//! cover the replay - no replay-protection bookkeeping needed at the
//! signature layer.

use crate::transfer::TransferPublic;

/// Domain separation tag for the spend-authorization message.
///
/// Prefixed to every message so a signature can never be lifted from this
/// protocol into some other protocol that happens to sign similar bytes.
pub const DOMAIN_TX: &[u8] = b"pq-rollup/spend-auth/v1";

/// The most nullifiers or outputs one transfer may carry.
///
/// Bounded well below the wire format's `u32` prefix so the count is also
/// representable in the block statement's `u16` shape limbs. A wallet that
/// exceeds this is not building a transfer this protocol supports.
pub const MAX_COUNT_PER_FIELD: usize = 1_024;

/// Why a statement could not be encoded for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// A nullifier or output count exceeded `MAX_COUNT_PER_FIELD`.
    TooLarge,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "transfer exceeds the count limits"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Encode a `TransferPublic` into the canonical signed-message bytes.
///
/// Layout (all counts little-endian `u32`, all digests raw 32 bytes):
///
/// ```text
///   DOMAIN_TX
///   || n_nullifiers || nullifier_0 || ... || nullifier_{n-1}
///   || n_outputs    || output_0    || ... || output_{m-1}
///   || root || nullifier_root_before || nullifier_root_after
///   || fee (u64 LE)
/// ```
///
/// # Errors
///
/// Returns `EncodeError::TooLarge` if either count exceeds
/// `MAX_COUNT_PER_FIELD`.
pub fn encode_statement(public: &TransferPublic) -> Result<Vec<u8>, EncodeError> {
    if public.nullifiers.len() > MAX_COUNT_PER_FIELD || public.outputs.len() > MAX_COUNT_PER_FIELD {
        return Err(EncodeError::TooLarge);
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
/// Callers have already bounds-checked against `MAX_COUNT_PER_FIELD`, which is
/// far below `u32::MAX`, so the truncating cast here is provably lossless. The
/// lint is allowed rather than replaced with error handling because the check
/// that makes this safe lives one frame up, in `encode_statement`, and
/// duplicating it here would suggest it can still fail.
#[allow(
    clippy::cast_possible_truncation,
    reason = "bounded by MAX_COUNT_PER_FIELD"
)]
fn push_count(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::NullifierRoots;
    use pq_hash::{Digest32, MerkleRoot, NoteHash, Nullifier};

    /// A distinct digest per index, losslessly (index as u64 LE in the first
    /// 8 bytes) so no count - including the oversized-cap test's 1025 - is
    /// silently truncated into a collision.
    fn digest(index: u64) -> Digest32 {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&index.to_le_bytes());
        Digest32::new(b)
    }

    fn statement(nf: usize, out: usize, fee: u64) -> TransferPublic {
        TransferPublic {
            nullifiers: (0..nf)
                .map(|i| Nullifier::from_digest(digest(u64::try_from(i).expect("test index fits"))))
                .collect(),
            outputs: (0..out)
                .map(|i| {
                    NoteHash::from_digest(digest(
                        100_000 + u64::try_from(i).expect("test index fits"),
                    ))
                })
                .collect(),
            root: MerkleRoot::from_digest(digest(200)),
            nullifier_roots: NullifierRoots {
                before: MerkleRoot::from_digest(digest(201)),
                after: MerkleRoot::from_digest(digest(202)),
            },
            fee,
        }
    }

    #[test]
    fn encoding_is_deterministic_and_prefixed() {
        let a = encode_statement(&statement(1, 1, 7)).expect("encode");
        let b = encode_statement(&statement(1, 1, 7)).expect("encode");
        assert_eq!(a, b);
        assert!(a.starts_with(DOMAIN_TX));
        // domain(24) + 4 + 32 + 4 + 32 + 96 + 8
        assert_eq!(a.len(), DOMAIN_TX.len() + 4 + 32 + 4 + 32 + 3 * 32 + 8);
    }

    #[test]
    fn a_fee_change_changes_the_message() {
        let a = encode_statement(&statement(1, 1, 7)).expect("encode");
        let b = encode_statement(&statement(1, 1, 8)).expect("encode");
        assert_ne!(a, b);
    }

    #[test]
    fn swapping_outputs_changes_the_message() {
        let a = encode_statement(&statement(1, 2, 0)).expect("encode");
        let mut s = statement(1, 2, 0);
        s.outputs.swap(0, 1);
        let b = encode_statement(&s).expect("encode");
        assert_ne!(a, b);
    }

    #[test]
    fn counts_are_injective_across_shapes() {
        // A statement whose nullifier bytes could be misread as an output list
        // must not collide with one that actually has that shape: the count
        // prefixes are what prevent it.
        let one_nf_two_out = encode_statement(&statement(1, 2, 0)).expect("encode");
        let two_nf_one_out = encode_statement(&statement(2, 1, 0)).expect("encode");
        assert_ne!(one_nf_two_out, two_nf_one_out);
    }

    #[test]
    fn oversized_counts_are_refused() {
        let s = statement(MAX_COUNT_PER_FIELD + 1, 0, 0);
        assert_eq!(
            encode_statement(&s),
            Err(EncodeError::TooLarge),
            "count above the cap must not encode"
        );
    }
}
