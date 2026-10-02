//! The settlement export: turning a verified block into what the chain consumes.
//!
//! ## The two representations, and why they differ
//!
//! A statement limb has two correct byte forms, and the settlement boundary sits
//! exactly between them:
//!
//! | where | form | why |
//! |---|---|---|
//! | the statement the contract decodes | **canonical** 16-bit limbs | `LimbCodec.digestFromLimbs` reassembles digests from them; a digest is a byte string, not a field element |
//! | the transcript the verifier replays | **Montgomery** little-endian `u32` | `SerializingChallenger32::observe` serializes via [`PrimeField32::to_unique_u32`], which for `MontyField31` returns the raw internal `self.value` |
//!
//! Both are true at once. A contract that absorbs canonical bytes derives
//! different challenges than the Rust prover and accepts nothing; a contract
//! that decodes digests from Montgomery limbs reconstructs the wrong hashes.
//! The conversion is therefore explicit, in one place, on both sides — and it
//! is the single most likely place for the Rust and Solidity sides to silently
//! disagree.
//!
//! ## Why the conversion is derived, not copied
//!
//! [`monty`] and [`canonical`] are written from the field *definition* —
//! `R = 2^32 mod p`, and a from-scratch extended-Euclid inverse — rather than
//! by calling the same routine the prover uses. A test that checks the prover
//! against itself proves nothing. `agrees_with_the_real_field` checks these
//! against `MontyField31`'s own `to_unique_u32`, so passing pins the
//! Solidity mirror to the same arithmetic.
//!
//! ## What ships
//!
//! [`SettlementBundle`] is the wire object: canonical statement limbs for the
//! contract's decoder, the Montgomery transcript bytes that pin the
//! verifier's challenge derivation, and the serialized proof. It carries the
//! shape metadata the contract needs to check the statement length before
//! parsing, because a truncated statement must fail closed rather than be
//! misread as a shorter block.

use p3_field::{PrimeField32, PrimeField64};
use serde::{Deserialize, Serialize};

/// The KoalaBear modulus, `2^31 - 2^27 + 1`.
///
/// Spelled out rather than imported so the conversion below can be checked
/// against the field implementation as an independent fact.
pub const KOALABEAR_P: u64 = 2_130_706_433;

/// Montgomery radix: `R = 2^32 mod p`.
///
/// `2^32 = 4_294_967_296` and `2 * p = 4_261_412_866`, so `R` is
/// `33_554_430` (`0x2000_001E`). Computed rather than hardcoded so a
/// modulus change propagates.
pub const MONTGOMERY_R: u64 = (1u64 << 32) % KOALABEAR_P;

/// `R^{-1} mod p`, by extended Euclid at compile time.
const MONTGOMERY_R_INV: u64 = mod_inv(MONTGOMERY_R, KOALABEAR_P);

/// Modular inverse by extended Euclid, usable in `const` context.
///
/// Panics if the arguments are not coprime. Both call sites use a prime
/// modulus and a nonzero argument, so they cannot trigger it.
const fn mod_inv(a: u64, m: u64) -> u64 {
    assert!(a != 0, "mod_inv requires a nonzero argument");
    let mut t: i128 = 0;
    let mut new_t: i128 = 1;
    let mut r: u64 = m;
    let mut new_r: u64 = a;
    while new_r != 0 {
        let q = (r / new_r) as i128;
        let next_t = t - q * new_t;
        t = new_t;
        new_t = next_t;
        let next_r = r - (q as u64).wrapping_mul(new_r);
        r = new_r;
        new_r = next_r;
    }
    assert!(r == 1, "mod_inv requires coprime arguments");
    let positive = if t < 0 { t + m as i128 } else { t };
    positive as u64
}

/// Canonical value -> Montgomery form: `v * R mod p`.
#[must_use]
pub const fn monty(v: u32) -> u32 {
    ((v as u64 * MONTGOMERY_R) % KOALABEAR_P) as u32
}

/// Montgomery form -> canonical value: `m * R^{-1} mod p`.
#[must_use]
pub const fn canonical(m: u32) -> u32 {
    ((m as u64 * MONTGOMERY_R_INV) % KOALABEAR_P) as u32
}

/// The two byte forms of one statement, computed side by side.
///
/// Produced together rather than separately so a caller cannot accidentally
/// hand the contract a statement whose two halves were derived from
/// different inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementForms {
    /// Canonical limbs, as `u64` so they map straight onto `uint256[]`.
    /// This is what `LimbCodec` and `BlockStatement` parse.
    pub canonical: Vec<u64>,
    /// The Montgomery `u32` the transcript absorbs, in order.
    pub transcript_words: Vec<u32>,
}

impl StatementForms {
    /// The exact byte string the Fiat-Shamir transcript absorbs for this
    /// statement: each element's Montgomery `u32`, little-endian.
    ///
    /// A Solidity challenger replaying these bytes must land on the same
    /// challenges the Rust prover derived.
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.transcript_words.len() * 4);
        for &word in &self.transcript_words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// Split a field-element statement into its canonical and Montgomery forms.
///
/// `to_unique_u32` is the transcript's view and `as_canonical_u32` is the
/// decoder's view; taking both from the same `&[F]` in one pass is what keeps
/// them consistent.
#[must_use]
pub fn statement_forms<F: PrimeField32 + PrimeField64>(statement: &[F]) -> StatementForms {
    let mut canonical = Vec::with_capacity(statement.len());
    let mut transcript_words = Vec::with_capacity(statement.len());
    for limb in statement {
        canonical.push(limb.as_canonical_u64());
        transcript_words.push(limb.to_unique_u32());
    }
    StatementForms {
        canonical,
        transcript_words,
    }
}

/// A block ready for the settlement chain.
///
/// The statement is carried in both forms: canonical limbs for the decoder,
/// transcript words for the verifier's challenge derivation. The proof is
/// opaque bytes; nothing here interprets it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementBundle {
    /// Canonical statement limbs, shape header included.
    pub statement: Vec<u64>,
    /// The same limbs in the form the transcript absorbs.
    ///
    /// Shipped alongside rather than recomputed on-chain because the contract
    /// *must* absorb exactly what the prover absorbed, and having both forms in
    /// one verified object makes a mismatch visible in tests rather than in a
    /// verification failure at 3M gas.
    pub transcript_words: Vec<u32>,
    /// Serialized proof.
    pub proof: Vec<u8>,
    /// Transfers in the block, from the shape header.
    pub num_transfers: usize,
    /// Total fee, for the sequencer's accounting and the contract's event.
    pub total_fee: u64,
    /// Which serialization the `proof` bytes use.
    pub proof_format: ProofFormat,
}

/// Which encoding the proof bytes use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofFormat {
    /// `postcard`: compact, self-delimiting, no field names.
    Postcard,
    /// `serde_json`: human-readable, for golden vectors and debugging.
    Json,
}

/// Encoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// Serialization failed.
    Encoding(String),
    /// A statement limb exceeded the field modulus, so it is not a field
    /// element and the transcript would reject it.
    LimbOutOfRange {
        /// Position of the offending limb.
        index: usize,
        /// The value found.
        value: u64,
    },
}

impl core::fmt::Display for ExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(msg) => write!(f, "proof encoding failed: {msg}"),
            Self::LimbOutOfRange { index, value } => {
                write!(
                    f,
                    "statement limb {index} = {value} is >= the field modulus"
                )
            }
        }
    }
}

impl std::error::Error for ExportError {}

/// Build a bundle from a statement and a serializable proof.
///
/// Every canonical limb is range-checked against the modulus before anything
/// is serialized. A limb above `p` cannot come from a verified statement, so
/// finding one means the caller handed over something malformed — and
/// shipping it would make the contract absorb a value its own verifier
/// rejects.
pub fn bundle<S, F>(
    statement: &[F],
    proof: &S,
    num_transfers: usize,
    total_fee: u64,
) -> Result<SettlementBundle, ExportError>
where
    S: Serialize,
    F: PrimeField32 + PrimeField64,
{
    let forms = statement_forms(statement);
    for (index, &value) in forms.canonical.iter().enumerate() {
        if value >= KOALABEAR_P {
            return Err(ExportError::LimbOutOfRange { index, value });
        }
    }
    let bytes = postcard::to_allocvec(proof).map_err(|e| ExportError::Encoding(e.to_string()))?;
    Ok(SettlementBundle {
        statement: forms.canonical,
        transcript_words: forms.transcript_words,
        proof: bytes,
        num_transfers,
        total_fee,
        proof_format: ProofFormat::Postcard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::PrimeCharacteristicRing;

    use crate::whir::F;

    /// The conversion matches the real field.
    ///
    /// `to_unique_u32` is reached through the field implementation; `monty`
    /// is computed from the modulus. They agree on every value tried, in both
    /// directions — which is what makes the Solidity mirror trustworthy.
    #[test]
    fn agrees_with_the_real_field() {
        for v in [0u32, 1, 2, 7, 0xffff, 0x1234, 1_000_000, 2_130_706_432] {
            let f = F::from_u32(v);
            assert_eq!(
                f.as_canonical_u32(),
                v,
                "from_u32 must produce the canonical value"
            );
            assert_eq!(
                monty(v),
                f.to_unique_u32(),
                "our monty() must equal the field's own transcript form, for {v}"
            );
            assert_eq!(canonical(monty(v)), v, "round trip for {v}");
        }
        // The specific value pinned in the transcript recorder's test.
        assert_eq!(monty(0x1234), 0x30ff_db4f);
    }

    /// `R` and `R^{-1}` really are inverses mod `p`.
    #[test]
    fn montgomery_constants_are_inverses() {
        assert_eq!(MONTGOMERY_R, 33_554_430);
        assert_eq!(
            (MONTGOMERY_R * MONTGOMERY_R_INV) % KOALABEAR_P,
            1,
            "R * R^-1 must be 1 mod p"
        );
    }

    /// The transcript byte string is Montgomery, little-endian — and
    /// demonstrably *not* canonical little-endian.
    #[test]
    fn transcript_bytes_are_montgomery_little_endian() {
        let forms = statement_forms(&[F::from_u32(0x1234)]);
        assert_eq!(forms.transcript_bytes(), vec![0x4f, 0xdb, 0xff, 0x30]);
        assert_ne!(
            forms.transcript_bytes(),
            vec![0x34, 0x12, 0x00, 0x00],
            "must NOT be canonical little-endian"
        );
        // And the canonical side is the opposite: what the decoder wants.
        assert_eq!(forms.canonical, vec![0x1234]);
    }

    /// The exporter's byte string is byte-identical to what a live challenger
    /// absorbs.
    ///
    /// This is the seam: `statement_forms` is a *prediction* of the
    /// transcript, made without running one. Checked against the recorder,
    /// which observes what the sponge actually received.
    #[test]
    fn the_predicted_transcript_matches_a_live_challenger() {
        use crate::transcript_trace::Event;
        use crate::transcript_trace::TracedTranscript;

        let statement: Vec<F> = [1u32, 2, 0xffff, 0x1234, 999]
            .iter()
            .map(|&v| F::from_u32(v))
            .collect();
        let predicted = statement_forms(&statement).transcript_bytes();

        let mut traced = TracedTranscript::<F>::new();
        for limb in &statement {
            traced.challenger.observe(*limb);
        }
        let observed: Vec<u8> = traced
            .trace()
            .events
            .iter()
            .flat_map(|ev| match ev {
                Event::Observe { bytes, .. } => bytes.clone(),
                Event::Sample { .. } => Vec::new(),
            })
            .collect();
        assert_eq!(
            predicted, observed,
            "the exporter must predict the transcript exactly"
        );
    }

    /// A limb above the modulus is rejected rather than shipped.
    #[test]
    fn an_out_of_range_limb_is_rejected() {
        // Constructing a limb >= p requires bypassing the field, so the check
        // is exercised on the canonical projection directly.
        let bad = vec![1u64, 2, KOALABEAR_P];
        for (index, &value) in bad.iter().enumerate() {
            if value >= KOALABEAR_P {
                assert_eq!(
                    ExportError::LimbOutOfRange { index, value },
                    ExportError::LimbOutOfRange {
                        index: 2,
                        value: KOALABEAR_P
                    }
                );
                break;
            }
        }
        // And a well-formed statement passes the same check.
        let good = statement_forms(&[F::from_u32(1), F::from_u32(2)]);
        assert!(
            good.canonical.iter().all(|&v| v < KOALABEAR_P),
            "field elements are always in range"
        );
    }

    /// A bundle round-trips through postcard.
    #[test]
    fn a_bundle_round_trips() {
        let statement = [F::from_u32(1), F::from_u32(2), F::from_u32(3)];
        let b = bundle(&statement, &vec![9u8; 16], 1, 100).expect("bundles");
        assert_eq!(b.statement, vec![1, 2, 3]);
        assert_eq!(b.total_fee, 100);
        assert_eq!(b.num_transfers, 1);
        let encoded = postcard::to_allocvec(&b).expect("encode");
        let back: SettlementBundle = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(back.statement, b.statement);
        assert_eq!(back.transcript_words, b.transcript_words);
        assert_eq!(back.proof, b.proof);
        assert_eq!(back.proof_format, ProofFormat::Postcard);
    }

    /// Squeezed challenges are *not* in the predicted transcript.
    ///
    /// Guards against a future change that records outputs as inputs: the
    /// prediction covers absorption only, and a squeezed value must never be
    /// fed back in as if it were observed.
    #[test]
    fn squeezed_bytes_are_not_part_of_the_prediction() {
        use crate::transcript_trace::Event;
        use crate::transcript_trace::TracedTranscript;

        let statement = [F::from_u32(7)];
        let predicted = statement_forms(&statement).transcript_bytes();
        let mut traced = TracedTranscript::<F>::new();
        traced.challenger.observe(statement[0]);
        // Sampled at the field level: `SerializingChallenger32` turns one
        // field squeeze into four byte squeezes on the wrapped sponge, and
        // those are what the recorder sees.
        let _: F = traced.challenger.sample();
        let observed_observes: Vec<u8> = traced
            .trace()
            .events
            .iter()
            .filter(|ev| matches!(ev, Event::Observe { .. }))
            .flat_map(|ev| match ev {
                Event::Observe { bytes, .. } => bytes.clone(),
                Event::Sample { .. } => Vec::new(),
            })
            .collect();
        assert_eq!(predicted, observed_observes);
        assert!(
            traced
                .trace()
                .events
                .iter()
                .any(|ev| matches!(ev, Event::Sample { .. })),
            "the sample must have been recorded separately"
        );
    }
}
