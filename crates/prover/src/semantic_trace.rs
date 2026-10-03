//! A semantic transcript recorder: what the protocol ASKS the transcript for.
//!
//! # Why a second recorder, when a byte-level one already exists
//!
//! `transcript_trace` records every byte absorbed and squeezed. That is the right
//! level for checking the sponge and the wrong level for reading the protocol,
//! because it sits BELOW rejection sampling. Two protocol operations become
//! indistinguishable there:
//!
//! ```text
//!   sample::<F>()     draws 4 bytes, masks to 31 bits, retries while >= P
//!   sample_bits(4)    draws 4 bytes, masks to 4 bits,  never retries
//! ```
//!
//! Both consume four bytes. Nothing in the byte stream says which happened, so any
//! attempt to recover a per-site element count from recorded bytes is guessing. That
//! is not a defect of the byte recorder; it follows from where it sits, and it is why
//! pinning the transcript by byte counts failed (decision D-054 and its addendum).
//!
//! # What this records instead
//!
//! The protocol's own vocabulary, at the `FieldChallenger` boundary that `p3-whir`
//! is written against: observe a base element, observe a commitment digest, sample an
//! extension-field challenge, sample k bits, grind for a proof-of-work witness.
//!
//! Rejection sampling happens INSIDE `sample`, so it is invisible here, which is the
//! point. The result is the program a verifier must execute, and unlike the byte
//! stream it is fixed by the configuration and the proof SHAPE rather than by the
//! proof VALUE. The tests assert exactly that.
//!
//! # Delegation, never reimplementation
//!
//! Every method forwards to the wrapped challenger, which is the production
//! `SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256Hash, 32>>`. This
//! type adds no sampling or serialisation logic, so it cannot drift from the
//! transcript it describes, and the byte stream underneath stays bit-identical to
//! production: a proof recorded through this wrapper still verifies untraced.
//!
//! It is concrete over the settlement config's types rather than generic. A generic
//! wrapper over `CanObserve<Hash<F, u8, N>>` and friends collides with the blanket
//! `&mut C` impls in `p3-challenger`, and working around that means re-implementing
//! dispatch, which is the one thing a recorder must not do.
//!
//! # Grinding
//!
//! Grinding forwards to the inner `grind`, which searches over clones. Rejected
//! candidates never reach the transcript, so they never reach this log; only the
//! accepted witness is recorded.

use crate::config::F;
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError, SerializingChallenger32,
};
use p3_field::{BasedVectorSpace, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleCap;
use p3_symmetric::Hash;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, PoisonError};

/// The challenger this recorder wraps: production, exactly.
pub type Production = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

/// A commitment digest as absorbed by the transcript.
pub type Digest = Hash<F, u8, 32>;

/// One protocol-level transcript operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemEvent {
    /// Absorbed one base field element.
    ///
    /// Recorded as `to_unique_u32`, the internal Montgomery form, because that is
    /// literally what goes into the sponge: p3 observes the little-endian bytes of
    /// `value.to_unique_u32()`. Sampling is the reverse case - the sponge hands out a
    /// raw masked sample, so `SampleBase` is canonical. The asymmetry is real, and
    /// each side is recorded in the form a verifier has to reproduce.
    ObserveBase {
        /// Wire form, matching the absorbed bytes.
        value: u32,
    },
    /// Absorbed raw bytes: a commitment digest, or a Merkle cap's digests concatenated.
    ///
    /// A cap is recorded as its concatenated roots because those are the bytes the
    /// on-chain verifier absorbs; the cap width follows from the length.
    ObserveBytes {
        /// The bytes absorbed, in order.
        bytes: Vec<u8>,
    },
    /// Sampled base field elements, one entry per `sample` call.
    ///
    /// An extension-field challenge appears as one event carrying `DIMENSION`
    /// coefficients rather than as a run of indistinguishable single draws.
    SampleBase {
        /// Canonical values, in basis-coefficient order.
        values: Vec<u32>,
    },
    /// Sampled `bits` uniformly random bits, yielding `value`.
    ///
    /// Distinct from `SampleBits`: this is the uniform-bit path, whose acceptance
    /// bound is the field order masked below the requested width, and above the field
    /// single-sample bit limit it draws TWO field elements internally. STIR query
    /// indices come from here.
    SampleUniformBits {
        /// Bits requested.
        bits: usize,
        /// Value drawn.
        value: usize,
    },
    /// Sampled `bits` random bits, yielding `value`.
    SampleBits {
        /// Bits requested.
        bits: usize,
        /// Value drawn, always below `1 << bits`.
        value: usize,
    },
    /// Verified a proof-of-work witness: squeeze, absorb it, read `bits` bits, require zero.
    ///
    /// This is the verifier's side of grinding and the event the settlement contract
    /// must reproduce. The squeeze is part of it: `SerializingChallenger32` overrides
    /// `check_witness` to flush the output buffer first, so the candidate is hashed
    /// against a digest of the transcript rather than its pending input.
    CheckWitness {
        /// Difficulty in bits.
        bits: usize,
        /// The witness the proof carried, canonical.
        witness: u32,
        /// Whether it passed. Always true in an accepting run.
        ok: bool,
    },
    /// Ground for `bits` proof-of-work bits and accepted `witness`.
    ///
    /// The verifier's side is `check_witness`: absorb the witness, then sample
    /// `bits` bits and require zero. Those two steps are what the default
    /// `check_witness` is written in terms of, so they appear in the log on their
    /// own; this event marks where the prover ground.
    Grind {
        /// Difficulty in bits.
        bits: usize,
        /// Accepted witness, canonical.
        witness: u32,
    },
}

/// The recorded semantic program.
pub type SemProgram = Vec<SemEvent>;

/// Shared, cloneable log that `SemChallenger` writes into.
#[derive(Clone, Default, Debug)]
pub struct SemSink(Arc<Mutex<SemProgram>>);

impl SemSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of everything recorded so far.
    pub fn program(&self) -> SemProgram {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn push(&self, event: SemEvent) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

/// Wraps the production challenger and logs protocol-level operations.
#[derive(Clone, Debug)]
pub struct SemChallenger {
    inner: Production,
    sink: SemSink,
}

impl SemChallenger {
    /// Wrap `inner`, logging into `sink`.
    #[must_use]
    pub const fn new(inner: Production, sink: SemSink) -> Self {
        Self { inner, sink }
    }
}

impl CanObserve<F> for SemChallenger {
    fn observe(&mut self, value: F) {
        self.sink.push(SemEvent::ObserveBase {
            value: value.to_unique_u32(),
        });
        self.inner.observe(value);
    }
}

impl CanObserve<Digest> for SemChallenger {
    fn observe(&mut self, value: Digest) {
        self.sink.push(SemEvent::ObserveBytes {
            bytes: value.as_ref().to_vec(),
        });
        self.inner.observe(value);
    }
}

impl CanObserve<MerkleCap<F, [u8; 32]>> for SemChallenger {
    fn observe(&mut self, value: MerkleCap<F, [u8; 32]>) {
        self.observe_cap(&value);
        self.inner.observe(value);
    }
}

impl CanObserve<&MerkleCap<F, [u8; 32]>> for SemChallenger {
    fn observe(&mut self, value: &MerkleCap<F, [u8; 32]>) {
        self.observe_cap(value);
        self.inner.observe(value);
    }
}

impl SemChallenger {
    /// Record a cap as its concatenated roots.
    fn observe_cap(&self, cap: &MerkleCap<F, [u8; 32]>) {
        let bytes: Vec<u8> = cap.roots().iter().flatten().copied().collect();
        self.sink.push(SemEvent::ObserveBytes { bytes });
    }
}
/// Sampling, for every value the protocol draws: base elements (degree 1), the
/// quintic challenge field, and the quartic extension WHIR folds query answers
/// into. One impl covers all degrees because the degree is exactly the basis
/// dimension, which is what makes each event self-describing.
impl<EF> CanSample<EF> for SemChallenger
where
    EF: BasedVectorSpace<F>,
{
    fn sample(&mut self) -> EF {
        let value: EF = self.inner.sample();
        let coeffs = <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value);
        // Canonical, not the internal Montgomery form. The sponge hands out a raw
        // masked sample and p3 turns it into a field element, so the canonical value
        // IS what the transcript produced; Montgomery is an arithmetic detail of the
        // field implementation. An on-chain sampler returns the same raw value, so
        // recording canonical is what lets a verifier compare without knowing the
        // Montgomery constant. Observing is the opposite case: p3 absorbs the
        // Montgomery bytes, so ObserveBase stays in wire form.
        let values: Vec<u32> = coeffs.iter().map(PrimeField32::as_canonical_u32).collect();
        self.sink.push(SemEvent::SampleBase { values });
        value
    }
}

impl CanSampleBits<usize> for SemChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        let value = self.inner.sample_bits(bits);
        self.sink.push(SemEvent::SampleBits { bits, value });
        value
    }
}

impl CanSampleUniformBits<F> for SemChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        // Recorded as its own operation. STIR query indices are drawn this way, so a
        // verifier that skipped it would desynchronise immediately. No double count:
        // the inner sampler calls the INNER sample_bits, which is not this impl.
        let value = self.inner.sample_uniform_bits::<RESAMPLE>(bits)?;
        self.sink.push(SemEvent::SampleUniformBits { bits, value });
        Ok(value)
    }
}

impl GrindingChallenger for SemChallenger {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        let witness = self.inner.grind(bits);
        self.sink.push(SemEvent::Grind {
            bits,
            witness: witness.to_unique_u32(),
        });
        witness
    }

    /// Forwarded, NOT inherited.
    ///
    /// The trait default is `observe(witness); sample_bits(bits) == 0`, but
    /// `SerializingChallenger32` OVERRIDES it to squeeze the pending output buffer
    /// first, so every proof-of-work candidate is hashed against a digest
    /// of the transcript rather than its pending input. Inheriting the default would
    /// skip that squeeze, desynchronise the sponge, and make a valid proof fail
    /// `InvalidPowWitness` — which is precisely how this was caught.
    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        let ok = self.inner.check_witness(bits, witness);
        self.sink.push(SemEvent::CheckWitness {
            bits,
            witness: witness.to_unique_u32(),
            ok,
        });
        ok
    }
}

impl FieldChallenger<F> for SemChallenger {}
