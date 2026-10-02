//! A byte-level transcript recorder, so an independent implementation can be
//! checked against the real verifier draw for draw.
//!
//! # Why this exists
//!
//! The settlement contract must reproduce our Fiat-Shamir transcript using
//! the native `keccak256` opcode. Every challenge the Solidity side derives
//! has to match what `p3-whir` derived, byte for byte. A mismatch that
//! happens to pass would be a soundness bug, so "the verifier accepts" is
//! not enough of a check.
//!
//! Comparing two implementations only at the *end* establishes nothing: both
//! could be wrong in the same way, or a wrong transcript could satisfy the
//! final identity by luck. The only check that means something is at the
//! finest granularity available — **every byte absorbed and every byte
//! squeezed, in order**.
//!
//! # Why the byte level, and why wrapping rather than reimplementing
//!
//! A Fiat-Shamir transcript is a state machine over one primitive: absorb
//! bytes, squeeze bytes. Everything else — field elements, digests, Merkle
//! caps, `PoW` witnesses — is a serialization choice layered on top.
//!
//! So this recorder implements only the *byte* traits, and the traced
//! challenger is
//!
//! ```text
//!   SerializingChallenger32<F, TraceChallenger<HashChallenger<u8, Keccak256Hash, 32>>>
//! ```
//!
//! Field-level observe and sample are handled by p3's own
//! `SerializingChallenger32`, which routes every one of them down through
//! this byte recorder. That matters twice over: the recorder cannot drift
//! from the serialization it is meant to be checking, because it never
//! re-implements it; and the trace it produces is exactly the byte stream
//! the on-chain verifier must reproduce.
//!
//! # Grinding is recorded as one event, not thousands
//!
//! Proof-of-work clones the challenger per candidate. Recording each attempt
//! would flood the trace with rejected work that never reaches the
//! transcript. `ByteGrindingChallenger` is therefore implemented by
//! delegating the search to the inner challenger, so rejected candidates
//! bypass the recorder entirely. The events that *do* land in the trace are
//! the ones the outer verifier performs on the real transcript: the squeeze,
//! the accepted witness, and the bits read back.
//!
//! # Method provenance
//!
//! This mirrors `GOATNetwork/bitcoin-stark-verifier`, which logs Plonky3's
//! own verifier's observe/sample sequence with a recording challenger and
//! checks its Bitcoin Script implementation against that log rather than
//! against a hand-written reference. Their reasoning, quoted: "every other
//! test compares a script against a Rust reference, which establishes that
//! the two agree — not that either is right." Logging what the real verifier
//! actually does is what closes that gap.

use p3_challenger::{ByteGrindingChallenger, CanObserve, CanSample};
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, PoisonError};

/// One recorded transcript event.
///
/// Only two kinds exist because a transcript only does two things.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// Bytes absorbed into the transcript.
    Observe {
        /// A human-readable tag, when the caller supplied one. The challenger
        /// traits carry no names, so tags are pushed in from outside; a trace
        /// without tags is hard to read against a verifier's source.
        tag: Option<String>,
        /// The exact bytes absorbed, in order.
        bytes: Vec<u8>,
    },
    /// Bytes squeezed out of the transcript.
    Sample {
        /// A human-readable tag, when the caller supplied one.
        tag: Option<String>,
        /// The exact bytes squeezed, in order.
        bytes: Vec<u8>,
    },
}

/// The full recorded sequence.
///
/// This is the golden vector. The Solidity verifier is correct when it
/// replays the same sequence and lands on the same values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptTrace {
    /// Every event, in the order it happened.
    pub events: Vec<Event>,
}

impl TranscriptTrace {
    /// Number of recorded events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// A readable rendering, one event per line.
    ///
    /// Bytes are shown as hex so the trace can be diffed against a Solidity
    /// `emit` of the same sequence.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (i, ev) in self.events.iter().enumerate() {
            let (verb, tag, bytes) = match ev {
                Event::Observe { tag, bytes } => ("observe", tag, bytes),
                Event::Sample { tag, bytes } => ("sample", tag, bytes),
            };
            let hex: String =
                bytes
                    .iter()
                    .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
                        use std::fmt::Write as _;
                        let _ = write!(acc, "{b:02x}");
                        acc
                    });
            let label = tag.as_deref().unwrap_or("-");
            let _ = writeln!(out, "{i:>4} {verb:<8} {label:<28} {hex}");
        }
        out
    }
}

/// A shared, append-only trace sink.
///
/// Shared through `Arc<Mutex<..>>` so a challenger can be cloned — which
/// grinding does many times — while every clone appends to one trace. `Arc`
/// rather than `Rc` because the prover is parallel: `ByteGrindingChallenger`
/// requires `Send + Sync`, and a non-thread-safe sink would not satisfy it.
#[derive(Clone, Default, Debug)]
pub struct TraceSink(Arc<Mutex<TranscriptTrace>>);

impl TraceSink {
    /// A fresh, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the trace recorded so far.
    ///
    /// A poisoned lock is recovered rather than panicked on. The trace is
    /// diagnostic data, not consensus state: `Vec::push` is panic-safe, so
    /// a panic elsewhere while the lock was held cannot have left a
    /// half-recorded event. Losing the trace to a panic in unrelated code
    /// would be worse than reading it.
    #[must_use]
    pub fn trace(&self) -> TranscriptTrace {
        let guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        guard.clone()
    }
}

/// A byte-level challenger decorator that records every absorb and squeeze.
///
/// Wrap it *under* `SerializingChallenger32` rather than over a field-level
/// challenger: see the module docs for why the byte level is the correct
/// seam.
pub struct TraceChallenger<Inner> {
    inner: Inner,
    sink: TraceSink,
    tag: Option<String>,
}

// `Debug` is implemented by hand rather than derived: the inner challenger is
// a sponge whose state is not interesting here, and requiring `Inner: Debug`
// would push that bound onto every consumer of the recorder.
impl<Inner> core::fmt::Debug for TraceChallenger<Inner> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TraceChallenger")
            .field("sink", &self.sink)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl<Inner: Clone> Clone for TraceChallenger<Inner> {
    /// Cloning shares the sink (so the trace stays one stream) and clones the
    /// inner challenger. The pending tag is deliberately **not** carried over:
    /// a clone is a different observation site, and letting one tag label
    /// events in two challengers would make the trace ambiguous.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sink: self.sink.clone(),
            tag: None,
        }
    }
}

impl<Inner> TraceChallenger<Inner> {
    /// Wrap `inner`, appending every event to `sink`.
    #[must_use]
    pub const fn new(inner: Inner, sink: TraceSink) -> Self {
        Self {
            inner,
            sink,
            tag: None,
        }
    }

    /// The sink this recorder writes to.
    #[must_use]
    pub const fn sink(&self) -> &TraceSink {
        &self.sink
    }

    /// Tag the next recorded event.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    fn record(&self, event: Event) {
        // See `TraceSink::trace` for why poisoning is recovered.
        let mut guard = self.sink.0.lock().unwrap_or_else(PoisonError::into_inner);
        guard.events.push(event);
    }

    const fn take_tag(&mut self) -> Option<String> {
        self.tag.take()
    }
}

impl<Inner: CanObserve<u8>> CanObserve<u8> for TraceChallenger<Inner> {
    fn observe(&mut self, value: u8) {
        let tag = self.take_tag();
        self.record(Event::Observe {
            tag,
            bytes: vec![value],
        });
        self.inner.observe(value);
    }

    fn observe_slice(&mut self, values: &[u8]) {
        let tag = self.take_tag();
        self.record(Event::Observe {
            tag,
            bytes: values.to_vec(),
        });
        self.inner.observe_slice(values);
    }
}

impl<Inner: CanSample<u8>> CanSample<u8> for TraceChallenger<Inner> {
    fn sample(&mut self) -> u8 {
        // Sample first, then record: the recorded value must be the one the
        // caller actually received, so a divergence between recorder and
        // sponge cannot hide.
        let value = self.inner.sample();
        let tag = self.take_tag();
        self.record(Event::Sample {
            tag,
            bytes: vec![value],
        });
        value
    }
}

impl<Inner: ByteGrindingChallenger> ByteGrindingChallenger for TraceChallenger<Inner> {
    /// Run the proof-of-work search on the inner challenger, unrecorded.
    ///
    /// The default implementation clones `self` per candidate and records
    /// each attempt, which would put every rejected witness in the trace.
    /// Those bytes never reach the real transcript — only the accepted
    /// witness does, and the outer verifier absorbs it through the ordinary
    /// `observe` path. Delegating keeps the trace to what actually happened.
    fn find_witness<const W: usize, const S: usize>(
        &self,
        num_candidates: u64,
        encode: impl Fn(u64) -> [u8; W] + Sync,
        accepts: impl Fn([u8; S]) -> bool + Sync,
    ) -> Option<u64> {
        self.inner.find_witness(num_candidates, encode, accepts)
    }
}

/// The Keccak sponge our settlement transcript runs on.
type KeccakSponge = p3_challenger::HashChallenger<u8, p3_keccak::Keccak256Hash, 32>;

/// A traced Keccak challenger over `F`, with the sink kept alongside.
///
/// `SerializingChallenger32` owns its inner challenger and exposes no
/// accessor, so the [`TraceSink`] is handed out at construction. The sink
/// is `Arc`-shared, so cloning the challenger keeps appending to the same
/// trace and the handle still sees it.
#[derive(Debug)]
pub struct TracedTranscript<F> {
    /// The challenger to hand to a prover or verifier.
    pub challenger: p3_challenger::SerializingChallenger32<F, TraceChallenger<KeccakSponge>>,
    sink: TraceSink,
}

impl<F: PrimeField32> TracedTranscript<F> {
    /// A traced challenger over `F`, starting from an empty transcript.
    #[must_use]
    pub fn new() -> Self {
        let sink = TraceSink::new();
        let inner = TraceChallenger::new(
            p3_challenger::HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}),
            sink.clone(),
        );
        Self {
            challenger: p3_challenger::SerializingChallenger32::<F, _>::new(inner),
            sink,
        }
    }

    /// The trace recorded so far.
    #[must_use]
    pub fn trace(&self) -> TranscriptTrace {
        self.sink.trace()
    }
}

impl<F: PrimeField32> Default for TracedTranscript<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    use crate::whir_recursion::F;

    type Traced = p3_challenger::SerializingChallenger32<F, TraceChallenger<KeccakSponge>>;

    /// The recorder on its own, for tests that exercise raw bytes.
    ///
    /// `SerializingChallenger32` deliberately implements `CanObserve<F>` and
    /// not `CanObserve<u8>` — it is the field/byte boundary — so byte-level
    /// behaviour has to be tested against the recorder directly.
    fn traced_recorder(sink: TraceSink) -> TraceChallenger<KeccakSponge> {
        TraceChallenger::new(
            p3_challenger::HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}),
            sink,
        )
    }

    /// Build a traced challenger and return it with its sink, so tests can
    /// read the trace without reaching through the wrapper.
    fn traced() -> (Traced, TraceSink) {
        let sink = TraceSink::new();
        let inner = TraceChallenger::new(
            p3_challenger::HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}),
            sink.clone(),
        );
        (
            p3_challenger::SerializingChallenger32::<F, _>::new(inner),
            sink,
        )
    }

    /// The recorder must be transparent: wrapping cannot change the values
    /// the challenger produces.
    ///
    /// If wrapping perturbed the sponge, the trace would describe a
    /// different transcript than the real one and every downstream check
    /// would be meaningless.
    #[test]
    fn wrapping_does_not_change_the_transcript() {
        let mut plain = p3_challenger::SerializingChallenger32::<F, _>::new(
            p3_challenger::HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}),
        );
        let (mut traced_ch, _sink) = traced();

        for i in 0..8u32 {
            let v = F::from_u32(i);
            plain.observe(v);
            traced_ch.observe(v);
        }
        let plain_samples: Vec<F> = (0..8).map(|_| plain.sample()).collect();
        let traced_samples: Vec<F> = (0..8).map(|_| traced_ch.sample()).collect();
        assert_eq!(
            plain_samples, traced_samples,
            "the recorder must be transparent to the sponge"
        );
    }

    /// Field elements reach the trace as **Montgomery-form** little-endian
    /// `u32`, not canonical form.
    ///
    /// This is the single most important anti-drift fact in the file, and it
    /// is easy to get wrong. `SerializingChallenger32::observe` serializes
    /// with `to_unique_u32()`, which for a Monty field returns the *raw
    /// internal* representation — the value already multiplied by
    /// `R = 2^32 mod p`. It is deliberately not canonicalized: hashing the
    /// internal form is unique per field element and avoids a reduction on
    /// the hot path.
    ///
    /// Consequence for the Solidity mirror: `KeccakChallenger.observeBase`
    /// must be fed the Montgomery-form limb, and the exporter must emit
    /// Montgomery-form values. Feeding canonical values would produce a
    /// different transcript and a verifier that accepts nothing — or, if
    /// both sides were wrong the same way, one that accepts too much.
    #[test]
    fn field_observes_are_recorded_as_montgomery_little_endian_u32() {
        // R = 2^32 mod p, computed independently of the field crate.
        const P: u64 = 2_130_706_433; // KoalaBear
        let (mut challenger, sink) = traced();
        let value = F::from_u16(0x1234);
        challenger.observe(value);
        let trace = sink.trace();
        assert_eq!(trace.events.len(), 1, "one observe records one event");

        let r = 1u64.rotate_left(32) % P;
        let expected = (u64::from(0x1234_u32) * r % P) as u32;

        match &trace.events[0] {
            Event::Observe { bytes, .. } => {
                assert_eq!(bytes, &expected.to_le_bytes());
                // And it is *not* the canonical serialization, so a future
                // "fix" to canonical form cannot pass this test silently.
                assert_ne!(bytes, &0x1234u32.to_le_bytes());
            }
            Event::Sample { .. } => panic!("expected an observe event, got a sample"),
        }
    }

    /// Sampling a field element must record the bytes the caller got, not
    /// something reconstructed after the fact.
    ///
    /// The direction here is the mirror image of `observe`. The sampler
    /// reads 4 raw bytes, masks them to `2^ceil(log2(p)) - 1`, and rejects
    /// until the masked value is below the modulus, constructing with
    /// `from_canonical_unchecked`. The recorder sits *below* the mask, so
    /// the recorded bytes are the raw stream: `raw & mask == canonical`,
    /// not necessarily `raw == canonical`. Pinning the exact relationship
    /// (including the mask) is what makes this usable as a Solidity golden
    /// vector.
    #[test]
    fn field_samples_record_the_bytes_actually_returned() {
        // KoalaBear: ORDER ~ 2^31, so the sampler masks with 0x7fff_ffff.
        const SAMPLE_MASK: u32 = 0x7fff_ffff;
        let (mut challenger, sink) = traced();
        challenger.observe(F::from_u32(7));
        let value: F = challenger.sample();
        let trace = sink.trace();

        // `sample_array::<4>` reads four individual bytes, so the recorder
        // sees four 1-byte `Sample` events, not one 4-byte event. The last
        // four are the accepted read: rejection sampling pushes any
        // discarded group earlier in the stream.
        let singles: Vec<u8> = trace
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Sample { bytes, .. } if bytes.len() == 1 => Some(bytes[0]),
                _ => None,
            })
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        assert_eq!(singles.len(), 4, "a base field element is 4 sampled bytes");
        let raw = u32::from_le_bytes(singles.try_into().expect("4 bytes"));
        assert_eq!(
            raw & SAMPLE_MASK,
            value.as_canonical_u32(),
            "masked raw stream bytes must equal the canonical value the caller received"
        );
    }

    /// Grinding must not pollute the trace with rejected candidates.
    ///
    /// A 6-bit grind tests up to 64 candidates per word read; the search
    /// touches the sponge many times. If the default `find_witness` were
    /// used, the trace would grow with the search rather than with the
    /// transcript.
    #[test]
    fn grinding_records_only_the_accepted_witness_path() {
        let (mut challenger, sink) = traced();
        challenger.observe(F::from_u32(0x99));
        let before = sink.trace().len();
        let witness = GrindingChallenger::grind(&mut challenger, 6);
        let added = sink.trace().len() - before;
        assert!(
            added <= 16,
            "grinding added {added} events; rejected candidates are leaking into the trace"
        );
        // And the witness is real: checking it against a fresh copy of the
        // same pre-grind state must pass.
        let (mut fresh, _s) = traced();
        fresh.observe(F::from_u32(0x99));
        assert!(
            GrindingChallenger::check_witness(&mut fresh, 6, witness),
            "the accepted witness must verify against the same transcript state"
        );
    }

    /// The rendered trace is readable enough to diff by hand against a
    /// Solidity `emit` of the same sequence.
    #[test]
    fn trace_renders() {
        let sink = TraceSink::new();
        let mut inner = traced_recorder(sink.clone()).with_tag("commitment");
        inner.observe(0xabu8);
        let rendered = sink.trace().render();
        assert!(rendered.contains("observe"));
        assert!(rendered.contains("commitment"));
        assert!(rendered.contains("ab"));
    }

    /// The trace must survive serialization, because the golden vectors are
    /// written to disk and consumed by the Solidity test suite.
    #[test]
    fn trace_serializes() {
        let sink = TraceSink::new();
        let mut inner = traced_recorder(sink.clone()).with_tag("x");
        inner.observe(1u8);
        let trace = sink.trace();
        let json = serde_json::to_string(&trace).expect("serialize");
        let back: TranscriptTrace = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trace, back);
    }
}
