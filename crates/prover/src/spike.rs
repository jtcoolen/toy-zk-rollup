//! Spike: prove + verify a Fibonacci STARK over the Keccak transcript.
//!
//! This exists to confirm one load-bearing fact before we build the real circuit
//! and the Solidity verifier on top of it: **a Keccak-256 Fiat-Shamir transcript
//! drives `p3_uni_stark::prove`/`verify` on `KoalaBear`.** If it does, the
//! Solidity verifier replays the transcript with the `keccak256` precompile and
//! Poseidon never appears on the verified path.
//!
//! Kept as a test because it is the executable statement of that fact.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_commit::ExtensionMmcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::FriParameters;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};

use crate::config::{config, mmcs, Challenge, F};

/// Trace width: the two Fibonacci registers.
const WIDTH: usize = 2;

/// A minimal AIR whose only job is to exercise the proving machinery.
///
/// Transition: `(a, b) -> (b, a + b)`. The public value pins the final `b`, so
/// the verifier checks something that actually varies with the witness.
struct FibAir;

impl<F> BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        1
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Guard (degree 1) times a degree-1 expression.
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let a = local[0];
        let b = local[1];
        let a_next = next[0];
        let b_next = next[1];

        let mut t = builder.when_transition();
        t.assert_eq(a_next, b);
        t.assert_eq(b_next, a + b);

        let x = builder.public_values()[0];
        builder.when_last_row().assert_eq(b, x);
    }
}

/// Build `n` Fibonacci rows and report the final `b`, which is the public value.
fn fib_trace<F: Field>(n: usize) -> (RowMajorMatrix<F>, F) {
    assert!(n.is_power_of_two(), "trace height must be a power of two");

    let mut vals = Vec::with_capacity(n * WIDTH);
    let mut a = F::ONE;
    let mut b = F::ONE;
    for _ in 0..n {
        vals.push(a);
        vals.push(b);
        let next_b = a + b;
        a = b;
        b = next_b;
    }

    let last_b = *vals.last().expect("trace is non-empty");
    (RowMajorMatrix::new(vals, WIDTH), last_b)
}

/// A testing-shaped FRI parameter set over our Keccak challenge MMCS.
fn test_config() -> crate::config::Config {
    let challenge_mmcs = ExtensionMmcs::<F, Challenge, _>::new(mmcs(3));
    let fri_params = FriParameters::new_testing(challenge_mmcs, 1);
    config(fri_params)
}

#[test]
fn keccak_transcript_drives_prove_and_verify() {
    let cfg = test_config();
    let (trace, last_b) = fib_trace::<F>(16);

    let proof = prove(&cfg, &FibAir, trace, &[last_b]).expect("prove should succeed");
    verify(&cfg, &FibAir, &proof, &[last_b]).expect("verify should succeed");
}

#[test]
fn verify_rejects_tampered_public_value() {
    let cfg = test_config();
    let (trace, last_b) = fib_trace::<F>(16);

    let proof = prove(&cfg, &FibAir, trace, &[last_b]).expect("prove should succeed");

    let wrong = last_b + F::ONE;
    assert!(
        verify(&cfg, &FibAir, &proof, &[wrong]).is_err(),
        "a public value that does not match the witness must not verify"
    );
}

/// The commitment layer is Keccak-256, and a digest is 32 raw bytes.
///
/// Byte-native digests are what let the Solidity verifier walk the same tree
/// with the `keccak256` opcode and no hash gadget at all. The earlier shape
/// (`PaddingFreeSponge<KeccakF, 25, 17, 4>`) produced 4 u64 limbs, which is
/// also 32 bytes but is NOT a Keccak-256 digest: no FIPS padding, u64 lane
/// order, 4-lane squeeze. Replaying that on-chain means a hand-rolled
/// permutation at ~30-50k gas per call. See D-050.
#[test]
fn commitments_are_keccak_sized() {
    let cfg = test_config();
    let (trace, last_b) = fib_trace::<F>(16);

    let proof = prove(&cfg, &FibAir, trace, &[last_b]).expect("prove should succeed");

    let cap = proof.commitments.trace.roots();
    assert_eq!(cap.len(), 8, "cap height 3 => 8 digests");
    for digest in cap {
        assert_eq!(digest.len(), 32, "Keccak-256 digest = 32 bytes");
    }
}

/// The challenge field must be the degree-5 extension over `KoalaBear`.
#[test]
fn challenge_field_is_quintic_over_koala_bear() {
    use p3_field::BasedVectorSpace;
    assert_eq!(<Challenge as BasedVectorSpace<F>>::DIMENSION, 5);
    assert!(Challenge::bits() >= 128, "challenge field too small");
}
