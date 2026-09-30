//! The no-fork recursion spike.
//!
//! Tests the load-bearing architectural claim: `TrustedPreparedLayer<InSC, OutSC, …>`
//! takes two *independent* STARK configs that share only their challenge field.
//!
//! - **`InSC`** (layer 0) runs on a Poseidon2 `DuplexChallenger`. The recursion
//!   circuit re-derives that transcript in-circuit with the Poseidon2
//!   permutation — the user-granted exception to the SHA-3-only rule.
//! - **`OutSC`** (the final layer) runs on a Keccak transcript. That is the
//!   transcript the Solidity verifier replays with the native `keccak256`
//!   opcode, so Fiat-Shamir on-chain costs tens of gas per challenge instead of
//!   thousands of field operations.
//!
//! ## The one gap this crate closes
//!
//! The recursion layer's in-circuit Merkle gadget is Poseidon2-shaped, so both
//! configs commit with a field-native `MerkleCap<F, [F; 8]>`. Plonky3's Keccak
//! `SerializingChallenger32` only knows how to observe `[u64; N]` and `[u8; N]`
//! caps — never `[F; N]`. [`KeccakOutChallenger`] wraps it and absorbs each field
//! element with the *same* bytes `CanObserve<F>` already uses: little-endian
//! `u32`. The transcript is still plain Keccak-256 over a byte string we define,
//! which is exactly what the Solidity verifier needs to reproduce.
//!
//! If this compiles and verifies, "Keccak transcript without forking the
//! recursion crate" holds. If it does not, the exception has to grow.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_errors_doc)]

use std::sync::Arc;

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, DuplexChallenger, FieldChallenger, GrindingChallenger,
    HashChallenger, SerializingChallenger32,
};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{MerkleCap, PaddingFreeSponge, Permutation, TruncatedPermutation};

// ---------------------------------------------------------------------------
// Field and MMCS — shared by both configs.
// ---------------------------------------------------------------------------

/// The base field: `KoalaBear`, a 31-bit Mersenne-friendly prime.
pub type F = KoalaBear;
/// The challenge field: degree-5 trinomial extension, ~128-bit conjecturable security.
pub type Challenge = QuinticTrinomialExtensionField<F>;
type Perm = Poseidon2KoalaBear<16>;

/// Poseidon2 state width.
pub const WIDTH: usize = 16;
/// Sponge rate in field elements.
pub const RATE: usize = 8;
/// Field elements per Merkle digest (8 × 31 bits ≈ 248 bits).
pub const DIGEST_ELEMS: usize = 8;

type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
type MyMmcs = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    MyHash,
    MyCompress,
    2,
    DIGEST_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
type MyPcs = TwoAdicFriPcs<F, Radix2DitParallel<F>, MyMmcs, ChallengeMmcs>;

/// Layer 0's transcript: Poseidon2, re-derived in-circuit by the recursion VM.
pub type InChallenger = DuplexChallenger<F, Perm, WIDTH, RATE>;

/// The raw Keccak transcript, before the field-native-cap adapter.
type RawKeccak = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

/// The final layer's transcript: Keccak-256, replayed on-chain by `keccak256`.
///
/// A newtype rather than the bare `SerializingChallenger32` because the recursion
/// layer commits with a field-native `MerkleCap<F, [F; N]>` and Plonky3's Keccak
/// challenger has no impl for that shape. See the module docs.
#[derive(Clone, Debug)]
pub struct KeccakOutChallenger(RawKeccak);

impl KeccakOutChallenger {
    /// A fresh Keccak-256 transcript with an empty initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self(SerializingChallenger32::from_hasher(
            Vec::new(),
            Keccak256Hash {},
        ))
    }
}

impl Default for KeccakOutChallenger {
    fn default() -> Self {
        Self::new()
    }
}

/// Absorb a base-field element as its little-endian `u32` — the same bytes the
/// inner challenger would use, so the wire format is unchanged.
impl CanObserve<F> for KeccakOutChallenger {
    fn observe(&mut self, value: F) {
        self.0.observe(value);
    }
}

/// The gap this newtype exists to close: a field-native Merkle cap, absorbed root
/// by root, element by element, each as little-endian `u32`.
///
/// Solidity mirrors this exactly: `abi.encodePacked` of each root's `uint32`
/// words, hashed with `keccak256`.
impl<const N: usize> CanObserve<MerkleCap<F, [F; N]>> for KeccakOutChallenger {
    fn observe(&mut self, cap: MerkleCap<F, [F; N]>) {
        self.observe(&cap);
    }
}

impl<const N: usize> CanObserve<&MerkleCap<F, [F; N]>> for KeccakOutChallenger {
    fn observe(&mut self, cap: &MerkleCap<F, [F; N]>) {
        for digest in cap.roots() {
            for &value in digest {
                self.0.observe(value);
            }
        }
    }
}

impl CanSample<F> for KeccakOutChallenger {
    fn sample(&mut self) -> F {
        self.0.sample()
    }
}

impl CanSample<Challenge> for KeccakOutChallenger {
    fn sample(&mut self) -> Challenge {
        self.0.sample()
    }
}

impl CanSampleBits<usize> for KeccakOutChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.0.sample_bits(bits)
    }
}

impl FieldChallenger<F> for KeccakOutChallenger {}

impl GrindingChallenger for KeccakOutChallenger {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.0.grind(bits)
    }

    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.0.check_witness(bits, witness)
    }
}

/// Lift a base-field permutation to the quintic challenge field.
///
/// The recursion circuit runs over `Challenge`, but the Fiat-Shamir permutation
/// it must replay is the base-field Poseidon2 over `[F; W]`. Each lane of the
/// lifted permutation carries its payload in the constant basis coefficient: the
/// other four coefficients are zero, so reading coefficient 0 recovers the base
/// field word, and re-embedding leaves a value that is still a valid `Challenge`.
///
/// This mirrors upstream's `p3_test_utils::LiftPermToQuintic` exactly. It lives
/// here rather than in that crate because it is `publish = false` and because this
/// byte-for-permutation semantics is load-bearing for the transcript, not test
/// scaffolding.
#[derive(Clone)]
struct LiftPermToQuintic<P, const W: usize> {
    perm: P,
}

impl<P, const W: usize> LiftPermToQuintic<P, W> {
    const fn new(perm: P) -> Self {
        Self { perm }
    }
}

impl<P: Permutation<[F; W]>, const W: usize> Permutation<[Challenge; W]>
    for LiftPermToQuintic<P, W>
{
    fn permute(&self, input: [Challenge; W]) -> [Challenge; W] {
        let bases: [F; W] = core::array::from_fn(|i| {
            <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(&input[i])[0]
        });
        let out = self.perm.permute(bases);
        core::array::from_fn(|i| Challenge::new([out[i], F::ZERO, F::ZERO, F::ZERO, F::ZERO]))
    }
}

/// The `PrimeField32` bound the inner challenger needs is satisfied by `F`; this
/// assertion keeps that visible rather than implicit at the impl site.
const _: () = {
    const fn _assert_prime_field32<T: PrimeField32>() {}
    let _ = _assert_prime_field32::<F>;
};

// ---------------------------------------------------------------------------
// The config wrapper.
//
// `TrustedPreparedLayer` requires `FriRecursionConfig` on *both* the source and
// the output config, and the body is identical apart from the challenger type.
// Upstream uses a macro for the same reason; so do we.
// ---------------------------------------------------------------------------

macro_rules! impl_recursion_config {
    ($name:ident, $challenger:ty) => {
        /// A STARK config carrying the extra FRI parameters the recursive verifier
        /// needs beyond what `StarkConfig` exposes.
        #[derive(Clone, Debug)]
        pub struct $name {
            config: Arc<p3_uni_stark::StarkConfig<MyPcs, Challenge, $challenger>>,
            fri_verifier_params: p3_recursion::FriVerifierParams,
            native_fri_params: p3_recursion::NativeFriParams,
            /// The base-field MMCS and FRI parameters this config commits with. The
            /// PCS keeps them private; restoring a pruned FRI proof's per-query
            /// Merkle chains needs both.
            fri_instance: Arc<(MyMmcs, FriParameters<ChallengeMmcs>)>,
        }

        impl $name {
            /// Assemble the config around `challenger` with the given Merkle cap height.
            ///
            /// # Panics
            ///
            /// If the FRI parameters are not representable in the base field's
            /// native parameter form. They are constants here, so this is a
            /// programming-error check, not a runtime condition.
            #[must_use]
            pub fn new(challenger: $challenger, cap_height: usize) -> Self {
                let (val_mmcs, fri_params) = make_fri(cap_height);
                let native_fri_params =
                    p3_recursion::NativeFriParams::try_from_native::<F, _>(&fri_params)
                        .expect("FRI parameters must be valid for KoalaBear");
                let pcs = MyPcs::new(
                    Radix2DitParallel::default(),
                    val_mmcs.clone(),
                    fri_params.clone(),
                );
                Self {
                    config: Arc::new(p3_uni_stark::StarkConfig::new(pcs, challenger)),
                    fri_verifier_params: verifier_params(native_fri_params),
                    native_fri_params,
                    fri_instance: Arc::new((val_mmcs, fri_params)),
                }
            }
        }

        impl std::ops::Deref for $name {
            type Target = p3_uni_stark::StarkConfig<MyPcs, Challenge, $challenger>;
            fn deref(&self) -> &Self::Target {
                &self.config
            }
        }

        impl p3_uni_stark::StarkGenericConfig for $name {
            type Challenge = Challenge;
            type Challenger = $challenger;
            type Pcs = MyPcs;
            fn pcs(&self) -> &MyPcs {
                self.config.pcs()
            }
            fn initialise_challenger(&self) -> $challenger {
                self.config.initialise_challenger()
            }
        }

        impl p3_recursion::FriRecursionConfig for $name
        where
            MyPcs: p3_recursion::RecursivePcs<
                $name,
                InputProof,
                InnerFri,
                p3_recursion::pcs::MerkleCapTargets<F, DIGEST_ELEMS>,
                <MyPcs as Pcs<Challenge, $challenger>>::Domain,
            >,
        {
            type Commitment = p3_recursion::pcs::MerkleCapTargets<F, DIGEST_ELEMS>;
            type InputProof = InputProof;
            type OpeningProof = InnerFri;
            type RawOpeningProof = <MyPcs as Pcs<Challenge, $challenger>>::Proof;
            const DIGEST_ELEMS: usize = DIGEST_ELEMS;

            fn native_fri_validation_params(&self) -> Option<p3_recursion::NativeFriParams> {
                Some(self.native_fri_params)
            }

            fn with_fri_opening_proof<A, R>(
                prev: &p3_recursion::RecursionInput<'_, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: p3_recursion::RecursiveAir<
                    p3_uni_stark::Val<Self>,
                    Self::Challenge,
                    p3_lookup::logup::LogUpGadget,
                >,
            {
                match prev {
                    p3_recursion::RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    p3_recursion::RecursionInput::BatchStark { proof, .. } => {
                        f(&proof.proof.opening_proof)
                    }
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut p3_circuit::CircuitBuilder<Challenge>,
            ) -> Result<(), p3_recursion::VerificationError> {
                use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
                // The circuit runs over the quintic challenge field, so the
                // base-field Poseidon2 permutation must be lifted to it.
                let perm = LiftPermToQuintic::<Perm, WIDTH>::new(default_koalabear_poseidon2_16());
                circuit.enable_poseidon2_perm_base::<
                    p3_poseidon2_circuit_air::KoalaBearD1Width16,
                    _,
                >(
                    generate_poseidon2_trace::<Challenge, p3_poseidon2_circuit_air::KoalaBearD1Width16>,
                    perm,
                );
                circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                if <p3_poseidon2_circuit_air::KoalaBearD1Width16 as p3_circuit::ops::Poseidon2Params>::D
                    == 1
                    && <Challenge as BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &<MyPcs as p3_recursion::RecursivePcs<
                $name,
                InputProof,
                InnerFri,
                p3_recursion::pcs::MerkleCapTargets<F, DIGEST_ELEMS>,
                <MyPcs as Pcs<Challenge, $challenger>>::Domain,
            >>::VerifierParams {
                &self.fri_verifier_params
            }

            fn set_fri_private_data(
                config: &Self,
                runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
                op_ids: &[p3_circuit::NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: p3_recursion::OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                use p3_recursion::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
                let p3_recursion::OpeningTranscript {
                    mut challenger,
                    commitments_with_opening_points,
                } = transcript;
                p3_recursion::observe_opened_values::<Self>(
                    &mut challenger,
                    &commitments_with_opening_points,
                    config.fri_instance.1.batch_proof_of_work_bits,
                );
                let claims: Vec<_> = commitments_with_opening_points
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect();
                let query_paths = restore_fri_query_paths(
                    &config.fri_instance.1,
                    &config.fri_instance.0,
                    &config.fri_instance.0,
                    opening_proof,
                    &mut challenger,
                    &claims,
                )
                .map_err(|_| "Failed to restore the FRI proof's per-query Merkle paths")?;
                set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                    runner,
                    op_ids,
                    &query_paths,
                    p3_recursion::Poseidon2Config::KOALA_BEAR_D1_W16,
                )
            }
        }
    };
}

impl_recursion_config!(InConfig, InChallenger);
impl_recursion_config!(OutConfig, KeccakOutChallenger);

type InputProof = p3_recursion::pcs::InputProofTargets<F, Challenge, RecValMmcsT>;
type RecValMmcsT = p3_recursion::pcs::RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>;
type InnerFri = p3_recursion::pcs::FriProofTargets<
    F,
    Challenge,
    p3_recursion::pcs::RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecValMmcsT>,
    InputProof,
    p3_recursion::pcs::Witness<F>,
>;

// ---------------------------------------------------------------------------
// A tiny AIR to prove.
// ---------------------------------------------------------------------------

/// Minimal AIR: `a' = a + b`, `b' = a + 2b`, first row `(1, 1)`.
///
/// Deliberately trivial — the point of this crate is the transcript split, not
/// the AIR.
#[derive(Clone, Copy, Debug)]
pub struct FibAir;

/// The trace width is field-agnostic, so `BaseAir` is implemented for *any* field.
/// Bounding it (e.g. `F: Field`) would make `Air<AB>` unsatisfiable, because
/// `AB::F` is only known to be a `Field` through the `AirBuilder` chain and Rust
/// does not carry that back into a separate impl.
impl<F> p3_air::BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }

    /// One public value: the running value `a` on the first row.
    ///
    /// The count is load-bearing — the transcript's domain-separator pattern is
    /// built from it, so a mismatch panics before proving rather than yielding a
    /// proof that fails verification.
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::{AirBuilder, WindowAccess};
        let main = builder.main();
        // Column 0 is `a`, column 1 is `b`; the window gives current and next row.
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        // The single public input pins `a` on the first row. Bound by constraint,
        // not by a backend cell pin: univariate STARKs reject the latter.
        let a_public: AB::Expr = builder.public_values()[0].into();
        builder.when_first_row().assert_eq(a, a_public);
        // The window is cyclic, so the transition must be gated off on the last
        // row or it would assert that the trace wraps back to its first row.
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
    }
}

/// Build the Fibonacci trace of the given power-of-two length.
#[must_use]
pub fn fib_trace(len: usize) -> RowMajorMatrix<F> {
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    RowMajorMatrix::new(values, 2)
}

fn make_fri(cap_height: usize) -> (MyMmcs, FriParameters<ChallengeMmcs>) {
    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    let val_mmcs = MyMmcs::new(hash, compress, cap_height);
    let fri_params = FriParameters {
        max_log_arity: 2,
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 64,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    };
    (val_mmcs, fri_params)
}

fn verifier_params(native: p3_recursion::NativeFriParams) -> p3_recursion::FriVerifierParams {
    p3_recursion::FriVerifierParams::with_mmcs(
        native.log_blowup(),
        native.log_final_poly_len(),
        native.max_log_arity(),
        native.commit_pow_bits(),
        native.query_pow_bits(),
        native.num_queries(),
        p3_recursion::Poseidon2Config::KOALA_BEAR_D1_W16,
    )
}

/// The Merkle cap height both configs commit with.
const CAP_HEIGHT: usize = 4;

/// Layer 0's config: Poseidon2 transcript.
#[must_use]
pub fn in_config() -> InConfig {
    InConfig::new(
        InChallenger::new(default_koalabear_poseidon2_16()),
        CAP_HEIGHT,
    )
}

/// The final layer's config: Keccak transcript.
#[must_use]
pub fn out_config() -> OutConfig {
    OutConfig::new(KeccakOutChallenger::new(), CAP_HEIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_uni_stark::{prove, verify};

    #[test]
    fn keccak_transcript_stark_proves_and_verifies_natively() {
        // The OutSC shape, standalone: a Keccak-challenger STARK verifies.
        let cfg = out_config();
        let air = FibAir;
        let trace = fib_trace(8);
        let pis: Vec<F> = vec![F::ONE];
        let proof = prove(&cfg, &air, trace, &pis).expect("Keccak-transcript STARK proves");
        verify(&cfg, &air, &proof, &pis).expect("Keccak-transcript STARK verifies");
    }

    #[test]
    fn no_fork_recursion_layer_builds_and_proves() {
        // The headline: layer 0 under InSC (Poseidon2 transcript), wrapped in a
        // layer whose own transcript is Keccak.
        let in_cfg = in_config();
        let out_cfg = out_config();
        let air = FibAir;
        let trace = fib_trace(8);
        let pis: Vec<F> = vec![F::ONE];
        let first = prove(&in_cfg, &air, trace, &pis).expect("layer 0 proves");
        verify(&in_cfg, &air, &first, &pis).expect("layer 0 verifies");

        let backend = p3_recursion::FriRecursionBackend::<WIDTH, RATE, _>::new_d5(
            p3_recursion::Poseidon2Config::KOALA_BEAR_D1_W16,
        );

        let layer = p3_recursion::TrustedPreparedLayer::<InConfig, OutConfig, FibAir, _, 5>::new(
            p3_recursion::TrustedPreparedSource::UniStark {
                config: in_cfg,
                air: &air,
                preprocessed_commit: None,
                proof: &first,
                public_inputs: &pis,
            },
            out_cfg,
            backend,
            p3_recursion::ProveNextLayerParams::default(),
        )
        .expect("recursion layer builds");

        let out = layer
            .prove(p3_recursion::TrustedPreparedInput::UniStark {
                proof: &first,
                public_inputs: &pis,
            })
            .expect("recursion layer proves");

        let verifier = layer.verifier();
        let statement: Vec<F> = pis.clone();
        verifier
            .verify(&out.0, &statement)
            .expect("recursion verifier accepts");
    }
}
