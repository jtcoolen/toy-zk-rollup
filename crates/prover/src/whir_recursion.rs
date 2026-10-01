//! The Poseidon2 WHIR recursion configuration: the layer the recursion engine verifies.
//!
//! ## Why this layer is Poseidon2 and the settlement layer is Keccak
//!
//! The recursion engine re-derives a child proof's Fiat-Shamir transcript *inside* a
//! circuit. Its in-circuit Merkle gadget is a Poseidon2 permutation, and the WHIR
//! recursive PCS is bounded to a field-native Merkle cap:
//!
//! ```text
//!   MT: Mmcs<Val, Commitment = MerkleCap<Val, [Val; DIGEST_ELEMS]>>
//! ```
//!
//! A Keccak wire-cap MMCS (`[u64; N]`) cannot satisfy that bound, so the layer that
//! gets recursed over must commit with a Poseidon2 field-native cap. That is the
//! user-granted exception, and it is confined to exactly this layer.
//!
//! The settlement layer (see [`crate::whir`]) is *not* recursed over in-circuit: the
//! recursion circuit this config builds is proven under the Keccak WHIR config through
//! `BatchStarkProver`, which only needs a `StarkGenericConfig`, not a
//! `WhirRecursionConfig`. So the field-native-cap bound never reaches the Keccak
//! layer, and Solidity replays its Keccak transcript and Keccak Merkle tree with the
//! native `keccak256` opcode.
//!
//! ```text
//!   base fib proof      Poseidon2 WHIR   <- this module, recursed over in-circuit
//!   recursion circuit   Keccak WHIR    <- crate::whir, proven natively, replayed by Solidity
//! ```
//!
//! ## Digest width
//!
//! The in-circuit Poseidon2 gadget runs at width 16, rate 8, so a Merkle digest is 8
//! base-field elements. That fixes [`DIGEST_ELEMS`] at 8 for every type in this
//! module; the settlement layer's Keccak digest is 4 `u64` limbs instead, and the two
//! never meet in one circuit.

use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::backend::whir::WhirRecursionConfig;
use p3_recursion::generation::OpeningTranscript;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::set_whir_mmcs_private_data;
use p3_recursion::pcs::whir::params::WhirVerifierParamsError;
use p3_recursion::pcs::whir::uni::{
    restore_whir_recursion_paths, whir_round_paths_op_count, WhirUniPcs, WhirUniProof,
    WhirUniProofTargets, WhirUniVerifierParams,
};
use p3_recursion::recursion::RecursionInput;
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{Poseidon2Config, VerificationError};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use p3_whir::parameters::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirConfigError,
};

/// Base field: `KoalaBear`, shared with the settlement layer.
pub type F = KoalaBear;

/// Challenge field: degree-4 binomial extension, the degree the WHIR recursion
/// backend supports.
pub type Challenge = BinomialExtensionField<F, 4>;

/// Poseidon2 permutation, width 16 — the in-circuit gadget's permutation.
pub type Perm = Poseidon2KoalaBear<16>;

/// Poseidon2 sponge: width 16, rate 8, 8-element digest.
type WhirHash = PaddingFreeSponge<Perm, 16, 8, 8>;

/// Two-to-one Merkle compressor over the same permutation.
type WhirCompress = TruncatedPermutation<Perm, 2, 8, 16>;

/// Field-native Merkle tree: the cap shape the recursion engine requires.
pub type WhirMmcs = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    WhirHash,
    WhirCompress,
    2,
    DIGEST_ELEMS,
>;

/// The Poseidon2 Fiat-Shamir challenger, re-derived in-circuit by the recursion VM.
pub type WhirChallenger = DuplexChallenger<F, Perm, 16, 8>;

/// The WHIR PCS over the Poseidon2 field-native Merkle tree.
pub type WhirPcs = WhirUniPcs<
    Challenge,
    F,
    Radix2DitParallel<F>,
    WhirMmcs,
    WhirChallenger,
    PrefixProver<F, Challenge>,
>;

/// Field elements per Merkle digest. Fixed at 8 by the width-16 / rate-8 gadget.
pub const DIGEST_ELEMS: usize = 8;

/// Conjectured security level for the recursion layer, matching the settlement
/// layer's [`crate::whir::SECURITY_LEVEL`].
///
/// A recursion chain is only as strong as its weakest layer, so this tracks the
/// settlement target rather than being chosen independently.
pub const SECURITY_LEVEL: usize = crate::whir::SECURITY_LEVEL;

/// Folding factor per WHIR round, matching the extension degree the backend supports.
pub const FOLDING_FACTOR: usize = 4;

/// The canonical `KoalaBear` width-16 Poseidon2 permutation.
///
/// The AIR recomputes every permutation from its own constants, so the hasher,
/// compressor and challenger must all use this exact instance or the in-circuit
/// transcript diverges from the native one.
#[must_use]
pub fn whir_perm() -> Perm {
    default_koalabear_poseidon2_16()
}

/// The Poseidon2 field-native MMCS every WHIR commitment in this layer uses.
#[must_use]
pub fn whir_mmcs(cap_height: usize) -> WhirMmcs {
    let perm = whir_perm();
    WhirMmcs::new(
        WhirHash::new(perm.clone()),
        WhirCompress::new(perm),
        cap_height,
    )
}

/// Build the WHIR protocol parameters for a given grinding budget.
///
/// `round_log_inv_rates` is empty so the round schedule is derived per commit,
/// which a config serving more than one trace size requires.
///
/// The soundness regime is [`SecurityAssumption::JohnsonBound`], not
/// `CapacityBound`. The recursion circuit re-verifying a WHIR base proof opens
/// ~500 claims at once, and the initial claim-combination ceiling is
///
/// ```text
///   bits = field_size_bits - log2(claims - 1) - list_size_bits
/// ```
///
/// `CapacityBound`'s list size grows with the degree (~13.7 bits here), putting
/// that ceiling near 86 bits — below the [`SECURITY_LEVEL`] target, and grinding
/// cannot recover it because the batching challenge precedes the first grind.
/// `JohnsonBound`'s list size is `log_inv_rate + log2(10)` (~4.8 bits at rate ½),
/// independent of degree, lifting the ceiling to ~109 bits. It is also the *proven*
/// regime — Reed-Solomon correlated agreement is established at that radius — so
/// this is the less conjectural choice, not merely the one that fits.
#[must_use]
pub const fn protocol_params(pow_bits: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level: SECURITY_LEVEL,
        pow_bits,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(FOLDING_FACTOR),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

/// Smallest grinding budget that yields a feasible WHIR schedule at
/// [`SECURITY_LEVEL`] for a statement of `num_variables`.
///
/// Same reasoning as [`crate::whir::required_pow_bits`]: too small a budget is
/// rejected, a budget at or above the security level zeroes the query count. The
/// search finds the cheapest sound budget. Generic over the challenger so the
/// Poseidon2 recursion layer and the Keccak settlement layer share one rule.
///
/// # Errors
///
/// Returns the last WHIR configuration error if no budget below the security level
/// yields a feasible schedule.
pub fn required_pow_bits(num_variables: usize) -> Result<usize, WhirConfigError> {
    const _: () = assert!(SECURITY_LEVEL > 0, "security level must be positive");
    let mut last_error = None;
    for budget in 0..SECURITY_LEVEL {
        let params = protocol_params(budget);
        match WhirConfig::<Challenge, F, WhirChallenger>::new(num_variables, params) {
            Ok(schedule) => return Ok(schedule.max_pow_bits()),
            Err(err) => last_error = Some(err),
        }
    }
    last_error.map_or_else(
        || {
            Err(WhirConfigError::PowBitsExceedBudget {
                required: SECURITY_LEVEL,
                budget: 0,
            })
        },
        Err,
    )
}

/// A STARK configuration carrying the WHIR verifier parameters the recursive
/// verifier needs beyond what `StarkConfig` exposes.
///
/// This is the `InSC` of the recursion layer: the config whose proofs the
/// recursion engine re-verifies in-circuit. It implements both
/// [`StarkGenericConfig`] (to prove natively) and [`WhirRecursionConfig`] (to be
/// recursed over).
#[derive(Clone, Debug)]
pub struct InnerWhirConfig {
    pcs: WhirPcs,
    challenger: WhirChallenger,
    /// Held so [`WhirRecursionConfig::pcs_verifier_params`] and
    /// [`WhirRecursionConfig::set_whir_private_data`] both read the round schedule
    /// this config's own `pcs` was built with.
    whir_verifier_params: WhirUniVerifierParams<F>,
}

impl InnerWhirConfig {
    /// Assemble the recursion-layer config.
    ///
    /// `log_max_lde_height` bounds the largest LDE height this config can commit;
    /// it must cover the recursion circuit's own trace. `cap_height` is the Merkle
    /// cap height.
    ///
    /// # Errors
    ///
    /// Returns [`WhirVerifierParamsError`] if the grinding budget cannot be derived
    /// for `log_max_lde_height` at [`SECURITY_LEVEL`], or if the verifier
    /// parameters reject the resulting schedule.
    pub fn new(
        log_max_lde_height: usize,
        cap_height: usize,
    ) -> Result<Self, WhirVerifierParamsError> {
        let pow_bits = required_pow_bits(log_max_lde_height)?;
        let params = protocol_params(pow_bits);
        let challenger = WhirChallenger::new(whir_perm());
        let pcs = WhirPcs::new(
            params.clone(),
            Radix2DitParallel::default(),
            whir_mmcs(cap_height),
            challenger.clone(),
            log_max_lde_height,
        );
        let whir_verifier_params = WhirUniVerifierParams::<F>::new(
            params,
            PrefixProver::<F, Challenge>::variable_order(),
            Poseidon2Config::KOALA_BEAR_D4_W16,
        )?;
        Ok(Self {
            pcs,
            challenger,
            whir_verifier_params,
        })
    }
}

impl StarkGenericConfig for InnerWhirConfig {
    type Pcs = WhirPcs;
    type Challenge = Challenge;
    type Challenger = WhirChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for InnerWhirConfig {
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<F, Challenge, WhirMmcs, DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<F, Challenge, WhirMmcs>;

    fn with_whir_opening_proof<A, R>(
        prev: &RecursionInput<'_, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<F, Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            whir_perm(),
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<F> {
        &self.whir_verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let mmcs = whir_mmcs(0);
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, DIGEST_ELEMS>(
            &mmcs,
            transcript,
            opening_proof,
            params.protocol_params(),
            params.folding(),
            params.variable_order(),
        )
        .map_err(|_| "Failed to restore WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let op_ids_slice = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for the restored WHIR Merkle paths")?;
            set_whir_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                runner,
                op_ids_slice,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::KOALA_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in InnerWhirConfig::set_whir_private_data");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
    use p3_circuit_prover::BatchStarkProver;
    use p3_field::PrimeCharacteristicRing;
    use p3_recursion::{
        backend::whir::WhirRecursionBackend, PreparedInput, PreparedLayer, PreparedSource,
        ProveNextLayerParams,
    };

    /// The recursion layer's own trace is bigger than the base proof's, so the
    /// config must be sized for the larger of the two. The recursion circuit that
    /// re-verifies a WHIR base proof stacks its columns into a multilinear of
    /// ~21 variables at this security level, which demands 16 grinding bits;
    /// sizing at 22 gives a budget of 17 that covers it with margin.
    const LOG_MAX_LDE: usize = 22;
    const CAP_HEIGHT: usize = 0;
    /// Base trace length: 1024 rows.
    const BASE_TRACE: usize = 1024;

    fn recursion_config() -> InnerWhirConfig {
        InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("recursion config should build")
    }

    /// The load-bearing test: a WHIR base proof, re-verified inside a circuit, then
    /// that circuit proven under the same WHIR config and checked.
    ///
    /// This is the `InSC` half of the architecture: the layer the recursion engine
    /// re-verifies in-circuit with the Poseidon2 gadget.
    #[test]
    fn whir_recursion_layer_proves_and_verifies() {
        let config = recursion_config();
        let air = FibonacciAir {};
        let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
        let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];

        let proof = p3_uni_stark::prove(&config, &air, trace, &pis)
            .expect("base WHIR proof should generate");
        p3_uni_stark::verify(&config, &air, &proof, &pis).expect("base WHIR proof should verify");

        let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>();
        let params = ProveNextLayerParams::default();
        let source = PreparedSource::UniStark {
            air: &air,
            proof: &proof,
            public_inputs: &pis,
            preprocessed_commit: None,
        };
        let input = PreparedInput::UniStark {
            proof: &proof,
            public_inputs: &pis,
            preprocessed_commit: None,
        };

        let owner = PreparedLayer::new(source, config.clone(), backend, params.clone())
            .expect("WHIR recursion layer should prepare");
        let output = owner
            .prove(input)
            .expect("WHIR recursion layer should prove");

        // Re-verify every non-primitive table the recursion proof claims. The
        // D4 width-16 Poseidon2 shape is not an arity-4 compression shape, so it
        // emits a single shared challenger-role output table. This mirrors the
        // upstream `OutputTableConfigs` helper, which is example-local rather
        // than library API.
        let p2 = Poseidon2Config::KOALA_BEAR_D4_W16;
        let mut prover = BatchStarkProver::new(config).with_table_packing(params.table_packing);
        prover.register_poseidon2_table::<4>(p2.for_shared_challenger_table());
        prover.register_recompose_table::<4>(true);
        prover
            .verify_all_tables::<Challenge>(&output.0)
            .expect("WHIR recursion layer proof should verify all tables");
    }

    /// `b` after `n` steps of the Fibonacci recurrence the upstream AIR encodes.
    fn fibonacci_output(n: usize) -> F {
        let mut a = F::ZERO;
        let mut b = F::ONE;
        for _ in 1..n {
            let next = a + b;
            a = b;
            b = next;
        }
        b
    }
}
