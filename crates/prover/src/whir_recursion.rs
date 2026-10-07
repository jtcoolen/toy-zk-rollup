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
//! module; the settlement layer's digest is 32 raw Keccak-256 bytes instead, and
//! the two never meet in one circuit. (The settlement layer used to be 4 `u64`
//! sponge limbs; it is byte-native now so Solidity replays it with the native
//! `keccak256` opcode — see D-050.)

use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{
    CircuitBuilder, CircuitRunner, NonPrimitiveOpId, StatementExport, StatementSchema,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    poseidon2_air_builders_for_configs, recompose_preprocessor, BatchStarkProver,
    ConstraintProfile, Poseidon2SharedPreprocessor, RecomposeAirBuilder, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionConfig};
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
use p3_recursion::{verify_p3_uni_proof_circuit, StarkVerifierInputsBuilder};
use p3_recursion::{PcsRecursionBackend, Poseidon2Config, ProveNextLayerParams, VerificationError};
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

/// Maximum LDE height the recursion layer is sized for.
///
/// The recursion layer's own trace is bigger than the base proof's, so the config
/// must be sized for the larger of the two. The recursion circuit that re-verifies
/// a WHIR base proof stacks its columns into a multilinear of ~21 variables at
/// this security level, which demands 16 grinding bits; sizing at 22 gives a
/// budget of 17 that covers it with margin.
pub const LOG_MAX_LDE: usize = 22;

/// Merkle cap height for the recursion layer's commitment.
pub const CAP_HEIGHT: usize = 0;

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
    protocol_params_with(pow_bits, 1)
}

/// [`protocol_params`] with an explicit starting inverse rate.
///
/// Rate 2 (a quarter-rate code) roughly halves the STIR query budget - and
/// with it the Merkle-path bytes, the dominant term of the on-chain proof -
/// at the cost of doubling every committed domain, one arity higher. The
/// soundness assumption stays `JohnsonBound` (the proven regime) at every rate.
#[must_use]
pub const fn protocol_params_with(
    pow_bits: usize,
    starting_log_inv_rate: usize,
) -> ProtocolParameters {
    ProtocolParameters {
        security_level: SECURITY_LEVEL,
        pow_bits,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(FOLDING_FACTOR),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate,
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
///
/// Backs off to the largest feasible arity when the request is past the field's
/// domain capacity, for the same reason as [`crate::whir::required_pow_bits`]:
/// the budget is an upper bound on what any smaller statement demands, and an
/// arity above the capacity cannot be committed at all, so there is nothing to
/// provision for.
///
/// # Errors
///
/// Returns the last WHIR configuration error if no arity from `num_variables`
/// down to zero yields a feasible schedule.
pub fn required_pow_bits(num_variables: usize) -> Result<usize, WhirConfigError> {
    required_pow_bits_with(num_variables, 1)
}

/// [`required_pow_bits`] at an explicit starting inverse rate.
///
/// # Errors
///
/// Returns the last WHIR configuration error if no arity yields a feasible
/// schedule at this rate.
pub fn required_pow_bits_with(
    num_variables: usize,
    starting_log_inv_rate: usize,
) -> Result<usize, WhirConfigError> {
    const _: () = assert!(SECURITY_LEVEL > 0, "security level must be positive");
    let mut last_error = None;
    for arity in (0..=num_variables).rev() {
        for budget in 0..SECURITY_LEVEL {
            let params = protocol_params_with(budget, starting_log_inv_rate);
            match WhirConfig::<Challenge, F, WhirChallenger>::new(arity, params) {
                Ok(schedule) => return Ok(schedule.max_pow_bits()),
                Err(err) => last_error = Some(err),
            }
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
        Self::new_with(log_max_lde_height, cap_height, 1)
    }

    /// [`InnerWhirConfig::new`] at an explicit starting inverse rate (see
    /// [`protocol_params_with`]).
    ///
    /// # Errors
    ///
    /// Returns the verifier-parameters error if this rate cannot reach
    /// [`SECURITY_LEVEL`] at `log_max_lde_height`.
    pub fn new_with(
        log_max_lde_height: usize,
        cap_height: usize,
        starting_log_inv_rate: usize,
    ) -> Result<Self, WhirVerifierParamsError> {
        // Blinding doubles the committed height, so the schedule must be sized
        // one arity above the trace bound. See `crate::whir::ZK_ARITY_SLACK`.
        let pow_bits = required_pow_bits_with(
            log_max_lde_height + crate::whir::ZK_ARITY_SLACK,
            starting_log_inv_rate,
        )?;
        let params = protocol_params_with(pow_bits, starting_log_inv_rate);
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

/// A recursion circuit bound to a statement, witnessed and ready to be proven
/// under the Keccak settlement config.
///
/// The `circuit` and its `traces` are the two halves the settlement prover needs;
/// `schema` describes the statement so the prover can register the matching
/// statement table.
pub struct RecursionCircuit {
    /// The compiled recursion circuit (over `Challenge`).
    pub circuit: p3_circuit::Circuit<Challenge>,
    /// The witnessed traces, config-agnostic across the Poseidon2/Keccak split.
    pub traces: p3_circuit::Traces<Challenge>,
    /// The statement schema installed on the circuit.
    pub schema: StatementSchema,
}

impl core::fmt::Debug for RecursionCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `Traces` holds trait objects and cannot derive `Debug`, and dumping the
        // full witness would be megabytes of noise. Report what identifies it.
        f.debug_struct("RecursionCircuit")
            .field("circuit", &self.circuit)
            .field(
                "non_primitive_traces",
                &self.traces.non_primitive_traces.len(),
            )
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

/// Builds the recursion circuit that verifies one base WHIR proof, witnesses it,
/// and binds its statement.
///
/// This is the production recursion step, not test scaffolding. It is written by
/// hand rather than through `build_next_layer_circuit` for one reason: the
/// statement. `build_next_layer_circuit` returns an opaque checked result whose
/// public-value targets are crate-private, so a caller cannot bind them. Here the
/// uni-branch build is replicated with the public pieces, and the verifier's own
/// `air_public_targets` are installed as the circuit's statement sink via
/// [`CircuitBuilder::set_statement_exports`]. That makes the settlement-layer
/// `verify(&proof, &public_inputs)` bind these exact values: the statement table's
/// public values *are* those targets, so a proof over different public values
/// fails verification.
///
/// The circuit is built and witnessed entirely against the Poseidon2 `InSC` (the
/// in-circuit Merkle gadget's field-native cap). The resulting `Traces` carry no
/// commitment-scheme identity, so they transfer unchanged to the Keccak settlement
/// layer — the field-native-cap bound that blocks a Keccak `WhirRecursionConfig`
/// never applies to the outer wrap.
///
/// # Errors
///
/// Returns the first failure from the build pipeline: input preflight/validation,
/// circuit preparation, verifier-input allocation, the verifier-circuit build,
/// statement installation, or witnessing. A returned error means no circuit was
/// produced; it never yields a partially bound circuit.
pub fn build_recursion_circuit<A>(
    inner: &InnerWhirConfig,
    air: &A,
    base: &p3_uni_stark::Proof<InnerWhirConfig>,
    public_inputs: &[F],
) -> Result<RecursionCircuit, Box<dyn std::error::Error>>
where
    A: RecursiveAir<F, Challenge, LogUpGadget>,
{
    let perm = Poseidon2Config::KOALA_BEAR_D4_W16;
    let backend = WhirRecursionBackend::<16, 8>::new(perm).for_extension_degree::<4>();
    let prev = RecursionInput::UniStark {
        proof: base,
        air,
        public_inputs: public_inputs.to_vec(),
        preprocessed_commit: None,
    };

    let mut builder = CircuitBuilder::new();
    PcsRecursionBackend::<InnerWhirConfig, A, 4>::preflight_input(&backend, inner, &prev)?;
    PcsRecursionBackend::<InnerWhirConfig, A, 4>::validate_input(&backend, inner, &prev)?;
    PcsRecursionBackend::<InnerWhirConfig, A, 4>::prepare_circuit(&backend, inner, &mut builder)?;
    let verifier_inputs = StarkVerifierInputsBuilder::<_, _, _>::try_allocate(
        &mut builder,
        base,
        None,
        public_inputs.len(),
    )?;
    let op_ids = verify_p3_uni_proof_circuit::<
        A,
        InnerWhirConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        (),
        WhirUniProofTargets<F, Challenge, WhirMmcs, DIGEST_ELEMS>,
        Poseidon2Config,
        16,
        8,
    >(
        inner,
        air,
        &mut builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        inner.pcs_verifier_params(),
        perm,
    )?;
    // Bind the statement: the circuit's public values are the verifier's own AIR
    // public-value targets, exactly the values the settlement `verify` is checked
    // against.
    let exports: Vec<StatementExport> = verifier_inputs
        .air_public_targets
        .iter()
        .map(|&target| StatementExport::Base(target))
        .collect();
    let schema = builder.set_statement_exports::<F>(&exports)?;

    let public = verifier_inputs.try_pack_public_values(public_inputs, base, &None)?;
    let private = verifier_inputs.try_pack_private_values(base)?;
    let circuit = builder.build()?;
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    PcsRecursionBackend::<InnerWhirConfig, A, 4>::set_private_data(
        &backend,
        inner,
        &mut runner,
        &op_ids,
        &prev,
    )?;
    let traces = runner.run()?;
    Ok(RecursionCircuit {
        circuit,
        traces,
        schema,
    })
}

/// Proves a witnessed recursion circuit under the Keccak WHIR settlement config
/// and returns the proof plus its verifier.
///
/// The non-primitive parts the circuit needs — the shared Poseidon2 table, the
/// recompose tables, and the statement table — are replicated for the Keccak
/// `StarkGenericConfig`. They recompute the same permutations the circuit used, so
/// the relation is identical even though the outer transcript and Merkle scheme
/// are Keccak. The returned verifier binds the statement: `verify(&proof, pis)`
/// accepts only for the `pis` the circuit was built with.
///
/// # Errors
///
/// Returns the settlement config error if `log_max_lde` is below the protocol's
/// minimum trace height, or a prover error if circuit preparation or proving
/// fails.
pub fn settle_recursion_circuit(
    rc: &RecursionCircuit,
    log_max_lde: usize,
) -> Result<
    (
        p3_circuit_prover::BatchStarkProof<crate::whir::Config>,
        p3_circuit_prover::CircuitVerifier<crate::whir::Config>,
    ),
    Box<dyn std::error::Error>,
> {
    let settlement = crate::whir::config(CAP_HEIGHT, log_max_lde)?;
    settle_recursion_circuit_with(rc, settlement)
}

/// [`settle_recursion_circuit`] under an arbitrary WHIR config.
///
/// The recursion circuit relation (Poseidon2 + recompose + statement tables)
/// is config-agnostic - the same argument
/// [`crate::transfer::settle_transfer_circuit_with`] makes for transfers: the
/// preprocessors are keyed on the base field, the AIR builders are generic
/// over SC, and only the PCS and challenger differ. Settling an INTERMEDIATE
/// layer under [`InnerWhirConfig`] (Poseidon2 `InSC`) is what lets the next
/// [`build_batch_recursion_circuit`] consume it; only the final layer settles
/// under the Keccak [`crate::whir::Config`].
///
/// # Errors
///
/// Returns a prover error if circuit preparation or proving fails under the config.
pub fn settle_recursion_circuit_with<SC>(
    rc: &RecursionCircuit,
    settlement: SC,
) -> Result<
    (
        p3_circuit_prover::BatchStarkProof<SC>,
        p3_circuit_prover::CircuitVerifier<SC>,
    ),
    Box<dyn std::error::Error>,
>
where
    SC: p3_uni_stark::StarkGenericConfig<Challenge = Challenge> + Send + Sync + Clone + 'static,
    p3_uni_stark::Val<SC>: p3_field::PrimeField64
        + p3_field::Field
        + p3_circuit_prover::config::StarkField
        + p3_field::extension::BinomiallyExtendable<4>,
    Challenge: p3_field::ExtensionField<p3_uni_stark::Val<SC>>
        + p3_field::BasedVectorSpace<p3_uni_stark::Val<SC>>
        + From<p3_uni_stark::Val<SC>>
        + p3_circuit_prover::field_params::ExtractBinomialW<p3_uni_stark::Val<SC>>,
    SC::Challenger: p3_challenger::GrindingChallenger<Witness = p3_uni_stark::Val<SC>>,
    p3_uni_stark::PcsProverError<SC>: Send,
    SC::Pcs: Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::Domain:
        p3_commit::PolynomialSpace<Val = F> + Send + Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::Commitment: Sync,
    p3_air::SymbolicExpressionExt<p3_uni_stark::Val<SC>, Challenge>: p3_field::Algebra<p3_uni_stark::SymbolicExpression<p3_uni_stark::Val<SC>>>
        + p3_field::Algebra<Challenge>,
    p3_circuit_prover::batch_stark_prover::Poseidon2AirBuilderForConfig<4>:
        p3_circuit_prover::common::NpoAirBuilder<SC, 4>,
    p3_circuit_prover::batch_stark_prover::RecomposeAirBuilder<4>:
        p3_circuit_prover::common::NpoAirBuilder<SC, 4>,
{
    let shared = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<p3_uni_stark::Val<SC>>>> = vec![
        Box::new(Poseidon2SharedPreprocessor::new(vec![shared])),
        recompose_preprocessor::<p3_uni_stark::Val<SC>>(true),
        Box::new(StatementPreprocessor::new(rc.schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<SC, 4>>> =
        poseidon2_air_builders_for_configs::<SC, 4>(vec![shared]);
    air_builders.push(Box::new(RecomposeAirBuilder::<4>::new(1, true)));
    air_builders.push(Box::new(StatementAirBuilder::<4>::new(rc.schema.clone())));

    let mut prover = BatchStarkProver::new(settlement)
        .with_table_packing(ProveNextLayerParams::default().table_packing);
    prover.register_poseidon2_table::<4>(shared);
    prover.register_recompose_table::<4>(true);
    prover.register_table_prover(Box::new(StatementProver::<4>::new(rc.schema.clone())));
    let prepared = prover.prepare_circuit(
        &rc.circuit,
        &preprocessors,
        &air_builders,
        ConstraintProfile::Standard,
    )?;
    let proof = prepared.prove(&rc.traces)?;
    Ok((proof, prepared.verifier()))
}

/// Build, witness, and statement-bind the recursion circuit that verifies one
/// *batch* WHIR proof — the shape a transfer settlement produces.
///
/// This is the join between [`crate::transfer`] and the recursion engine. The
/// transfer is proven under the Poseidon2 `InSC` with
/// [`crate::transfer::settle_transfer_circuit_with`], yielding a
/// `BatchStarkProof<InnerWhirConfig>`; this function re-verifies that proof
/// inside a circuit and exports its statement, so the resulting `RecursionCircuit`
/// can be wrapped by [`settle_recursion_circuit`] under the Keccak `OutSC`.
///
/// ## Why the trusted entry point
///
/// [`p3_recursion::verifier::verify_trusted_p3_batch_proof_circuit`] is used
/// rather than the plain `verify_p3_batch_proof_circuit`. The trusted variant
/// derives every table AIR and every table's public values from the *retained
/// verifier descriptor* instead of from the proof, so a proof cannot choose its own
/// relation. It also calls `verifier.verify(proof, statement)` before allocating
/// anything, which is what makes the statement binding real rather than advisory.
///
/// ## Statement binding
///
/// The statement table is one instance among the batch's non-primitive tables. Its
/// position comes from `verifier.statement_layout().table_instance()`, and the
/// circuit's statement sink is installed from *that instance's* AIR public-value
/// targets — the same targets the in-circuit verifier constrained. A proof bound to
/// any other statement fails before the sink is ever reached.
///
/// # Errors
///
/// Returns the first failure from native verification of the inner proof, table
/// reconstruction, circuit preparation, verifier-circuit build, statement
/// installation, or witnessing.
pub fn build_batch_recursion_circuit(
    inner: &InnerWhirConfig,
    verifier: &p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
    proof: &p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
    statement: &[F],
) -> Result<RecursionCircuit, Box<dyn std::error::Error>> {
    use p3_recursion::verifier::verify_trusted_p3_batch_proof_circuit;
    use p3_recursion::{BatchOnly, TrustedPcsRecursionBackend};

    let perm = Poseidon2Config::KOALA_BEAR_D4_W16;
    let backend = WhirRecursionBackend::<16, 8>::new(perm).for_extension_degree::<4>();

    let statement_instance = verifier
        .statement_layout()
        .table_instance()
        .ok_or("inner verifier carries no statement table to bind")?;

    let mut builder = CircuitBuilder::new();
    PcsRecursionBackend::<InnerWhirConfig, BatchOnly, 4>::prepare_circuit(
        &backend,
        inner,
        &mut builder,
    )?;

    let (verifier_inputs, op_ids) = verify_trusted_p3_batch_proof_circuit::<
        InnerWhirConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        (),
        WhirUniProofTargets<F, Challenge, WhirMmcs, DIGEST_ELEMS>,
        LogUpGadget,
        Poseidon2Config,
        16,
        8,
        4,
    >(
        verifier,
        &mut builder,
        proof,
        statement,
        inner.pcs_verifier_params(),
        &LogUpGadget::new(),
        perm,
    )?;

    // Bind the statement: the circuit's exported base values are the AIR public
    // targets of the statement table instance, exactly the targets the in-circuit
    // verifier constrained against the inner proof.
    let statement_targets = verifier_inputs
        .air_public_targets
        .get(statement_instance)
        .ok_or("statement table instance absent from verifier inputs")?;
    let exports: Vec<StatementExport> = statement_targets
        .iter()
        .map(|&target| StatementExport::Base(target))
        .collect();
    let schema = builder.set_statement_exports::<F>(&exports)?;

    let table_public_inputs = verifier.table_public_values(statement)?;
    let public = verifier_inputs.try_pack_public_values(
        &table_public_inputs,
        &proof.proof,
        verifier.common_data(),
    )?;
    let private = verifier_inputs.try_pack_private_values(&proof.proof)?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    TrustedPcsRecursionBackend::<InnerWhirConfig, BatchOnly, 4>::set_private_data_for_trusted_batch(
        &backend,
        verifier,
        proof,
        statement,
        &mut runner,
        &op_ids,
    )?;
    let traces = runner.run()?;
    Ok(RecursionCircuit {
        circuit,
        traces,
        schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
    use p3_field::PrimeCharacteristicRing;
    use p3_recursion::{PreparedInput, PreparedLayer, PreparedSource};

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

    /// The settlement half of the architecture: the recursion circuit built over
    /// the Poseidon2 `InSC` is proven under the Keccak WHIR `OutSC`, so the proof
    /// that reaches the chain carries a Keccak transcript and a Keccak Merkle
    /// tree that Solidity replays with the native `keccak256` opcode.
    ///
    /// The two configs never meet inside a circuit. The recursion circuit is built
    /// and witnessed entirely against the Poseidon2 `InSC` (the in-circuit Merkle
    /// gadget's field-native cap), and its output — `Traces<Challenge>` — is
    /// config-agnostic: `Challenge` is the same degree-4 extension in both. The
    /// Keccak `OutSC` only ever wraps those traces with the outer WHIR PCS and the
    /// outer Keccak transcript, so the field-native-cap bound that blocks a Keccak
    /// `WhirRecursionConfig` never applies here.
    ///
    /// The statement is bound through `build_recursion_circuit` (see its docs):
    /// the verifier's own AIR public-value targets become the circuit's statement
    /// sink, so the settlement `verify(&proof, pis)` accepts only for the `pis`
    /// the circuit was built with.
    #[test]
    fn keccak_settlement_proves_the_recursion_circuit() {
        // 1. A base proof under the Poseidon2 WHIR recursion config.
        let inner = recursion_config();
        let air = FibonacciAir {};
        let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
        let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];
        let base = p3_uni_stark::prove(&inner, &air, trace, &pis)
            .expect("base WHIR proof should generate");
        p3_uni_stark::verify(&inner, &air, &base, &pis).expect("base WHIR proof should verify");

        // 2. Build and witness the statement-bound recursion circuit.
        let rc = build_recursion_circuit(&inner, &air, &base, &pis)
            .expect("recursion circuit should build and witness");

        // 3. Prove it under the Keccak WHIR settlement config.
        let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE)
            .expect("settlement should prove the recursion circuit under Keccak WHIR");

        // 4. The settlement verifier accepts, and binds the statement: the fib
        //    public inputs are the statement table's public values. Its transcript
        //    is Keccak and its commitments are the Keccak wire-cap Merkle tree,
        //    which is exactly what the Solidity verifier replays.
        verifier
            .verify(&proof, &pis)
            .expect("Keccak WHIR settlement verifier should accept the recursion proof");

        // 5. The binding is real: the same proof must be rejected against any
        //    other statement. Without this, the settlement layer would accept a
        //    proof of *some* recursion and let the chain record arbitrary public
        //    values, which is the whole thing the statement exists to prevent.
        let tampered = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE) + F::ONE];
        assert!(
            verifier.verify(&proof, &tampered).is_err(),
            "settlement verifier must reject a proof bound to different public values"
        );
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
