//! WHIR-backed settlement configuration: the layer a Solidity verifier replays.
//!
//! ## Why WHIR replaces FRI here
//!
//! The rollup settles on an EVM chain, so the proof that reaches the chain has to be
//! cheap to *verify*, not cheap to produce. Two properties of WHIR decide this:
//!
//! 1. **Round-level multi-openings.** WHIR authenticates every query of a round with
//!    one pruned Merkle multiproof (`Mmcs::MultiProof`), instead of one opening per
//!    sampled index. That collapses the verifier's Merkle work from `O(queries x depth)`
//!    separate hash chains into one batched walk per round.
//! 2. **A pluggable transcript.** The WHIR prover and verifier are generic over the
//!    Fiat-Shamir challenger (`FieldChallenger + GrindingChallenger +
//!    CanSampleUniformBits`). A Keccak-256 challenger satisfies all three natively,
//!    so every challenge the on-chain verifier derives comes from the `keccak256`
//!    opcode (`0x20`, ~30 gas) rather than from a hash Solidity would have to
//!    implement itself.
//!
//! ## Where the Poseidon2 exception still lives
//!
//! The recursion VM's in-circuit Merkle gadget is Poseidon2-shaped: the entry point
//! that feeds it Merkle paths takes a permutation config with only Poseidon1 and
//! Poseidon2 variants. There is no Keccak instantiation of that gadget.
//!
//! That constrains only the layers verified *inside* a circuit, and the recursion
//! engine prepares the circuit from the config of the layer being verified, not the
//! one doing the verifying. So the split is:
//!
//! ```text
//!   Shielded layer    SHA3-256      note/nullifier derivation; Keccak-f[1600]
//!                                 rows carrying the 0x06 domain byte
//!   Layers 0..N-1     Poseidon2     Merkle + transcript, verified in-circuit by
//!                                 the recursion engine  <- the granted exception
//!   Layer N (final)   Keccak-256    Merkle + transcript, replayed by Solidity
//!                                 with the native opcode; no exception needed
//! ```
//!
//! The final layer is the one this module builds. Nothing in it is checked in-circuit,
//! so its Keccak commitments and Keccak transcript cost the recursion engine nothing.
//!
//! ## Field
//!
//! `KoalaBear` base with a degree-4 binomial extension. Degree 4 is what the upstream
//! recursion backend supports for WHIR; the security margin comes from the protocol
//! parameter below rather than from the extension degree, so `SECURITY_LEVEL` is set
//! directly to the 128-bit target instead of being inferred from `5 x 31` bits.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_sumcheck::layout::PrefixProver;
use p3_uni_stark::StarkConfig;
use p3_whir::parameters::{
    FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirConfigError,
};

use crate::config::Mmcs;

/// Base field: `KoalaBear`, a 31-bit Mersenne-prime-friendly field with a large
/// two-adic subgroup, which is what WHIR's folding rounds need.
pub type F = KoalaBear;

/// Challenge field: degree-4 binomial extension of [`F`].
///
/// Degree 4 is fixed by the recursion backend's WHIR support, not by security.
/// The security target is set explicitly in [`PROTOCOL_PARAMS`].
pub type Challenge = BinomialExtensionField<F, 4>;

/// The Keccak-256 Fiat-Shamir transcript.
///
/// Each base-field element is absorbed as its little-endian `u32`, the same byte
/// convention the shielded layer and the Solidity verifier use, so the on-chain
/// side reproduces the transcript with `abi.encodePacked` plus `keccak256`.
pub type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

/// FFT engine used to encode WHIR's committed codewords.
pub type Dft = Radix2DitParallel<F>;

/// The WHIR-backed univariate PCS over the Keccak Merkle tree.
///
/// Implements `UnivariateStarkPcs`, so it drops into `p3_uni_stark::{prove, verify}`
/// unchanged: switching from FRI to WHIR is a PCS substitution, not a prover rewrite.
pub type Pcs = WhirUniPcs<Challenge, F, Dft, Mmcs, Challenger, PrefixProver<F, Challenge>>;

/// The full settlement STARK configuration.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Conjectured security level in bits, targeting the post-quantum bound.
///
/// Set explicitly rather than derived from the extension degree: WHIR spends its
/// security budget across folding rounds, STIR queries and proof-of-work, so the
/// protocol parameter is the honest place to state the target.
///
/// ## Why 96 and not 128
///
/// WHIR's security is capped *structurally*, before any grinding, by the initial
/// batching claim:
///
/// ```text
///   bits = log2(|EF|) - 1 - log2(claims - 1) - list_size_bits
/// ```
///
/// The batching challenge that combines the opening claims happens *before* the
/// first folding grind, so proof-of-work provably cannot recover security lost
/// here — grinding only tops up what the algebra leaves short.
///
/// On `KoalaBear` with a degree-4 extension, `log2(|EF|) - 1` is 123 bits. A
/// small statement like the test's Fibonacci AIR (6 opening claims, rate 1/2)
/// lands near 107 bits no matter how hard it grinds. 128 is therefore not a
/// tuning knob on this field: it is above the ceiling.
///
/// 96 sits comfortably under that ceiling with real margin, is a recognised
/// post-quantum level for hash-based assumptions, and grinds only a handful of
/// bits at batch sizes. Raising the target past ~107 would require a larger
/// extension degree or field, which the recursion backend does not support for
/// WHIR today.
pub const SECURITY_LEVEL: usize = 96;

/// Folding factor per WHIR round.
///
/// `WhirUniPcs` requires a constant folding factor; 4 matches the recursion
/// backend's supported extension degree and keeps the round count low.
pub const FOLDING_FACTOR: usize = 4;

/// Build the WHIR protocol parameters.
///
/// `round_log_inv_rates` is left empty so the round schedule is derived per commit.
/// A config that serves more than one trace size — a base proof's opening and the
/// verifier circuit's own trace — needs this, or the two would demand conflicting
/// schedules from one fixed list.
///
/// The soundness regime is [`SecurityAssumption::JohnsonBound`]. The settlement
/// layer proves the recursion circuit, which re-verifies a WHIR base proof and
/// opens ~500 claims at once. The initial claim-combination ceiling is
/// `field_size_bits - log2(claims - 1) - list_size_bits`, and `CapacityBound`'s
/// degree-dependent list size puts that near 86 bits — under the
/// [`SECURITY_LEVEL`] target, unrecoverable by grinding because the batching
/// challenge precedes the first grind. `JohnsonBound`'s list size is
/// degree-independent (~4.8 bits at rate ½), lifting the ceiling to ~109 bits,
/// and is the proven regime rather than a capacity conjecture. See
/// [`crate::whir_recursion::protocol_params`] for the same reasoning on the
/// recursion side.
#[must_use]
pub const fn protocol_params() -> ProtocolParameters {
    ProtocolParameters {
        security_level: SECURITY_LEVEL,
        pow_bits: 0,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(FOLDING_FACTOR),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

/// Grinding budget the protocol derives for a given statement size.
///
/// WHIR buys part of its security from the field and folding schedule and the rest
/// from proof-of-work. At [`SECURITY_LEVEL`] a `KoalaBear` / degree-4 extension
/// cannot cover the whole target algebraically, so some grinding is mandatory, and
/// the amount depends on how many variables the statement has.
///
/// The budget is found by search rather than stated, because the schedule both
/// reports and enforces the requirement, and its feasible band is narrow:
///
/// - too small a budget is rejected outright, since the target cannot be reached;
/// - a budget at or above [`SECURITY_LEVEL`] credits grinding with the *whole*
///   target, which drops the query count to zero and makes the proximity test
///   accept any committed function.
///
/// So the answer is the smallest budget that builds a schedule with queries left in
/// it, which is also the cheapest one that is still sound.
///
/// # Errors
///
/// Returns the last WHIR configuration error if no budget below the security level
/// yields a feasible schedule, which means the target cannot be met at this size.
///
/// # Panics
///
/// Never. A compile-time assertion guarantees `SECURITY_LEVEL > 0`, so the search
/// runs at least once and always yields an error to report when no budget fits.
pub fn required_pow_bits(num_variables: usize) -> Result<usize, WhirConfigError> {
    const _: () = assert!(SECURITY_LEVEL > 0, "security level must be positive");
    let mut last_error = None;
    for budget in 0..SECURITY_LEVEL {
        let params = ProtocolParameters {
            pow_bits: budget,
            ..protocol_params()
        };
        match WhirConfig::<Challenge, F, Challenger>::new(num_variables, params) {
            Ok(schedule) => return Ok(schedule.max_pow_bits()),
            Err(err) => last_error = Some(err),
        }
    }
    // The const assertion above makes the loop run at least once, so `last_error`
    // is always `Some` here; the fallback is unreachable but returns an error
    // rather than panicking, so no caller can crash on it.
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

/// Assemble the settlement configuration.
///
/// `cap_height` is the Merkle cap height: the tree is committed with its top
/// `cap_height` levels withheld, trading a slightly larger opening proof for a
/// smaller commitment.
///
/// `num_variables` is the largest statement the config will be asked to prove. The
/// grinding budget is derived from it, so the config is guaranteed to accept every
/// statement up to that size and refuses to be built at all if the security target
/// is unreachable.
///
/// # Errors
///
/// Returns the WHIR configuration error if `num_variables` cannot reach
/// [`SECURITY_LEVEL`].
pub fn config(cap_height: usize, num_variables: usize) -> Result<Config, WhirConfigError> {
    let pow_bits = required_pow_bits(num_variables)?;
    let params = ProtocolParameters {
        pow_bits,
        ..protocol_params()
    };
    let pcs = Pcs::new(
        params,
        Dft::default(),
        crate::config::mmcs(cap_height),
        crate::config::challenger(),
        num_variables,
    );
    Ok(StarkConfig::new(pcs, crate::config::challenger()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    /// Fibonacci AIR: `a' = a + b`, `b' = a + 2b`, with the *final* `a` exposed
    /// as the public output.
    ///
    /// The public value is bound by a constraint rather than a cell pin, because
    /// univariate STARKs reject boundary cell pins.
    #[derive(Clone, Copy, Debug)]
    struct FibAir;

    impl<F> BaseAir<F> for FibAir {
        fn width(&self) -> usize {
            2
        }

        fn num_public_values(&self) -> usize {
            1
        }
    }

    impl<AB: AirBuilder> Air<AB> for FibAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
            let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
            let two = AB::F::ONE + AB::F::ONE;
            let out: AB::Expr = builder.public_values()[0].into();

            builder.when_first_row().assert_eq(a, AB::F::ONE);
            builder.when_first_row().assert_eq(b, AB::F::ONE);
            builder.when_transition().assert_eq(a + b, a_next);
            builder.when_transition().assert_eq(a + b * two, b_next);
            builder.when_last_row().assert_eq(a, out);
        }
    }

    /// Build the Fibonacci trace and the public output it proves.
    ///
    /// Row `i` is `(a_i, b_i)` following the AIR's own recurrence, so the trace
    /// and the constraints are written from the same rule.
    fn fib(len: usize) -> (RowMajorMatrix<F>, Vec<F>) {
        let mut values = vec![F::ONE; len * 2];
        for i in 1..len {
            let a = values[(i - 1) * 2];
            let b = values[(i - 1) * 2 + 1];
            values[i * 2] = a + b;
            values[i * 2 + 1] = a + (b + b);
        }
        let last_row_a = values[values.len() - 2];
        (RowMajorMatrix::new(values, 2), vec![last_row_a])
    }

    /// Trace length used by these tests; 64 rows is 6 variables.
    const LOG_TRACE: usize = 6;

    fn settlement_config() -> Config {
        config(0, LOG_TRACE).expect("WHIR settlement config should build")
    }

    #[test]
    fn whir_keccak_proves_and_verifies_natively() {
        let config = settlement_config();
        let air = FibAir;
        let (trace, pis) = fib(1 << LOG_TRACE);

        let proof =
            p3_uni_stark::prove(&config, &air, trace, &pis).expect("WHIR proof generation failed");
        p3_uni_stark::verify(&config, &air, &proof, &pis)
            .expect("WHIR/Keccak proof failed to verify natively");
    }

    #[test]
    fn whir_rejects_a_wrong_public_input() {
        let config = settlement_config();
        let air = FibAir;
        let (trace, pis) = fib(1 << LOG_TRACE);
        let proof =
            p3_uni_stark::prove(&config, &air, trace, &pis).expect("WHIR proof generation failed");

        let mut tampered = pis;
        tampered[0] += F::ONE;
        assert!(
            p3_uni_stark::verify(&config, &air, &proof, &tampered).is_err(),
            "a proof must not verify against a public input it was not made for"
        );
    }

    #[test]
    fn grinding_budget_is_sized_not_guessed() {
        // The budget the config uses is exactly what the schedule demands, so no
        // statement up to the declared size is refused and none grinds extra.
        let required = required_pow_bits(LOG_TRACE).expect("schedule should be feasible");
        // At 96-bit with a small statement the algebra already covers the target,
        // so grinding may legitimately be zero. What we refuse is a budget at or
        // above the security level, which zeroes the query count and makes the
        // proximity test accept any committed function.
        assert!(
            required < SECURITY_LEVEL,
            "a budget at the security level zeroes the query count: {required}"
        );
    }

    #[test]
    fn grinding_grows_with_statement_size() {
        // Monotonicity is what lets one config sized at a maximum serve every
        // smaller statement. If this ever breaks, the sizing rule is wrong.
        let small = required_pow_bits(10).expect("feasible");
        let large = required_pow_bits(22).expect("feasible");
        assert!(
            small <= large,
            "required grinding must not shrink as the statement grows: {small} > {large}"
        );
    }

    #[test]
    fn one_config_sized_at_max_serves_smaller_statements() {
        // The operational contract: a node builds one config at its largest
        // expected batch and proves smaller statements through it.
        let config = config(0, 22).expect("config at batch size should build");
        let air = FibAir;
        let (trace, pis) = fib(1 << LOG_TRACE);
        let proof = p3_uni_stark::prove(&config, &air, trace, &pis)
            .expect("a small statement must prove under a batch-sized config");
        p3_uni_stark::verify(&config, &air, &proof, &pis)
            .expect("a small statement must verify under a batch-sized config");
    }
}
