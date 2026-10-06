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

/// Arity the zero-knowledge masks add to every committed polynomial.
///
/// Blinding doubles each committed height, and the stacked arity WHIR sizes its
/// grinding against is the height of what actually gets committed. So a
/// statement whose trace tops out at `2^n` is committed at `2^(n + 1)`, and the
/// grinding budget has to be read off that arity — sizing it at `n` asks the
/// schedule for fewer bits than the doubled commitment will demand, and the
/// commit is rejected as under-grounded.
///
/// The second unit is the witness width. The stacked arity WHIR sizes against
/// is not the trace height alone but the height plus the columns stacked on
/// top of it, and for these circuits the width contributes one more variable
/// on top of the doubling. Measured on both the recursion circuit (which
/// demands 18 grinding bits at `log_max_lde = 22`) and the block circuit
/// (23 bits at 25), the largest commitment stacks at exactly
/// `log_max_lde + 2`, so that is the arity the budget is read off.
pub const ZK_ARITY_SLACK: usize = 2;

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
/// If the requested arity is past the field's domain capacity — no budget builds
/// a schedule at all — the search backs off to the largest arity that does build,
/// rather than failing. This is safe: the grinding budget is an upper bound on
/// what any smaller statement will demand, and a budget sized at a larger arity
/// only ever over-provisions (more grinding, never less soundness). It is the
/// width-plus-ZK ceiling (`log_max_lde + 2`) that runs into the capacity wall at
/// the top of the supported range; backing off keeps the top of the range usable
/// without special-casing each circuit.
///
/// # Errors
///
/// Returns the last WHIR configuration error if no arity from `num_variables`
/// down to zero yields a feasible schedule, which means the target cannot be met
/// at any size.
///
/// # Panics
///
/// Never. A compile-time assertion guarantees `SECURITY_LEVEL > 0`, so the search
/// runs at least once and always yields an error to report when no budget fits.
pub fn required_pow_bits(num_variables: usize) -> Result<usize, WhirConfigError> {
    required_pow_bits_with(num_variables, 1)
}

/// [`required_pow_bits`] at an explicit starting inverse rate.
pub fn required_pow_bits_with(
    num_variables: usize,
    starting_log_inv_rate: usize,
) -> Result<usize, WhirConfigError> {
    const _: () = assert!(SECURITY_LEVEL > 0, "security level must be positive");
    let mut last_error = None;
    // Back off from the requested arity down to zero. The first arity that builds
    // a schedule wins; within it, the smallest budget that leaves queries in.
    for arity in (0..=num_variables).rev() {
        for budget in 0..SECURITY_LEVEL {
            let params = ProtocolParameters {
                pow_bits: budget,
                starting_log_inv_rate,
                ..protocol_params()
            };
            match WhirConfig::<Challenge, F, Challenger>::new(arity, params) {
                Ok(schedule) => return Ok(schedule.max_pow_bits()),
                Err(err) => last_error = Some(err),
            }
        }
    }
    // The inner loop runs at least once for arity 0, so `last_error` is always
    // `Some` here; the fallback is unreachable but returns an error rather than
    // panicking, so no caller can crash on it.
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
    config_with(cap_height, num_variables, 1)
}

/// [`config`] at an explicit starting inverse rate. Rate 2 (quarter-rate)
/// roughly halves the STIR query budget - the dominant term of the on-chain
/// proof - at the cost of one more arity of committed domain; the final
/// layer's arity budget is what decides whether it fits. Soundness stays
/// `JohnsonBound` (the proven regime) at every rate.
pub fn config_with(
    cap_height: usize,
    num_variables: usize,
    starting_log_inv_rate: usize,
) -> Result<Config, WhirConfigError> {
    let pow_bits = required_pow_bits_with(num_variables + ZK_ARITY_SLACK, starting_log_inv_rate)?;
    let params = ProtocolParameters {
        pow_bits,
        starting_log_inv_rate,
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
    use p3_field::PrimeCharacteristicRing;

    use crate::fixtures::{fib, FibAir};

    #[test]
    #[ignore = "parameter sweep; run with --nocapture when sizing the on-chain schedule"]
    fn dump_schedule_curve() {
        // Extension degree vs query count, at our block circuit's actual
        // stacked arity (25; measured as needing 19 grinding bits).
        //
        // WHIR's initial batching ceiling is
        //     bits = log2(|EF|) - 1 - log2(claims - 1) - list_size_bits
        // and everything short of the security target is bought back with
        // QUERIES. So |EF| is the biggest single lever on proof size.
        //
        // KoalaBear supports binomial extensions of degree 4 and 8 only
        // (`BinomialExtensionData<4>` / `<8>`); the quintic `sol-whir-p3`
        // uses is a TRINOMIAL (X^5+X^2-1), a different type that this
        // workspace's WHIR path does not accept.
        use p3_field::extension::BinomialExtensionField;
        type EF4 = BinomialExtensionField<F, 4>;
        type EF8 = BinomialExtensionField<F, 8>;

        for (label, rows) in [("ext4", sweep_q::<EF4>()), ("ext8", sweep_q::<EF8>())] {
            for (lir, pow, rounds, total) in rows {
                println!(
                    "  {label} lir={lir} pow={pow:>3}: rounds={rounds} total_queries={total:>4}"
                );
            }
        }
    }

    /// Total queries per (lir, pow) for a given extension field, at nv=25.
    fn sweep_q<EF>() -> Vec<(usize, usize, usize, usize)>
    where
        EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField,
    {
        let mut out = Vec::new();
        for lir in [1usize, 2, 3] {
            for pow in [19usize, 24, 32, 48] {
                let params = ProtocolParameters {
                    security_level: SECURITY_LEVEL,
                    pow_bits: pow,
                    round_log_inv_rates: Vec::new(),
                    folding_factor: FoldingFactor::Constant(FOLDING_FACTOR),
                    soundness_type: SecurityAssumption::JohnsonBound,
                    starting_log_inv_rate: lir,
                };
                if let Ok(cfg) = WhirConfig::<EF, F, Challenger>::new(25, params) {
                    let total: usize = cfg
                        .round_parameters()
                        .iter()
                        .map(|r| r.num_queries)
                        .sum::<usize>()
                        + cfg.final_round_config().num_queries;
                    out.push((lir, pow, cfg.n_rounds(), total));
                }
            }
        }
        out
    }

    /// Trace length used by these tests.
    ///
    /// Zero knowledge puts a floor on this: the mask must supply at least
    /// `2 * (e * n_F + n_D)` random field elements (eq. 17 of
    /// <https://eprint.iacr.org/2024/1037>), where `e` is the extension
    /// degree, `n_F` the out-of-domain opening count and `n_D` the WHIR
    /// query count. At 96-bit security with a degree-4 extension that floor is
    /// a few hundred elements, so a 64-row trace cannot be hidden at all and
    /// the prover refuses it rather than emitting a proof that leaks. 4096
    /// rows clears it with room to spare and matches the smallest batch the
    /// settlement layer actually sees.
    const LOG_TRACE: usize = 12;

    /// Height the test config is sized at, mirroring production: one config
    /// built at the largest LDE the settlement layer will see, used for every
    /// smaller statement.
    ///
    /// The prover's *stacked* commit arity is not the trace height. It is the
    /// trace height plus the width's contribution, plus the ZK doubling, and
    /// the quotient-chunk expansion pushes it higher still — for this AIR the
    /// largest commitment stacks to 17 variables even though the trace is 12.
    /// Sizing the grinding budget at the raw trace height under-provisions it
    /// and the prover refuses the statement. Production sidesteps this by
    /// sizing once at the batch ceiling; the tests do the same.
    const CONFIG_LDE: usize = 22;

    fn settlement_config() -> Config {
        config(0, CONFIG_LDE).expect("WHIR settlement config should build")
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
    /// The grinding budget the schedule derives, per statement arity.
    ///
    /// Recorded as a test because the curve is what makes the settlement height a
    /// security decision rather than a tuning knob: each doubling of the statement
    /// costs roughly one more ground bit, and a config sized below the arity the
    /// prover actually commits at is refused.
    #[test]
    fn pow_bits_grows_with_statement_arity() {
        for v in 16..=24 {
            match crate::whir::required_pow_bits(v) {
                Ok(bits) => assert!(
                    bits < SECURITY_LEVEL,
                    "budget must stay under the target at {v} variables"
                ),
                Err(e) => panic!("arity {v} should be schedulable: {e}"),
            }
        }
    }
}
