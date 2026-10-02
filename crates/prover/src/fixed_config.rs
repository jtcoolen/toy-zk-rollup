//! Export the settlement WHIR schedule as data the Solidity verifier consumes.
//!
//! # Why this exists
//!
//! The on-chain verifier must agree with the prover on every schedule
//! parameter: round count, folding factors, query counts, `PoW` bits, OOD
//! sample counts, sumcheck round counts, domain sizes. If any of those is
//! hand-transcribed into Solidity, it will drift the first time the prover's
//! parameters move, and the failure mode is a verification failure that
//! looks like a proof bug.
//!
//! So the schedule is **generated, not transcribed**. This module reads the
//! real [`WhirConfig`] our prover builds and emits a [`FixedSchedule`] that
//! serializes to JSON. A Solidity code generator turns that JSON into a
//! `WhirFixedConfig.sol` whose constants are the same numbers, and a test
//! asserts the two agree.
//!
//! This mirrors the architecture of `ethereum/sol-whir-p3`, which splits
//! each schedule into a generated `*FixedConfig` contract, a protocol
//! `Core`, a wire `Codec`, and a native blob verifier. The key property
//! borrowed from there is that **the schedule is data, not control flow**:
//! the Solidity verifier reads its parameters from a generated contract
//! rather than encoding them in `if` chains.
//!
//! See `.scratch/pq-shielded-rollup/decisions.md` D-047 for the full
//! reference-repo comparison, and D-036 for why we take the standalone
//! WHIR path rather than their `LeanVM` terminal.

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::ExtensionField;
use p3_whir::parameters::{RoundConfig, WhirConfig};
use serde::{Deserialize, Serialize};

/// Project one `p3_whir::RoundConfig` onto the plain-data form.
const fn round_schedule(round: &RoundConfig) -> RoundSchedule {
    RoundSchedule {
        pow_bits: round.pow_bits,
        folding_pow_bits: round.folding_pow_bits,
        num_queries: round.num_queries,
        ood_samples: round.ood_samples,
        num_variables: round.num_variables,
        folding_factor: round.folding_factor,
        log_inv_rate: round.log_inv_rate,
        domain_size: round.domain_size,
        log_folded_domain_size: round.log_folded_domain_size,
    }
}

/// One WHIR round's derived parameters.
///
/// Mirrors `p3_whir::parameters::RoundConfig` field-for-field. Kept as a
/// plain data type (no generics, no field elements) so it serializes
/// cleanly and the Solidity side has nothing to interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundSchedule {
    /// `PoW` bits for this round's `STIR` query phase.
    pub pow_bits: usize,
    /// `PoW` bits for this round's folding sumcheck.
    pub folding_pow_bits: usize,
    /// `STIR` proximity queries in this round.
    pub num_queries: usize,
    /// Out-of-domain evaluation samples.
    pub ood_samples: usize,
    /// Multilinear variables remaining after folding in this round.
    pub num_variables: usize,
    /// Variables folded in this round.
    pub folding_factor: usize,
    /// Log-inverse rate of the codeword committed after this round.
    pub log_inv_rate: usize,
    /// Evaluation domain size before folding in this round.
    pub domain_size: usize,
    /// Log of the folded evaluation domain size.
    pub log_folded_domain_size: usize,
}

/// The whole settlement schedule, as data.
///
/// Every number the Solidity verifier needs in order to know *how many*
/// rounds to run, *how many* queries to draw per round, and *when* to stop.
/// None of these can be inferred from the proof itself — the proof is
/// variable-length precisely because the schedule determines its shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedSchedule {
    /// Variables in the original multilinear polynomial.
    pub num_variables: usize,
    /// Largest base-two domain dimension the encoder supports.
    pub max_log_domain_size: usize,
    /// OOD samples during the commitment phase.
    pub commitment_ood_samples: usize,
    /// `PoW` bits for the initial folding sumcheck, before any `STIR` rounds.
    pub starting_folding_pow_bits: usize,
    /// Proximity queries in the terminal test against the last commitment.
    pub terminal_num_queries: usize,
    /// `PoW` bits guarding the terminal proximity test.
    pub terminal_pow_bits: usize,
    /// Sumcheck rounds in the final phase.
    pub final_sumcheck_rounds: usize,
    /// `PoW` bits for the final folding sumcheck.
    pub final_folding_pow_bits: usize,
    /// Starting log-inverse rate.
    pub starting_log_inv_rate: usize,
    /// Target security level in bits.
    pub security_level: usize,
    /// Configured `PoW` bits.
    pub pow_bits: usize,
    /// Number of intermediate `STIR` rounds.
    pub n_rounds: usize,
    /// Concrete folding factors before the final direct-send phase.
    pub folding_schedule: Vec<usize>,
    /// Per-round derived parameters, in round order.
    pub rounds: Vec<RoundSchedule>,
    /// The final round's derived parameters.
    pub final_round: RoundSchedule,
}

impl FixedSchedule {
    /// Build the schedule from the real `WhirConfig` the prover runs on.
    ///
    /// `max_log_domain_size` is passed in because `WhirConfig` keeps it
    /// private; it is the encoder's capacity, which our caller knows from
    /// the field's two-adicity.
    ///
    /// Every other field is read through the config's public accessors, so
    /// this cannot drift from what the prover actually derived.
    #[must_use]
    pub fn from_whir_config<EF, F, C>(
        config: &WhirConfig<EF, F, C>,
        max_log_domain_size: usize,
    ) -> Self
    where
        F: p3_field::Field + p3_field::PrimeField32,
        EF: ExtensionField<F>,
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let rounds = config
            .round_parameters()
            .iter()
            .map(round_schedule)
            .collect();
        Self {
            num_variables: config.num_variables(),
            max_log_domain_size,
            commitment_ood_samples: config.commitment_ood_samples(),
            starting_folding_pow_bits: config.starting_folding_pow_bits(),
            terminal_num_queries: config.terminal().num_queries,
            terminal_pow_bits: config.terminal().pow_bits,
            final_sumcheck_rounds: config.final_sumcheck_rounds(),
            final_folding_pow_bits: config.final_folding_pow_bits(),
            starting_log_inv_rate: config.starting_log_inv_rate,
            security_level: config.security_level,
            pow_bits: config.pow_bits,
            n_rounds: config.n_rounds(),
            folding_schedule: config.folding_schedule().to_vec(),
            rounds,
            final_round: round_schedule(&config.final_round_config()),
        }
    }

    /// Total `STIR` queries across all rounds plus the terminal test.
    ///
    /// This is the number that drives proof size almost linearly: each query
    /// is a Merkle path over the Keccak tree. Recorded in D-038 as the
    /// reason our proof is 767 KB against `sol-whir-p3`'s 54 KB.
    #[must_use]
    pub fn total_queries(&self) -> usize {
        self.rounds.iter().map(|r| r.num_queries).sum::<usize>() + self.terminal_num_queries
    }

    /// Serialize to pretty JSON for the Solidity code generator.
    ///
    /// # Errors
    ///
    /// Returns a serde error string if serialization fails, which for this
    /// all-integer type means an out-of-memory condition.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_settlement_schedule_extracts_cleanly() {
        // Pull the schedule out of the config the prover actually runs on,
        // so this test fails if the prover's parameters move without the
        // generated Solidity config being regenerated.
        use crate::whir;
        use p3_field::TwoAdicField;
        use p3_uni_stark::StarkGenericConfig as _;

        let nv = 25;
        let cfg = whir::config(0, nv).expect("settlement config should build at arity 25");
        let max_log_domain_size = <crate::whir::F as TwoAdicField>::TWO_ADICITY;
        let whir_cfg = cfg.pcs().whir_config(nv);
        let schedule = FixedSchedule::from_whir_config(&whir_cfg, max_log_domain_size);

        assert_eq!(schedule.num_variables, nv);
        assert_eq!(schedule.max_log_domain_size, 24, "KoalaBear two-adicity");
        assert_eq!(schedule.security_level, 96);
        assert_eq!(schedule.starting_log_inv_rate, 1);
        assert!(
            schedule.n_rounds >= 1,
            "a real schedule folds at least once"
        );
        assert_eq!(schedule.rounds.len(), schedule.n_rounds);
        assert!(schedule.total_queries() > 0);

        // Every round must stay inside the encoder's domain capacity, and the
        // variable count must strictly decrease as folding proceeds.
        let mut prev_vars = nv;
        for round in &schedule.rounds {
            assert!(
                round.log_folded_domain_size <= schedule.max_log_domain_size,
                "folded domain {} exceeds encoder capacity",
                round.log_folded_domain_size
            );
            assert!(
                round.num_variables < prev_vars,
                "folding must reduce the variable count: {prev_vars} -> {}",
                round.num_variables
            );
            prev_vars = round.num_variables;
        }
        assert!(
            schedule.final_round.num_variables <= prev_vars,
            "final round must not increase the variable count"
        );
    }

    #[test]
    fn the_real_schedule_serializes_for_the_solidity_generator() {
        use crate::whir;
        use p3_field::TwoAdicField;
        use p3_uni_stark::StarkGenericConfig as _;

        let nv = 25;
        let cfg = whir::config(0, nv).expect("settlement config should build");
        let whir_cfg = cfg.pcs().whir_config(nv);
        let schedule = FixedSchedule::from_whir_config(
            &whir_cfg,
            <crate::whir::F as TwoAdicField>::TWO_ADICITY,
        );
        let json = schedule.to_json().expect("schedule serializes to JSON");
        let back: FixedSchedule = serde_json::from_str(&json).expect("generated JSON parses back");
        assert_eq!(back, schedule, "the generator input must round-trip");
    }

    #[test]
    fn total_queries_sums_rounds_and_terminal() {
        let schedule = FixedSchedule {
            num_variables: 25,
            max_log_domain_size: 24,
            commitment_ood_samples: 2,
            starting_folding_pow_bits: 4,
            terminal_num_queries: 11,
            terminal_pow_bits: 19,
            final_sumcheck_rounds: 4,
            final_folding_pow_bits: 0,
            starting_log_inv_rate: 1,
            security_level: 96,
            pow_bits: 19,
            n_rounds: 3,
            folding_schedule: vec![4, 4, 4],
            rounds: vec![
                RoundSchedule {
                    pow_bits: 19,
                    folding_pow_bits: 4,
                    num_queries: 100,
                    ood_samples: 2,
                    num_variables: 21,
                    folding_factor: 4,
                    log_inv_rate: 1,
                    domain_size: 1 << 25,
                    log_folded_domain_size: 21,
                },
                RoundSchedule {
                    pow_bits: 19,
                    folding_pow_bits: 0,
                    num_queries: 80,
                    ood_samples: 2,
                    num_variables: 17,
                    folding_factor: 4,
                    log_inv_rate: 1,
                    domain_size: 1 << 21,
                    log_folded_domain_size: 17,
                },
                RoundSchedule {
                    pow_bits: 19,
                    folding_pow_bits: 0,
                    num_queries: 80,
                    ood_samples: 2,
                    num_variables: 13,
                    folding_factor: 4,
                    log_inv_rate: 1,
                    domain_size: 1 << 17,
                    log_folded_domain_size: 13,
                },
            ],
            final_round: RoundSchedule {
                pow_bits: 19,
                folding_pow_bits: 0,
                num_queries: 11,
                ood_samples: 2,
                num_variables: 9,
                folding_factor: 4,
                log_inv_rate: 1,
                domain_size: 1 << 13,
                log_folded_domain_size: 9,
            },
        };
        assert_eq!(schedule.total_queries(), 100 + 80 + 80 + 11);
    }

    #[test]
    fn the_schedule_round_trips_through_json() {
        let schedule = FixedSchedule {
            num_variables: 9,
            max_log_domain_size: 8,
            commitment_ood_samples: 2,
            starting_folding_pow_bits: 0,
            terminal_num_queries: 5,
            terminal_pow_bits: 3,
            final_sumcheck_rounds: 1,
            final_folding_pow_bits: 0,
            starting_log_inv_rate: 1,
            security_level: 96,
            pow_bits: 3,
            n_rounds: 1,
            folding_schedule: vec![4],
            rounds: vec![RoundSchedule {
                pow_bits: 3,
                folding_pow_bits: 0,
                num_queries: 5,
                ood_samples: 2,
                num_variables: 5,
                folding_factor: 4,
                log_inv_rate: 1,
                domain_size: 512,
                log_folded_domain_size: 5,
            }],
            final_round: RoundSchedule {
                pow_bits: 3,
                folding_pow_bits: 0,
                num_queries: 5,
                ood_samples: 2,
                num_variables: 1,
                folding_factor: 4,
                log_inv_rate: 1,
                domain_size: 32,
                log_folded_domain_size: 1,
            },
        };
        let json = schedule.to_json().expect("serializes");
        let back: FixedSchedule = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, schedule);
    }
}

#[cfg(test)]
mod dump {
    use super::*;
    use crate::whir;
    use p3_field::TwoAdicField;
    use p3_uni_stark::StarkGenericConfig as _;

    #[test]
    #[ignore = "diagnostic dump; run with --nocapture to inspect the real schedule"]
    fn print_real_schedule() {
        let nv = 25;
        let cfg = whir::config(0, nv).expect("config");
        let whir_cfg = cfg.pcs().whir_config(nv);
        let s = FixedSchedule::from_whir_config(
            &whir_cfg,
            <crate::whir::F as TwoAdicField>::TWO_ADICITY,
        );
        println!("{}", s.to_json().unwrap());
        println!("TOTAL QUERIES: {}", s.total_queries());
    }
}
