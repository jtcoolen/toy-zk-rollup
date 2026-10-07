//! Grinding-vs-queries grid at the CURRENT operating point (D-092 batch 45).
//!
//! The chain runs rate 4/4 at arity 24 with the minimum feasible grind.
//! This sweep holds (arity, rate, folding) fixed and walks the grinding
//! budget upward, printing the resulting per-round query schedule and a
//! paths proxy - the lever that decides whether the engine drops below
//! ~45M (fewer queries = less per-query work: foldRow + leaf keccak).

use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use prover::whir_recursion::{Challenge, WhirChallenger, F};

const SECURITY_LEVEL: usize = 96;

const fn params(pow_bits: usize, log_inv_rate: usize, folding: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level: SECURITY_LEVEL,
        pow_bits,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(folding),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: log_inv_rate,
    }
}

fn schedule_line(cfg: &WhirConfig<Challenge, F, WhirChallenger>) -> String {
    let rounds: Vec<String> = cfg
        .round_parameters()
        .iter()
        .map(|r| format!("{}q@d{}", r.num_queries, r.log_folded_domain_size))
        .collect();
    let t = cfg.terminal();
    let last = cfg.round_parameters().last();
    let tdepth = last.map_or(8, |l| l.log_folded_domain_size.saturating_sub(1));
    let tot: usize = cfg.round_parameters().iter().map(|r| r.num_queries).sum::<usize>() + t.num_queries;
    format!(
        "total_q={tot:>4} [{}] terminal={}q@d{} max_pow={}",
        rounds.join(" "),
        t.num_queries,
        tdepth,
        cfg.max_pow_bits()
    )
}

#[test]
#[ignore = "schedule sweep; run with --nocapture"]
fn pow_grid_rate4_arity24() {
    for rate in [3usize, 4] {
        println!("=== arity 24, folding 4, rate {rate}: grinding budget sweep ===");
        for pow in [0usize, 8, 16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80, 88] {
            match WhirConfig::<Challenge, F, WhirChallenger>::new(24, params(pow, rate, 4)) {
                Ok(cfg) => println!("pow={pow:>3} {}", schedule_line(&cfg)),
                Err(e) => println!("pow={pow:>3} infeasible: {e:?}"),
            }
        }
    }
}
