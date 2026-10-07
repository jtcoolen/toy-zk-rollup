//! WHIR parameter sweep: how do grinding budget, starting inverse rate, and
//! folding factor move the query budget (and therefore the on-chain proof,
//! which is paths-dominated: paths = queries x depth x 32 B)?
//!
//! Pure schedule solving - no proving - so a full sweep is instant. The
//! `proof_proxy` column estimates the paths bytes of one STARK at that arity:
//! sum over rounds of `num_queries` x `log_folded_domain` x 32.

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

/// Estimated paths bytes: per round queries x depth x 32, plus the terminal
/// round at its own depth. Depth of a round is its `log_folded_domain_size`.
fn proof_proxy(cfg: &WhirConfig<Challenge, F, WhirChallenger>) -> usize {
    let mut bytes = 0usize;
    for r in cfg.round_parameters() {
        bytes += r.num_queries * r.log_folded_domain_size * 32;
    }
    let t = cfg.terminal();
    // terminal depth: last round folded domain minus one folding step
    let last = cfg.round_parameters().last();
    let tdepth = last.map_or(8, |l| l.log_folded_domain_size.saturating_sub(1));
    bytes += t.num_queries * tdepth * 32;
    bytes
}

#[test]
#[ignore = "parameter sweep; run with --nocapture"]
fn sweep_grinding() {
    // The chain settles at arity 24 (`CHAIN_LOG_MAX_LDE`); probe that plus 21
    // (the base fib layer) for context.
    for arity in [21usize, 24] {
        println!("=== arity {arity}, folding 4, rate 1/2: grinding budget sweep ===");
        println!(
            "{:>8} {:>10} {:>12} {:>12}",
            "pow", "tot_q", "proxy_KiB", "feasible"
        );
        for pow in [0usize, 8, 16, 20, 23, 24, 32, 48, 64, 80, 96] {
            match WhirConfig::<Challenge, F, WhirChallenger>::new(arity, params(pow, 1, 4)) {
                Ok(cfg) => {
                    let tot: usize = cfg.round_parameters().iter().map(|r| r.num_queries).sum();
                    let proxy = proof_proxy(&cfg);
                    println!("{:>8} {:>10} {:>12} {:>12}", pow, tot, proxy / 1024, "yes");
                }
                Err(e) => println!(
                    "{:>8} {:>10} {:>12} {:>12}",
                    pow,
                    "-",
                    "-",
                    format!("{e:?}")
                ),
            }
        }
    }
}

#[test]
#[ignore = "parameter sweep; run with --nocapture"]
fn sweep_rate_and_folding() {
    for arity in [21usize, 24] {
        println!("=== arity {arity}: rate x folding grid (pow = min feasible) ===");
        println!(
            "{:>6} {:>8} {:>10} {:>12} {:>12}",
            "rate", "fold", "tot_q", "proxy_KiB", "status"
        );
        for rate in [1usize, 2, 3] {
            for fold in [2usize, 4, 8] {
                // find min feasible pow for this combo
                let mut found = None;
                for pow in 0..SECURITY_LEVEL {
                    if let Ok(cfg) = WhirConfig::<Challenge, F, WhirChallenger>::new(
                        arity,
                        params(pow, rate, fold),
                    ) {
                        found = Some((pow, cfg));
                        break;
                    }
                }
                match found {
                    Some((pow, cfg)) => {
                        let tot: usize = cfg.round_parameters().iter().map(|r| r.num_queries).sum();
                        let proxy = proof_proxy(&cfg);
                        println!(
                            "{:>6} {:>8} {:>10} {:>12} pow={pow}",
                            rate,
                            fold,
                            tot,
                            proxy / 1024
                        );
                    }
                    None => println!("{:>6} {:>8} {:>10} {:>12} infeasible", rate, fold, "-", "-"),
                }
            }
        }
    }
}
