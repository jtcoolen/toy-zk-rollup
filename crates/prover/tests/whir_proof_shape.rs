//! Dump the shape of a real settlement-config WHIR proof so the Solidity walk
//! is written against measurements rather than against a reading of the reference.
//!
//! ```text
//! cargo test -p prover --test whir_proof_shape -- --ignored --nocapture
//! ```
//!
//! The wire type is `WhirUniProof`, one complete WHIR argument per commitment:
//!
//! ```text
//! Proof { commitment, opening_proof: WhirUniProof { rounds: [
//!     PcsProof { whir: WhirProof { initial_ood_answers,
//!                              initial_sumcheck: SumcheckData {
//!                                  polynomial_evaluations: Vec<[EF;2]>,
//!                                  pow_witnesses },
//!                              rounds: [WhirRoundProof { commitment,
//!                                  ood_answers, pow_witness, openings,
//!                                  sumcheck }],
//!                              final_poly: Option<Poly<EF>>,
//!                              final_pow_witness, final_openings,
//!                              final_sumcheck },
//!                evals: [OpeningBatch] } ] },
//!     public_values }
//! ```
//!
//! `polynomial_evaluations` is `Vec<[EF;2]>` - the `(c_a, c_inf)` pair
//! `SumcheckCore.verifyRounds` already consumes, per round.

use p3_field::{BasedVectorSpace, PrimeField32};
use p3_uni_stark::prove;

use prover::config::F;
use prover::fixtures::{fib, FibAir};
use prover::whir::{config, Challenge};

/// Canonical coefficients of one extension element, low order first.
fn ec(v: &Challenge) -> [u32; 4] {
    let s = <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v);
    [
        s[0].as_canonical_u32(),
        s[1].as_canonical_u32(),
        s[2].as_canonical_u32(),
        s[3].as_canonical_u32(),
    ]
}

#[test]
#[ignore = "exploratory dump"]
fn dump_shape() {
    let cfg = config(0, 22).expect("config");
    let air = FibAir;
    let (trace, pis) = fib(1 << 12);
    let proof = prove(&cfg, &air, trace, &pis).expect("prove");
    println!("public_values (pis): {pis:?}");
    println!("degree_bits: {:?}", proof.degree_bits);
    println!("ood_pow_witness: {:?}", proof.ood_pow_witness);
    println!(
        "opened trace_local: {}",
        proof.opened_values.trace_local.len()
    );
    println!(
        "opened trace_next: {:?}",
        proof.opened_values.trace_next.as_ref().map(Vec::len)
    );
    println!(
        "opened quotient_chunks: {}",
        proof.opened_values.quotient_chunks.len()
    );
    let uni = &proof.opening_proof;
    println!("commitment rounds: {}", uni.rounds.len());
    for (ri, rp) in uni.rounds.iter().enumerate() {
        let w = &rp.whir;
        println!("=== commitment round {ri} ===");
        println!("  evals batches: {}", rp.evals.len());
        println!("  initial_ood_answers: {}", w.initial_ood_answers.len());
        println!(
            "  initial_sumcheck: {} rounds, {} pow witnesses",
            w.initial_sumcheck.polynomial_evaluations.len(),
            w.initial_sumcheck.pow_witnesses.len()
        );
        if let Some(&[a, b]) = w.initial_sumcheck.polynomial_evaluations.first() {
            println!("    first pair c_a={:?} c_inf={:?}", ec(&a), ec(&b));
        }
        println!("  whir rounds: {}", w.rounds.len());
        for (i, r) in w.rounds.iter().enumerate() {
            let rows = match &r.openings {
                p3_whir::pcs::proof::QueryOpenings::Base(o) => o.rows.len(),
                p3_whir::pcs::proof::QueryOpenings::Extension(o) => o.rows.len(),
            };
            let width = match &r.openings {
                p3_whir::pcs::proof::QueryOpenings::Base(o) => o.rows.first().map_or(0, Vec::len),
                p3_whir::pcs::proof::QueryOpenings::Extension(o) => {
                    o.rows.first().map_or(0, Vec::len)
                }
            };
            println!(
                "    whir round {}: committed={} ood={} queries={} (row width {}) sc_rounds={} sc_pow={}",
                i,
                r.commitment.is_some(),
                r.ood_answers.len(),
                rows,
                width,
                r.sumcheck.polynomial_evaluations.len(),
                r.sumcheck.pow_witnesses.len()
            );
        }
        println!(
            "  final_poly: {:?}",
            w.final_poly.as_ref().map(|p| p.iter().count())
        );
        let fq = match &w.final_openings {
            p3_whir::pcs::proof::QueryOpenings::Base(o) => {
                (o.rows.len(), o.rows.first().map_or(0, Vec::len))
            }
            p3_whir::pcs::proof::QueryOpenings::Extension(o) => {
                (o.rows.len(), o.rows.first().map_or(0, Vec::len))
            }
        };
        println!("  final queries: {} row width {}", fq.0, fq.1);
        println!(
            "  final_sumcheck: {:?}",
            w.final_sumcheck
                .as_ref()
                .map(|s| s.polynomial_evaluations.len())
        );
    }
    let bytes = postcard::to_allocvec(&proof).expect("encode");
    println!("whole proof bytes: {}", bytes.len());
    let uni_bytes = postcard::to_allocvec(uni).expect("encode");
    println!("opening_proof bytes: {}", uni_bytes.len());
}
