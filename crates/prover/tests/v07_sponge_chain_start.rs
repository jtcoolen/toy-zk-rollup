//! V-07 (audit of a54c197): the gadget sponges' chain-start capacity must be pinned.
//!
//! `p2_sponge_limbs` starts a fresh Poseidon2 chain with `new_start = true` on a
//! *non-challenger* table. On that table the AIR leaves a chain-start row's capacity
//! free (the pin fires only for shared/challenger roles), so unless the gadget *feeds* the
//! capacity slots as inputs — putting them on the witness bus — a malicious prover can
//! re-choose the IV and fork one note into many nullifiers.
//!
//! These tests are the negative half of the fix: forge a chain-start row's capacity to
//! non-zero, recompute the permutation and every exposed output consistently (so the
//! permutation itself stays satisfied and the only possible violation is the capacity
//! binding), then prove-and-verify against the honest circuit's constraint system. The
//! honest circuits must verify; the forged ones must be rejected.
//!
//! The harness mirrors `vendor/p3-recursion/recursion/tests/challenger_sponge_binding.rs`.

#[path = "../../../vendor/p3-recursion/recursion/tests/common/rejection_oracle.rs"]
mod rejection_oracle;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    NpoTypeId, Poseidon2Config, Poseidon2Trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::tables::{Traces, WitnessTrace};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking, config,
};
use p3_field::BasedVectorSpace;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_symmetric::Permutation;

#[cfg(debug_assertions)]
use rejection_oracle::run_with_debug_oracle;
use rejection_oracle::{ProofCheckError, assert_rejected};

use prover::commitment_gadget::p2_sponge_limbs;
use prover::whir_recursion::{Challenge, whir_perm};
use prover::F;

type EF = Challenge;

const D: usize = 4;
const WIDTH: usize = 16;
const WIDTH_EXT: usize = WIDTH / D;
/// Rate slots per row at this shape (2 ext elements = 8 base elements).
const RATE_EXT: usize = 2;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;

fn enable_perm(builder: &mut CircuitBuilder<EF>) {
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        whir_perm(),
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
}

fn sponge_circuit() -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    enable_perm(&mut builder);
    let limbs = builder.alloc_private_inputs(16, "limbs");
    let _out = p2_sponge_limbs(&mut builder, &limbs).expect("sponge builds");
    builder.build().expect("circuit builds")
}

fn sponge_privates() -> Vec<EF> {
    (100..116).map(|i| EF::from_u64(i)).collect()
}

fn run_with(circuit: &Circuit<EF>, privates: &[EF]) -> Traces<EF> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[]).expect("no publics");
    runner.set_private_inputs(privates).expect("privates fit");
    runner.run().expect("witness generation succeeds")
}

fn witness_values(circuit: &Circuit<EF>, privates: &[EF]) -> Vec<EF> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[]).expect("no publics");
    runner.set_private_inputs(privates).expect("privates fit");
    runner.execute_all().expect("witness generation succeeds");
    runner.witness().iter().map(|v| v.expect("honest witness is complete")).collect()
}

/// Prove `traces` against the constraint system of `circuit`, then verify.
fn prove_and_verify(circuit: &Circuit<EF>, traces: &Traces<EF>) -> Result<(), ProofCheckError> {
    let table_packing = TablePacking::new(1, 1);
    let stark_config = config::koala_bear();
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders = poseidon2_air_builders_for_configs::<KoalaBearConfig, D>(vec![CFG]);
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, true));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, EF, D>(
            circuit,
            &table_packing,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(CFG);
    prover.register_recompose_table::<D>(true);

    #[cfg(debug_assertions)]
    let result = run_with_debug_oracle(|| {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    });

    #[cfg(not(debug_assertions))]
    let result = {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    };

    #[cfg(debug_assertions)]
    return match result {
        Ok(result) => result,
        Err(kind) => Err(ProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    result
}

/// Forge the chain-start row's capacity: bump every capacity coefficient, recompute the
/// permutation for that row and every continuation row in the same chain, and keep the
/// witness bus consistent with the forged outputs — so the *only* thing left to catch the
/// forgery is the binding on the capacity the first row absorbs.
fn forge_chain_start_capacity(circuit: &Circuit<EF>, privates: &[EF]) -> Traces<EF> {
    let mut traces = run_with(circuit, privates);
    let source_id = NpoTypeId::poseidon2_perm(CFG);
    let source = traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&source_id)
        .expect("gadget circuit has the perm source trace")
        .clone();
    assert!(!source.operations.is_empty());
    assert!(source.operations[0].new_start, "row 0 starts the chain");

    let mut forged = source;
    let mut witness = witness_values(circuit, privates);
    let perm = default_koalabear_poseidon2_16();

    let mut chain_end = 1;
    while chain_end < forged.operations.len() && !forged.operations[chain_end].new_start {
        chain_end += 1;
    }
    for row_index in 0..chain_end {
        let row = &mut forged.operations[row_index];
        if row_index == 0 {
            for limb in RATE_EXT..WIDTH_EXT {
                for j in 0..D {
                    row.input_values[limb * D + j] += F::ONE;
                }
            }
        }
        let input: [F; WIDTH] = row
            .input_values
            .as_slice()
            .try_into()
            .expect("perm row has fixed width");
        let output = perm.permute(input);
        for (limb, (&ctl, &wid)) in row.out_ctl.iter().zip(row.output_indices.iter()).enumerate() {
            if ctl {
                let coeffs = &output[limb * D..(limb + 1) * D];
                witness[wid as usize] =
                    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(coeffs)
                        .expect("output coefficients form an extension element");
            }
        }
        if row_index + 1 < chain_end {
            // Continuation rows chain their capacity from this row's output; their rate
            // slots are bus-fed from the absorbed limbs and stay untouched.
            let next = &mut forged.operations[row_index + 1];
            for limb in RATE_EXT..WIDTH_EXT {
                next.input_values[limb * D..(limb + 1) * D]
                    .copy_from_slice(&output[limb * D..(limb + 1) * D]);
            }
        }
    }

    traces.non_primitive_traces.insert(source_id, Box::new(forged));
    traces.witness_trace = WitnessTrace::new(witness);
    traces
}

/// Harness sanity: the honest sponge proves and verifies.
#[test]
fn honest_sponge_proves_and_verifies() {
    let circuit = sponge_circuit();
    let privates = sponge_privates();
    let traces = run_with(&circuit, &privates);
    prove_and_verify(&circuit, &traces).expect("honest sponge must verify");
}

/// V-07: a forged chain-start capacity on `p2_sponge_limbs` must be rejected. This is the
/// nullifier shape: `nf = H(DOMAIN || sk_d || rho)` runs through this sponge, and a free IV
/// lets one note yield many nullifiers (self double-spend).
#[test]
fn sponge_chain_start_capacity_is_bound() {
    let circuit = sponge_circuit();
    let privates = sponge_privates();
    let forged = forge_chain_start_capacity(&circuit, &privates);
    assert_rejected(
        &prove_and_verify(&circuit, &forged),
        "the capacity the sponge chain start absorbs must not be freely re-choosable (V-07)",
    );
}
