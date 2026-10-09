//! Composed settlement-shape vectors: the WHIR core walk, driven at the real batch
//! opening shapes, inside the batch transcript delegate, in place of the native PCS.
//!
//! ~~~text
//! cargo test -p prover --test composed_vectors -- --ignored --nocapture
//! ~~~
//!
//! # The composition claim
//!
//! The settlement contract replays the batch transcript (pinned by
//! `batch_stark_vectors`) and, at the delegate, runs its own WHIR core (ported in M1-M4
//! from the walk pinned by `whir_proof_vectors`). Neither pin alone proves the two halves
//! compose: the batch fixture hands the WHIR core a per-round statement (stacked config,
//! opening schedule, univariate points) that only exists at settlement shape, and the
//! WHIR fixture never sees the batch transcript around it.
//!
//! This test closes that gap. It proves the settlement batch under the semantic config,
//! replays the batch phases by hand, and inside transcript.delegate replaces the native
//! PCS with the shared WHIR walk: for each of the five opening rounds it rebuilds the
//! WHIR config and opening schedule from public ingredients (`padded_arity`,
//! `checked_stacked_num_variables`, `univariate_eq_point` - the same construction
//! `round_schedule` performs), drives `verify_whir_round` on the batch challenger, and
//! re-checks the claimed openings against the walk's bound evaluations with the
//! univariate-eq scales. `one_run` then asserts the combined event program equals the
//! native `CircuitVerifier::verify` run's - batch phases and WHIR core events alike.
//!
//! If the programs agree, the Solidity composition is mechanical assembly of pieces
//! each already pinned: `BatchTranscript.sol` up to the delegate, then `WhirVerifierCore`
//! per round with the statement exported here.
#![recursion_limit = "256"]

use std::error::Error;
use std::path::PathBuf;

use serde_json::json;

use prover::semantic_trace::SemChallenger;
use prover::F;

use prover::composed_export::{composed_run_twin, export_and_write};
use prover::settlement_replay::{
    fib_recursion, hex, settlement_params, settlement_params_for, Challenge, SemPcs,
};
use prover::whir_recursion::LOG_MAX_LDE;

use pq_hash::{Poseidon2Commitment, Poseidon2Shielded};
use prover::block::{block_statement, build_multi_transfer_circuit, ChildProof, TransferShape};
use prover::client::{prove_client_transfer, ClientSpec};
use prover::fixtures::{funded_note, seed, tree_with};
use prover::whir_recursion::InnerWhirConfig;
use shielded::keys::derive_spend_pk;
use shielded::{Note, NullifierMap};

// D-092 batch 89: settlement blinding is OFF. The settlement proof (the STARK
// of the rc circuit that ShieldedPool verifies) is fully deterministic - no
// randomization round, no blinding rows. The client transfer proof keeps its
// ZK layer (InnerWhirConfig pins ZK = true in crate::whir); only the outer
// layer drops it. Checked at compile time so the shape pins cannot rot.
const _: bool =
    !<SemPcs as p3_commit::UnivariateStarkPcs<Challenge, SemChallenger>>::ZK;

/// The linchpin: prove, verify natively, replay the batch phases with the shared WHIR
/// walk in the delegate, and require the combined programs to agree (asserted inside
/// `one_run`). Then export the per-round statements and the composed blob for Solidity.
///
/// D-092 batch 89: with settlement blinding off a second run is byte-identical and
/// classifies nothing, so the fixed/varying split is structural (see
/// `structural_batch_fixed`): batch-region constants (seed, degree, public values,
/// preprocessed digest) ride in the bundle's constant section; everything else -
/// including the whole delegate region - is proof data read from calldata.
#[test]
#[ignore = "proves the settlement batch twice (~12s); regenerates composed_vectors.{json,bin}"]
fn composed_program_equality_and_export() {
    let (pis, rc) = fib_recursion();
    let params = settlement_params();
    // D-092 batch 89: the fixed/varying split comes from a seed-twin pair (see
    // composed_run_twin): the same settlement proven under two Fiat-Shamir
    // initial states. Witness-dependent values move between seeds (varying);
    // keccak framing labels and shape constants do not (fixed). The batch
    // region stays structural, and all-zero fixed runs are reclassified as
    // proof data inside the twin (structurally-zero extension elements are not
    // framing constants).
    let (doc, out, program, fixed, starts) =
        composed_run_twin(&pis, &rc, &params, LOG_MAX_LDE, 1).expect("composed twin");
    export_and_write(
        doc,
        &out,
        &program,
        &fixed,
        &starts,
        "composed_vectors",
        None,
        vec![],
    )
    .expect("export");
}

/// Shape pin: the committed artifact must describe the settlement batch's five opening
/// rounds with the measured matrix shapes. A stale or hand-edited file fails here.
#[test]
fn composed_artifact_shape_is_pinned() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    let Ok(text) = std::fs::read_to_string(dir.join("composed_vectors.json")) else {
        // Absent until the ignored export has been run once.
        return;
    };
    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    // D-092 batch 89 canonical env (WHIR_INNER_RATE=3 WHIR_RATE_FINAL=4): the
    // fib settlement folds at blowup 16, so the opening schedule is four rounds,
    // not the five the rate-2 vectors carried. Round 1 is the per-instance column
    // split (8 matrices); the others open the six instance commitments.
    let rounds = doc["rounds"].as_array().unwrap();
    assert_eq!(doc["num_rounds"].as_u64().unwrap(), 4);
    let matrix_counts: Vec<u64> = rounds
        .iter()
        .map(|r| r["matrices"].as_array().unwrap().len() as u64)
        .collect();
    assert_eq!(matrix_counts, vec![6, 8, 6, 6]);
    let point_counts: Vec<Vec<u64>> = rounds
        .iter()
        .map(|r| {
            r["matrices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["points"].as_array().unwrap().len() as u64)
                .collect()
        })
        .collect();
    assert_eq!(point_counts, vec![
        vec![1, 1, 2, 2, 1, 1],
        vec![1, 1, 1, 1, 1, 1, 1, 1],
        vec![1, 1, 2, 2, 1, 1],
        vec![2, 2, 2, 2, 2, 2],
    ]);
    // Every round carries a completed walk: the terminal phase closed with a claim.
    for r in rounds {
        assert!(r["walk"]["terminal"]["claimed_after_final"].is_array());
        assert!(!r["walk"]["rounds"]["params"].as_array().unwrap().is_empty());
        assert!(!r["schedule"]["rounds"].as_array().unwrap().is_empty());
    }
}

/// Genesis data for the on-chain test, written as the small sidecar the
/// Solidity E2E test reads (the full export is tens of MB and parsing it
/// on-chain in setUp exhausts the EVM memory limit). Returns the extras the
/// full export embeds.
fn write_block_genesis(
    note: Note,
    out_note: Note,
    pis: &[F],
) -> Result<Vec<(&'static str, serde_json::Value)>, Box<dyn Error>> {
    // The pool must start at the tree the block was witnessed against (the
    // funded note's leaf). D-088: the contract no longer re-derives the tree -
    // it stores the attested `rootAfter` - so the sidecar names the genesis
    // ROOT (what the constructor takes) and the expected root after the block
    // (what applyBlock must store). The root-after is computed by appending
    // the output to the genesis tree, so it still cross-checks the prover's
    // own frontier fold against an independent tree walk.
    let p2 = pq_hash::Poseidon2Commitment::default();
    let mut pool_tree = tree_with(&[note]).0;
    let genesis_root = pool_tree.root();
    pool_tree.append(&out_note.commit(&p2));
    let extras = vec![
        ("genesis_leaves", json!([hex(note.commit(&p2).as_bytes())])),
        ("genesis_root_hex", json!(hex(genesis_root.as_bytes()))),
        (
            "pool_root_after_hex",
            json!(hex(pool_tree.root().as_bytes())),
        ),
    ];
    let sidecar = serde_json::json!({
        "statement": pis
            .iter()
            .map(p3_field::PrimeField32::as_canonical_u32)
            .collect::<Vec<_>>(),
        "genesis_leaves": extras[0].1.clone(),
        "genesis_root_hex": extras[1].1.clone(),
        "pool_root_after_hex": extras[2].1.clone(),
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::write(
        dir.join("block_genesis.json"),
        serde_json::to_string_pretty(&sidecar)?,
    )?;
    Ok(extras)
}

/// The real shielded block circuit through the same composed machinery.
///
/// One client transfer (a funded note spent through the transfer circuit with a
/// real SPHINCS+ signature, SHA3-256 note derivation and nullifier absence fold)
/// recursed into the block circuit and settled under the Keccak WHIR config at
/// `BLOCK_LOG_MAX_LDE`. The export is what the contract replays:
/// `block_composed_vectors.{json,bin}` plus the block statement (shape header +
/// child statement, canonical limbs) that `ShieldedPool.applyBlock` receives.
///
/// ```text
/// cargo test -p prover --test composed_vectors block_program_equality_and_export -- --ignored --nocapture
/// ```
#[test]
#[ignore = "proves the real block circuit twice (many minutes); regenerates block_composed_vectors.{json,bin}"]
fn block_program_equality_and_export() -> Result<(), Box<dyn Error>> {
    // One transfer keeps the settlement trace smallest while still exercising
    // the whole shielded path end to end.
    let (note, sk_d) = funded_note(11, 1_000);
    let (tree, paths) = tree_with(&[note]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(9));
    // The inner (client) config: transfer proofs are Poseidon2 WHIR at the
    // recursion circuit's LDE, exactly as a real client produces them.
    let inner = InnerWhirConfig::new(prover::transfer::LOG_MAX_LDE, 0).expect("inner config");

    let out_note = Note::new(900, seed(200), seed(201), recipient);
    let spec = ClientSpec {
        note: &note,
        sk_d: &sk_d,
        path: &paths[0],
        index: 0,
        output: &out_note,
        fee: 100,
    };
    let mut map = NullifierMap::new(Poseidon2Commitment::default());
    let client = prove_client_transfer(&inner, &spec, &tree, &mut map).expect("client prove");

    let shape = TransferShape {
        num_nullifiers: 1,
        num_outputs: 1,
    };
    let children = vec![ChildProof {
        verifier: &client.verifier,
        proof: &client.proof,
        statement: &client.statement,
        shape,
    }];
    let rc = build_multi_transfer_circuit(&inner, &children).expect("block circuit");

    // The folded block statement (D-089): header, statement fold root, the
    // four endpoint digests, the fee - exactly what the contract's decoder
    // parses and what applyBlock must be handed. Built by the same shared
    // builder the circuit's export mirrors.
    let pis: Vec<F> = block_statement([shape].iter(), [client.statement.as_slice()])?;

    let params = settlement_params_for(prover::block::BLOCK_LOG_MAX_LDE, 1);

    // Seed-twin classification (see composed_run_twin): framing constants ride
    // in the bundle's constant section, witness data on the wire.
    let (doc, out, program, fixed, starts) = composed_run_twin(
        &pis,
        &rc,
        &params,
        prover::block::BLOCK_LOG_MAX_LDE,
        1,
    )?;

    let extras = write_block_genesis(note, out_note, &pis)?;
    export_and_write(
        doc,
        &out,
        &program,
        &fixed,
        &starts,
        "block_composed_vectors",
        Some(&pis),
        extras,
    )
}

/// D-092 batch 80: PRODUCTION shielded-pool size census (not the Fibonacci
/// harness). One real client transfer (SPHINCS+ sig, SHA3 note derivation,
/// nullifier absence fold) -> block recursion circuit -> Keccak settlement at
/// the canonical env. Prints rows for every artifact: client circuit, client
/// proof, rc circuit, final proof instances.
#[test]
#[ignore = "proves the real shielded chain; run with --release and canonical env"]
fn shielded_size_census() -> Result<(), Box<dyn Error>> {
    use p3_circuit::Op;
    let (note, sk_d) = funded_note(11, 1_000);
    let (tree, paths) = tree_with(&[note]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(9));
    let inner = InnerWhirConfig::new(prover::transfer::LOG_MAX_LDE, 0).expect("inner config");
    let out_note = Note::new(900, seed(200), seed(201), recipient);

    // --- client transfer circuit (the shielded client proof's circuit) -----
    let transfer = shielded::Transfer {
        spends: vec![shielded::transfer::Spend { note: &note, sk_d: &sk_d, path: &paths[0], index: 0 }],
        outputs: vec![out_note],
        fee: 100,
    };
    let (public, nf_w, frontier) = prover::fixtures::public_and_witnesses(&transfer, &tree);
    let tc = prover::transfer::build_transfer_circuit(&transfer, &public, &nf_w, &frontier)
        .expect("transfer circuit");
    let npo = tc.census_npo_rows();
    println!(
        "CENSUS client circuit: ops={} witnesses={} alu_rows={} npo={:?}",
        tc.census_ops(), tc.census_witnesses(), tc.census_alu_rows(), npo);
    let pad = |n: usize| n.next_power_of_two();
    println!("CENSUS client circuit padded rows: alu->{}", pad(tc.census_alu_rows()));

    // --- client proof (InSC/Poseidon2) --------------------------------------
    let mut map = NullifierMap::new(Poseidon2Commitment::default());
    let spec = ClientSpec {
        note: &note, sk_d: &sk_d, path: &paths[0], index: 0, output: &out_note, fee: 100,
    };
    let client = prove_client_transfer(&inner, &spec, &tree, &mut map).expect("client prove");
    println!(
        "CENSUS client proof: {} B (postcard), statement {} limbs",
        postcard::to_allocvec(&client.proof).map_or(0, |v| v.len()),
        client.statement.len());

    // --- block recursion circuit (in-circuit verifier of the client proof) --
    let shape = TransferShape { num_nullifiers: 1, num_outputs: 1 };
    let children = vec![ChildProof {
        verifier: &client.verifier, proof: &client.proof, statement: &client.statement, shape,
    }];
    let rc = build_multi_transfer_circuit(&inner, &children).expect("block circuit");
    let mut alu = 0; let mut npoc = 0; let mut hint = 0; let mut cst = 0; let mut pubc = 0;
    for op in &rc.circuit.ops {
        match op {
            Op::Const { .. } => cst += 1,
            Op::Public { .. } => pubc += 1,
            Op::Alu { .. } => alu += 1,
            Op::Hint { .. } => hint += 1,
            Op::NonPrimitiveOpWithExecutor { .. } => npoc += 1,
        }
    }
    let mut npo_rows: Vec<(String, usize)> = rc.traces.non_primitive_traces.iter()
        .map(|(k, v)| (format!("{k:?}"), v.rows())).collect();
    npo_rows.sort_by(|a, b| b.1.cmp(&a.1));
    println!(
        "CENSUS rc circuit: ops={} (alu={alu} npo={npoc} hint={hint} const={cst} pub={pubc}) witnesses={} padded->{}",
        rc.circuit.ops.len(), rc.circuit.witness_count, pad(rc.traces.alu_trace.op_kind.len()));
    for (k, r) in &npo_rows { println!("CENSUS rc npo {k}: {r} rows"); }

    // --- final settlement (Keccak OutSC, canonical rate) --------------------
    let pis: Vec<prover::F> = block_statement([shape].iter(), [client.statement.as_slice()])?;
    let rate: usize = std::env::var("WHIR_RATE_FINAL").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let (bundle, config, _chunks) =
        prover::composed_export::settlement_bundle_with_blob(&rc, &pis, rate).expect("settle");
    println!("CENSUS final proof: {} B (raw bundle), rate={rate}", bundle.len());
    if let Some(insts) = config.get("instances").and_then(|v| v.as_array()) {
        for (i, inst) in insts.iter().enumerate() {
            let h = inst.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
            let w = inst.get("width").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("CENSUS final inst{i}: height={h} width={w}");
        }
    }
    Ok(())
}
/// D-092 batch 81: THE canonical v8 wire is now the SHIELDED POOL chain -
/// one real client transfer (SPHINCS+ sig, SHA3 note derivation, nullifier
/// absence fold, Poseidon2 commitment tree) -> block recursion circuit ->
/// Keccak settlement. Replaces the Fibonacci harness export. Writes the same
/// v8 vector filenames the contract tests read.
#[test]
#[ignore = "proves the real shielded chain; regenerates the canonical v8 vectors"]
fn export_shielded_bundle_v8() -> Result<(), Box<dyn Error>> {
    use p3_symmetric::CryptographicHasher;
    let (note, sk_d) = funded_note(11, 1_000);
    let (tree, paths) = tree_with(&[note]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(9));
    let inner = InnerWhirConfig::new(prover::transfer::LOG_MAX_LDE, 0).expect("inner config");
    let out_note = Note::new(900, seed(200), seed(201), recipient);
    let mut map = NullifierMap::new(Poseidon2Commitment::default());
    let spec = ClientSpec {
        note: &note, sk_d: &sk_d, path: &paths[0], index: 0, output: &out_note, fee: 100,
    };
    let client = prove_client_transfer(&inner, &spec, &tree, &mut map).expect("client prove");

    let shape = TransferShape { num_nullifiers: 1, num_outputs: 1 };
    let children = vec![ChildProof {
        verifier: &client.verifier, proof: &client.proof, statement: &client.statement, shape,
    }];
    let rc = build_multi_transfer_circuit(&inner, &children).expect("block circuit");
    let pis: Vec<prover::F> = block_statement([shape].iter(), [client.statement.as_slice()])?;

    let rate: usize = std::env::var("WHIR_RATE_FINAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let (bundle, jj, blob) =
        prover::composed_export::settlement_bundle_with_blob(&rc, &pis, rate).expect("settle");
    let _ = &bundle;
    let flat = prover::wbnd::flat_from_vectors(&jj);
    let (v7, cfg) = prover::wbnd::encode_bundle_v8_split(&flat, &jj, &blob);
    let chunks = prover::wbnd::chunk_config(&cfg, 24000);
    let joined: Vec<u8> = chunks.iter().flatten().copied().collect();
    let digest: [u8; 32] = p3_keccak::Keccak256Hash.hash_iter(joined.iter().copied());
    let mut hexs = String::with_capacity(64);
    for b in digest { use std::fmt::Write; write!(&mut hexs, "{b:02x}").expect("hex"); }

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/test/vectors");
    std::fs::write(format!("{dir}/recursion_chain_bundle_v8.bin"), &v7).expect("write v8");
    std::fs::write(format!("{dir}/recursion_chain_config_v8.bin"), &cfg).expect("write cfg");
    for (i, c) in chunks.iter().enumerate() {
        std::fs::write(format!("{dir}/recursion_chain_config_chunk_v8_{i}.bin"), c).expect("write chunk");
    }
    let stmt: Vec<u64> = pis.iter().map(p3_field::PrimeField64::as_canonical_u64).collect();
    let sidecar = serde_json::json!({
        "statement": stmt,
        "bundle_v8_len": v7.len(),
        "config_len": cfg.len(),
        "config_digest": format!("0x{}", hexs),
        "chunk_lens": chunks.iter().map(Vec::len).collect::<Vec<_>>(),
    });
    std::fs::write(format!("{dir}/recursion_chain_sidecar_v8.json"), sidecar.to_string()).expect("write sidecar");
    println!("SHIELDED v8 bundle {} B, config {} B, {} chunks, rate={}", v7.len(), cfg.len(), chunks.len(), rate);
    Ok(())
}

/// D-092 batch 84: FULL SHAPE REPORT - per-op-kind rows for every circuit in
/// the recursion, WHIR schedule at both levels, proof field breakdown.
#[test]
#[ignore = "proves the real shielded chain; prints the complete shape census"]
fn shielded_shape_report() -> Result<(), Box<dyn Error>> {
    use p3_circuit::Op;
    let (note, sk_d) = funded_note(11, 1_000);
    let (tree, paths) = tree_with(&[note]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(9));
    let inner = InnerWhirConfig::new(prover::transfer::LOG_MAX_LDE, 0).expect("inner config");
    let out_note = Note::new(900, seed(200), seed(201), recipient);

    // ---- client circuit ----------------------------------------------------
    let transfer = shielded::Transfer {
        spends: vec![shielded::transfer::Spend { note: &note, sk_d: &sk_d, path: &paths[0], index: 0 }],
        outputs: vec![out_note],
        fee: 100,
    };
    let (public, nf_w, frontier) = prover::fixtures::public_and_witnesses(&transfer, &tree);
    let tc = prover::transfer::build_transfer_circuit(&transfer, &public, &nf_w, &frontier).expect("tc");
    for (k, r) in tc.census_alu_by_kind() { println!("SHAPE client alu {k}: {r}"); }
    println!("SHAPE client circuit: ops={} witnesses={} alu_rows={}",
        tc.census_ops(), tc.census_witnesses(), tc.census_alu_rows());
    for (k, r) in tc.census_npo_rows() { println!("SHAPE client npo {k}: {r}"); }

    // ---- client proof ------------------------------------------------------
    let mut map = NullifierMap::new(Poseidon2Commitment::default());
    let spec = ClientSpec { note: &note, sk_d: &sk_d, path: &paths[0], index: 0, output: &out_note, fee: 100 };
    let client = prove_client_transfer(&inner, &spec, &tree, &mut map).expect("client prove");
    let raw = postcard::to_allocvec(&client.proof).map_or(0, |v| v.len());
    println!("SHAPE client proof: {} B raw, statement {} limbs", raw, client.statement.len());
    println!("SHAPE client proof: rows={:?} ext_degree={} non_primitives={} table_packing={:?}",
        client.proof.rows, client.proof.ext_degree, client.proof.non_primitives.len(), client.proof.table_packing);

    // ---- rc circuit --------------------------------------------------------
    let shape = TransferShape { num_nullifiers: 1, num_outputs: 1 };
    let children = vec![ChildProof { verifier: &client.verifier, proof: &client.proof, statement: &client.statement, shape }];
    let rc = build_multi_transfer_circuit(&inner, &children).expect("rc");
    let mut alu_by: std::collections::BTreeMap<String, usize> = Default::default();
    for op in &rc.circuit.ops {
        if let Op::Alu { kind, .. } = op {
            *alu_by.entry(format!("{kind:?}")).or_default() += 1;
        }
    }
    println!("SHAPE rc circuit: ops={} witnesses={} alu_rows={}", rc.circuit.ops.len(), rc.circuit.witness_count, rc.traces.alu_trace.op_kind.len());
    for (k, v) in &alu_by { println!("SHAPE rc alu {k}: {v}"); }
    for (k, r) in rc.traces.non_primitive_traces.iter().map(|(k, v)| (format!("{k:?}"), v.rows())) { println!("SHAPE rc npo {k}: {r}"); }

    // ---- settlement --------------------------------------------------------
    let pis: Vec<prover::F> = block_statement([shape].iter(), [client.statement.as_slice()])?;
    let rate: usize = std::env::var("WHIR_RATE_FINAL").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let (bundle, jj, _blob) = prover::composed_export::settlement_bundle_with_blob(&rc, &pis, rate).expect("settle");
    println!("SHAPE final proof: {} B raw rate={}", bundle.len(), rate);
    if let Some(insts) = jj.get("instances").and_then(|v| v.as_array()) {
        for (i, inst) in insts.iter().enumerate() {
            println!("SHAPE final inst{i}: {}", serde_json::to_string(inst).unwrap_or_default().chars().take(200).collect::<String>());
        }
    }
    if let Some(m) = jj.as_object() {
        let mut sizes: Vec<(String, usize)> = m.iter().map(|(k, v)| (k.clone(), serde_json::to_string(v).map_or(0, |s| s.len()))).collect();
        sizes.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, s) in sizes.iter().take(25) { println!("SHAPE final json field {k}: ~{s} B"); }
    }
    Ok(())
}
