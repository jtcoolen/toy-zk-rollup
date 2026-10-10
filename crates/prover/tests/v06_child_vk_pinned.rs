//! V-06: the block circuit must verify every child transfer proof against the
//! *canonical* verifying key for its shape — never against the verifier object
//! the client supplied.
//!
//! The in-circuit verifier allocates the child's preprocessed commitment as
//! free public-input targets, and the recursion evaluates the *supplied*
//! verifier's relation. Left alone, a client could build a weaker circuit of
//! the same public shape, prove on it, and hand the sequencer the weaker
//! verifier plus a proof that verifies natively and in-circuit alike — the
//! block proof would then attest to a relation nobody pinned.
//!
//! The fix: build_multi_transfer_circuit builds the child verifier itself
//! (a witness-free fixture prepare per shape), verifies the client's proof
//! against *that*, rejects any client verifier whose preprocessed commitment
//! or relation differs, and constrains the in-circuit commitment targets to
//! the canonical constant.
use p3_field::PrimeCharacteristicRing;
use pq_hash::Poseidon2Shielded;
use prover::block::{
    ChildProof, TransferShape, build_multi_transfer_circuit, canonical_child_preprocessed,
};
use prover::fixtures::{funded_note, public_and_witnesses, seed, tree_with};
use prover::transfer::{
    LOG_MAX_LDE, build_transfer_circuit, prepare_transfer_circuit_with,
    settle_transfer_circuit_with,
};
use prover::whir_recursion::{Challenge, InnerWhirConfig};
use shielded::Note;
use shielded::keys::derive_spend_pk;
use shielded::transfer::{Spend, Transfer};

const ONE_IN_ONE_OUT: TransferShape = TransferShape {
    num_nullifiers: 1,
    num_outputs: 1,
};

/// The canonical inner config, same as the block tests use.
fn inner() -> InnerWhirConfig {
    InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config should build")
}

/// Build a 1-in / 1-out transfer circuit from a self-contained fixture —
/// same shape as the H-03 tests, different seeds.
fn one_in_one_out(byte: u8) -> prover::transfer::TransferCircuit {
    let (a, sk_a) = funded_note(byte, 1_000);
    let (tree, paths) = tree_with(&[a]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(byte + 40));
    let transfer = Transfer {
        spends: vec![Spend {
            note: &a,
            sk_d: &sk_a,
            path: &paths[0],
            index: 0,
        }],
        outputs: vec![Note::new(900, seed(byte + 41), seed(byte + 42), recipient)],
        fee: 100,
    };
    transfer.check_balance().expect("fixture balances");
    let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
    build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
        .expect("a balanced transfer with a valid path should witness")
}

/// V-06 acceptance 1 (the first one to write): a proof made under a *forged*
/// verifying key — a same-shape circuit with one extra unused constant, so a
/// genuinely different relation and preprocessed commitment — must be rejected
/// by the block circuit even though it verifies natively under its own
/// verifier.
#[test]
fn child_proof_under_forged_vk_rejected() {
    let inner = inner();

    // The forge: same public shape, one extra unused const op. The witness
    // still satisfies every original constraint, and the proof verifies under
    // the forged verifier — that is what makes this a verifying-key forgery
    // rather than a broken proof.
    let mut forged = one_in_one_out(7);
    forged
        .forge_append_const_for_test(Challenge::from_u16(7))
        .expect("appending an unused const must keep the circuit witnessable");
    let (proof, verifier) =
        settle_transfer_circuit_with(&forged, inner.clone()).expect("forged circuit should prove");
    // Sanity: the forged proof really is valid under the forged verifier —
    // otherwise this test would pass for the wrong reason.
    verifier
        .verify(&proof, forged.statement())
        .expect("the forged proof must verify under its own verifier");

    let children = vec![ChildProof {
        verifier: &verifier,
        proof: &proof,
        statement: forged.statement(),
        shape: ONE_IN_ONE_OUT,
    }];

    let err = build_multi_transfer_circuit(&inner, &children)
        .expect_err("a proof under a non-canonical verifying key must be rejected (V-06)");
    let msg = err.to_string();
    assert!(
        msg.contains("canonical"),
        "rejection must name the canonical-key mismatch, got: {msg}"
    );
}

/// V-06 acceptance 2: the canonical pin must equal the preprocessed commitment
/// an honest client's verifier carries — for *any* honest fixture of the shape.
/// If the pin disagreed with honest verifiers, honest blocks would break; if it
/// depended on witness values, it would not be a key.
#[test]
fn canonical_pin_matches_honest_client_verifiers() {
    let inner = inner();
    let pin =
        canonical_child_preprocessed(&inner, &ONE_IN_ONE_OUT).expect("canonical pin must derive");
    // Two honest fixtures, different notes/trees/recipients (H-03 made the
    // preprocessed commitment shape-only, so both must carry the same pin).
    for byte in [1u8, 2] {
        let tc = one_in_one_out(byte);
        let prepared =
            prepare_transfer_circuit_with(&tc, inner.clone()).expect("honest circuit must prepare");
        let verifier = prepared.verifier();
        let honest = verifier
            .common_data()
            .preprocessed
            .as_ref()
            .expect("honest verifier carries preprocessed data");
        assert_eq!(
            pin, honest.commitment,
            "canonical pin must equal the honest client's preprocessed commitment"
        );
    }
}

/// V-06 acceptance 3: an honest child still builds the block circuit — the pin
/// must not break the happy path.
#[test]
fn honest_block_still_builds_under_the_pin() {
    let inner = inner();
    let honest = one_in_one_out(3);
    let (proof, verifier) =
        settle_transfer_circuit_with(&honest, inner.clone()).expect("honest circuit should prove");
    let children = vec![ChildProof {
        verifier: &verifier,
        proof: &proof,
        statement: honest.statement(),
        shape: ONE_IN_ONE_OUT,
    }];
    build_multi_transfer_circuit(&inner, &children)
        .expect("an honest child must build the block circuit under the pin");
}
