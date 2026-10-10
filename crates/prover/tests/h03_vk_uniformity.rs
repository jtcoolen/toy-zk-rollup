//! H-03: the transfer circuit's *preprocessed* data must depend on the
//! circuit's shape (spend and output counts) and nothing else.
//!
//! Preprocessed columns are committed publicly and unblinded, and the client
//! hands its `CircuitVerifier` — preprocessed commitment included — to the
//! sequencer. Before the fix the circuit baked note-specific values into
//! `define_const`: the membership siblings (which determine the spent leaf's
//! position), the recipient's `pk_d`, and the tree/nullifier roots. Anyone
//! holding the verifier could recover them and link every incoming note to a
//! static recipient key.
//!
//! The fix moves all of it to witnesses (siblings, `pk_d`) or witness-backed
//! statement exports (the roots). These tests pin the property and the
//! tamper-resistance of the new witness path.
use pq_hash::Poseidon2Shielded;
use prover::fixtures::{funded_note, public_and_witnesses, seed, tree_with};
use prover::transfer::{build_transfer_circuit, TransferCircuit};
use shielded::keys::derive_spend_pk;
use shielded::transfer::{Spend, Transfer};
use shielded::Note;

/// Build a 1-in / 1-out transfer circuit from a self-contained fixture:
/// `byte` seeds the note, `recipient_byte` the output's recipient key.
fn one_in_one_out(byte: u8, recipient_byte: u8) -> TransferCircuit {
    let (a, sk_a) = funded_note(byte, 1_000);
    let (tree, paths) = tree_with(&[a]);
    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(recipient_byte));
    let transfer = Transfer {
        spends: vec![Spend {
            note: &a,
            sk_d: &sk_a,
            path: &paths[0],
            index: 0,
        }],
        outputs: vec![Note::new(
            900,
            seed(recipient_byte.wrapping_add(40)),
            seed(recipient_byte.wrapping_add(41)),
            recipient,
        )],
        fee: 100,
    };
    transfer.check_balance().expect("fixture balances");
    let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
    build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
        .expect("a balanced transfer with a valid path should witness")
}

/// H-03 acceptance 1: two transfers of the same shape, different notes, trees,
/// positions and recipient keys, must produce *identical* preprocessed
/// constants. Any note-specific value in the const multiset is a leak.
#[test]
fn preprocessed_is_shape_only() {
    let left = one_in_one_out(1, 9);
    let right = one_in_one_out(2, 17);

    // Sanity: the two fixtures really are different transfers — different
    // statements, or the comparison below proves nothing.
    assert_ne!(
        left.statement(),
        right.statement(),
        "fixtures must differ, or the const comparison is vacuous"
    );

    let a = left.census_consts();
    let b = right.census_consts();
    assert_eq!(
        a, b,
        "preprocessed constants differ between two transfers of the same shape: a note-specific value is baked into the verifying key (H-03)"
    );
}

/// H-03 acceptance 2: with the membership siblings as witnesses, a tampered
/// sibling must still fail — the fold has to reach the pinned root, and a
/// wrong sibling folds elsewhere. The witness is free, the constraint is not.
#[test]
fn tampered_membership_sibling_rejected() {
    let (a, sk_a) = funded_note(3, 1_000);
    let (tree, paths) = tree_with(&[a]);
    assert!(!paths[0].is_empty(), "fixture tree must have depth");

    let recipient = derive_spend_pk(&Poseidon2Shielded, &seed(11));
    let outputs = vec![Note::new(900, seed(60), seed(61), recipient)];
    let transfer = Transfer {
        spends: vec![Spend {
            note: &a,
            sk_d: &sk_a,
            path: &paths[0],
            index: 0,
        }],
        outputs: outputs.clone(),
        fee: 100,
    };
    transfer.check_balance().expect("fixture balances");

    let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
    // Honest baseline witnesses.
    let tc = build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
        .expect("honest transfer should witness");
    assert!(!tc.statement().is_empty());

    // Tamper: replace one sibling with a foreign digest. The fold cannot
    // reach the pinned root, so the witness must fail.
    let mut tampered_path = paths[0].clone();
    let level = tampered_path.len() / 2;
    tampered_path[level] = pq_hash::Digest32::new([7u8; 32]);
    let foreign = Transfer {
        spends: vec![Spend {
            note: &a,
            sk_d: &sk_a,
            path: &tampered_path,
            index: 0,
        }],
        outputs: outputs.clone(),
        fee: 100,
    };
    let (public2, nf2, frontier2) = public_and_witnesses(&foreign, &tree);
    let built = build_transfer_circuit(&foreign, &public2, &nf2, &frontier2);
    assert!(
        built.is_err(),
        "a tampered sibling must not fold to the pinned root (H-03)"
    );
}
