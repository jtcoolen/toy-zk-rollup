//! End-to-end sequencer: real notes, real client proofs, real block settlement.
//!
//! This is the spine test. It drives the node the way the wallet and the
//! network will drive it — prove on the client side, submit, batch, settle —
//! with no mocks anywhere in the path. Every proof here is a real WHIR proof
//! over a real transfer circuit, and the block proof is verified natively
//! before the state advances.
//!
//! What it establishes, in order:
//!
//! 1. two independently-proven client transfers batch into one block that
//!    verifies;
//! 2. the block statement is the shape header plus both transfers'
//!    statements, exactly as the contract will decode it;
//! 3. the state after applying matches the roots the proof attests to;
//! 4. a transfer that double-spends across the batch is rejected at
//!    admission, before any proving work is wasted on it.

use node::{
    ClientTransferProof, PoolState, Sequencer, SequencerError, ShieldedTransfer, StateError,
};
use pq_hash::{Keccak256Commitment, MerkleRoot, Sha3_256Shielded};
use pq_sign::rand::{rngs::StdRng, SeedableRng};
use pq_sign::{SpendAuth, SphincsPlusAuth};
use prover::block::TransferShape;
use prover::client::{prove_client_transfer, ClientSpec};
use prover::fixtures::{funded_note, seed, tree_with};
use prover::transfer::LOG_MAX_LDE;
use prover::whir_recursion::InnerWhirConfig;
use shielded::keys::derive_spend_pk;

/// One input, one output — the shape every transfer in these tests has.
const ONE_IN_ONE_OUT: TransferShape = TransferShape {
    num_nullifiers: 1,
    num_outputs: 1,
};

/// Shape-header length for a two-transfer block: one block count plus two
/// limbs per transfer.
const HEADER_LIMBS: usize = 5;

/// Prove one client transfer and wrap it in a signed envelope.
///
/// Mirrors the wallet's job: build the witness locally, prove, sign the
/// public statement, hand the bundle to the network.
///
/// Ten arguments is a lot, and the alternative — a builder or a params struct —
/// would add ceremony to a test helper that is called a handful of times with
/// values that are all obviously distinct. The lint is allowed rather than
/// restructured because the restructuring would make the call sites harder to
/// read, not easier.
#[allow(clippy::too_many_arguments)]
fn client_prove(
    inner: &InnerWhirConfig,
    note: &shielded::Note,
    sk_d: &[u8; 32],
    path: &[pq_hash::Digest32],
    index: usize,
    out_value: u64,
    recipient: shielded::SpendPublicKey,
    root: MerkleRoot,
    map: &mut shielded::NullifierMap<Keccak256Commitment>,
    key_seed: u64,
) -> Result<ClientTransferProof, Box<dyn std::error::Error>> {
    let output = shielded::Note::new(out_value, seed(0x51), seed(0x52), recipient);
    let spec = ClientSpec {
        note,
        sk_d,
        path,
        index,
        output: &output,
        fee: 100,
    };
    let artifacts = prove_client_transfer(inner, &spec, root, map)?;
    let envelope = sign_statement(&artifacts.public, key_seed);
    Ok(ClientTransferProof {
        verifier: artifacts.verifier,
        proof: artifacts.proof,
        statement: artifacts.statement,
        shape: ONE_IN_ONE_OUT,
        public: artifacts.public,
        envelope,
    })
}

/// Sign a public statement with a deterministic SPHINCS+ key.
///
/// The message is built through the real [`ShieldedTransfer`] encoder, so
/// the signature covers exactly the bytes the node re-encodes and checks.
fn sign_statement(public: &shielded::TransferPublic, key_seed: u64) -> ShieldedTransfer {
    let mut rng = StdRng::seed_from_u64(key_seed);
    let (sk, vk) = SphincsPlusAuth::generate_keypair(&mut rng);
    let unsigned = ShieldedTransfer {
        public: public.clone(),
        verifying_key: vk.clone(),
        signature: SphincsPlusAuth::sign(&sk, b"unused"),
    };
    let message = unsigned.signing_message().expect("test statement encodes");
    ShieldedTransfer {
        public: public.clone(),
        verifying_key: vk,
        signature: SphincsPlusAuth::sign(&sk, &message),
    }
}

/// A tree holding both notes, with its root and both membership paths.
///
/// Both transfers must witness the *same* root, and it must be the root of
/// the tree that actually holds them — a root read from some other tree would
/// leave the block's shared-root anchor testing nothing.
fn shared_tree(
    note_a: &shielded::Note,
    note_b: &shielded::Note,
) -> (MerkleRoot, Vec<Vec<pq_hash::Digest32>>) {
    let (tree, paths) = tree_with(&[*note_a, *note_b]);
    (tree.root(), paths)
}

/// The initial distribution: both notes, committed.
fn genesis_notes(note_a: &shielded::Note, note_b: &shielded::Note) -> Vec<pq_hash::NoteHash> {
    vec![
        note_a.commit(&Keccak256Commitment),
        note_b.commit(&Keccak256Commitment),
    ]
}

/// The root of a tree holding `notes`, computed independently of
/// `PoolState::funded`.
fn tree_root_of(notes: &[shielded::Note]) -> MerkleRoot {
    use shielded::tree::CommitmentTree;
    let mut tree = CommitmentTree::new(Keccak256Commitment);
    for n in notes {
        tree.append(&n.commit(&Keccak256Commitment));
    }
    tree.root()
}

#[test]
fn two_client_proofs_settle_into_one_verified_block() -> Result<(), Box<dyn std::error::Error>> {
    let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0)?;
    let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));

    let (note_a, sk_a) = funded_note(11, 1_000);
    let (note_b, sk_b) = funded_note(22, 2_000);
    let (root, paths) = shared_tree(&note_a, &note_b);

    // One map across both transfers: the chain constraint only means
    // something if they are transitions of the same nullifier trie.
    let mut map = shielded::NullifierMap::new(Keccak256Commitment);

    let tx_a = client_prove(
        &inner, &note_a, &sk_a, &paths[0], 0, 900, recipient, root, &mut map, 1,
    )?;
    let tx_b = client_prove(
        &inner, &note_b, &sk_b, &paths[1], 1, 1_900, recipient, root, &mut map, 2,
    )?;

    // Preconditions the block's soundness rests on, asserted rather than
    // assumed: same tree root, chained nullifier roots.
    assert_eq!(tx_a.public.root, tx_b.public.root);
    assert_eq!(
        tx_a.public.nullifier_roots.after, tx_b.public.nullifier_roots.before,
        "the second transfer must chain from the first's nullifier root"
    );

    // `submit` takes ownership, so anything the assertions need is captured
    // before the move.
    let expected_len = HEADER_LIMBS + tx_a.statement.len() + tx_b.statement.len();
    let final_nf_root = tx_b.public.nullifier_roots.after;
    let nf_a = note_a.nullifier(&Sha3_256Shielded, &sk_a);

    // The sequencer starts from a tree that already holds both notes, which
    // is what the transfers' witnessed root commits to.
    let mut seq = Sequencer::funded(LOG_MAX_LDE, genesis_notes(&note_a, &note_b))?;
    seq.submit(tx_a)?;
    seq.submit(tx_b)?;
    assert_eq!(seq.pending(), 2);

    let block = seq.produce_block()?;
    assert_eq!(block.num_transfers, 2);
    assert_eq!(block.total_fee, 200);

    // The statement is the shape header followed by both transfers'
    // statements — the exact layout `BlockStatement.sol` decodes.
    assert_eq!(
        block.statement.len(),
        expected_len,
        "block statement = header({HEADER_LIMBS}) + two transfer statements"
    );

    // The settled proof verifies against the statement the contract is handed.
    block
        .verifier
        .verify(&block.proof, &block.statement)
        .expect("the settled block proof must verify");

    // And the node's state landed where the proof says it should.
    assert_eq!(seq.state().block_number(), 1);
    assert_eq!(seq.state().note_count(), 4, "2 funded + 2 outputs");
    assert_eq!(seq.state().spent_count(), 2);
    assert_eq!(
        seq.state().nullifier_root(),
        final_nf_root,
        "the committed nullifier root must be the last transfer's `after`"
    );
    assert!(seq.state().is_spent(&nf_a));
    Ok(())
}

#[test]
fn a_double_spend_across_the_batch_is_rejected_at_admission(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0)?;
    let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
    let (note_a, sk_a) = funded_note(11, 1_000);
    let (note_b, sk_b) = funded_note(22, 2_000);
    let (root, paths) = shared_tree(&note_a, &note_b);

    let mut map = shielded::NullifierMap::new(Keccak256Commitment);
    let tx_a = client_prove(
        &inner, &note_a, &sk_a, &paths[0], 0, 900, recipient, root, &mut map, 1,
    )?;

    let nf_a = note_a.nullifier(&Sha3_256Shielded, &sk_a);
    let nf_b = note_b.nullifier(&Sha3_256Shielded, &sk_b);

    let mut seq = Sequencer::funded(LOG_MAX_LDE, genesis_notes(&note_a, &note_b))?;
    seq.submit(tx_a)?;

    // A second transfer spending the SAME note, proven against the
    // *committed* nullifier root rather than the pending one. It is a valid
    // proof of a real relation — it just isn't the relation the pool is in.
    // Admission is what must catch it.
    let mut fresh_map = shielded::NullifierMap::new(Keccak256Commitment);
    // Same value as the honest transfer so the only difference is the
    // replayed nullifier. A different value would fail the balance check
    // first, and the test would pass without ever reaching admission.
    let replay = client_prove(
        &inner,
        &note_a,
        &sk_a,
        &paths[0],
        0,
        900,
        recipient,
        root,
        &mut fresh_map,
        3,
    )?;

    let before = seq.pending();
    let err = seq
        .submit(replay)
        .expect_err("a replay of a queued nullifier must be rejected");
    assert!(
        matches!(
            err,
            SequencerError::State(StateError::StaleNullifierRoot { .. })
        ),
        "expected a stale nullifier root, got {err}"
    );
    assert_eq!(
        seq.pending(),
        before,
        "a rejected submit must not grow the mempool"
    );

    // The honest transfer is still queued and still settles.
    let block = seq.produce_block()?;
    assert_eq!(block.num_transfers, 1);
    assert!(seq.state().is_spent(&nf_a));

    // The unused second note stays unspent: nothing in this test consumed it.
    assert!(
        !seq.state().is_spent(&nf_b),
        "an unspent note's nullifier must remain absent"
    );
    Ok(())
}

#[test]
fn an_empty_mempool_produces_no_block() {
    let mut seq = Sequencer::new(LOG_MAX_LDE).expect("sequencer builds");
    assert_eq!(
        seq.produce_block().err().map(|e| e.to_string()),
        Some("mempool empty".to_string())
    );
    assert_eq!(seq.state().block_number(), 0);
}

#[test]
fn a_funded_genesis_matches_a_tree_of_the_same_notes() {
    // `PoolState::funded` must compute its root by appending, not by
    // assignment. If funding ever wrote a root directly, it would diverge
    // from an independently built tree and this fails.
    let (note_a, _sk_a) = funded_note(11, 1_000);
    let (note_b, _sk_b) = funded_note(22, 2_000);

    let funded = PoolState::funded(genesis_notes(&note_a, &note_b));
    assert_eq!(
        funded.root(),
        tree_root_of(&[note_a, note_b]),
        "funded root must equal the tree built from the same notes"
    );
    assert_eq!(
        funded.nullifier_root(),
        PoolState::genesis().nullifier_root(),
        "funding notes must not touch the nullifier map"
    );
    assert_eq!(funded.note_count(), 2);
    assert_eq!(funded.block_number(), 0);
}
