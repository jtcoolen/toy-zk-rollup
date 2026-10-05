//! # shielded
//!
//! The shielded pool's domain model: what a note is, what makes a transfer valid,
//! and how notes are Merkleized.
//!
//! This crate is the **executable specification** of the rules the STARK proves.
//! It contains no proving code and no Plonky3 types. The prover consumes these
//! types and re-expresses their rules as polynomial constraints; a test in
//! `prover` checks that both agree on the same witness.
//!
//! ## The pieces
//!
//! | Module | What it fixes |
//! |---|---|
//! | [`note`] | The note's fields, its commitment preimage, its nullifier. |
//! | [`keys`] | Spend and viewing keys, as opaque bytes. |
//! | [`transfer`] | The conservation law and the public statement shape. |
//! | [`tree`] | The append-only commitment tree and the path format. |
//!
//! ## Why the preimage formats live here
//!
//! A note commitment is a hash of a specific byte layout. That layout is
//! consensus-critical: change the field order and every existing commitment is
//! invalidated. So the layout is written down once, in
//! [`Note::commit`](note::Note::commit), with the domain tags next to it, rather
//! than being implicit in whatever a gadget happens to hash.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod keys;
pub mod note;
pub mod nullifier_tree;
pub mod signing;
pub mod transfer;
pub mod tree;

pub use keys::{IncomingViewingKey, SpendPublicKey};
pub use note::Note;
pub use nullifier_tree::{
    verify_non_inclusion, NonInclusionWitness, NullifierMap, NULLIFIER_TREE_DEPTH,
};
pub use signing::{encode_statement, EncodeError, DOMAIN_TX, MAX_COUNT_PER_FIELD};
pub use transfer::{BalanceError, NullifierRoots, Transfer, TransferPublic, MAX_VALUE};
pub use tree::{CommitmentTree, MembershipPath};
