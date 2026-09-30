//! # pq-hash
//!
//! Post-quantum hashing for the shielded pool, expressed as **three distinct
//! dependency-injection traits** so that no layer can be cross-wired with another.
//!
//! ## Why three traits and not one
//!
//! A single `Hasher` abstraction invites a maintainer to point the shielded layer
//! at the Merkle hash, or the transcript at the note hash. Each of those is a
//! silent, consensus-breaking change. Three unrelated traits make the mistake a
//! compile error: [`Sha3_256Shielded`] implements [`ShieldedHasher`] and nothing
//! else, so it *cannot* be passed where a [`CommitmentHasher`] is expected.
//!
//! ## The layering (see `.scratch/pq-shielded-rollup/issues/02-hash-layering.md`)
//!
//! | Layer | Primitive | Why |
//! |---|---|---|
//! | Shielded (note/nullifier derivation) | SHA3-256 | User-mandated. FIPS-202, post-quantum. |
//! | Commitment (Merkle tree, FRI) | Keccak-256 | `0x20` precompile on EVM: ~30 gas vs ~60 for SHA3. |
//! | Transcript (Fiat-Shamir) | Keccak-256 | Same precompile argument; the Solidity verifier replays it natively. |
//!
//! Keccak-256 and SHA3-256 differ only in the padding byte (`0x06` vs `0x01`).
//! Using Keccak on-chain is therefore a **gas choice, not a security downgrade** —
//! both are 128-bit post-quantum hashes with no known structural weakness.
//!
//! ## What this crate deliberately does not do
//!
//! It has no dependency on Plonky3. The Plonky3 challenger plumbing lives in
//! `prover`, so this crate stays a pure, auditable crypto leaf.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod commitment;
mod digest;
mod shielded;
mod traits;

pub use commitment::Keccak256Commitment;
pub use digest::{Digest32, MerkleRoot, NoteHash, Nullifier};
pub use shielded::Sha3_256Shielded;
pub use traits::{CommitmentHasher, ShieldedHasher};

/// The digest length every implementation in this crate produces.
pub const DIGEST_LEN: usize = 32;
