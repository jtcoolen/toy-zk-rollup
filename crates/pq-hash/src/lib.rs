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
//! | Commitment (note Merkle tree) | Poseidon2 (`KoalaBear`, width 16) | The tree is hashed *in-circuit* now: the proof attests each append and the contract only stores roots. One Poseidon2 perm is one AIR row; Keccak-f would cost ~24. See D-088 and [`poseidon`]. |
//! | Nullifier tree (in-circuit absence folds) | Keccak-256 | Already arithmetized with the vendored Keccak gadget; the contract never touches it. Untouched by D-088. |
//! | Transcript (Fiat-Shamir) | Keccak-256 | Native EVM opcode; the Solidity verifier replays it natively. |
//!
//! Keccak-256 and SHA3-256 are the same sponge with a different domain-separation
//! byte: Keccak-256 (the original) pads with `0x01`, FIPS-202 SHA3-256 pads with
//! `0x06`. They are not interchangeable — hashing the same input gives different
//! digests — but they carry the same 128-bit collision security and no known
//! structural weakness, so choosing Keccak on-chain is a **gas choice, not a
//! security downgrade**.
//!
//! The asymmetry that drives the split: `keccak256` is a *native opcode* (0x20)
//! costing ~30 gas, while FIPS SHA3-256 has **no precompile at all** — verifying
//! it on-chain would mean implementing the sponge in Solidity, thousands of gas per
//! hash. The shielded layer runs off-chain and in the wallet, where SHA3-256 is
//! free to use; the commitment and transcript layers are replayed by the verifier,
//! where Keccak is the only cheap option.
//!
//! Note that the EVM precompiles at `0x01`–`0x09` are `ecrecover`, `sha256`,
//! `ripemd160`, `identity`, and the BLAKE2/bls set — none of them is SHA3-256,
//! and there is no `keccakf1600` permutation precompile either.
//!
//! ## What this crate deliberately does not do
//!
//! Its only Plonky3 dependency is the Poseidon2 commitment layer: pure-Rust
//! field, permutation and sponge crates, no prover plumbing. The challenger
//! machinery still lives in `prover`.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod commitment;
mod digest;
mod poseidon;
mod shielded;
mod traits;

pub use commitment::Keccak256Commitment;
pub use digest::{Digest32, MerkleRoot, NoteHash, Nullifier};
pub use poseidon::{
    bytes_to_field_elements, digest_to_elements, elements_to_digest, poseidon2_16, Field,
    Poseidon2Commitment, Poseidon2Compress, Poseidon2Perm16, Poseidon2Sponge, DIGEST_ELEMS,
    KOALABEAR_P_U32, RATE, WIDTH,
};
pub use shielded::Sha3_256Shielded;
pub use traits::{CommitmentHasher, ShieldedHasher};

/// The digest length every implementation in this crate produces.
pub const DIGEST_LEN: usize = 32;
