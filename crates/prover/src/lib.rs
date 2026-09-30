//! STARK proving for the post-quantum shielded rollup.
//!
//! ## What lives here
//!
//! The proving side is a thin, explicit composition of off-the-shelf Plonky3
//! pieces. Deliberately *not* hidden behind a generic framework: every choice in
//! [`config`] is a decision that the Solidity verifier has to reproduce, so it is
//! written out in one place where a reviewer can see all of it at once.
//!
//! ```text
//!   config.rs   the STARK configuration (field, commitment, transcript)
//!   spike.rs    the executable proof that the Keccak transcript works end-to-end
//! ```
//!
//! ## The hash policy this crate implements
//!
//! | Layer        | Hash         | Where verified              |
//! |------------|--------------|-----------------------------|
//! | Shielded   | SHA3-256     | off-chain + Solidity `0x04` |
//! | Commitment | Keccak-256   | Solidity `0x20` precompile  |
//! | Transcript | Keccak-256   | Solidity `keccak256()`      |
//!
//! Keccak in the commitment layer *and* the transcript is what makes an on-chain
//! verifier affordable: both are precompiles. Nothing on the verified path needs a
//! SNARK-friendly permutation, so the verified path contains no Poseidon at all.
//!
//! ## Why no SNARKs
//!
//! A STARK's verifier work is FRI verification plus constraint evaluation, both of
//! which are hash-and-field-arithmetic. That is checkable by a small, auditable
//! Solidity contract with no trusted setup and no pairing curve.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
// The spike is the executable statement of a property we depend on, not shipped API.
#[cfg(test)]
mod spike;

pub use config::{Challenge, Challenger, Config, F};
