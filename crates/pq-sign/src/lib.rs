//! # pq-sign
//!
//! Post-quantum spend authorization, behind one trait so the rest of the system
//! cannot tell which scheme is wired in — and cannot accidentally fall back to a
//! classical signature.
//!
//! ## Why SPHINCS+ and not ML-DSA
//!
//! SPHINCS+ verification is *entirely* hash-based: WOTS+ one-time chains, a FORS
//! forest, and a hypertree of hashes. That means the in-circuit / on-chain verifier
//! reuses the same SHA-256 machinery it already has. ML-DSA needs NTT-based
//! lattice arithmetic — thousands of extra constraints and a whole second
//! codebase. See `.scratch/pq-shielded-rollup/issues/06-pq-signature-choice.md`.
//!
//! ## The `Sha2_*` parameter sets matter
//!
//! `slh-dsa`'s `Sha2_*` sets use **pure SHA-256 / HMAC-SHA256 / MGF1-SHA256**
//! with no SHAKE anywhere. That lets a verifier depend on a single hash primitive
//! (`sha256`, an EVM precompile) rather than two. We use `Sha2_128f`.
//!
//! The `f` ("fast") variant verifies ~16x faster than `s` at the cost of a larger
//! signature. In a circuit/on-chain-bound system the verification cost is what
//! gates us, so `f` wins; the 8KB signature is a bandwidth detail we hide in the
//! wallet.
//!
//! ## Stub authorization
//!
//! [`StubSpendAuth`] exists so the pipeline can be exercised before the real
//! verifier lands. It is gated behind the non-default `insecure-stub` feature and
//! unit tests assert it cannot be selected in a release build.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod spend_auth;
#[cfg(feature = "insecure-stub")]
mod stub;

pub use slh_dsa::{Sha2_128f, SigningKey, VerifyingKey};
pub use spend_auth::{SpendAuth, SpendAuthError, SphincsPlusAuth};
#[cfg(feature = "insecure-stub")]
pub use stub::StubSpendAuth;

/// Re-export so callers can generate keys without naming `rand` directly.
pub use rand;
