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
//!   whir.rs     the WHIR-backed settlement configuration Solidity replays
//!   spike.rs    the executable proof that the Keccak transcript works end-to-end
//! ```
//!
//! ## The hash policy this crate implements
//!
//! | Layer        | Hash         | Where verified                          |
//! |------------|--------------|-----------------------------------------|
//! | Shielded   | SHA3-256     | Keccak-f[1600] rows, `0x06` pad byte    |
//! | Commitment | Keccak-256   | Solidity `keccak256()` (opcode `0x20`)  |
//! | Transcript | Keccak-256   | Solidity `keccak256()` (opcode `0x20`)  |
//!
//! Keccak in the commitment layer *and* the transcript is what makes an on-chain
//! verifier affordable: `keccak256` is a native opcode, and SHA3-256 is the same
//! permutation with a different domain-separation byte, so one audited permutation
//! covers both. There is no precompile for SHA3 itself, and none is needed.
//!
//! The recursion engine's in-circuit Merkle gadget is Poseidon2-shaped, so the
//! intermediate layers use Poseidon2; the settlement layer built in [`whir`] does
//! not, because nothing verifies it in-circuit.
//!
//! ## Why no SNARKs
//!
//! A STARK's verifier work is FRI verification plus constraint evaluation, both of
//! which are hash-and-field-arithmetic. That is checkable by a small, auditable
//! Solidity contract with no trusted setup and no pairing curve.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod block;
pub mod config;
pub mod sha3_block;
pub mod transfer;
pub mod whir;
pub mod whir_recursion;
// The spike is the executable statement of a property we depend on, not shipped API.
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod spike;

pub use config::{Challenge, Challenger, Config, F};

#[cfg(test)]
mod profile_guard {
    /// Proving must run optimized, and with overflow checks still on.
    ///
    /// Both halves of this matter, and neither is obvious from a green suite:
    ///
    /// - `opt-level = 3` is what makes a block proof take 9 s instead of 466 s.
    ///   An unoptimized prover measures the wrong thing, because the prover is
    ///   the code under test.
    /// - `debug_assertions` must stay **on**. Release turns them off, and they
    ///   have caught real bugs here that the release build silently masked -- a
    ///   `u8` overflow in a test fixture, and `debug_assert_eq!` checks inside
    ///   the recursion crate that catch stacked-arity mismatches before they
    ///   become wrong proofs.
    ///
    /// `.cargo/config.toml` sets `opt-level = 3` together with
    /// `debug-assertions = true` on the dev profile. This test pins that
    /// combination so a future profile reshuffle cannot quietly drop the checks
    /// while keeping the speed.
    ///
    /// This fails under `cargo test --release`, which is intended: release drops
    /// the overflow checks this project depends on. The optimized-by-default dev
    /// profile is the supported way to build and test here -- cargo has no
    /// `[build] profile` key, so making `dev` fast is the only way to get
    /// release speed without passing a flag.
    ///
    /// Kept as a runtime assertion rather than a `const` one so a deliberate
    /// `--release` build still compiles; only the test run objects.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn proving_keeps_overflow_checks_on() {
        assert!(
            cfg!(debug_assertions),
            "the prover must be tested with debug-assertions on; release's \
             debug_assertions = false hides overflow bugs this project has \
             already hit. See .cargo/config.toml"
        );
    }
}
