//! The rollup node: state, mempool, and the block driver.
//!
//! # The pipeline
//!
//! ```text
//!   ShieldedTransfer (wallet-signed, client-proven)
//!          │
//!          ▼
//!   Sequencer::submit ── verify SPHINCS+ envelope
//!                    ── check roots against current state
//!                    ── verify the child transfer proof natively
//!          │
//!          ▼
//!   mempool (FIFO)
//!          │
//!          ▼
//!   Sequencer::produce_block
//!          ├── build_multi_transfer_circuit   (verifies N children in-circuit)
//!          ├── settle_block_circuit           (Keccak-256 WHIR, the settlement proof)
//!          ├── verify the block proof natively (rehearsal of the contract)
//!          └── apply to PoolState             (append outputs, insert nullifiers)
//!          │
//!          ▼
//!   BlockArtifact { statement, proof }  ──►  ShieldedPool.applyBlock(...)
//! ```
//!
//! # Where the cryptography lives
//!
//! Three layers, each with a distinct job and a distinct hash:
//!
//! | layer | hash | where verified | what it establishes |
//! |---|---|---|---|
//! | note/nullifier derivation | SHA3-256 | in-circuit | knowledge of `sk_d`; value binding |
//! | inner transfer proof | Poseidon2 (in-circuit) | by the block circuit | the transfer relation holds |
//! | settlement proof | Keccak-256 | by the EVM | the whole block is valid |
//!
//! SHA3-256 is the shielded layer: it is what a note's commitment and a
//! nullifier are made of, and it is computed *inside* the circuit, so the
//! circuit can attest to it without the EVM ever evaluating SHA3.
//!
//! Keccak-256 is the settlement boundary: the outer WHIR proof's transcript
//! and Merkle commitments use it because the EVM has `keccak256` as a native
//! opcode (4 gas per round word) and does not have SHA3 at usable cost. The
//! two never substitute for each other, and the domain separation between them
//! is deliberate — see the `pq-hash` crate.
//!
//! SPHINCS+ is the outer envelope on the wire. It stops junk before proving
//! and gives submission provenance. It is *not* what authorises the spend —
//! the in-circuit nullifier relation does — and [`tx`] says so plainly rather
//! than letting the envelope look stronger than it is.
//!
//! # What this crate does not do
//!
//! It does not build transfer witnesses. Those need the note, the spending
//! key, and the membership path, and they must be built on the spender's
//! machine. A node that could build them is a node that could spend anything.
//! The client-side half is the wallet; see `wallet/`.

pub mod sequencer;
pub mod state;
pub mod tx;

pub use sequencer::{BlockArtifact, ClientTransferProof, Sequencer, SequencerError};
pub use state::{PoolState, StateError};
pub use tx::{ShieldedTransfer, TxError};
