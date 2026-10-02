//! The block driver: mempool in, settled block out.
//!
//! # The trust boundary, drawn where the proofs are
//!
//! A transfer arrives already proven. The wallet runs the transfer circuit on
//! the spender's machine, because the witness — the note, `sk_d`, the
//! membership path — must never leave it. What the sequencer receives is a
//! proof plus a public statement plus an SPHINCS+ envelope, and its job is to
//! verify, batch, re-prove, and submit.
//!
//! ```text
//!   wallet                          sequencer
//!   ──────                          ─────────
//!   build transfer witness
//!   prove transfer circuit  ────►   verify envelope (SPHINCS+)
//!   (Poseidon2 WHIR)                verify child proof natively
//!                                   admit to mempool
//!                                   build block circuit
//!                                     verifies N child proofs in-circuit
//!                                     anchors one shared root
//!                                     chains the nullifier map
//!                                   settle under Keccak WHIR
//!                                   verify the block proof natively
//!                                   apply to state, submit to L1
//! ```
//!
//! The sequencer never sees a note's value, its `rho`, or a spending key. That
//! is not a courtesy — it is the shielded property. Everything the sequencer
//! could lie about is covered by a proof the contract checks.
//!
//! # Why the sequencer verifies natively before submitting
//!
//! Submitting an invalid block costs gas and stalls the pool. Verifying first
//! is cheap insurance and, more importantly, it is the same code path the
//! contract will run, so a proof that fails here would fail there. The native
//! check is not a substitute for the contract's; it is a rehearsal of it.

use std::collections::VecDeque;

use prover::block::{self, ChildProof, TransferShape};
use prover::whir_recursion::InnerWhirConfig;
use shielded::TransferPublic;

use crate::state::{PoolState, StateError};
use crate::tx::{ShieldedTransfer, TxError};

/// A client-produced transfer proof, bundled with everything the block circuit
/// needs to re-verify it.
///
/// The `CircuitVerifier` travels with the proof because the block circuit
/// takes the child's relation from the *retained verifier*, not from anything
/// the proof asserts. A proof arriving without its verifier cannot be batched:
/// there would be nothing to check its shape against.
///
/// This bundle is not serializable, and that is a real architectural seam, not
/// an oversight. A production sequencer would not receive the verifier from
/// the client — it would rebuild it from the circuit's identity, since the
/// verifier is a deterministic function of the circuit and its config. The
/// demo keeps client and sequencer in one process and passes the verifier
/// directly, which is the same value either way; the network transport for it
/// is ticketed work, not missing security.
pub struct ClientTransferProof {
    /// The verifier retained from the client's proving run.
    pub verifier: p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
    /// The client's proof, under the inner (Poseidon2) WHIR config.
    pub proof: p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
    /// The statement the client proved, as base-field limbs.
    pub statement: Vec<prover::F>,
    /// The transfer's shape, so the block can locate limbs in the statement.
    pub shape: TransferShape,
    /// The public statement, for state admission and application.
    pub public: TransferPublic,
    /// The SPHINCS+ envelope that authorized the spend.
    pub envelope: ShieldedTransfer,
}

// `CircuitVerifier` and `BatchStarkProof` do not implement `Debug`, and a
// derived impl would be impossible rather than merely noisy. Report what
// identifies the bundle.
impl core::fmt::Debug for ClientTransferProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientTransferProof")
            .field("statement_len", &self.statement.len())
            .field("shape", &self.shape)
            .field("nullifiers", &self.public.nullifiers.len())
            .field("outputs", &self.public.outputs.len())
            .field("fee", &self.public.fee)
            .finish_non_exhaustive()
    }
}

/// A settled block: the artefacts that go to L1.
pub struct BlockArtifact {
    /// The verified block statement: shape header plus every transfer's
    /// statement, as base-field limbs.
    pub statement: Vec<prover::F>,
    /// The settled Keccak-WHIR block proof.
    pub proof: p3_circuit_prover::BatchStarkProof<prover::whir::Config>,
    /// The verifier that accepted it, for the native-check audit trail.
    pub verifier: p3_circuit_prover::CircuitVerifier<prover::whir::Config>,
    /// Number of transfers in the block.
    pub num_transfers: usize,
    /// Total fees collected.
    pub total_fee: u64,
}

impl core::fmt::Debug for BlockArtifact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The proof is hundreds of KB; report what identifies it.
        f.debug_struct("BlockArtifact")
            .field("num_transfers", &self.num_transfers)
            .field("total_fee", &self.total_fee)
            .field("statement_len", &self.statement.len())
            .finish_non_exhaustive()
    }
}

/// Errors from the block driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequencerError {
    /// A transfer failed its envelope check.
    Tx(TxError),
    /// A transfer could not be admitted to the current state.
    State(StateError),
    /// A child proof failed native verification.
    InvalidChildProof,
    /// The block circuit could not be built or proven.
    Proving(String),
    /// The settled block proof failed native verification.
    InvalidBlockProof,
    /// The mempool is empty; there is nothing to prove.
    Empty,
}

impl core::fmt::Display for SequencerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tx(e) => write!(f, "transaction rejected: {e}"),
            Self::State(e) => write!(f, "state rejected transfer: {e}"),
            Self::InvalidChildProof => write!(f, "child transfer proof invalid"),
            Self::Proving(msg) => write!(f, "block proving failed: {msg}"),
            Self::InvalidBlockProof => write!(f, "settled block proof invalid"),
            Self::Empty => write!(f, "mempool empty"),
        }
    }
}

impl std::error::Error for SequencerError {}

impl From<TxError> for SequencerError {
    fn from(e: TxError) -> Self {
        Self::Tx(e)
    }
}

impl From<StateError> for SequencerError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

/// The sequencer.
///
/// Holds the canonical state and a FIFO mempool. Batching is greedy: a block
/// takes up to `max_transfers_per_block` from the front of the queue. Timing
/// policy (when to close a block) is deliberately not modelled — it is a
/// deployment concern, and modelling it here would suggest the protocol cares,
/// which it does not: any batch that verifies is a valid block.
///
/// # The pending nullifier projection
///
/// The two roots a transfer witnesses advance on different schedules within a
/// batch, and the sequencer has to track both:
///
/// * **Tree root** — every transfer in a batch witnesses the *same* committed
///   tree root. A transfer's outputs are not spendable until its block lands,
///   so nothing in the batch moves the tree out from under its siblings.
/// * **Nullifier root** — chains forward transfer by transfer. A transfer must
///   prove its nullifiers were absent from a map that already contains every
///   earlier queued transfer's nullifiers, or the batch would admit a
///   double-spend that no single committed snapshot shows.
///
/// `pending` is that chained map. Admission checks against `pending.root()`,
/// not `state.nullifier_root()`, and then advances `pending`. After a block
/// settles, `pending` is rebuilt from the newly-committed map plus whatever is
/// still queued — which reproduces the same chain, because the queued
/// transfers' `before` roots were already pinned by the drained ones.
pub struct Sequencer {
    state: PoolState,
    mempool: VecDeque<ClientTransferProof>,
    pending: shielded::NullifierMap<pq_hash::Keccak256Commitment>,
    inner: InnerWhirConfig,
    max_transfers_per_block: usize,
}

impl core::fmt::Debug for Sequencer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sequencer")
            .field("pending", &self.mempool.len())
            .field("max_transfers_per_block", &self.max_transfers_per_block)
            .field("state", &self.state)
            // `inner` (the WHIR config) is omitted: it is large, opaque, and
            // carries no information that distinguishes two sequencers.
            .finish_non_exhaustive()
    }
}

impl Sequencer {
    /// Build a sequencer over a fresh genesis state.
    ///
    /// `log_max_lde` sizes the inner WHIR config's height budget; it must
    /// cover the largest transfer circuit the pool will see.
    ///
    /// # Errors
    ///
    /// Returns [`SequencerError::Proving`] if the inner WHIR config cannot be
    /// sized for `log_max_lde`.
    pub fn new(log_max_lde: usize) -> Result<Self, SequencerError> {
        Ok(Self {
            state: PoolState::genesis(),
            mempool: VecDeque::new(),
            pending: PoolState::genesis().nullifier_map(),
            inner: InnerWhirConfig::new(log_max_lde, 0)
                .map_err(|e| SequencerError::Proving(e.to_string()))?,
            // Sized to the block height the prover is measured at (fan-in 2
            // at v=25). Raising this requires re-measuring the height budget;
            // see `prover::block::BLOCK_LOG_MAX_LDE`.
            max_transfers_per_block: 2,
        })
    }

    /// A sequencer whose genesis state already holds `notes`.
    ///
    /// The demo's transfers spend notes that were distributed at genesis, so
    /// the sequencer must start from a funded tree — a transfer's `root`
    /// commits to a tree that already contains the note being spent. See
    /// [`PoolState::funded`].
    ///
    /// # Errors
    ///
    /// Returns [`SequencerError::Proving`] if the inner WHIR config cannot be
    /// sized for `log_max_lde`.
    pub fn funded(
        log_max_lde: usize,
        notes: impl IntoIterator<Item = pq_hash::NoteHash>,
    ) -> Result<Self, SequencerError> {
        Ok(Self {
            state: PoolState::funded(notes),
            mempool: VecDeque::new(),
            pending: PoolState::genesis().nullifier_map(),
            inner: InnerWhirConfig::new(log_max_lde, 0)
                .map_err(|e| SequencerError::Proving(e.to_string()))?,
            max_transfers_per_block: 2,
        })
    }

    /// The canonical state.
    #[must_use]
    pub const fn state(&self) -> &PoolState {
        &self.state
    }

    /// Transfers waiting in the mempool.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.mempool.len()
    }

    /// Admit a proven transfer to the mempool.
    ///
    /// Three checks, cheapest first, so a junk transfer is rejected before a
    /// proof is ever looked at:
    ///
    /// 1. the SPHINCS+ envelope verifies over the public statement;
    /// 2. the statement's roots match the current state;
    /// 3. the child proof verifies natively.
    ///
    /// The order matters for `DoS` resistance: (1) is one hash-based signature
    /// check, (2) is a couple of comparisons, (3) is a STARK verification.
    ///
    /// # Errors
    ///
    /// Returns the first failing check's error.
    pub fn submit(&mut self, transfer: ClientTransferProof) -> Result<(), SequencerError> {
        transfer.envelope.verify_signature()?;
        // Checked against the *pending* nullifier root: the transfer must be
        // absent from everything already queued, not just from what settled.
        self.state
            .check_admit_against(&transfer.public, self.pending.root())?;
        transfer
            .verifier
            .verify(&transfer.proof, &transfer.statement)
            .map_err(|_| SequencerError::InvalidChildProof)?;
        for nf in &transfer.public.nullifiers {
            // `false` here would mean the nullifier is already in the pending
            // projection — a double-spend against the queue. The `before`-root
            // check above should already have caught it (a transfer that
            // repeats a queued nullifier cannot have witnessed the pending
            // root it claims), but the insert result is checked rather than
            // discarded so a gap in that reasoning fails closed.
            if !self.pending.insert(nf) {
                return Err(StateError::DoubleSpend(*nf).into());
            }
        }
        self.mempool.push_back(transfer);
        Ok(())
    }

    /// Drain the mempool into one settled block.
    ///
    /// Takes up to `max_transfers_per_block` from the front, builds the block
    /// circuit that verifies all of them in-circuit, settles it under the
    /// Keccak WHIR config, verifies the result natively, and applies the
    /// transfers to the state.
    ///
    /// The state is mutated only after the block proof verifies. A failed
    /// `produce_block` leaves the mempool and state untouched, so a caller can
    /// retry or drop without corrupting anything.
    ///
    /// # Errors
    ///
    /// Returns [`SequencerError::Empty`] if the mempool is empty, or the
    /// proving/verification failure that stopped the block.
    pub fn produce_block(&mut self) -> Result<BlockArtifact, SequencerError> {
        if self.mempool.is_empty() {
            return Err(SequencerError::Empty);
        }
        let take = self.max_transfers_per_block.min(self.mempool.len());
        let batch: Vec<ClientTransferProof> = self.mempool.drain(..take).collect();

        let artifact = self.settle_batch(&batch)?;

        // The proof verified; now record what it established.
        for item in &batch {
            self.state.apply(&item.public)?;
        }
        self.state.commit_block();

        // Re-project the pending map from the newly committed state plus
        // whatever is still queued. Rebuilding rather than continuing to use
        // the old projection keeps `pending` anchored to committed state, so
        // a later rejection cannot leave it drifted ahead of the ledger.
        self.pending = self.state.nullifier_map();
        for item in &self.mempool {
            for nf in &item.public.nullifiers {
                // Same reasoning as in `submit`: a repeat here would mean the
                // queue holds two transfers spending one nullifier, which the
                // per-transfer `before`-root check forbids. Checked, not
                // ignored.
                if !self.pending.insert(nf) {
                    return Err(StateError::DoubleSpend(*nf).into());
                }
            }
        }
        Ok(artifact)
    }

    /// Build and settle the block circuit for one batch, without touching
    /// state. Split out so a caller can prove a batch without applying it.
    fn settle_batch(&self, batch: &[ClientTransferProof]) -> Result<BlockArtifact, SequencerError> {
        let children: Vec<ChildProof<'_>> = batch
            .iter()
            .map(|item| ChildProof {
                verifier: &item.verifier,
                proof: &item.proof,
                statement: &item.statement,
                shape: item.shape,
            })
            .collect();

        let rc = block::build_multi_transfer_circuit(&self.inner, &children)
            .map_err(|e| SequencerError::Proving(e.to_string()))?;

        let (proof, verifier) = block::settle_block_circuit(&rc, block::BLOCK_LOG_MAX_LDE)
            .map_err(|e| SequencerError::Proving(e.to_string()))?;

        let statement = block_statement(&children)?;

        // Rehearse the contract: verify the settled proof against the exact
        // statement the contract will be handed.
        verifier
            .verify(&proof, &statement)
            .map_err(|_| SequencerError::InvalidBlockProof)?;

        let total_fee = batch.iter().map(|item| item.public.fee).sum();

        Ok(BlockArtifact {
            statement,
            proof,
            verifier,
            num_transfers: batch.len(),
            total_fee,
        })
    }
}

/// Reconstruct the block statement from children: shape header, then each
/// child's statement, concatenated.
///
/// Mirrors the contract's `BlockStatement.decode` exactly. The header is
/// derived from the children's shapes, not supplied, so the contract and the
/// prover cannot disagree about where the header ends.
///
/// # Errors
///
/// Returns [`SequencerError::Proving`] if a shape header cannot be encoded —
/// a block with more than 65 535 transfers, or a transfer with more than
/// 65 535 inputs. Both are far beyond what the mempool admits, but the
/// failure is propagated rather than assumed away: a wrong header would pin
/// the shared-root anchor to the wrong limbs.
fn block_statement(children: &[ChildProof<'_>]) -> Result<Vec<prover::F>, SequencerError> {
    let header = block::shape_header(children.iter().map(|c| &c.shape))
        .map_err(|e| SequencerError::Proving(format!("shape header: {e}")))?;
    let mut out: Vec<prover::F> = Vec::with_capacity(
        header.len() + children.iter().map(|c| c.statement.len()).sum::<usize>(),
    );
    // Fully qualified `from_u16`: `Vec<F>` implements both `Extend<&F>` and
    // `Extend<F>`, so an unannotated closure leaves inference unresolved.
    out.extend(
        header
            .iter()
            .map(|&v| <prover::F as p3_field::PrimeCharacteristicRing>::from_u16(v)),
    );
    for child in children {
        out.extend_from_slice(child.statement);
    }
    Ok(out)
}
