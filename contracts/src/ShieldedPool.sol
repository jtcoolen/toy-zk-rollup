// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IWhirVerifier} from "./interfaces/IWhirVerifier.sol";
import {BlockStatement} from "./BlockStatement.sol";

/// Settlement for the post-quantum shielded pool: a state-root tracker.
///
/// This contract holds **two roots and nothing else that matters**. Every block
/// must present a proof that carries the chain from the roots it currently
/// stores to a new pair of roots, and the contract records the new pair. Both
/// roots are *attested*: the contract checks continuity and stores what the
/// proof says, and derives nothing.
///
/// * **Commitment tree** — note commitments. Since D-088 the transfer circuit
///   re-derives every output append in-circuit (Poseidon2 frontier fold) and
///   exports the post-append root as a public value, chained child by child in
///   the block circuit. The contract therefore stores the attested root exactly
///   like the nullifier root: a continuity check and two storage writes, with
///   no tree re-derivation at all (the whole applyBlock body, stub verifier
///   aside, is ~0.5M gas regardless of output count). The old Keccak
///   accumulator re-hashed every leaf on-chain; that work now happens once,
///   in-circuit, where a false root makes the block unwitnessable.
/// * **Nullifier map** — spent nullifiers. The contract stores the root and
///   chains it; it does **not** hold a set of nullifiers and performs no replay
///   check of its own.
///
/// ## Why there is no nullifier set
///
/// Replay resistance used to live here: insert each nullifier, revert on a
/// duplicate. That made the contract a second source of truth for a fact the
/// proof already establishes. The transfer circuit now proves nullifier
/// *non-membership* in-circuit (D-032, D-035): each spend folds
/// `keccak256` from an empty-subtree constant up to the nullifier root it
/// inherited, then folds the nullifier itself up to the root after insertion.
/// Both endpoints are in the verified statement, and the block circuit chains
/// one transfer's `after` to the next transfer's `before`.
///
/// So a replayed nullifier cannot extend the chain: its absence fold cannot
/// land on the root it inherited, because that root already has it inserted.
/// The block is simply unwitnessable. A contract-side set would add a store
/// write per nullifier (~20k gas each) to re-check something the proof already
/// makes impossible, and — worse — would mean a bug in the contract could
/// diverge from a correct proof.
///
/// What the contract *does* contribute is the one thing no proof can: knowing
/// which root the chain is actually at. The circuit proves its own
/// `rootBefore` is internally consistent; only this contract can say "that is
/// the root we are at".
///
/// ## Trust model
///
/// The prover is untrusted. The verifier is injected and assumed correct. The
/// sequencer is untrusted for *what* it batches and *when*, but cannot forge a
/// block: every state transition here is gated on a verified proof.
///
/// ## What this contract does not do
///
/// It does not check that fees are correct — the circuit enforces value
/// conservation, so `sum(inputs) = sum(outputs) + fee` already holds. It does
/// not check that a transfer's outputs are well-formed — the circuit commits to
/// them. Anything the circuit proves is not repeated here.
contract ShieldedPool {
    using BlockStatement for uint256[];

    /// Verifies the recursive WHIR proof. Immutable: the settlement rules cannot
    /// change under a live pool.
    IWhirVerifier public immutable verifier;

    /// Number of blocks applied.
    uint256 public blockNumber;

    /// The commitment-tree root the next block must build on.
    bytes32 public currentRoot;

    /// The nullifier-map root the next block must build on.
    bytes32 public currentNullifierRoot;

    /// Collected fees, withdrawable by `feeRecipient`.
    address public feeRecipient;

    /// A block was applied, carrying both root transitions.
    event BlockApplied(
        uint256 indexed blockNumber,
        bytes32 rootBefore,
        bytes32 rootAfter,
        bytes32 nullifierRootBefore,
        bytes32 nullifierRootAfter,
        uint256 fee
    );

    error NotVerified();
    error RootMismatch(bytes32 expected, bytes32 got);
    error NullifierRootMismatch(bytes32 expected, bytes32 got);
    error NotFeeRecipient();

    /// Deploy at an explicit genesis state.
    ///
    /// `genesisRoot_` is the commitment-tree root the genesis state has - the
    /// Poseidon2 root of the tree holding the funded notes (D-088: roots are
    /// attested, not derived, so the deployer names the root the first block
    /// will be witnessed against; the genesis file emitted by the prover export
    /// or `node genesis` carries exactly that value).
    ///
    /// `genesisNullifierRoot_` is the nullifier-map root the genesis state has.
    /// Pass `bytes32(0)` to mean "an empty nullifier map": the contract then
    /// computes the prover's empty-map root itself (depth 256, empty leaf zero,
    /// empty[h] = keccak(empty[h-1] || empty[h-1]) - a constant of that scheme,
    /// ~256 keccak at deploy) rather than trusting a first block to name it.
    ///
    /// Neither root is trusted blindly: the first applied block must prove a
    /// transition *from* them, so a wrong genesis simply makes every real block
    /// revert with RootMismatch / NullifierRootMismatch.
    constructor(
        IWhirVerifier verifier_,
        address feeRecipient_,
        bytes32 genesisRoot_,
        bytes32 genesisNullifierRoot_
    ) {
        require(address(verifier_) != address(0), "verifier required");
        require(feeRecipient_ != address(0), "fee recipient required");
        verifier = verifier_;
        feeRecipient = feeRecipient_;
        currentRoot = genesisRoot_;
        currentNullifierRoot =
            genesisNullifierRoot_ == bytes32(0) ? _emptyNullifierRoot() : genesisNullifierRoot_;
    }
    /// Apply a verified block.
    ///
    /// The order of checks is deliberate. Verification comes first because it is
    /// the expensive one and because nothing else should be examined until the
    /// statement is known to be genuine. Continuity is checked next, before any
    /// state is touched, so a block that does not extend the current state
    /// reverts without partially applying.
    function applyBlock(uint256[] calldata statement, bytes calldata proof) external {
        if (!verifier.verify(statement, proof)) revert NotVerified();

        // `decode` takes memory; copying the calldata once is cheaper than
        // re-reading it per field and keeps the decoder simple.
        BlockStatement.Block memory block_ = statement.decode();

        // Continuity: this block must extend the state we are actually in.
        if (block_.rootBefore != currentRoot) {
            revert RootMismatch(currentRoot, block_.rootBefore);
        }
        if (block_.nullifierBefore != currentNullifierRoot) {
            revert NullifierRootMismatch(currentNullifierRoot, block_.nullifierBefore);
        }

        // Both roots are taken from the proof. That is the whole point of
        // proving the transition in-circuit: the circuit re-derives the tree
        // append (D-088) and the nullifier insertions, chains every transfer's
        // `after` to the next transfer's `before`, and exports the endpoints.
        // The contract records endpoints it cannot derive but can verify -
        // continuity against its own state is the only fact no proof can own.
        currentRoot = block_.rootAfter;
        currentNullifierRoot = block_.nullifierAfter;
        currentNullifierRoot = block_.nullifierAfter;

        unchecked {
            ++blockNumber;
        }
        emit BlockApplied(
            blockNumber,
            block_.rootBefore,
            block_.rootAfter,
            block_.nullifierBefore,
            block_.nullifierAfter,
            block_.totalFee
        );
    }

    /// The root of an empty nullifier map: the prover's depth-256 empty-subtree
    /// chain (`NULLIFIER_TREE_DEPTH` in `crates/shielded/src/nullifier_tree.rs`).
    /// Deploy-time only; the value is a constant of the scheme.
    function _emptyNullifierRoot() private pure returns (bytes32 cur) {
        for (uint256 h; h < 256; ++h) {
            cur = keccak256(abi.encodePacked(cur, cur));
        }
    }

    /// Withdraw collected fees. Only the fee recipient.
    function withdrawFees() external {
        if (msg.sender != feeRecipient) revert NotFeeRecipient();
        uint256 amount = address(this).balance;
        if (amount > 0) {
            (bool ok,) = feeRecipient.call{value: amount}("");
            require(ok, "fee transfer failed");
        }
    }
}
