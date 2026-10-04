// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IWhirVerifier} from "./interfaces/IWhirVerifier.sol";
import {BlockStatement} from "./BlockStatement.sol";
import {MerkleAccumulator} from "./MerkleAccumulator.sol";

/// Settlement for the post-quantum shielded pool: a state-root tracker.
///
/// This contract holds **two roots and nothing else that matters**. Every block
/// must present a proof that carries the chain from the roots it currently
/// stores to a new pair of roots, and the contract records the new pair.
///
/// * **Commitment tree** — note commitments. The contract appends the block's
///   outputs and derives the new root itself, because the circuit deliberately
///   does not prove the post-append root. Appending is deterministic given the
///   statement, so the contract is the right place for it.
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
contract ShieldedPool is MerkleAccumulator {
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

    constructor(IWhirVerifier verifier_, address feeRecipient_) {
        require(address(verifier_) != address(0), "verifier required");
        require(feeRecipient_ != address(0), "fee recipient required");
        verifier = verifier_;
        feeRecipient = feeRecipient_;
        // Both trees start empty; the first block's `before` roots must equal
        // these. The commitment root is this contract's own empty tree. The
        // nullifier map's empty root is the PROVER's scheme - depth 256, empty
        // leaf zero, empty[h] = keccak(empty[h-1] || empty[h-1]) - and it is a
        // constant of that scheme, so we compute it once at deploy (~256
        // keccak) rather than trusting a first block to name it. A block whose
        // nullifierBefore is anything else does not extend an empty map.
        currentRoot = root();
        currentNullifierRoot = _emptyNullifierRoot();
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

        // Append every output commitment. The tree advances exactly as the
        // proven statement says, and the resulting root becomes the next
        // block's required `rootBefore`.
        for (uint256 i; i < block_.transfers.length; ++i) {
            bytes32[] memory outs = block_.transfers[i].outputs;
            for (uint256 j; j < outs.length; ++j) {
                _append(outs[j]);
            }
        }

        bytes32 rootAfter = root();
        currentRoot = rootAfter;
        // The nullifier root is not recomputed — it is taken from the proof.
        // That is the whole point of proving the transition in-circuit: the
        // contract records an endpoint it cannot derive but can verify.
        currentNullifierRoot = block_.nullifierAfter;

        unchecked {
            ++blockNumber;
        }
        emit BlockApplied(
            blockNumber,
            block_.rootBefore,
            rootAfter,
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
