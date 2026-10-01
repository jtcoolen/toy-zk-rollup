// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IWhirVerifier} from "./interfaces/IWhirVerifier.sol";
import {BlockStatement} from "./BlockStatement.sol";
import {MerkleAccumulator} from "./MerkleAccumulator.sol";

/// Settlement for the post-quantum shielded pool.
///
/// This contract is where the rollup's security actually lands. Everything the
/// circuits prove is only meaningful because of what is checked *here*:
///
/// * **Nullifier non-membership.** The transfer AIR proves an input note exists
///   in the tree; it cannot prove the note has never been spent before, because
///   that is a fact about the chain's history, not about the witness. The
///   on-chain nullifier set is what closes that gap. Without this contract the
///   claim made in `crates/prover/src/transfer.rs` is simply false and notes
///   can be spent twice.
/// * **Root continuity.** Each block must build on the root the previous block
///   left. The circuit proves its own `rootBefore` is internally consistent;
///   only the contract can say "that is the root we are actually at".
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

    /// Nullifiers already spent. The whole point of this contract.
    mapping(bytes32 nullifier => bool spent) public nullifierSet;

    /// Number of blocks applied.
    uint256 public blockNumber;

    /// The root the next block must build on.
    bytes32 public currentRoot;

    /// Collected fees, withdrawable by `feeRecipient`.
    address public feeRecipient;

    /// A block was applied.
    event BlockApplied(uint256 indexed blockNumber, bytes32 rootBefore, bytes32 rootAfter, uint256 fee);

    /// A nullifier was spent.
    event NullifierSpent(bytes32 indexed nullifier);

    /// A note commitment was appended.
    event NoteAppended(bytes32 indexed commitment, uint256 index);

    error NotVerified();
    error RootMismatch(bytes32 expected, bytes32 got);
    error NullifierAlreadySpent(bytes32 nullifier);
    error NotFeeRecipient();

    constructor(IWhirVerifier verifier_, address feeRecipient_) {
        require(address(verifier_) != address(0), "verifier required");
        require(feeRecipient_ != address(0), "fee recipient required");
        verifier = verifier_;
        feeRecipient = feeRecipient_;
        // The tree starts empty; the first block's rootBefore must equal this.
        currentRoot = root();
    }

    /// Apply a verified block.
    ///
    /// The order of checks is deliberate. Verification comes first because it is
    /// the expensive one and because nothing else should be examined until the
    /// statement is known to be genuine. Nullifier replay is checked for *all*
    /// transfers before *any* is marked, so a block that spends the same note
    /// twice reverts without partially applying.
    function applyBlock(uint256[] calldata statement, bytes calldata proof) external {
        if (!verifier.verify(statement, proof)) revert NotVerified();

        BlockStatement.Block memory block_ = statement.decode();

        // Continuity: this block must extend the state we are actually in.
        if (block_.rootBefore != currentRoot) {
            revert RootMismatch(currentRoot, block_.rootBefore);
        }

        // Pass one: reject any nullifier already spent, including duplicates
        // inside this block. Reading only, so a duplicate is caught before the
        // first copy is written.
        for (uint256 i; i < block_.transfers.length; ++i) {
            bytes32[] memory nfs = block_.transfers[i].nullifiers;
            for (uint256 j; j < nfs.length; ++j) {
                if (nullifierSet[nfs[j]]) revert NullifierAlreadySpent(nfs[j]);
            }
        }

        // Pass two: mark them spent.
        for (uint256 i; i < block_.transfers.length; ++i) {
            bytes32[] memory nfs = block_.transfers[i].nullifiers;
            for (uint256 j; j < nfs.length; ++j) {
                nullifierSet[nfs[j]] = true;
                emit NullifierSpent(nfs[j]);
            }
        }

        // Append every output commitment. The tree advances exactly as the
        // statement says, and the resulting root becomes the next block's
        // required rootBefore.
        for (uint256 i; i < block_.transfers.length; ++i) {
            bytes32[] memory outs = block_.transfers[i].outputs;
            for (uint256 j; j < outs.length; ++j) {
                _append(outs[j]);
                emit NoteAppended(outs[j], leafCount - 1);
            }
        }

        bytes32 rootAfter = root();
        currentRoot = rootAfter;
        unchecked {
            ++blockNumber;
        }
        emit BlockApplied(blockNumber, block_.rootBefore, rootAfter, block_.totalFee);
    }

    /// Whether `nullifier` has been spent.
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifierSet[nullifier];
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
