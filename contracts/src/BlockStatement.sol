// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {LimbCodec} from "./LimbCodec.sol";

/// Parsing of a verified block statement into the actions it authorises.
///
/// The statement layout is fixed by the Rust prover
/// (`crates/prover/src/block.rs`, `TransferShape`) and mirrored here exactly:
///
/// ```text
/// [ n, (inputs_0, outputs_0), ..., (inputs_{n-1}, outputs_{n-1}),
///   transfer 0: nullifiers..., outputs..., root, nfRootBefore, nfRootAfter, fee,
///   transfer 1: ... ]
/// ```
///
/// Three digests sit between a transfer's hashes and its fee: the commitment
/// root its inputs opened against, and the nullifier-map root before and after
/// this transfer's nullifiers were inserted.
///
/// The header is part of the *verified* statement, exported by the circuit as
/// constants. That matters: if the contract were told the split instead, a prover
/// could declare a split that makes the contract read an output commitment as a
/// nullifier, or skip a real nullifier and spend it again in a later block.
/// Reading the split from the proof removes that degree of freedom.
library BlockStatement {
    using LimbCodec for uint256[];

    /// Digests per transfer that are not nullifiers or outputs: the commitment
    /// root plus the nullifier-map root pair.
    uint256 public constant ROOTS_PER_TRANSFER = 3;

    /// Fee limbs per transfer (`VALUE_LIMBS` in the transfer circuit).
    uint256 public constant FEE_LIMBS = 4;

    /// One transfer's worth of actions, decoded.
    struct Transfer {
        /// Nullifiers this transfer spends, in order.
        bytes32[] nullifiers;
        /// Note commitments to append to the tree, in order.
        bytes32[] outputs;
        /// The commitment-tree root this transfer was witnessed against.
        bytes32 rootBefore;
        /// The nullifier-map root before this transfer's nullifiers.
        bytes32 nullifierBefore;
        /// The nullifier-map root after they were inserted.
        bytes32 nullifierAfter;
        /// The fee, in base units.
        uint64 fee;
    }

    /// A whole block, decoded.
    struct Block {
        /// The transfers, in statement order.
        Transfer[] transfers;
        /// The commitment root every transfer shares, enforced in-circuit by the
        /// anchor.
        bytes32 rootBefore;
        /// The nullifier-map root the block starts from: the first transfer's
        /// `nullifierBefore`.
        bytes32 nullifierBefore;
        /// The nullifier-map root the block ends at: the last transfer's
        /// `nullifierAfter`.
        bytes32 nullifierAfter;
        /// Total fees across all transfers.
        uint256 totalFee;
    }

    /// Number of statement limbs for `numTransfers` transfers carrying
    /// `totalHashes` hashes between them.
    ///
    /// Header (1 + 2 per transfer), then per transfer: its hashes, three root
    /// digests, one fee. Both the root term and the fee term scale with the
    /// transfer count, not with the statement as a whole.
    function expectedLen(uint256 numTransfers, uint256 totalHashes)
        internal
        pure
        returns (uint256)
    {
        return 1 + 2 * numTransfers
            + (totalHashes + ROOTS_PER_TRANSFER * numTransfers) * LimbCodec.LIMBS_PER_DIGEST
            + FEE_LIMBS * numTransfers;
    }

    /// Decode a verified statement.
    ///
    /// The caller must have already verified the accompanying proof against
    /// `statement`; this function performs no cryptographic check. It only
    /// translates, and rejects statements that do not match their own header.
    function decode(uint256[] memory statement) internal pure returns (Block memory block_) {
        require(statement.length >= 1, "empty statement");
        uint256 n = statement[0];
        require(n >= 1, "block has no transfers");
        require(n <= type(uint16).max, "block too large");

        uint256 cursor = 1;
        uint256 totalHashes = 0;
        uint256[] memory inputs = new uint256[](n);
        uint256[] memory outputs = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            inputs[i] = statement[cursor++];
            outputs[i] = statement[cursor++];
            totalHashes += inputs[i] + outputs[i];
        }

        // The header must account for the whole statement; a mismatch means the
        // statement was not produced by the prover that exported this header.
        uint256 expected = expectedLen(n, totalHashes);
        require(statement.length == expected, "statement length disagrees with header");

        block_.transfers = new Transfer[](n);
        bytes32 sharedRoot = bytes32(0);
        for (uint256 i; i < n; ++i) {
            uint256 nin = inputs[i];
            uint256 nout = outputs[i];

            bytes32[] memory nfs = new bytes32[](nin);
            for (uint256 j; j < nin; ++j) {
                nfs[j] = statement.digestFromLimbs(cursor);
                cursor += LimbCodec.LIMBS_PER_DIGEST;
            }
            bytes32[] memory outs = new bytes32[](nout);
            for (uint256 j; j < nout; ++j) {
                outs[j] = statement.digestFromLimbs(cursor);
                cursor += LimbCodec.LIMBS_PER_DIGEST;
            }
            bytes32 root = statement.digestFromLimbs(cursor);
            cursor += LimbCodec.LIMBS_PER_DIGEST;
            bytes32 nfBefore = statement.digestFromLimbs(cursor);
            cursor += LimbCodec.LIMBS_PER_DIGEST;
            bytes32 nfAfter = statement.digestFromLimbs(cursor);
            cursor += LimbCodec.LIMBS_PER_DIGEST;
            uint64 fee = statement.u64FromLimbs(cursor);
            cursor += FEE_LIMBS;

            if (i == 0) {
                sharedRoot = root;
                block_.nullifierBefore = nfBefore;
            } else {
                // Redundant with the in-circuit anchor and nullifier chain, but a
                // contract should not rely on the circuit having remembered to
                // constrain something. These are cheap reads of values that were
                // already proven, and they make the contract's own invariant
                // explicit rather than implied.
                require(root == sharedRoot, "transfers disagree on root");
                require(nfBefore == block_.transfers[i - 1].nullifierAfter, "nullifier chain broken");
            }

            block_.transfers[i] = Transfer({
                nullifiers: nfs,
                outputs: outs,
                rootBefore: root,
                nullifierBefore: nfBefore,
                nullifierAfter: nfAfter,
                fee: fee
            });
            block_.totalFee += fee;
        }
        block_.rootBefore = sharedRoot;
        block_.nullifierAfter = block_.transfers[n - 1].nullifierAfter;
    }
}
