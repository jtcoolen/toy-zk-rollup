// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {LimbCodec} from "./LimbCodec.sol";

/// Parsing of a verified block statement into the actions it authorises.
///
/// The statement layout is fixed by the Rust prover
/// (`crates/prover/src/block.rs`, `block_statement`) and mirrored here exactly:
///
/// ```text
/// [ n, (inputs_0, outputs_0), ..., (inputs_{n-1}, outputs_{n-1}),
///   statementRoot, rootBefore, rootAfter, nfRootBefore, nfRootAfter,
///   fee_0, ..., fee_{n-1} ]
/// ```
///
/// `statementRoot` is a Poseidon2 fold over the children's full public-input
/// statements (D-089): the circuit folds each child's *verified* statement
/// targets into one running digest and exports the result, so one 32-byte
/// digest attests to every per-transfer nullifier, output commitment and
/// intermediate root without any of them being re-exposed. The contract
/// cannot open the fold - Poseidon2 is not cheap on the EVM - and does not
/// need to: the fold is bound by the proof, exactly like the roots it sits
/// beside. What the pool acts on is the four block digests and the fees.
///
/// The header is part of the *verified* statement, exported by the circuit as
/// constants. That matters: if the contract were told the split instead, a
/// prover could declare a shape that disagrees with what was verified. Reading
/// the split from the proof removes that degree of freedom.
library BlockStatement {
    using LimbCodec for uint256[];

    /// Fee limbs per transfer (`VALUE_LIMBS` in the transfer circuit).
    uint256 public constant FEE_LIMBS = 4;

    /// Digests exported after the fold root: the commitment-tree root pair and
    /// the nullifier-map root pair the block transitions between.
    uint256 public constant BLOCK_DIGESTS = 4;

    /// A whole block, decoded.
    struct Block {
        /// Number of transfers in the block (the header's first limb).
        uint256 numTransfers;
        /// The Poseidon2 fold over the children's full statements (D-089).
        /// Opaque on-chain by design: it is pinned by the proof, not opened.
        bytes32 statementRoot;
        /// The commitment root the block starts from: the first transfer's
        /// `rootBefore`.
        bytes32 rootBefore;
        /// The commitment root the block ends at: the last transfer's
        /// `rootAfter`, chained in-circuit child by child (D-088).
        bytes32 rootAfter;
        /// The nullifier-map root the block starts from: the first transfer's
        /// `nullifierBefore`.
        bytes32 nullifierBefore;
        /// The nullifier-map root the block ends at: the last transfer's
        /// `nullifierAfter`.
        bytes32 nullifierAfter;
        /// Total fees across all transfers, summed from the per-transfer limbs.
        uint256 totalFee;
    }

    /// Number of statement limbs for a block of `numTransfers` transfers.
    ///
    /// Header (1 + 2 per transfer), the fold root, the four block digests, and
    /// one fee per transfer. Note the child statements themselves are *not*
    /// here - that is the whole point of the fold: the length is `81 + 6n`,
    /// independent of how many nullifiers and outputs each transfer carries.
    function expectedLen(uint256 numTransfers) internal pure returns (uint256) {
        return 1 + 2 * numTransfers + (1 + BLOCK_DIGESTS) * LimbCodec.LIMBS_PER_DIGEST
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

        // Skip the shape counts: they are part of the verified statement but
        // the fold already covers the child statements they describe, and the
        // length check below pins the header to the statement that ships with
        // it. A header that disagrees with the statement cannot decode.
        //
        // M-03: the counts are still RANGE-CHECKED, not skipped. The circuit
        // exports each one through u16::try_from (crates/prover/src/block.rs,
        // shape_header), so an honest statement's header limbs are all <=
        // 0xffff. An unchecked header position is an F_p value the pool never
        // looks at but the constraint identity consumes raw - pinning the
        // range removes it as a degree of freedom even for a caller that
        // skipped the proof check.
        uint256 cursor = 1 + 2 * n;
        require(statement.length == expectedLen(n), "statement length disagrees with header");
        for (uint256 i = 1; i < cursor; ++i) {
            require(statement[i] <= type(uint16).max, "shape count out of range");
        }

        block_.numTransfers = n;
        block_.statementRoot = statement.digestFromLimbs(cursor);
        cursor += LimbCodec.LIMBS_PER_DIGEST;
        block_.rootBefore = statement.digestFromLimbs(cursor);
        cursor += LimbCodec.LIMBS_PER_DIGEST;
        block_.rootAfter = statement.digestFromLimbs(cursor);
        cursor += LimbCodec.LIMBS_PER_DIGEST;
        block_.nullifierBefore = statement.digestFromLimbs(cursor);
        cursor += LimbCodec.LIMBS_PER_DIGEST;
        block_.nullifierAfter = statement.digestFromLimbs(cursor);
        cursor += LimbCodec.LIMBS_PER_DIGEST;

        for (uint256 i; i < n; ++i) {
            block_.totalFee += statement.u64FromLimbs(cursor);
            cursor += FEE_LIMBS;
        }
        // The fee loop consumed exactly the statement; the length check above
        // already guarantees this, but a decoder should not rely on its caller
        // having checked.
        require(cursor == statement.length, "trailing limbs after fees");
    }
}
