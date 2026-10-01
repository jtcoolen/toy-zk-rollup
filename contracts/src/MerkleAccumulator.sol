// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Append-only Keccak-256 Merkle accumulator matching the prover's tree.
///
/// The tree is depth 32, leaves are note commitments, and unpopulated branches
/// are filled with the *empty subtree digest* for that height rather than being
/// absent. That is what makes the root independent of how much of the tree is
/// populated, and it is the same scheme the Rust `CommitmentTree` implements, so
/// a root computed here equals a root computed by the prover.
///
/// ```text
/// empty[0] = 0x00..00
/// empty[h] = keccak256(empty[h-1] || empty[h-1])
/// ```
///
/// ## Why the contract computes the root at all
///
/// The circuit proves that each transfer's `rootBefore` is real — every input
/// opens against it. It does *not* prove the root after the outputs are
/// appended, because that would mean re-implementing the whole tree inside the
/// AIR. So the contract derives `rootAfter` itself and stores it as the next
/// block's `rootBefore`. The alternative — letting the prover assert `rootAfter`
/// — would let a prover set the tree to whatever it liked.
///
/// ## Representation
///
/// Only `DEPTH` branch nodes are stored, not the tree. A complete subtree of
/// height `h` exists exactly when bit `h` of the leaf count is set, so presence
/// is derived from the count and needs no sentinel. Reading the root costs
/// `DEPTH` hashes; appending costs one hash per set bit in the count.
abstract contract MerkleAccumulator {
    /// Tree depth in levels above the leaves.
    uint256 public constant DEPTH = 32;

    /// Number of leaves appended so far.
    uint256 public leafCount;

    /// `branch[h]` is the digest of the complete subtree of height `h` most
    /// recently closed. Valid only when bit `h` of `leafCount` is set.
    mapping(uint256 => bytes32) private branch;

    /// Append one leaf.
    ///
    /// Merges upward through every already-present subtree of equal height: two
    /// height-`h` subtrees become one height-`(h+1)` subtree.
    function _append(bytes32 leaf) internal {
        bytes32 cur = leaf;
        uint256 h = 0;
        while (h < DEPTH && ((leafCount >> h) & 1) == 1) {
            cur = keccak256(abi.encodePacked(branch[h], cur));
            unchecked {
                ++h;
            }
        }
        require(h < DEPTH, "merkle tree full");
        branch[h] = cur;
        unchecked {
            ++leafCount;
        }
    }

    /// The current root.
    ///
    /// Folds from the leaves upward. At each height the accumulated value meets
    /// either the stored subtree of that height — which sits to its left — or the
    /// empty subtree, which fills the unpopulated right side.
    function root() public view returns (bytes32) {
        bytes32 cur = bytes32(0);
        bytes32 empty = bytes32(0);
        for (uint256 h; h < DEPTH; ++h) {
            if (h > 0) {
                empty = keccak256(abi.encodePacked(empty, empty));
            }
            if (((leafCount >> h) & 1) == 1) {
                cur = keccak256(abi.encodePacked(branch[h], cur));
            } else {
                cur = keccak256(abi.encodePacked(cur, empty));
            }
        }
        return cur;
    }
}
