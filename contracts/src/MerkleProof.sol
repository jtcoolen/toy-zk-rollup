// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Verification of a membership opening against a trusted Merkle root.
///
/// The settlement path never rebuilds the tree. It holds a root it already
/// trusts — stored by a previous settlement — and checks that a claimed leaf
/// sits at a claimed index under it. That is this function.
///
/// ## The tree is prefix-free
///
/// `hashPair(l, r) = keccak256(l || r)` with no leaf prefix and no leaf
/// hashing. That is a deliberate choice, pinned by
/// `crates/shielded/tests/contract_vectors.rs` and the vectors in
/// `test/vectors/merkle.json`, and it is a divergence worth naming: the
/// vendored `sol-whir-p3` Merkle helpers use `0x00`/`0x01` domain
/// separators for leaves and internal nodes.
///
/// Domain separation exists to stop second-preimage attacks where an
/// attacker makes one structure's bytes look like another's. Here the
/// separation comes from somewhere else: leaves are note commitments and
/// internal nodes are pair hashes, but the two never appear in the same
/// position of the fold, and the depth is fixed at 32 with the index
/// selecting the side at every level. A path is not interchangeable with a
/// leaf because the fold shape is fixed by the index.
///
/// Anyone porting a helper from the vendored library must strip its prefixes
/// or the roots will not match. That mismatch is silent: both sides produce
/// a 32-byte digest, only one of them is the right one.
library MerkleProof {
    /// Tree depth in levels above the leaves. Must equal `DEPTH` in
    /// `crates/shielded/src/tree.rs`. Pinned by the generated
    /// `test/MerkleVectors.t.sol`.
    uint256 public constant DEPTH = 32;

    /// Recompute the root from a leaf and its opening.
    ///
    /// `siblings[i]` is the digest of the subtree adjacent to the path node at
    /// height `i`, leaf-to-root. Bit `i` of `index` selects which side the
    /// sibling sits on: set means the running value went right, so the sibling
    /// is on the left.
    ///
    /// Returns the recomputed root. The caller compares it against the root it
    /// trusts; this function does not decide what a valid root is.
    function computeRoot(
        bytes32 leaf,
        uint256 index,
        bytes32[DEPTH] memory siblings
    ) internal pure returns (bytes32) {
        bytes32 current = leaf;
        for (uint256 level; level < DEPTH; ++level) {
            bool goRight = (index >> level) & 1 == 1;
            current = goRight
                ? keccak256(abi.encodePacked(siblings[level], current))
                : keccak256(abi.encodePacked(current, siblings[level]));
        }
        return current;
    }

    /// Check that `leaf` opens at `index` under `root`.
    function verify(
        bytes32 root,
        uint256 index,
        bytes32 leaf,
        bytes32[DEPTH] memory siblings
    ) internal pure returns (bool) {
        return computeRoot(leaf, index, siblings) == root;
    }
}
