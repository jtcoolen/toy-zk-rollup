// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Openings against the STARK commitment tree.
///
/// This is the tree the prover commits trace matrices with, and it is a
/// *different* tree from the shielded note tree in `MerkleProof.sol` - but
/// only in its leaves and its depth, not in its fold:
///
/// |              | shielded (`MerkleProof`) | STARK (this)              |
/// |--------------|--------------------------|---------------------------|
/// | leaf         | a note commitment, already | `keccak256(row bytes)`     |
/// |              | a `bytes32`                |                            |
/// | depth        | fixed 32                   | `siblings.length`          |
/// | node         | `keccak256(l || r)`        | `keccak256(l || r)`        |
/// | side rule    | sibling left when bit set  | sibling left when bit set  |
///
/// The fold is byte-identical, which is why one hash convention serves both
/// and why `StarkMerkleTest` asserts the two agree when handed 32 siblings.
///
/// ## Why the leaves are hashed and the shielded ones are not
///
/// A shielded leaf is a note commitment: already a digest, fixed width. A
/// STARK leaf is a *row* - a variable number of field elements - so it needs
/// a hash to become a fixed-width tree input. The encoding is
/// `RawDataSerializable::into_byte_stream`: each element as 4-byte
/// little-endian `to_unique_u32` (Montgomery form), concatenated, no length
/// prefix and no domain separator. Those are the same bytes
/// `SerializingChallenger32` absorbs when the transcript sees a row, so the
/// leaf the Merkle path authenticates and the row the transcript bound are
/// the same object.
///
/// Ground truth: `crates/prover/tests/mmcs_vectors.rs`, emitted to
/// `test/vectors/mmcs.json` from the real `MerkleTreeMmcs`. That generator
/// searches all four fold conventions and asserts the one implemented here is
/// the one the prover produces, so a Plonky3 ordering change fails in CI
/// rather than on-chain.
library StarkMerkle {
    /// Leaf digest from already-encoded row bytes.
    ///
    /// The caller supplies the `into_byte_stream` encoding; use
    /// `leafFromLimbs` when starting from field elements.
    function leaf(bytes memory rowBytes) internal pure returns (bytes32) {
        return keccak256(rowBytes);
    }

    /// Leaf digest from field elements given in canonical `u32` form.
    ///
    /// Each limb is written little-endian, matching
    /// `MontyField31::into_bytes`. Limbs are NOT range-checked against the
    /// KoalaBear modulus: the transcript binds the field elements elsewhere,
    /// and a caller that passes a non-field `u32` produces a leaf no honest
    /// prover could open, which is a soundness failure the caller owns.
    function leafFromLimbs(uint256[] memory limbs) internal pure returns (bytes32) {
        bytes memory row = new bytes(limbs.length * 4);
        for (uint256 i; i < limbs.length; ++i) {
            uint256 v = limbs[i];
            // Without this a limb >= 2^32 would silently truncate, and two
            // different uint256 inputs would encode to the same leaf - a
            // collision handed to whoever built the array.
            require(v >> 32 == 0, "limb out of u32 range");
            // Assembly keeps this to four MSTORE8s per limb with the limb
            // loaded once. The settlement path hashes one leaf per query, so
            // this is on the hot path. Writes stay inside `row` because the
            // loop bound and the allocation are the same expression.
            assembly {
                let dst := add(add(row, 0x20), mul(i, 4))
                mstore8(dst, and(v, 0xff))
                mstore8(add(dst, 1), and(shr(8, v), 0xff))
                mstore8(add(dst, 2), and(shr(16, v), 0xff))
                mstore8(add(dst, 3), and(shr(24, v), 0xff))
            }
        }
        return keccak256(row);
    }

    /// Recompute the root from a leaf digest and its opening.
    ///
    /// `siblings` runs leaf-to-root, so `siblings[0]` is the leaf's own
    /// sibling. Bit `level` of `index` selects the side: set means the running
    /// value went right, so the sibling is on the left.
    ///
    /// The depth is `siblings.length`, which the caller must tie to the
    /// commitment it trusts - a short path that happens to reach a trusted
    /// root is a second-preimage, not an opening. Callers take the expected
    /// depth from the tree geometry the transcript already bound.
    function computeRoot(
        bytes32 leafDigest,
        uint256 index,
        bytes32[] memory siblings
    ) internal pure returns (bytes32 current) {
        // Scratch pair at the top of memory (the region memory-safe assembly
        // may use without bumping the free pointer): one 64-byte buffer reused
        // per level, so a 20-level path costs zero allocations instead of 20
        // 64-byte ones. The two orderings are the same store pair with the
        // operands swapped - a select on the bit, not two code paths.
        assembly ("memory-safe") {
            let buf := mload(0x40)
            current := leafDigest
            let src := add(siblings, 0x20)
            let n := mload(siblings)
            for { let level := 0 } lt(level, n) { level := add(level, 1) } {
                let sib := mload(add(src, shl(5, level)))
                let left := current
                let right := sib
                if and(shr(level, index), 1) {
                    // went right: sibling on the left
                    left := sib
                    right := current
                }
                mstore(buf, left)
                mstore(add(buf, 0x20), right)
                current := keccak256(buf, 0x40)
            }
        }
    }

    /// Check that a leaf digest opens at `index` to `expectedRoot`.
    ///
    /// `expectedDepth` is checked as well as the root: an attacker who can
    /// truncate a path could otherwise reach a trusted root through a subtree.
    function verify(
        bytes32 expectedRoot,
        uint256 index,
        bytes32 leafDigest,
        bytes32[] memory siblings,
        uint256 expectedDepth
    ) internal pure returns (bool) {
        if (siblings.length != expectedDepth) {
            return false;
        }
        return computeRoot(leafDigest, index, siblings) == expectedRoot;
    }
}