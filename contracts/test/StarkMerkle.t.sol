// SPDX-License-Identifier: MIT
// Vectors from `crates/prover/tests/mmcs_vectors.rs`. Regenerate with:
//     cargo test -p prover --test mmcs_vectors -- --ignored --nocapture
// DO NOT edit the vectors by hand.
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StarkMerkle} from "../src/verifier/StarkMerkle.sol";
import {MerkleProof} from "../src/MerkleProof.sol";

/// Pins `StarkMerkle` to the real Plonky3 `MerkleTreeMmcs` over Keccak-256.
///
/// Three things are checked, and the negative ones are the point:
///
/// 1. the leaf codec - `into_byte_stream` (LE Montgomery limbs, no prefix) -
///    reproduces the prover's leaf digest;
/// 2. the fold reproduces the committed cap root at every index, which is
///    what proves the sibling ordering and side rule;
/// 3. wrong index, wrong leaf, and a truncated path all reject. A fold that
///    only passes positives is worthless: with four plausible conventions,
///    a wrong one still produces a 32-byte digest.
///
/// A fourth test asserts the STARK fold and the shielded fold are the same
/// function at depth 32, so the two trees cannot drift apart silently.
contract StarkMerkleTest is Test {
    string internal constant VECTOR = "test/vectors/mmcs.json";

    function test_leaf_codec_matches_rust() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".case_count");
        assertTrue(n > 0, "no cases");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat("$.cases[", vm.toString(i), "]");
            uint256[] memory limbs = vm.parseJsonUintArray(json, string.concat(base, ".row_u32"));
            bytes memory wantDigest = vm.parseJsonBytes(json, string.concat(base, ".leaf_digest_hex"));
            bytes memory wantBytes = vm.parseJsonBytes(json, string.concat(base, ".leaf_bytes_hex"));

            // The encoding itself: 4-byte LE per limb, concatenated. Compared
            // as bytes, not as hashes, so a wrong width or byte order names
            // itself instead of showing up as an unrelated digest mismatch.
            assertEq(
                _leBytes(limbs),
                wantBytes,
                string.concat("leaf bytes differ at case ", vm.toString(i))
            );

            // Both entry points must agree with the prover.
            assertEq(
                StarkMerkle.leafFromLimbs(limbs),
                bytes32(wantDigest),
                string.concat("leafFromLimbs differs at case ", vm.toString(i))
            );
            assertEq(
                StarkMerkle.leaf(wantBytes),
                bytes32(wantDigest),
                string.concat("leaf differs at case ", vm.toString(i))
            );
        }
    }

    /// Every index opens to the committed root - the ordering proof.
    function test_openings_reproduce_committed_root() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory root = vm.parseJsonBytes(json, ".root_hex");
        uint256 depth = vm.parseJsonUint(json, ".log_height");
        uint256 n = vm.parseJsonUint(json, ".case_count");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat("$.cases[", vm.toString(i), "]");
            uint256 index = vm.parseJsonUint(json, string.concat(base, ".index"));
            bytes32 leafDigest = bytes32(vm.parseJsonBytes(json, string.concat(base, ".leaf_digest_hex")));
            bytes[] memory sibs = vm.parseJsonBytesArray(json, string.concat(base, ".siblings_hex"));

            assertEq(sibs.length, depth, "sibling count != log2(height)");

            bytes32[] memory siblings = new bytes32[](sibs.length);
            for (uint256 l; l < sibs.length; ++l) {
                siblings[l] = bytes32(sibs[l]);
            }

            bytes32 got = StarkMerkle.computeRoot(leafDigest, index, siblings);
            assertEq(got, bytes32(root), string.concat("root differs at index ", vm.toString(index)));
            assertTrue(
                StarkMerkle.verify(bytes32(root), index, leafDigest, siblings, depth),
                string.concat("verify rejects a valid opening at index ", vm.toString(index))
            );
        }
    }

    /// A shifted index folds the siblings on the wrong sides.
    function test_wrong_index_rejects() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory root = vm.parseJsonBytes(json, ".root_hex");
        uint256 depth = vm.parseJsonUint(json, ".log_height");
        uint256 n = vm.parseJsonUint(json, ".case_count");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat("$.cases[", vm.toString(i), "]");
            uint256 index = vm.parseJsonUint(json, string.concat(base, ".index"));
            bytes32 leafDigest = bytes32(vm.parseJsonBytes(json, string.concat(base, ".leaf_digest_hex")));
            bytes[] memory sibs = vm.parseJsonBytesArray(json, string.concat(base, ".siblings_hex"));
            bytes32[] memory siblings = new bytes32[](sibs.length);
            for (uint256 l; l < sibs.length; ++l) {
                siblings[l] = bytes32(sibs[l]);
            }

            // Flip the lowest bit: a different leaf position, same path.
            uint256 wrong = index ^ 1;
            assertFalse(
                StarkMerkle.verify(bytes32(root), wrong, leafDigest, siblings, depth),
                string.concat("wrong index accepted at ", vm.toString(index))
            );
        }
    }

    /// A tampered leaf must not open under the same path.
    function test_tampered_leaf_rejects() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory root = vm.parseJsonBytes(json, ".root_hex");
        uint256 depth = vm.parseJsonUint(json, ".log_height");
        string memory base = "$.cases[0]";

        uint256 index = vm.parseJsonUint(json, string.concat(base, ".index"));
        bytes32 leafDigest = bytes32(vm.parseJsonBytes(json, string.concat(base, ".leaf_digest_hex")));
        bytes[] memory sibs = vm.parseJsonBytesArray(json, string.concat(base, ".siblings_hex"));
        bytes32[] memory siblings = new bytes32[](sibs.length);
        for (uint256 l; l < sibs.length; ++l) {
            siblings[l] = bytes32(sibs[l]);
        }

        // The untampered leaf must verify, so a rejection below is attributable
        // to the tamper and not to a broken path.
        assertTrue(
            StarkMerkle.verify(bytes32(root), index, leafDigest, siblings, depth),
            "control opening must verify"
        );
        assertFalse(
            StarkMerkle.verify(bytes32(root), index, bytes32(uint256(uint16(0xdead))), siblings, depth),
            "tampered leaf accepted"
        );
    }

    /// A truncated path is a second-preimage attempt, not an opening: the
    /// fold must be told the depth the commitment implies and refuse less.
    function test_truncated_path_rejects() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory root = vm.parseJsonBytes(json, ".root_hex");
        uint256 depth = vm.parseJsonUint(json, ".log_height");
        string memory base = "$.cases[0]";

        uint256 index = vm.parseJsonUint(json, string.concat(base, ".index"));
        bytes32 leafDigest = bytes32(vm.parseJsonBytes(json, string.concat(base, ".leaf_digest_hex")));
        bytes[] memory sibs = vm.parseJsonBytesArray(json, string.concat(base, ".siblings_hex"));
        bytes32[] memory full = new bytes32[](sibs.length);
        for (uint256 l; l < sibs.length; ++l) {
            full[l] = bytes32(sibs[l]);
        }

        bytes32[] memory short = new bytes32[](sibs.length - 1);
        for (uint256 l; l < short.length; ++l) {
            short[l] = full[l];
        }

        assertFalse(
            StarkMerkle.verify(bytes32(root), index, leafDigest, short, depth),
            "short path accepted"
        );
        // And the depth mismatch is caught even if the fold would coincidentally
        // land on the root, which it cannot here but must not be relied on.
        assertTrue(
            StarkMerkle.verify(bytes32(root), index, leafDigest, full, depth),
            "full path must verify"
        );
    }

    /// The two Merkle conventions in this repository must fold identically at
///    depth 32. They differ only in what a leaf is; if a future edit adds a
    ///    prefix or flips a side rule in one library and not the other, this
    ///    catches it without needing vectors for both trees.
    function test_stark_and_shielded_folds_agree_at_depth_32() public pure {
        bytes32[32] memory shieldedSiblings;
        bytes32[] memory starkSiblings = new bytes32[](32);
        for (uint256 i; i < 32; ++i) {
            bytes32 d = keccak256(abi.encodePacked("sibling", i));
            shieldedSiblings[i] = d;
            starkSiblings[i] = d;
        }

        bytes32 leaf = keccak256("leaf");
        for (uint256 idx = 0; idx < 8; ++idx) {
            assertEq(
                StarkMerkle.computeRoot(leaf, idx, starkSiblings),
                MerkleProof.computeRoot(leaf, idx, shieldedSiblings),
                string.concat("folds disagree at index ", vm.toString(idx))
            );
        }
    }

    /// limbs -> concatenated 4-byte LE, as a bytes value for comparison.
    function _leBytes(uint256[] memory limbs) internal pure returns (bytes memory out) {
        out = new bytes(limbs.length * 4);
        for (uint256 i; i < limbs.length; ++i) {
            uint256 v = limbs[i];
            out[i * 4] = bytes1(uint8(v));
            out[i * 4 + 1] = bytes1(uint8(v >> 8));
            out[i * 4 + 2] = bytes1(uint8(v >> 16));
            out[i * 4 + 3] = bytes1(uint8(v >> 24));
        }
    }
}