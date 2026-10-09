// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// Unit test for the v8 MROOTS satellite entry: a synthetic binary tree,
/// a pruned digest stream generated DIRECTLY from the tree (sibling nodes
/// read by position, not by walking), and the walk's root checked against
/// the tree root. Independent oracle for the frontier walk.
contract MrootsWalkTest is Test {
    TerminalWeight tw;

    function setUp() public { tw = new TerminalWeight(); }

    function _keccak(bytes32 a, bytes32 b) private pure returns (bytes32) {
        assembly { mstore(0, a) mstore(32, b) } 
        return keccak256(abi.encodePacked(_mem32(a), _mem32(b)));
    }
    function _mem32(bytes32 v) private pure returns (bytes32) { return v; }

    function test_walk_synthetic_tree() public {
        uint256 depth = 8;
        uint256 n = 1 << depth;
        // Tree nodes in a flat array: nodes[n + i] = leaf i.
        bytes32[] memory nodes = new bytes32[](2 * n);
        for (uint256 i; i < n; ++i) nodes[n + i] = bytes32(i + 1);
        for (uint256 p = n - 1; p >= 1; --p) {
            nodes[p] = _keccak(nodes[2 * p], nodes[2 * p + 1]);
        }

        uint256[] memory q = new uint256[](5);
        q[0] = 3; q[1] = 3; q[2] = 100; q[3] = 101; q[4] = 255;
        uint256 nq = q.length;

        // Stream: level-major, groups ascending; a lone child contributes
        // its sibling read straight from the tree. The satellite dedups
        // first, so the oracle must walk the sorted-UNIQUE set too.
        uint256[] memory frontier = new uint256[](nq);
        uint256 uf = 0;
        for (uint256 i; i < nq; ++i) {
            if (i == 0 || q[i] != q[i - 1]) frontier[uf++] = q[i];
        }
        uint256[] memory frontier0 = new uint256[](uf);
        for (uint256 i; i < uf; ++i) frontier0[i] = frontier[i];
        frontier = frontier0;
        uint256[] memory stream = new uint256[](depth * nq);
        uint256 w = 0;
        for (uint256 lvl; lvl < depth; ++lvl) {
            uint256 m = 0;
            uint256 i = 0;
            while (i < frontier.length) {
                uint256 parent = frontier[i] >> 1;
                if (i + 1 < frontier.length && (frontier[i + 1] >> 1) == parent) {
                    frontier[m] = parent; m++; i += 2;
                } else {
                    // Walk index at level lvl maps to heap node (n>>lvl)+idx.
                    uint256 sibWalk = frontier[i] ^ 1;
                    uint256 sibHeap = (n >> lvl) + sibWalk;
                    stream[w] = uint256(nodes[sibHeap]); w++;
                    frontier[m] = parent; m++; i++;
                }
            }
            // dedup parents into a fresh frontier
            uint256[] memory nf = new uint256[](m);
            uint256 u2 = 0;
            for (uint256 j; j < m; ++j) {
                if (j == 0 || frontier[j] != frontier[j - 1]) { nf[u2] = frontier[j]; u2++; }
            }
            frontier = nf;
        }

        // Frame: [magic, depth, nq, nD, indices..., leaves..., stream..., expectedRoot]
        bytes memory frame = new bytes((5 + 2 * nq + w) * 32);
        assembly {
            let p := add(frame, 32)
            mstore(p, 0x4D524F4F5453)
            mstore(add(p, 32), depth)
            mstore(add(p, 64), nq)
            mstore(add(p, 96), w)
            p := add(p, 128)
            for { let i := 0 } lt(i, nq) { i := add(i, 1) } {
                mstore(p, mload(add(q, add(32, mul(i, 32)))))
                p := add(p, 32)
            }
            for { let i := 0 } lt(i, nq) { i := add(i, 1) } {
                mstore(p, mload(add(nodes, add(32, add(mul(32, n), mul(32, mload(add(q, add(32, mul(i, 32))))))))))
                p := add(p, 32)
            }
            for { let i := 0 } lt(i, w) { i := add(i, 1) } {
                mstore(p, mload(add(stream, add(32, mul(i, 32)))))
                p := add(p, 32)
            }
            mstore(p, mload(add(nodes, 64))) // expectedRoot = nodes[1]
        }
        (bool ok, bytes memory ret) = address(tw).staticcall(frame);
        if (!ok) {
            uint256 sel;
            assembly { sel := shr(224, mload(add(ret, 32))) }
            emit log_named_uint("revert selector", sel);
            emit log_named_uint("ret len", ret.length);
        }
        assertTrue(ok, "satellite call ok");
        require(ret.length == 96, "reply 96");
        bytes32 root;
        assembly { root := mload(add(ret, 64)) }
        assertEq(root, nodes[1], "walk root == tree root");
    }

    // V-04 regression: two openings at the SAME index carrying DIFFERENT
    // leaves must revert with InconsistentDuplicateOpenings (the reference
    // mmcs check). Before the fix the walk silently kept one row and the
    // other's fold entered the claim unauthenticated. The honest duplicate
    // case (same index, same leaf) is covered by test_walk_synthetic_tree
    // above - q[0] == q[1] == 3 - and must keep passing.
    function test_v04_duplicate_index_different_leaf_reverts() public {
        // Tree: leaves [A,B,C,D]; queries [1,1] with leaves (B, B') where
        // B' is a wrong digest for index 1. Stream sized for the deduped
        // single-index frontier {1}: level 0 sibling A, level 1 sibling
        // hash(C,D).
        bytes32 A = bytes32(uint256(0xA));
        bytes32 B = bytes32(uint256(0xB));
        bytes32 C = bytes32(uint256(0xC));
        bytes32 D = bytes32(uint256(0xD));
        bytes32 AB = _keccak(A, B);
        bytes32 CD = _keccak(C, D);
        bytes32 root = _keccak(AB, CD);

        uint256 nq = 2;
        uint256[] memory stream = new uint256[](2);
        stream[0] = uint256(A);   // sibling of leaf 1 at level 0
        stream[1] = uint256(CD);  // sibling at level 1
        bytes memory frame = new bytes((5 + 2 * nq + 2) * 32);
        assembly {
            let p := add(frame, 32)
            mstore(p, 0x4D524F4F5453) // MROOTS
            mstore(add(p, 32), 2)     // depth
            mstore(add(p, 64), 2)     // nq
            mstore(add(p, 96), 2)     // nD
            p := add(p, 128)
            mstore(p, 1)              // index 1
            mstore(add(p, 32), 1)     // index 1 again
            p := add(p, 64)
            mstore(p, B)              // leaf B (honest)
            mstore(add(p, 32), 0xBAD) // leaf B' (forged, same index)
            p := add(p, 64)
            mstore(p, mload(add(stream, 32)))
            mstore(add(p, 32), mload(add(stream, 64)))
            mstore(add(p, 64), root)
        }
        vm.expectRevert(TerminalWeight.InconsistentDuplicateOpenings.selector);
        (bool dupOk,) = address(tw).staticcall(frame);
        dupOk;
    }

    // The honest twin of the test above: same index twice, SAME leaf - the
    // dedup keeps one node and the walk must still succeed.
    function test_v04_duplicate_index_same_leaf_passes() public {
        bytes32 A = bytes32(uint256(0xA));
        bytes32 B = bytes32(uint256(0xB));
        bytes32 C = bytes32(uint256(0xC));
        bytes32 D = bytes32(uint256(0xD));
        bytes32 AB = _keccak(A, B);
        bytes32 CD = _keccak(C, D);
        bytes32 root = _keccak(AB, CD);

        uint256 nq = 2;
        bytes memory frame = new bytes((5 + 2 * nq + 2) * 32);
        assembly {
            let p := add(frame, 32)
            mstore(p, 0x4D524F4F5453)
            mstore(add(p, 32), 2)
            mstore(add(p, 64), 2)
            mstore(add(p, 96), 2)
            p := add(p, 128)
            mstore(p, 1)
            mstore(add(p, 32), 1)
            p := add(p, 64)
            mstore(p, 0xB)
            mstore(add(p, 32), 0xB)
            p := add(p, 64)
            mstore(p, 0xA)
            mstore(add(p, 32), CD)
            mstore(add(p, 64), root)
        }
        (bool ok, bytes memory ret) = address(tw).staticcall(frame);
        if (!ok) {
            uint256 sel;
            assembly { sel := shr(224, mload(add(ret, 32))) }
            emit log_named_uint("revert selector", sel);
        }
        assertTrue(ok, "honest duplicate walk ok");
    }
}
