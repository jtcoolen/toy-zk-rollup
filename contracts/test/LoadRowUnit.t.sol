// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {WhirVerifierCore} from "../src/verifier/WhirVerifierCore.sol";

contract LoadRowUnit is Test {
    // Drive the real _loadRowFused through the library by replicating its
    // visibility: it is private, so test through a thin shim compiled into
    // the library? Not possible. Instead copy both variants here.

    function generic(
        uint256[] memory elems,
        uint256[] memory flat,
        uint256 rowsCd,
        uint256 base,
        uint256 rowLimbs,
        bool rowsAreBase
    ) public pure returns (bytes32 leaf) {
        bytes4 selTag = 0x12345678;
        assembly ("memory-safe") {
            let dst := add(mload(0x40), 0x20)
            let ep := add(elems, 0x20)
            let p := 0x7f000001
            let rr := 0x01fffffe
            function swap32(x) -> y {
                y := or(
                    or(and(shl(24, x), 0xff000000), and(shl(8, x), 0xff0000)),
                    or(and(shr(8, x), 0xff00), shr(24, x))
                )
            }
            let src := rowsCd
            switch rowsCd
            case 0 { src := add(add(flat, 0x20), mul(base, 0x20)) }
            default { src := add(rowsCd, mul(base, 4)) }
            let m32 := 0xffffffff
            for { let j := 0 } lt(j, rowLimbs) { j := add(j, 1) } {
                let v := 0
                switch rowsCd
                case 0 { v := mload(add(src, shl(5, j))) }
                default { v := swap32(shr(224, calldataload(add(src, shl(2, j))))) }
                if iszero(lt(v, p)) { mstore(0, selTag) mstore(4, v) revert(0, 36) }
                mstore(add(dst, shl(2, j)), shl(224, swap32(mod(mul(v, rr), p))))
                switch rowsAreBase
                case 1 { mstore(add(ep, shl(5, j)), shl(224, v)) }
                default {
                    let sh := sub(224, shl(5, and(j, 3)))
                    let epw := add(ep, shl(5, shr(2, j)))
                    mstore(epw, or(and(mload(epw), not(shl(sh, m32))), shl(sh, v)))
                }
            }
            leaf := keccak256(dst, mul(rowLimbs, 4))
        }
    }

    function hot(
        uint256[] memory elems,
        uint256 rowsCd,
        uint256 base,
        uint256 rowLimbs
    ) public pure returns (bytes32 leaf) {
        bytes4 selTag = 0x12345678;
        assembly ("memory-safe") {
            let dst := add(mload(0x40), 0x20)
            let ep := add(elems, 0x20)
            let p := 0x7f000001
            let rr := 0x01fffffe
            function swap32(x) -> y {
                y := or(
                    or(and(shl(24, x), 0xff000000), and(shl(8, x), 0xff0000)),
                    or(and(shr(8, x), 0xff00), shr(24, x))
                )
            }
            let hs := add(rowsCd, mul(base, 4))
            for { let e := 0 } lt(e, shr(2, rowLimbs)) { e := add(e, 1) } {
                let c0 := swap32(shr(224, calldataload(add(hs, shl(4, e)))))
                let c1 := swap32(shr(224, calldataload(add(hs, add(shl(4, e), 4)))))
                let c2 := swap32(shr(224, calldataload(add(hs, add(shl(4, e), 8)))))
                let c3 := swap32(shr(224, calldataload(add(hs, add(shl(4, e), 12)))))
                if iszero(lt(c0, p)) { mstore(0, selTag) mstore(4, c0) revert(0, 36) }
                if iszero(lt(c1, p)) { mstore(0, selTag) mstore(4, c1) revert(0, 36) }
                if iszero(lt(c2, p)) { mstore(0, selTag) mstore(4, c2) revert(0, 36) }
                if iszero(lt(c3, p)) { mstore(0, selTag) mstore(4, c3) revert(0, 36) }
                mstore(add(dst, shl(4, e)), shl(224, swap32(mod(mul(c0, rr), p))))
                mstore(add(dst, add(shl(4, e), 4)), shl(224, swap32(mod(mul(c1, rr), p))))
                mstore(add(dst, add(shl(4, e), 8)), shl(224, swap32(mod(mul(c2, rr), p))))
                mstore(add(dst, add(shl(4, e), 12)), shl(224, swap32(mod(mul(c3, rr), p))))
                mstore(add(ep, shl(5, e)),
                    or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))))
            }
            leaf := keccak256(dst, mul(rowLimbs, 4))
        }
    }

    function test_hot_matches_generic() public view {
        // Build 5 rows of 64 ext limbs (256 B each) in calldata via external
        // call args.
        bytes memory rows = new bytes(5 * 256);
        for (uint256 i; i < 5 * 64; ++i) {
            uint256 v = 1 + (i * 2654435761) % 2130706432;
            // Wire limbs are little-endian (the loader byte-swaps).
            rows[i * 4] = bytes1(uint8(v));
            rows[i * 4 + 1] = bytes1(uint8(v >> 8));
            rows[i * 4 + 2] = bytes1(uint8(v >> 16));
            rows[i * 4 + 3] = bytes1(uint8(v >> 24));
        }
        this.compare(rows);
    }

    function compare(bytes calldata rows) public pure {
        for (uint256 r; r < 5; ++r) {
            uint256[] memory e1 = new uint256[](16);
            uint256[] memory e2 = new uint256[](16);
            uint256[] memory empty = new uint256[](0);
            uint256 cd1;
            uint256 cd2;
            assembly {
                cd1 := add(rows.offset, mul(r, 256))
                cd2 := add(rows.offset, mul(r, 256))
            }
            bytes32 l1 = generic(e1, empty, cd1, 0, 64, false);
            bytes32 l2 = hot(e2, cd2, 0, 64);
            require(l1 == l2, "leaf mismatch");
            for (uint256 k; k < 16; ++k) {
                require(e1[k] == e2[k], "elems mismatch");
            }
        }
    }
}
