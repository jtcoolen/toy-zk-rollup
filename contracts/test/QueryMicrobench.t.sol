// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";

/// Microbench: exact copy of _loadRowFused Yul + evaluate_hypercube, looped.
contract LoadRowTarget {
    /// Copy of WhirVerifierCore._loadRowFused (v8, fused leaf+elems).
    function loadRowFused(
        uint256[] memory elems,
        uint256[] memory flat,
        uint256 rowsCd,
        uint256 base,
        uint256 rowLimbs,
        uint256 rowElems,
        bool rowsAreBase,
        uint256 mode
    ) public pure returns (bytes32 leaf) {
        rowElems;
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
                if and(mode, 1) {
                    mstore(add(dst, shl(2, j)), shl(224, swap32(mod(mul(v, rr), p))))
                }
                if and(mode, 2) {
                    switch rowsAreBase
                    case 1 { mstore(add(ep, shl(5, j)), shl(224, v)) }
                    default {
                        let sh := sub(224, shl(5, and(j, 3)))
                        let epw := add(ep, shl(5, shr(2, j)))
                        mstore(epw, or(and(mload(epw), not(shl(sh, m32))), shl(sh, v)))
                    }
                }
            }
            if and(mode, 4) { leaf := keccak256(dst, mul(rowLimbs, 4)) }
        }
    }

    /// Specialized: calldata source, extension rows. Per-element loop.
    function loadRowSpec(
        uint256[] memory elems,
        uint256 src,
        uint256 rowElems
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
            for { let e := 0 } lt(e, rowElems) { e := add(e, 1) } {
                let c0 := swap32(shr(224, calldataload(add(src, shl(4, e)))))
                let c1 := swap32(shr(224, calldataload(add(src, add(shl(4, e), 4)))))
                let c2 := swap32(shr(224, calldataload(add(src, add(shl(4, e), 8)))))
                let c3 := swap32(shr(224, calldataload(add(src, add(shl(4, e), 12)))))
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
            leaf := keccak256(dst, mul(shl(2, rowElems), 4))
        }
    }
}


contract QueryMicrobenchTest is Test {
    LoadRowTarget target;

    function setUp() public {
        target = new LoadRowTarget();
    }

    function test_microbench() public {
        // 64 limbs per row, extension rows (4 limbs per element, 16 elems).
        bytes memory rows = new bytes(64 * 4 * 20);
        for (uint256 i; i < 64 * 20; ++i) {
            // canonical-ish values, BE words
            uint256 v = 1234567 + i;
            rows[i * 4] = bytes1(uint8(v >> 24));
            rows[i * 4 + 1] = bytes1(uint8(v >> 16));
            rows[i * 4 + 2] = bytes1(uint8(v >> 8));
            rows[i * 4 + 3] = bytes1(uint8(v));
        }
        uint256[] memory elems = new uint256[](16);
        uint256[] memory flat = new uint256[](0);
        uint256 g0 = gasleft();
        for (uint256 i; i < 100; ++i) {
            target.loadRowFused(elems, flat, 0, i * 64, 64, 16, false, 7);
        }
        uint256 memGas = (g0 - gasleft()) / 100;
        emit log_named_uint("loadRowFused memory-path gas/query", memGas);

        // calldata path: call through external so calldataload is live.
        g0 = gasleft();
        for (uint256 i; i < 100; ++i) {
            this.loadFromCalldata(rows, elems, i % 20);
        }
        uint256 cdGas = (g0 - gasleft()) / 100;
        emit log_named_uint("loadRowFused calldata-path gas/query (incl call)", cdGas);

        // fold: evaluate_hypercube on 16 elems, point of 4.
        uint256[] memory point = new uint256[](4);
        point[0] = 0x12345678; point[1] = 0x9abcdef0; point[2] = 2; point[3] = 3;
        g0 = gasleft();
        for (uint256 i; i < 100; ++i) {
            KoalaBearExt4.evaluate_hypercube(elems, point);
        }
        emit log_named_uint("evaluate_hypercube gas/query", (g0 - gasleft()) / 100);

        // Bisect on the calldata path (the real one): mode bits.
        uint256[6] memory modes = [uint256(0), 1, 2, 4, 3, 7];
        string[6] memory names = ["mode0 loop-only", "mode1 +mod/leaf", "mode2 +elems", "mode4 +keccak", "mode3 mod+elems", "mode7 all"];
        for (uint256 m; m < 6; ++m) {
            g0 = gasleft();
            for (uint256 i; i < 100; ++i) {
                this.loadFromCalldataM(rows, elems, i % 20, modes[m]);
            }
            emit log_named_uint(names[m], (g0 - gasleft()) / 100);
        }

        // Specialized kernel through external call (calldata live).
        g0 = gasleft();
        for (uint256 i; i < 100; ++i) {
            this.loadSpec(rows, elems, i % 20);
        }
        emit log_named_uint("loadRowSpec (incl call)", (g0 - gasleft()) / 100);
    }

    function loadFromCalldata(bytes calldata rows, uint256[] memory elems, uint256 row)
        public
        view
        returns (bytes32)
    {
        uint256 flat0;
        assembly { flat0 := add(rows.offset, rows.offset) }
        // rows data starts at rows.offset; row r starts at + r*64*4
        return target.loadRowFused(elems, new uint256[](0), flat0 + row * 256, 0, 64, 16, false, 7);
    }

    function loadSpec(bytes calldata rows, uint256[] memory elems, uint256 row)
        public
        view
        returns (bytes32)
    {
        uint256 src;
        assembly { src := add(rows.offset, mul(row, 256)) }
        return target.loadRowSpec(elems, src, 16);
    }

    function loadFromCalldataM(bytes calldata rows, uint256[] memory elems, uint256 row, uint256 mode)
        public
        view
        returns (bytes32)
    {
        uint256 flat0;
        assembly { flat0 := add(rows.offset, rows.offset) }
        return target.loadRowFused(elems, new uint256[](0), flat0 + row * 256, 0, 64, 16, false, mode);
    }
}
