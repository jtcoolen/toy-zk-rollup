// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {StirOpenings} from "../src/verifier/StirOpenings.sol";

/// Microbench: what does one 16-element hypercube fold actually cost?
using KeccakChallenger for KeccakChallenger.State;

contract FoldRowBenchTest is Test {
    function test_bench_absorb() public {
        KeccakChallenger.State memory st;
        // warm the buffer big
        bytes memory blob = new bytes(65536);
        st.observeBytes(blob);
        uint256 g0 = gasleft();
        uint256 packed = (0x12345678 << 224) | (0x9abcdef0 << 192) | (0x11112222 << 160) | (0x33334444 << 128);
        for (uint256 k; k < 1000; ++k) {
            st.observeExt4Mont(packed);
        }
        emit log_named_uint("gas per observeExt4Mont", (g0 - gasleft()) / 1000);

        // bulk: 10688 words in one call
        uint256 g1 = gasleft();
        st.observeBasesLE(blob, 0, 10688);
        emit log_named_uint("gas per word observeBasesLE (10688)", (g1 - gasleft()) / 10688);

        // bulk split into 8 calls of 1336 (per-claim framing)
        uint256 g2 = gasleft();
        for (uint256 c; c < 8; ++c) {
            st.observeBasesLE(blob, c * 1336 * 4, 1336);
        }
        emit log_named_uint("gas per word observeBasesLE (8x1336)", (g2 - gasleft()) / 10688);
    }

    function test_single_fold64() public {
        uint256[] memory row = new uint256[](64);
        for (uint256 i; i < 64; ++i) {
            row[i] = ((i + 1) << 224) | ((i + 2) << 192) | ((i + 3) << 160) | ((i + 4) << 128);
        }
        uint256[] memory r = new uint256[](6);
        for (uint256 i; i < 6; ++i) {
            r[i] = ((i + 5) << 224) | ((i + 6) << 192) | ((i + 7) << 160) | ((i + 8) << 128);
        }
        emit log_named_uint("fold once", StirOpenings.foldRow(row, r));
    }

    function test_bench_foldrow() public {
        uint256[] memory row = new uint256[](16);
        for (uint256 i; i < 16; ++i) {
            row[i] = ((i + 1) << 224) | ((i + 2) << 192) | ((i + 3) << 160) | ((i + 4) << 128);
        }
        uint256[] memory r = new uint256[](4);
        for (uint256 i; i < 4; ++i) {
            r[i] = ((i + 5) << 224) | ((i + 6) << 192) | ((i + 7) << 160) | ((i + 8) << 128);
        }
        uint256 g0 = gasleft();
        uint256 acc;
        for (uint256 k; k < 1000; ++k) {
            acc += StirOpenings.foldRow(row, r);
        }
        uint256 per = (g0 - gasleft()) / 1000;
        emit log_named_uint("gas per foldRow (16 elems, 15 folds)", per);
        emit log_named_uint("gas per _fold_once", per / 15);
        emit log_named_uint("sink", acc);
    }

    function test_bench_foldrow64() public {
        uint256[] memory row = new uint256[](64);
        for (uint256 i; i < 64; ++i) {
            row[i] = ((i + 1) << 224) | ((i + 2) << 192) | ((i + 3) << 160) | ((i + 4) << 128);
        }
        uint256[] memory r = new uint256[](6);
        for (uint256 i; i < 6; ++i) {
            r[i] = ((i + 5) << 224) | ((i + 6) << 192) | ((i + 7) << 160) | ((i + 8) << 128);
        }
        uint256 g0 = gasleft();
        uint256 acc;
        unchecked {
            for (uint256 k; k < 1000; ++k) {
                acc += StirOpenings.foldRow(row, r);
            }
        }
        uint256 per = (g0 - gasleft()) / 1000;
        emit log_named_uint("gas per foldRow (64 elems, 6 dims, 63 folds)", per);
        emit log_named_uint("gas per _fold_once", per / 63);
        emit log_named_uint("sink", acc);
    }
}
