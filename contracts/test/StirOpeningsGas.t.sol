// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/Test.sol";
import {StarkMerkle} from "../src/verifier/StarkMerkle.sol";
import {StirOpenings} from "../src/verifier/StirOpenings.sol";

/// Gas for one STIR opening, measured rather than estimated.
///
/// D-039 splits a chunk verification across transactions, which only works if
/// a single query is bounded by a constant. The per-query work here is depth
/// Merkle compressions plus one row hash plus a 16-element fold, so it should
/// be flat in the number of queries - but "should" is what the amortised
/// frontier walk was supposed to make true too, and the whole point of the
/// per-query model is that it does not depend on what the previous query did.
/// This test is the number that goes into the transaction budget.
contract StirOpeningsGasTest is Test {
    using stdJson for string;

    string internal constant VECTOR = "test/vectors/stir_vectors.json";

    /// Not `view`: `emit log_named_uint` calls the logger address. The gas
    /// measurement brackets only `openAndFold`, so the logger is outside it.
    function test_one_opening_gas() public {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256[] memory limbs = new uint256[](64);
        for (uint256 i; i < 64; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(base, ".row_ext[", vm.toString(i / 4), "]"));
            limbs[i] = coeffs[i % 4];
        }
        uint256[] memory row = new uint256[](16);
        for (uint256 i; i < 16; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(base, ".row_ext[", vm.toString(i), "]"));
            row[i] = StirOpenings.ext4([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
        }
        bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
        uint256[] memory randomness = new uint256[](4);
        for (uint256 i; i < 4; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(ck, ".randomness[", vm.toString(i), "]"));
            randomness[i] = StirOpenings.ext4([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
        }

        // Resolve every cheatcode BEFORE the bracket. Argument expressions are
        // evaluated inside it, and a JSON read over a 56 KB file costs more than
        // the opening itself - the first version of this test reported 76k for
        // that reason alone.
        bytes32 root = json.readBytes32(string.concat(ck, ".root_hex"));
        uint256 index = json.readUint(string.concat(base, ".index"));

        uint256 before = gasleft();
        StirOpenings.openAndFold(root, index, 6, limbs, row, siblings, randomness);
        uint256 used = before - gasleft();
        emit log_named_uint("gas per STIR opening (depth 6, 16 ext elements)", used);
        // A loose ceiling that only fires on an order-of-magnitude regression.
        // The point is to notice if a change makes openings scale with the tree
        // rather than the depth, not to win a gas competition.
        assertLt(used, 80_000, "one opening blew the per-query budget");
    }

    /// Where the per-opening gas actually goes, so the budget is written against
    /// a known split rather than a total. The three parts are independent and
    /// each has a different optimisation: the leaf is one hash over a wide row,
    /// the path is `depth` hashes over 64 bytes, the fold is extension arithmetic
    /// with no hashing at all.
    function test_opening_gas_splits_as_expected() public {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256[] memory limbs = new uint256[](64);
        for (uint256 i; i < 64; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(base, ".row_ext[", vm.toString(i / 4), "]"));
            limbs[i] = coeffs[i % 4];
        }
        uint256[] memory row = new uint256[](16);
        for (uint256 i; i < 16; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(base, ".row_ext[", vm.toString(i), "]"));
            row[i] = StirOpenings.ext4([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
        }
        bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
        uint256[] memory randomness = new uint256[](4);
        for (uint256 i; i < 4; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(ck, ".randomness[", vm.toString(i), "]"));
            randomness[i] = StirOpenings.ext4([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
        }
        bytes32 leaf = StirOpenings.extLeaf(limbs);

        uint256 a = gasleft();
        StirOpenings.extLeaf(limbs);
        uint256 leafGas = a - gasleft();

        uint256 b = gasleft();
        StarkMerkle.computeRoot(leaf, 9, siblings);
        uint256 pathGas = b - gasleft();

        uint256 c = gasleft();
        StirOpenings.foldRow(row, randomness);
        uint256 foldGas = c - gasleft();

        emit log_named_uint("  leaf (1 hash over 256 bytes + 64 limb conversions)", leafGas);
        emit log_named_uint("  path (6 hashes over 64 bytes)", pathGas);
        emit log_named_uint("  fold (15 extension folds, no hashing)", foldGas);

        // The measured split at depth 6 with a 16-element row: leaf ~22k, fold
        // ~17k, path ~2.6k. Two conclusions, both opposite to what seemed
        // obvious when this layer was designed:
        //
        // - The Merkle PATH is almost free. Porting p3 amortised frontier walk to
        //   share sibling hashes between queries would save a few thousand gas per
        //   query and cost a large, hard-to-audit state machine. Not worth it, and
        //   now that is a measurement rather than a hunch.
        // - Hashing the wide row costs about as much as folding it. If openings
        //   ever need to get cheaper, the target is the leaf encoding and the
        //   extension arithmetic, not the tree.
        assertGt(leafGas, pathGas, "leaf should cost more than a 6-level path");
        assertGt(foldGas, pathGas, "fold should cost more than a 6-level path");
        assertLt(pathGas, leafGas / 4, "path should stay a small share of an opening");
    }
}
