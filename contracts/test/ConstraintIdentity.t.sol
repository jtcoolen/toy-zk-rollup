// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {ConstraintIdentity} from "../src/verifier/ConstraintIdentity.sol";

/// Pins the constraint layer - the last layer of `verify_batch` - against the
/// prover's own evaluation. For every settlement instance the export carries the
/// flattened constraint DAG, every opened value the program consumes, the trusted
/// domain parameters, and the values the Rust verifier computed. The test reruns
/// selectors, the DAG fold, the chunk vanishings and the quotient recompose in
/// Solidity and requires each to match, then checks the identity
/// `fold * inv_vanishing == quotient` exactly as `verify_batch` does.
contract ConstraintIdentityTest is Test {
    using ConstraintIdentity for ConstraintIdentity.Program;

    string internal constant JSON = "test/vectors/constraint_identity_vectors.json";

    function test_selectors_match_the_library() public view {
        string memory j = vm.readFile(JSON);
        uint256[] memory zeta = _packExt(vm.parseJsonUintArray(j, ".zeta"));
        uint256 z = zeta[0];
        uint256 n = vm.parseJsonUintArray(j, ".degree_bits").length;
        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".instances[", vm.toString(i), "]");
            uint256 logSize = vm.parseJsonUint(j, string.concat(base, ".trace_domain.log_size"));
            uint256 invShift = vm.parseJsonUint(j, string.concat(base, ".trace_domain.inv_shift"));
            uint256 hInv = vm.parseJsonUint(j, string.concat(base, ".trace_domain.h_inv"));
            ConstraintIdentity.Selectors memory sels = ConstraintIdentity.selectors(z, invShift, logSize, hInv);
            assertEq(sels.isFirst, _packOne(j, string.concat(base, ".selectors_expected.is_first")), "is_first");
            assertEq(sels.isLast, _packOne(j, string.concat(base, ".selectors_expected.is_last")), "is_last");
            assertEq(sels.isTransition, _packOne(j, string.concat(base, ".selectors_expected.is_transition")), "is_transition");
            assertEq(sels.invVanishing, _packOne(j, string.concat(base, ".selectors_expected.inv_vanishing")), "inv_vanishing");
        }
    }

    function test_fold_times_inv_vanishing_equals_quotient() public {
        string memory j = vm.readFile(JSON);
        uint256 z = _packExt(vm.parseJsonUintArray(j, ".zeta"))[0];
        uint256 alpha = _packExt(vm.parseJsonUintArray(j, ".constraint_alpha"))[0];
        uint256 n = vm.parseJsonUintArray(j, ".degree_bits").length;
        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".instances[", vm.toString(i), "]");
            uint256 gas0 = gasleft();

            ConstraintIdentity.Program memory prog;
            prog.nodes = vm.parseJsonUintArray(j, string.concat(base, ".nodes"));
            prog.baseConsts = vm.parseJsonUintArray(j, string.concat(base, ".base_consts"));
            prog.extConsts = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".ext_consts")));
            prog.roots = vm.parseJsonUintArray(j, string.concat(base, ".roots"));

            ConstraintIdentity.Opened memory opened;
            opened.mainLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.main_local")));
            opened.mainNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.main_next")));
            opened.preLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.pre_local")));
            opened.preNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.pre_next")));
            opened.permLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_local")));
            opened.permNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_next")));
            opened.permChallenges = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_challenges")));
            opened.permValues = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_values")));
            opened.publicValues = vm.parseJsonUintArray(j, string.concat(base, ".opened.public_values"));
            opened.periodicValues = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.periodic_values")));

            uint256 logSize = vm.parseJsonUint(j, string.concat(base, ".trace_domain.log_size"));
            uint256 invShift = vm.parseJsonUint(j, string.concat(base, ".trace_domain.inv_shift"));
            uint256 hInv = vm.parseJsonUint(j, string.concat(base, ".trace_domain.h_inv"));
            ConstraintIdentity.Selectors memory sels = ConstraintIdentity.selectors(z, invShift, logSize, hInv);

            uint256 fold = prog.foldConstraints(opened, sels, alpha);
            assertEq(fold, _packOne(j, string.concat(base, ".expected_fold")), "fold");

            // Chunk vanishings and the trusted cross-domain inverses.
            uint256 k = vm.parseJsonUint(j, string.concat(base, ".num_chunks"));
            ConstraintIdentity.ChunkDomain[] memory domains =
                new ConstraintIdentity.ChunkDomain[](k);
            for (uint256 c; c < k; ++c) {
                string memory dpath = string.concat(base, ".chunk_domains[", vm.toString(c), "]");
                domains[c].logSize = vm.parseJsonUint(j, string.concat(dpath, ".log_size"));
                domains[c].shift = vm.parseJsonUint(j, string.concat(dpath, ".shift"));
                domains[c].invShift = vm.parseJsonUint(j, string.concat(dpath, ".inv_shift"));
            }
            uint256[] memory zstars = ConstraintIdentity.chunkVanishings(z, domains);
            uint256[] memory zstarsExpected = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".zstars_expected")));
            for (uint256 c; c < k; ++c) {
                assertEq(zstars[c], zstarsExpected[c], "zstar");
            }

            uint256[] memory invD = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".inv_d")));
            uint256[] memory chunks = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".quotient_chunks")));
            uint256 quotient = ConstraintIdentity.recomposeQuotient(chunks, domains, invD, z);
            assertEq(quotient, _packOne(j, string.concat(base, ".expected_quotient")), "quotient");

            // The identity itself.
            assertEq(KoalaBearExt4.mul(fold, sels.invVanishing), quotient, "constraint identity");
            emit gas_snapshot(i, gas0 - gasleft());
        }
    }

    event gas_snapshot(uint256 instance, uint256 gas);

    /// Pack a flat canonical u32 array (4 words per element) into packed ext4.
    function _packExt(uint256[] memory flat) internal pure returns (uint256[] memory out) {
        require(flat.length % 4 == 0, "flat ext array");
        out = new uint256[](flat.length / 4);
        for (uint256 i; i < out.length; ++i) {
            uint256[4] memory c = [flat[4 * i], flat[4 * i + 1], flat[4 * i + 2], flat[4 * i + 3]];
            out[i] = KoalaBearExt4.pack(c);
        }
    }

    function _packOne(string memory j, string memory path) internal pure returns (uint256) {
        return _packExt(vm.parseJsonUintArray(j, path))[0];
    }
}
