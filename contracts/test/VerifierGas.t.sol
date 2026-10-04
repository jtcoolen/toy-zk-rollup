// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {BatchTranscript} from "../src/verifier/BatchTranscript.sol";
import {ConstraintIdentity} from "../src/verifier/ConstraintIdentity.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Gas benchmark for the settlement verifier, measured honestly: every input is
/// parsed BEFORE the measured region, so the numbers are the verifier's own work,
/// not forge-std's JSON reader. The same parse runs in a control test; the pin
/// tests' totals minus these parse costs is what a settlement transaction pays.
///
/// Bounds are asserted so a regression that doubles a layer fails CI, not just a
/// benchmark run.
contract VerifierGasTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/batch_stark_vectors.bin";
    string internal constant JSON = "test/vectors/batch_stark_vectors.json";
    string internal constant CIR = "test/vectors/constraint_identity_vectors.json";

    uint256 internal constant SEED_WORDS_END = 348;
    uint256 internal constant DEGREE_WORDS_END = 444;
    uint256 internal constant PV_WORDS_END = 456;
    uint256 internal constant PRE_DIGEST_END = 488;

    event layer(string name, uint256 gas);

    /// The batch transcript walk with everything pre-parsed: this is the settlement
    /// transaction's own cost for the Fiat-Shamir layer.
    function test_gas_batch_transcript_walk() public {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        string memory j = vm.readFile(JSON);

        bytes memory seedWords = _slice(b.raw, b.constOff, SEED_WORDS_END);
        bytes memory degreeWords =
            _slice(b.raw, b.constOff + SEED_WORDS_END, DEGREE_WORDS_END - SEED_WORDS_END);
        bytes memory pvWords =
            _slice(b.raw, b.constOff + DEGREE_WORDS_END, PV_WORDS_END - DEGREE_WORDS_END);
        bytes32 preDigest = bytes32(_slice(b.raw, b.constOff + PV_WORDS_END, 32));
        bytes32 mainDigest = bytes32(_slice(b.raw, b.varOff, 32));
        bytes32 permDigest = bytes32(_slice(b.raw, b.varOff + 32, 32));
        bytes32 quotDigest = bytes32(_slice(b.raw, b.varOff + 160, 32));
        bytes32 randDigest = bytes32(_slice(b.raw, b.varOff + 192, 32));
        uint256 numInstances = vm.parseJsonUint(j, ".num_instances");
        uint256[] memory terminals = new uint256[](numInstances);
        for (uint256 i; i < numInstances; ++i) {
            terminals[i] =
                _parseExt(j, string.concat(".instances[", vm.toString(i), "].lookup_terminal"));
        }
        uint256 lookupPow = vm.parseJsonUint(j, ".pow_witnesses.lookup");
        uint256 oodPow = vm.parseJsonUint(j, ".pow_witnesses.ood");

        uint256 g0 = gasleft();
        BatchTranscript.State memory s = BatchTranscript.begin(seedWords, degreeWords);
        BatchTranscript.mainPhase(s, mainDigest, pvWords);
        BatchTranscript.preprocessedPhase(s, preDigest);
        (uint256 lookupAlpha, uint256 beta) = BatchTranscript.lookupPhase(s, 0, lookupPow);
        uint256 constraintAlpha = BatchTranscript.permutationPhase(s, permDigest, terminals);
        BatchTranscript.quotientPhase(s, quotDigest, randDigest);
        uint256 zeta = BatchTranscript.oodPhase(s, 0, oodPow);
        uint256 walkGas = g0 - gasleft();
        emit layer("batch_transcript_walk", walkGas);
        // Sanity: the walk still produces the pinned challenges.
        assertEq(zeta, _parseExt(j, ".zeta"));
        assertTrue(lookupAlpha != 0 && beta != 0 && constraintAlpha != 0);
        // Bound: the walk is ~18M today; fail CI past 25M.
        assertLt(walkGas, 25_000_000, "batch transcript walk regressed");
    }

    /// One instance's pre-parsed constraint-layer inputs.
    struct Inst {
        ConstraintIdentity.Program prog;
        ConstraintIdentity.Opened opened;
        uint256 logSize;
        uint256 invShift;
        uint256 hInv;
        ConstraintIdentity.ChunkDomain[] domains;
        uint256[] invD;
        uint256[] chunks;
    }

    /// The constraint layer per instance: selectors, fold and the quotient
    /// recompose, each measured separately with inputs pre-parsed.
    function test_gas_constraint_layer() public {
        string memory j = vm.readFile(CIR);
        uint256 zeta = _parseExt(j, ".zeta");
        uint256 alpha = _parseExt(j, ".constraint_alpha");
        uint256 n = vm.parseJsonUintArray(j, ".degree_bits").length;
        Inst[] memory insts = new Inst[](n);
        for (uint256 i; i < n; ++i) {
            insts[i] = _parseInst(j, i);
        }
        uint256 totalSelectors;
        uint256 totalFold;
        uint256 totalQuot;
        for (uint256 i; i < n; ++i) {
            (uint256 gs, uint256 gf, uint256 gq) = _measure(insts[i], zeta, alpha, i);
            totalSelectors += gs;
            totalFold += gf;
            totalQuot += gq;
        }
        emit layer("constraint_layer_total", totalSelectors + totalFold + totalQuot);
        // Bound: ~40M today; fail CI past 55M.
        assertLt(totalSelectors + totalFold + totalQuot, 55_000_000, "constraint layer regressed");
    }

    function _parseInst(string memory j, uint256 i) private pure returns (Inst memory m) {
        string memory base = string.concat(".instances[", vm.toString(i), "]");
        m.prog.nodes = vm.parseJsonUintArray(j, string.concat(base, ".nodes"));
        m.prog.baseConsts = vm.parseJsonUintArray(j, string.concat(base, ".base_consts"));
        m.prog.extConsts = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".ext_consts")));
        m.prog.roots = vm.parseJsonUintArray(j, string.concat(base, ".roots"));
        m.opened.mainLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.main_local")));
        m.opened.mainNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.main_next")));
        m.opened.preLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.pre_local")));
        m.opened.preNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.pre_next")));
        m.opened.permLocal = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_local")));
        m.opened.permNext = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_next")));
        m.opened.permChallenges =
            _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_challenges")));
        m.opened.permValues = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.perm_values")));
        m.opened.publicValues = vm.parseJsonUintArray(j, string.concat(base, ".opened.public_values"));
        m.opened.periodicValues =
            _packExt(vm.parseJsonUintArray(j, string.concat(base, ".opened.periodic_values")));
        m.logSize = vm.parseJsonUint(j, string.concat(base, ".trace_domain.log_size"));
        m.invShift = vm.parseJsonUint(j, string.concat(base, ".trace_domain.inv_shift"));
        m.hInv = vm.parseJsonUint(j, string.concat(base, ".trace_domain.h_inv"));
        uint256 k = vm.parseJsonUint(j, string.concat(base, ".num_chunks"));
        m.domains = new ConstraintIdentity.ChunkDomain[](k);
        for (uint256 c; c < k; ++c) {
            string memory dpath = string.concat(base, ".chunk_domains[", vm.toString(c), "]");
            m.domains[c].logSize = vm.parseJsonUint(j, string.concat(dpath, ".log_size"));
            m.domains[c].shift = vm.parseJsonUint(j, string.concat(dpath, ".shift"));
            m.domains[c].invShift = vm.parseJsonUint(j, string.concat(dpath, ".inv_shift"));
        }
        m.invD = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".inv_d")));
        m.chunks = _packExt(vm.parseJsonUintArray(j, string.concat(base, ".quotient_chunks")));
    }

    /// One instance's three measured sections; asserts the identity inside.
    function _measure(Inst memory m, uint256 zeta, uint256 alpha, uint256 i)
        private returns (uint256 gs, uint256 gf, uint256 gq)
    {
        uint256 g0 = gasleft();
        ConstraintIdentity.Selectors memory sels =
            ConstraintIdentity.selectors(zeta, m.invShift, m.logSize, m.hInv);
        uint256 g1 = gasleft();
        uint256 fold = ConstraintIdentity.foldConstraints(m.prog, m.opened, sels, alpha);
        uint256 g2 = gasleft();
        uint256 quotient = ConstraintIdentity.recomposeQuotient(m.chunks, m.domains, m.invD, zeta);
        uint256 g3 = gasleft();
        assertEq(KoalaBearExt4.mul(fold, sels.invVanishing), quotient, "identity");
        gs = g0 - g1;
        gf = g1 - g2;
        gq = g2 - g3;
        emit layer(string.concat("instance_", vm.toString(i), "_selectors"), gs);
        emit layer(string.concat("instance_", vm.toString(i), "_fold"), gf);
        emit layer(string.concat("instance_", vm.toString(i), "_quotient"), gq);
    }
    function _slice(bytes memory src, uint256 start, uint256 len)
        private pure returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = src[start + i];
        }
    }

    function _parseExt(string memory j, string memory path) private pure returns (uint256) {
        uint256[4] memory coeffs;
        for (uint256 i; i < 4; ++i) {
            coeffs[i] = vm.parseJsonUint(j, string.concat(path, "[", vm.toString(i), "]"));
        }
        return KoalaBearExt4.pack(coeffs);
    }

    function _packExt(uint256[] memory flat) private pure returns (uint256[] memory out) {
        require(flat.length % 4 == 0, "flat ext array");
        out = new uint256[](flat.length / 4);
        for (uint256 i; i < out.length; ++i) {
            uint256[4] memory c = [flat[4 * i], flat[4 * i + 1], flat[4 * i + 2], flat[4 * i + 3]];
            out[i] = KoalaBearExt4.pack(c);
        }
    }
}
