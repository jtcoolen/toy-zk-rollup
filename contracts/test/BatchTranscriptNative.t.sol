// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {BatchTranscript} from "../src/verifier/BatchTranscript.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Drives the PRODUCTION batch transcript (contracts/src/verifier/BatchTranscript.sol)
/// with the payloads of the prover's semantic blob and checks the four challenges it
/// draws against the exported values.
///
/// The difference from BatchTranscript.t.sol matters: that test walks the recorded event
/// schedule, so it pins the sponge. This test runs the hand-written phase sequence a
/// settlement contract would actually execute - seed, degree bits, commitments, public
/// values, grinds, terminals - and lands on the same alpha, beta, constraint alpha and
/// zeta. If the production sequence were wrong in any absorb, the draws here diverge even
/// though the walk passes.
///
/// Payload geometry (fixed by the batch layer's structure, asserted below):
///
///     constant payload: [0, 348) seed words | [348, 444) degree-bit words
///                       | [444, 456) public values | [456, 488) preprocessed digest
///     variable payload: [0, 32) main | [32, 64) permutation | [64, 160) 6 terminals
///                       | [160, 192) quotient | [192, 224) random
contract BatchTranscriptNativeTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/batch_stark_vectors.bin";
    string internal constant JSON = "test/vectors/batch_stark_vectors.json";

    uint256 internal constant SEED_WORDS_END = 348;
    uint256 internal constant DEGREE_WORDS_END = 444;
    uint256 internal constant PV_WORDS_END = 456;
    uint256 internal constant PRE_DIGEST_END = 488;

    function test_native_phase_sequence_lands_on_the_exported_challenges() public view {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        string memory j = vm.readFile(JSON);

        // The trusted-setup prefix: seed words then degree-bit words, both fixed by the
        // circuit shape (the degree bits are circuit constants, not proof bytes).
        bytes memory seedWords = _slice(b.raw, b.constOff, SEED_WORDS_END);
        bytes memory degreeWords =
            _slice(b.raw, b.constOff + SEED_WORDS_END, DEGREE_WORDS_END - SEED_WORDS_END);
        bytes memory pvWords =
            _slice(b.raw, b.constOff + DEGREE_WORDS_END, PV_WORDS_END - DEGREE_WORDS_END);
        bytes32 preDigest = bytes32(_slice(b.raw, b.constOff + PV_WORDS_END, 32));

        // Proof data.
        bytes32 mainDigest = bytes32(_slice(b.raw, b.varOff, 32));
        bytes32 permDigest = bytes32(_slice(b.raw, b.varOff + 32, 32));
        bytes32 quotDigest = bytes32(_slice(b.raw, b.varOff + 160, 32));
        // D-092 batch 89: settlement blinding is off - no randomization round,
        // so the wire carries no rand digest. hasRand=false ignores the value.
        bytes32 randDigest = bytes32(0);

        // The six LogUp terminals, canonical packed, from the JSON (the proof codec's
        // job in production; the blob's copies are the same values in wire form).
        uint256 numInstances = vm.parseJsonUint(j, ".num_instances");
        uint256[] memory terminals = new uint256[](numInstances);
        for (uint256 i; i < numInstances; ++i) {
            terminals[i] =
                parseExt(j, string.concat(".instances[", vm.toString(i), "].lookup_terminal"));
        }

        BatchTranscript.State memory s =
            BatchTranscript.begin(seedWords, degreeWords);
        BatchTranscript.mainPhase(s, mainDigest, pvWords);
        BatchTranscript.preprocessedPhase(s, preDigest);
        (uint256 lookupAlpha, uint256 beta) =
            BatchTranscript.lookupPhase(s, 0, vm.parseJsonUint(j, ".pow_witnesses.lookup"));
        uint256 constraintAlpha =
            BatchTranscript.permutationPhase(s, permDigest, terminals);
        BatchTranscript.quotientPhase(s, quotDigest, randDigest, false);
        uint256 zeta = BatchTranscript.oodPhase(s, 0, vm.parseJsonUint(j, ".pow_witnesses.ood"));

        assertEq(lookupAlpha, parseExt(j, ".lookup_alpha"), "lookup alpha");
        assertEq(beta, parseExt(j, ".beta"), "beta");
        assertEq(constraintAlpha, parseExt(j, ".constraint_alpha"), "constraint alpha");
        assertEq(zeta, parseExt(j, ".zeta"), "zeta");

        // The computed bus pair for bus 0 (the only bus in this shape) equals the
        // exported pair - the same arithmetic D-063 pins in the walk test, now through
        // the production helper.
        uint256 wTuples = vm.parseJsonUint(j, ".bus_layout.max_message_width");
        (uint256 prefix, uint256 combiner) = BatchTranscript.lookupPair(lookupAlpha, beta, 0, wTuples);
        assertEq(prefix, parseExt(j, ".instances[0].lookup_challenges[0]"), "bus 0 prefix");
        assertEq(combiner, parseExt(j, ".instances[0].lookup_challenges[1]"), "bus 0 combiner");
    }

    /// A zero-difficulty grind carrying a nonzero witness must revert: at bits = 0 the
    /// verifier absorbs the witness without sampling against it, so a nonzero value
    /// names a search that never happened (NonCanonicalPowWitness in p3).
    function test_noncanonical_pow_witness_reverts() public {
        BatchTranscriptHarness h = new BatchTranscriptHarness();
        vm.expectRevert(BatchTranscript.NonCanonicalPowWitness.selector);
        h.grindWith(0, 7);
    }

    function _slice(bytes memory src, uint256 start, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = src[start + i];
        }
    }

    function parseExt(string memory j, string memory path) private pure returns (uint256) {
        uint256[4] memory coeffs;
        for (uint256 i; i < 4; ++i) {
            coeffs[i] = vm.parseJsonUint(j, string.concat(path, "[", vm.toString(i), "]"));
        }
        return KoalaBearExt4.pack(coeffs);
    }
}

/// External frame so expectRevert sees the revert at a lower call depth.
contract BatchTranscriptHarness {
    function grindWith(uint256 bits, uint256 witness) external pure {
        BatchTranscript.State memory s;
        BatchTranscript.oodPhase(s, bits, witness);
    }
}

