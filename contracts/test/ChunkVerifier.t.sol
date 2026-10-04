// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {ChunkVerifier} from "../src/verifier/ChunkVerifier.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Pins the multi-transaction carry: the chunked walk (one phase per call, the
/// sponge serialized and deserialized at every boundary) must land on EXACTLY the
/// same challenges as the single-shot production walk pinned by
/// BatchTranscriptNative.t.sol. If the carry dropped or reordered any sponge state
/// - absorbed bytes, output block, output index - the draws diverge.
contract ChunkVerifierTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/batch_stark_vectors.bin";
    string internal constant JSON = "test/vectors/batch_stark_vectors.json";

    // Payload geometry, same as the native test (fixed by the batch structure).
    uint256 internal constant SEED_WORDS_END = 348;
    uint256 internal constant DEGREE_WORDS_END = 444;
    uint256 internal constant PV_WORDS_END = 456;
    uint256 internal constant PRE_DIGEST_END = 488;

    function test_chunked_walk_lands_on_the_same_challenges() public view {
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

        // One call per phase, carry crossing every boundary.
        bytes memory carry = ChunkVerifier.begin(seedWords, degreeWords);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_BEGIN);
        carry = ChunkVerifier.stepMain(carry, mainDigest, pvWords);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_MAIN);
        carry = ChunkVerifier.stepPreprocessed(carry, preDigest);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_PREPROCESSED);
        carry = ChunkVerifier.stepLookup(carry, 0, lookupPow);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_LOOKUP);
        carry = ChunkVerifier.stepPermutation(carry, permDigest, terminals);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_PERMUTATION);
        carry = ChunkVerifier.stepQuotient(carry, quotDigest, randDigest);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_QUOTIENT);
        carry = ChunkVerifier.stepOod(carry, 0, oodPow);
        assertEq(ChunkVerifier.phaseOf(carry), ChunkVerifier.PHASE_OOD);

        assertEq(
            ChunkVerifier.challenge(carry, ChunkVerifier.CHALLENGE_LOOKUP_ALPHA),
            _parseExt(j, ".lookup_alpha"),
            "lookup alpha");
        assertEq(
            ChunkVerifier.challenge(carry, ChunkVerifier.CHALLENGE_BETA),
            _parseExt(j, ".beta"),
            "beta");
        assertEq(
            ChunkVerifier.challenge(carry, ChunkVerifier.CHALLENGE_CONSTRAINT_ALPHA),
            _parseExt(j, ".constraint_alpha"),
            "constraint alpha");
        assertEq(ChunkVerifier.challenge(carry, ChunkVerifier.CHALLENGE_ZETA), _parseExt(j, ".zeta"), "zeta");
    }

    /// A carry may not skip a phase: stepOod on a post-begin carry must revert, and
    /// a challenge may not be read before its phase drew it.
    function test_cannot_skip_a_phase() public {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        bytes memory seedWords = _slice(b.raw, b.constOff, SEED_WORDS_END);
        bytes memory degreeWords =
            _slice(b.raw, b.constOff + SEED_WORDS_END, DEGREE_WORDS_END - SEED_WORDS_END);
        bytes memory carry = ChunkVerifier.begin(seedWords, degreeWords);

        // stepOod demands PHASE_QUOTIENT; the carry is at PHASE_BEGIN.
        ChunkVerifierHarness h = new ChunkVerifierHarness();
        vm.expectRevert(
            abi.encodeWithSelector(
                ChunkVerifier.PhaseOutOfOrder.selector, ChunkVerifier.PHASE_QUOTIENT, ChunkVerifier.PHASE_BEGIN)
        );
        h.stepOodWith(carry);
    }

    /// A challenge read before its phase drew it reverts with the same error.
    function test_cannot_read_a_challenge_early() public {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        bytes memory seedWords = _slice(b.raw, b.constOff, SEED_WORDS_END);
        bytes memory degreeWords =
            _slice(b.raw, b.constOff + SEED_WORDS_END, DEGREE_WORDS_END - SEED_WORDS_END);
        bytes memory carry = ChunkVerifier.begin(seedWords, degreeWords);
        ChunkVerifierHarness h = new ChunkVerifierHarness();
        vm.expectRevert(
            abi.encodeWithSelector(
                ChunkVerifier.PhaseOutOfOrder.selector, ChunkVerifier.PHASE_OOD, ChunkVerifier.PHASE_BEGIN)
        );
        h.challengeWith(carry, ChunkVerifier.CHALLENGE_ZETA);
    }

    function _slice(bytes memory src, uint256 start, uint256 len)
        private
        pure
        returns (bytes memory out)
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
}

/// External frame so expectRevert sees the revert at a lower call depth.
contract ChunkVerifierHarness {
    function stepOodWith(bytes memory carry) external pure {
        ChunkVerifier.stepOod(carry, 0, 0);
    }

    function challengeWith(bytes memory carry, uint256 which) external pure {
        ChunkVerifier.challenge(carry, which);
    }
}
