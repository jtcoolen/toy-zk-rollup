// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirVerifierCore} from "../src/verifier/WhirVerifierCore.sol";

/// The WHIR initial phase, pinned against the prover's own transcript.
///
/// The artifact (`contracts/test/vectors/whir_proof_vectors.json`) is generated
/// by `crates/prover/tests/whir_proof_vectors.rs`, which walks the transcript
/// with the SAME `WhirVerifierTranscript` the native verifier uses and asserts
/// its event stream is identical to the native verifier's. Every value asserted
/// here is what the Rust verifier itself computed - never a reimplementation of
/// its formula.
///
/// Each assertion pins a distinct failure mode:
///
/// - `alpha` catches a desynchronised sponge anywhere before the draw, and a
///   port that draws the batching challenge twice (alpha and gamma are ONE
///   sample under two names).
/// - `claimedEval` catches the constraint's statement order: concrete claims
///   are weighted at gamma^0.. and the virtual answers after them - the REVERSE
///   of the transcript order. Invisible to the sponge; only this assertion sees
///   it.
/// - `foldedClaim` and `randomness` pin the sumcheck fold and its reduction
///   point, i.e. the {0,1,infinity} identity (D-048).
contract WhirInitialPhaseTest is Test {
    string constant ARTIFACT = "test/vectors/whir_proof_vectors.json";

    function _u(uint256 v) private pure returns (string memory) {
        return vm.toString(v);
    }

    /// One extension element stored as a flat four-limb array at `path`.
    function _extFlat(string memory j, string memory path) private pure returns (uint256) {
        return (vm.parseJsonUint(j, string.concat(path, "[0]")) << 224)
            | (vm.parseJsonUint(j, string.concat(path, "[1]")) << 192)
            | (vm.parseJsonUint(j, string.concat(path, "[2]")) << 160)
            | (vm.parseJsonUint(j, string.concat(path, "[3]")) << 128);
    }

    /// The `i`-th extension element of an array of four-limb arrays at `path`.
    function _extAt(string memory j, string memory path, uint256 i) private pure returns (uint256) {
        return _extFlat(j, string.concat(path, "[", _u(i), "]"));
    }

    /// Word count of fixed-absorb run `i` (hex string of 4-byte LE words).
    function _runWords(string memory j, uint256 i) private pure returns (uint256) {
        return bytes(vm.parseJsonString(j, string.concat(".fixed_absorb[", _u(i), "]"))).length / 8;
    }

    /// Concatenate the hex constant runs `[from, to)` into one payload.
    function _constants(string memory j, uint256 from, uint256 to) private pure returns (bytes memory out) {
        for (uint256 i = from; i < to; ++i) {
            out = abi.encodePacked(
                out, vm.parseJsonBytes(j, string.concat(".fixed_absorb[", _u(i), "]"))
            );
        }
    }

    /// Assemble the initial-phase inputs from the artifact.
    function _inputs(string memory j)
        private
        pure
        returns (
            bytes memory constants,
            WhirVerifierCore.InitialSchedule memory s,
            WhirVerifierCore.InitialInput memory input
        )
    {
        constants = _constants(j, 0, 5);

        // Schedule lengths, read from the artifact rather than hard-coded: run 0
        // sits between the commitment and the virtual claim, run 1 before each
        // concrete claim's evaluations (both claims share the length), run 3
        // before the batching draw, and the first 37 words of run 4 belong to
        // the sumcheck's own separator.
        s.preClaimsConstants = _runWords(j, 0);
        s.perClaimConstants = _runWords(j, 1);
        s.batchingConstants = _runWords(j, 3);
        s.sumcheckConstants = 37;

        uint256 width = vm.parseJsonUint(j, ".shape.width");
        uint256 claims = vm.parseJsonUint(j, ".shape.num_opening_claims");
        uint256 oodSamples = vm.parseJsonUint(j, ".shape.commitment_ood_samples");

        uint256[] memory evals = new uint256[](claims * width);
        uint256[] memory widths = new uint256[](claims);
        for (uint256 c; c < claims; ++c) {
            widths[c] = width;
            for (uint256 w; w < width; ++w) {
                evals[c * width + w] = _extAt(j, string.concat(".bound_evals[", _u(c), "]"), w);
            }
        }
        uint256[] memory oodAnswers = new uint256[](oodSamples);
        for (uint256 i; i < oodSamples; ++i) {
            oodAnswers[i] = _extAt(j, ".initial_ood_answers", i);
        }

        uint256 rounds = vm.parseJsonUint(j, ".schedule.rounds[0].folding_factor");
        uint256[] memory cA = new uint256[](rounds);
        uint256[] memory cInf = new uint256[](rounds);
        for (uint256 r; r < rounds; ++r) {
            cA[r] = _extAt(j, ".initial_sumcheck_ca", r);
            cInf[r] = _extAt(j, ".initial_sumcheck_cinf", r);
        }

        input.oodAnswers = oodAnswers;
        input.openingEvals = evals;
        input.claimWidths = widths;
        input.roundCA = cA;
        input.roundCInf = cInf;
        input.powWitnesses = new uint256[](0);
        input.powBits = vm.parseJsonUint(j, ".shape.starting_folding_pow_bits");
    }

    function test_initial_phase_matches_the_prover() public view {
        string memory j = vm.readFile(ARTIFACT);
        (bytes memory constants, WhirVerifierCore.InitialSchedule memory s, WhirVerifierCore.InitialInput memory input) =
            _inputs(j);

        WhirVerifierCore.Transcript memory t;
        t.constants = constants;
        // The STARK layer observes the batch commitment before handing over to
        // WHIR (p3's observe_commitment); the core's transcript starts after it.
        WhirVerifierCore.observeDigest(t, vm.parseJsonBytes32(j, ".commitment"));
        uint256 g0 = gasleft();
        WhirVerifierCore.InitialOutput memory out = WhirVerifierCore.verifyInitial(t, s, input);
        // Verify-only gas, measured before the assertion block. Bound: ~2.6M today;
        // fail CI past 5M. (The test's total includes JSON parsing.)
        assertLt(g0 - gasleft(), 1_000_000, "initial phase verify regressed");

        // The flat dot product above is only valid because no statement group is
        // empty: an empty group would still advance gamma's running exponent.
        // Assert it against the prover's own group lengths rather than assume it.
        uint256 groups = vm.parseJsonUint(j, ".counts.num_initial_eq_groups");
        assertEq(groups, 3, "statement groups");
        for (uint256 i; i < groups; ++i) {
            // Each group holds at least one constraint in this shape.
            assertTrue(vm.parseJsonUint(j, string.concat(".initial_eq_group_lens[", _u(i), "]")) > 0, "empty statement group would shift gamma");
        }

        assertEq(out.alpha, _extFlat(j, ".alpha"), "alpha");
        assertEq(out.claimedEval, _extFlat(j, ".initial_claimed_eval"), "combined claim");
        assertEq(out.foldedClaim, _extFlat(j, ".claimed_eval"), "folded claim");

        uint256 rounds = vm.parseJsonUint(j, ".schedule.rounds[0].folding_factor");
        assertEq(out.randomness.length, rounds, "randomness count");
        for (uint256 i; i < rounds; ++i) {
            assertEq(
                out.randomness[i],
                _extAt(j, ".initial_randomness", i),
                string.concat("initial randomness ", _u(i))
            );
        }
        // alpha and gamma are one draw under two names; the core must never
        // draw twice.
        assertEq(_extFlat(j, ".alpha"), _extFlat(j, ".gamma"), "artifact: alpha == gamma");
    }

    /// A tampered claimed evaluation must change the combined claim: the
    /// transcript binds the claim rather than replaying a fixed sum.
    function test_tampered_claim_changes_the_combined_eval() public view {
        string memory j = vm.readFile(ARTIFACT);
        (bytes memory constants, WhirVerifierCore.InitialSchedule memory s, WhirVerifierCore.InitialInput memory input) =
            _inputs(j);

        WhirVerifierCore.Transcript memory honest;
        honest.constants = constants;
        uint256 honestClaim = WhirVerifierCore.verifyInitial(honest, s, input).claimedEval;

        input.openingEvals[0] = KoalaBearExt4.add(input.openingEvals[0], KoalaBearExt4.ONE);
        WhirVerifierCore.Transcript memory tampered;
        tampered.constants = constants;
        uint256 tamperedClaim = WhirVerifierCore.verifyInitial(tampered, s, input).claimedEval;

        assertTrue(honestClaim != tamperedClaim, "the combined claim ignores the proof's evaluations");
    }
}
