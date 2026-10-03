// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierCore} from "../src/verifier/WhirVerifierCore.sol";
import {WhirInitialPhaseHarness as Init} from "./utils/WhirInitialPhaseHarness.sol";

/// One intermediate WHIR round, pinned against the prover's own transcript.
///
/// The round consumes the REAL carried claim and fold point produced by the
/// initial phase, so a mismatch localises to this phase. Every expected value
/// is what the Rust verifier computed while walking the same proof - never a
/// reimplementation of its formula.
///
/// Each assertion pins a distinct failure mode:
///
/// - `gamma` catches any desynchronisation before the round batching draw
///   (a missing OOD answer, a PoW absorbed at the wrong site, a wrong index
///   bit width).
/// - `folds[q]` catches the Merkle path order, the leaf encoding, or the
///   hypercube fold - the STIR layer end to end.
/// - `claimedEval` catches the constraint's statement order and the carried
///   claim's gamma^0 weight (invisible to the sponge).
/// - `foldedClaim` and `randomness` pin the round sumcheck.
/// External wrapper: a library call is inlined, so a revert inside
/// WhirVerifierCore.verifyRound happens at the same call depth as the
/// expectRevert cheatcode and forge rejects it. One external hop fixes that.
contract RoundHarness {
    function round(
        WhirVerifierCore.Transcript memory t,
        WhirVerifierCore.RoundSchedule memory s,
        WhirVerifierCore.RoundInput memory input,
        uint256 carried
    ) external pure returns (WhirVerifierCore.RoundOutput memory) {
        return WhirVerifierCore.verifyRound(t, s, input, carried);
    }
}

contract WhirRoundPhaseTest is Test {
    string constant ARTIFACT = "test/vectors/whir_proof_vectors.json";

    function _u(uint256 v) private pure returns (string memory) {
        return vm.toString(v);
    }

    /// Run the initial phase, returning a transcript parked after its sumcheck
    /// plus the claim and fold point the first round consumes.
    function _afterInitial(string memory j)
        private
        pure
        returns (WhirVerifierCore.Transcript memory t, uint256 carried, uint256[] memory randomness)
    {
        (WhirVerifierCore.InitialSchedule memory s, WhirVerifierCore.InitialInput memory input) =
            Init.inputs(j);
        // Runs 0-4 belong to the initial phase, run 5 is the round sumcheck's
        // separator, run 6 the final sumcheck's; the cursor walks them in order,
        // so the payload carries all of them and each phase consumes its own.
        t.constants = Init.constants(j, 0, 7);
        WhirVerifierCore.observeDigest(t, vm.parseJsonBytes32(j, ".commitment"));
        WhirVerifierCore.InitialOutput memory init = WhirVerifierCore.verifyInitial(t, s, input);
        // Cross-check against the prover's own values so a round-phase failure
        // cannot be an initial-phase failure in disguise.
        assertEq(init.claimedEval, Init.extFlat(j, ".initial_claimed_eval"), "initial combined claim");
        assertEq(init.foldedClaim, Init.extFlat(j, ".claimed_eval"), "initial folded claim");
        carried = init.foldedClaim;
        randomness = init.randomness;
    }

    /// Assemble round `r`'s schedule and proof inputs.
    function _round(string memory j, uint256 r, uint256[] memory prevRandomness)
        private
        pure
        returns (WhirVerifierCore.RoundSchedule memory s, WhirVerifierCore.RoundInput memory input)
    {
        string memory rp = string.concat(".round_params[", _u(r), "]");
        // [num_variables, log_folded_domain_size, ood_samples, folding_pow_bits]
        uint256 logFolded = vm.parseJsonUint(j, string.concat(rp, "[1]"));
        uint256 oodSamples = vm.parseJsonUint(j, string.concat(rp, "[2]"));

        s.roundIndex = r;
        s.oodSamples = oodSamples;
        // The round sumcheck's separator is fixed-absorb run 5: runs 0-4 were
        // consumed by the initial phase.
        s.sumcheckConstants = Init.runWords(j, 5);

        uint256 numQueries =
            vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", _u(r), "]"));
        uint256 rowElems = uint256(1) << prevRandomness.length;

        input.commitment =
            vm.parseJsonBytes32(j, string.concat(".round_commitments[", _u(r), "]"));
        input.prevCommitment = r == 0
            ? vm.parseJsonBytes32(j, ".commitment")
            : vm.parseJsonBytes32(j, string.concat(".round_commitments[", _u(r - 1), "]"));

        input.oodAnswers = new uint256[](oodSamples);
        for (uint256 i; i < oodSamples; ++i) {
            input.oodAnswers[i] =
                Init.extAt(j, string.concat(".round_ood_answers[", _u(r), "]"), i);
        }
        input.powWitness = vm.parseJsonUint(j, string.concat(".round_pow_witnesses[", _u(r), "]"));
        input.powBits = vm.parseJsonUint(j, string.concat(".schedule.rounds[", _u(r), "].pow_bits"));
        input.logFoldedDomainSize = logFolded;
        input.numQueries = numQueries;

        // Round 0 opens base-field rows (one limb per element); later rounds
        // open extension rows (four limbs per element). The artifact says which
        // it exported rather than the test assuming the round index.
        uint256 extRows = vm.parseJsonUint(j, ".counts.num_round_rows_ext");
        uint256 baseRows = vm.parseJsonUint(j, ".counts.num_round_rows_base");
        input.rowsAreBase = extRows == 0 && baseRows > 0;
        uint256 limbsPerElem = input.rowsAreBase ? 1 : 4;
        input.rowElems = rowElems;
        input.rowLimbs = rowElems * limbsPerElem;
        input.rowsFlat = new uint256[](numQueries * input.rowLimbs);
        for (uint256 q; q < numQueries; ++q) {
            for (uint256 e; e < rowElems; ++e) {
                for (uint256 k; k < limbsPerElem; ++k) {
                    uint256 limb = input.rowsAreBase
                        ? vm.parseJsonUint(
                            j,
                            string.concat(".round_rows_base[", _u(q), "][", _u(e), "]")
                        )
                        : vm.parseJsonUint(
                            j,
                            string.concat(".round_rows_ext[", _u(q), "][", _u(e), "][", _u(k), "]")
                        );
                    input.rowsFlat[q * input.rowLimbs + e * limbsPerElem + k] = limb;
                }
            }
        }

        uint256 depth = vm.parseJsonUint(j, ".counts.round0_path_depth");
        input.paths = new bytes32[][](numQueries);
        for (uint256 q; q < numQueries; ++q) {
            input.paths[q] = new bytes32[](depth);
            for (uint256 h; h < depth; ++h) {
                input.paths[q][h] = vm.parseJsonBytes32(
                    j, string.concat(".round0_paths[", _u(q), "][", _u(h), "]")
                );
            }
        }

        input.prevRandomness = prevRandomness;

        uint256 sumcheckRounds =
            vm.parseJsonUint(j, string.concat(".counts.num_round_sumcheck_rounds[", _u(r), "]"));
        input.sumcheckCA = new uint256[](sumcheckRounds);
        input.sumcheckCInf = new uint256[](sumcheckRounds);
        for (uint256 i; i < sumcheckRounds; ++i) {
            input.sumcheckCA[i] =
                Init.extAt(j, string.concat(".round_sumcheck_ca[", _u(r), "]"), i);
            input.sumcheckCInf[i] =
                Init.extAt(j, string.concat(".round_sumcheck_cinf[", _u(r), "]"), i);
        }
        input.sumcheckPowWitnesses = new uint256[](0);
        input.sumcheckPowBits = vm.parseJsonUint(j, string.concat(rp, "[3]"));
    }

    function test_round_matches_the_prover() public view {
        string memory j = vm.readFile(ARTIFACT);
        uint256 nRounds = vm.parseJsonUint(j, ".shape.n_rounds");
        assertEq(nRounds, 1, "this artifact exercises one intermediate round");

        (WhirVerifierCore.Transcript memory t, uint256 carried, uint256[] memory randomness) =
            _afterInitial(j);

        for (uint256 r; r < nRounds; ++r) {
            (WhirVerifierCore.RoundSchedule memory s, WhirVerifierCore.RoundInput memory input) =
                _round(j, r, randomness);
            WhirVerifierCore.RoundOutput memory out =
                WhirVerifierCore.verifyRound(t, s, input, carried);

            assertEq(out.gamma, Init.extFlat(j, string.concat(".round_batching[", _u(r), "]")), "round batching");
            uint256 folds = vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", _u(r), "]"));
            for (uint256 q; q < folds; ++q) {
                assertEq(
                    out.folds[q],
                    Init.extAt(j, string.concat(".round_folds[", _u(r), "]"), q),
                    string.concat("fold ", _u(q)));
            }
            assertEq(
                out.claimedEval,
                Init.extFlat(j, string.concat(".round_claimed_evals[", _u(r), "]")),
                "round combined claim");
            assertEq(
                out.foldedClaim,
                Init.extFlat(j, string.concat(".round_folded_claims[", _u(r), "]")),
                "round folded claim");


            uint256 drawn = vm.parseJsonUint(j, ".counts.num_ood_points");
            assertEq(out.oodPoints.length, drawn, "ood point count");
            for (uint256 i; i < drawn; ++i) {
                assertEq(
                    out.oodPoints[i],
                    Init.extAt(j, ".ood_points", i),
                    string.concat("ood point ", _u(i)));
            }

            uint256 sumcheckRounds =
                vm.parseJsonUint(j, string.concat(".counts.num_round_sumcheck_rounds[", _u(r), "]"));
            assertEq(out.randomness.length, sumcheckRounds, "round randomness count");
            for (uint256 i; i < sumcheckRounds; ++i) {
                assertEq(
                    out.randomness[i],
                    Init.extAt(j, string.concat(".round_randomness[", _u(r), "]"), i),
                    string.concat("round randomness ", _u(i)));
            }

            carried = out.foldedClaim;
            randomness = out.randomness;
        }
    }

    /// A tampered opened row must change both its fold and the combined claim:
    /// the Merkle authentication and the batching are load-bearing, not
    /// decorative. (The honest root check reverts on tampering; this test
    /// perturbs a row AND its fold consistently is impossible - so it checks
    /// the fold changes when the row changes, with the path left alone, which
    /// the root check catches.)
    function test_tampered_row_fails_authentication() public {
        string memory j = vm.readFile(ARTIFACT);
        (WhirVerifierCore.Transcript memory t, uint256 carried, uint256[] memory randomness) =
            _afterInitial(j);
        (WhirVerifierCore.RoundSchedule memory s, WhirVerifierCore.RoundInput memory input) =
            _round(j, 0, randomness);

        // Flip one limb of the first opened row. The Merkle leaf no longer
        // matches the authenticated root, so the round must revert rather than
        // fold a forged row into the claim.
        input.rowsFlat[0] = input.rowsFlat[0] + 1;
        RoundHarness harness = new RoundHarness();
        vm.expectRevert();
        harness.round(t, s, input, carried);
    }
}
