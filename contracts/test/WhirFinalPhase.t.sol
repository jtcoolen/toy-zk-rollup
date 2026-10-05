// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierCore} from "../src/verifier/WhirVerifierCore.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirInitialPhaseHarness as Init} from "./utils/WhirInitialPhaseHarness.sol";

/// External wrapper: a library call is inlined, so a revert inside
/// WhirVerifierCore.verifyFinal happens at the same call depth as the
/// expectRevert cheatcode and forge rejects it. One external hop fixes that.
contract FinalHarness {
    function finalPhase(
        WhirVerifierCore.Transcript memory t,
        WhirVerifierCore.FinalSchedule memory s,
        WhirVerifierCore.FinalInput memory input,
        uint256 carried
    ) external pure returns (WhirVerifierCore.FinalOutput memory) {
        return WhirVerifierCore.verifyFinal(t, s, input, carried);
    }
}

/// The WHIR final phase, pinned against the prover's own transcript.
///
/// The final phase consumes the REAL carried claim and fold points of every
/// earlier phase - initial sumcheck, then each intermediate round - so a
/// mismatch localises to this phase. The expected values are what the Rust
/// verifier computed while walking the same proof.
///
/// What each assertion pins:
///
/// - the terminal STIR check (fold == poly at the domain point) is inside
///   verifyFinal: a wrong path, leaf encoding, fold point, or public
///   polynomial reverts before the sumcheck runs.
/// - foldedClaim pins the closing sumcheck end to end.
/// - randomness pins the closing point the final evaluation folds at.
/// - the terminal identity (claim == weight * poly(r)) is checked inside
///   verifyFinal against the constraint weights the test assembles from the
///   exported points: a wrong gamma power, a wrong localR slice, or a wrong
///   selection weight reverts.
contract WhirFinalPhaseTest is Test {
    string constant ARTIFACT = "test/vectors/whir_proof_vectors.json";

    function _flatPaths(
        string memory j,
        string memory field,
        uint256 numQueries,
        uint256 depth
    ) private pure returns (bytes32[] memory out) {
        out = new bytes32[](numQueries * depth);
        for (uint256 q; q < numQueries; ++q) {
            for (uint256 h; h < depth; ++h) {
                out[q * depth + h] =
                    vm.parseJsonBytes32(j, string.concat(field, "[", _u(q), "][", _u(h), "]"));
            }
        }
    }

    function _u(uint256 v) private pure returns (string memory) {
        return vm.toString(v);
    }

    /// Run the initial phase and every intermediate round, returning the
    /// transcript parked after the last round sumcheck, the carried claim,
    /// the last fold point, and every folding randomness in protocol order.
    function _beforeFinal(string memory j) private pure returns (
        WhirVerifierCore.Transcript memory t,
        uint256 carried,
        uint256[] memory lastRandomness,
        uint256[] memory allRandomness,
        uint256[] memory oodPoint0
    ) {
        (WhirVerifierCore.InitialSchedule memory s0, WhirVerifierCore.InitialInput memory i0) =
            Init.inputs(j);
        t.constants = Init.constants(j, 0, 7);
        WhirVerifierCore.observeDigest(t, vm.parseJsonBytes32(j, ".commitment"));
        WhirVerifierCore.InitialOutput memory init = WhirVerifierCore.verifyInitial(t, s0, i0);
        assertEq(init.claimedEval, Init.extFlat(j, ".initial_claimed_eval"), "initial combined claim");
        assertEq(init.foldedClaim, Init.extFlat(j, ".claimed_eval"), "initial folded claim");
        carried = init.foldedClaim;
        lastRandomness = init.randomness;
        allRandomness = init.randomness;

        uint256 nRounds = vm.parseJsonUint(j, ".shape.n_rounds");
        for (uint256 r; r < nRounds; ++r) {
            string memory rp = string.concat(".round_params[", _u(r), "]");
            uint256 oodSamples = vm.parseJsonUint(j, string.concat(rp, "[2]"));
            uint256 numQueries =
                vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", _u(r), "]"));

            WhirVerifierCore.RoundSchedule memory s;
            s.roundIndex = r;
            s.oodSamples = oodSamples;
            s.sumcheckConstants = Init.runWords(j, 5);

            WhirVerifierCore.RoundInput memory input;
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
            input.powWitness =
                vm.parseJsonUint(j, string.concat(".round_pow_witnesses[", _u(r), "]"));
            input.powBits =
                vm.parseJsonUint(j, string.concat(".schedule.rounds[", _u(r), "].pow_bits"));
            input.logFoldedDomainSize = vm.parseJsonUint(j, string.concat(rp, "[1]"));
            input.numQueries = numQueries;

            uint256 rowElems = uint256(1) << lastRandomness.length;
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
                                j, string.concat(".round_rows_base[", _u(q), "][", _u(e), "]"))
                            : vm.parseJsonUint(j, string.concat(".round_rows_ext[", _u(q), "][",
                                _u(e), "][", _u(k), "]"));
                        input.rowsFlat[q * input.rowLimbs + e * limbsPerElem + k] = limb;
                    }
                }
            }
            uint256 depth = vm.parseJsonUint(j, ".counts.round0_path_depth");
            input.pathsFlat = _flatPaths(j, ".round0_paths", numQueries, depth);
            input.prevRandomness = lastRandomness;

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

            WhirVerifierCore.RoundOutput memory out =
                WhirVerifierCore.verifyRound(t, s, input, carried);
            assertEq(
                out.foldedClaim,
                Init.extFlat(j, string.concat(".round_folded_claims[", _u(r), "]")),
                "round folded claim");
            carried = out.foldedClaim;
            lastRandomness = out.randomness;
            // Protocol order: initial, then each round's sumcheck point.
            uint256[] memory grown =
                new uint256[](allRandomness.length + out.randomness.length);
            for (uint256 i; i < allRandomness.length; ++i) {
                grown[i] = allRandomness[i];
            }
            for (uint256 i; i < out.randomness.length; ++i) {
                grown[allRandomness.length + i] = out.randomness[i];
            }
            allRandomness = grown;
            if (r == 0 && oodSamples > 0) {
                oodPoint0 = out.oodPoints;
            }
        }
    }

    /// Assemble the final phase's schedule and proof inputs from the artifact.
    function _final(string memory j, uint256[] memory lastRandomness)
        private pure returns (WhirVerifierCore.FinalSchedule memory s, WhirVerifierCore.FinalInput memory input)
    {
        s.finalPolyConstants = 0;
        s.roundIndex = vm.parseJsonUint(j, ".shape.n_rounds");
        // Fixed-absorb run 6: the closing sumcheck's domain separator.
        s.sumcheckConstants = Init.runWords(j, 6);

        uint256 numQueries = vm.parseJsonUint(j, ".schedule.final_round.num_queries");
        uint256 rowElems = uint256(1) << lastRandomness.length;

        input.finalPoly = new uint256[](vm.parseJsonUint(j, ".counts.final_poly_len"));
        for (uint256 i; i < input.finalPoly.length; ++i) {
            input.finalPoly[i] = Init.extAt(j, ".final_poly", i);
        }
        uint256 nRounds = vm.parseJsonUint(j, ".shape.n_rounds");
        input.lastCommitment = nRounds == 0
            ? vm.parseJsonBytes32(j, ".commitment")
            : vm.parseJsonBytes32(j, string.concat(".round_commitments[", _u(nRounds - 1), "]"));
        input.powWitness = vm.parseJsonUint(j, ".final_pow_witness");
        input.powBits = vm.parseJsonUint(j, ".schedule.final_round.pow_bits");
        input.logFoldedDomainSize =
            vm.parseJsonUint(j, ".schedule.final_round.log_folded_domain_size");
        input.numQueries = numQueries;

        input.rowElems = rowElems;
        input.rowLimbs = rowElems * 4; // terminal rows are extension-valued
        input.rowsFlat = new uint256[](numQueries * input.rowLimbs);
        for (uint256 q; q < numQueries; ++q) {
            for (uint256 e; e < rowElems; ++e) {
                for (uint256 k; k < 4; ++k) {
                    input.rowsFlat[q * input.rowLimbs + e * 4 + k] = vm.parseJsonUint(
                        j, string.concat(".final_rows_ext[", _u(q), "][", _u(e), "][", _u(k), "]"));
                }
            }
        }

        uint256 depth = input.logFoldedDomainSize;
        input.pathsFlat = _flatPaths(j, ".final_paths", numQueries, depth);
        input.prevRandomness = lastRandomness;

        // The domain points are base scalars on the folded domain; the STIR
        // check and the selection weights both need them lifted.
        input.domainPoints = new uint256[](numQueries);
        for (uint256 q; q < numQueries; ++q) {
            input.domainPoints[q] = KoalaBearExt4.fromBase(
                vm.parseJsonUint(j, string.concat(".final_domain_points[", _u(q), "]")));
        }

        uint256 sumcheckRounds = vm.parseJsonUint(j, ".shape.final_sumcheck_rounds");
        input.sumcheckCA = new uint256[](sumcheckRounds);
        input.sumcheckCInf = new uint256[](sumcheckRounds);
        for (uint256 i; i < sumcheckRounds; ++i) {
            input.sumcheckCA[i] = Init.extAt(j, ".final_sumcheck_ca", i);
            input.sumcheckCInf[i] = Init.extAt(j, ".final_sumcheck_cinf", i);
        }
        uint256 powCount = vm.parseJsonUint(j, ".counts.num_final_sumcheck_pow_witnesses");
        input.sumcheckPowWitnesses = new uint256[](powCount);
        for (uint256 i; i < powCount; ++i) {
            input.sumcheckPowWitnesses[i] =
                vm.parseJsonUint(j, string.concat(".final_sumcheck_pow_witnesses[", _u(i), "]"));
        }
        input.sumcheckPowBits = vm.parseJsonUint(j, ".schedule.final_round.folding_pow_bits");
        input.allRandomness = new uint256[](0); // filled by the caller
        input.constraints = new WhirGadgets.ConstraintWeight[](0); // filled by the caller
    }

    /// The constraint weights the terminal identity batches over: the initial
    /// constraint (equality statements only, gamma^0..) and one constraint per
    /// intermediate round (carried claim at gamma^0, OOD points, then the STIR
    /// selection group). The final round's STIR claims are NOT here: they are
    /// checked directly against the public polynomial.
    function _constraints(string memory j, uint256[] memory oodPoint0)
        private pure returns (WhirGadgets.ConstraintWeight[] memory constraints)
    {
        uint256 nRounds = vm.parseJsonUint(j, ".shape.n_rounds");
        constraints = new WhirGadgets.ConstraintWeight[](1 + nRounds);

        // --- initial constraint ---
        uint256 nv0 = vm.parseJsonUint(j, ".initial_constraint_num_variables");
        uint256 nPoints = vm.parseJsonUint(j, ".counts.num_initial_eq_points");
        constraints[0].numVariables = nv0;
        constraints[0].gamma = Init.extFlat(j, ".gamma");
        constraints[0].initialPower = 0;
        constraints[0].eqPoints = new uint256[][](nPoints);
        for (uint256 p; p < nPoints; ++p) {
            constraints[0].eqPoints[p] = new uint256[](nv0);
            for (uint256 c; c < nv0; ++c) {
                constraints[0].eqPoints[p][c] =
                    Init.extAt(j, string.concat(".initial_eq_points[", _u(p), "]"), c);
            }
        }

        // --- one per intermediate round ---
        for (uint256 r; r < nRounds; ++r) {
            uint256 nq = vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", _u(r), "]"));
            uint256 oodSamples = vm.parseJsonUint(
                j, string.concat(".round_params[", _u(r), "][2]"));
            constraints[1 + r].numVariables =
                vm.parseJsonUint(j, string.concat(".round_params[", _u(r), "][0]"));
            constraints[1 + r].gamma =
                Init.extFlat(j, string.concat(".round_batching[", _u(r), "]"));
            // The carried claim keeps gamma^0; fresh groups start at gamma^1.
            constraints[1 + r].initialPower = 1;
            constraints[1 + r].eqPoints = new uint256[][](oodSamples);
            uint256 nvRound = constraints[1 + r].numVariables;
            for (uint256 p; p < oodSamples; ++p) {
                // The constraint's point is expand_from_univariate of the drawn
                // scalar: [z^(2^(nv-1)), ..., z^2, z].
                constraints[1 + r].eqPoints[p] =
                    WhirGadgets.expandFromUnivariate(oodPoint0[p], nvRound);
            }
            constraints[1 + r].selVars = new uint256[](nq);
            for (uint256 q; q < nq; ++q) {
                constraints[1 + r].selVars[q] = KoalaBearExt4.fromBase(vm.parseJsonUint(
                    j, string.concat(".round_domain_points[", _u(r), "][", _u(q), "]")));
            }
        }
    }

    function test_final_phase_matches_the_prover() public view {
        string memory j = vm.readFile(ARTIFACT);
        (
            WhirVerifierCore.Transcript memory t,
            uint256 carried,
            uint256[] memory lastRandomness,
            uint256[] memory allRandomness,
            uint256[] memory oodPoint0
        ) = _beforeFinal(j);

        (WhirVerifierCore.FinalSchedule memory s, WhirVerifierCore.FinalInput memory input) =
            _final(j, lastRandomness);
        input.allRandomness = allRandomness;
        input.constraints = _constraints(j, oodPoint0);

        uint256 g0 = gasleft();
        WhirVerifierCore.FinalOutput memory out =
            WhirVerifierCore.verifyFinal(t, s, input, carried);
        // Verify-only gas. Bound: ~85M today (final sumcheck + STIR openings);
        // fail CI past 100M.
        assertLt(g0 - gasleft(), 8_000_000, "final phase verify regressed");

        assertEq(out.foldedClaim, Init.extFlat(j, ".claimed_after_final"), "final folded claim");
        uint256 n = vm.parseJsonUint(j, ".shape.final_sumcheck_rounds");
        assertEq(out.randomness.length, n, "closing randomness count");
        for (uint256 i; i < n; ++i) {
            assertEq(
                out.randomness[i],
                Init.extAt(j, ".final_randomness", i),
                string.concat("closing randomness ", _u(i)));
        }
        // The terminal identity itself (folded == weight * poly(r)) is checked
        // inside verifyFinal: reaching here at all is the assertion.
    }

    /// A tampered public polynomial must break the terminal STIR check: the
    /// fold of an authenticated row cannot be made to agree with a forged
    /// coefficient table, so the verifier reverts instead of accepting.
    function test_tampered_final_poly_reverts() public {
        string memory j = vm.readFile(ARTIFACT);
        (
            WhirVerifierCore.Transcript memory t,
            uint256 carried,
            uint256[] memory lastRandomness,
            uint256[] memory allRandomness,
            uint256[] memory oodPoint0
        ) = _beforeFinal(j);

        (WhirVerifierCore.FinalSchedule memory s, WhirVerifierCore.FinalInput memory input) =
            _final(j, lastRandomness);
        input.allRandomness = allRandomness;
        input.constraints = _constraints(j, oodPoint0);
        // Tamper a REAL field lane: the packed word's low 128 bits are
        // padding, rejected at decode (PAD_MASK) and ignored by the lane-wise
        // field arithmetic, so +1 there is not a polynomial change. Lane 0
        // (bits 224-255) is the first coefficient's first coordinate.
        input.finalPoly[0] = input.finalPoly[0] + (uint256(1) << 224);

        FinalHarness harness = new FinalHarness();
        vm.expectRevert();
        harness.finalPhase(t, s, input, carried);
    }
}
