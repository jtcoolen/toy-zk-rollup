// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirVerifierCore} from "../src/verifier/WhirVerifierCore.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";
import {TerminalRef} from "./utils/TerminalRef.sol";

/// The composed settlement verifier: the WHIR core driven at the REAL opening
/// shapes, seeded from the batch transcript at the delegate point.
///
/// This is the end-to-end pin for the WHIR layer at the settlement shape. The
/// batch layer (BatchTranscript) is pinned separately; here the sponge is seeded
/// by walking the prover's semantic blob up to the delegate event, then the
/// WHIR core replays one opening round exactly as a settlement contract would,
/// checking every challenge and the terminal identity against the prover's own
/// values.
///
/// WHY THE SPONGE IS SEEDED, NOT RE-DERIVED
///
/// The batch layer absorbs the WHIR commitment (the batch main commitment) as
/// its last step before delegating. The WHIR core's first transcript action is
/// therefore NOT an absorb of that commitment - it is the initial phase's claim
/// registration, on a sponge that already carries the commitment. walkTo stops
/// the blob walk at the delegate event, handing us that sponge.
///
/// THE FRAMING TABLE (D-070)
///
/// Each round's config-fixed absorbs are exported as one flat byte string plus
/// the per-phase word counts: pre-claim framing (one block per virtual claim),
/// per-concrete-claim framing, the batching block, and the sumcheck separators.
/// The contract reads the framing bytes verbatim and consumes them by count;
/// the counts are structural, never proof-driven.
contract WhirComposedTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/composed_vectors.bin";
    string internal constant FLAT = "test/vectors/composed_flat.json";

    /// The delegate event: the batch layer's last absorbed event is the
    /// commitment at 155; the WHIR core's first event is 161.
    uint256 internal constant DELEGATE_SITE = 161;

    /// The harness's stand-in for the pinned TerminalWeight satellite: the
    /// terminal identity evaluated in plain Solidity, in its own contract so
    /// the eval chain stays out of the final phase's stack frame.
    TerminalRef internal terminalRef = new TerminalRef();

    function _flat() private view returns (string memory) {
        // WHIR_FLAT points the harness at another shape (e.g. the recursion
        // chain vectors, D-092 batch 19); default is the Fibonacci settlement.
        return vm.readFile(vm.envOr("WHIR_FLAT", string(FLAT)));
    }

    /// The semantic blob matching [_flat]; WHIR_BLOB switches both together.
    function _blob() private view returns (string memory) {
        return vm.envOr("WHIR_BLOB", string(BLOB));
    }

    /// Slice a flat uint array out of a longer one.
    function _slice(uint256[] memory src, uint256 start, uint256 len)
        private
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](len);
        for (uint256 i; i < len; ++i) {
            out[i] = src[start + i];
        }
    }

    /// Rebuild a ragged uint256[][] from a flat array plus per-row lengths.
    function _ragged(uint256[] memory flat, uint256[] memory lens)
        private
        pure
        returns (uint256[][] memory out)
    {
        out = new uint256[][](lens.length);
        uint256 off;
        for (uint256 i; i < lens.length; ++i) {
            out[i] = new uint256[](lens[i]);
            for (uint256 j; j < lens[i]; ++j) {
                out[i][j] = flat[off + j];
            }
            off += lens[i];
        }
    }

    /// Read node `idx` (32 bytes) from a hex-blob byte string.
    function _node(bytes memory blob, uint256 idx) private pure returns (bytes32 out) {
        assembly ("memory-safe") {
            out := mload(add(add(blob, 32), mul(idx, 32)))
        }
    }

    /// Rebuild a ragged bytes32[][] (Merkle paths) from a hex-blob byte
    /// string plus per-query node counts, starting at node `start`.
    function _paths(bytes memory blob, uint256 start, uint256[] memory lens)
        private
        pure
        returns (bytes32[] memory out)
    {
        uint256 total;
        for (uint256 i; i < lens.length; ++i) {
            total += lens[i];
        }
        out = new bytes32[](total);
        uint256 off = start;
        uint256 w;
        for (uint256 i; i < lens.length; ++i) {
            for (uint256 j; j < lens[i]; ++j) {
                out[w++] = _node(blob, off + j);
            }
            off += lens[i];
        }
    }

    /// Split a hex-blob byte string of 32-byte items into a bytes32 array.
    function _split32(bytes memory blob) private pure returns (bytes32[] memory out) {
        out = new bytes32[](blob.length / 32);
        for (uint256 i; i < out.length; ++i) {
            out[i] = _node(blob, i);
        }
    }

    /// Sum a uint array.
    function _sum(uint256[] memory a) private pure returns (uint256 s) {
        for (uint256 i; i < a.length; ++i) {
            s += a[i];
        }
    }

    function _u(uint256 v) private pure returns (string memory) {
        return vm.toString(v);
    }

    /// Seed the WHIR sponge at an opening round's delegate point by walking
    /// the blob. Round 0 starts at the batch delegate event; each later round
    /// starts where the previous round's walk ended (round_starts).
    function _seedSponge(uint256 site) private view returns (WhirVerifierCore.Transcript memory t) {
        SemanticBlob.Blob memory b = SemanticBlob.load(_blob());
        SemanticBlob.Walk memory w = SemanticBlob.walkTo(b, site, true, false);
        t.state = w.state;
    }

    /// Build the terminal constraint weights for one opening round: the initial
    /// constraint (equality groups from the exported eq_points) plus one per
    /// intermediate round (expanded OOD points and selector domain points).
    function _constraints(string memory j, uint256 r)
        private
        pure
        returns (WhirGadgets.ConstraintWeight[] memory constraints)
    {
        string memory R = string.concat(".rounds[", _u(r), "]");
        uint256 nInter = vm.parseJsonUint(j, string.concat(R, ".n_inter"));
        constraints = new WhirGadgets.ConstraintWeight[](1 + nInter);

        // --- initial constraint: equality groups, one per eq_point ---
        uint256 nv0 = vm.parseJsonUint(j, string.concat(R, ".num_variables"));
        uint256[] memory eqFlat = vm.parseJsonUintArray(j, string.concat(R, ".eq_points"));
        uint256[] memory eqLens = vm.parseJsonUintArray(j, string.concat(R, ".eq_points_lens"));
        constraints[0].numVariables = nv0;
        constraints[0].gamma = vm.parseJsonUint(j, string.concat(R, ".gamma"));
        constraints[0].initialPower = 0;
        constraints[0].eqPoints = _ragged(eqFlat, eqLens);

        // --- one per intermediate round ---
        uint256[] memory params = vm.parseJsonUintArray(j, string.concat(R, ".params"));
        uint256[] memory oodPoints = vm.parseJsonUintArray(j, string.concat(R, ".ood_points"));
        uint256[] memory oodSamples = vm.parseJsonUintArray(j, string.concat(R, ".sched_ood_samples"));
        uint256[] memory batching = vm.parseJsonUintArray(j, string.concat(R, ".round_batching"));
        uint256[] memory domainPoints = vm.parseJsonUintArray(j, string.concat(R, ".domain_points"));
        uint256[] memory domainLens = vm.parseJsonUintArray(j, string.concat(R, ".domain_point_lens"));
        uint256 oodOff;
        uint256 domOff;
        for (uint256 i; i < nInter; ++i) {
            uint256 nv = params[i * 4];
            constraints[1 + i].numVariables = nv;
            constraints[1 + i].gamma = batching[i];
            constraints[1 + i].initialPower = 1;
            uint256 os = oodSamples[i];
            constraints[1 + i].eqPoints = new uint256[][](os);
            for (uint256 p; p < os; ++p) {
                constraints[1 + i].eqPoints[p] =
                    WhirGadgets.expandFromUnivariate(oodPoints[oodOff + p], nv);
            }
            oodOff += os;
            uint256 nq = domainLens[i];
            constraints[1 + i].selVars = new uint256[](nq);
            for (uint256 q; q < nq; ++q) {
                constraints[1 + i].selVars[q] = KoalaBearExt4.fromBase(domainPoints[domOff + q]);
            }
            domOff += nq;
        }
    }

    function test_composed_round0_matches_the_prover() public view {
        _runRound(_flat(), 0);
    }

    function test_composed_round1_matches_the_prover() public view {
        _runRound(_flat(), 1);
    }

    function test_composed_round2_matches_the_prover() public view {
        _runRound(_flat(), 2);
    }

    function test_composed_round3_matches_the_prover() public view {
        _runRound(_flat(), 3);
    }

    function test_composed_round4_matches_the_prover() public view {
        _runRound(_flat(), 4);
    }

    /// The per-round flat arrays the intermediate loop walks, with cursors.
    struct RoundCtx {
        string j;
        string R;
        uint256[] oodAnswers;
        uint256[] oodAnswerLens;
        uint256[] queryLens;
        uint256[] rowsIsBase;
        uint256[] rowsFlat;
        uint256[] sumcheckLens;
        uint256[] sumcheckPowLens;
        uint256[] randomnessLens;
        uint256[] roundRandomness;
        uint256[] sumcheckCA;
        uint256[] sumcheckCInf;
        uint256[] sumcheckPow;
        uint256[] powWitnesses;
        uint256[] schedPowBits;
        uint256[] schedFoldPowBits;
        uint256[] schedLogFolded;
        uint256[] schedOodSamples;
        bytes32[] roundCommitments;
        bytes32 batchCommitment;
        bytes pathsBlob;
        uint256[] foldLens;
        uint256[] folds;
        uint256[] claimedEvals;
        uint256[] foldedClaims;
        uint256[] roundBatching;
        uint256[] framingSeps;
        uint256 oodOff;
        uint256 rowOff;
        uint256 scOff;
        uint256 scpOff;
        uint256 randOff;
        uint256 pathOff;
        uint256 foldOff;
        uint256 sepIdx;
    }

    /// Drive one opening round end to end: initial phase, intermediate rounds,
    /// final phase, checking every exported challenge and the terminal identity.
    function _runRound(string memory j, uint256 r) private view {
        string memory R = string.concat(".rounds[", _u(r), "]");
        uint256[] memory roundStarts = vm.parseJsonUintArray(j, ".round_starts");
        WhirVerifierCore.Transcript memory t = _seedSponge(roundStarts[r]);
        t.constants = vm.parseJsonBytes(j, string.concat(R, ".framing_hex"));

        uint256[] memory framingPre = vm.parseJsonUintArray(j, string.concat(R, ".framing_pre"));
        uint256[] memory framingClaim = vm.parseJsonUintArray(j, string.concat(R, ".framing_claim"));
        uint256 framingBatching = vm.parseJsonUint(j, string.concat(R, ".framing_batching"));

        // --- initial phase ---
        WhirVerifierCore.InitialSchedule memory s0;
        s0.preClaimsConstants = framingPre;
        s0.perClaimConstants = framingClaim;
        s0.batchingConstants = framingBatching;
        uint256[] memory framingSeps = vm.parseJsonUintArray(j, string.concat(R, ".framing_seps"));
        s0.sumcheckConstants = framingSeps[0];

        WhirVerifierCore.InitialInput memory i0;
        i0.oodAnswers = vm.parseJsonUintArray(j, string.concat(R, ".initial_ood_answers"));
        i0.openingEvals = vm.parseJsonUintArray(j, string.concat(R, ".bound_evals"));
        i0.claimWidths = vm.parseJsonUintArray(j, string.concat(R, ".claim_widths"));
        i0.claimPerm = vm.parseJsonUintArray(j, string.concat(R, ".claim_perm"));
        i0.roundCA = vm.parseJsonUintArray(j, string.concat(R, ".initial_sumcheck_ca"));
        i0.roundCInf = vm.parseJsonUintArray(j, string.concat(R, ".initial_sumcheck_cinf"));
        i0.powWitnesses = vm.parseJsonUintArray(j, string.concat(R, ".initial_sumcheck_pow_witnesses"));
        i0.powBits = vm.parseJsonUint(j, string.concat(R, ".starting_folding_pow_bits"));

        WhirVerifierCore.InitialOutput memory init = WhirVerifierCore.verifyInitial(t, s0, i0);
        assertEq(init.alpha, vm.parseJsonUint(j, string.concat(R, ".alpha")), "alpha");
        assertEq(
            init.claimedEval, vm.parseJsonUint(j, string.concat(R, ".initial_claimed_eval")), "initial claim"
        );
        assertEq(init.foldedClaim, vm.parseJsonUint(j, string.concat(R, ".claimed_eval")), "initial folded");
        assertEq(init.randomness, vm.parseJsonUintArray(j, string.concat(R, ".initial_randomness")), "initial randomness");

        RoundCtx memory ctx;
        ctx.j = j;
        ctx.R = R;
        ctx.oodAnswers = vm.parseJsonUintArray(j, string.concat(R, ".ood_answers"));
        ctx.oodAnswerLens = vm.parseJsonUintArray(j, string.concat(R, ".ood_answer_lens"));
        ctx.queryLens = vm.parseJsonUintArray(j, string.concat(R, ".query_lens"));
        ctx.rowsIsBase = vm.parseJsonUintArray(j, string.concat(R, ".rows_is_base"));
        ctx.rowsFlat = vm.parseJsonUintArray(j, string.concat(R, ".rows_flat"));
        ctx.sumcheckLens = vm.parseJsonUintArray(j, string.concat(R, ".sumcheck_lens"));
        ctx.sumcheckPowLens = vm.parseJsonUintArray(j, string.concat(R, ".sumcheck_pow_lens"));
        ctx.randomnessLens = vm.parseJsonUintArray(j, string.concat(R, ".randomness_lens"));
        ctx.roundRandomness = vm.parseJsonUintArray(j, string.concat(R, ".round_randomness"));
        ctx.sumcheckCA = vm.parseJsonUintArray(j, string.concat(R, ".sumcheck_ca"));
        ctx.sumcheckCInf = vm.parseJsonUintArray(j, string.concat(R, ".sumcheck_cinf"));
        ctx.sumcheckPow = vm.parseJsonUintArray(j, string.concat(R, ".sumcheck_pow_witnesses"));
        ctx.powWitnesses = vm.parseJsonUintArray(j, string.concat(R, ".pow_witnesses"));
        ctx.schedPowBits = vm.parseJsonUintArray(j, string.concat(R, ".sched_pow_bits"));
        ctx.schedFoldPowBits = vm.parseJsonUintArray(j, string.concat(R, ".sched_folding_pow_bits"));
        ctx.schedLogFolded = vm.parseJsonUintArray(j, string.concat(R, ".sched_log_folded"));
        ctx.schedOodSamples = vm.parseJsonUintArray(j, string.concat(R, ".sched_ood_samples"));
        ctx.roundCommitments = _split32(vm.parseJsonBytes(j, string.concat(R, ".round_commitments_hex")));
        ctx.batchCommitment = vm.parseJsonBytes32(j, string.concat(R, ".commitment"));
        ctx.pathsBlob = vm.parseJsonBytes(j, string.concat(R, ".paths_hex"));
        ctx.foldLens = vm.parseJsonUintArray(j, string.concat(R, ".fold_lens"));
        ctx.folds = vm.parseJsonUintArray(j, string.concat(R, ".folds"));
        ctx.claimedEvals = vm.parseJsonUintArray(j, string.concat(R, ".claimed_evals"));
        ctx.foldedClaims = vm.parseJsonUintArray(j, string.concat(R, ".folded_claims"));
        ctx.roundBatching = vm.parseJsonUintArray(j, string.concat(R, ".round_batching"));
        ctx.framingSeps = framingSeps;
        ctx.sepIdx = 1;

        uint256 nInter = vm.parseJsonUint(j, string.concat(R, ".n_inter"));
        uint256 carried = init.foldedClaim;
        uint256[] memory lastRandomness = init.randomness;
        uint256[] memory allRandomness = init.randomness;
        Threading memory th = _runIntermediates(t, ctx, nInter, carried, lastRandomness, allRandomness);
        _runFinal(t, ctx, r, nInter, th.carried, th.lastRandomness, th.allRandomness);
    }

    /// Values threaded out of the intermediate loop: memory reassignment
    /// inside a function is invisible to the caller, so the loop must return
    /// its updated claim and randomness explicitly.
    struct Threading {
        uint256 carried;
        uint256[] lastRandomness;
        uint256[] allRandomness;
    }

    /// The intermediate WHIR rounds, threaded with the folded claim.
    function _runIntermediates(
        WhirVerifierCore.Transcript memory t,
        RoundCtx memory ctx,
        uint256 nInter,
        uint256 carried,
        uint256[] memory lastRandomness,
        uint256[] memory allRandomness
    ) private view returns (Threading memory th) {
        for (uint256 i; i < nInter; ++i) {
            WhirVerifierCore.RoundSchedule memory s;
            s.roundIndex = i;
            s.oodSamples = ctx.schedOodSamples[i];
            s.sumcheckConstants = ctx.framingSeps[ctx.sepIdx];
            ++ctx.sepIdx;

            WhirVerifierCore.RoundInput memory input;
            input.commitment = ctx.roundCommitments[i];
            input.prevCommitment = i == 0 ? ctx.batchCommitment : ctx.roundCommitments[i - 1];
            uint256 os = ctx.oodAnswerLens[i];
            input.oodAnswers = _slice(ctx.oodAnswers, ctx.oodOff, os);
            ctx.oodOff += os;
            input.powWitness = ctx.powWitnesses[i];
            input.powBits = ctx.schedPowBits[i];
            input.logFoldedDomainSize = ctx.schedLogFolded[i];
            uint256 nq = ctx.queryLens[i];
            input.numQueries = nq;

            uint256 rowElems = uint256(1) << lastRandomness.length;
            bool rowsAreBase = ctx.rowsIsBase[i] == 1;
            uint256 limbsPerElem = rowsAreBase ? 1 : 4;
            input.rowElems = rowElems;
            input.rowLimbs = rowElems * limbsPerElem;
            input.rowsAreBase = rowsAreBase;
            input.rowsFlat = _slice(ctx.rowsFlat, ctx.rowOff, nq * input.rowLimbs);
            ctx.rowOff += nq * input.rowLimbs;

            // Every query in round i opens at depth sched_log_folded[i].
            uint256 depth = ctx.schedLogFolded[i];
            input.pathsFlat = _paths(ctx.pathsBlob, ctx.pathOff, _repeat(depth, nq));
            ctx.pathOff += nq * depth;

            input.prevRandomness = lastRandomness;
            uint256 scr = ctx.sumcheckLens[i];
            input.sumcheckCA = _slice(ctx.sumcheckCA, ctx.scOff, scr);
            input.sumcheckCInf = _slice(ctx.sumcheckCInf, ctx.scOff, scr);
            ctx.scOff += scr;
            uint256 scp = ctx.sumcheckPowLens[i];
            input.sumcheckPowWitnesses = _slice(ctx.sumcheckPow, ctx.scpOff, scp);
            ctx.scpOff += scp;
            input.sumcheckPowBits = ctx.schedFoldPowBits[i];

            WhirVerifierCore.RoundOutput memory out =
                WhirVerifierCore.verifyRound(t, s, input, carried);
            assertEq(out.gamma, ctx.roundBatching[i], "round gamma");
            assertEq(out.claimedEval, ctx.claimedEvals[i], "round claimed");
            assertEq(out.foldedClaim, ctx.foldedClaims[i], "round folded");
            uint256 rl = ctx.randomnessLens[i];
            assertEq(out.randomness, _slice(ctx.roundRandomness, ctx.randOff, rl), "round randomness");
            ctx.randOff += rl;
            // The folds: the contract's own Merkle+fold must match the prover's.
            uint256 fl = ctx.foldLens[i];
            assertEq(out.folds, _slice(ctx.folds, ctx.foldOff, fl), "round folds");
            ctx.foldOff += fl;

            carried = out.foldedClaim;
            lastRandomness = out.randomness;
            uint256[] memory grown = new uint256[](allRandomness.length + out.randomness.length);
            for (uint256 k; k < allRandomness.length; ++k) {
                grown[k] = allRandomness[k];
            }
            for (uint256 k; k < out.randomness.length; ++k) {
                grown[allRandomness.length + k] = out.randomness[k];
            }
            allRandomness = grown;
        }
        th = Threading(carried, lastRandomness, allRandomness);
    }

    /// The final phase: bind the public polynomial, terminal queries, closing
    /// sumcheck, and the terminal identity.
    function _runFinal(
        WhirVerifierCore.Transcript memory t,
        RoundCtx memory ctx,
        uint256 r,
        uint256 nInter,
        uint256 carried,
        uint256[] memory lastRandomness,
        uint256[] memory allRandomness
    ) private view {
        string memory R = ctx.R;
        WhirVerifierCore.FinalSchedule memory sf;
        sf.finalPolyConstants = 0;
        sf.roundIndex = nInter;
        sf.sumcheckConstants = ctx.framingSeps[ctx.sepIdx];

        WhirVerifierCore.FinalInput memory fi;
        fi.finalPoly = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_poly"));
        fi.lastCommitment = nInter == 0 ? ctx.batchCommitment : ctx.roundCommitments[nInter - 1];
        fi.powWitness = vm.parseJsonUint(ctx.j, string.concat(R, ".final_pow_witness"));
        fi.powBits = vm.parseJsonUint(ctx.j, string.concat(R, ".final_pow_bits"));
        fi.logFoldedDomainSize = vm.parseJsonUint(ctx.j, string.concat(R, ".final_log_folded"));
        uint256[] memory fPathLens = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_path_lens"));
        uint256 nqT = fPathLens.length;
        fi.numQueries = nqT;
        uint256 rowElemsT = uint256(1) << lastRandomness.length;
        fi.rowElems = rowElemsT;
        fi.rowLimbs = rowElemsT * 4;
        fi.rowsFlat = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_rows_ext"));
        bytes memory fPaths = vm.parseJsonBytes(ctx.j, string.concat(R, ".final_paths_hex"));
        fi.pathsFlat = _paths(fPaths, 0, fPathLens);
        fi.prevRandomness = lastRandomness;
        uint256[] memory fDomBase = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_domain_points"));
        fi.domainPoints = new uint256[](nqT);
        for (uint256 q; q < nqT; ++q) {
            fi.domainPoints[q] = KoalaBearExt4.fromBase(fDomBase[q]);
        }
        fi.sumcheckCA = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_sumcheck_ca"));
        fi.sumcheckCInf = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_sumcheck_cinf"));
        fi.sumcheckPowWitnesses = vm.parseJsonUintArray(ctx.j, string.concat(R, ".final_sumcheck_pow_witnesses"));
        fi.sumcheckPowBits = vm.parseJsonUint(ctx.j, string.concat(R, ".final_folding_pow_bits"));

        WhirVerifierCore.FinalOutput memory fout = WhirVerifierCore.verifyFinal(t, sf, fi, carried);
        assertEq(fout.foldedClaim, vm.parseJsonUint(ctx.j, string.concat(R, ".claimed_after_final")), "final folded");

        // The terminal identity (D-086 step A): verifyFinal no longer evaluates
        // it - the eval chain moved to the pinned TerminalWeight satellite, and
        // the equality became the caller's job. This harness is a caller, so it
        // checks it against TerminalRef, a separate contract holding the same
        // identity in plain Solidity: an independent second opinion on what the
        // satellite computes, and the only way the eval chain fits alongside the
        // final phase without blowing the stack.
        assertEq(
            fout.foldedClaim,
            terminalRef.expected(allRandomness, fout.randomness, _constraints(ctx.j, r), fi.finalPoly),
            "terminal identity (weight * poly(r))");
    }

    /// An array of `n` copies of `v`.
    function _repeat(uint256 v, uint256 n) private pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = v;
        }
    }
}
