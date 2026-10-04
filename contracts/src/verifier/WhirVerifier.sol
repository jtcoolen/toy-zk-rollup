// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {IWhirVerifier} from "../interfaces/IWhirVerifier.sol";
import {BatchTranscript} from "./BatchTranscript.sol";
import {WhirVerifierCore} from "./WhirVerifierCore.sol";
import {WhirGadgets} from "./WhirGadgets.sol";

/// The settlement verifier: replays `p3_batch_stark::verify_batch` at the
/// settlement shape, end to end, from one proof blob.
///
/// WIRE FORMAT (D-071, v3)
///
/// `proof` is a 16-byte header followed by three word sections (u32 little
/// endian): CONFIG (trusted-setup framing and schedule), PROOF (the prover's
/// bytes), STATEMENT (audit surface, not consumed here). The header pins the
/// magic `WBND`, the version, and the CONFIG/PROOF word counts, so the
/// decoder never guesses a boundary.
///
/// WHAT IS TRUSTED, WHAT IS DERIVED
///
/// CONFIG is deploy-time data: the batch framing prefix (seed, degree bits,
/// preprocessed digest, grind difficulties) and each opening round's schedule
/// and framing labels. A deployment should pin `keccak256(configSection)`.
/// PROOF is everything the prover sends: digests, public values, grind
/// witnesses, LogUp terminals, commitments, opening evaluations, sumcheck
/// round values, opened rows, Merkle paths, the public polynomial, and the
/// zeta-derived eq_points (D-072 phase 1).
///
/// Everything the transcript would derive - challenges, folds, claimed evals,
/// folding randomness, query indices, and every domain point - is recomputed
/// here, never read from the proof. The domain points in particular are
/// computed as `g^index` from the indices this verifier itself sampled
/// (D-072): the proof cannot steer the STIR checks by picking its own points.
///
/// THE WALK
///
/// One Keccak sponge runs the whole protocol: the batch phases first (seed,
/// degree bits, main digest + public values, preprocessed digest, lookup
/// grind + alpha/beta, permutation digest + terminals + constraint alpha,
/// quotient digests, ood grind + zeta), then each opening round's WHIR core
/// walk on the SAME sponge - the batch layer delegates to the PCS layer
/// without reseeding. Each round re-binds its framing constants (config bytes
/// consumed by count, D-070) and re-runs the claim from its own initial phase;
/// only the sponge is continuous.
///
/// The statement argument is the batch's public values (instance 5's
/// `[0, 1, 377841674]` at the pinned shape). They are absorbed into the
/// transcript from the PROOF section, so the verifier checks them against the
/// caller's statement before absorbing: a proof for different public values
/// cannot be replayed against this statement.
contract WhirVerifier is IWhirVerifier {
    using WhirVerifierCore for WhirVerifierCore.Transcript;

    /// The proof does not start with the WBND magic.
    error BadMagic();

    /// The wire magic: ASCII "WBND" (Whir Bundle).
    bytes4 private constant MAGIC = 0x5742_4e44;
    /// The proof section header is not version 3.
    error BadVersion(uint256 version);
    /// The proof is shorter than its own section table.
    error ProofTooShort();
    /// A proof public value disagrees with the caller's statement limb.
    error StatementMismatch(uint256 index);
    /// The statement carries a different number of public values than the proof.
    error StatementLengthMismatch(uint256 expected, uint256 actual);
    /// A schedule shape the decoder cannot represent (arity beyond the table).
    error UnsupportedShape(uint256 logSize);
    /// A digest blob that does not hold exactly 32 bytes.
    error BadDigestBlob();

    // ---------------------------------------------------------------------
    // Two-adic generators (canonical base elements)
    //
    // p3-koala-bear's TWO_ADIC_GENERATORS table: entry k is a 2^k-th primitive
    // root of unity, k up to TWO_ADICITY = 24 (p - 1 = 2^24 * 127). The folded
    // domains are indexed by log_folded_domain_size, so a query at index i on
    // the 2^k-sized folded domain sits at g_k^i.
    // ---------------------------------------------------------------------
    uint256 private constant G0 = 0x1;
    uint256 private constant G1 = 0x7f00_0000;
    uint256 private constant G2 = 0x7e01_0002;
    uint256 private constant G3 = 0x6832_fe4a;
    uint256 private constant G4 = 0x08db_d69c;
    uint256 private constant G5 = 0x0a28_f031;
    uint256 private constant G6 = 0x5c4a_5b99;
    uint256 private constant G7 = 0x29b7_5a80;
    uint256 private constant G8 = 0x1766_8b8a;
    uint256 private constant G9 = 0x27ad_539b;
    uint256 private constant G10 = 0x334d_48c7;
    uint256 private constant G11 = 0x7744_959c;
    uint256 private constant G12 = 0x768f_c6fa;
    uint256 private constant G13 = 0x3039_64b2;
    uint256 private constant G14 = 0x3e68_7d4d;
    uint256 private constant G15 = 0x45a6_0e61;
    uint256 private constant G16 = 0x6e2f_4d7a;
    uint256 private constant G17 = 0x163b_d499;
    uint256 private constant G18 = 0x6c4a_8a45;
    uint256 private constant G19 = 0x143e_f899;
    uint256 private constant G20 = 0x514d_dcad;
    uint256 private constant G21 = 0x484e_f19b;
    uint256 private constant G22 = 0x205d_63c3;
    uint256 private constant G23 = 0x68e7_dd49;
    uint256 private constant G24 = 0x6ac4_9f88;

    /// The 2^k-th primitive root of unity, canonical base element.
    function twoAdicGenerator(uint256 k) public pure returns (uint256) {
        if (k == 0) return G0;
        if (k == 1) return G1;
        if (k == 2) return G2;
        if (k == 3) return G3;
        if (k == 4) return G4;
        if (k == 5) return G5;
        if (k == 6) return G6;
        if (k == 7) return G7;
        if (k == 8) return G8;
        if (k == 9) return G9;
        if (k == 10) return G10;
        if (k == 11) return G11;
        if (k == 12) return G12;
        if (k == 13) return G13;
        if (k == 14) return G14;
        if (k == 15) return G15;
        if (k == 16) return G16;
        if (k == 17) return G17;
        if (k == 18) return G18;
        if (k == 19) return G19;
        if (k == 20) return G20;
        if (k == 21) return G21;
        if (k == 22) return G22;
        if (k == 23) return G23;
        if (k == 24) return G24;
        revert UnsupportedShape(k);
    }

    // ---------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------

    /// Replay the batch verification. Reverts on any failure; returns true only
    /// when every challenge, opening, and the terminal identity check out.
    function verify(uint256[] calldata statement, bytes calldata proof)
        external
        pure
        override
        returns (bool)
    {
        bytes memory m = proof;
        if (m.length < 16) revert ProofTooShort();
        bytes4 magic;
        assembly ("memory-safe") {
            // bytes memory: the length word sits at m, the data at m+32.
            magic := mload(add(m, 32))
        }
        if (magic != MAGIC) revert BadMagic();
        uint256 version;
        uint256 cfgWords;
        uint256 prfWords;
        assembly ("memory-safe") {
            // One version byte at offset 4, then two u32 LE section lengths at
            // offsets 8 and 12. The data starts at m+32, and mload reads
            // big-endian-aligned, so the field at proof offset X sits in the TOP
            // bytes of the word loaded at m+32+X.
            version := shr(248, mload(add(m, 36)))
            cfgWords := shr(224, mload(add(m, 40)))
            prfWords := shr(224, mload(add(m, 44)))
        }
        // The u32 LE fields need a byte swap; the version byte does not.
        cfgWords = _swapBytes(cfgWords);
        prfWords = _swapBytes(prfWords);
        if (version != 3) revert BadVersion(version);
        if (m.length < 16 + (cfgWords + prfWords) * 4) revert ProofTooShort();

        // Word offsets into the proof data: the 16-byte header is 4 words, so
        // CONFIG starts at word 4 and PROOF right after the CONFIG words.
        uint256 co = 4;
        uint256 po = 4 + cfgWords;

        BatchCfg memory cfg;
        (cfg, co) = _decodeBatchCfg(m, co);
        BatchPrf memory prf;
        (prf, po) = _decodeBatchPrf(m, po);
        _checkStatement(prf.pvBytes, statement);

        // --- the batch transcript walk -------------------------------------------
        BatchTranscript.State memory s = BatchTranscript.begin(cfg.seedBytes, cfg.degreeBytes);
        BatchTranscript.mainPhase(s, prf.mainDigest, prf.pvBytes);
        BatchTranscript.preprocessedPhase(s, cfg.preDigest);
        BatchTranscript.lookupPhase(s, cfg.lookupPowBits, prf.lookupPow);
        BatchTranscript.permutationPhase(s, prf.permDigest, prf.terminals);
        BatchTranscript.quotientPhase(s, prf.quotDigest, prf.randDigest);
        BatchTranscript.oodPhase(s, cfg.oodPowBits, prf.oodPow);

        // Hand the sponge to the WHIR core: the batch layer delegates to the PCS
        // layer on the SAME challenger, so no reseed happens here.
        WhirVerifierCore.Transcript memory t;
        t.state = s.sponge;

        // --- CONFIG: schedule ------------------------------------------------------
        uint256 numRounds;
        (numRounds, co) = _word(m, co);
        // round_starts is a test-harness artifact (per-round sponge seeding);
        // the on-chain walk is continuous, so it is skipped, not consumed.
        (, co) = _arr(m, co);

        // --- per opening round -------------------------------------------------------
        for (uint256 r; r < numRounds; ++r) {
            RoundCfg memory c;
            (c, co) = _decodeRoundCfg(m, co);
            RoundPrf memory p;
            (p, po) = _decodeRoundPrf(m, po);
            _runRound(t, c, p);
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Batch-layer section decode
    // ---------------------------------------------------------------------

    /// The batch framing prefix from CONFIG.
    struct BatchCfg {
        bytes seedBytes;
        bytes degreeBytes;
        bytes32 preDigest;
        uint256 lookupPowBits;
        uint256 oodPowBits;
    }

    /// The batch layer's varying absorbs from PROOF.
    struct BatchPrf {
        bytes32 mainDigest;
        bytes pvBytes;
        uint256 lookupPow;
        bytes32 permDigest;
        uint256[] terminals;
        bytes32 quotDigest;
        bytes32 randDigest;
        uint256 oodPow;
    }

    function _decodeBatchCfg(bytes memory m, uint256 off)
        private
        pure
        returns (BatchCfg memory c, uint256 no)
    {
        uint256 len;
        (len, no) = _word(m, off);
        uint256 end = no + len; // len counts words, no is a word offset
        (c.seedBytes, no) = _blob(m, no);
        (c.degreeBytes, no) = _blob(m, no);
        (c.preDigest, no) = _raw32(m, no);
        (c.lookupPowBits, no) = _word(m, no);
        (c.oodPowBits, no) = _word(m, no);
        if (no != end) revert ProofTooShort();
    }

    function _decodeBatchPrf(bytes memory m, uint256 off)
        private
        pure
        returns (BatchPrf memory p, uint256 no)
    {
        uint256 len;
        (len, no) = _word(m, off);
        uint256 end = no + len; // len counts words, no is a word offset
        (p.mainDigest, no) = _raw32(m, no);
        (p.pvBytes, no) = _blob(m, no);
        (p.lookupPow, no) = _word(m, no);
        (p.permDigest, no) = _raw32(m, no);
        (p.terminals, no) = _raw32Arr(m, no);
        (p.quotDigest, no) = _raw32(m, no);
        (p.randDigest, no) = _raw32(m, no);
        (p.oodPow, no) = _word(m, no);
        if (no != end) revert ProofTooShort();
        // The proof section repeats the round count as a sanity anchor; skip it
        // (the CONFIG count drives the loop).
        (, no) = _word(m, no);
    }

    /// The public values the proof absorbs must be the caller's statement: this
    /// is the only seam between "a valid proof" and "a valid proof of THIS
    /// statement". The blob stores them as u32 LE words in Montgomery form -
    /// p3's challenger serializes the internal representation - while the
    /// statement is canonical, so the comparison converts.
    function _checkStatement(bytes memory pvBytes, uint256[] calldata statement) private pure {
        uint256 pvCount = pvBytes.length / 4;
        if (statement.length != pvCount) {
            revert StatementLengthMismatch(pvCount, statement.length);
        }
        for (uint256 i; i < pvCount; ++i) {
            uint256 v;
            assembly ("memory-safe") {
                v := shr(224, mload(add(add(pvBytes, 32), mul(i, 4))))
            }
            if (mulmod(statement[i], MONTGOMERY_R, FIELD_P) != _swapBytes(v)) {
                revert StatementMismatch(i);
            }
        }
    }

    /// KoalaBear modulus and Montgomery constant (2^32 mod p).
    uint256 private constant FIELD_P = 2130706433;
    uint256 private constant MONTGOMERY_R = 33554430;

    // ---------------------------------------------------------------------
    // One opening round: initial phase, intermediate rounds, final phase
    // ---------------------------------------------------------------------

    /// Values threaded out of the intermediate loop: memory reassignment inside
    /// a function is invisible to the caller, so the loop returns its updated
    /// claim and randomness explicitly.
    struct Threading {
        uint256 carried;
        uint256[] lastRandomness;
        uint256[] allRandomness;
    }

    function _runRound(
        WhirVerifierCore.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p
    ) private pure {
        // Each round re-binds its framing constants (D-070): the config bytes are
        // consumed by count, and the cursor restarts with the round.
        t.constants = c.framingHex;
        t.constOff = 0;

        // --- initial phase ---------------------------------------------------------
        WhirVerifierCore.InitialSchedule memory s0;
        s0.preClaimsConstants = c.framingPre;
        s0.perClaimConstants = c.framingClaim;
        s0.batchingConstants = c.framingBatching;
        s0.sumcheckConstants = c.framingSeps[0];

        WhirVerifierCore.InitialInput memory i0;
        i0.oodAnswers = p.initOodAnswers;
        i0.openingEvals = p.boundEvals;
        i0.claimWidths = c.claimWidths;
        i0.claimPerm = c.claimPerm;
        i0.roundCA = p.initScA;
        i0.roundCInf = p.initScInf;
        i0.powWitnesses = p.initScPow;
        i0.powBits = c.startingPowBits;

        WhirVerifierCore.InitialOutput memory init = WhirVerifierCore.verifyInitial(t, s0, i0);

        // The constraint weights the terminal identity consumes. The initial
        // constraint carries the equality groups (zeta-derived, proof-supplied,
        // D-072 phase 1); each intermediate round's constraint carries its drawn
        // OOD points expanded, and the query domain points computed in-circuit
        // from the indices the transcript sampled (D-072 phase 2).
        WhirGadgets.ConstraintWeight[] memory constraints =
            new WhirGadgets.ConstraintWeight[](1 + c.nInter);
        constraints[0].numVariables = c.numVariables;
        constraints[0].gamma = init.alpha;
        constraints[0].initialPower = 0;
        constraints[0].eqPoints = _ragged(p.eqPoints, c.eqPointsLens);

        Threading memory th = _runIntermediates(t, c, p, init, constraints);
        _runFinal(t, c, p, th, constraints);
    }

    /// Cursor positions into the flat proof arrays while walking the
    /// intermediate rounds. Bundled in one struct so the loop body does not
    /// need five separate stack slots.
    struct Cursors {
        uint256 oodOff;
        uint256 rowOff;
        uint256 scOff;
        uint256 scpOff;
        uint256 pathOff;
    }

    /// What one intermediate round hands to the next.
    struct Step {
        uint256 carried;
        uint256[] lastRandomness;
        uint256[] allRandomness;
    }

    function _runIntermediates(
        WhirVerifierCore.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        WhirVerifierCore.InitialOutput memory init,
        WhirGadgets.ConstraintWeight[] memory constraints
    ) private pure returns (Threading memory th) {
        Cursors memory cur;
        Step memory st = Step(init.foldedClaim, init.randomness, init.randomness);
        for (uint256 i; i < c.nInter; ++i) {
            _runOneIntermediate(t, c, p, i, cur, st, constraints);
        }
        th = Threading(st.carried, st.lastRandomness, st.allRandomness);
    }

    function _runOneIntermediate(
        WhirVerifierCore.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        uint256 i,
        Cursors memory cur,
        Step memory st,
        WhirGadgets.ConstraintWeight[] memory constraints
    ) private pure {
        WhirVerifierCore.RoundSchedule memory s;
        s.roundIndex = i;
        s.oodSamples = c.schedOodSamples[i];
        s.sumcheckConstants = c.framingSeps[1 + i];

        WhirVerifierCore.RoundInput memory input;
        input.commitment = p.roundCommitments[i];
        input.prevCommitment = i == 0 ? p.batchCommitment : p.roundCommitments[i - 1];
        uint256 os = p.oodAnswerLens[i];
        input.oodAnswers = _slice(p.oodAnswers, cur.oodOff, os);
        cur.oodOff += os;
        input.powWitness = p.powWitnesses[i];
        input.powBits = c.schedPowBits[i];
        input.logFoldedDomainSize = c.schedLogFolded[i];
        uint256 nq = c.schedNumQueries[i];
        input.numQueries = nq;

        uint256 rowElems = uint256(1) << st.lastRandomness.length;
        bool rowsAreBase = c.rowsIsBase[i] == 1;
        input.rowElems = rowElems;
        input.rowLimbs = rowElems * (rowsAreBase ? 1 : 4);
        input.rowsAreBase = rowsAreBase;
        input.rowsFlat = _slice(p.rowsFlat, cur.rowOff, nq * input.rowLimbs);
        cur.rowOff += nq * input.rowLimbs;

        // Every query in round i opens at depth sched_log_folded[i].
        uint256 depth = c.schedLogFolded[i];
        input.paths = _paths(p.pathsBlob, cur.pathOff, _repeat(depth, nq));
        cur.pathOff += nq * depth;

        input.prevRandomness = st.lastRandomness;
        uint256 scr = p.scLens[i];
        input.sumcheckCA = _slice(p.scA, cur.scOff, scr);
        input.sumcheckCInf = _slice(p.scInf, cur.scOff, scr);
        cur.scOff += scr;
        uint256 scp = p.scPowLens[i];
        input.sumcheckPowWitnesses = _slice(p.scPow, cur.scpOff, scp);
        cur.scpOff += scp;
        input.sumcheckPowBits = c.schedFoldPowBits[i];

        WhirVerifierCore.RoundOutput memory out =
            WhirVerifierCore.verifyRound(t, s, input, st.carried);

        // This round's constraint: equality groups from its drawn OOD points,
        // selection group from the domain points of its drawn indices.
        WhirGadgets.ConstraintWeight memory cw;
        cw.numVariables = c.params[i * 4];
        cw.gamma = out.gamma;
        cw.initialPower = 1;
        cw.eqPoints = new uint256[][](out.oodPoints.length);
        for (uint256 q; q < out.oodPoints.length; ++q) {
            cw.eqPoints[q] = WhirGadgets.expandFromUnivariate(out.oodPoints[q], cw.numVariables);
        }
        uint256 gen = twoAdicGenerator(c.schedLogFolded[i]);
        cw.selVars = new uint256[](out.queryIndices.length);
        for (uint256 q; q < out.queryIndices.length; ++q) {
            cw.selVars[q] = WhirGadgets.powConstBase(gen, out.queryIndices[q]);
        }
        constraints[1 + i] = cw;

        st.carried = out.foldedClaim;
        st.lastRandomness = out.randomness;
        st.allRandomness = _concat(st.allRandomness, out.randomness);
    }

    function _concat(uint256[] memory a, uint256[] memory b)
        private
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](a.length + b.length);
        for (uint256 k; k < a.length; ++k) {
            out[k] = a[k];
        }
        for (uint256 k; k < b.length; ++k) {
            out[a.length + k] = b[k];
        }
    }

    function _runFinal(
        WhirVerifierCore.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        Threading memory th,
        WhirGadgets.ConstraintWeight[] memory constraints
    ) private pure {
        uint256 nInter = c.nInter;
        WhirVerifierCore.FinalSchedule memory sf;
        sf.finalPolyConstants = 0;
        sf.roundIndex = nInter;
        // framingSeps[0] framed the initial sumcheck, [1+i] framed round i, so
        // the closing sumcheck's separator sits at 1 + nInter.
        sf.sumcheckConstants = c.framingSeps[1 + nInter];

        WhirVerifierCore.FinalInput memory fi;
        fi.finalPoly = p.finalPoly;
        fi.lastCommitment = nInter == 0 ? p.batchCommitment : p.roundCommitments[nInter - 1];
        fi.powWitness = p.finalPowWitness;
        fi.powBits = c.finalPowBits;
        fi.logFoldedDomainSize = c.finalLogFolded;
        uint256 nqT = c.finalNumQueries;
        fi.numQueries = nqT;
        uint256 rowElems = uint256(1) << th.lastRandomness.length;
        fi.rowElems = rowElems;
        fi.rowLimbs = rowElems * 4;
        fi.rowsFlat = p.finalRowsExt;
        fi.paths = _paths(p.finalPathsBlob, 0, _repeat(c.finalLogFolded, nqT));
        fi.prevRandomness = th.lastRandomness;
        // D-072 phase 2: the domain points are computed in-circuit from the
        // indices this verifier samples, not read from the proof.
        fi.domainGenerator = twoAdicGenerator(c.finalLogFolded);
        fi.sumcheckCA = p.finalScA;
        fi.sumcheckCInf = p.finalScInf;
        fi.sumcheckPowWitnesses = p.finalScPow;
        fi.sumcheckPowBits = c.finalFoldPowBits;
        fi.allRandomness = th.allRandomness;
        fi.constraints = constraints;

        WhirVerifierCore.verifyFinal(t, sf, fi, th.carried);
    }

    // ---------------------------------------------------------------------
    // Decoded section shapes
    // ---------------------------------------------------------------------

    /// One opening round's trusted-setup schedule (CONFIG section).
    struct RoundCfg {
        uint256 nInter;
        uint256[] claimPerm;
        bytes framingHex;
        uint256[] framingPre;
        uint256[] framingClaim;
        uint256 framingBatching;
        uint256[] framingSeps;
        uint256[] claimWidths;
        uint256[] eqPointsLens;
        uint256[] eqGroupLens;
        uint256 numVariables;
        uint256 startingPowBits;
        uint256 commitmentOodSamples;
        uint256[] schedPowBits;
        uint256[] schedFoldPowBits;
        uint256[] schedNumQueries;
        uint256[] schedOodSamples;
        uint256[] schedLogFolded;
        uint256[] schedLogInvRate;
        uint256 finalPowBits;
        uint256 finalFoldPowBits;
        uint256 finalNumQueries;
        uint256 finalLogFolded;
        uint256 finalLogInvRate;
        uint256[] params;
        uint256[] rowsIsBase;
    }

    /// One opening round's prover bytes (PROOF section).
    struct RoundPrf {
        bytes32 batchCommitment;
        uint256[] boundEvals;
        uint256[] initOodAnswers;
        uint256[] initScA;
        uint256[] initScInf;
        uint256[] initScPow;
        uint256[] rowsFlat;
        bytes pathsBlob;
        bytes32[] roundCommitments;
        uint256[] oodAnswers;
        uint256[] oodAnswerLens;
        uint256[] powWitnesses;
        uint256[] scA;
        uint256[] scInf;
        uint256[] scPow;
        uint256[] scLens;
        uint256[] scPowLens;
        uint256[] finalPoly;
        uint256 finalPowWitness;
        uint256[] finalRowsExt;
        bytes finalPathsBlob;
        uint256[] finalScA;
        uint256[] finalScInf;
        uint256[] finalScPow;
        uint256[] eqPoints;
    }

    function _decodeRoundCfg(bytes memory m, uint256 off)
        private
        pure
        returns (RoundCfg memory c, uint256 no)
    {
        no = off;
        (c.nInter, no) = _word(m, no);
        (c.claimPerm, no) = _arr(m, no);
        (c.framingHex, no) = _blob(m, no);
        (c.framingPre, no) = _arr(m, no);
        (c.framingClaim, no) = _arr(m, no);
        (c.framingBatching, no) = _word(m, no);
        (c.framingSeps, no) = _arr(m, no);
        (c.claimWidths, no) = _arr(m, no);
        (c.eqPointsLens, no) = _arr(m, no);
        (c.eqGroupLens, no) = _arr(m, no);
        (c.numVariables, no) = _word(m, no);
        (c.startingPowBits, no) = _word(m, no);
        (c.commitmentOodSamples, no) = _word(m, no);
        (c.schedPowBits, no) = _arr(m, no);
        (c.schedFoldPowBits, no) = _arr(m, no);
        (c.schedNumQueries, no) = _arr(m, no);
        (c.schedOodSamples, no) = _arr(m, no);
        (c.schedLogFolded, no) = _arr(m, no);
        (c.schedLogInvRate, no) = _arr(m, no);
        (c.finalPowBits, no) = _word(m, no);
        (c.finalFoldPowBits, no) = _word(m, no);
        (c.finalNumQueries, no) = _word(m, no);
        (c.finalLogFolded, no) = _word(m, no);
        (c.finalLogInvRate, no) = _word(m, no);
        (c.params, no) = _arr(m, no);
        (c.rowsIsBase, no) = _arr(m, no);
    }

    function _decodeRoundPrf(bytes memory m, uint256 off)
        private
        pure
        returns (RoundPrf memory p, uint256 no)
    {
        no = off;
        (p.batchCommitment, no) = _blob32(m, no);
        (p.boundEvals, no) = _extArr(m, no);
        (p.initOodAnswers, no) = _extArr(m, no);
        (p.initScA, no) = _extArr(m, no);
        (p.initScInf, no) = _extArr(m, no);
        (p.initScPow, no) = _arr(m, no);
        (p.rowsFlat, no) = _arr(m, no);
        (p.pathsBlob, no) = _blob(m, no);
        (p.roundCommitments, no) = _blobArr32(m, no);
        (p.oodAnswers, no) = _extArr(m, no);
        (p.oodAnswerLens, no) = _arr(m, no);
        (p.powWitnesses, no) = _arr(m, no);
        (p.scA, no) = _extArr(m, no);
        (p.scInf, no) = _extArr(m, no);
        (p.scPow, no) = _arr(m, no);
        (p.scLens, no) = _arr(m, no);
        (p.scPowLens, no) = _arr(m, no);
        (p.finalPoly, no) = _extArr(m, no);
        (p.finalPowWitness, no) = _word(m, no);
        (p.finalRowsExt, no) = _arr(m, no);
        (p.finalPathsBlob, no) = _blob(m, no);
        (p.finalScA, no) = _extArr(m, no);
        (p.finalScInf, no) = _extArr(m, no);
        (p.finalScPow, no) = _arr(m, no);
        (p.eqPoints, no) = _extArr(m, no);
    }

    // ---------------------------------------------------------------------
    // Section readers
    //
    // Every reader takes the section bytes and a WORD offset and returns the
    // value plus the next word offset. Words are u32 little endian on the
    // wire; mload reads big-endian-aligned, so a word read is shr(224) plus
    // a byte swap. 32-byte items (digests, packed extension elements) are
    // stored big-endian and read straight through.
    // ---------------------------------------------------------------------

    function _word(bytes memory d, uint256 off) private pure returns (uint256 v, uint256 no) {
        assembly {
            v := shr(224, mload(add(add(d, 32), mul(off, 4))))
        }
        v = _swapBytes(v);
        no = off + 1;
    }

    function _arr(bytes memory d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 n;
        (n, no) = _word(d, off);
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            (out[i], no) = _word(d, no);
        }
    }

    /// A byte blob: word count, then raw bytes (padded to a word boundary).
    function _blob(bytes memory d, uint256 off)
        private
        pure
        returns (bytes memory out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        out = new bytes(nBytes);
        uint256 words = (nBytes + 3) / 4;
        assembly {
            // The allocation has roundup32(nBytes) usable bytes after the length
            // word; copy exactly that many, no more, so the tail store stays
            // inside this allocation.
            let usable := and(add(nBytes, 31), not(31))
            let src := add(add(d, 32), mul(no, 4))
            let dst := add(out, 32)
            for { let i := 0 } lt(i, usable) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
        no += words;
    }

    /// A blob holding exactly one 32-byte big-endian item (a digest).
    function _blob32(bytes memory d, uint256 off)
        private
        pure
        returns (bytes32 out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        if (nBytes != 32) revert BadDigestBlob();
        assembly {
            out := mload(add(add(d, 32), mul(no, 4)))
        }
        no += 8;
    }

    /// A blob holding a sequence of 32-byte big-endian items (Merkle paths,
    /// commitment lists): returned as a bytes blob the ragged readers index.
    function _blobArr32(bytes memory d, uint256 off)
        private
        pure
        returns (bytes32[] memory out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        uint256 n = nBytes / 32;
        out = new bytes32[](n);
        assembly {
            let dst := add(out, 32)
            let srcBase := add(add(d, 32), mul(no, 4))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(dst, mul(i, 32)), mload(add(srcBase, mul(i, 32))))
            }
        }
        no += nBytes / 4;
    }

    /// Raw 32-byte items WITHOUT a length prefix (the batch prefix digests).
    function _raw32(bytes memory d, uint256 off)
        private
        pure
        returns (bytes32 out, uint256 no)
    {
        assembly {
            out := mload(add(add(d, 32), mul(off, 4)))
        }
        no = off + 8;
    }

    /// A count word followed by that many raw 32-byte items (terminals).
    function _raw32Arr(bytes memory d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 n;
        (n, no) = _word(d, off);
        out = new uint256[](n);
        assembly {
            let dst := add(out, 32)
            let srcBase := add(add(d, 32), mul(no, 4))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(dst, mul(i, 32)), mload(add(srcBase, mul(i, 32))))
            }
        }
        no += n << 3;
    }

    /// A blob of 32-byte packed extension elements, returned as uint256 words.
    function _extArr(bytes memory d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        uint256 n = nBytes / 32;
        out = new uint256[](n);
        assembly {
            let dst := add(out, 32)
            let srcBase := add(add(d, 32), mul(no, 4))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(dst, mul(i, 32)), mload(add(srcBase, mul(i, 32))))
            }
        }
        no += nBytes / 4;
    }

    // ---------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------

    function _swapBytes(uint256 v) private pure returns (uint256 r) {
        r = v & 0xffff_ffff;
        r = ((r & 0xff00_ff00) >> 8) | ((r & 0x00ff_00ff) << 8);
        r = ((r & 0xffff_0000) >> 16) | ((r & 0x0000_ffff) << 16);
    }

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

    function _ragged(uint256[] memory flat, uint256[] memory lens)
        private
        pure
        returns (uint256[][] memory out)
    {
        out = new uint256[][](lens.length);
        uint256 off = 0;
        for (uint256 i; i < lens.length; ++i) {
            out[i] = new uint256[](lens[i]);
            for (uint256 j; j < lens[i]; ++j) {
                out[i][j] = flat[off + j];
            }
            off += lens[i];
        }
    }

    function _node(bytes memory blob, uint256 idx) private pure returns (bytes32 out) {
        assembly ("memory-safe") {
            out := mload(add(add(blob, 32), mul(idx, 32)))
        }
    }

    function _paths(bytes memory blob, uint256 start, uint256[] memory lens)
        private
        pure
        returns (bytes32[][] memory out)
    {
        out = new bytes32[][](lens.length);
        uint256 off = start;
        for (uint256 i; i < lens.length; ++i) {
            out[i] = new bytes32[](lens[i]);
            for (uint256 j; j < lens[i]; ++j) {
                out[i][j] = _node(blob, off + j);
            }
            off += lens[i];
        }
    }

    function _repeat(uint256 v, uint256 n) private pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = v;
        }
    }
}
