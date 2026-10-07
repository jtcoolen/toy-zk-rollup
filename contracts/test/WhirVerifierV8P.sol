// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {BatchTranscript} from "../src/verifier/BatchTranscript.sol";
import {WhirVerifierCoreV8P} from "./WhirVerifierCoreV8P.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";

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
contract WhirVerifierV8P {
    event P(string s);
    function _log(string memory s) private { emit P(s); }
    function _logr(string memory s, uint256 r) private {
        emit P(string(abi.encodePacked(s, vm2str(r))));
    }
    function vm2str(uint256 r) private pure returns (string memory) {
        if (r == 0) return "0";
        uint256 n = r; uint256 len;
        while (n > 0) { len++; n /= 10; }
        bytes memory b = new bytes(len);
        while (r > 0) { len--; b[len] = bytes1(uint8(48 + r % 10)); r /= 10; }
        return string(b);
    }
    uint256[] public profileData;
    using WhirVerifierCoreV8P for WhirVerifierCoreV8P.Transcript;
    using KoalaBearExt4 for uint256;

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

    /// A packed extension element on the wire carried a nonzero low-128-bit
    /// padding region. The padding is not part of the field element and every
    /// consumer reduces lanes mod P, so a nonzero padding is a second
    /// representation of the same element - proof malleability. The honest
    /// encoder always zeroes it; rejecting at decode closes it for every
    /// consumer at once. (Lanes at or above P are tolerated: they reduce to
    /// their canonical value in every consumer, exactly as before.)

    /// The LogUp terminals must sum to zero across the batch: each AIR commits one
    /// terminal (the sum of its per-row rational contributions), and the batch is
    /// only satisfiable if they cancel. p3 verify_batch ends with exactly this
    /// check (p3-lookup LogUpGadget::verify_terminal_sum); without it a prover
    /// could balance nothing and still pass the opening argument.
    error TerminalSumNonZero();

    /// The constraint identity failed for instance i: fold(alpha, C(zeta)) *
    /// inv_vanishing(zeta) != quotient(zeta) on the derived opened values.
    error ConstraintIdentityMismatch(uint256 instance);

    /// The CONSTRAINTS section is missing or misframed (wire v4).
    error BadConstraints();

    /// The terminal-weight satellite's runtime code is not the code pinned at
    /// construction. Checked before every call (D-086 step A). The satellite can
    /// only make verification FAIL - the caller does the final equality - so a
    /// swap is not a soundness hole, but the pin is what makes one loud.
    error SatelliteUnpinned();

    /// The satellite did not answer with a well-formed [magic, weight, value]
    /// reply. Its own revert data bubbles up when it carried any.
    error SatelliteCallFailed();

    /// The terminal identity failed: the claim does not equal the constraint
    /// weight times the polynomial evaluation. This is the verifier's last
    /// line: everything before it is Fiat-Shamir bookkeeping.
    error TerminalClaimMismatch(uint256 expected, uint256 actual);

    /// The terminal-weight frame magic: ASCII "TWIGHT", matching TerminalWeight.
    uint256 private constant TERMINAL_MAGIC = 0x5457_4947_4854;

    /// The pinned TerminalWeight satellite: the terminal weight and value, out
    /// of the core's bytecode and into a contract of its own (D-086 step A).
    address private immutable SATELLITE;

    /// `SATELLITE.codehash` as seen at construction, re-checked before every
    /// call. A satellite deployed behind a proxy or swapped afterwards is not
    /// the code the core was sized and reviewed against.
    bytes32 private immutable SATELLITE_CODEHASH;

    /// Pin the terminal-weight satellite. Empty code is rejected here rather
    /// than discovered as a failed call on the first verify.
    constructor(address terminalWeight) {
        if (terminalWeight == address(0) || terminalWeight.code.length == 0) {
            revert SatelliteUnpinned();
        }
        SATELLITE = terminalWeight;
        SATELLITE_CODEHASH = terminalWeight.codehash;
    }

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
    ///
    /// `view`, not `pure`: the terminal identity is evaluated by the pinned
    /// TerminalWeight satellite over a staticcall (D-086 step A), which keeps
    /// the eval chain out of this contract's bytecode. Everything else here
    /// reads nothing but the arguments.
    function verify(uint256[] calldata statement, bytes calldata proof)
        external
        returns (bool)
    {
        _logr("enter gasleft ", gasleft());
        uint256[] memory acc = new uint256[](200);
        uint256 _g;
        // The proof is read straight from CALLODATA: every reader below is a
        // calldataload, so the 2.8 MB bundle is never copied into memory. The
        // copy alone measured 92.4M gas (memory expansion + refill) on the real
        // bundle - the single largest item after the open path.
        if (proof.length < 16) revert ProofTooShort();
        bytes4 magic;
        uint256 version;
        uint256 cfgWords;
        uint256 prfWords;
        assembly ("memory-safe") {
            // calldataload is big-endian-aligned like mload: the field at proof
            // byte offset X sits in the TOP bytes of the word loaded at
            // proof.offset + X.
            magic := calldataload(proof.offset)
            version := shr(248, calldataload(add(proof.offset, 4)))
            cfgWords := shr(224, calldataload(add(proof.offset, 8)))
            prfWords := shr(224, calldataload(add(proof.offset, 12)))
        }
        if (magic != MAGIC) revert BadMagic();
        // The u32 LE fields need a byte swap; the version byte does not.
        cfgWords = _swapBytes(cfgWords);
        prfWords = _swapBytes(prfWords);
        // v5: full bundle. v7: same grammar, PROOF ext arrays compacted to
        // 16-byte limbs with an in-band flag per array (D-092 batch 41). v8:
        // intermediate Merkle paths pruned to the query frontier, digests
        // amortized across queries (D-092 batch 42). v6 bundles are re-framed
        // by WhirVerifierV6 and never arrive as 6.
        if (version != 5 && version != 7 && version != 8) revert BadVersion(version);
        if (proof.length < 20 + (cfgWords + prfWords) * 4) revert ProofTooShort();
        // v5 header tail: u32 LE STATEMENT word count right after PROOF.
        StmRef memory stm;
        assembly ("memory-safe") {
            // shr(224) leaves the u32's four bytes big-endian in the LOW 32
            // bits: b0 (the LE LSB) at bits 31..24. Reverse for the LE value.
            let w := shr(224, calldataload(add(proof.offset, add(16, mul(add(cfgWords, prfWords), 4)))))
            w := or(
                or(and(shr(24, w), 0xff), and(shr(8, w), 0xff00)),
                or(and(shl(8, w), 0xff0000), and(shl(24, w), 0xff000000))
            )
            mstore(stm, mul(w, 4)) // len
            mstore(add(stm, 32), add(proof.offset, mul(add(5, add(cfgWords, prfWords)), 4))) // abs
        }
        if (proof.length < 20 + (cfgWords + prfWords) * 4 + stm.len) revert ProofTooShort();

        // Word offsets into the proof data: the 16-byte header is 4 words, so
        // CONFIG starts at word 4 and PROOF right after the CONFIG words.
        uint256 co = 4;
        uint256 po = 4 + cfgWords;

        _g = gasleft();
        BatchCfg memory cfg;
        (cfg, co) = _decodeBatchCfg(proof, co);
        BatchPrf memory prf;
        (prf, po) = _decodeBatchPrf(proof, po);
        _checkStatement(prf.pvBytes, statement);
        acc[0] += _g - gasleft();
        _logr("decode done gasleft ", gasleft());
        _g = gasleft();

        // --- post-opening check: the LogUp terminal sum ---------------------------
        // Mirrors verify_batch's final lookup_gadget.verify_terminal_sum: the
        // terminals are proof-supplied extension elements (packed limbs at bits
        // 224/192/160/128, canonical) and must sum to zero in the extension field.
        // Independent of transcript state, so it runs fail-fast before the round
        // loop: one packed add per terminal, no inversions.
        uint256 terminalSum = 0;
        for (uint256 i; i < prf.terminals.length; ++i) {
            terminalSum = KoalaBearExt4.add(terminalSum, prf.terminals[i]);
        }
        if (terminalSum != 0) revert TerminalSumNonZero();

        // --- the batch transcript walk -------------------------------------------
        BatchTranscript.State memory s = BatchTranscript.begin(cfg.seedBytes, cfg.degreeBytes);
        BatchTranscript.mainPhase(s, prf.mainDigest, prf.pvBytes);
        BatchTranscript.preprocessedPhase(s, cfg.preDigest);
        (uint256 lookupAlpha, uint256 beta) =
            BatchTranscript.lookupPhase(s, cfg.lookupPowBits, prf.lookupPow);
        uint256 constraintAlpha =
            BatchTranscript.permutationPhase(s, prf.permDigest, prf.terminals);
        BatchTranscript.quotientPhase(s, prf.quotDigest, prf.randDigest);
        uint256 zeta = BatchTranscript.oodPhase(s, cfg.oodPowBits, prf.oodPow);
        acc[1] += _g - gasleft();
        _logr("batch transcript done gasleft ", gasleft());

        // Hand the sponge to the WHIR core: the batch layer delegates to the PCS
        // layer on the SAME challenger, so no reseed happens here.
        WhirVerifierCoreV8P.Transcript memory t;
        t.state = s.sponge;

        // --- CONFIG: schedule + per opening round -------------------------------
        // The constraint identity (D-076) needs each round's bound evaluations
        // after the walk: keep them (rounds 1..4; round 0 is the random round).
        uint256[][] memory boundEvalsOf;
        (co, boundEvalsOf) = _runRounds(proof, co, po, t, stm, acc);

        // --- the constraint identity (D-076), on the satellite (batch 48) -------
        // The last layer of verify_batch: per instance, recompute every opened
        // value from the bound evaluations this walk just verified, then check
        // fold(alpha, C(zeta)) * inv_vanishing(zeta) == quotient(zeta). The
        // programs and domain constants are CONFIG (trusted setup, v4 tail):
        // the engine skips the section and ships it verbatim to TerminalWeight,
        // which parses it and reverts on any mismatch - the codehash pin makes
        // that verdict authoritative, exactly as for MROOTS.
        uint256 csWords;
        (csWords, co) = _word(proof, co);
        _g = gasleft();
        _callIdentity(
            zeta, constraintAlpha, lookupAlpha, beta, prf.terminals, statement,
            proof, co, csWords, boundEvalsOf
        );
        acc[6] += _g - gasleft();
        _log("identity done");
        profileData = acc;

        return true;
    }

    /// Walk the schedule: decode each round's CONFIG + PROOF blocks and run
    /// its WHIR opening. Split out of verify() purely for stack depth - the
    /// post-loop values (zeta, the alphas) no longer have to stay live
    /// through the loop body. Returns the config cursor and each round's
    /// bound evaluations.
    function _runRounds(
        bytes calldata proof,
        uint256 co,
        uint256 po,
        WhirVerifierCoreV8P.Transcript memory t,
        StmRef memory stm,
        uint256[] memory acc
    ) private returns (uint256 no, uint256[][] memory boundEvalsOf) {
        uint256 numRounds;
        (numRounds, no) = _word(proof, co);
        boundEvalsOf = new uint256[][](numRounds);
        // round_starts is a test-harness artifact (per-round sponge seeding);
        // the on-chain walk is continuous, so it is skipped, not consumed.
        (, no) = _arr(proof, no);
        for (uint256 r; r < numRounds; ++r) {
            uint256 _gd = gasleft();
            RoundCfg memory c;
            (c, no) = _decodeRoundCfg(proof, no);
            RoundPrf memory p;
            (p, po) = _decodeRoundPrf(proof, po);
            acc[7] += _gd - gasleft();
            boundEvalsOf[r] = p.boundEvals;
            _logr("round ", r);
            _logr("  pre gasleft ", gasleft());
            _runRound(t, c, p, stm, r, acc);
            _logr("  post gasleft ", gasleft());
        }
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

    function _decodeBatchCfg(bytes calldata m, uint256 off)
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

    function _decodeBatchPrf(bytes calldata m, uint256 off)
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

    /// Where the raw STATEMENT section lives in the proof calldata (v5).
    struct StmRef {
        uint256 len;
        uint256 abs;
    }

    function _runRound(
        WhirVerifierCoreV8P.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        StmRef memory stm,
        uint256 roundIdx,
        uint256[] memory acc
    ) private view {
        uint256 base = 10 + roundIdx * 32;
        t.acc = acc;
        t.base = base;
        // Each round re-binds its framing constants (D-070): the config bytes are
        // consumed by count, and the cursor restarts with the round.
        t.constants = c.framingHex;
        t.constOff = 0;

        // --- initial phase ---------------------------------------------------------
        WhirVerifierCoreV8P.InitialSchedule memory s0;
        s0.preClaimsConstants = c.framingPre;
        s0.perClaimConstants = c.framingClaim;
        s0.batchingConstants = c.framingBatching;
        s0.sumcheckConstants = c.framingSeps[0];

        WhirVerifierCoreV8P.InitialInput memory i0;
        i0.oodAnswers = p.initOodAnswers;
        i0.openingEvals = p.boundEvals;
        i0.claimWidths = c.claimWidths;
        i0.claimPerm = c.claimPerm;
        i0.roundCA = p.initScA;
        i0.roundCInf = p.initScInf;
        i0.powWitnesses = p.initScPow;
        i0.powBits = c.startingPowBits;

        uint256 _gi = gasleft();
        WhirVerifierCoreV8P.InitialOutput memory init = WhirVerifierCoreV8P.verifyInitial(t, s0, i0);
        acc[base + 0] += _gi - gasleft();

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
        // Mode 2 (D-086 step C): the eq groups are DERIVED from the public
        // STATEMENT section (opening points) plus the transcript-drawn virtual
        // claim points - the satellite walks the slice itself, nothing
        // proof-supplied enters the weight.
        constraints[0].stmCdBase = stm.abs;
        constraints[0].stmLen = stm.len;
        constraints[0].stmRound = roundIdx;
        constraints[0].virtualPoints = init.virtualPoints;

        Threading memory th = _runIntermediates(t, c, p, init, constraints, acc, base);
        _runFinal(t, c, p, th, constraints, acc, base);
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
        WhirVerifierCoreV8P.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        WhirVerifierCoreV8P.InitialOutput memory init,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory acc,
        uint256 base
    ) private view returns (Threading memory th) {
        Cursors memory cur;
        Step memory st = Step(init.foldedClaim, init.randomness, init.randomness);
        for (uint256 i; i < c.nInter; ++i) {
            _runOneIntermediate(t, c, p, i, cur, st, constraints, acc, base);
        }
        th = Threading(st.carried, st.lastRandomness, st.allRandomness);
    }

    function _runOneIntermediate(
        WhirVerifierCoreV8P.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        uint256 i,
        Cursors memory cur,
        Step memory st,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory acc,
        uint256 base
    ) private view {
        WhirVerifierCoreV8P.RoundSchedule memory s;
        s.roundIndex = i;
        s.oodSamples = c.schedOodSamples[i];
        s.sumcheckConstants = c.framingSeps[1 + i];

        WhirVerifierCoreV8P.RoundInput memory input;
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
        input.rowsCdBase = p.rowsAbs + cur.rowOff * 4;
        input.rowsLen = nq * input.rowLimbs;
        cur.rowOff += nq * input.rowLimbs;

        // Every query in round i opens at depth sched_log_folded[i]. The
        // sibling grid stays in calldata: 750 KB read exactly once. v8
        // replaces the grid with one pruned stream per round, amortized
        // across queries and walked once on the satellite.
        uint256 depth = c.schedLogFolded[i];
        input.pathsCdBase = p.pathsAbs + cur.pathOff * 32;
        if (p.prunedLens.length == 0) {
            cur.pathOff += nq * depth;
        } else {
            input.prunedNDigests = p.prunedLens[i];
            cur.pathOff += input.prunedNDigests;
        }

        input.prevRandomness = st.lastRandomness;
        input.satellite = SATELLITE;
        input.satelliteCodehash = SATELLITE_CODEHASH;
        uint256 scr = p.scLens[i];
        input.sumcheckCA = _slice(p.scA, cur.scOff, scr);
        input.sumcheckCInf = _slice(p.scInf, cur.scOff, scr);
        cur.scOff += scr;
        uint256 scp = p.scPowLens[i];
        input.sumcheckPowWitnesses = _slice(p.scPow, cur.scpOff, scp);
        cur.scpOff += scp;
        input.sumcheckPowBits = c.schedFoldPowBits[i];

        uint256 _gr = gasleft();
        WhirVerifierCoreV8P.RoundOutput memory out =
            WhirVerifierCoreV8P.verifyRound(t, s, input, st.carried);
        acc[base + 1] += _gr - gasleft();

        // This round's constraint: equality groups from its drawn OOD points,
        // selection group from the domain points of its drawn indices.
        uint256 _gc = gasleft();
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
        acc[base + 3] += _gc - gasleft();

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
        WhirVerifierCoreV8P.Transcript memory t,
        RoundCfg memory c,
        RoundPrf memory p,
        Threading memory th,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory acc,
        uint256 base
    ) private view {
        uint256 nInter = c.nInter;
        WhirVerifierCoreV8P.FinalSchedule memory sf;
        sf.finalPolyConstants = 0;
        sf.roundIndex = nInter;
        // framingSeps[0] framed the initial sumcheck, [1+i] framed round i, so
        // the closing sumcheck's separator sits at 1 + nInter.
        sf.sumcheckConstants = c.framingSeps[1 + nInter];

        WhirVerifierCoreV8P.FinalInput memory fi;
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
        fi.rowsCdBase = p.finalRowsAbs;
        fi.rowsLen = p.finalRowsLen;
        fi.pathsCdBase = p.finalPathsAbs;
        fi.prevRandomness = th.lastRandomness;
        // D-072 phase 2: the domain points are computed in-circuit from the
        // indices this verifier samples, not read from the proof.
        fi.domainGenerator = twoAdicGenerator(c.finalLogFolded);
        fi.sumcheckCA = p.finalScA;
        fi.sumcheckCInf = p.finalScInf;
        fi.sumcheckPowWitnesses = p.finalScPow;
        fi.sumcheckPowBits = c.finalFoldPowBits;

        uint256 _gv = gasleft();
        WhirVerifierCoreV8P.FinalOutput memory out =
            WhirVerifierCoreV8P.verifyFinal(t, sf, fi, th.carried);
        acc[base + 4] += _gv - gasleft();

        // The terminal identity, the caller's job since D-086 step A. Its own
        // function: the frame packer's assembly block needs most of the stack
        // for itself and cannot share a stack frame with the final phase.
        uint256 _gt = gasleft();
        _checkTerminalIdentity(
            th.allRandomness, out.randomness, constraints, fi.finalPoly, out.foldedClaim);
        acc[base + 5] += _gt - gasleft();
    }

    /// The terminal identity (D-086 step A):
    ///
    ///     foldedClaim == eval_constraints_poly(all_r) * final_poly(final_r)
    ///
    /// all_r is every folding randomness in protocol order with the closing
    /// sumcheck's appended; each constraint reads the LAST k of them (Prefix
    /// order). The eval chain itself runs in the pinned TerminalWeight
    /// satellite - it is the largest single block of verifier bytecode and it
    /// runs once per round, so keeping it out of this contract is what leaves
    /// room under EIP-170. The EQUALITY is checked here, by the caller: a
    /// faulty or malicious satellite can only make verification FAIL.
    function _checkTerminalIdentity(
        uint256[] memory allRandomness,
        uint256[] memory closing,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory finalPoly,
        uint256 foldedClaim
    ) private view {
        uint256[] memory allR = _concat(allRandomness, closing);
        (uint256 weight, uint256 value) =
            _terminalWeight(allR, constraints, finalPoly, closing);
        uint256 expected = KoalaBearExt4.mul(weight, value);
        if (foldedClaim != expected) {
            revert TerminalClaimMismatch(expected, foldedClaim);
        }
    }

    /// Ask the pinned TerminalWeight satellite for the constraint weight at
    /// allR and the public polynomial at randomness.
    ///
    /// Split into pack + call so the frame builder stays its own function:
    /// inlined into the final phase, the assembly block's live set pushed the
    /// via-IR scheduler past the stack limit.
    function _terminalWeight(
        uint256[] memory allR,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory finalPoly,
        uint256[] memory randomness
    ) private view returns (uint256 weight, uint256 value) {
        (uint256 frame, uint256 size) =
            _packTerminalFrame(allR, constraints, finalPoly, randomness);
        return _callSatellite(frame, size);
    }

    /// Build the TWIGHT frame at the free pointer and return its base and
    /// length. Raw words, no ABI codec - the satellite's fallback parses the
    /// same layout from the other side.
    ///
    /// The one thing that costs something: the wire eq groups live in THIS
    /// call's calldata and the satellite reads eq groups from its own, so the
    /// flat eq section is copied into the frame (~773 KB at the settlement
    /// shape, once per round). Read-don't-decode is preserved on both sides of
    /// the boundary; only the boundary itself pays.
    function _packTerminalFrame(
        uint256[] memory allR,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory finalPoly,
        uint256[] memory randomness
    ) private pure returns (uint256 frame, uint256 size) {
        assembly ("memory-safe") {
            // Single pass: the free pointer IS the cursor. Nothing allocates
            // through Solidity until the frame is complete.
            frame := mload(0x40)
            let c := frame

            mstore(c, TERMINAL_MAGIC)
            c := add(c, 32)

            // --- allR ---
            let n := mload(allR)
            mstore(c, n)
            c := add(c, 32)
            mcopy(c, add(allR, 32), mul(n, 32))
            c := add(c, mul(n, 32))

            // --- constraints ---
            let m := mload(constraints)
            mstore(c, m)
            c := add(c, 32)
            let cb := add(constraints, 32)
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                // ConstraintWeight field order: [0]numVariables [1]gamma
                // [2]initialPower [3]eqPoints [4]eqCdBase [5]eqLens [6]selVars
                // [7]stmCdBase [8]stmLen [9]stmRound [10]virtualPoints
                // [11]groupDescs.
                // The array is a POINTER array (the struct has dynamic
                // members), so slot i holds the address of the struct.
                let base := mload(add(cb, mul(i, 32)))
                let eqCd := mload(add(base, 128))
                let stmCd := mload(add(base, 224))
                let mode := 0
                if iszero(stmCd) { if eqCd { mode := 1 } }
                if stmCd { mode := 2 }
                // The group source pointer follows the mode: eqLens (+160) for
                // wire groups, eqPoints (+96) for derived ones; mode 2 has no
                // shipped groups at all.
                let src := 0
                if iszero(stmCd) { src := mload(add(base, add(96, mul(mode, 64)))) }
                let nGroups := 0
                if src { nGroups := mload(src) }
                let selPtr := mload(add(base, 192))
                let nSel := 0
                if selPtr { nSel := mload(selPtr) }

                mstore(c, mload(base))
                mstore(add(c, 32), mload(add(base, 32)))   // gamma
                mstore(add(c, 64), mload(add(base, 64)))   // initialPower
                mstore(add(c, 96), mode)
                mstore(add(c, 128), nGroups)
                mstore(add(c, 160), nSel)
                c := add(c, 192)

                switch mode
                case 1 {
                    // Wire groups: lengths, then the flat words copied out of
                    // the proof calldata so they become the satellite's own.
                    mcopy(c, add(src, 32), mul(nGroups, 32))
                    c := add(c, mul(nGroups, 32))
                    let total := 0
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        total := add(total, mload(add(add(src, 32), mul(j, 32))))
                    }
                    calldatacopy(c, eqCd, mul(total, 32))
                    c := add(c, mul(total, 32))
                }
                case 2 {
                    // Statement-derived groups (D-086 step C): the raw
                    // STATEMENT slice moves verbatim from the proof calldata
                    // into the satellite's calldata, preceded by the slice
                    // length, the round index, and the virtual claim points.
                    let stmLen := mload(add(base, 256))
                    let stmRound := mload(add(base, 288))
                    let vp := mload(add(base, 320))
                    let nVp := 0
                    if vp { nVp := mload(vp) }
                    mstore(c, stmLen)
                    mstore(add(c, 32), stmRound)
                    mstore(add(c, 64), nVp)
                    c := add(c, 96)
                    if vp {
                        mcopy(c, add(vp, 32), mul(nVp, 32))
                        c := add(c, mul(nVp, 32))
                    }
                    calldatacopy(c, stmCd, stmLen)
                    c := add(c, stmLen)
                }
                default {
                    // Derived groups: k words each, ragged in memory.
                    let pd := add(src, 32)
                    let k := mload(base)
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        let grp := mload(add(pd, mul(j, 32)))
                        mcopy(c, add(grp, 32), mul(k, 32))
                        c := add(c, mul(k, 32))
                    }
                }
                if selPtr {
                    mcopy(c, add(selPtr, 32), mul(nSel, 32))
                    c := add(c, mul(nSel, 32))
                }
            }

            // --- finalPoly, randomness ---
            let nf := mload(finalPoly)
            mstore(c, nf)
            c := add(c, 32)
            mcopy(c, add(finalPoly, 32), mul(nf, 32))
            c := add(c, mul(nf, 32))
            let nr := mload(randomness)
            mstore(c, nr)
            c := add(c, 32)
            mcopy(c, add(randomness, 32), mul(nr, 32))
            c := add(c, mul(nr, 32))

            size := sub(c, frame)
            // Reserve the frame plus the 96-byte reply buffer the call lands in.
            mstore(0x40, add(c, 96))
        }
    }

    /// staticcall the pinned satellite and read back [magic, w, v] (96 B).
    /// One call path for every frame kind: the terminal weight and the v8
    /// MROOTS walk both come through here. Because the codehash pin proves
    /// the callee is OUR satellite - which either returns exactly 96 bytes
    /// echoing the frame's own magic or reverts - the reply needs no magic
    /// or length re-check: a wrong answer is a revert, by construction.
    /// The frame must have 96 bytes of reserved space after it for the reply.
    function _callSatellite(uint256 frame, uint256 size)
        private
        view
        returns (uint256 w, uint256 v)
    {
        // Re-check the pin: the code that runs must be the code that was
        // sized, reviewed, and deployed alongside this verifier.
        if (SATELLITE_CODEHASH != SATELLITE.codehash) revert SatelliteUnpinned();
        // Left-aligned so a 4-byte revert payload carries the selector.
        uint256 failSel = uint256(bytes32(SatelliteCallFailed.selector));
        // Assembly cannot name an immutable; bind them to locals first.
        address satellite = SATELLITE;
        uint256 reply = frame + size;
        assembly ("memory-safe") {
            let ok := staticcall(gas(), satellite, frame, size, reply, 96)
            switch ok
            case 0 {
                // Bubble the satellite's own revert data when it carried any:
                // a malformed frame says so instead of vanishing into a bool.
                let rd := returndatasize()
                switch rd
                case 0 { mstore(0, failSel) revert(0, 4) }
                default { returndatacopy(0, 0, rd) revert(0, rd) }
            }
            if iszero(ok) { mstore(0, failSel) revert(0, 4) }
            w := mload(add(reply, 32))
            v := mload(add(reply, 64))
        }
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
        // Flat rows stay in calldata: absolute byte offset + limb count.
        uint256 rowsAbs;
        uint256 rowsLen;
        // Merkle-path blobs stay in calldata: absolute calldata BYTE offsets
        // of the blob data (calldata refs cannot live in a memory struct, and
        // threading the proof through would blow the stack in _runOneInter-
        // mediate). _paths reads straight from these offsets.
        uint256 pathsAbs;
        uint256 finalPathsAbs;
        // v8: per-intermediate digest counts of the pruned stream, in wire
        // order; empty when the bundle carries expanded paths.
        uint256[] prunedLens;
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
        /// v8: final-phase rows stay in calldata (zero-copy), like rounds.
        uint256 finalRowsAbs;
        uint256 finalRowsLen;
        uint256[] finalScA;
        uint256[] finalScInf;
        uint256[] finalScPow;
    }

    function _decodeRoundCfg(bytes calldata m, uint256 off)
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

    function _decodeRoundPrf(bytes calldata m, uint256 off)
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
        {
            // _arr prefix: count of u32 limbs (4 bytes each).
            uint256 nLimbs;
            (nLimbs, no) = _word(m, no);
            uint256 abs;
            assembly ("memory-safe") {
                abs := add(m.offset, mul(no, 4))
            }
            p.rowsAbs = abs;
            p.rowsLen = nLimbs;
            no += nLimbs;
        }
        {
            uint256 nBytes;
            (nBytes, no) = _word(m, no);
            // v8: bit 31 of the count word flags a PRUNED stream. Mask it
            // before advancing the cursor; the flag then selects the
            // pruned_lens array that follows the blob.
            bool pruned = nBytes >> 31 == 1;
            nBytes &= 0x7fff_ffff;
            uint256 abs;
            assembly ("memory-safe") {
                abs := add(m.offset, mul(no, 4))
            }
            p.pathsAbs = abs;
            no += nBytes / 4;
            if (pruned) {
                (p.prunedLens, no) = _arr(m, no);
            }
        }
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
        {
            // v8: the final rows are the same wire shape as the round rows
            // (u32 LE limbs), so keep them in calldata: the hot row loader
            // reads them zero-copy and the memory copy disappears.
            uint256 nLimbs;
            (nLimbs, no) = _word(m, no);
            uint256 abs;
            assembly ("memory-safe") {
                abs := add(m.offset, mul(no, 4))
            }
            p.finalRowsAbs = abs;
            p.finalRowsLen = nLimbs;
            no += nLimbs;
        }
        {
            uint256 nBytes;
            (nBytes, no) = _word(m, no);
            uint256 abs;
            assembly ("memory-safe") {
                abs := add(m.offset, mul(no, 4))
            }
            p.finalPathsAbs = abs;
            no += nBytes / 4;
        }
        (p.finalScA, no) = _extArr(m, no);
        (p.finalScInf, no) = _extArr(m, no);
        (p.finalScPow, no) = _arr(m, no);
        // v5 (D-086 step C): the per-round eq-points blob is GONE from the
        // wire; the initial constraint derives its groups from STATEMENT.
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

    function _word(bytes calldata d, uint256 off) private pure returns (uint256 v, uint256 no) {
        assembly {
            v := shr(224, calldataload(add(d.offset, mul(off, 4))))
        }
        v = _swapBytes(v);
        no = off + 1;
    }

    function _arr(bytes calldata d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 n;
        (n, no) = _word(d, off);
        out = new uint256[](n);
        // One assembly pass: per-element _word calls cost ~460 gas/word in ABI
        // call overhead alone (measured on rowsFlat); this loop is ~80.
        assembly ("memory-safe") {
            let src := add(d.offset, mul(no, 4))
            let dst := add(out, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let x := shr(224, calldataload(add(src, mul(i, 4))))
                // byte-swap the low 32 bits: LE u32 on the wire, canonical here
                let r := or(and(shr(8, x), 0x00ff00ff), and(shl(8, x), 0xff00ff00))
                r := or(and(shr(16, r), 0x0000ffff), and(shl(16, r), 0xffff0000))
                mstore(add(dst, mul(i, 32)), r)
            }
        }
        no += n;
    }

    /// A byte blob: word count, then raw bytes (padded to a word boundary).
    function _blob(bytes calldata d, uint256 off)
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
            // inside this allocation. calldatacopy sources straight from the
            // calldata section - no intermediate copy of the proof.
            let usable := and(add(nBytes, 31), not(31))
            let src := add(d.offset, mul(no, 4))
            calldatacopy(add(out, 32), src, usable)
        }
        no += words;
    }

    /// A blob holding exactly one 32-byte big-endian item (a digest).
    function _blob32(bytes calldata d, uint256 off)
        private
        pure
        returns (bytes32 out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        if (nBytes != 32) revert BadDigestBlob();
        assembly {
            out := calldataload(add(d.offset, mul(no, 4)))
        }
        no += 8;
    }

    /// A blob holding a sequence of 32-byte big-endian items (Merkle paths,
    /// commitment lists): returned as a bytes blob the ragged readers index.
    function _blobArr32(bytes calldata d, uint256 off)
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
            let srcBase := add(d.offset, mul(no, 4))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(dst, mul(i, 32)), calldataload(add(srcBase, mul(i, 32))))
            }
        }
        no += nBytes / 4;
    }

    /// Raw 32-byte items WITHOUT a length prefix (the batch prefix digests).
    function _raw32(bytes calldata d, uint256 off)
        private
        pure
        returns (bytes32 out, uint256 no)
    {
        assembly {
            out := calldataload(add(d.offset, mul(off, 4)))
        }
        no = off + 8;
    }

    /// A count word followed by that many raw 32-byte items (terminals).
    function _raw32Arr(bytes calldata d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 n;
        (n, no) = _word(d, off);
        out = new uint256[](n);
        assembly {
            let dst := add(out, 32)
            let srcBase := add(d.offset, mul(no, 4))
            let PAD_MASK := sub(shl(128, 1), 1)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let w := calldataload(add(srcBase, mul(i, 32)))
                if and(w, PAD_MASK) {
                    mstore(0, 0)
                    revert(0, 0)
                }
                mstore(add(dst, mul(i, 32)), w)
            }
        }
        no += n << 3;
    }

    /// A blob of 32-byte packed extension elements, returned as uint256 words.
    function _extArr(bytes calldata d, uint256 off)
        private
        pure
        returns (uint256[] memory out, uint256 no)
    {
        uint256 nBytes;
        (nBytes, no) = _word(d, off);
        // v7 in-band flag: bit 31 of the byte count selects the compact
        // 16-byte limb layout (batch 41). Real blobs are far below 2^31 B.
        bool compact = nBytes > 0x7fff_ffff;
        nBytes &= 0x7fff_ffff;
        if (compact) {
            // v7: four BE limbs per element (16 B), lifted to the packed
            // word at bits 224..128; the low 128 bits are zero by layout.
            uint256 n16 = nBytes / 16;
            out = new uint256[](n16);
            assembly {
                let dst := add(out, 32)
                let srcBase := add(d.offset, mul(no, 4))
                for { let i := 0 } lt(i, n16) { i := add(i, 1) } {
                    mstore(add(dst, mul(i, 32)), shl(128, shr(128, calldataload(add(srcBase, mul(i, 16))))))
                }
            }
            no += nBytes / 4;
            return (out, no);
        }
        uint256 n = nBytes / 32;
        out = new uint256[](n);
        assembly {
            let dst := add(out, 32)
            let srcBase := add(d.offset, mul(no, 4))
            let PAD_MASK := sub(shl(128, 1), 1)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let w := calldataload(add(srcBase, mul(i, 32)))
                if and(w, PAD_MASK) {
                    mstore(0, 0)
                    revert(0, 0)
                }
                mstore(add(dst, mul(i, 32)), w)
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
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(src, 0x20), mul(start, 0x20)), mul(len, 0x20))
        }
    }


    function _node(bytes memory blob, uint256 idx) private pure returns (bytes32 out) {
        assembly ("memory-safe") {
            out := mload(add(add(blob, 32), mul(idx, 32)))
        }
    }


    /// The constraint identity on the satellite (batch 48). Pack the CIDNTY
    /// frame - [magic, zeta, constraintAlpha, lookupAlpha, beta, terminals,
    /// statement, raw CONFIG CONSTRAINTS bytes, bound evals for rounds 1..4]
    /// - and staticcall TerminalWeight. The satellite parses the CONFIG
    /// section itself (node programs stay in ITS calldata, read in place),
    /// rebuilds every opened value, and checks fold * inv_vanishing ==
    /// quotient per instance, reverting with the engine's own
    /// ConstraintIdentityMismatch selector on failure.
    function _callIdentity(
        uint256 zeta,
        uint256 constraintAlpha,
        uint256 lookupAlpha,
        uint256 beta,
        uint256[] memory terminals,
        uint256[] calldata statement,
        bytes calldata proof,
        uint256 cfgWord,
        uint256 cfgWords,
        uint256[][] memory boundEvalsOf
    ) private view {
        uint256 frame;
        uint256 size;
        assembly ("memory-safe") {
            frame := mload(0x40)
            let c := frame
            mstore(c, 0x4349444E5459) // "CIDNTY"
            c := add(c, 32)
            mstore(c, zeta)
            mstore(add(c, 32), constraintAlpha)
            mstore(add(c, 64), lookupAlpha)
            mstore(add(c, 96), beta)
            c := add(c, 128)
            let n := mload(terminals)
            mstore(c, n)
            c := add(c, 32)
            mcopy(c, add(terminals, 32), mul(n, 32))
            c := add(c, mul(n, 32))
            let ns := statement.length
            mstore(c, ns)
            c := add(c, 32)
            calldatacopy(c, statement.offset, mul(ns, 32))
            c := add(c, mul(ns, 32))
            mstore(c, cfgWords)
            c := add(c, 32)
            calldatacopy(c, add(proof.offset, mul(cfgWord, 4)), mul(cfgWords, 4))
            c := add(c, mul(cfgWords, 4))
            for { let r := 1 } lt(r, 5) { r := add(r, 1) } {
                let arr := mload(add(add(boundEvalsOf, 32), mul(r, 32)))
                let bl := mload(arr)
                mstore(c, bl)
                c := add(c, 32)
                mcopy(c, add(arr, 32), mul(bl, 32))
                c := add(c, mul(bl, 32))
            }
            size := sub(c, frame)
            // Reserve the frame plus the 96-byte reply buffer.
            mstore(0x40, add(c, 96))

        }
        // The satellite's verdict is its silence: a mismatch reverts with
        // ConstraintIdentityMismatch and bubbles through _callSatellite.
        (uint256 w, uint256 v) = _callSatellite(frame, size);
        w;
        v;
    }

}