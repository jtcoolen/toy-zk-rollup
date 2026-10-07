// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {StirOpenings} from "./StirOpenings.sol";
import {WhirGadgets} from "./WhirGadgets.sol";
import {SumcheckCore} from "./SumcheckCore.sol";

/// The WHIR verifier core: the Fiat-Shamir replay of a WHIR opening proof.
///
/// WHAT THIS IS
///
/// A line-for-line port of `p3_whir::pcs::verifier::Verifier::verify` and the
/// `replay` beneath it, expressed against the Solidity challenger, field and
/// sumcheck primitives in this tree. The reference order is:
///
/// 1. the STARK layer observes the batch commitment and hands the WHIR core
///    the opening points and claimed evaluations (p3's `add_claim_at`, where
///    a caller-fixed point contributes NO transcript step);
/// 2. the initial phase: virtual out-of-domain claims, the layout batching
///    challenge, and the initial sumcheck;
/// 3. one phase per WHIR round: round commitment, OOD answers, query proof of
///    work, query indices, round batching challenge, round sumcheck;
/// 4. the final phase: the final polynomial, the terminal claim check, and the
///    closing sumcheck, ending in an algebraic identity rather than a
///    transcript checkpoint.
///
/// THE CONSTANT BLOB (D-059)
///
/// p3's transcript absorbs shape fingerprints and domain separators at every
/// protocol boundary. Their bytes are fixed by the public configuration, not
/// by the proof, so the contract does not re-derive them: the prover exports
/// them once and the contract absorbs them verbatim from `Transcript.constants`
/// at structurally known positions. The positions are not read from the proof
/// - a proof-driven schedule would be attacker-controlled - they are the
/// positions the hand-written port visits them at, mirroring the Rust.
///
/// FIELD CONVENTION
///
/// Packed extension elements are canonical: `c0 << 224 | c1 << 192 | c2 << 160
/// | c3 << 128`, four KoalaBear limbs, the low 128 bits always zero. The
/// transcript absorbs each limb in MONTGOMERY form because that is what p3's
/// `SerializingChallenger32` writes. `SumcheckCore.observeExt4Canonical` owns
/// that conversion; nothing here absorbs a field element any other way.
library WhirVerifierCore {
    using KeccakChallenger for KeccakChallenger.State;

    /// The sponge plus the config-fixed byte stream.
    ///
    /// `constants` is the constant payload of the prover's semantic blob: the
    /// concatenation of every config-fixed absorb run, in transcript order.
    /// `constOff` walks it. The payload is public configuration - it is a
    /// function of the WHIR parameters and the opening shape, both of which
    /// the settlement contract fixes at deployment - so it may live in
    /// calldata or code next to `WhirFixedConfig`.
    struct Transcript {
        KeccakChallenger.State state;
        bytes constants;
        uint256 constOff;
    }

    /// Raised when the constant payload runs out, i.e. the proof's shape does
    /// not match the configuration the blob was generated for.
    error ConstantsExhausted(uint256 need, uint256 have);

    /// Raised when a claim's evaluation count does not match its declared
    /// width. Mirrors `OpeningBatchSizeMismatch`.
    error OpeningEvalCountMismatch(uint256 claim, uint256 expected, uint256 actual);

    /// Absorb `n` config-fixed base words from the constant payload.
    ///
    /// The words are already in wire form (Montgomery), exactly as the prover
    /// serialized them, so they go straight to `observeBase`.
    function absorbConstants(Transcript memory t, uint256 n) internal pure {
        if (t.constOff + 4 * n > t.constants.length) {
            revert ConstantsExhausted(4 * n, t.constants.length - t.constOff);
        }
        uint256 end = t.constOff + 4 * n;
        // One bulk pass: the payload is already in the transcript's byte order
        // (little-endian words), so the absorber appends it verbatim after a
        // per-word range check. Byte-identical to the previous per-word
        // observeBase(swapBytes(..)) loop - pinned by the transcript vectors.
        t.state.observeBasesLE(t.constants, t.constOff, n);
        t.constOff = end;
    }

    /// Reverse the four bytes of a 32-bit word.
    ///
    /// The payload stores each word little-endian; mload reads big-endian. A
    /// 16-bit lane swap is NOT enough - it leaves the word byte-reversed in
    /// pairs, which is still a value that can exceed the modulus, and
    /// `observeBase` reverts on exactly that.
    function swapBytes(uint32 v) internal pure returns (uint256) {
        uint32 r = (v >> 24) | ((v >> 8) & 0x0000_ff00) | ((v << 8) & 0x00ff_0000) | (v << 24);
        return uint256(r);
    }

    /// Observe one extension element from the proof: four Montgomery limbs.
    function observeExt(Transcript memory t, uint256 packed) internal pure {
        t.state.observeExt4Mont(packed);
    }

    /// Draw one extension element: four independent base samples, packed
    /// canonical. Matches p3's `CanSample<EF>` for `SerializingChallenger32`.
    function drawExt(Transcript memory t) internal pure returns (uint256) {
        return SumcheckCore.sampleExt4(t.state);
    }

    /// Observe a 32-byte digest (a Merkle commitment) from the proof.
    function observeDigest(Transcript memory t, bytes32 digest) internal pure {
        t.state.observeBytes(abi.encodePacked(digest));
    }

    /// The initial phase's structural constants: how many config-fixed words
    /// sit at each boundary before the batching challenge.
    ///
    /// These come from the fixed configuration, never from the proof. They are
    /// the positions `absorbConstants` visits; the values are in the blob.
    struct InitialSchedule {
        /// Framing words absorbed before each virtual claim's point draw, one
        /// entry per OOD sample.
        ///
        /// Each virtual claim is framed by its own run: the stream is
        /// `framing, draw, answer` per virtual claim, so a settlement shape
        /// with two OOD samples absorbs two framing blocks. At the small shape
        /// there is one entry (possibly zero words).
        uint256[] preClaimsConstants;
        /// Framing words absorbed before each concrete opening claim's
        /// evaluations, one entry per claim.
        ///
        /// At the small shape every claim is framed identically, so this is a
        /// uniform array. At the settlement shape the framing is ragged: a
        /// claim whose table carries structurally-constrained (constant)
        /// columns absorbs a longer framing prefix, and the constant columns
        /// themselves arrive as ordinary evaluations from the proof. Only the
        /// framing prefix differs per claim; the evaluation loop does not.
        uint256[] perClaimConstants;
        /// Words absorbed after the last claim and before the batching draw.
        uint256 batchingConstants;
        /// Words absorbed between the batching draw and the initial sumcheck's
        /// first round: the sumcheck's versioned domain separator and shape
        /// fingerprint. `SumcheckCore.verifyRounds` deliberately does not absorb
        /// it - the caller does - so this is where it enters.
        uint256 sumcheckConstants;
    }

    /// Everything the initial phase reads from the proof.
    struct InitialInput {
        /// The virtual out-of-domain answers, one per `commitment_ood_samples`.
        uint256[] oodAnswers;
        /// Claimed evaluations, flattened in claim order: all of claim 0's
        /// columns, then claim 1's, and so on.
        uint256[] openingEvals;
        /// Number of evaluations per opening claim.
        uint256[] claimWidths;
        /// Claim indices in CONSTRAINT order (placement order: tables by
        /// descending arity, ties by descending table index, claims within a
        /// table in insertion order). The transcript absorbs evaluations in
        /// PROOF order; the batched claim weights them in placement order,
        /// because plan_layout assigns stacked slots largest-table-first.
        /// Empty means identity (proof order == placement order).
        uint256[] claimPerm;
        /// The initial sumcheck's round polynomials, `h(0)` and `h(infinity)`.
        uint256[] roundCA;
        uint256[] roundCInf;
        /// The initial sumcheck's proof-of-work witnesses; empty at zero
        /// difficulty.
        uint256[] powWitnesses;
        /// `starting_folding_pow_bits`.
        uint256 powBits;
    }

    /// What the initial phase produces.
    struct InitialOutput {
        /// The layout batching challenge. Also the constraint's batching
        /// challenge `gamma`: p3 draws ONE sample and uses it under both
        /// names. A port that drew twice would leave every later sample
        /// self-consistent and the whole proof meaningless.
        uint256 alpha;
        /// The combined claim the initial sumcheck must open with.
        uint256 claimedEval;
        /// The claim after folding, i.e. the initial sumcheck's output.
        uint256 foldedClaim;
        /// The point the initial sumcheck reduces to, one coordinate per
        /// folding factor.
        uint256[] randomness;
        /// The virtual claims' univariate points: drawn from the transcript
        /// BEFORE each answer was absorbed, one per OOD answer. WBND v5 no
        /// longer ships the virtual eq groups - the terminal identity derives
        /// them from these points, which is strictly sounder than trusting
        /// proof-supplied coordinates.
        uint256[] virtualPoints;
    }

    /// Flat eval order for the batched claim: constraint position ->
    /// proof-order eval index. claimPerm maps constraint position ->
    /// proof-order claim index; evals inside a claim keep their order. An
    /// empty perm is the identity.
    function _claimEvalOrder(uint256[] memory widths, uint256[] memory claimPerm, uint256 total)
        private
        pure
        returns (uint256[] memory order)
    {
        order = new uint256[](total);
        if (claimPerm.length == 0) {
            for (uint256 k; k < total; ++k) {
                order[k] = k;
            }
            return order;
        }
        uint256[] memory starts = new uint256[](widths.length);
        uint256 acc = 0;
        for (uint256 c; c < widths.length; ++c) {
            starts[c] = acc;
            acc += widths[c];
        }
        uint256 pos = 0;
        for (uint256 pIdx; pIdx < claimPerm.length; ++pIdx) {
            uint256 ci = claimPerm[pIdx];
            for (uint256 e; e < widths[ci]; ++e) {
                order[pos++] = starts[ci] + e;
            }
        }
    }

    /// Replay the WHIR initial phase.
    ///
    /// Mirrors, in order:
    /// - `Verifier::verify`'s claim registration (`add_virtual_eval` per OOD
    ///   answer, `add_claim_at` per opening batch);
    /// - `replay`'s `delegate_initial_fold`: `batching_challenge`,
    ///   `constraint(alpha)`, `constraint.combine_evals`, then
    ///   `initial_sumcheck.verify_rounds`.
    ///
    /// Two orderings are easy to read backwards and are pinned here:
    ///
    /// - TRANSCRIPT order is virtual claims FIRST, then concrete claims. Each
    ///   virtual claim draws its univariate point BEFORE absorbing its answer
    ///   (`add_virtual_eval` samples the point first). A concrete claim
    ///   absorbs no point at all: `add_claim_at` with `PointSource::Given`
    ///   contributes no transcript step, which is why the opening points are
    ///   inputs to this function and never proof bytes.
    ///
    /// - CONSTRAINT order is the reverse: concrete claims first, then the
    ///   virtual block (`layout::constraint` walks placements, then virtual
    ///   claims). The batching powers follow the CONSTRAINT order, so the
    ///   claimed evaluation weights concrete evals at gamma^0.. and virtual
    ///   answers after them. Getting these two orders confused is invisible
    ///   to the sponge and visible only in the final identity.
    ///
    /// - Within the concrete claims, constraint order is PLACEMENT order, not
    ///   proof order: `plan_layout` stacks the largest table first, so the
    ///   constraint walks tables by descending arity (ties: descending table
    ///   index), claims within a table in insertion order. `claimPerm` carries
    ///   that permutation; the transcript still absorbs in proof order.
    function verifyInitial(
        Transcript memory t,
        InitialSchedule memory s,
        InitialInput memory input
    ) internal pure returns (InitialOutput memory out) {
        // --- claim registration ------------------------------------------------
        // Virtual claims: framing, then draw the point, then bind the answer.
        // The drawn point is the virtual eq group's univariate point; v5 keeps
        // it for the terminal identity instead of discarding it.
        out.virtualPoints = new uint256[](input.oodAnswers.length);
        for (uint256 i; i < input.oodAnswers.length; ++i) {
            absorbConstants(t, s.preClaimsConstants[i]);
            out.virtualPoints[i] = drawExt(t);
            observeExt(t, input.oodAnswers[i]);
        }

        // Concrete claims: the point is the caller's, so only the evaluations
        // reach the wire.
        uint256 cursor = 0;
        for (uint256 c; c < input.claimWidths.length; ++c) {
            absorbConstants(t, s.perClaimConstants[c]);
            uint256 width = input.claimWidths[c];
            if (cursor + width > input.openingEvals.length) {
                revert OpeningEvalCountMismatch(c, width, input.openingEvals.length - cursor);
            }
            for (uint256 j; j < width; ++j) {
                observeExt(t, input.openingEvals[cursor + j]);
            }
            cursor += width;
        }

        // --- batching challenge -------------------------------------------------
        absorbConstants(t, s.batchingConstants);
        uint256 alpha = drawExt(t);

        // --- combined claim ------------------------------------------------------
        //
        // `Constraint::combine_evals` walks statement groups with a running
        // exponent, each group starting where the previous one stopped. The
        // initial constraint holds only equality groups - one per concrete
        // claim, then one virtual block - so the walk is a flat dot product of
        // [concrete evals..., virtual answers...] against gamma^0, gamma^1, ...
        // Verified against the prover's own `combine_evals` output in
        // `whir_proof_vectors.json` (`initial_claimed_eval`).
        uint256 claimed = 0;
        uint256 power = KoalaBearExt4.ONE;
        // Walk concrete claims in placement order: claimPerm maps constraint
        // position -> proof-order claim index. An empty perm is the identity.
        uint256[] memory order = _claimEvalOrder(input.claimWidths, input.claimPerm, input.openingEvals.length);
        for (uint256 k; k < input.openingEvals.length; ++k) {
            claimed = KoalaBearExt4.add(claimed, KoalaBearExt4.mul(input.openingEvals[order[k]], power));
            power = KoalaBearExt4.mul(power, alpha);
        }
        for (uint256 i; i < input.oodAnswers.length; ++i) {
            claimed = KoalaBearExt4.add(claimed, KoalaBearExt4.mul(input.oodAnswers[i], power));
            power = KoalaBearExt4.mul(power, alpha);
        }

        // --- initial sumcheck ----------------------------------------------------
        absorbConstants(t, s.sumcheckConstants);
        //
        // `SumcheckCore.verifyRounds` owns the absorb-grind-draw order and the
        // {0,1,infinity} fold (D-048), and rejects a non-canonical witness
        // count before touching the sponge.
        (uint256 folded, uint256[] memory randomness) = SumcheckCore.verifyRounds(
            t.state, claimed, input.roundCA, input.roundCInf, input.powWitnesses, input.powBits
        );

        out.alpha = alpha;
        out.claimedEval = claimed;
        out.foldedClaim = folded;
        out.randomness = randomness;
    }

    // ---------------------------------------------------------------------
    // Intermediate rounds
    // ---------------------------------------------------------------------

    /// One intermediate WHIR round's structural constants.
    ///
    /// Like the initial schedule these are config-fixed counts, never proof
    /// data. The round's OOD point draws, query-index draws and batching draw
    /// absorb no fixed bytes of their own: the WHIR transcript's step labels
    /// steer the sampler's hierarchy, they are not appended to the byte
    /// stream. That is an empirical fact of the traced prover (D-059), not an
    /// assumption - the semantic blob shows no constant run between the round
    /// commitment and the round sumcheck's separator.
    struct RoundSchedule {
        /// Which round this is, for error reporting only.
        uint256 roundIndex;
        /// The round's out-of-domain sample count from the config. The proof
        /// must carry exactly this many answers.
        uint256 oodSamples;
        /// Words absorbed between the round batching draw and the round
        /// sumcheck's first round (the sumcheck's domain separator).
        uint256 sumcheckConstants;
    }

    /// Everything one intermediate round reads from the proof.
    struct RoundInput {
        /// This round's Merkle commitment (the new root the transcript binds).
        bytes32 commitment;
        /// The round's out-of-domain answers, in draw order.
        uint256[] oodAnswers;
        /// The post-commitment proof-of-work witness (canonical base field).
        uint256 powWitness;
        /// `round_params.pow_bits`. At zero difficulty the witness is pinned
        /// to zero here - the grind itself absorbs nothing at zero bits, so
        /// only this check stops a proof smuggling a nonzero witness through.
        uint256 powBits;
        /// `log_folded_domain_size`: the bit width of one query index AND the
        /// depth of the tree the queries open in. Both are `log2(height)` of the
        /// queried dimensions (`height = domain_size >> folding_factor`), so one
        /// number serves both.
        uint256 logFoldedDomainSize;
        /// Number of STIR queries. The count comes from the schedule the
        /// caller holds, never from the proof.
        uint256 numQueries;
        /// Opened rows, flattened canonical limbs: base-field limbs in round
        /// 0, four limbs per extension element afterwards. When the rows live
        /// in calldata (the settlement path), rowsCdBase is the absolute
        /// calldata byte offset of the flat limbs and rowsFlat is unused:
        /// materializing 36k words of rows cost ~17M gas in memory expansion
        /// alone at the heap's high-water mark, and the query loop copies each
        /// row into its limbs buffer anyway. 0 selects the memory source (the
        /// internal-API test harnesses build rows from JSON fixtures).
        uint256[] rowsFlat;
        /// Absolute calldata byte offset of the flat rows, or 0 for memory.
        uint256 rowsCdBase;
        /// Total limbs available in the calldata source.
        uint256 rowsLen;
        /// Canonical limbs per row (row width for base rows, 4x that for
        /// extension rows).
        uint256 rowLimbs;
        /// Packed extension elements per row: `1 << prevRandomness.length`.
        uint256 rowElems;
        /// True when the rows are base field (round 0 only).
        bool rowsAreBase;
        /// Per-query Merkle paths, leaf-to-root, FLAT in query order against
        /// `prevCommitment` (memory path: JSON harnesses, always from word 0).
        bytes32[] pathsFlat;
        /// Absolute calldata byte offset of the first query's sibling path in
        /// the flat grid (32 B per level, query-major), or 0 for the memory
        /// source above. All queries share one depth, so query q's path starts
        /// at `pathsCdBase + q*depth*32`.
        uint256 pathsCdBase;
        /// v8: digest count of this round's PRUNED digest stream (wire
        /// pruned_lens[i]), or 0 when the round carries expanded paths. When
        /// non-zero, pathsCdBase points at the stream instead of the query
        /// grid and the per-query path decode is replaced by ONE amortized
        /// frontier walk on the satellite, checked against prevCommitment.
        uint256 prunedNDigests;
        /// The commitment the queries open against: the previous round's root,
        /// or the batch commitment for round 0.
        bytes32 prevCommitment;
        /// The previous fold point, packed: the initial sumcheck's randomness
        /// for round 0, the previous round sumcheck's randomness after that.
        uint256[] prevRandomness;
        /// The round sumcheck's round polynomials and witnesses.
        uint256[] sumcheckCA;
        uint256[] sumcheckCInf;
        uint256[] sumcheckPowWitnesses;
        /// `round_params.folding_pow_bits`.
        uint256 sumcheckPowBits;
    }

    /// What one intermediate round produces.
    struct RoundOutput {
        /// The round batching challenge: weights this round's fresh claims.
        uint256 gamma;
        /// The combined claim entering the round sumcheck, after this round's
        /// constraint folded onto the carried claim.
        uint256 claimedEval;
        /// The claim after the round sumcheck folds it.
        uint256 foldedClaim;
        /// The point this round's sumcheck reduces to: the next round's fold
        /// point (or the terminal phase's, after the last round).
        uint256[] randomness;
        /// The out-of-domain points drawn this round, unexpanded.
        uint256[] oodPoints;
        /// Each query's folded row evaluation, in query order.
        uint256[] folds;
        /// The query indices the transcript sampled, in query order. The caller
        /// needs them to rebuild each query's domain point (g^index) for the
        /// constraint weights without trusting proof bytes for it (D-072).
        uint256[] queryIndices;
        /// v8: MROOTS frame address and byte size this round built (size 0
        /// when the round carried expanded paths). The frame sits at the top
        /// of memory with a 96-byte reply slot reserved after it; the caller
        /// staticcalls the satellite through callSatellite - the same helper
        /// the terminal weight uses - and checks the root against the round's
        /// prevCommitment.
        uint256 frameAddr;
        uint256 frameSize;
    }

    /// A round carries the wrong number of OOD answers for its shape.
    error RoundOodAnswerCountMismatch(uint256 round, uint256 expected, uint256 actual);
    /// A round carries the wrong number of opened rows or paths for its query count.
    error RoundRowCountMismatch(uint256 expected, uint256 actual);
    /// A zero-difficulty site carried a nonzero proof-of-work witness.
    /// Mirrors `NonCanonicalPowWitness`.
    error NonCanonicalPowWitness(uint256 round);
    /// The opened rows do not tile the flattened buffer, or a row's width
    /// disagrees with the fold point that must fold it.
    error RowBufferMismatch(uint256 expected, uint256 actual);


    /// Replay one intermediate WHIR round.
    ///
    /// Mirrors `replay`'s per-round body, in order:
    ///
    /// 1. bind the round commitment (`ParsedCommitment::parse_with_round`);
    /// 2. per OOD sample: draw the point, bind the answer;
    /// 3. check the post-commitment proof of work (`verify_stir_challenges
    ///    does this BEFORE drawing the query indices);
    /// 4. draw the query indices as uniform bit strings;
    /// 5. open every query against the PREVIOUS commitment and fold each row
    ///    at the previous fold point (`verify_merkle_proof` + `eval_ext`);
    /// 6. draw the round batching challenge;
    /// 7. fold this round's claims onto the carried claim: the carried claim
    ///    keeps gamma^0 (`new_with_existing_claim` sets `initial_power = 1`),
    ///    the OOD group takes gamma^1.., the query group follows;
    /// 8. run the round sumcheck on the combined claim.
    ///
    /// The step order is the transcript's, and steps 3-5 are interleaved the
    /// way the Rust interleaves them: the PoW sits between the OOD answers and
    /// the index draws, not next to the sumcheck.
    /// Fill the reused limbs buffer with one opened row. rowsCd != 0 selects
    /// the calldata source: rowLimbs u32 LE words at that byte offset,
    /// expanded to canonical uint256 (byte-swap as in the section decoder).
    /// rowsCd == 0 selects the memory source: rowLimbs words at flat + base.
    /// A separate function keeps the query loop's stack shallow.
    /// Fused row load: ONE pass over the opened row's wire limbs produces both
    /// views the query needs - the packed extension elements the fold consumes
    /// and the leaf digest the Merkle check authenticates - with no intermediate
    /// limbs buffer, no second pass, and no separate range-check pass.
    ///
    /// The wire limbs are the Montgomery form of the canonical values: each
    /// canonical limb v (checked v < P here, exactly as extLeaf did) becomes
    /// w = v * R mod P written as four little-endian bytes into scratch above
    /// the free pointer, and keccak covers exactly 4 * rowLimbs bytes. The
    /// spill of each 4-byte store (one mstore writes 32) is overwritten by the
    /// next limb's store; the final spill sits in the unread scratch tail.
    ///
    /// The caller guarantees the row shape (the round's checks run before the
    /// first query): rowLimbs == rowElems for base rows, 4 * rowElems for
    /// extension rows, and the source holds rowLimbs limbs at base.
    function _loadRowFused(
        uint256[] memory elems,
        uint256[] memory flat,
        uint256 rowsCd,
        uint256 base,
        uint256 rowLimbs,
        uint256 rowElems,
        bool rowsAreBase
    ) private pure returns (bytes32 leaf) {
        // rowElems is implied by rowLimbs and rowsAreBase (checked once per
        // round by the caller); silence the unused-parameter warning.
        rowElems;
        bytes4 selTag = StirOpenings.LimbOutOfRange.selector;
        assembly ("memory-safe") {
            let dst := add(mload(0x40), 0x20) // leaf scratch above the free pointer
            let ep := add(elems, 0x20)
            let p := 0x7f000001
            let rr := 0x01fffffe
            function swap32(x) -> y {
                y := or(
                    or(and(shl(24, x), 0xff000000), and(shl(8, x), 0xff0000)),
                    or(and(shr(8, x), 0xff00), shr(24, x))
                )
            }
            // limb source: absolute calldata byte offset, or memory array data.
            let src := rowsCd
            switch rowsCd
            case 0 { src := add(add(flat, 0x20), mul(base, 0x20)) }
            default { src := add(rowsCd, mul(base, 4)) }
            // One pass over the rowLimbs wire limbs: each canonical value v
            // (range-checked here) feeds BOTH outputs - the Montgomery LE byte
            // word for the leaf and the packed element lane for the fold.
            // Base rows: limb j is element j, lane 0 only. Extension rows:
            // limbs 4e..4e+3 fill element e top lane first; all four lanes are
            // rewritten every query, so no stale bits survive the reuse.
            // One pass over the rowLimbs wire limbs: each canonical value v
            // (range-checked here) feeds BOTH outputs - the Montgomery LE
            // byte word for the leaf and the packed element lane for the
            // fold. Base rows: limb j is element j, lane 0 only. Extension
            // rows: limbs 4e..4e+3 fill element e top lane first; every
            // lane is rewritten each query, so buffer reuse is safe.
            // The lane mask is a hoisted variable because forge-lint flags
            // a literal value operand in shl as a suspected arg swap.
            let m32 := 0xffffffff
            for { let j := 0 } lt(j, rowLimbs) { j := add(j, 1) } {
                let v := 0
                switch rowsCd
                case 0 { v := mload(add(src, shl(5, j))) }
                default { v := swap32(shr(224, calldataload(add(src, shl(2, j))))) }
                if iszero(lt(v, p)) { mstore(0, selTag) mstore(4, v) revert(0, 36) }
                mstore(add(dst, shl(2, j)), shl(224, swap32(mod(mul(v, rr), p))))
                switch rowsAreBase
                case 1 { mstore(add(ep, shl(5, j)), shl(224, v)) }
                default {
                    let sh := sub(224, shl(5, and(j, 3)))
                    let epw := add(ep, shl(5, shr(2, j)))
                    mstore(epw, or(and(mload(epw), not(shl(sh, m32))), shl(sh, v)))
                }
            }

            leaf := keccak256(dst, mul(rowLimbs, 4))
        }
    }

    /// v8: one amortized pruned-Merkle walk per round, on the satellite
    /// (TerminalWeight, MROOTS entry). The frame is
    /// [magic, depth, nq, nDigests, indices..., leaves..., stream...];
    /// _frameOpen allocates it and copies the stream, _framePut drops each
    /// query's (index, leaf) in as the fold loop produces them - no side
    /// arrays, no second pass. The frame travels out through RoundOutput
    /// (.frameSize): the engine staticcalls the satellite - it already owns
    /// that machinery for the terminal weight - and compares the root, so
    /// the core carries no second call path.
    function _frameOpen(
        uint256 depth,
        uint256 nq,
        uint256 nDigests,
        uint256 streamCdBase,
        bytes32 expectedRoot
    ) private pure returns (uint256 frame, uint256 size) {
        assembly ("memory-safe") {
            // +1 word: the expected root rides at the frame's tail, so the
            // pinned satellite compares it itself and reverts on mismatch -
            // the engine needs no second comparison path.
            size := mul(add(add(5, mul(2, nq)), nDigests), 32)
            frame := mload(0x40)
            // Reserve the frame plus the 96-byte reply slot the shared
            // satellite call writes into, so later allocations cannot
            // clobber either.
            mstore(0x40, add(frame, add(size, 96)))
            mstore(frame, 0x4D524F4F5453) // "MROOTS"
            mstore(add(frame, 32), depth)
            mstore(add(frame, 64), nq)
            mstore(add(frame, 96), nDigests)
            calldatacopy(add(frame, mul(add(4, mul(2, nq)), 32)), streamCdBase, mul(nDigests, 32))
            mstore(add(frame, mul(add(add(4, mul(2, nq)), nDigests), 32)), expectedRoot)
        }
    }



    function _framePut(
        uint256 frame,
        uint256 nq,
        uint256 q,
        uint256 idx,
        bytes32 leaf
    ) private pure {
        assembly ("memory-safe") {
            mstore(add(frame, add(128, mul(q, 32))), idx)
            mstore(add(frame, add(add(128, mul(nq, 32)), mul(q, 32))), leaf)
        }
    }

    function verifyRound(
        Transcript memory t,
        RoundSchedule memory s,
        RoundInput memory input,
        uint256 carriedClaim
    ) internal pure returns (RoundOutput memory out) {
        // --- shape checks before any sponge work --------------------------------
        //
        // Every rejection below happens before the first absorb so a malformed
        // proof cannot desynchronise the transcript on its way out.
        if (input.powBits == 0 && input.powWitness != 0) {
            revert NonCanonicalPowWitness(s.roundIndex);
        }
        if (input.oodAnswers.length != s.oodSamples) {
            revert RoundOodAnswerCountMismatch(s.roundIndex, s.oodSamples, input.oodAnswers.length);
        }
        if (input.rowElems != (uint256(1) << input.prevRandomness.length)) {
            revert RowBufferMismatch(uint256(1) << input.prevRandomness.length, input.rowElems);
        }
        // The row width relation the fused loader assumes: base rows send one
        // wire limb per element, extension rows four. openAndFold used to
        // enforce this per query; the loader folds the leaf and the elements
        // in one pass, so the relation is checked once per round instead.
        if (input.rowLimbs != input.rowElems
            && input.rowLimbs != input.rowElems * KoalaBearExt4.DEGREE)
        {
            revert RowBufferMismatch(input.rowElems * KoalaBearExt4.DEGREE, input.rowLimbs);
        }
        uint256 expectedLimbs = input.numQueries * input.rowLimbs;
        uint256 haveLimbs = input.rowsCdBase == 0 ? input.rowsFlat.length : input.rowsLen;
        if (haveLimbs != expectedLimbs) {
            revert RowBufferMismatch(expectedLimbs, haveLimbs);
        }

        // --- 1-2: commitment, then OOD point/answer pairs ----------------------
        observeDigest(t, input.commitment);
        out.oodPoints = new uint256[](input.oodAnswers.length);
        for (uint256 i; i < input.oodAnswers.length; ++i) {
            out.oodPoints[i] = drawExt(t);
            observeExt(t, input.oodAnswers[i]);
        }

        // --- 3: proof of work ----------------------------------------------------
        //
        // At zero bits `checkWitness` returns true without absorbing, which is
        // exactly why the witness was pinned to zero above.
        if (!t.state.checkWitness(input.powBits, input.powWitness)) {
            revert NonCanonicalPowWitness(s.roundIndex);
        }

        // --- 4: query indices ------------------------------------------------------
        //
        // Uniform bit strings, not reduced field elements: `sampleBits` draws exactly
        // `logFoldedDomainSize` bits with no rejection band, matching `sample_uniform_bits
        // on the serializing challenger.
        uint256[] memory indices = new uint256[](input.numQueries);
        for (uint256 q; q < input.numQueries; ++q) {
            indices[q] = t.state.sampleBits(input.logFoldedDomainSize);
        }
        out.queryIndices = indices;

        // --- 5: open and fold every query ------------------------------------------
        out.folds = new uint256[](input.numQueries);
        uint256[] memory elems = new uint256[](input.rowElems);
        uint256[] memory flat = input.rowsFlat;
        uint256 rowsCd = input.rowsCdBase;
        uint256 frame = 0;
        if (input.prunedNDigests != 0) {
            (frame, out.frameSize) = _frameOpen(
                input.logFoldedDomainSize, input.numQueries, input.prunedNDigests,
                input.pathsCdBase, input.prevCommitment
            );
        }
        for (uint256 q; q < input.numQueries; ++q) {
            // One pass produces the packed fold inputs AND the authenticated
            // leaf: the leaf covers the flat wire limbs (Montgomery form),
            // the fold consumes the packed elements, both built from the same
            // decode, so they cannot disagree.
            bytes32 leaf = _loadRowFused(
                elems,
                flat,
                rowsCd,
                q * input.rowLimbs,
                input.rowLimbs,
                input.rowElems,
                input.rowsAreBase
            );
            if (frame != 0) {
                // v8: no per-query path walk here. The fold needs only the
                // row; authentication moves to one amortized walk after the
                // loop. This query's (index, leaf) drops straight into the
                // frame - index at word 4+q, leaf at word 4+nq+q - so the
                // loop needs no side arrays and no second pass.
                _framePut(frame, input.numQueries, q, indices[q], leaf);
                out.folds[q] = StirOpenings.foldRow(elems, input.prevRandomness);
            } else {
                out.folds[q] = StirOpenings.openAndFoldLeaf(
                    input.prevCommitment,
                    indices[q],
                    input.logFoldedDomainSize,
                    leaf,
                    elems,
                    input.pathsFlat,
                    q * input.logFoldedDomainSize,
                    input.pathsCdBase == 0 ? 0 : input.pathsCdBase + q * input.logFoldedDomainSize * 32,
                    input.prevRandomness
                );
            }
        }
        if (frame != 0) {
            // The frame (plus its reserved reply slot) sits at the top of
            // memory; the engine staticcalls the satellite with it through
            // callSatellite and checks the root against prevCommitment.
            out.frameAddr = frame;
        }

        // --- 6: round batching challenge ----------------------------------------------
        uint256 gamma = drawExt(t);
        out.gamma = gamma;

        // --- 7: fold this round's claims onto the carried claim ------------------------
        //
        // `Constraint::new_with_existing_claim(gamma, nv, [Eq(ood), Select(folds)])
        // then `combine_evals`: the carried claim holds gamma^0, the equality group
        // takes gamma^1..gamma^ood_samples, the selection group follows at the
        // next powers up. The running exponent is exactly what `combine_evals`'s
        // `shift` does.
        uint256 claimed = carriedClaim;
        uint256 power = gamma; // gamma^1: the carried claim owns gamma^0
        for (uint256 i; i < input.oodAnswers.length; ++i) {
            claimed = KoalaBearExt4.add(claimed, KoalaBearExt4.mul(input.oodAnswers[i], power));
            power = KoalaBearExt4.mul(power, gamma);
        }
        for (uint256 q; q < input.numQueries; ++q) {
            claimed = KoalaBearExt4.add(claimed, KoalaBearExt4.mul(out.folds[q], power));
            power = KoalaBearExt4.mul(power, gamma);
        }
        out.claimedEval = claimed;

        // --- 8: round sumcheck -----------------------------------------------------------
        absorbConstants(t, s.sumcheckConstants);
        (uint256 folded, uint256[] memory randomness) = SumcheckCore.verifyRounds(
            t.state,
            claimed,
            input.sumcheckCA,
            input.sumcheckCInf,
            input.sumcheckPowWitnesses,
            input.sumcheckPowBits
        );
        out.foldedClaim = folded;
        out.randomness = randomness;
    }

    // ---------------------------------------------------------------------
    // Final phase
    // ---------------------------------------------------------------------

    /// The final phase's structural constants.
    struct FinalSchedule {
        /// Words absorbed before the final polynomial's evaluations. The
        /// WHIR transcript binds the polynomial inside its own bracket, which
        /// appends no fixed bytes; the field stays for shapes that do.
        uint256 finalPolyConstants;
        /// Which round index the terminal PoW and queries are labelled with
        /// (n_rounds), for error reporting.
        uint256 roundIndex;
        /// Words absorbed between the terminal query draw and the closing
        /// sumcheck's first round (the closing sumcheck's domain separator).
        uint256 sumcheckConstants;
    }

    /// Everything the final phase reads from the proof.
    struct FinalInput {
        /// The final polynomial, sent in the clear: packed extension
        /// elements, low index first. Length must be 2^num_variables.
        uint256[] finalPoly;
        /// The root the terminal queries open against: the last round's
        /// commitment, or the batch commitment when there were no rounds.
        bytes32 lastCommitment;
        /// The terminal proof-of-work witness and difficulty.
        uint256 powWitness;
        uint256 powBits;
        /// `log_folded_domain_size` of the final round config: query bit width
        /// and Merkle depth, as in an intermediate round.
        uint256 logFoldedDomainSize;
        /// Terminal query count from the schedule, never from the proof.
        uint256 numQueries;
        /// Terminal opened rows (extension-valued), flattened canonical limbs,
        /// plus the same geometry as RoundInput's row fields.
        uint256[] rowsFlat;
        /// Absolute calldata byte offset of the flat rows, or 0 for memory
        /// (see RoundInput.rowsCdBase).
        uint256 rowsCdBase;
        /// Total limbs available in the calldata source.
        uint256 rowsLen;
        uint256 rowLimbs;
        uint256 rowElems;
        /// Per-query Merkle paths against `lastCommitment`, FLAT in query
        /// order (memory path: JSON harnesses).
        bytes32[] pathsFlat;
        /// Absolute calldata byte offset of the flat sibling grid, or 0 for
        /// the memory source above (see RoundInput.pathsCdBase).
        uint256 pathsCdBase;
        /// The last round's folding randomness: the terminal fold point.
        uint256[] prevRandomness;
        /// The terminal queries' domain points, lifted base scalars, in query
        /// order: `g^index` on the folded domain. The STIR check evaluates the
        /// public polynomial here.
        ///
        /// When `domainGenerator` is nonzero this field is IGNORED and
        /// recomputed in-circuit from the sampled indices (D-072): the proof
        /// does not get to pick its own domain points.
        uint256[] domainPoints;
        /// When nonzero, the folded-domain generator (canonical base element)
        /// used to compute each query's domain point as `generator^index` from
        /// the indices the transcript itself sampled.
        uint256 domainGenerator;
        /// Closing sumcheck round values and witnesses.
        uint256[] sumcheckCA;
        uint256[] sumcheckCInf;
        uint256[] sumcheckPowWitnesses;
        uint256 sumcheckPowBits;
    }

    /// What the final phase produces.
    struct FinalOutput {
        /// The claim after the closing sumcheck folded it.
        uint256 foldedClaim;
        /// The point the closing sumcheck reduces to. The caller concatenates
        /// this onto its accumulated folding randomness to form all_r for the
        /// terminal identity (D-086 step A).
        uint256[] randomness;
        /// The terminal query indices the transcript sampled, in query order:
        /// the caller's source for each query's domain point (D-072).
        uint256[] queryIndices;
    }

    /// A terminal query's folded row disagrees with the public polynomial.
    error StirChallengeFailed(uint256 query);
    /// The folding randomness is shorter than a constraint's arity.
    error RandomnessTooShort(uint256 need, uint256 have);

    /// Replay the final phase.
    ///
    /// Mirrors `replay`'s final block: bind the public polynomial,
    /// terminal PoW, terminal query indices, open each query against the last
    /// root and fold it at the last round's randomness, then check each fold
    /// against the public polynomial at the query's domain point (the STIR
    /// statement verified directly - the terminal claims are NOT batched into
    /// the running claim), then run the closing sumcheck.
    ///
    /// The terminal identity
    ///
    ///     claimed == eval_constraints_poly(all_r) * final_poly(final_r)
    ///
    /// is NOT evaluated here (D-086 step A): the eval chain is the largest
    /// single block of verifier bytecode and runs exactly once per verify, so
    /// it lives in the pinned TerminalWeight satellite. The caller performs
    /// the equality against the foldedClaim and randomness returned here.
    /// There is no transcript checkpoint after the closing sumcheck: the
    /// algebra IS the checkpoint, wherever it is evaluated.
    function verifyFinal(
        Transcript memory t,
        FinalSchedule memory s,
        FinalInput memory input,
        uint256 carriedClaim
    ) internal pure returns (FinalOutput memory out) {
        // Shape checks before any sponge work.
        if (input.powBits == 0 && input.powWitness != 0) {
            revert NonCanonicalPowWitness(s.roundIndex);
        }
        if (input.rowElems != (uint256(1) << input.prevRandomness.length)) {
            revert RowBufferMismatch(uint256(1) << input.prevRandomness.length, input.rowElems);
        }
        // The row width relation the fused loader assumes: base rows send one
        // wire limb per element, extension rows four. openAndFold used to
        // enforce this per query; the loader folds the leaf and the elements
        // in one pass, so the relation is checked once per round instead.
        if (input.rowLimbs != input.rowElems
            && input.rowLimbs != input.rowElems * KoalaBearExt4.DEGREE)
        {
            revert RowBufferMismatch(input.rowElems * KoalaBearExt4.DEGREE, input.rowLimbs);
        }
        uint256 haveLimbsF = input.rowsCdBase == 0 ? input.rowsFlat.length : input.rowsLen;
        if (haveLimbsF != input.numQueries * input.rowLimbs) {
            revert RowBufferMismatch(input.numQueries * input.rowLimbs, haveLimbsF);
        }
        if (input.domainGenerator == 0 && input.domainPoints.length != input.numQueries) {
            revert RoundRowCountMismatch(input.numQueries, input.domainPoints.length);
        }

        // --- bind the public polynomial ------------------------------------------
        absorbConstants(t, s.finalPolyConstants);
        for (uint256 i; i < input.finalPoly.length; ++i) {
            observeExt(t, input.finalPoly[i]);
        }

        // --- terminal PoW and query indices ----------------------------------------
        if (!t.state.checkWitness(input.powBits, input.powWitness)) {
            revert NonCanonicalPowWitness(s.roundIndex);
        }
        uint256[] memory indices = new uint256[](input.numQueries);
        for (uint256 q; q < input.numQueries; ++q) {
            indices[q] = t.state.sampleBits(input.logFoldedDomainSize);
        }
        out.queryIndices = indices;

        // Domain points: computed in-circuit from the sampled indices when a
        // generator was supplied, so the STIR check cannot be steered by
        // proof-chosen points (D-072).
        if (input.domainGenerator != 0) {
            input.domainPoints = new uint256[](input.numQueries);
            for (uint256 q; q < input.numQueries; ++q) {
                input.domainPoints[q] = WhirGadgets.powConstBase(input.domainGenerator, indices[q]);
            }
        }

        // --- open, fold, and check each query against the public polynomial ----------
        uint256[] memory elems = new uint256[](input.rowElems);
        uint256[] memory flat = input.rowsFlat;
        uint256 rowsCd = input.rowsCdBase;
        for (uint256 q; q < input.numQueries; ++q) {
            bytes32 leaf = _loadRowFused(
                elems,
                flat,
                rowsCd,
                q * input.rowLimbs,
                input.rowLimbs,
                input.rowElems,
                false
            );
            uint256 fold = StirOpenings.openAndFoldLeaf(
                input.lastCommitment,
                indices[q],
                input.logFoldedDomainSize,
                leaf,
                elems,
                input.pathsFlat,
                q * input.logFoldedDomainSize,
                input.pathsCdBase == 0 ? 0 : input.pathsCdBase + q * input.logFoldedDomainSize * 32,
                input.prevRandomness
            );
            // The STIR statement: the fold must equal the public polynomial at
            // the query's domain point. This is `SelectStatement::verify` on the
            // univariate points - Horner over the coefficient table.
            uint256 expectedFold = StirOpenings.horner(input.finalPoly, input.domainPoints[q]);
            if (fold != expectedFold) {
                revert StirChallengeFailed(q);
            }
        }

        // --- closing sumcheck ----------------------------------------------------------
        absorbConstants(t, s.sumcheckConstants);
        (uint256 folded, uint256[] memory randomness) = SumcheckCore.verifyRounds(
            t.state,
            carriedClaim,
            input.sumcheckCA,
            input.sumcheckCInf,
            input.sumcheckPowWitnesses,
            input.sumcheckPowBits
        );
        out.foldedClaim = folded;
        out.randomness = randomness;
    }
}
