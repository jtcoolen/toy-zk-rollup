// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
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
        bytes memory c = t.constants;
        for (uint256 off = t.constOff; off < end; off += 4) {
            uint256 word;
            assembly {
                // The payload stores each word little-endian. mload reads 32
                // bytes big-endian-aligned, so the FOUR PAYLOAD BYTES sit in the
                // TOP 32 bits of the loaded word - shift right by 224, do NOT
                // truncate to uint32, which would keep the bytes 28..32.
                word := shr(224, mload(add(add(c, 32), off)))
            }
            // safe: word is shr(224, mload(..)), so it is at most 2^32 - 1.
            // forge-lint: disable-next-line(unsafe-typecast)
            t.state.observeBase(swapBytes(uint32(word)));
        }
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
        SumcheckCore.observeExt4Canonical(t.state, packed);
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
        /// Words absorbed after the commitment and before the first claim.
        uint256 preClaimsConstants;
        /// Words absorbed before each concrete opening claim's evaluations.
        uint256 perClaimConstants;
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
    function verifyInitial(
        Transcript memory t,
        InitialSchedule memory s,
        InitialInput memory input
    ) internal pure returns (InitialOutput memory out) {
        // --- claim registration ------------------------------------------------
        absorbConstants(t, s.preClaimsConstants);

        // Virtual claims: draw the point, then bind the answer.
        for (uint256 i; i < input.oodAnswers.length; ++i) {
            drawExt(t); // the virtual claim's univariate point; unused here
            observeExt(t, input.oodAnswers[i]);
        }

        // Concrete claims: the point is the caller's, so only the evaluations
        // reach the wire.
        uint256 cursor = 0;
        for (uint256 c; c < input.claimWidths.length; ++c) {
            absorbConstants(t, s.perClaimConstants);
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
        for (uint256 i; i < input.openingEvals.length; ++i) {
            claimed = KoalaBearExt4.add(claimed, KoalaBearExt4.mul(input.openingEvals[i], power));
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
}
