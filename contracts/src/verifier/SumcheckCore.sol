// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "../../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

/// The WHIR sumcheck round fold, for the `Basis::Evaluation` reading.
///
/// WHY THIS IS NOT THE VENDORED `_verifySumcheck`
///
/// `sol-whir-p3` folds each round with `KoalaBearExt4.extrapolate_012`,
/// i.e. Lagrange interpolation of a quadratic through the nodes
/// {0, 1, 2}. Our prover does not use that identity. p3 0.8.0's WHIR
/// verifier calls `SumcheckData::verify_rounds(..., Basis::Evaluation)`,
/// whose round identity is `p3_sumcheck::lagrange::extrapolate_01inf` —
/// interpolation through {0, 1, infinity}.
///
/// Measured over 256 generated cases, the {0,1,2} fold agrees with the
/// real Rust fold on 96 and disagrees on 160 (62.5%). The agreements are
/// the degenerate operands, which is why a hand-written spot check would
/// have confirmed the wrong formula. See D-048.
///
/// THE IDENTITY
///
/// The round sends two values, `c_a = h(0)` and `c_inf = h(infinity)`.
/// The sumcheck invariant `h(0) + h(1) = C` supplies the third point,
/// `h(1) = C - c_a`, so three points fix the quadratic and the verifier
/// reduces its claim to
///
///     C' = c_a * (1 - r) + (C - c_a) * r + c_inf * r * (r - 1)
///
/// which is `extrapolate_01inf(c_a, C - c_a, c_inf, r)`.
///
/// Note the transcript ordering, which is load-bearing and comes from
/// `p3_sumcheck::transcript::VerifierTranscript::round`: absorb the pair
/// `c_a, c_inf`, then optionally grind on the witness, then draw `r`.
/// Drawing `r` before absorbing the pair, or absorbing them in the other
/// order, desynchronizes every subsequent challenge.
library SumcheckCore {
    using KeccakChallenger for KeccakChallenger.State;

    /// The extension field's one, packed.
    uint256 private constant ONE = uint256(1) << 224;

    /// KoalaBear's Montgomery radix, R = 2^32 mod p.
    ///
    /// NOT 2^31. Getting this wrong by a factor of two produces a value
    /// that is a valid field element and simply wrong, which is the worst
    /// possible failure mode for a constant like this.
    uint256 private constant MONTGOMERY_R = 0x01ff_fffe;

    /// The field modulus.
    uint256 private constant P = 0x7f00_0001;

    /// Convert a canonical base element to its Montgomery form.
    ///
    /// THE CANONICAL / MONTGOMERY ASYMMETRY
    ///
    /// Field arithmetic in this codebase is done on canonical limbs, which
    /// is why `KoalaBearExt4.mul` and friends take canonical inputs. The
    /// transcript, however, absorbs the Montgomery representation, because
    /// that is what p3's `SerializingChallenger32` writes: it serializes
    /// `to_unique_u32()`, which is the internal Montgomery form.
    ///
    /// So a value that is `1` in the field is absorbed as `0x01fffffe`,
    /// little-endian on the wire. Absorbing the canonical `1` instead
    /// desynchronizes every subsequent challenge, silently.
    function toMontgomery(uint256 canonicalValue) internal pure returns (uint256) {
        return (canonicalValue * MONTGOMERY_R) % P;
    }

    /// Absorb one extension element given in canonical packed form.
    ///
    /// Each of the four limbs is converted to Montgomery and absorbed as a
    /// base element, which puts its little-endian bytes on the wire. This
    /// is the shape p3's `observe_extensions` produces for a degree-4
    /// element: 16 bytes, four limbs, no padding and no domain separator
    /// of its own.
    function observeExt4Canonical(
        KeccakChallenger.State memory challenger,
        uint256 packed
    )
        internal
        pure
    {
        // Limb layout is c0<<224 | c1<<192 | c2<<160 | c3<<128. The low 128
        // bits are ALWAYS zero, so reading `packed & mask` yields a valid-looking
        // zero instead of c3. Round 0 of the vectors has c3 == 0, which is
        // exactly why a hand-written spot check would not have caught this.
        challenger.observeExt4Mont(packed);
    }

    /// Raised when a round's proof carries the wrong number of values.
    error RoundCountMismatch(uint256 expected, uint256 actual);

    /// Raised when the proof's PoW witness count does not match the difficulty.
    error PowWitnessCountMismatch(uint256 expected, uint256 actual);

    /// Raised when a PoW witness fails its difficulty check.
    error InvalidPowWitness(uint256 round);

    /// Interpolate the quadratic through {0, 1, infinity} and evaluate at `r`.
    ///
    /// `h(r) = e0*(1-r) + e1*r + eInf*r*(r-1)`.
    ///
    /// This is the primitive; `foldClaim` is the round-level use of it.
    function extrapolate01inf(
        uint256 e0,
        uint256 e1,
        uint256 eInf,
        uint256 r
    )
        internal
        pure
        returns (uint256)
    {
        // L_0(r) = 1 - r
        uint256 w0 = KoalaBearExt4.sub(ONE, r);
        // L_1(r) = r
        uint256 w1 = r;
        // L_inf(r) = r * (r - 1)
        uint256 wInf = KoalaBearExt4.mul(r, KoalaBearExt4.sub(r, ONE));

        return KoalaBearExt4.add(
            KoalaBearExt4.add(KoalaBearExt4.mul(e0, w0), KoalaBearExt4.mul(e1, w1)),
            KoalaBearExt4.mul(eInf, wInf)
        );
    }

    /// Reduce a running claim through one round.
    ///
    /// `claimed_sum` is the claim before the round; the return value is the
    /// claim after, equal to the round polynomial at `r`.
    ///
    /// The round identity `h(0) + h(1) = C` is what makes two transmitted
    /// values enough: `h(1)` is derived, never sent.
    function foldClaim(
        uint256 claimedSum,
        uint256 cA,
        uint256 cInf,
        uint256 r
    )
        internal
        pure
        returns (uint256)
    {
        return extrapolate01inf(cA, KoalaBearExt4.sub(claimedSum, cA), cInf, r);
    }

    /// Replay a batch of sumcheck rounds against the transcript.
    ///
    /// `cA[i]` and `cInf[i]` are the round's two transmitted values,
    /// packed as extension elements. `powWitnesses` must be empty when
    /// `powBits == 0` and hold exactly one witness per round otherwise —
    /// the canonical shape p3 enforces, and checked before any transcript
    /// work so a malformed proof cannot desynchronize Fiat-Shamir.
    ///
    /// Returns the folded claim and the folding challenges, one per round.
    ///
    /// The caller is responsible for absorbing the sumcheck domain
    /// separator before calling this. In p3 0.8.0 that separator is
    /// versioned and shape-dependent; see `WhirFixedConfig` for where the
    /// measured constant blob lives.
    function verifyRounds(
        KeccakChallenger.State memory challenger,
        uint256 claimedSum,
        uint256[] memory cA,
        uint256[] memory cInf,
        uint256[] memory powWitnesses,
        uint256 powBits
    )
        internal
        pure
        returns (uint256, uint256[] memory)
    {
        uint256 rounds = cA.length;
        if (cInf.length != rounds) {
            revert RoundCountMismatch(rounds, cInf.length);
        }

        // Canonical proof shape, mirrored from p3: zero difficulty means an
        // empty witness vector, positive difficulty means exactly one per
        // round. Checked before the loop so the index below is always in
        // bounds and a wrong count never reaches the sponge.
        uint256 expectedWitnesses = powBits > 0 ? rounds : 0;
        if (powWitnesses.length != expectedWitnesses) {
            revert PowWitnessCountMismatch(expectedWitnesses, powWitnesses.length);
        }

        uint256[] memory challenges = new uint256[](rounds);
        uint256 claim = claimedSum;

        for (uint256 i; i < rounds; ++i) {
            // Bind both values before the challenge that is evaluated
            // against them. Order matters: c_a then c_inf, matching
            // `observe_extensions(ROUND_POLY, &[c_a, c_inf])`.
            //
            // NOT `observeValidatedPackedExt4Pair`: that helper assumes the
            // packed value is already in the form the transcript wants. Our
            // packed values are canonical, and the transcript wants
            // Montgomery, so the conversion has to happen here.
            observeExt4Canonical(challenger, cA[i]);
            observeExt4Canonical(challenger, cInf[i]);

            if (powBits > 0 && !challenger.checkWitness(powBits, powWitnesses[i])) {
                revert InvalidPowWitness(i);
            }

            uint256 r = sampleExt4(challenger);
            challenges[i] = r;
            claim = foldClaim(claim, cA[i], cInf[i], r);
        }

        return (claim, challenges);
    }

    /// Sample an extension element: four base coefficients, each drawn
    /// independently. Matches p3's `CanSample<EF>` for
    /// `SerializingChallenger32`, which fills the basis coefficients by
    /// repeated base sampling.
    function sampleExt4(KeccakChallenger.State memory challenger)
        internal
        pure
        returns (uint256)
    {
        return (challenger.sampleBase() << 224)
            | (challenger.sampleBase() << 192)
            | (challenger.sampleBase() << 160)
            | (challenger.sampleBase() << 128);
    }
}
