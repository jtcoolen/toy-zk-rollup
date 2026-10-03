// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "../../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {SumcheckCore} from "./SumcheckCore.sol";

/// The batch STARK transcript: the Fiat-Shamir layer that wraps a WHIR opening proof.
///
/// WHAT THIS IS
///
/// A line-for-line port of `p3_batch_stark::transcript::BatchVerifierTranscript`, the
/// driver `verify_batch` runs before it delegates to the PCS opening argument. The
/// settlement proof is a `BatchStarkProof` whose WHIR proof is the batch proof's
/// `opening_proof`, so this layer runs FIRST and hands its sponge, mid-stream, to
/// `WhirVerifierCore` (D-060: the opening points are inputs to that handover, never
/// transcript bytes).
///
/// THE SEQUENCE (pinned by crates/prover/tests/batch_stark_vectors.rs, D-062)
///
///     new:        absorb the seed words, then each instance's degree bits as an
///                 extension element (4 wire words each) - all trusted setup
///     main:       absorb the main commitment, then every instance's public values
///     preprocessed: absorb the trusted-setup preprocessed commitment (constant)
///     lookup:     check the proof-of-work witness, draw alpha then beta (4 samples
///                 each); the per-lookup challenge pairs are COMPUTED, not drawn:
///                 prefix[bus] = alpha + (bus + 1) * beta^W (D-063)
///     permutation: absorb the permutation commitment, then every LogUp terminal
///                 (4 wire words each), then draw the constraint folding challenge
///     quotient:   absorb the quotient-chunk commitment, then the randomization one
///     ood:        check the proof-of-work witness, draw zeta (4 samples)
///     delegate:   the WHIR core continues on this same sponge state
///
/// The event offsets of every phase boundary are exported by the vector generator as
/// `phase_marks` and asserted by the test, so this sequence is the library's sequence,
/// not a reading of it.
///
/// WIRE CONVENTIONS
///
/// Field words are absorbed in wire form (Montgomery, little-endian u32), exactly as
/// `SerializingChallenger32` writes them; the proof codec hands this layer bytes, never
/// canonical integers. Commitments are the single 32-byte digest of a height-zero Merkle
/// cap. The trusted-setup payload concatenates, in order: the seed words, the degree-bit
/// words, and the preprocessed commitment digest.
library BatchTranscript {
    using KeccakChallenger for KeccakChallenger.State;

    /// The sponge plus the trusted-setup byte stream it has consumed so far.
    struct State {
        KeccakChallenger.State sponge;
    }

    /// The challenges the batch layer draws, in the order drawn.
    struct Challenges {
        /// LogUp base randomness (pool offset 0).
        uint256 lookupAlpha;
        /// LogUp payload combiner (pool offset 4).
        uint256 beta;
        /// The challenge folding every instance's constraints (pool offset 8).
        uint256 constraintAlpha;
        /// The out-of-domain point every opening is taken at (pool offset 12).
        uint256 zeta;
    }

    /// A proof-of-work witness failed its difficulty check.
    error PowWitnessRejected(uint256 bits);

    /// A zero-difficulty grind must carry the canonical zero witness: at bits = 0
    /// nothing is sampled, so a nonzero witness would name a search that never happened.
    /// Mirrors `NonCanonicalLookupPowWitness` / `NonCanonicalOodPowWitness`.
    error NonCanonicalPowWitness();

    /// Absorbs the trusted-setup prefix: the domain-separator seed words and the
    /// per-instance degree-bit words, both fixed by the circuit shape. `seedWords` and
    /// `degreeBitWords` are wire-form little-endian u32 streams.
    function begin(bytes memory seedWords, bytes memory degreeBitWords)
        internal
        pure
        returns (State memory s)
    {
        absorbWords(s.sponge, seedWords);
        absorbWords(s.sponge, degreeBitWords);
    }

    /// main_phase: the main trace commitment, then every instance's public values.
    function mainPhase(State memory s, bytes32 mainDigest, bytes memory publicValueWords)
        internal
        pure
    {
        s.sponge.observeHashU8Digest(mainDigest);
        absorbWords(s.sponge, publicValueWords);
    }

    /// preprocessed_phase: the trusted-setup preprocessed commitment. The batch has one
    /// exactly when the circuit table includes preprocessed AIRs; the settlement batch
    /// always does, and the digest is identical in every proof (it is not even carried in
    /// `BatchProof`), so it is a deployment constant.
    function preprocessedPhase(State memory s, bytes32 preprocessedDigest) internal pure {
        s.sponge.observeHashU8Digest(preprocessedDigest);
    }

    /// lookup_phase: check the grind, then draw alpha and beta. Returns them packed.
    ///
    /// `powBits` is 0 for the settlement shape, in which case the witness must be the
    /// canonical zero and the check absorbs it without sampling.
    function lookupPhase(State memory s, uint256 powBits, uint256 powWitness)
        internal
        pure
        returns (uint256 lookupAlpha, uint256 beta)
    {
        grind(s.sponge, powBits, powWitness);
        lookupAlpha = drawExt(s.sponge);
        beta = drawExt(s.sponge);
    }

    /// permutation_phase: the permutation commitment, every LogUp terminal (packed ext,
    /// wire order), then the constraint folding challenge.
    function permutationPhase(State memory s, bytes32 permutationDigest, uint256[] memory terminals)
        internal
        pure
        returns (uint256 constraintAlpha)
    {
        s.sponge.observeHashU8Digest(permutationDigest);
        for (uint256 i; i < terminals.length; ++i) {
            SumcheckCore.observeExt4Canonical(s.sponge, terminals[i]);
        }
        constraintAlpha = drawExt(s.sponge);
    }

    /// quotient_phase: the quotient-chunk commitment, then the randomization commitment
    /// (present exactly when the PCS hides, which the settlement WHIR always does).
    function quotientPhase(State memory s, bytes32 quotientDigest, bytes32 randomDigest)
        internal
        pure
    {
        s.sponge.observeHashU8Digest(quotientDigest);
        s.sponge.observeHashU8Digest(randomDigest);
    }

    /// ood_phase: check the grind, then draw zeta.
    function oodPhase(State memory s, uint256 powBits, uint256 powWitness)
        internal
        pure
        returns (uint256 zeta)
    {
        grind(s.sponge, powBits, powWitness);
        zeta = drawExt(s.sponge);
    }

    /// The per-lookup challenge pair for a bus, computed rather than drawn (D-063):
    /// `[alpha + (bus + 1) * beta^W, beta]`. `maxMessageWidth` is the widest lookup
    /// tuple over any bus, trusted-setup metadata derived from the AIRs.
    function lookupPair(uint256 lookupAlpha, uint256 beta, uint256 bus, uint256 maxMessageWidth)
        internal
        pure
        returns (uint256 prefix, uint256 combiner)
    {
        uint256 gamma = KoalaBearExt4.ONE;
        for (uint256 i; i < maxMessageWidth; ++i) {
            gamma = KoalaBearExt4.mul(gamma, beta);
        }
        prefix = lookupAlpha;
        for (uint256 i; i <= bus; ++i) {
            prefix = KoalaBearExt4.add(prefix, gamma);
        }
        combiner = beta;
    }

    /// One grind step: at zero difficulty the witness is absorbed but never sampled
    /// against, so pin it to zero first (the batch transcript's own rule, ahead of the
    /// step); at nonzero difficulty absorb and require `bits` zero bits.
    function grind(KeccakChallenger.State memory sponge, uint256 powBits, uint256 witness)
        private
        pure
    {
        if (powBits == 0) {
            if (witness != 0) {
                revert NonCanonicalPowWitness();
            }
            // Nothing enters the sponge at zero difficulty: the prover emitted the
            // canonical zero without searching, so there is nothing to bind.
        } else {
            if (!sponge.checkWitness(powBits, witness)) {
                revert PowWitnessRejected(powBits);
            }
        }
    }

    /// Draws one packed extension element: four base samples, in limb order.
    function drawExt(KeccakChallenger.State memory sponge) private pure returns (uint256) {
        uint256[4] memory limbs;
        for (uint256 i; i < 4; ++i) {
            limbs[i] = sponge.sampleBase();
        }
        return KoalaBearExt4.pack(limbs);
    }

    /// Absorbs a wire-form little-endian u32 stream, four bytes at a time.
    ///
    /// Same read as `WhirVerifierCore.absorbConstants`: the payload stores each word
    /// little-endian, mload reads big-endian-aligned, so the four payload bytes sit in
    /// the TOP 32 bits of the loaded word - shift right by 224 and byte-reverse.
    function absorbWords(KeccakChallenger.State memory sponge, bytes memory words) private pure {
        for (uint256 off = 0; off < words.length; off += 4) {
            uint256 word;
            assembly {
                word := shr(224, mload(add(add(words, 32), off)))
            }
            // safe: word is shr(224, mload(..)), so it is at most 2^32 - 1.
            // forge-lint: disable-next-line(unsafe-typecast)
            sponge.observeBase(swapBytes(uint32(word)));
        }
    }

    /// Reverses the bytes of a uint32 (the payload is little-endian; the assembly above
    /// reads big-endian).
    function swapBytes(uint32 v) internal pure returns (uint256) {
        uint256 r = v;
        r = ((r & 0xff00_ff00) >> 8) | ((r & 0x00ff_00ff) << 8);
        r = ((r & 0xffff_0000) >> 16) | ((r & 0x0000_ffff) << 16);
        return r & (2 ** 32 - 1);
    }
}

