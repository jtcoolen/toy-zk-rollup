// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {BatchTranscript} from "./BatchTranscript.sol";

/// Multi-transaction carry for the batch STARK transcript (M7).
///
/// WHY THIS EXISTS
///
/// The batch transcript walk is ~55M gas and the constraint layer another ~40M; one
/// settlement transaction running the whole verifier approaches the block gas limit
/// and leaves no headroom for the WHIR core. The verifier therefore runs as a
/// sequence of transactions, each doing one transcript phase, and the Fiat-Shamir
/// sponge has to survive from one to the next.
///
/// WHAT THE CARRY IS
///
/// `KeccakChallenger.State` is `{bytes inputBuffer; uint256 inputLen; bytes32
/// outputBlock; uint256 outputIndex}`. `_flush` hashes exactly `inputLen` bytes from
/// the buffer start, so the buffer's allocated CAPACITY is not part of the state -
/// only the first `inputLen` bytes are. The complete serializable carry is: those
/// absorbed bytes, the output block, the output index, the phase counter, and the
/// challenges drawn so far (alpha, beta, constraint alpha, zeta) that later phases
/// and the constraint layer consume. A few hundred bytes.
///
/// Each `step*` decodes the carry, checks the phase counter, runs exactly one
/// `BatchTranscript` phase, writes the mutated sponge back, and re-encodes. The
/// decode/encode boundary is what makes this a real cross-transaction carry: a step
/// cannot peek at state a later step produces, and a carry cannot be replayed out of
/// order (the counter is monotonic and each step demands its predecessor).
///
/// The trusted-setup inputs (seed words, degree-bit words, preprocessed digest) are
/// NOT carried: they are fixed by the circuit and re-supplied by the caller. The
/// carry starts after `begin`.
library ChunkVerifier {
    /// A phase step was called out of order, or a carry was replayed.
    error PhaseOutOfOrder(uint256 expected, uint256 got);

    /// Phase counter values. `phase` records the last phase COMPLETED.
    uint256 internal constant PHASE_BEGIN = 1;
    uint256 internal constant PHASE_MAIN = 2;
    uint256 internal constant PHASE_PREPROCESSED = 3;
    uint256 internal constant PHASE_LOOKUP = 4;
    uint256 internal constant PHASE_PERMUTATION = 5;
    uint256 internal constant PHASE_QUOTIENT = 6;
    uint256 internal constant PHASE_OOD = 7;

    /// Which challenge `challenge()` is asked for.
    uint256 internal constant CHALLENGE_LOOKUP_ALPHA = 0;
    uint256 internal constant CHALLENGE_BETA = 1;
    uint256 internal constant CHALLENGE_CONSTRAINT_ALPHA = 2;
    uint256 internal constant CHALLENGE_ZETA = 3;

    /// The in-memory form of the carry between decode and encode.
    struct Chunk {
        KeccakChallenger.State sponge;
        uint256 phase;
        uint256 lookupAlpha;
        uint256 beta;
        uint256 constraintAlpha;
        uint256 zeta;
    }

    /// Start the walk: absorb the trusted-setup prefix and emit the first carry.
    function begin(bytes memory seedWords, bytes memory degreeBitWords)
        internal pure returns (bytes memory)
    {
        BatchTranscript.State memory s = BatchTranscript.begin(seedWords, degreeBitWords);
        Chunk memory c;
        c.sponge = s.sponge;
        c.phase = PHASE_BEGIN;
        return encode(c);
    }

    /// main_phase: the main trace commitment, then every instance's public values.
    function stepMain(bytes memory carry, bytes32 mainDigest, bytes memory publicValueWords)
        internal pure returns (bytes memory)
    {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_BEGIN);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        BatchTranscript.mainPhase(s, mainDigest, publicValueWords);
        c.sponge = s.sponge;
        c.phase = PHASE_MAIN;
        return encode(c);
    }

    /// preprocessed_phase: the trusted-setup preprocessed commitment digest.
    function stepPreprocessed(bytes memory carry, bytes32 preprocessedDigest)
        internal pure returns (bytes memory)
    {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_MAIN);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        BatchTranscript.preprocessedPhase(s, preprocessedDigest);
        c.sponge = s.sponge;
        c.phase = PHASE_PREPROCESSED;
        return encode(c);
    }

    /// lookup_phase: the grind check, then alpha and beta.
    function stepLookup(bytes memory carry, uint256 powBits, uint256 powWitness)
        internal pure returns (bytes memory)
    {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_PREPROCESSED);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        (c.lookupAlpha, c.beta) = BatchTranscript.lookupPhase(s, powBits, powWitness);
        c.sponge = s.sponge;
        c.phase = PHASE_LOOKUP;
        return encode(c);
    }

    /// permutation_phase: the permutation commitment, the LogUp terminals, then the
    /// constraint folding challenge.
    function stepPermutation(
        bytes memory carry,
        bytes32 permutationDigest,
        uint256[] memory terminals
    ) internal pure returns (bytes memory) {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_LOOKUP);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        c.constraintAlpha = BatchTranscript.permutationPhase(s, permutationDigest, terminals);
        c.sponge = s.sponge;
        c.phase = PHASE_PERMUTATION;
        return encode(c);
    }

    /// quotient_phase: the quotient-chunk commitment, then the randomization
    /// one when the PCS hides (D-092 batch 89: false for the non-ZK settlement).
    function stepQuotient(bytes memory carry, bytes32 quotientDigest, bytes32 randomDigest, bool hasRand)
        internal pure returns (bytes memory)
    {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_PERMUTATION);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        BatchTranscript.quotientPhase(s, quotientDigest, randomDigest, hasRand);
        c.sponge = s.sponge;
        c.phase = PHASE_QUOTIENT;
        return encode(c);
    }

    /// ood_phase: the grind check, then zeta. After this the sponge is handed to the
    /// WHIR core (the opening argument) and the constraint layer.
    function stepOod(bytes memory carry, uint256 powBits, uint256 powWitness)
        internal pure returns (bytes memory)
    {
        Chunk memory c = decode(carry);
        _expect(c.phase, PHASE_QUOTIENT);
        BatchTranscript.State memory s;
        s.sponge = c.sponge;
        c.zeta = BatchTranscript.oodPhase(s, powBits, powWitness);
        c.sponge = s.sponge;
        c.phase = PHASE_OOD;
        return encode(c);
    }

    /// Read a drawn challenge out of a carry. Reverts if the phase drawing it has
    /// not run yet, so a caller cannot consume a challenge before it exists.
    function challenge(bytes memory carry, uint256 which) internal pure returns (uint256) {
        Chunk memory c = decode(carry);
        uint256 need = which <= CHALLENGE_BETA
            ? PHASE_LOOKUP
            : (which == CHALLENGE_CONSTRAINT_ALPHA ? PHASE_PERMUTATION : PHASE_OOD);
        if (c.phase < need) {
            revert PhaseOutOfOrder(need, c.phase);
        }
        if (which == CHALLENGE_LOOKUP_ALPHA) {
            return c.lookupAlpha;
        }
        if (which == CHALLENGE_BETA) {
            return c.beta;
        }
        if (which == CHALLENGE_CONSTRAINT_ALPHA) {
            return c.constraintAlpha;
        }
        return c.zeta;
    }

    /// The phase counter of a carry.
    function phaseOf(bytes memory carry) internal pure returns (uint256) {
        return decode(carry).phase;
    }

    /// The sponge's absorbed bytes of a carry (the WHIR core resumes from these).
    function absorbedBytes(bytes memory carry) internal pure returns (bytes memory) {
        return decode(carry).sponge.inputBuffer;
    }

    /// Serialize the carry.
    function encode(Chunk memory c) internal pure returns (bytes memory) {
        bytes memory absorbed = _prefix(c.sponge.inputBuffer, c.sponge.inputLen);
        return abi.encode(
            absorbed,
            c.sponge.outputBlock,
            c.sponge.outputIndex,
            c.phase,
            c.lookupAlpha,
            c.beta,
            c.constraintAlpha,
            c.zeta
        );
    }

    /// Deserialize a carry, rebuilding a sponge whose buffer holds exactly the
    /// absorbed bytes (capacity is not state, so the rebuilt buffer is canonical).
    function decode(bytes memory carry) internal pure returns (Chunk memory c) {
        bytes memory absorbed;
        uint256 outputIndex;
        uint256 phase;
        uint256 lookupAlpha;
        uint256 beta;
        uint256 constraintAlpha;
        uint256 zeta;
        bytes32 outputBlock;
        (absorbed, outputBlock, outputIndex, phase, lookupAlpha, beta, constraintAlpha, zeta) =
            abi.decode(carry, (bytes, bytes32, uint256, uint256, uint256, uint256, uint256, uint256));
        c.sponge.inputBuffer = absorbed;
        c.sponge.inputLen = absorbed.length;
        c.sponge.outputBlock = outputBlock;
        c.sponge.outputIndex = outputIndex;
        c.phase = phase;
        c.lookupAlpha = lookupAlpha;
        c.beta = beta;
        c.constraintAlpha = constraintAlpha;
        c.zeta = zeta;
    }

    function _expect(uint256 got, uint256 want) private pure {
        if (got != want) {
            revert PhaseOutOfOrder(want, got);
        }
    }

    /// The first `len` bytes of `src` as a fresh bytes array.
    function _prefix(bytes memory src, uint256 len) private pure returns (bytes memory out) {
        if (len == 0) {
            return out;
        }
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(src, 0x20), len)
        }
    }
}
