// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {WhirVerifierCore} from "../../src/verifier/WhirVerifierCore.sol";

/// Artifact-driven assembly of the initial phase's inputs.
///
/// Shared by the initial-phase test and every later-phase test that needs a
/// transcript parked at a protocol boundary. The schedule lengths are read
/// from the artifact's fixed-absorb runs rather than hard-coded: run 0 sits
/// between the commitment and the virtual claim, runs 1-2 before each
/// concrete claim's evaluations, run 3 before the batching draw, and run 4
/// is the initial sumcheck's separator.
///
/// A library cannot inherit forge-std's Test contract, so the cheatcode is
/// reached through its canonical address. The JSON cheatcodes take
/// `string calldata`, which is why the artifact is threaded as a string, not
/// as bytes.
library WhirInitialPhaseHarness {
    /// forge-std's cheatcode address.
    Vm private constant VM = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function uintAt(string memory j, string memory path) internal pure returns (uint256) {
        return VM.parseJsonUint(j, path);
    }

    function bytesAt(string memory j, string memory path) internal pure returns (bytes memory) {
        return VM.parseJsonBytes(j, path);
    }

    function stringAt(string memory j, string memory path) internal pure returns (string memory) {
        return VM.parseJsonString(j, path);
    }

    function digestAt(string memory j, string memory path) internal pure returns (bytes32) {
        return VM.parseJsonBytes32(j, path);
    }

    function str(uint256 v) internal pure returns (string memory) {
        return VM.toString(v);
    }

    /// One extension element stored as a flat four-limb array at `path`.
    function extFlat(string memory j, string memory path) internal pure returns (uint256) {
        return (uintAt(j, string.concat(path, "[0]")) << 224)
            | (uintAt(j, string.concat(path, "[1]")) << 192)
            | (uintAt(j, string.concat(path, "[2]")) << 160)
            | (uintAt(j, string.concat(path, "[3]")) << 128);
    }

    /// The `i`-th extension element of an array of four-limb arrays.
    function extAt(string memory j, string memory path, uint256 i) internal pure returns (uint256) {
        return extFlat(j, string.concat(path, "[", str(i), "]"));
    }

    /// Word count of fixed-absorb run `i` (hex string of 4-byte LE words).
    function runWords(string memory j, uint256 i) internal pure returns (uint256) {
        return bytes(stringAt(j, string.concat(".fixed_absorb[", str(i), "]"))).length / 8;
    }

    /// Concatenate the hex constant runs `[from, to)` into one payload.
    function constants(string memory j, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        for (uint256 i = from; i < to; ++i) {
            out = abi.encodePacked(
                out, bytesAt(j, string.concat(".fixed_absorb[", str(i), "]"))
            );
        }
    }

    /// Assemble the initial-phase schedule and inputs (not the constants).
    function inputs(string memory j)
        internal
        pure
        returns (WhirVerifierCore.InitialSchedule memory s, WhirVerifierCore.InitialInput memory input)
    {
        s.preClaimsConstants = runWords(j, 0);
        s.batchingConstants = runWords(j, 3);
        s.sumcheckConstants = runWords(j, 4);

        uint256 width = uintAt(j, ".shape.width");
        uint256 claims = uintAt(j, ".shape.num_opening_claims");

        // Small shape: every claim is framed by the same run (run 1). The
        // settlement shape replaces this uniform fill with a per-claim table
        // derived from the composed run schedule.
        s.perClaimConstants = new uint256[](claims);
        for (uint256 c; c < claims; ++c) {
            s.perClaimConstants[c] = runWords(j, 1);
        }
        uint256 oodSamples = uintAt(j, ".shape.commitment_ood_samples");

        uint256[] memory evals = new uint256[](claims * width);
        uint256[] memory widths = new uint256[](claims);
        for (uint256 c; c < claims; ++c) {
            widths[c] = width;
            for (uint256 w; w < width; ++w) {
                evals[c * width + w] = extAt(j, string.concat(".bound_evals[", str(c), "]"), w);
            }
        }
        uint256[] memory oodAnswers = new uint256[](oodSamples);
        for (uint256 i; i < oodSamples; ++i) {
            oodAnswers[i] = extAt(j, ".initial_ood_answers", i);
        }

        uint256 rounds = uintAt(j, ".schedule.rounds[0].folding_factor");
        uint256[] memory cA = new uint256[](rounds);
        uint256[] memory cInf = new uint256[](rounds);
        for (uint256 r; r < rounds; ++r) {
            cA[r] = extAt(j, ".initial_sumcheck_ca", r);
            cInf[r] = extAt(j, ".initial_sumcheck_cinf", r);
        }

        input.oodAnswers = oodAnswers;
        input.openingEvals = evals;
        input.claimWidths = widths;
        input.roundCA = cA;
        input.roundCInf = cInf;
        input.powWitnesses = new uint256[](0);
        input.powBits = uintAt(j, ".shape.starting_folding_pow_bits");
    }
}
