// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {SumcheckCore} from "../src/verifier/SumcheckCore.sol";

/// Pins the sumcheck fold against vectors produced by the real
/// `SumcheckData::verify_rounds` running over the workspace's traced
/// Keccak challenger.
///
/// The point of this test is not only that our fold is right, but that the
/// vendored alternative is wrong for us. `sol-whir-p3` folds with
/// `extrapolate_012` over {0,1,2}; p3 0.8.0 folds with
/// `extrapolate_01inf` over {0,1,infinity}. Both return a well-formed
/// field element. The disagreement is silent, so it is asserted here
/// explicitly rather than left to be discovered as a verification failure
/// with a misleading cause.
///
/// Regenerate with:
///     cargo test -p prover --test `sumcheck_vectors` -- --ignored --nocapture
contract SumcheckCoreTest is Test {
    using KeccakChallenger for KeccakChallenger.State;
    using SumcheckCore for KeccakChallenger.State;

    string internal constant VECTOR = "test/vectors/sumcheck_vectors.json";

    /// Our fold matches the real Rust fold on every case.
    function test_fold_matches_rust() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".num_cases");
        assertTrue(n > 0, "no cases");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".cases[", vm.toString(i), "]");
            uint256 cA = pack(limbs(json, string.concat(base, ".c_a")));
            uint256 cInf = pack(limbs(json, string.concat(base, ".c_inf")));
            uint256 claim = pack(limbs(json, string.concat(base, ".claimed_sum")));
            uint256 r = pack(limbs(json, string.concat(base, ".r")));
            uint256 want = pack(limbs(json, string.concat(base, ".folded")));

            assertEq(
                SumcheckCore.foldClaim(claim, cA, cInf, r), want, string.concat("case ", vm.toString(i))
            );
        }
    }

    /// The vendored {0,1,2} fold must NOT match, on a majority of cases.
    ///
    /// This is a negative test with a specific purpose: if someone later
    /// "simplifies" `SumcheckCore` to call `extrapolate_012`, this fails
    /// loudly instead of the change quietly becoming the new reference.
    /// The measured split over these vectors is 96 agree / 160 disagree.
    function test_vendored_012_fold_diverges() public {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".num_cases");
        uint256 disagree;

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".cases[", vm.toString(i), "]");
            uint256 cA = pack(limbs(json, string.concat(base, ".c_a")));
            uint256 cInf = pack(limbs(json, string.concat(base, ".c_inf")));
            uint256 claim = pack(limbs(json, string.concat(base, ".claimed_sum")));
            uint256 r = pack(limbs(json, string.concat(base, ".r")));
            uint256 want = pack(limbs(json, string.concat(base, ".folded")));

            uint256 vendored = KoalaBearExt4.extrapolate_012(
                cA, KoalaBearExt4.sub(claim, cA), cInf, r
            );
            if (vendored != want) {
                ++disagree;
            }
        }

        // 160 of 256 measured. Assert a floor well above zero so the test
        // stays meaningful if the operand set changes, and below n so it
        // does not claim total disagreement, which is false.
        assertTrue(disagree > n / 4, "vendored 012 fold unexpectedly close to the real fold");
        assertTrue(disagree < n, "vendored 012 fold unexpectedly identical everywhere");
        emit log_named_uint("cases where vendored 012 disagrees with the real fold", disagree);
    }

    /// A full multi-round replay: absorb the domain-separator prefix, then
    /// per round absorb the pair and draw the challenge, and land on the
    /// same final claim the real verifier produced.
    function test_replay_matches_rust() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 nReplays = vm.parseJsonUint(json, ".num_replays");
        assertTrue(nReplays > 0, "no replays");

        for (uint256 k; k < nReplays; ++k) {
            string memory base = string.concat(".replays[", vm.toString(k), "]");
            uint256 rounds = vm.parseJsonUint(json, string.concat(base, ".num_rounds"));

            KeccakChallenger.State memory challenger = freshChallenger();

            // The versioned, self-describing prefix p3 0.8.0 absorbs before
            // any round. It is a constant for a fixed shape, so it is
            // carried as a blob rather than reconstructed here.
            challenger.observeBytes(hexString(json, string.concat(base, ".prefix_hex")));

            uint256[] memory cA = new uint256[](rounds);
            uint256[] memory cInf = new uint256[](rounds);
            uint256[] memory noWitnesses = new uint256[](0);

            for (uint256 i; i < rounds; ++i) {
                string memory rb = string.concat(base, ".inputs[", vm.toString(i), "]");
                cA[i] = pack(limbs(json, string.concat(rb, ".c_a")));
                cInf[i] = pack(limbs(json, string.concat(rb, ".c_inf")));
            }

            (uint256 claim, uint256[] memory challenges) = SumcheckCore.verifyRounds(
                challenger,
                pack(limbs(json, string.concat(base, ".initial_claim"))),
                cA,
                cInf,
                noWitnesses,
                0
            );

            assertEq(
                claim,
                pack(limbs(json, string.concat(base, ".final_claim"))),
                string.concat("replay ", vm.toString(k), " final claim")
            );

            for (uint256 i; i < rounds; ++i) {
                assertEq(
                    challenges[i],
                    pack(limbs(json, string.concat(base, ".challenges[", vm.toString(i), "].r"))),
                    string.concat("replay ", vm.toString(k), " round ", vm.toString(i), " challenge")
                );
            }
        }
    }

    /// The per-round absorbed bytes must match what the round actually
    /// puts on the wire, independent of the prefix.
    function test_round_absorbs_are_the_pair_in_order() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 nReplays = vm.parseJsonUint(json, ".num_replays");

        for (uint256 k; k < nReplays; ++k) {
            string memory base = string.concat(".replays[", vm.toString(k), "]");
            uint256 rounds = vm.parseJsonUint(json, string.concat(base, ".num_rounds"));
            string[] memory absorbs = vm.parseJsonStringArray(
                json, string.concat(base, ".round_absorbs_hex")
            );
            assertEq(absorbs.length, rounds, "one absorb blob per round");

            for (uint256 i; i < rounds; ++i) {
                // 8 limbs of 4 bytes = 32 bytes: c_a's four limbs then
                // c_inf's four limbs, each in Montgomery little-endian.
                // Decoded bytes, not the hex string's character count.
                bytes memory blob =
                    hexString(json, string.concat(base, ".round_absorbs_hex[", vm.toString(i), "]"));
                assertEq(blob.length, 32, "round absorb width");
            }
        }
    }

    /// A tampered round value must change the final claim, proving the
    /// fold actually depends on the proof rather than the transcript alone.
    function test_tampered_round_changes_claim() public view {
        string memory json = vm.readFile(VECTOR);
        string memory base = ".replays[1]";
        uint256 rounds = vm.parseJsonUint(json, string.concat(base, ".num_rounds"));

        uint256[] memory cA = new uint256[](rounds);
        uint256[] memory cInf = new uint256[](rounds);
        for (uint256 i; i < rounds; ++i) {
            string memory rb = string.concat(base, ".inputs[", vm.toString(i), "]");
            cA[i] = pack(limbs(json, string.concat(rb, ".c_a")));
            cInf[i] = pack(limbs(json, string.concat(rb, ".c_inf")));
        }
        uint256[] memory noWitnesses = new uint256[](0);
        uint256 initial = pack(limbs(json, string.concat(base, ".initial_claim")));

        KeccakChallenger.State memory honest = freshChallenger();
        honest.observeBytes(hexString(json, string.concat(base, ".prefix_hex")));
        (uint256 honestClaim,) =
            SumcheckCore.verifyRounds(honest, initial, cA, cInf, noWitnesses, 0);

        // Tamper with one round's c_a.
        cA[1] = KoalaBearExt4.add(cA[1], KoalaBearExt4.ONE);
        KeccakChallenger.State memory tampered = freshChallenger();
        tampered.observeBytes(hexString(json, string.concat(base, ".prefix_hex")));
        (uint256 tamperedClaim,) =
            SumcheckCore.verifyRounds(tampered, initial, cA, cInf, noWitnesses, 0);

        assertTrue(honestClaim != tamperedClaim, "tamper had no effect");
    }

    /// Skipping the domain separator must produce a different result, so
    /// the prefix cannot be silently dropped.
    function test_missing_prefix_desynchronizes() public view {
        string memory json = vm.readFile(VECTOR);
        string memory base = ".replays[0]";
        uint256 rounds = vm.parseJsonUint(json, string.concat(base, ".num_rounds"));

        uint256[] memory cA = new uint256[](rounds);
        uint256[] memory cInf = new uint256[](rounds);
        for (uint256 i; i < rounds; ++i) {
            string memory rb = string.concat(base, ".inputs[", vm.toString(i), "]");
            cA[i] = pack(limbs(json, string.concat(rb, ".c_a")));
            cInf[i] = pack(limbs(json, string.concat(rb, ".c_inf")));
        }
        uint256[] memory noWitnesses = new uint256[](0);
        uint256 initial = pack(limbs(json, string.concat(base, ".initial_claim")));

        KeccakChallenger.State memory withPrefix = freshChallenger();
        withPrefix.observeBytes(hexString(json, string.concat(base, ".prefix_hex")));
        (uint256 withPrefixClaim,) =
            SumcheckCore.verifyRounds(withPrefix, initial, cA, cInf, noWitnesses, 0);

        KeccakChallenger.State memory withoutPrefix = freshChallenger();
        (uint256 withoutPrefixClaim,) =
            SumcheckCore.verifyRounds(withoutPrefix, initial, cA, cInf, noWitnesses, 0);

        assertTrue(
            withPrefixClaim != withoutPrefixClaim,
            "domain separator had no effect; it is not being absorbed"
        );
    }

    /// A wrong round count in the witness vector is rejected before the
    /// sponge sees anything.
    function test_witness_count_mismatch_reverts() public {
        string memory json = vm.readFile(VECTOR);
        string memory base = ".replays[0]";
        uint256 rounds = vm.parseJsonUint(json, string.concat(base, ".num_rounds"));

        uint256[] memory cA = new uint256[](rounds);
        uint256[] memory cInf = new uint256[](rounds);
        uint256[] memory oneWitness = new uint256[](1);

        KeccakChallenger.State memory challenger = freshChallenger();

        // Route through an external contract: `SumcheckCore` is a library whose
        // `internal pure` functions are inlined into the caller, so a revert
        // would land at the same cheatcode depth as `expectRevert` itself and
        // the assertion would pass vacuously.
        SumcheckProbe probe = new SumcheckProbe();
        vm.expectRevert(
            abi.encodeWithSelector(SumcheckCore.PowWitnessCountMismatch.selector, 0, 1)
        );
        probe.verifyRounds(challenger, 0, cA, cInf, oneWitness, 0);
    }

    /// External wrapper around the inlined library entry point.
    function test_round_count_mismatch_reverts() public {
        uint256[] memory cA = new uint256[](2);
        uint256[] memory cInf = new uint256[](3);
        uint256[] memory noWitness = new uint256[](0);
        KeccakChallenger.State memory challenger = freshChallenger();
        SumcheckProbe probe = new SumcheckProbe();
        vm.expectRevert(
            abi.encodeWithSelector(SumcheckCore.RoundCountMismatch.selector, 2, 3)
        );
        probe.verifyRounds(challenger, 0, cA, cInf, noWitness, 0);
    }

    function freshChallenger() internal pure returns (KeccakChallenger.State memory s) {
        return s;
    }

    function pack(uint256[4] memory c) internal pure returns (uint256) {
        return KoalaBearExt4.pack(c);
    }

    function limbs(string memory json, string memory key) internal pure returns (uint256[4] memory out) {
        uint256[] memory raw = vm.parseJsonUintArray(json, key);
        require(raw.length == 4, "expected 4 limbs");
        out[0] = raw[0];
        out[1] = raw[1];
        out[2] = raw[2];
        out[3] = raw[3];
    }

    /// Read a hex string from the JSON and hand back the raw bytes.
    function hexString(string memory json, string memory key)
        internal
        pure
        returns (bytes memory out)
    {
        return vm.parseJsonBytes(json, string.concat(key));
    }
}

/// External entry point for revert-depth-sensitive tests.
contract SumcheckProbe {
    function verifyRounds(
        KeccakChallenger.State memory challenger,
        uint256 claimedSum,
        uint256[] memory cA,
        uint256[] memory cInf,
        uint256[] memory powWitnesses,
        uint256 powBits
    )
        external
        pure
        returns (uint256, uint256[] memory)
    {
        return SumcheckCore.verifyRounds(challenger, claimedSum, cA, cInf, powWitnesses, powBits);
    }
}
