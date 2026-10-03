// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Cross-checks the WHIR proof artifact: the blob the contract walks against the
/// JSON the contract's expected values live in.
///
/// This is the harness `WhirVerifierCore.sol` is written against. The blob is the
/// transcript program - the same schedule the native verifier's sponge consumed -
/// and the JSON holds the values that program produces: the batching challenges,
/// the sumcheck reduction points, the query indices, the commitments. Walking the
/// blob through the Solidity sponge and landing on every JSON value means the
/// Solidity sponge and the Rust sponge agree on this proof, which is the property a
/// settlement verifier needs before any of the arithmetic layers are wired up.
///
/// The two files come from one run of the generator
/// (`cargo test -p prover --test whir_proof_vectors -- --ignored --nocapture`),
/// and the generator refuses to write them unless its own replay of the verifier
/// transcript is byte-identical to the native verifier's. So agreement here is
/// Solidity-vs-Rust, not Solidity-vs-a-reimplementation-of-Rust.
///
/// The proof is HVZK-blinded with OS-seeded masking, so regeneration moves every
/// sample and digest. Nothing here pins a literal value; every assertion relates
/// the two artifacts to each other, or pins a SHAPE.
contract WhirProofVectorsTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/whir_proof_vectors.bin";
    string internal constant JSON = "test/vectors/whir_proof_vectors.json";

    /// The recorded proof must be an accepting one, or every value below is a
    /// description of a proof nobody accepted.
    function test_artifact_declares_acceptance() public view {
        string memory j = vm.readFile(JSON);
        assertTrue(vm.parseJsonBool(j, ".accept"), "recorded proof did not verify");
        assertEq(vm.parseJsonUint(j, ".shape.stacked_num_variables"), 11, "stacked arity");
        assertEq(vm.parseJsonUint(j, ".shape.n_rounds"), 1, "WHIR rounds");
        assertEq(vm.parseJsonUint(j, ".shape.final_sumcheck_rounds"), 3, "final sumcheck rounds");
    }

    /// The Solidity sponge, driven by the blob, must reproduce every challenge the
    /// Rust verifier drew - in order, at the position each one occupies in the
    /// sample pool.
    ///
    /// The pool order is the protocol order, so this single test pins the whole
    /// initial phase and the whole round loop as a SEQUENCE: alpha, gamma, the four
    /// initial-sumcheck coordinates, the round OOD point, the round batching
    /// challenge, the four round-sumcheck coordinates, and the three closing
    /// coordinates. A missing or extra absorb anywhere upstream shifts every value
    /// after it and fails the first comparison that follows.
    function test_sponge_reproduces_every_draw() public view {
        string memory j = vm.readFile(JSON);
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        SemanticBlob.Walk memory w = SemanticBlob.walk(b, true, true);

        // The walk consumed every payload byte: the schedule and the payloads agree.
        assertEq(w.cursor.constants, b.constLen, "constant payload not fully read");
        assertEq(w.cursor.variables, b.varLen, "variable payload not fully read");
        assertEq(w.cursor.samples, b.sampleLen, "sample payload not fully read");
        assertEq(w.cursor.uniform, b.uniformLen, "uniform payload not fully read");
        assertEq(w.cursor.witnesses, b.witnessLen, "witness payload not fully read");

        // Each virtual claim costs the sponge one extension sample: the univariate
        // point `add_virtual_eval` draws before binding the claim's evaluation. Those
        // come FIRST, ahead of the batching challenge, and a verifier that skipped
        // them would desynchronise every later draw - which is exactly what the
        // comparisons below would then report as a bogus mismatch. So the offset is
        // stated, not assumed.
        uint256 at = 4 * vm.parseJsonUint(j, ".shape.commitment_ood_samples");
        at = expectExt(j, ".alpha", w.samples, at);
        // The batching challenge and the constraint's combination factor GAMMA are the
        // SAME draw: `batching_challenge` feeds `constraint(alpha)`, and
        // `challenge_powers(1).next()` returns that alpha unchanged. One sample, two
        // names. Asserting the identity here rather than drawing twice is what keeps
        // the port from inventing a phantom absorb - the single most dangerous class of
        // transcript bug, because everything downstream still looks self-consistent.
        uint256[] memory gammaLimbs = vm.parseJsonUintArray(j, ".gamma");
        for (uint256 k; k < 4; ++k) {
            assertEq(w.samples[at - 4 + k], gammaLimbs[k], "gamma must be the same draw as alpha");
        }
        uint256 initRand = vm.parseJsonUint(j, ".schedule.rounds[0].folding_factor");
        for (uint256 i; i < initRand; ++i) {
            at = expectExt(j, string.concat(".initial_randomness[", vm.toString(i), "]"), w.samples, at);
        }
        uint256 ood = vm.parseJsonUint(j, ".shape.commitment_ood_samples");
        for (uint256 i; i < ood; ++i) {
            at = expectExt(j, string.concat(".ood_points[", vm.toString(i), "]"), w.samples, at);
        }
        uint256 rb = vm.parseJsonUint(j, ".shape.n_rounds");
        for (uint256 i; i < rb; ++i) {
            at = expectExt(j, string.concat(".round_batching[", vm.toString(i), "]"), w.samples, at);
        }
        uint256 rounds = vm.parseJsonUint(j, ".shape.n_rounds");
        for (uint256 r; r < rounds; ++r) {
            uint256 coords = vm.parseJsonUint(j, ".schedule.rounds[0].folding_factor");
            for (uint256 c; c < coords; ++c) {
                at = expectExt(
                    j,
                    string.concat(
                        ".round_randomness[", vm.toString(r), "][", vm.toString(c), "]"
                    ),
                    w.samples,
                    at
                );
            }
        }
        uint256 fr = vm.parseJsonUint(j, ".shape.final_sumcheck_rounds");
        for (uint256 i; i < fr; ++i) {
            at = expectExt(j, string.concat(".final_randomness[", vm.toString(i), "]"), w.samples, at);
        }
        // Every sampled word is accounted for by a named protocol value. If the
        // protocol drew something this test does not name, the tail check catches it
        // here rather than leaving a value silently unchecked.
        assertEq(at, w.samples.length, "sample pool tail is not explained by any exported value");
    }

    /// The commitments the transcript bound are the commitments the proof carries.
    ///
    /// Slot 0 is the STARK commitment the batch layer absorbs before the WHIR core
    /// runs; the rest are the per-round commitments, in round order. A verifier that
    /// bound a stale or reordered digest would desynchronise the sponge here.
    function test_absorbed_digests_match_the_proof() public view {
        string memory j = vm.readFile(JSON);
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        SemanticBlob.Walk memory w = SemanticBlob.walk(b, false, true);

        assertEq(w.digests.length, 1 + vm.parseJsonUint(j, ".counts.num_round_commitments"), "digest count");
        assertEq(w.digests[0], vm.parseJsonBytes32(j, ".commitment"), "STARK commitment");
        for (uint256 i; i < w.digests.length - 1; ++i) {
            assertEq(
                w.digests[i + 1],
                vm.parseJsonBytes32(j, string.concat(".round_commitments[", vm.toString(i), "]")),
                "round commitment"
            );
        }
    }

    /// The uniform draws ARE the query indices.
    ///
    /// WHIR samples query positions as uniform bit strings rather than reducing a
    /// sponge word modulo the domain size, so the contract must draw the same bit
    /// widths in the same order and read the same numbers back. This test pins that
    /// identity: the blob's uniform payload equals the JSON's query index lists,
    /// and the walk verified each draw against the recording.
    function test_uniform_draws_are_the_query_indices() public view {
        string memory j = vm.readFile(JSON);
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        // walk with check=true asserts every draw against the blob's uniform pool.
        SemanticBlob.walk(b, true, false);

        uint256 sets = vm.parseJsonUint(j, ".counts.num_query_sets");
        uint256 total;
        uint256[] memory lens = new uint256[](sets);
        for (uint256 s; s < sets; ++s) {
            lens[s] = vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", vm.toString(s), "]"));
            total += lens[s];
        }
        assertEq(total * 2, b.uniformLen, "query indices do not fill the uniform payload");

        // Spot-check the first and last index of every set against the payload, so a
        // payload that merely has the right length cannot pass.
        uint256 start;
        for (uint256 s; s < sets; ++s) {
            string memory base = string.concat(".query_indices[", vm.toString(s), "]");
            assertEq(
                vm.parseJsonUint(j, string.concat(base, "[0]")),
                _uniformAt(b, start),
                "first query index of set differs"
            );
            assertEq(
                vm.parseJsonUint(j, string.concat(base, "[", vm.toString(lens[s] - 1), "]")),
                _uniformAt(b, start + lens[s] - 1),
                "last query index of set differs"
            );
            start += lens[s];
        }
    }

    /// The exported fixed blobs must tile the blob's constant payload exactly: every
    /// byte the contract hard-codes appears in exactly one run, in order, and nothing
    /// else does. A proof-varying digest inside a run would break the tiling, which
    /// is how a stale-commitment bug gets caught at the artifact layer.
    function test_fixed_blobs_tile_the_constant_payload() public view {
        string memory j = vm.readFile(JSON);
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        uint256 runs = vm.parseJsonUint(j, ".counts.num_fixed_absorb");
        assertTrue(runs > 0, "no fixed blobs");
        uint256 at;
        for (uint256 i; i < runs; ++i) {
            bytes memory run = vm.parseJsonBytes(j, string.concat(".fixed_absorb[", vm.toString(i), "]"));
            assertTrue(at + run.length <= b.constLen, "fixed run overruns the constant payload");
            for (uint256 k; k < run.length; ++k) {
                require(
                    b.raw[b.constOff + at + k] == run[k],
                    string.concat("fixed run ", vm.toString(i), " byte ", vm.toString(k), " differs")
                );
            }
            at += run.length;
        }
        assertEq(at, b.constLen, "fixed runs do not cover the constant payload");
    }

    /// The schedule the contract reads must agree with the blob it walks.
    ///
    /// Round count, folding factors and query counts all appear in both files: the
    /// schedule JSON drives the contract's loop bounds, the blob drives its sponge.
    /// If they disagree the contract would stop the loop at the wrong place while
    /// the sponge had already consumed more, and every later sample would be wrong.
    function test_schedule_agrees_with_blob() public view {
        string memory j = vm.readFile(JSON);
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        uint256 rounds = vm.parseJsonUint(j, ".counts.num_schedule_rounds");
        assertEq(rounds, vm.parseJsonUint(j, ".shape.n_rounds"), "schedule round count");

        // The blob's uniform runs are exactly the per-round query sets followed by
        // the terminal set: one run per set, same lengths.
        uint256 set;
        uint256 scheduleAt = SemanticBlob.HEADER_LEN;
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 kind = uint256(uint8(b.raw[scheduleAt]));
            uint256 run = SemanticBlob.readU16Be(b.raw, scheduleAt + 2);
            scheduleAt += 4;
            if (kind != SemanticBlob.OP_UNIFORM_BITS) {
                continue;
            }
            assertEq(
                run,
                vm.parseJsonUint(j, string.concat(".counts.query_set_lens[", vm.toString(set), "]")),
                "uniform run disagrees with query set"
            );
            ++set;
        }
        assertEq(set, vm.parseJsonUint(j, ".counts.num_query_sets"), "uniform run count");
    }

    /// Every negative control in the artifact was rejected by the native verifier.
    ///
    /// A contract cannot be sounder than the reference it replays. If a tampered
    /// field slipped through here, the field carries data nothing checks and the
    /// port would inherit the hole, so the claim is checked from the artifact rather
    /// than asserted from a run nobody can inspect.
    function test_negative_controls_rejected() public view {
        string memory j = vm.readFile(JSON);
        uint256 n = vm.parseJsonUint(j, ".counts.num_negatives");
        assertTrue(n > 0, "no negative controls recorded");
        for (uint256 i; i < n; ++i) {
            assertTrue(
                vm.parseJsonBool(j, string.concat(".negatives[", vm.toString(i), "].rejected")),
                "the native verifier accepted a tampered proof"
            );
        }
    }

    /// Compares one exported extension element (four canonical limbs, low first)
    /// against four consecutive sampled words, and returns the new pool position.
    function expectExt(
        string memory j,
        string memory key,
        uint256[] memory pool,
        uint256 at
    ) private pure returns (uint256) {
        uint256[] memory limbs = vm.parseJsonUintArray(j, key);
        require(limbs.length == 4, "expected 4 limbs");
        for (uint256 k; k < 4; ++k) {
            require(at + k < pool.length, "sample pool exhausted");
            require(
                pool[at + k] == limbs[k],
                string.concat(
                    key, " limb ", vm.toString(k), ": got ", vm.toString(pool[at + k]), " want ", vm.toString(limbs[k])
                )
            );
        }
        return at + 4;
    }

    /// Reads one uniform draw out of the blob's uniform payload (big-endian u16).
    function _uniformAt(SemanticBlob.Blob memory b, uint256 i) private pure returns (uint256) {
        return SemanticBlob.readU16Be(b.raw, b.uniformOff + i * 2);
    }

}