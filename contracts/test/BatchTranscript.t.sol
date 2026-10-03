// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Replays the BATCH transcript - the layer the settlement verifier wraps around the
/// WHIR opening argument - against vectors from crates/prover/tests/batch_stark_vectors.rs.
///
/// The generator proves the settlement batch under a semantic config whose challenger
/// forwards to the production Keccak challenger and records (D-061), runs the native
/// p3_batch_stark::verify_batch through it, and asserts a hand-driven phase-by-phase
/// replay produces the SAME event stream (D-062). The blob is that stream. So walking it
/// through the Solidity sponge and landing on every JSON value is Solidity-vs-Rust on
/// the real verifier sequence, not on a re-reading of it.
///
/// The phase order the walk pins:
///
///     instance_bindings(degree_bits) -> main(main_com, public_values)
///       -> preprocessed(pre_com) -> lookup(pow) -> [alpha, beta]
///       -> permutation(perm_com, terminals) -> [constraint alpha]
///       -> quotient(q_com, random_com) -> ood(pow) -> [zeta]
///       -> delegate(WHIR opening) -> finish
///
/// The four extension draws of the batch layer sit at fixed pool offsets because the
/// layout is structural: lookup_phase draws alpha then beta, permutation_phase draws the
/// constraint alpha, ood_phase draws zeta. The per-lookup challenge PAIRS are not drawn
/// - they are computed as prefix[bus] = alpha + (bus + 1) * beta^W - so this test
/// recomputes them on-chain (D-063) and checks against the exported pairs.
contract BatchTranscriptTest is Test {
    using SemanticBlob for SemanticBlob.Blob;

    string internal constant BLOB = "test/vectors/batch_stark_vectors.bin";
    string internal constant JSON = "test/vectors/batch_stark_vectors.json";

    /// Structural pool offsets of the batch layer's extension draws, in phase order.
    uint256 internal constant POOL_LOOKUP_ALPHA = 0;
    uint256 internal constant POOL_BETA = 4;
    uint256 internal constant POOL_CONSTRAINT_ALPHA = 8;
    uint256 internal constant POOL_ZETA = 12;

    /// The Solidity sponge, driven by the blob's schedule, must reproduce every value
    /// the Rust verifier drew. walk(check: true) asserts every sample, every uniform
    /// draw (including the 21-bit WHIR query indices) and every proof-of-work witness;
    /// this then pins the four batch-layer extension draws against the JSON.
    function test_batch_phase_draws_match_the_prover() public view {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        SemanticBlob.Walk memory w = SemanticBlob.walk(b, true, true);

        // Every payload consumed exactly: a short read means the schedule and payloads
        // disagree, which would desync a verifier at some later, unnamed site.
        assertEq(w.cursor.constants, b.constLen, "constant payload not fully read");
        assertEq(w.cursor.variables, b.varLen, "variable payload not fully read");
        assertEq(w.cursor.samples, b.sampleLen, "sample payload not fully read");
        assertEq(w.cursor.uniform, b.uniformLen, "uniform payload not fully read");
        assertEq(w.cursor.witnesses, b.witnessLen, "witness payload not fully read");

        string memory j = vm.readFile(JSON);
        assertEq(w.samples.length, 716, "sample pool size");
        assertEqSamples(w, POOL_LOOKUP_ALPHA, j, ".lookup_alpha", "lookup alpha");
        assertEqSamples(w, POOL_BETA, j, ".beta", "beta");
        assertEqSamples(w, POOL_CONSTRAINT_ALPHA, j, ".constraint_alpha", "constraint alpha");
        assertEqSamples(w, POOL_ZETA, j, ".zeta", "zeta");
    }

    /// The commitment absorbs land where the phases put them: main, preprocessed (the
    /// trusted-setup digest carried as a constant - the OP_CONST_COMMITMENT op),
    /// permutation, quotient, random. Pinning the first five digests proves the constant
    /// commitment is absorbed at the right site, not merely present somewhere.
    function test_commitment_absorbs_in_phase_order() public view {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        SemanticBlob.Walk memory w = SemanticBlob.walk(b, false, true);
        assertEq(w.digests.length, 22, "digest count: 21 proof + 1 trusted setup");

        string memory j = vm.readFile(JSON);
        assertEq(toHex(w.digests[0]), vm.parseJsonString(j, ".commitments.main"), "main");
        assertEq(
            toHex(w.digests[1]),
            vm.parseJsonString(j, ".commitments.preprocessed"),
            "preprocessed (constant commitment)"
        );
        assertEq(
            toHex(w.digests[2]), vm.parseJsonString(j, ".commitments.permutation"), "permutation"
        );
        assertEq(
            toHex(w.digests[3]), vm.parseJsonString(j, ".commitments.quotient_chunks"), "quotient"
        );
        assertEq(toHex(w.digests[4]), vm.parseJsonString(j, ".commitments.random"), "random");
    }

    /// The bus layout recomputed on-chain (D-063): prefix[i] = alpha + (i + 1) * beta^W,
    /// with W the widest tuple on any bus, and every lookup's pair [prefix[bus], beta]
    /// checked against the exported pair. A settlement verifier must derive these from
    /// the two drawn challenges and the trusted-setup bus ids - they are never proof
    /// data - so this is the exact arithmetic the contract will run.
    function test_bus_prefixes_recompute_from_alpha_beta() public view {
        string memory j = vm.readFile(JSON);
        uint256 wTuples = vm.parseJsonUint(j, ".bus_layout.max_message_width");
        uint256 numInstances = vm.parseJsonUint(j, ".num_instances");

        uint256 alpha = parseExt(j, ".lookup_alpha");
        uint256 beta = parseExt(j, ".beta");

        // gamma = beta^W by iterated multiplication (W is a small trusted-setup count).
        uint256 gamma = KoalaBearExt4.ONE;
        for (uint256 i; i < wTuples; ++i) {
            gamma = KoalaBearExt4.mul(gamma, beta);
        }

        for (uint256 inst; inst < numInstances; ++inst) {
            string memory base = string.concat(".instances[", vm.toString(inst), "]");
            // The challenge list is flat: each lookup contributes two consecutive
            // 4-coefficient entries, [prefix, beta], so pairs step by 2. The pair count
            // comes from bus_ids, a flat array of trusted-setup bus ids (D-063).
            uint256 numPairs = vm.parseJsonUintArray(j, string.concat(base, ".bus_ids")).length;
            for (uint256 k; k < 2 * numPairs; k += 2) {
                string memory idx = vm.toString(k / 2);
                uint256 bus =
                    vm.parseJsonUint(j, string.concat(base, ".bus_ids[", idx, "]"));
                // prefix[bus] = alpha + (bus + 1) * gamma, by iterated addition.
                uint256 prefix = alpha;
                for (uint256 i; i <= bus; ++i) {
                    prefix = KoalaBearExt4.add(prefix, gamma);
                }
                uint256 pair0 =
                    parseExt(j, string.concat(base, ".lookup_challenges[", vm.toString(k), "]"));
                uint256 pair1 = parseExt(
                    j, string.concat(base, ".lookup_challenges[", vm.toString(k + 1), "]"));
                assertEq(prefix, pair0, "bus prefix");
                assertEq(beta, pair1, "pair beta");
            }
        }
    }

    /// The cross-AIR LogUp terminal sum must vanish: the sum of all terminals is zero.
    /// No transcript involvement, but the contract must check it after the constraints,
    /// so it is checked here against the exported terminals.
    function test_lookup_terminals_sum_to_zero() public view {
        string memory j = vm.readFile(JSON);
        uint256 numInstances = vm.parseJsonUint(j, ".num_instances");
        uint256 sum;
        uint256 count;
        for (uint256 inst; inst < numInstances; ++inst) {
            string memory path =
                string.concat(".instances[", vm.toString(inst), "].lookup_terminal");
            if (vm.keyExistsJson(j, path)) {
                sum = KoalaBearExt4.add(sum, parseExt(j, path));
                ++count;
            }
        }
        assertEq(count, numInstances, "every settlement instance carries a terminal");
        assertEq(sum, 0, "terminal sum must vanish");
    }

    /// Tampering one byte of a proof commitment digest must change every downstream
    /// draw: the digest is absorbed before the lookup, permutation, quotient and OOD
    /// challenges, so the walk's sample checks fail after it. This is the binding
    /// between commitments and challenges - without it a verifier could be shown a
    /// proof whose commitments were swapped after hashing.
    function test_tampered_commitment_digest_reverts() public {
        // External frame: expectRevert needs the revert to come from a nested call.
        BatchTamperHarness harness = new BatchTamperHarness();
        vm.expectRevert();
        harness.walkTampered(BLOB);
    }

    /// Compares four consecutive base samples at off against a JSON coefficient array.
    function assertEqSamples(
        SemanticBlob.Walk memory w,
        uint256 off,
        string memory j,
        string memory path,
        string memory what
    ) private pure {
        for (uint256 i; i < 4; ++i) {
            uint256 want = vm.parseJsonUint(j, string.concat(path, "[", vm.toString(i), "]"));
            assertEq(w.samples[off + i], want, string.concat(what, " coeff"));
        }
    }

    /// Parses the JSON array of four base-field coefficients at path into the packed
    /// extension form the field library operates on.
    function parseExt(string memory j, string memory path) private pure returns (uint256) {
        uint256[4] memory coeffs;
        for (uint256 i; i < 4; ++i) {
            coeffs[i] =
                vm.parseJsonUint(j, string.concat(path, "[", vm.toString(i), "]"));
        }
        return KoalaBearExt4.pack(coeffs);
    }

    /// Lowercase hex of a 32-byte digest, matching the artifact's encoding.
    function toHex(bytes32 v) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i; i < 32; ++i) {
            out[i * 2] = alphabet[uint8(v[i]) >> 4];
            out[i * 2 + 1] = alphabet[uint8(v[i]) & 15];
        }
        return string(out);
    }
}

/// Loads a blob, flips one bit inside the variable payload (a proof commitment digest),
/// and walks with checking on. Lives outside the test contract so the revert crosses a
/// call frame and expectRevert can observe it.
contract BatchTamperHarness {
    using SemanticBlob for SemanticBlob.Blob;

    function walkTampered(string memory blobPath) external view {
        SemanticBlob.Blob memory b = SemanticBlob.load(blobPath);
        bytes memory raw = b.raw;
        raw[b.varOff + 16] = raw[b.varOff + 16] ^ bytes1(uint8(1));
        b.raw = raw;
        SemanticBlob.walk(b, true, false);
    }
}

