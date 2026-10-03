// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KeccakChallenger} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

/// Replays the WHIR verifier's own Fiat-Shamir program on the EVM sponge.
///
/// # What this checks that nothing else does
///
/// The vector is not a hand-written description of the transcript. It is the
/// absorb/squeeze sequence recorded from a real p3 WHIR verification
/// (crates/prover/tests/whir_transcript_vectors.rs), covering the labelled
/// DomainSeparator seed, every folding round, the grinding steps and the final
/// phase. p3-whir does not run a bare sponge, and the ordering is upstream
/// control flow rather than a published spec.
///
/// So this test is the bridge: the Rust side proves the vector is a genuine
/// transcript (replaying it reproduces its own squeezes), and this test proves the
/// EVM sponge reproduces the same squeezes from the same absorbs. Rust agrees with
/// the vector and Solidity agrees with the vector, therefore Solidity agrees with
/// Rust — with neither implementation serving as the other's reference. That is
/// the property a settlement verifier needs, and comparing Solidity against a Rust
/// helper written by the same author would not give it.
///
/// # Vector format
///
/// One hex string, a sequence of self-delimiting events:
///
///     op : 1 byte   (0x00 absorb, 0x01 squeeze)
///     len: 4 bytes  little-endian
///     payload: len bytes
///
/// Four length bytes, not two: a two-byte length truncates any absorb over 65535
/// bytes, and a truncated length desynchronises every later event into garbage
/// that still parses.
///
/// Flat hex rather than a JSON array because the program runs to ~6900 events;
/// one string keeps the walk a cursor rather than a parse.
contract WhirTranscriptReplayTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    string internal constant VECTOR = "test/vectors/whir_transcript_vectors.json";

    /// Reads the program and replays it, asserting every recorded squeeze.
    ///
    /// Also asserts the stream is not vacuous: it must absorb a seed at least as
    /// long as the 64-byte protocol identifier before the first squeeze, and it
    /// must squeeze something. A test that replayed an empty or absorb-only
    /// program would pass without checking anything.
    function test_replay_whir_transcript() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory program = vm.parseJsonBytes(json, ".program");
        uint256 expectedEvents = vm.parseJsonUint(json, ".events");

        KeccakChallenger.State memory state;
        uint256 pos;
        uint256 events;
        uint256 squeezedBytes;
        uint256 seedBytes;
        bool sampled;

        while (pos < program.length) {
            require(pos + 5 <= program.length, "truncated event header");
            uint8 op = uint8(program[pos]);
            uint256 len = uint256(uint8(program[pos + 1]))
                | (uint256(uint8(program[pos + 2])) << 8)
                | (uint256(uint8(program[pos + 3])) << 16)
                | (uint256(uint8(program[pos + 4])) << 24);
            pos += 5;
            require(pos + len <= program.length, "truncated event payload");

            if (op == 0) {
                state.observeBytes(_slice(program, pos, len));
                // Only the absorbs BEFORE the first squeeze are the seed. A real
                // transcript interleaves absorbs and squeezes from then on, so
                // counting later absorbs would overstate the seed.
                if (!sampled) {
                    seedBytes += len;
                }
            } else {
                require(op == 1, "unknown op");
                sampled = true;
                bytes memory got = state.sampleBytes(len);
                bytes memory want = _slice(program, pos, len);
                assertEq(
                    keccak256(got),
                    keccak256(want),
                    string.concat(
                        "squeeze ", vm.toString(events), " diverges from the recorded transcript"
                    )
                );
                squeezedBytes += len;
            }
            pos += len;
            events += 1;
        }

        assertEq(events, expectedEvents, "event count differs from the vector");
        assertGt(squeezedBytes, 0, "the program squeezed nothing, so this proved nothing");
        assertGe(seedBytes, 64, "a labelled transcript absorbs at least a 64-byte protocol id");
    }

    /// A corrupted absorb must change a later squeeze.
    ///
    /// Without this, a replay that quietly ignored the absorbs could still pass:
    /// the squeeze check alone cannot distinguish "this is a real transcript" from
    /// "the sponge was never touched". Flipping one seed byte has to change every
    /// derived challenge, and this asserts that it does.
    function test_corrupted_seed_changes_the_squeezes() public view {
        string memory json = vm.readFile(VECTOR);
        bytes memory program = vm.parseJsonBytes(json, ".program");

        // Flip the low bit of the first absorbed byte: part of the length element
        // that opens the seed, the most load-bearing byte in the stream.
        program[5] = bytes1(uint8(program[5]) ^ 1);

        KeccakChallenger.State memory state;
        uint256 pos;
        bool diverged;

        while (pos < program.length) {
            uint8 op = uint8(program[pos]);
            uint256 len = uint256(uint8(program[pos + 1]))
                | (uint256(uint8(program[pos + 2])) << 8)
                | (uint256(uint8(program[pos + 3])) << 16)
                | (uint256(uint8(program[pos + 4])) << 24);
            pos += 5;
            if (op == 0) {
                state.observeBytes(_slice(program, pos, len));
            } else {
                bytes memory got = state.sampleBytes(len);
                bytes memory want = _slice(program, pos, len);
                if (keccak256(got) != keccak256(want)) {
                    diverged = true;
                    break;
                }
            }
            pos += len;
        }

        assertTrue(diverged, "a corrupted seed produced the recorded squeezes: replay is vacuous");
    }

    /// Copies a slice of calldata-ish memory bytes into a fresh array.
    function _slice(bytes memory src, uint256 start, uint256 len)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(src, 0x20), start), len)
        }
    }
}
