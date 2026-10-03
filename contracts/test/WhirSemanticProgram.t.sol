// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {KeccakChallenger} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

/// Replays the WHIR verifier transcript at the PROTOCOL level.
///
/// The sibling WhirTranscriptReplay test replays a byte stream. This replays the
/// OPERATION stream, which is the level the verifier is written at: each entry says
/// observe this, sample that, check a proof-of-work witness. The distinction matters
/// because the byte stream is not reproducible - a squeeze flushes a partially-filled
/// output buffer, so how many bytes it absorbs depends on how many rejection samples
/// happened upstream, and two recordings of the SAME proof differ at squeeze sites.
/// The operation stream is identical across witnesses, measured over four.
///
/// The vector comes from crates/prover/tests/whir_semantic_program.rs, which proves
/// with the production config and VERIFIES through the recorder. Verification passing
/// is the evidence that the recorded operations are the ones p3 actually ran. So that
/// test and this one together make Solidity agree with Rust without either being the
/// other reference - the property a settlement verifier needs.
///
/// This test is what found two real bugs in the vendored challenger: observeBase did
/// not invalidate buffered output, and checkWitness omitted the squeeze that folds
/// pending input into the digest before the witness is absorbed.
///
/// Blob layout (header big-endian, field words little-endian):
///
///     magic "WSPR" | version u16 | schedule_len u16
///       | const_len | var_len | sample_len | uniform_len | witness_len   (u32 each)
///     then schedule_len entries of [kind u8, arg u8, run u16], then five payloads
///
/// Field words are little-endian because that is the order the transcript absorbs
/// them, so a constant run is exactly the byte string the sponge eats.
contract WhirSemanticProgramTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    /// The blob is the whole spec: header, schedule and five payloads in one binary.
    /// Read with `readFileBinary` so there is no hex copy to keep in step with it.
    string internal constant BLOB = "test/vectors/whir_semantic_program.bin";

    uint256 internal constant OP_CONST_U32 = 0;
    uint256 internal constant OP_VAR_U32 = 1;
    uint256 internal constant OP_COMMITMENT = 2;
    uint256 internal constant OP_SAMPLE_BASE = 3;
    uint256 internal constant OP_UNIFORM_BITS = 4;
    uint256 internal constant OP_CHECK_WITNESS = 5;

    uint256 internal constant HEADER_LEN = 28;
    uint256 internal constant MAGIC = 0x57535052; // "WSPR"
    uint256 internal constant DIGEST_LEN = 32;

    struct Blob {
        bytes raw;
        uint256 scheduleLen;
        uint256 constOff;
        uint256 varOff;
        uint256 sampleOff;
        uint256 uniformOff;
        uint256 witnessOff;
    }

    /// Cursors into the five payloads, advanced as the schedule is walked.
    struct Cursor {
        uint256 constants;
        uint256 variables;
        uint256 samples;
        uint256 uniform;
        uint256 witnesses;
    }

    function readU32Le(bytes memory b, uint256 off) private pure returns (uint256 v) {
        v = uint256(uint8(b[off]))
            | (uint256(uint8(b[off + 1])) << 8)
            | (uint256(uint8(b[off + 2])) << 16)
            | (uint256(uint8(b[off + 3])) << 24);
    }

    function readU16Be(bytes memory b, uint256 off) private pure returns (uint256 v) {
        v = (uint256(uint8(b[off])) << 8) | uint256(uint8(b[off + 1]));
    }

    function readU32Be(bytes memory b, uint256 off) private pure returns (uint256 v) {
        v = (uint256(uint8(b[off])) << 24)
            | (uint256(uint8(b[off + 1])) << 16)
            | (uint256(uint8(b[off + 2])) << 8)
            | uint256(uint8(b[off + 3]));
    }

    /// Loads and validates the blob header, so a truncated or mis-versioned vector
    /// fails here instead of desynchronising into a bogus mismatch later.
    function loadBlob() internal view returns (Blob memory b) {
        b.raw = vm.readFileBinary(BLOB);
        require(b.raw.length > HEADER_LEN, "blob shorter than header");
        require(readU32Be(b.raw, 0) == MAGIC, "blob magic");
        assertEq(readU16Be(b.raw, 4), 1, "blob version");
        b.scheduleLen = readU16Be(b.raw, 6);
        uint256 payloadStart = HEADER_LEN + b.scheduleLen * 4;
        uint256 end = payloadStart + readU32Be(b.raw, 8) + readU32Be(b.raw, 12)
            + readU32Be(b.raw, 16) + readU32Be(b.raw, 20) + readU32Be(b.raw, 24);
        assertEq(b.raw.length, end, "payload lengths do not tile the blob");
        b.constOff = payloadStart;
        b.varOff = b.constOff + readU32Be(b.raw, 8);
        b.sampleOff = b.varOff + readU32Be(b.raw, 12);
        b.uniformOff = b.sampleOff + readU32Be(b.raw, 16);
        b.witnessOff = b.uniformOff + readU32Be(b.raw, 20);
    }

    /// Walks the whole schedule against one challenger.
    ///
    /// `check` asserts every sampled value against the recording. With it off the same
    /// walk only advances the sponge, which is what the state-pinning test wants.
    function walk(Blob memory b, bool check)
        internal
        pure
        returns (KeccakChallenger.State memory st, Cursor memory c)
    {
        uint256 scheduleAt = HEADER_LEN;
        uint256 site;
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 kind = uint256(uint8(b.raw[scheduleAt]));
            uint256 arg = uint256(uint8(b.raw[scheduleAt + 1]));
            uint256 run = readU16Be(b.raw, scheduleAt + 2);
            scheduleAt += 4;
            for (uint256 k; k < run; ++k) {
                ++site;
                if (kind == OP_CONST_U32) {
                    st.observeBase(readU32Le(b.raw, b.constOff + c.constants));
                    c.constants += 4;
                } else if (kind == OP_VAR_U32) {
                    st.observeBase(readU32Le(b.raw, b.varOff + c.variables));
                    c.variables += 4;
                } else if (kind == OP_COMMITMENT) {
                    st.observeBytes(sliceDigest(b.raw, b.varOff + c.variables));
                    c.variables += DIGEST_LEN;
                } else if (kind == OP_SAMPLE_BASE) {
                    uint256 got = st.sampleBase();
                    if (check) {
                        require(
                            got == readU32Le(b.raw, b.sampleOff + c.samples),
                            string.concat("sample mismatch at site ", vm.toString(site))
                        );
                    }
                    c.samples += 4;
                } else if (kind == OP_UNIFORM_BITS) {
                    uint256 got = st.sampleBits(arg);
                    if (check) {
                        require(
                            got == readU16Be(b.raw, b.uniformOff + c.uniform),
                            string.concat("uniform bits mismatch at site ", vm.toString(site), " bits ", vm.toString(arg))
                        );
                    }
                    c.uniform += 2;
                } else {
                    uint256 witness = readU32Le(b.raw, b.witnessOff + c.witnesses);
                    if (check) {
                        assertTrue(st.checkWitness(arg, witness), "proof-of-work witness rejected");
                    } else {
                        st.checkWitness(arg, witness);
                    }
                    c.witnesses += 4;
                }
            }
        }
        assertEq(scheduleAt, b.constOff, "schedule did not end at the payloads");
    }

    /// Copies one 32-byte digest out of the blob. Only seven commitments appear in the
    /// whole program, so the copy is free next to the absorb it feeds.
    function sliceDigest(bytes memory raw, uint256 off) private pure returns (bytes memory out) {
        out = new bytes(DIGEST_LEN);
        assembly ("memory-safe") {
            mstore(add(out, 0x20), mload(add(add(raw, 0x20), off)))
        }
    }

    /// Replays every recorded operation on the EVM sponge and asserts every recorded
    /// sample. If the Solidity sampler consumed bytes in a different order, or with a
    /// different rejection bound, a sample would mismatch at the site named in the log.
    function test_replay_semantic_program() public view {
        Blob memory b = loadBlob();
        (KeccakChallenger.State memory st, Cursor memory c) = walk(b, true);

        // Every payload consumed exactly. A short read means the schedule and the
        // payloads disagree, which would leave a verifier absorbing the wrong bytes at
        // some later, unnamed site.
        assertEq(c.constants, readU32Be(b.raw, 8), "constant payload not fully read");
        assertEq(c.variables, readU32Be(b.raw, 12), "variable payload not fully read");
        assertEq(c.samples, readU32Be(b.raw, 16), "sample payload not fully read");
        assertEq(c.uniform, readU32Be(b.raw, 20), "uniform payload not fully read");
        assertEq(c.witnesses, readU32Be(b.raw, 24), "witness payload not fully read");
        assertEq(c.samples / 4, 224, "sample count");
        assertEq(c.witnesses / 4, 23, "witness check count");
        assertTrue(st.outputIndex <= DIGEST_LEN, "output index out of range");
    }
    /// A golden that survives regenerating the vector.
    ///
    /// The chaining state after the FULL replay is not pinnable: the proof is
    /// HVZK-blinded, so every regeneration changes the proof data, and with it every
    /// sample and the final state. Verified by recording the same witness three times
    /// - the schedule and the config-fixed constant payload were byte-identical, while
    /// the variable, sample, uniform and witness payloads all moved.
    ///
    /// The config-fixed constants are exactly the part a verifier hard-codes, so
    /// absorbing them through the challenger and pinning the result pins the things
    /// that must not drift: little-endian word encoding in observeBase, buffer growth,
    /// and the flush-chaining rule that hashes the previous digest forward. A pure
    /// Python sponge written from the p3 source reaches the same state.
    ///
    /// This absorbs the constant payload as a sequence, which is not the real
    /// transcript order - samples interleave and flush. It is a parity check on the
    /// absorb path, not a replay of the protocol.
    function test_config_fixed_constants_reach_pinned_state() public view {
        Blob memory b = loadBlob();
        KeccakChallenger.State memory st;
        uint256 constAt = b.constOff;
        uint256 scheduleAt = HEADER_LEN;
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 kind = uint256(uint8(b.raw[scheduleAt]));
            uint256 run = readU16Be(b.raw, scheduleAt + 2);
            scheduleAt += 4;
            if (kind != OP_CONST_U32) {
                continue;
            }
            for (uint256 k; k < run; ++k) {
                st.observeBase(readU32Le(b.raw, constAt));
                constAt += 4;
            }
        }
        assertEq(constAt - b.constOff, readU32Be(b.raw, 8), "not every constant absorbed");
        assertEq(
            st.debugInputHash(),
            0xa8eac9b8e75e9fab0bc7981fce47e33fea382bea2cf648185268c6ad07a1eea7,
            "chaining state over config-fixed constants"
        );
    }
}