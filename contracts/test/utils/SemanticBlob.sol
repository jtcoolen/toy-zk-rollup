// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

/// Reader for the WSPR transcript-program blob written by `prover::semantic_blob`.
///
/// One reader lives here so every test that replays a recorded transcript walks the
/// same format code. Two readers drift: a schedule misread in one test still
/// "passes" against a pool that was misread the same way, which is exactly the
/// self-agreeing failure mode the vector methodology exists to prevent.
///
/// Blob layout (header big-endian, field words little-endian, uniform words
/// big-endian):
///
///     magic "WSPR" | version u16 | schedule_len u16
///       | const_len | var_len | sample_len | uniform_len | witness_len   (u32 each)
///     then schedule_len entries of [kind u8, arg u8, run u16], then five payloads
///
/// Field words are little-endian because that is the order the transcript absorbs
/// them, so a constant run is exactly the byte string the sponge eats.
library SemanticBlob {
    using KeccakChallenger for KeccakChallenger.State;

    /// The standard cheatcode address, so a library can read vector files without
    /// every caller threading a `Vm` through.
    Vm internal constant VM = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 internal constant OP_CONST_U32 = 0;
    uint256 internal constant OP_VAR_U32 = 1;
    uint256 internal constant OP_COMMITMENT = 2;
    uint256 internal constant OP_SAMPLE_BASE = 3;
    uint256 internal constant OP_UNIFORM_BITS = 4;
    uint256 internal constant OP_CHECK_WITNESS = 5;
    /// A commitment digest taken from the constant payload: a trusted-setup commitment
    /// (the preprocessed trace commitment) is identical in every proof and is not part of
    /// the batch proof at all, so the contract carries it as a literal.
    uint256 internal constant OP_CONST_COMMITMENT = 6;
    /// A uniform draw wider than 16 bits, as a 4-byte big-endian word. WHIR query indices
    /// are drawn at the full LDE domain width (21 bits at log_max_lde 22).
    uint256 internal constant OP_UNIFORM_BITS_32 = 7;

    uint256 internal constant HEADER_LEN = 28;
    uint256 internal constant MAGIC = 0x57535052; // "WSPR"
    /// v2: adds OP_CONST_COMMITMENT and OP_UNIFORM_BITS_32. A v1 reader cannot parse a v2
    /// stream, so the version is asserted, not assumed.
    uint256 internal constant BLOB_VERSION = 2;
    uint256 internal constant DIGEST_LEN = 32;

    struct Blob {
        bytes raw;
        uint256 scheduleLen;
        uint256 constLen;
        uint256 varLen;
        uint256 sampleLen;
        uint256 uniformLen;
        uint256 witnessLen;
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
        /// Record-position counters for the recorded arrays in Walk. They live
        /// here (not as walk locals) to keep the walk loop inside the Yul stack
        /// limit now that it also carries a stop site.
        uint256 recordedSamples;
        uint256 recordedDigests;
    }

    /// The result of a walk: the final sponge state, the payload cursors, and -
    /// when `record` was set - every value the Solidity sponge itself produced,
    /// in draw order. The recorded arrays are what a test compares against the
    /// JSON side of an artifact, so the comparison is Solidity-vs-Rust directly
    /// rather than Solidity-vs-blob-vs-blob-vs-Rust.
    struct Walk {
        KeccakChallenger.State state;
        Cursor cursor;
        uint256[] samples;
        bytes32[] digests;
    }

    function readU32Le(bytes memory b, uint256 off) internal pure returns (uint256 v) {
        v = uint256(uint8(b[off]))
            | (uint256(uint8(b[off + 1])) << 8)
            | (uint256(uint8(b[off + 2])) << 16)
            | (uint256(uint8(b[off + 3])) << 24);
    }

    function readU16Be(bytes memory b, uint256 off) internal pure returns (uint256 v) {
        v = (uint256(uint8(b[off])) << 8) | uint256(uint8(b[off + 1]));
    }

    function readU32Be(bytes memory b, uint256 off) internal pure returns (uint256 v) {
        v = (uint256(uint8(b[off])) << 24)
            | (uint256(uint8(b[off + 1])) << 16)
            | (uint256(uint8(b[off + 2])) << 8)
            | uint256(uint8(b[off + 3]));
    }

    /// Loads and validates a blob's header, so a truncated or mis-versioned vector
    /// fails here instead of desynchronising into a bogus mismatch later.
    function load(string memory path) internal view returns (Blob memory b) {
        b.raw = VM.readFileBinary(path);
        require(b.raw.length > HEADER_LEN, "blob shorter than header");
        require(readU32Be(b.raw, 0) == MAGIC, "blob magic");
        require(readU16Be(b.raw, 4) == BLOB_VERSION, "blob version");
        b.scheduleLen = readU16Be(b.raw, 6);
        b.constLen = readU32Be(b.raw, 8);
        b.varLen = readU32Be(b.raw, 12);
        b.sampleLen = readU32Be(b.raw, 16);
        b.uniformLen = readU32Be(b.raw, 20);
        b.witnessLen = readU32Be(b.raw, 24);
        uint256 payloadStart = HEADER_LEN + b.scheduleLen * 4;
        uint256 end =
            payloadStart + b.constLen + b.varLen + b.sampleLen + b.uniformLen + b.witnessLen;
        require(b.raw.length == end, "payload lengths do not tile the blob");
        b.constOff = payloadStart;
        b.varOff = b.constOff + b.constLen;
        b.sampleOff = b.varOff + b.varLen;
        b.uniformOff = b.sampleOff + b.sampleLen;
        b.witnessOff = b.uniformOff + b.uniformLen;
    }

    /// Walks the whole schedule against one challenger.
    ///
    /// `check` asserts every sampled value, uniform draw and proof-of-work witness
    /// against the recording. `record` additionally keeps every value the Solidity
    /// sponge produced, and every commitment digest it absorbed, so a caller can
    /// compare them against independently exported values.
    function walk(Blob memory b, bool check, bool record) internal pure returns (Walk memory w) {
        w = _walk(b, type(uint256).max, check, record);
        require(w.cursor.constants + w.cursor.variables <= b.constLen + b.varLen, "walk cursors");
    }

    /// Walks the schedule up to (but not including) event site `stopSite`, parking the
    /// sponge mid-stream. This is the batch -> WHIR handover: the batch layer's events
    /// end at the delegate point with the WHIR commitment already absorbed, and the
    /// WHIR core continues on the returned sponge.
    function walkTo(Blob memory b, uint256 stopSite, bool check, bool record)
        internal
        pure
        returns (Walk memory w)
    {
        w = _walk(b, stopSite, check, record);
    }

    /// The shared walk body, stopping after `stopSite` events.
    function _walk(Blob memory b, uint256 stopSite, bool check, bool record)
        private
        pure
        returns (Walk memory w)
    {
        if (record) {
            w.samples = new uint256[](b.sampleLen / 4);
            w.digests = new bytes32[](countDigests(b));
        }
        uint256 site;
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 scheduleAt = HEADER_LEN + e * 4;
            uint256 kind = uint256(uint8(b.raw[scheduleAt]));
            uint256 arg = uint256(uint8(b.raw[scheduleAt + 1]));
            uint256 run = readU16Be(b.raw, scheduleAt + 2);
            for (uint256 k; k < run; ++k) {
                if (site >= stopSite) {
                    return w;
                }
                ++site;
                if (kind == OP_CONST_U32) {
                    w.state.observeBase(readU32Le(b.raw, b.constOff + w.cursor.constants));
                    w.cursor.constants += 4;
                } else if (kind == OP_VAR_U32) {
                    w.state.observeBase(readU32Le(b.raw, b.varOff + w.cursor.variables));
                    w.cursor.variables += 4;
                } else if (kind == OP_COMMITMENT || kind == OP_CONST_COMMITMENT) {
                    w.cursor.recordedDigests =
                        absorbDigest(b, w, kind == OP_CONST_COMMITMENT, record, w.cursor.recordedDigests);
                } else if (kind == OP_SAMPLE_BASE) {
                    uint256 got = w.state.sampleBase();
                    if (record) {
                        w.samples[w.cursor.recordedSamples] = got;
                        ++w.cursor.recordedSamples;
                    }
                    if (check) {
                        require(
                            got == readU32Le(b.raw, b.sampleOff + w.cursor.samples),
                            string.concat("sample mismatch at site ", VM.toString(site))
                        );
                    }
                    w.cursor.samples += 4;
                } else if (kind == OP_UNIFORM_BITS || kind == OP_UNIFORM_BITS_32) {
                    uint256 got = w.state.sampleBits(arg);
                    bool wide = kind == OP_UNIFORM_BITS_32;
                    uint256 want = wide
                        ? readU32Be(b.raw, b.uniformOff + w.cursor.uniform)
                        : readU16Be(b.raw, b.uniformOff + w.cursor.uniform);
                    if (check) {
                        requireUniform(got, want, site, arg);
                    }
                    w.cursor.uniform += wide ? 4 : 2;
                } else {
                    require(
                        kind == OP_CHECK_WITNESS,
                        string.concat(
                            "unknown schedule op ",
                            VM.toString(kind),
                            " at site ",
                            VM.toString(site)
                        )
                    );
                    uint256 witness = readU32Le(b.raw, b.witnessOff + w.cursor.witnesses);
                    if (check) {
                        require(w.state.checkWitness(arg, witness), "proof-of-work witness rejected");
                    } else {
                        w.state.checkWitness(arg, witness);
                    }
                    w.cursor.witnesses += 4;
                }
            }
        }
    }

    /// Compares one uniform draw against the recording, naming the site on failure.
    ///
    /// Extracted so the walk loop stays inside the Yul stack limit.
    function requireUniform(uint256 got, uint256 want, uint256 site, uint256 bits)
        private
        pure
    {
        if (got != want) {
            revert(
                string.concat(
                    "uniform mismatch site ",
                    VM.toString(site),
                    " bits ",
                    VM.toString(bits),
                    " want ",
                    VM.toString(want),
                    " got ",
                    VM.toString(got)
                )
            );
        }
    }

    /// Absorbs one commitment digest from the constant or variable payload, records it
    /// when asked, advances the matching cursor, and returns the digest counter.
    ///
    /// Extracted because the walk loop otherwise overflows the Yul stack.
    function absorbDigest(
        Blob memory b,
        Walk memory w,
        bool fromConstants,
        bool record,
        uint256 nDigest
    ) private pure returns (uint256) {
        uint256 at =
            fromConstants ? b.constOff + w.cursor.constants : b.varOff + w.cursor.variables;
        bytes memory digest = sliceDigest(b.raw, at);
        w.state.observeBytes(digest);
        if (record) {
            w.digests[nDigest] = bytes32(digest);
            ++nDigest;
        }
        if (fromConstants) {
            w.cursor.constants += DIGEST_LEN;
        } else {
            w.cursor.variables += DIGEST_LEN;
        }
        return nDigest;
    }

    /// Absorbs ONLY the constant runs, in order, and returns how many bytes they were.
    ///
    /// This is not the protocol order - samples interleave and flush the buffer - so it
    /// is a parity check on the absorb path rather than a transcript replay. It is what
    /// lets a test pin the sponge state over the config-fixed constants, which are the
    /// exact bytes a verifier hard-codes and therefore the exact bytes that must not
    /// drift between the prover and the contract.
    function absorbConstants(Blob memory b) internal pure returns (KeccakChallenger.State memory st, uint256 absorbed) {
        uint256 at = b.constOff;
        uint256 scheduleAt = HEADER_LEN;
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 kind = uint256(uint8(b.raw[scheduleAt]));
            uint256 run = readU16Be(b.raw, scheduleAt + 2);
            scheduleAt += 4;
            if (kind == OP_CONST_COMMITMENT) {
                for (uint256 k; k < run; ++k) {
                    st.observeBytes(sliceDigest(b.raw, at));
                    at += DIGEST_LEN;
                }
            } else if (kind != OP_CONST_U32) {
                continue;
            } else {
                for (uint256 k; k < run; ++k) {
                    st.observeBase(readU32Le(b.raw, at));
                    at += 4;
                }
            }
        }
        absorbed = at - b.constOff;
    }

    /// Number of commitment absorbs in the schedule, so the recorded digest array can
    /// be sized before the walk.
    function countDigests(Blob memory b) internal pure returns (uint256 n) {
        for (uint256 e; e < b.scheduleLen; ++e) {
            uint256 at = HEADER_LEN + e * 4;
            uint256 kind = uint256(uint8(b.raw[at]));
            if (kind == OP_COMMITMENT || kind == OP_CONST_COMMITMENT) {
                // One digest per absorbed site: the run length, not one per entry.
                n += readU16Be(b.raw, at + 2);
            }
        }
    }

    /// Copies one 32-byte digest out of the blob. Commitments are rare, so the copy
    /// is free next to the absorb it feeds.
    function sliceDigest(bytes memory raw, uint256 off) internal pure returns (bytes memory out) {
        out = new bytes(DIGEST_LEN);
        assembly ("memory-safe") {
            mstore(add(out, 0x20), mload(add(add(raw, 0x20), off)))
        }
    }
}
