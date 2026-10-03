// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofCodec} from "../src/verifier/ProofCodec.sol";

/// The postcard decoder, pinned against bytes the Rust serializer produced.
///
/// Every expectation here comes from a prover-emitted vector, never from a
/// Solidity-side reimplementation of postcard. That distinction is the point: a
/// decoder tested against a second decoder written by the same author, in the
/// same language, proves nothing about the wire format.
///
/// ## Why the tests call through external wrappers
///
/// ProofCodec takes bytes calldata on purpose - the settlement proof is ~676 KB
/// and copying it to memory would cost more than verifying it. But a bytes
/// memory value cannot be passed where bytes calldata is expected, so a test
/// that built its fixture in memory could not call the library at all. Routing
/// through an external function is the only way to get genuine calldata, and it
/// has a second benefit: it exercises the same ABI boundary the real verifier
/// entry point will use.
contract ProofCodecTest is Test {
    using ProofCodec for bytes;

    string internal constant VECTORS = "test/vectors/";

    // -----------------------------------------------------------------------
    // External wrappers: the only way to hand the library real calldata
    // -----------------------------------------------------------------------

    function decodeU32(bytes calldata blob) external pure returns (uint32 v, uint256 pos) {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (v, c) = blob.readU32(c);
        pos = c.pos;
    }

    function decodeBool(bytes calldata blob) external pure returns (bool v, uint256 pos) {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (v, c) = blob.readBool(c);
        pos = c.pos;
    }

    function decodeOptionTag(bytes calldata blob) external pure returns (bool present, uint256 pos) {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (present, c) = blob.readOptionTag(c);
        pos = c.pos;
    }

    /// Skips one MerkleCap (count plus one digest), then reads the Option tag.
    function decodeOptionTagAfterCap(bytes calldata blob)
        external
        pure
        returns (bool present, uint256 pos)
    {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (, c) = blob.readUsize(c);
        (, c) = blob.readDigest(c);
        (present, c) = blob.readOptionTag(c);
        pos = c.pos;
    }

    function decodeBytesVec(bytes calldata blob)
        external
        pure
        returns (bytes memory out, uint256 pos)
    {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (out, c) = blob.readBytesVec(c);
        pos = c.pos;
    }

    function digestAt(bytes calldata blob, uint256 off) external pure returns (bytes32, uint256) {
        ProofCodec.Cursor memory c = ProofCodec.Cursor(off);
        (bytes32 d, ProofCodec.Cursor memory next) = blob.readDigest(c);
        return (d, next.pos);
    }

    function finishAt(bytes calldata blob, uint256 pos) external pure {
        blob.finish(ProofCodec.Cursor(pos));
    }

    /// Everything the composite walk produces.
    ///
    /// A struct rather than fifteen return values: the EVM stack cannot hold
    /// that many, and the compiler says so with a stack-too-deep error rather
    /// than a helpful hint.
    struct Composite {
        uint8 tag;
        uint32 small;
        uint32 big;
        bool flag;
        bool presentTag;
        uint32 presentValue;
        bool absentTag;
        uint32[4] fixedVals;
        uint256 listLen;
        /// Last item of the list; meaningless when listLen is 0.
        uint32 listLast;
        uint256 wideLen;
        uint32 wideLast;
        uint256 pos;
    }

    /// Walks the composite fixture end to end.
    function walkComposite(bytes calldata blob) external pure returns (Composite memory out) {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (out.tag, c) = blob.readByte(c);
        (out.small, c) = blob.readU32(c);
        (out.big, c) = blob.readU32(c);
        (out.flag, c) = blob.readBool(c);
        (out.presentTag, c) = blob.readOptionTag(c);
        (out.presentValue, c) = blob.readU32(c);
        (out.absentTag, c) = blob.readOptionTag(c);
        // A fixed array carries NO length prefix.
        for (uint256 i; i < 4; ++i) {
            (out.fixedVals[i], c) = blob.readU32(c);
        }
        (out.listLen, c) = blob.readUsize(c);
        for (uint256 i; i < out.listLen; ++i) {
            (out.listLast, c) = blob.readU32(c);
        }
        (out.wideLen, c) = blob.readUsize(c);
        for (uint256 i; i < out.wideLen; ++i) {
            (out.wideLast, c) = blob.readU32(c);
        }
        blob.finish(c);
        out.pos = c.pos;
    }

    /// Walks the leading fields of a real settlement proof and returns the
    /// cursor position plus the two values a caller must not get wrong: the
    /// blinding tag and the first opening length.
    function walkProofLeading(bytes calldata blob)
        external
        pure
        returns (uint256 traceCount, bool randomPresent, uint256 traceLocalLen, uint256 pos)
    {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (traceCount, c) = blob.readUsize(c);
        (, c) = blob.readDigest(c);
        (, c) = blob.readUsize(c);
        (, c) = blob.readDigest(c);
        (randomPresent, c) = blob.readOptionTag(c);
        if (randomPresent) {
            (, c) = blob.readUsize(c);
            (, c) = blob.readDigest(c);
        }
        (traceLocalLen, c) = blob.readUsize(c);
        // The vector records exactly the bytes this walk consumes, so a cursor
        // that drifted anywhere above lands somewhere other than the end and
        // finish() reverts. This is the strongest single assertion in the file:
        // it fails for any misread varint, tag, or digest width.
        blob.finish(c);
        pos = c.pos;
    }

    // -----------------------------------------------------------------------
    // Varints
    // -----------------------------------------------------------------------

    /// Every varint edge case, decoded from the bytes postcard emitted.
    function test_varint_edges_match_rust() public view {
        string memory path = string.concat(VECTORS, "varint_vectors.json");
        string memory json = vm.readFile(path);
        uint256 n = vm.parseJsonUint(json, ".case_count");
        assertEq(n, 12, "expected the full edge-case set");
        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".values[", vm.toString(i), "]");
            uint64 want = uint64(vm.parseJsonUint(json, string.concat(base, ".value")));
            bytes memory encoded = vm.parseJsonBytes(json, string.concat(base, ".u32_hex"));

            (uint32 got, uint256 pos) = this.decodeU32(encoded);
            assertEq(uint256(got), uint256(want), "varint value mismatch");
            assertEq(pos, encoded.length, "varint did not consume its own encoding");
        }
    }

    /// 127 is the last one-byte value and 128 the first two-byte one. A reader
    /// with the continuation test inverted handles these wrong and everything
    /// else right, which is the worst kind of bug to leave in.
    function test_varint_boundary_between_one_and_two_bytes() public view {
        (uint32 a, uint256 pa) = this.decodeU32(hex"7f");
        assertEq(a, 127);
        assertEq(pa, 1);

        (uint32 b, uint256 pb) = this.decodeU32(hex"8001");
        assertEq(b, 128);
        assertEq(pb, 2);
    }

    /// ff ff ff ff 0f is the exact five-byte form of u32::MAX, with a final
    /// group of 15 - the most a u32 can hold in its last group. postcard accepts
    /// precisely this, so the contract must too, or it would reject honest
    /// proofs that carry a full-width value.
    function test_u32_max_uses_the_full_five_byte_form() public view {
        (uint32 v, uint256 pos) = this.decodeU32(hex"ffffffff0f");
        assertEq(v, type(uint32).max);
        assertEq(pos, 5);
    }

    /// Six groups is out of range for a u32. postcard rejects this with
    /// DeserializeBadVarint; accepting it would let the contract verify a proof
    /// the Rust verifier refuses.
    function test_reject_varint_exceeding_u32() public {
        vm.expectRevert(abi.encodeWithSelector(ProofCodec.VarintOutOfRange.selector, uint256(0)));
        this.decodeU32(hex"ffffffffff7f");
    }

    /// 80 00 is a redundant encoding of zero. The postcard reader accepts it and
    /// the writer never emits it, so rejecting it costs nothing in liveness and
    /// buys proof-byte uniqueness: with two encodings of one proof,
    /// keccak256(proof) stops being a sound identity and any replay guard keyed
    /// on proof bytes becomes bypassable.
    function test_reject_non_canonical_varint() public {
        vm.expectRevert(abi.encodeWithSelector(ProofCodec.VarintNotCanonical.selector, uint256(0)));
        this.decodeU32(hex"8000");
    }

    /// A continuation bit with nothing after it.
    function test_reject_truncated_varint() public {
        vm.expectRevert(
            abi.encodeWithSelector(ProofCodec.ProofTruncated.selector, uint256(1), uint256(1))
        );
        this.decodeU32(hex"80");
    }

    // -----------------------------------------------------------------------
    // Composite shapes
    // -----------------------------------------------------------------------

    /// The shapes the proof is built from, walked against postcard bytes.
    ///
    /// Each shape carries a rule a hand-rolled decoder gets wrong: Option is a
    /// tag rather than a length, a fixed array has NO length prefix, bool is one
    /// byte, and u8 is a raw byte while everything wider is a varint.
    function test_composite_shapes_match_rust() public view {
        string memory path = string.concat(VECTORS, "composite_vectors.json");
        string memory json = vm.readFile(path);
        uint256 n = vm.parseJsonUint(json, ".case_count");
        assertEq(n, 2, "expected both bool encodings");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".cases[", vm.toString(i), "]");
            bytes memory blob = vm.parseJsonBytes(json, string.concat(base, ".hex"));
            bool wantFlag = vm.parseJsonBool(json, string.concat(base, ".flag"));
            uint64 wantPresent = uint64(vm.parseJsonUint(json, string.concat(base, ".present")));
            uint256 wantWideLen = vm.parseJsonUint(json, string.concat(base, ".wide_len"));
            uint64 wantWideLast = uint64(vm.parseJsonUint(json, string.concat(base, ".wide_last")));
            uint256 wantLen = vm.parseJsonUint(json, string.concat(base, ".len"));

            Composite memory got = this.walkComposite(blob);

            assertEq(got.tag, 0xff, "u8 must be a raw byte, not a varint");
            assertEq(got.small, 1);
            assertEq(got.big, type(uint32).max, "u32::MAX must survive the round trip");
            assertEq(got.flag, wantFlag);
            assertTrue(got.presentTag, "Some must tag as 1");
            assertEq(got.presentValue, wantPresent);
            assertFalse(got.absentTag, "None must tag as 0 and carry no payload");
            assertEq(got.fixedVals[0], 0);
            assertEq(got.fixedVals[1], 1);
            assertEq(got.fixedVals[2], 127);
            assertEq(got.fixedVals[3], 128, "fixed array read without a length prefix");
            assertEq(got.listLen, i == 0 ? 0 : 1, "zero-length Vec must decode");
            // The item VALUE is only meaningful when the list is non-empty, so
            // this is asserted per case rather than inside the shared walker.
            assertEq(got.listLast, i == 0 ? 0 : 7, "Vec item value mismatch");
            assertEq(got.wideLen, wantWideLen);
            assertEq(got.wideLast, wantWideLast);
            assertEq(got.pos, wantLen, "cursor must land exactly on the encoded length");
        }
    }

    /// bool has two legal encodings. Anything else is a decoding error, not a
    /// truthy byte - matching DeserializeBadBool.
    function test_reject_bad_bool() public {
        vm.expectRevert(abi.encodeWithSelector(ProofCodec.BadBool.selector, uint256(0), uint8(2)));
        this.decodeBool(hex"02");
    }

    function test_accept_both_bool_encodings() public view {
        (bool f, uint256 pf) = this.decodeBool(hex"00");
        assertFalse(f);
        assertEq(pf, 1);
        (bool t, uint256 pt) = this.decodeBool(hex"01");
        assertTrue(t);
        assertEq(pt, 1);
    }

    function test_reject_bad_option_tag() public {
        vm.expectRevert(
            abi.encodeWithSelector(ProofCodec.BadOptionTag.selector, uint256(0), uint8(2))
        );
        this.decodeOptionTag(hex"02");
    }

    // -----------------------------------------------------------------------
    // A real proof
    // -----------------------------------------------------------------------

    /// Walks the leading fields of a real settlement proof.
    ///
    /// This is the test that matters most. Everything above checks primitives;
    /// this checks the ORDER the prover writes them in, and that a MerkleCap is
    /// a varint count plus digests rather than a bare digest. Getting the cap
    /// wrong desynchronises the cursor at byte 0, and every later field then
    /// decodes cleanly into garbage - which is exactly how a verifier ends up
    /// checking a commitment nobody committed to.
    function test_walk_real_proof_leading_fields() public view {
        string memory path = string.concat(VECTORS, "proof_shape.json");
        string memory json = vm.readFile(path);
        bytes memory blob = vm.parseJsonBytes(json, ".leading_hex");

        (uint256 traceCount, bool randomPresent, uint256 traceLocalLen, uint256 pos) =
            this.walkProofLeading(blob);

        assertEq(traceCount, vm.parseJsonUint(json, ".commitments_trace_count"), "trace cap count");
        assertEq(traceCount, 1, "cap_height 0 means one digest per cap");
        assertEq(
            uint8(randomPresent ? 1 : 0),
            vm.parseJsonUint(json, ".commitments_random_tag"),
            "blinding tag"
        );
        assertEq(traceLocalLen, vm.parseJsonUint(json, ".opened_values_trace_local_len"));
        assertEq(pos, vm.parseJsonUint(json, ".cursor_after_leading"), "cursor walk diverged");
    }

    /// The settlement proof must carry a blinding commitment.
    ///
    /// random = None means a NON-zero-knowledge proof. The Rust verifier rejects
    /// that mismatch against SC::Pcs::ZK; this is the same check at the wire
    /// layer, and asserting the recorded tag is Some means a prover that
    /// silently stopped blinding fails here instead of shipping a linkable
    /// proof.
    function test_real_proof_carries_blinding_commitment() public view {
        string memory path = string.concat(VECTORS, "proof_shape.json");
        string memory json = vm.readFile(path);
        bytes memory blob = vm.parseJsonBytes(json, ".leading_hex");
        (, bool randomPresent,,) = this.walkProofLeading(blob);
        assertTrue(randomPresent, "a blinded proof must carry the mask commitment");
    }

    /// Tag 00 must decode as None and consume exactly one byte, so the absence
    /// of blinding is visible rather than a silent cursor slip.
    function test_absent_blinding_is_decoded_as_none() public view {
        bytes memory blob = abi.encodePacked(hex"01", new bytes(32), hex"00");
        (bool present, uint256 pos) = this.decodeOptionTagAfterCap(blob);
        assertFalse(present);
        assertEq(pos, 34, "None consumes the tag byte and nothing else");
    }

    // -----------------------------------------------------------------------
    // Bounds and framing
    // -----------------------------------------------------------------------

    function test_reject_digest_past_the_end() public {
        bytes memory short = new bytes(31);
        vm.expectRevert(
            abi.encodeWithSelector(ProofCodec.BadLength.selector, uint256(32), uint256(31))
        );
        this.digestAt(short, 0);
    }

    /// finish is what stops a proof from carrying a second, unchecked payload
    /// after the fields the verifier looked at.
    function test_reject_trailing_bytes() public {
        bytes memory blob = hex"0100";
        vm.expectRevert(
            abi.encodeWithSelector(ProofCodec.BadLength.selector, uint256(2), uint256(1))
        );
        this.finishAt(blob, 1);
    }

    function test_finish_accepts_exact_consumption() public view {
        this.finishAt(hex"01", 1);
    }

    function test_readBytesVec_matches_length_prefix() public view {
        (bytes memory out, uint256 pos) = this.decodeBytesVec(hex"03aabbcc");
        assertEq(out.length, 3);
        assertEq(uint8(out[0]), 0xaa);
        assertEq(uint8(out[2]), 0xcc);
        assertEq(pos, 4);
    }

    function test_readBytesVec_rejects_short_payload() public {
        vm.expectRevert(
            abi.encodeWithSelector(ProofCodec.BadLength.selector, uint256(5), uint256(2))
        );
        this.decodeBytesVec(hex"05aabb");
    }

    /// A digest read must equal the same 32 bytes assembled one byte at a time.
    ///
    /// The expected value here is built by an explicit shift-and-or loop, which
    /// shares no code with readDigest. Comparing the decoder against a copy of
    /// itself would pass no matter what it did; this pins the BYTE ORDER as well
    /// as the offset, which is the part that silently produces a digest nobody
    /// committed to. Sweeping every offset covers all 32 alignments.
    function test_readDigest_matches_byte_by_byte_at_every_offset() public view {
        bytes memory blob = new bytes(96);
        for (uint256 i; i < blob.length; ++i) {
            blob[i] = bytes1(uint8(7 + i));
        }
        for (uint256 off; off < 64; ++off) {
            (bytes32 viaCodec, uint256 pos) = this.digestAt(blob, off);
            assertEq(pos, off + 32, "digest must advance exactly 32");

            bytes32 want;
            for (uint256 i; i < 32; ++i) {
                // bytes32(bytes1) LEFT-aligns, so byte off lands in the most
                // significant slot and each later byte shifts RIGHT by 8. That is
                // the order a digest has: byte 0 is the most significant, so the
                // result equals what keccak256 returns over the same bytes.
                want |= bytes32(blob[off + i]) >> (8 * i);
            }
            assertEq(viaCodec, want, "digest byte order or base offset diverged");
        }
    }

    /// A digest read straight out of a real proof must equal the digest the Rust
    /// prover recorded for the same field.
    function test_readDigest_matches_recorded_proof_digest() public view {
        string memory path = string.concat(VECTORS, "proof_shape.json");
        string memory json = vm.readFile(path);
        bytes memory blob = vm.parseJsonBytes(json, ".leading_hex");

        // The trace cap is: varint count (1 byte), then one 32-byte digest.
        (bytes32 traceDigest,) = this.digestAt(blob, 1);
        bytes memory want = vm.parseJsonBytes(json, ".commitments_trace_digests[0]");
        assertEq(abi.encodePacked(traceDigest).length, 32);
        assertEq(
            traceDigest,
            bytes32(want),
            "the digest read from the proof differs from the one the prover committed"
        );
    }
}
