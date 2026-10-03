// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Decoding the prover's postcard wire format out of calldata.
///
/// The proof reaches the contract as one opaque `bytes` blob because that is
/// what `p3-uni-stark::Proof` serialises to with postcard, and postcard is what
/// the prover and the node already speak. Re-encoding it into an ABI tuple on
/// the way in would mean trusting a second serialisation path; instead the
/// contract decodes the same bytes the Rust verifier decodes.
///
/// ## The format, in full
///
/// postcard is small enough to state exactly, and every rule here is load-
/// bearing:
///
/// - Integers are **unsigned LEB128 varints**: 7 payload bits per byte, least
///   significant group first, high bit set on every byte but the last. So 0..127
///   is one byte, 128..16383 is two.
/// - `Vec<T>` is a varint length followed by that many `T`, with no padding.
/// - `Option<T>` is a one-byte tag: `0x00` for `None`, `0x01` followed by the
///   value for `Some`. There is no other legal tag.
/// - `[T; N]` is `N` values with **no** length prefix, since `N` is a compile-
///   time constant on both sides.
/// - `bool` is one byte, `0x00` or `0x01`. Any other byte is a decoding error,
///   not truthy.
///
/// ## Matching the Rust decoder exactly, and where we are deliberately stricter
///
/// Two divergences are possible and they are not equally bad.
///
/// Accepting what Rust rejects is a **soundness** bug: the contract would
/// verify a proof `p3-uni-stark::verify` refuses, so the chain would settle a
/// statement no honest verifier agrees to. So the varint bounds here are copied
/// from postcard 1.1.3 rather than invented:
///
/// | type   | max bytes | max value in the final byte |
/// |--------|-----------|-----------------------------|
/// | `u32`  | 5         | 15  (`(1 << 32%7) - 1`)     |
/// | `u64`  | 10        | 1   (`(1 << 64%7) - 1`)     |
///
/// and `bool` / `Option` reject every byte outside their legal set, as
/// `DeserializeBadBool` / `DeserializeBadOption` do.
///
/// Rejecting what Rust accepts is a **liveness** bug, and there is one place
/// where this contract is intentionally stricter: postcard's varint reader does
/// NOT reject a redundant trailing zero group, so `80 00` decodes as 0. We do
/// reject it (`VarintNotCanonical`). postcard's *serializer* only ever emits
/// minimal encodings, so no honest proof can carry a non-canonical varint -
/// meaning this costs nothing in liveness and buys something real: the proof's
/// bytes become a unique encoding of its contents, so `keccak256(proof)` is a
/// sound identity for it. Without that, one proof has many byte representations
/// and any replay guard keyed on proof bytes is bypassable.
///
/// ## Why every read is bounds-checked
///
/// A desynchronised cursor is the failure mode that matters. If a varint is
/// misread or a tag byte is skipped, the remaining fields still decode - into
/// unrelated bytes. That is how a verifier ends up checking a commitment that
/// was never committed to. So reads past the end revert, and `finish` requires
/// the cursor to land exactly on the end: trailing bytes mean the decoder
/// stopped early, and accepting them would let a proof carry a second,
/// unchecked payload.
///
/// ## Why the cursor is an offset, not a slice
///
/// The proof arrives in calldata and is never copied to memory. Every accessor
/// takes `bytes calldata` plus a cursor and returns the advanced cursor, so a
/// full decode touches each calldata word once. Copying a ~676 KB proof into
/// memory would cost more than the verification itself.
library ProofCodec {
    /// Read position into a proof blob.
    ///
    /// Deliberately a plain offset: the bytes stay in calldata, so the cursor is
    /// one word and can live on the stack.
    struct Cursor {
        uint256 pos;
    }

    /// The proof ended where a value was expected.
    error ProofTruncated(uint256 need, uint256 have);

    /// A varint with a redundant trailing zero group, e.g. `80 00` for zero.
    ///
    /// Stricter than postcard on purpose - see the header. Two encodings of one
    /// number means two byte strings decode to one proof, and a malleable proof
    /// is a proof whose identity is not its bytes.
    error VarintNotCanonical(uint256 at);

    /// A varint wider than the target type can hold, or whose final byte exceeds
    /// the value the type can represent. Matches `DeserializeBadVarint`.
    error VarintOutOfRange(uint256 at);

    /// An `Option` tag that is neither 0 nor 1.
    error BadOptionTag(uint256 at, uint8 tag);

    /// A `bool` byte that is neither 0 nor 1.
    error BadBool(uint256 at, uint8 value);

    /// A fixed-width read the proof is too short for, or a `finish` with bytes
    /// left over.
    error BadLength(uint256 want, uint256 have);

    /// A cursor at the start of a proof.
    function start() internal pure returns (Cursor memory) {
        return Cursor(0);
    }

    /// Bytes still unread.
    function remaining(bytes calldata proof, Cursor memory c) internal pure returns (uint256) {
        return proof.length - c.pos;
    }

    /// One byte, advancing the cursor.
    function readByte(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (uint8 b, Cursor memory)
    {
        if (c.pos >= proof.length) revert ProofTruncated(1, remaining(proof, c));
        b = uint8(proof[c.pos]);
        return (b, Cursor(c.pos + 1));
    }

    /// An unsigned LEB128 varint into `maxBytes` bytes whose final group is at
    /// most `maxLastGroup`.
    ///
    /// `maxBytes`/`maxLastGroup` are postcard's `varint_max::<T>()` and
    /// `max_of_last_byte::<T>()`, so the accepted set is exactly postcard's plus
    /// the canonicality rule below.
    function readVarint(bytes calldata proof, Cursor memory c, uint256 maxBytes, uint256 maxLastGroup)
        internal
        pure
        returns (uint256 value, Cursor memory)
    {
        uint256 at = c.pos;
        uint256 pos = c.pos;
        uint256 shift = 0;
        uint256 acc = 0;
        for (uint256 i; i < maxBytes; ++i) {
            if (pos >= proof.length) revert ProofTruncated(1, remaining(proof, c));
            uint8 b = uint8(proof[pos]);
            ++pos;
            acc |= uint256(b & 0x7f) << shift;
            if (b & 0x80 == 0) {
                // Final group: the type cannot represent more than this.
                if (i == maxBytes - 1 && uint256(b) > maxLastGroup) revert VarintOutOfRange(at);
                // Canonicality, stricter than postcard: a multi-byte varint must
                // not end on a zero group. `b == 0` on the first byte is the
                // legal encoding of zero.
                if (i != 0 && b == 0) revert VarintNotCanonical(at);
                return (acc, Cursor(pos));
            }
            shift += 7;
        }
        // Every allowed byte carried a continuation bit.
        revert VarintOutOfRange(at);
    }

    /// A `u32`, which postcard encodes as a varint of at most 5 bytes with a
    /// final group of at most 15.
    function readU32(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (uint32 value, Cursor memory)
    {
        uint256 wide = 0;
        (wide, c) = readVarint(proof, c, 5, 15);
        // Safe: 5 groups of 7 bits with the final group <= 15 is at most 2^32 - 1.
        // forge-lint: disable-next-line(unsafe-typecast)
        return (uint32(wide), c);
    }

    /// A `u64`, at most 10 bytes with a final group of at most 1.
    function readU64(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (uint64 value, Cursor memory)
    {
        uint256 wide = 0;
        (wide, c) = readVarint(proof, c, 10, 1);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (uint64(wide), c);
    }

    /// A `usize`, which postcard encodes as a varint with the same bounds as
    /// `u64`. The prover targets 64-bit hosts; a 32-bit prover would change the
    /// wire format and is out of scope.
    function readUsize(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (uint256 value, Cursor memory)
    {
        return readVarint(proof, c, 10, 1);
    }

    /// An `Option<T>` tag. Returns false for `None` and leaves the cursor on the
    /// value for `Some`, so the caller decodes the payload only when present.
    function readOptionTag(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (bool present, Cursor memory)
    {
        uint8 tag = 0;
        (tag, c) = readByte(proof, c);
        if (tag == 0) return (false, c);
        if (tag == 1) return (true, c);
        revert BadOptionTag(c.pos - 1, tag);
    }

    /// A `bool`, strict about its two legal encodings.
    function readBool(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (bool value, Cursor memory)
    {
        uint8 b = 0;
        (b, c) = readByte(proof, c);
        if (b > 1) revert BadBool(c.pos - 1, b);
        return (b == 1, c);
    }

    /// A fixed-width byte string, copied to memory.
    ///
    /// For values that are consumed as a whole rather than scanned - openings,
    /// chunk payloads - where a memory copy is what the consumer needs anyway.
    function readFixed(bytes calldata proof, Cursor memory c, uint256 n)
        internal
        pure
        returns (bytes memory out, Cursor memory)
    {
        if (remaining(proof, c) < n) revert BadLength(n, remaining(proof, c));
        out = proof[c.pos:c.pos + n];
        return (out, Cursor(c.pos + n));
    }

    /// A 32-byte Merkle digest.
    ///
    /// The slice is exactly one word, so the copy is 32 bytes and the mload
    /// reads it big-endian with no shifting: the result compares equal to the
    /// bytes32 that keccak256 produced over the same bytes.
    ///
    /// Deliberately no calldataload here. The absolute calldata offset of a
    /// bytes calldata parameter is not the same value for internal and external
    /// callers, and a digest read from the wrong base is a digest nobody
    /// committed to - which is exactly the silent failure this library exists to
    /// prevent. The 32-byte copy is cheaper than that bug.
    function readDigest(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (bytes32 out, Cursor memory)
    {
        if (remaining(proof, c) < 32) revert BadLength(32, remaining(proof, c));
        bytes memory raw = proof[c.pos:c.pos + 32];
        assembly {
            // raw is a freshly allocated 32-byte array, so its payload starts
            // at raw + 0x20 and this load cannot read outside it.
            out := mload(add(raw, 0x20))
        }
        return (out, Cursor(c.pos + 32));
    }

    /// A varint-length-prefixed `Vec<u8>`, returned as raw bytes.
    function readBytesVec(bytes calldata proof, Cursor memory c)
        internal
        pure
        returns (bytes memory out, Cursor memory)
    {
        uint256 len = 0;
        (len, c) = readUsize(proof, c);
        if (remaining(proof, c) < len) revert BadLength(len, remaining(proof, c));
        out = proof[c.pos:c.pos + len];
        return (out, Cursor(c.pos + len));
    }

    /// Asserts the whole proof has been consumed.
    ///
    /// Called at the end of a decode. Trailing bytes mean the decoder stopped
    /// early - usually because a length or tag was misread - and accepting them
    /// would let a proof carry a second, unchecked payload.
    function finish(bytes calldata proof, Cursor memory c) internal pure {
        if (c.pos != proof.length) revert BadLength(proof.length, c.pos);
    }
}

