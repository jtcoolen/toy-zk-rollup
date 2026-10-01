// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Conversion between the prover's statement representation and native EVM
/// words.
///
/// The prover carries every 32-byte digest as 16 little-endian 16-bit limbs,
/// each a base-field element (`bytes_to_limbs` in the Rust prover). A digest is
/// therefore *not* a field element and must not be read as one: it is sixteen
/// 16-bit values packed for the circuit's convenience.
///
/// This library is the single place that knows that layout. Getting it backwards
/// silently changes every hash the contract computes, so the round-trip is
/// asserted in tests against vectors emitted by the Rust prover.
library LimbCodec {
    /// Limbs in a 32-byte digest.
    uint256 public constant LIMBS_PER_DIGEST = 16;

    /// Maximum value of a single limb.
    uint256 public constant MAX_LIMB = 0xffff;

    /// Reassemble a 32-byte digest from 16 little-endian 16-bit limbs.
    ///
    /// Limb `i` holds bytes `2i` (low) and `2i+1` (high). The returned
    /// `bytes32` is the digest in its usual big-endian byte order, so it
    /// compares equal to the output of `keccak256` over the same bytes.
    ///
    /// Reverts if any limb exceeds 16 bits. A larger value cannot come from a
    /// verified statement of the expected shape, so accepting one would mean
    /// reading a field element as a limb and hashing something the prover never
    /// committed to.
    function digestFromLimbs(uint256[] memory limbs, uint256 offset)
        internal
        pure
        returns (bytes32 out)
    {
        require(limbs.length >= offset + LIMBS_PER_DIGEST, "limb slice out of range");
        for (uint256 i; i < LIMBS_PER_DIGEST; ++i) {
            uint256 limb = limbs[offset + i];
            require(limb <= MAX_LIMB, "limb exceeds 16 bits");
            // Byte 2i is the limb's low byte, byte 2i+1 its high byte. Byte 0 is
            // the most significant byte of the bytes32.
            out |= bytes32(limb & 0xff) << (8 * (31 - 2 * i));
            out |= bytes32(limb >> 8) << (8 * (30 - 2 * i));
        }
    }

    /// Reassemble a 64-bit value from four little-endian 16-bit limbs.
    ///
    /// The prover splits amounts this way for its carry-adder. The top limb holds
    /// 14 bits, so the representable range is 2^62.
    function u64FromLimbs(uint256[] memory limbs, uint256 offset) internal pure returns (uint64) {
        require(limbs.length >= offset + 4, "limb slice out of range");
        uint256 acc = 0;
        for (uint256 i; i < 4; ++i) {
            uint256 limb = limbs[offset + i];
            require(limb <= MAX_LIMB, "limb exceeds 16 bits");
            acc |= limb << (16 * i);
        }
        // Safe: each limb is <= 0xffff and there are exactly four, so `acc` is
        // at most 2^64 - 1.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(acc);
    }
}
