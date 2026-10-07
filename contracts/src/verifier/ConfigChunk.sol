// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The runtime template for a config chunk: reads the data blob appended
/// after this contract runtime code by the ConfigChunk constructor. The
/// deployed chunk IS this code + [data | uint32 len], so a chunk holds
/// ~24.5 KB of CONFIG in code - no storage, no SLOAD, and the code deposit
/// (200 gas/byte) is paid once at deploy, not per verify (D-092 v6 wire).
///
/// A separate template contract is required because a contract cannot
/// reference its own runtimeCode (circular bytecode reference).
contract ConfigChunkBody {
    /// The read range ran past the chunk.
    error OutOfRange();

    /// Byte length of the appended data blob (uint32 trailer).
    function dataLen() external view returns (uint256 n) {
        assembly {
            extcodecopy(address(), mload(0x40), sub(extcodesize(address()), 4), 4)
            n := shr(224, mload(mload(0x40)))
        }
    }

    /// `len` bytes of chunk data starting at `offset`, as memory.
    function read(uint256 offset, uint256 len) external view returns (bytes memory out) {
        uint256 n = this.dataLen();
        if (offset + len < offset || offset + len > n) revert OutOfRange();
        out = new bytes(len);
        assembly {
            let start := sub(sub(extcodesize(address()), n), 4)
            extcodecopy(address(), add(out, 32), add(start, offset), len)
        }
    }
}

/// One chunk of the verifier CONFIG section, pinned in code (D-092 v6 wire).
///
/// EIP-170 caps runtime code at 24,576 B, so the ~182 KB CONFIG ships as a
/// chunked set of these (8 chunks at the settlement shape). The verifier
/// pins keccak256 of the chunk data at construction - the "deployment
/// should pin keccak256(configSection)" discipline the v5 wire documented
/// but never enforced.
contract ConfigChunk {
    /// The chunk carries more bytes than one runtime code can hold.
    error ChunkTooLarge(uint256 len);

    /// Type members only: the DEPLOYED runtime is ConfigChunkBody's code
    /// (the constructor returns it), so these never execute. They exist so
    /// callers can type chunks as ConfigChunk and still call the body API.
    function dataLen() external pure returns (uint256) {
        revert();
    }

    function read(uint256 offset, uint256 len) external pure returns (bytes memory) {
        offset;
        len;
        revert();
    }

    constructor(bytes memory data) {
        uint256 body = type(ConfigChunkBody).runtimeCode.length;
        if (data.length + body + 4 > 24576) revert ChunkTooLarge(data.length);
        // The uint32 cast is safe: the ChunkTooLarge guard above bounds
        // data.length well below 2^32.
        // forge-lint: disable-next-line(encode-packed-collision, unsafe-typecast)
        bytes memory rt = abi.encodePacked(type(ConfigChunkBody).runtimeCode, data, uint32(data.length));
        assembly {
            return(add(rt, 32), mload(rt))
        }
    }
}
