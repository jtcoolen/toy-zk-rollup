// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IWhirVerifier} from "../interfaces/IWhirVerifier.sol";
import {ConfigChunk} from "./ConfigChunk.sol";

/// D-092 v6 wire: the same verification, with CONFIG moved out of every
/// proof and into deploy-time code (D-092 batch 25). The v5 wire ships
/// 182 KB of CONFIG - AIR constraints, round schedules, framing - inside
/// every 627 KB bundle even though nothing in it depends on the proof;
/// the header comment always called it "deploy-time data" but the wire
/// never let a deployment pin it. v6 fixes that:
///
///   * CONFIG ships once, as chunked ConfigChunk code satellites
///     (EIP-170: 8 x 24,576 B), pinned here by keccak256 at construction.
///   * The on-chain bundle is header(ver=6, cfgWords=0) + PROOF +
///     stmLen + STATEMENT - identical grammar otherwise, so the prover
///     side is a 4-line change and the v5 artifacts stay valid.
///   * This contract re-frames the v6 bundle into a v5 bundle in memory
///     (header + CONFIG from the chunks + the untouched PROOF/STATEMENT
///     tail) and staticcalls the frozen v5 engine. The v5 verifier stays
///     byte-exact ground truth; v6 sits BESIDE it (D-092).
///
/// Phase 2 of the redesign replaces the re-frame with direct extcodecopy
/// CONFIG reads inside the engine itself, dropping the ~1M re-frame cost
/// on top of the 2.9M calldata saving measured here.
contract WhirVerifierV6 is IWhirVerifier {
    /// The v6 bundle is too short to hold a header.
    error BundleTooShort();

    /// The v6 header did not say WBND/6/cfgWords=0.
    error BadBundle();

    /// The pinned CONFIG digest does not match the chunk set.
    error ConfigMismatch();

    /// The v5 engine reverted.
    error EngineReverted();

    /// The frozen v5 engine.
    IWhirVerifier public immutable ENGINE;

    /// keccak256 of the concatenated CONFIG section bytes.
    bytes32 public immutable CONFIG_DIGEST;

    /// CONFIG section length in bytes (multiple of 4).
    uint256 public immutable CONFIG_LEN;

    /// Chunk satellites, in CONFIG order.
    ConfigChunk[] internal _chunks;

    /// Chunk byte lengths, parallel to _chunks.
    uint256[] internal _lens;

    /// Total CONFIG bytes covered by the chunk set.
    uint256 internal _total;

    /// The chunk set does not cover exactly CONFIG_LEN bytes.
    error ChunkSetMismatch();

    constructor(IWhirVerifier engine_, ConfigChunk[] memory chunks, bytes32 configDigest) {
        ENGINE = engine_;
        CONFIG_DIGEST = configDigest;
        uint256 total = 0;
        for (uint256 i; i < chunks.length; ++i) {
            // forge-lint: disable-next-line(calls-loop)
            uint256 n = chunks[i].dataLen();
            _chunks.push(chunks[i]);
            _lens.push(n);
            total += n;
        }
        _total = total;
        CONFIG_LEN = total;
        if (total % 4 != 0) revert ChunkSetMismatch();
        if (_digest() != configDigest) revert ConfigMismatch();
    }

    /// keccak256 over the chunk data in order - the concatenation, matching
    /// the Rust side: keccak256(CONFIG section bytes).
    function _digest() internal view returns (bytes32) {
        bytes memory all = new bytes(_total);
        uint256 dst = 0;
        for (uint256 i; i < _chunks.length; ++i) {
            // forge-lint: disable-next-line(calls-loop)
            bytes memory b = _chunks[i].read(0, _lens[i]);
            uint256 n = _lens[i];
            assembly {
                let s := add(b, 32)
                let d := add(add(all, 32), dst)
                for { let o := 0 } lt(o, n) { o := add(o, 32) } {
                    mstore(add(d, o), mload(add(s, o)))
                }
            }
            dst += n;
        }
        return keccak256(all);
    }

    /// Verify a v6 bundle: header(ver 6, cfgWords 0) + PROOF + stmLen +
    /// STATEMENT. Builds the engine's call payload DIRECTLY in final ABI
    /// layout - selector, heads, statement, then the v5 bundle (header +
    /// CONFIG from the chunks + the untouched v6 tail) - in ONE memory
    /// buffer, and staticcalls it. The old path built a 445 KB v5 frame and
    /// then encodeCall-copied it into a second 445 KB buffer: two quadratic
    /// memory expansions (~1.6M gas), a zeroing pass, and a full copy, for
    /// bytes that were already contiguous. One buffer, one expansion, zero
    /// copies beyond the extcodecopy/calldatacopy that must happen anyway.
    function verify(uint256[] calldata statement, bytes calldata bundle) external view returns (bool) {
        if (bundle.length < 20) revert BundleTooShort();
        uint256 version;
        uint256 cfgWords;
        assembly {
            version := shr(248, calldataload(add(bundle.offset, 4)))
            cfgWords := shr(224, calldataload(add(bundle.offset, 8)))
        }
        if (bundle[0] != 0x57 || bundle[1] != 0x42 || bundle[2] != 0x4E || bundle[3] != 0x44) {
            revert BadBundle();
        }
        // v6: standard ext limbs. v7: compact 16-byte ext limbs (batch 41).
        // The frame stamps whichever version arrived; the engine decodes ext
        // arrays accordingly. CONFIG is identical between the two.
        if ((version != 6 && version != 7) || cfgWords != 0) revert BadBundle();

        uint256 cLen = CONFIG_LEN;
        uint256 tail = bundle.length - 16;
        uint256 stmtN = statement.length;
        uint256 bundleLen = 16 + cLen + tail;
        // Engine calldata layout (absolute, selector included): heads at 4
        // and 36; statement length word at 68, data at 100; bundle length
        // word at 100 + 32*stmtN, data at 132 + 32*stmtN.
        uint256 bundleOff = 132 + 32 * stmtN;
        uint256 payload = bundleOff + bundleLen;
        bytes4 sel = IWhirVerifier.verify.selector;
        uint256 engine = uint256(uint160(address(ENGINE)));
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(add(ptr, payload), 64))
            let p := ptr
            mstore(p, sel) // bytes4 is already left-aligned in its word
            mstore(add(p, 4), 64)
            mstore(add(p, 36), add(96, mul(stmtN, 32)))
            mstore(add(p, 68), stmtN)
            calldatacopy(add(p, 100), statement.offset, mul(stmtN, 32))
            mstore(add(p, add(100, mul(stmtN, 32))), bundleLen)
            // v5 header: WBND, ver 5, cfgWords LE at +8, prfWords LE at +12
            // (prfWords copied verbatim from the v6 header).
            let b := add(p, bundleOff)
            mstore8(b, 0x57)
            mstore8(add(b, 1), 0x42)
            mstore8(add(b, 2), 0x4E)
            mstore8(add(b, 3), 0x44)
            // v6 frames as v5 (standard ext limbs); v7 frames as v7 (compact).
            mstore8(add(b, 4), add(5, mul(gt(version, 6), 2)))
            let cw := div(cLen, 4)
            let q := add(b, 8)
            mstore8(q, and(cw, 0xff))
            mstore8(add(q, 1), and(shr(8, cw), 0xff))
            mstore8(add(q, 2), and(shr(16, cw), 0xff))
            mstore8(add(q, 3), and(shr(24, cw), 0xff))
            let hw := calldataload(bundle.offset)
            q := add(b, 12)
            mstore8(q, byte(12, hw))
            mstore8(add(q, 1), byte(13, hw))
            mstore8(add(q, 2), byte(14, hw))
            mstore8(add(q, 3), byte(15, hw))
        }
        // CONFIG from the chunk set: extcodecopy straight into the payload.
        // The chunk runtime ends with [data | uint32 len], so the data start
        // is codesize - 4 - len; no chunk.read call, no intermediate buffer.
        uint256 dst = bundleOff + 16;
        for (uint256 i; i < _chunks.length; ++i) {
            address ch = address(_chunks[i]);
            uint256 len = _lens[i];
            assembly {
                let cs := extcodesize(ch)
                extcodecopy(ch, mload(0x40), sub(cs, 4), 4)
                let dl := shr(224, mload(mload(0x40)))
                let start := sub(sub(cs, dl), 4)
                extcodecopy(ch, add(ptr, dst), start, len)
            }
            dst += len;
        }
        // v6 tail: PROOF + stmLen + STATEMENT, verbatim from bundle byte 16,
        // then the staticcall itself - reply lands in the 64-byte slack.
        assembly {
            calldatacopy(add(ptr, dst), add(bundle.offset, 16), tail)
            let out := and(add(add(ptr, payload), 63), not(31))
            let ok := staticcall(gas(), engine, ptr, payload, out, 96)
            switch ok
            case 1 { return(out, 32) }
            default {
                let rd := returndatasize()
                if gt(rd, 96) { rd := 96 }
                revert(out, rd)
            }
        }
    }
}
