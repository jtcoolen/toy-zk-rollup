// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
import {TerminalRef} from "./utils/TerminalRef.sol";

/// The TWIGHT frame protocol, tested against the plain-Solidity reference:
/// the same frame read two ways must give the same weight and value, and
/// every malformed frame must revert rather than answer. Production reaches
/// this through WhirVerifier's staticcall; here the frames are built by hand
/// so a protocol drift fails HERE and not as an anonymous e2e revert.
contract TerminalWeightTest is Test {
    TerminalWeight satellite;
    TerminalRef referenceImpl;

    function setUp() public {
        satellite = new TerminalWeight();
        referenceImpl = new TerminalRef();
    }

    /// A small but non-degenerate shape: two constraints, different k, one
    /// with selectors, one with initialPower = 1.
    uint256[] _allR;
    uint256[] _eq0a;
    uint256[] _eq0b;
    uint256[] _eq1;
    uint256[] _sel;
    uint256[] _poly;
    uint256[] _closing;

    function _shape() internal {
        _allR = new uint256[](5);
        for (uint256 i; i < 5; ++i) {
            _allR[i] = KoalaBearExt4.fromBase(1000 + i * 37);
        }
        _eq0a = new uint256[](2);
        _eq0a[0] = KoalaBearExt4.fromBase(11);
        _eq0a[1] = KoalaBearExt4.fromBase(13);
        _eq0b = new uint256[](2);
        _eq0b[0] = KoalaBearExt4.fromBase(17);
        _eq0b[1] = KoalaBearExt4.fromBase(19);
        _eq1 = new uint256[](3);
        for (uint256 i; i < 3; ++i) {
            _eq1[i] = KoalaBearExt4.fromBase(23 + i);
        }
        _sel = new uint256[](2);
        _sel[0] = KoalaBearExt4.fromBase(31);
        _sel[1] = KoalaBearExt4.fromBase(37);
        _poly = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            _poly[i] = KoalaBearExt4.fromBase(101 + i * 7);
        }
        // evaluate_hypercube wants |poly| == 2^|closing|: 8 coefficients, 3 dims.
        _closing = new uint256[](3);
        for (uint256 i; i < 3; ++i) {
            _closing[i] = KoalaBearExt4.fromBase(211 + i * 5);
        }
    }

    function _w(uint256 x) private pure returns (bytes memory) {
        return abi.encode(x);
    }

    /// The frame's allR section is what the verifier packs: every folding
    /// randomness with the closing point appended, exactly as TerminalRef
    /// reassembles it.
    function _allFrame() private view returns (bytes memory b) {
        b = _w(_allR.length + _closing.length);
        for (uint256 i; i < _allR.length; ++i) b = bytes.concat(b, _w(_allR[i]));
        for (uint256 i; i < _closing.length; ++i) b = bytes.concat(b, _w(_closing[i]));
    }

    /// Frame with both constraints in mode 0 (derived groups, memory-shaped).
    function _frameMode0() private view returns (bytes memory f) {
        bytes memory all = _allFrame();
        f = _w(TerminalWeight(satellite).MAGIC());
        f = bytes.concat(f, all);
        f = bytes.concat(f, _w(2));
        // constraint 0: k=2, gamma, initialPower 0, mode 0, 2 groups, no sel
        f = bytes.concat(f, _w(2), _w(KoalaBearExt4.fromBase(5)), _w(0), _w(0), _w(2), _w(0));
        f = bytes.concat(f, _w(_eq0a[0]), _w(_eq0a[1]), _w(_eq0b[0]), _w(_eq0b[1]));
        // constraint 1: k=3, gamma, initialPower 1, mode 0, 1 group, 2 sel
        f = bytes.concat(f, _w(3), _w(KoalaBearExt4.fromBase(7)), _w(1), _w(0), _w(1), _w(2));
        f = bytes.concat(f, _w(_eq1[0]), _w(_eq1[1]), _w(_eq1[2]));
        f = bytes.concat(f, _w(_sel[0]), _w(_sel[1]));
        f = bytes.concat(f, _w(_poly.length));
        for (uint256 i; i < _poly.length; ++i) f = bytes.concat(f, _w(_poly[i]));
        f = bytes.concat(f, _w(_closing.length));
        for (uint256 i; i < _closing.length; ++i) f = bytes.concat(f, _w(_closing[i]));
    }

    /// The same frame with constraint 0's groups in mode 1 (wire-shaped: the
    /// satellite reads them from its own calldata, eqCdBase style).
    function _frameMode1() private view returns (bytes memory f) {
        bytes memory all = _allFrame();
        f = _w(TerminalWeight(satellite).MAGIC());
        f = bytes.concat(f, all);
        f = bytes.concat(f, _w(2));
        // mode 1: nGroups lengths, then the flat words
        f = bytes.concat(f, _w(2), _w(KoalaBearExt4.fromBase(5)), _w(0), _w(1), _w(2), _w(0));
        f = bytes.concat(f, _w(2), _w(2));
        f = bytes.concat(f, _w(_eq0a[0]), _w(_eq0a[1]), _w(_eq0b[0]), _w(_eq0b[1]));
        f = bytes.concat(f, _w(3), _w(KoalaBearExt4.fromBase(7)), _w(1), _w(0), _w(1), _w(2));
        f = bytes.concat(f, _w(_eq1[0]), _w(_eq1[1]), _w(_eq1[2]));
        f = bytes.concat(f, _w(_sel[0]), _w(_sel[1]));
        f = bytes.concat(f, _w(_poly.length));
        for (uint256 i; i < _poly.length; ++i) f = bytes.concat(f, _w(_poly[i]));
        f = bytes.concat(f, _w(_closing.length));
        for (uint256 i; i < _closing.length; ++i) f = bytes.concat(f, _w(_closing[i]));
    }

    function _reference() private view returns (uint256) {
        WhirGadgets.ConstraintWeight[] memory cs =
            new WhirGadgets.ConstraintWeight[](2);
        cs[0].numVariables = 2;
        cs[0].gamma = KoalaBearExt4.fromBase(5);
        cs[0].initialPower = 0;
        cs[0].eqPoints = new uint256[][](2);
        cs[0].eqPoints[0] = _eq0a;
        cs[0].eqPoints[1] = _eq0b;
        cs[1].numVariables = 3;
        cs[1].gamma = KoalaBearExt4.fromBase(7);
        cs[1].initialPower = 1;
        cs[1].eqPoints = new uint256[][](1);
        cs[1].eqPoints[0] = _eq1;
        cs[1].selVars = _sel;
        return referenceImpl.expected(_allR, _closing, cs, _poly);
    }

    function _call(bytes memory f)
        private view returns (bool ok, bytes memory ret)
    {
        (ok, ret) = address(satellite).staticcall(f);
    }

    function test_frame_mode0_matches_the_reference() public {
        _shape();
        (bool ok, bytes memory ret) = _call(_frameMode0());
        assertTrue(ok, "satellite reverted");
        assertEq(ret.length, 96, "reply length");
        (uint256 magic, uint256 weight, uint256 value) =
            abi.decode(ret, (uint256, uint256, uint256));
        assertEq(magic, TerminalWeight(satellite).MAGIC(), "reply magic");
        assertEq(
            KoalaBearExt4.mul(weight, value),
            _reference(),
            "weight * value != reference");
    }

    /// Mode 1 must agree with mode 0 word for word: same eq groups, read from
    /// calldata instead of memory.
    function test_frame_mode1_agrees_with_mode0() public {
        _shape();
        (bool ok0, bytes memory r0) = _call(_frameMode0());
        (bool ok1, bytes memory r1) = _call(_frameMode1());
        assertTrue(ok0 && ok1, "satellite reverted");
        assertEq(r0, r1, "mode 1 disagrees with mode 0");
    }

    function test_bad_magic_reverts() public {
        _shape();
        bytes memory f = _frameMode0();
        assembly { mstore(add(f, 32), 0xdeadbeef) }
        vm.expectRevert(TerminalWeight.BadFrame.selector);
        _call(f);
    }

    function test_trailing_words_revert() public {
        _shape();
        bytes memory f = bytes.concat(_frameMode0(), _w(0));
        vm.expectRevert(TerminalWeight.BadFrameLength.selector);
        _call(f);
    }

    function test_truncated_frame_reverts() public {
        _shape();
        bytes memory f = _frameMode0();
        bytes memory cut = new bytes(f.length - 32);
        for (uint256 i; i < cut.length; ++i) cut[i] = f[i];
        vm.expectRevert(TerminalWeight.BadFrameLength.selector);
        _call(cut);
    }

    // ---------------------------------------------------------------------
    // Mode 2 (D-086 step C): statement-derived groups.
    //
    // A tiny statement section exercising every branch of the derivation:
    //   matrix A: log_size 3 -> PADDED arity 4 (the folding-factor floor),
    //             width 1, one point zA.
    //   matrix B: log_size 4 -> arity 4, width 1, one point zB.
    // Equal padded arities: the reverse walk places B (later source index)
    // first, slot raw 0 -> sel 0; A second, raw 1 -> sel 1 (k=5, one
    // selector bit). Then one virtual group: raw expansion, no selector.
    // The mode-0 frame spells the same three groups out as explicit
    // coordinates (bridge form for the matrices, raw for the virtual one),
    // so agreement proves the derivation, not just the evaluation.
    // ---------------------------------------------------------------------

    function _u32le(uint256 x) private pure returns (bytes memory b) {
        b = new bytes(4);
        b[0] = bytes1(uint8(x & 0xff));
        b[1] = bytes1(uint8((x >> 8) & 0xff));
        b[2] = bytes1(uint8((x >> 16) & 0xff));
        b[3] = bytes1(uint8((x >> 24) & 0xff));
    }

    /// Bridge-form coordinates for a matrix group: coords[i] =
    /// y_i/(1+y_i) with y_i = z^(2^(arity-1-i)), then one selector bit.
    function _bridgeCoords(uint256 z, uint256 selBit)
        private
        pure
        returns (uint256[] memory c)
    {
        uint256 arity = 4;
        uint256[] memory ys = new uint256[](arity);
        ys[0] = z;
        for (uint256 i = 1; i < arity; ++i) ys[i] = KoalaBearExt4.square(ys[i - 1]);
        c = new uint256[](arity + 1);
        for (uint256 i; i < arity; ++i) {
            uint256 y = ys[arity - 1 - i];
            c[i] = KoalaBearExt4.mul(
                y, KoalaBearExt4.inv(KoalaBearExt4.add(KoalaBearExt4.ONE, y))
            );
        }
        c[arity] = selBit == 1 ? KoalaBearExt4.fromBase(1) : 0;
    }

    /// Raw expansion for the virtual group: coords[i] = v^(2^(k-1-i)).
    function _rawCoords(uint256 v, uint256 k)
        private
        pure
        returns (uint256[] memory c)
    {
        uint256[] memory ys = new uint256[](k);
        ys[0] = v;
        for (uint256 i = 1; i < k; ++i) ys[i] = KoalaBearExt4.square(ys[i - 1]);
        c = new uint256[](k);
        for (uint256 i; i < k; ++i) c[i] = ys[k - 1 - i];
    }

    uint256 private constant Z_A = 11 << 224;
    uint256 private constant Z_B = 13 << 224;
    uint256 private constant V_P = 17 << 224;

    function _statement() private pure returns (bytes memory stm) {
        stm = bytes.concat(_u32le(1), _u32le(2));
        // matrix A: raw log_size 3 (padded to 4), width 1, one point.
        stm = bytes.concat(stm, _u32le(3), _u32le(1), _u32le(1), _u32le(32), _w(Z_A));
        // matrix B: log_size 4, width 1, one point.
        stm = bytes.concat(stm, _u32le(4), _u32le(1), _u32le(1), _u32le(32), _w(Z_B));
    }

    function _tail() private view returns (bytes memory f) {
        f = _w(_poly.length);
        for (uint256 i; i < _poly.length; ++i) f = bytes.concat(f, _w(_poly[i]));
        f = bytes.concat(f, _w(_closing.length));
        for (uint256 i; i < _closing.length; ++i) f = bytes.concat(f, _w(_closing[i]));
    }

    function _frameMode2(uint256 k) private view returns (bytes memory f) {
        bytes memory stm = _statement();
        f = _w(TerminalWeight(satellite).MAGIC());
        f = bytes.concat(f, _allFrame());
        f = bytes.concat(f, _w(1));
        f = bytes.concat(f, _w(k), _w(KoalaBearExt4.fromBase(5)), _w(0), _w(2), _w(0), _w(0));
        f = bytes.concat(f, _w(stm.length), _w(0), _w(1), _w(V_P), stm);
        f = bytes.concat(f, _tail());
    }

    /// The same three groups spelled out as mode-0 coordinates, placement
    /// order: B (sel 0), A (sel 1), virtual (raw).
    function _frameMode2Spelled() private view returns (bytes memory f) {
        uint256[] memory gb = _bridgeCoords(Z_B, 0);
        uint256[] memory ga = _bridgeCoords(Z_A, 1);
        uint256[] memory gv = _rawCoords(V_P, 5);
        f = _w(TerminalWeight(satellite).MAGIC());
        f = bytes.concat(f, _allFrame());
        f = bytes.concat(f, _w(1));
        f = bytes.concat(f, _w(5), _w(KoalaBearExt4.fromBase(5)), _w(0), _w(0), _w(3), _w(0));
        for (uint256 i; i < 5; ++i) f = bytes.concat(f, _w(gb[i]));
        for (uint256 i; i < 5; ++i) f = bytes.concat(f, _w(ga[i]));
        for (uint256 i; i < 5; ++i) f = bytes.concat(f, _w(gv[i]));
        f = bytes.concat(f, _tail());
    }

    function test_frame_mode2_matches_spelled_groups() public {
        _shape();
        (bool ok2, bytes memory r2) = _call(_frameMode2(5));
        (bool ok0, bytes memory r0) = _call(_frameMode2Spelled());
        assertTrue(ok2, "mode 2 reverted");
        assertTrue(ok0, "mode 0 reverted");
        assertEq(r2, r0, "mode 2 disagrees with the spelled-out groups");
    }

    /// The spelled groups must also match the independent reference.
    function test_frame_mode2_matches_the_reference() public {
        _shape();
        WhirGadgets.ConstraintWeight[] memory cs =
            new WhirGadgets.ConstraintWeight[](1);
        cs[0].numVariables = 5;
        cs[0].gamma = KoalaBearExt4.fromBase(5);
        cs[0].eqPoints = new uint256[][](3);
        cs[0].eqPoints[0] = _bridgeCoords(Z_B, 0);
        cs[0].eqPoints[1] = _bridgeCoords(Z_A, 1);
        cs[0].eqPoints[2] = _rawCoords(V_P, 5);
        (bool ok, bytes memory ret) = _call(_frameMode2(5));
        assertTrue(ok, "mode 2 reverted");
        (, uint256 weight, uint256 value) = abi.decode(ret, (uint256, uint256, uint256));
        assertEq(
            KoalaBearExt4.mul(weight, value),
            referenceImpl.expected(_allR, _closing, cs, _poly),
            "mode 2 weight * value != reference");
    }

    /// A constraint narrower than the folding factor cannot host the padded
    /// matrices: BadArity(4, 3), the padded arity, not the raw log_size.
    function test_mode2_bad_arity_reverts() public {
        _shape();
        (bool ok, bytes memory ret) = _call(_frameMode2(3));
        assertFalse(ok, "k=3 must not accept arity-4 matrices");
        // staticcall revert data bubbles up verbatim; compare it directly
        // (expectRevert does not intercept the caught staticcall here).
        assertEq(
            keccak256(ret),
            keccak256(abi.encodeWithSelector(TerminalWeight.BadArity.selector, 4, 3)),
            "wrong revert");
    }

}