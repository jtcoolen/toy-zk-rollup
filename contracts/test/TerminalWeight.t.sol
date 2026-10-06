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
}