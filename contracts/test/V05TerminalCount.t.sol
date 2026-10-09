// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// V-05 regression: the CIDNTY satellite must pin the proof's terminal
/// count to the number of CONFIG instances flagged hasTerminal. The engine
/// absorbs the permutation phase over whatever terminals the proof carries,
/// so an unpinned count lets a prover shift every later challenge with
/// terminals the constraint identity never sees. CONFIG is the authority;
/// this satellite is codehash-pinned by the engine.
contract V05TerminalCountTest is Test {
    TerminalWeight tw;

    function setUp() public { tw = new TerminalWeight(); }

    function _sw(bytes memory b, uint256 at, uint256 v) private pure {
        assembly ("memory-safe") { mstore(add(add(b, 32), at), v) }
    }

    /// Minimal CIDNTY frame: one identity instance, hasTerminal[0] = true,
    /// so the circuit expects exactly ONE terminal. `nTerm` is what the
    /// proof claims to carry.
    function _frame(uint256 nTerm) private pure returns (bytes memory) {
        uint32[] memory cfg = new uint32[](24);
        cfg[0] = 1;  // n instances
        cfg[1] = 0;  // statement instance
        cfg[14] = 1; // traceInvShift
        cfg[15] = 1; // traceHInv
        cfg[20] = 1; // hasTerminal[0] -> expectedTerms = 1
        cfg[21] = 1; // nr rounds
        cfg[22] = 1; // roundArities[0] len
        cfg[23] = 1; // roundArities[0][0]

        uint256 cfgWords = cfg.length;
        uint256 totalWords = 8 + nTerm + cfgWords + 1; // +1 empty bound-eval
        bytes memory f = new bytes(totalWords * 32);
        assembly ("memory-safe") {
            mstore(add(f, 32), 0x4349444E5459) // CIDNTY
            mstore(add(f, 64), 7)  // zeta
            mstore(add(f, 96), 8)  // alpha
            mstore(add(f, 128), 9) // lookupAlpha
            mstore(add(f, 160), 10) // beta
        }
        // Frame order (satellite _cidnty): nTerm, terminals, nStm,
        // statement, cfgWords, CONFIG, bound-evals.
        uint256 p = 5 * 32;
        _sw(f, p, nTerm); p += 32;
        for (uint256 t = 0; t < nTerm; ++t) { _sw(f, p, 0xAA00 + t); p += 32; }
        _sw(f, p, 0); p += 32;      // nStm
        _sw(f, p, cfgWords); p += 32;
        for (uint256 w = 0; w < cfgWords; ++w) {
            uint32 v = cfg[w];
            uint256 at = p + w * 4;
            f[at] = bytes1(uint8(v));
            f[at + 1] = bytes1(uint8(v >> 8));
            f[at + 2] = bytes1(uint8(v >> 16));
            f[at + 3] = bytes1(uint8(v >> 24));
        }
        p += cfgWords * 4;
        _sw(f, p, 0); // boundEvals[0] length = 0
        return f;
    }

    function test_v05_terminal_count_mismatch_reverts() public view {
        (bool ok1, bytes memory ret1) = address(tw).staticcall(_frame(2));
        assertTrue(!ok1, "nTerm=2 must revert");
        assertEq(ret1, abi.encodeWithSelector(TerminalWeight.TerminalCountMismatch.selector, 1, 2));
    }

    function test_v05_terminal_count_short_reverts() public view {
        (bool ok2, bytes memory ret2) = address(tw).staticcall(_frame(0));
        assertTrue(!ok2, "nTerm=0 must revert");
        assertEq(ret2, abi.encodeWithSelector(TerminalWeight.TerminalCountMismatch.selector, 1, 0));
    }
}
