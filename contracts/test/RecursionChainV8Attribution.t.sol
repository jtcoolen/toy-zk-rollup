// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierV8P} from "./WhirVerifierV8P.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// D-092 batch 46: v8-shaped gas attribution. WhirVerifierV8P is a byte-fork
/// of the v8 engine with gasleft() snapshots at every phase boundary, run on
/// the real v8 vectors. The wire bundle carries no CONFIG (cfgWords=0); the
/// V6 wrapper splices it from the chunk set before calling the engine, so
/// this test splices the same way and calls the probe directly (the probe
/// writes its profile to storage, which a staticcall wrapper would forbid).
contract RecursionChainV8AttributionTest is Test {
    WhirVerifierV8P p;
    uint256[] statement;
    bytes bundle;
    bytes cfg;

    function setUp() public {
        p = new WhirVerifierV8P(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar_v8.json");
        statement = vm.parseJsonUintArray(j, ".statement");
        bundle = vm.readFileBinary("test/vectors/recursion_chain_bundle_v8.bin");
        cfg = vm.readFileBinary("test/vectors/recursion_chain_config_v8.bin");
    }

    /// header(16) with cfgWords stamped + CONFIG + tail, exactly as the V6
    /// wrapper hands the engine.
    function _engineBundle() internal view returns (bytes memory) {
        uint256 cw = cfg.length / 4;
        uint256 tail = bundle.length - 16;
        bytes memory full = new bytes(16 + cfg.length + tail);
        bytes memory bnd = bundle;
        bytes memory c = cfg;
        assembly {
            let d := add(full, 32)
            // WBND + ver 8 + cfgWords LE + prfWords (copied from wire header).
            mstore(d, mload(add(bnd, 32)))
            mstore8(add(d, 4), 8)
            mstore8(add(d, 8), and(cw, 0xff))
            mstore8(add(d, 9), and(shr(8, cw), 0xff))
            mstore8(add(d, 10), and(shr(16, cw), 0xff))
            mstore8(add(d, 11), and(shr(24, cw), 0xff))
            // CONFIG copy
            let cl := mload(c)
            for { let o := 0 } lt(o, cl) { o := add(o, 32) } {
                mstore(add(add(d, 16), o), mload(add(add(c, 32), o)))
            }
            // tail copy: bundle[16:]
            let src := add(add(bnd, 32), 16)
            for { let o := 0 } lt(o, tail) { o := add(o, 32) } {
                mstore(add(add(add(d, 16), cl), o), mload(add(src, o)))
            }
        }
        return full;
    }

    function test_attribution_v8() public {
        bytes memory full = _engineBundle();
        emit log_named_bytes("wire head", bytes.concat(bundle[0], bundle[1], bundle[2], bundle[3], bundle[4], bundle[5], bundle[6], bundle[7]));
        emit log_named_bytes("full head", bytes.concat(full[0], full[1], full[2], full[3], full[4], full[5], full[6], full[7]));
        emit log_named_uint("full len", full.length);
        emit log_named_uint("bundle len", bundle.length);
        emit log_named_uint("cfg len", cfg.length);
        assertTrue(p.verify(statement, full), "probe verifies");
        uint256 total;
        for (uint256 i; i < 130; ++i) {
            total += p.profileData(i);
        }
        emit log_named_uint("TOTAL accounted", total);
        emit log_named_uint("decode+statement", p.profileData(0));
        emit log_named_uint("batch transcript", p.profileData(1));
        emit log_named_uint("constraint identity", p.profileData(6));
        emit log_named_uint("round decode (all)", p.profileData(7));
        for (uint256 r; r < 5; ++r) {
            uint256 base = 10 + r * 32;
            emit log_named_uint("-- initial", p.profileData(base + 0));
            emit log_named_uint("   verifyRound", p.profileData(base + 1));
            emit log_named_uint("   satellite MROOTS", p.profileData(base + 2));
            emit log_named_uint("   constraint weight", p.profileData(base + 3));
            emit log_named_uint("   verifyFinal", p.profileData(base + 4));
            emit log_named_uint("   terminal identity", p.profileData(base + 5));
            emit log_named_uint("     r: phases1-4", p.profileData(base + 8));
            emit log_named_uint("     r: query loop", p.profileData(base + 9));
            emit log_named_uint("     r: phases6-7", p.profileData(base + 10));
            emit log_named_uint("     r: round sumcheck", p.profileData(base + 19));
            emit log_named_uint("     i: claim reg", p.profileData(base + 12));
            emit log_named_uint("     i: sumcheck", p.profileData(base + 11));
            emit log_named_uint("     i: #openingEvals", p.profileData(base + 24));
            emit log_named_uint("     i: #oodAnswers", p.profileData(base + 25));
            emit log_named_uint("     i: #claims", p.profileData(base + 26));
            emit log_named_uint("     i: framing sum", p.profileData(base + 27));
            emit log_named_uint("       q: loadRowFused", p.profileData(base + 13));
            emit log_named_uint("       q: framePut", p.profileData(base + 14));
            emit log_named_uint("       q: foldRow", p.profileData(base + 15));
            emit log_named_uint("       nq", p.profileData(base + 6));
            emit log_named_uint("       rowLimbs", p.profileData(base + 7));
            emit log_named_uint("       rowElems", p.profileData(base + 16));
            emit log_named_uint("       |randomness|", p.profileData(base + 17));
            emit log_named_uint("       rowsAreBase", p.profileData(base + 18));
            emit log_named_uint("       0x40 before loop", p.profileData(base + 16));
            emit log_named_uint("       0x40 after loop", p.profileData(base + 17));
            emit log_named_uint("       fp entry", p.profileData(base + 20));
            emit log_named_uint("       fp after loop", p.profileData(base + 21));
            emit log_named_uint("       fp q0", p.profileData(base + 22));
            emit log_named_uint("       fp qn", p.profileData(base + 23));
        }
    }
}
