// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierP} from "./WhirVerifierP.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// D-092 batch 31: the gas-attribution table the Phase-2 plan needs.
/// WhirVerifierP is a byte-fork of the frozen v5 engine with gasleft()
/// snapshots at every phase boundary (decode, transcript, per-round
/// initial/open/fold/sumcheck/constraints, terminal identity, constraint
/// identity). Same wire, same vectors: the numbers are the engine's own.
contract RecursionChainAttributionTest is Test {
    function test_attribution() public {
        WhirVerifierP p = new WhirVerifierP(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar.json");
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes memory bundle = vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
        (bool ok, uint256[] memory acc) = p.verifyProfiled(statement, bundle);
        assertTrue(ok, "verifies");
        uint256 total;
        for (uint256 i; i < acc.length; ++i) {
            total += acc[i];
        }
        emit log_named_uint("TOTAL accounted", total);
        emit log("acc[0] batch decode (cfg+prf+statement)");
        emit log_named_uint("  gas", acc[0]);
        emit log("acc[1] batch transcript phases");
        emit log_named_uint("  gas", acc[1]);
        emit log("acc[6] constraint identity (_checkIdentity)");
        emit log_named_uint("  gas", acc[6]);
        emit log("acc[7] constraints decode");
        emit log_named_uint("  gas", acc[7]);
        for (uint256 r; r < 5; ++r) {
            uint256 base = 10 + r * 16;
            emit log_named_uint("-- round", r);
            emit log_named_uint("  cfg/prf decode", acc[base + 10]);
            emit log_named_uint("  initial phase", acc[base + 8]);
            emit log_named_uint("  transcript+pow+indices", acc[base + 0]);
            emit log_named_uint("  open+fold queries", acc[base + 1]);
            emit log_named_uint("  gamma+claim fold", acc[base + 2]);
            emit log_named_uint("  round sumcheck", acc[base + 3]);
            emit log_named_uint("  constraint weights", acc[base + 4]);
            emit log_named_uint("  final: poly+pow+points", acc[base + 5]);
            emit log_named_uint("  final: open+STIR", acc[base + 6]);
            emit log_named_uint("  closing sumcheck", acc[base + 7]);
            emit log_named_uint("  terminal identity", acc[base + 9]);
        }
    }

    /// The terminal frame pack is a ~773 KB calldata->memory copy per round
    /// (WhirVerifier doc). Standalone cost of exactly that copy:
    function test_frame_pack_bench() public {
        bytes memory bundle = vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
        uint256 n = 773_000;
        uint256 g = gasleft();
        bytes memory frame = new bytes(n);
        assembly {
            let dst := add(frame, 32)
            let src := add(bundle, 32)
            for { let o := 0 } lt(o, n) { o := add(o, 32) } {
                mstore(add(dst, o), mload(add(src, o)))
            }
        }
        emit log_named_uint("773KB memory->memory copy", g - gasleft());
        require(frame.length == n);
    }
}
