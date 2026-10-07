// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {WhirVerifierV6} from "../src/verifier/WhirVerifierV6.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
import {ConfigChunk} from "../src/verifier/ConfigChunk.sol";

/// D-092 v7 wire: the same chain proof with the PROOF section's extension
/// arrays compacted to 16-byte limbs (the 16 pad bytes per element were
/// wire waste - batch 41). Same CONFIG, same statement; the wrapper stamps
/// the version through so the engine picks the right ext decoder.
contract RecursionChainV7Test is Test {
    WhirVerifier internal engineV5;
    WhirVerifierV6 internal verifier;
    uint256[] internal statement;
    bytes32 internal configDigest;

    function setUp() public {
        engineV5 = new WhirVerifier(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar_v7.json");
        statement = vm.parseJsonUintArray(j, ".statement");
        configDigest = vm.parseJsonBytes32(j, ".config_digest");
        bytes memory cfg = vm.readFileBinary("test/vectors/recursion_chain_config_v7.bin");
        uint256 per = 24000;
        uint256 n = (cfg.length + per - 1) / per;
        ConfigChunk[] memory chunks = new ConfigChunk[](n);
        for (uint256 i; i < n; ++i) {
            uint256 start = i * per;
            uint256 len = (cfg.length - start < per) ? cfg.length - start : per;
            bytes memory c = new bytes(len);
            for (uint256 k; k < len; ++k) {
                c[k] = cfg[start + k];
            }
            chunks[i] = new ConfigChunk(c);
        }
        verifier = new WhirVerifierV6(engineV5, chunks, configDigest);
    }

    function _bundleV7() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/recursion_chain_bundle_v7.bin");
    }

    function test_v7_bundle_verifies() public view {
        assertTrue(verifier.verify(statement, _bundleV7()), "v7 proof verifies");
    }

    function test_gas_v7() public {
        uint256 g = gasleft();
        assertTrue(verifier.verify(statement, _bundleV7()));
        emit log_named_uint("v7 gas", g - gasleft());
        emit log_named_uint("v7 bundle bytes", _bundleV7().length);
    }

    function test_rejects_wrong_statement() public view {
        uint256[] memory bad = new uint256[](3);
        bad[0] = statement[0];
        bad[1] = statement[1];
        bad[2] = statement[2] + 1;
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (bad, _bundleV7())));
        assertFalse(ok, "wrong statement must revert");
    }

    function test_rejects_tampered_bundle() public view {
        bytes memory b = _bundleV7();
        // Flip a byte deep in the PROOF section (past header + a few KB).
        uint256 i = 8000;
        b[i] = bytes1(uint8(b[i]) ^ 0x01);
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (statement, b)));
        assertFalse(ok, "tampered bundle must revert");
    }
}