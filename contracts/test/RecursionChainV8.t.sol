// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {WhirVerifierV6} from "../src/verifier/WhirVerifierV6.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
import {ConfigChunk} from "../src/verifier/ConfigChunk.sol";

/// D-092 v8 wire: the same chain proof with the intermediate Merkle paths
/// pruned to the query frontier (batch 42). Each round's expanded sibling
/// grid is replaced by one digest stream amortized across its queries; the
/// engine folds rows as before and hands the frontier walk to the satellite
/// in one call per round. Same CONFIG, same statement.
contract RecursionChainV8Test is Test {
    WhirVerifier internal engineV5;
    WhirVerifierV6 internal verifier;
    uint256[] internal statement;
    bytes32 internal configDigest;

    function setUp() public {
        engineV5 = new WhirVerifier(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar_v8.json");
        statement = vm.parseJsonUintArray(j, ".statement");
        configDigest = vm.parseJsonBytes32(j, ".config_digest");
        bytes memory cfg = vm.readFileBinary("test/vectors/recursion_chain_config_v8.bin");
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

    function _bundleV8() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/recursion_chain_bundle_v8.bin");
    }

    function test_v8_bundle_verifies() public view {
        assertTrue(verifier.verify(statement, _bundleV8()), "v8 proof verifies");
    }

    function test_gas_v8() public {
        uint256 g = gasleft();
        assertTrue(verifier.verify(statement, _bundleV8()));
        emit log_named_uint("v8 gas", g - gasleft());
        emit log_named_uint("v8 bundle bytes", _bundleV8().length);
    }

    function test_rejects_wrong_statement() public view {
        uint256[] memory bad = new uint256[](3);
        bad[0] = statement[0];
        bad[1] = statement[1];
        bad[2] = statement[2] + 1;
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (bad, _bundleV8())));
        assertFalse(ok, "wrong statement must revert");
    }

    function test_rejects_tampered_bundle() public view {
        bytes memory b = _bundleV8();
        // Flip a byte deep in the PROOF section (past header + a few KB).
        uint256 i = 8000;
        b[i] = bytes1(uint8(b[i]) ^ 0x01);
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (statement, b)));
        assertFalse(ok, "tampered bundle must revert");
    }
}