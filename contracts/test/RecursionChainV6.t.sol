// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {WhirVerifierV6} from "../src/verifier/WhirVerifierV6.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
import {ConfigChunk} from "../src/verifier/ConfigChunk.sol";

/// D-092 v6 wire: the same chain proof, with CONFIG pinned at deploy time
/// instead of shipped per proof. The v5 bundle is 627,136 B; the v6 bundle
/// is the same PROOF + STATEMENT with CONFIG removed (~445 KB). This test
/// is the gas comparison the redesign proposal needs.
contract RecursionChainV6Test is Test {
    WhirVerifier internal engineV5;
    WhirVerifierV6 internal verifier;
    uint256[] internal statement;
    bytes32 internal configDigest;

    function setUp() public {
        engineV5 = new WhirVerifier(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar_v6.json");
        statement = vm.parseJsonUintArray(j, ".statement");
        configDigest = vm.parseJsonBytes32(j, ".config_digest");
        // Chunk at runtime: the digest is keccak256(concat chunks), so the
        // split is free as long as each chunk fits one code page (body 561 B
        // + data + uint32 trailer <= 24,576).
        bytes memory cfg = vm.readFileBinary("test/vectors/recursion_chain_config.bin");
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

    function _bundleV6() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/recursion_chain_bundle_v6.bin");
    }

    function _bundleV5() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
    }

    /// The v6 bundle verifies through the wrapper.
    function test_v6_bundle_verifies() public view {
        assertTrue(verifier.verify(statement, _bundleV6()), "v6 proof verifies");
    }

    /// The gas comparison: v6 calldata is CONFIG-free; the wrapper pays a
    /// re-frame + staticcall but saves 182 KB of calldata decode.
    function test_gas_v6_vs_v5() public {
        uint256 g5 = gasleft();
        assertTrue(engineV5.verify(statement, _bundleV5()));
        uint256 used5 = g5 - gasleft();
        uint256 g6 = gasleft();
        assertTrue(verifier.verify(statement, _bundleV6()));
        uint256 used6 = g6 - gasleft();
        emit log_named_uint("v5 gas", used5);
        emit log_named_uint("v6 gas", used6);
        emit log_named_uint("v5 bundle bytes", _bundleV5().length);
        emit log_named_uint("v6 bundle bytes", _bundleV6().length);
    }

    function test_rejects_wrong_statement() public view {
        uint256[] memory bad = new uint256[](3);
        bad[0] = 0;
        bad[1] = 1;
        bad[2] = statement[2] + 1;
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (bad, _bundleV6())));
        assertFalse(ok, "wrong statement reverts");
    }

    function test_rejects_tampered_bundle() public view {
        bytes memory b = _bundleV6();
        b[b.length / 3] = b[b.length / 3] ^ hex"01";
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (statement, b)));
        assertFalse(ok, "tampered bundle reverts");
    }

    function test_rejects_bad_header() public view {
        bytes memory b = _bundleV6();
        b[4] = hex"07"; // version 7
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifierV6.verify, (statement, b)));
        assertFalse(ok, "bad version reverts");
    }
}
