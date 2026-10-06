// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// Where does the 175M go? Tamper one byte at a fraction of the bundle and
/// record the gas consumed before the revert: the verifier is deterministic,
/// so gas-at-revert(f) is the cost of everything the walk did up to the
/// section that byte lives in. The curve is the phase decomposition the
/// redesign budget needs, without instrumenting production code.
contract RecursionChainGasProfileTest is Test {
    WhirVerifier internal verifier;
    uint256[] internal statement;

    function setUp() public {
        verifier = new WhirVerifier(address(new TerminalWeight()));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar.json");
        statement = vm.parseJsonUintArray(j, ".statement");
    }

    function _bundle() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
    }

    function _gasAt(bytes memory b) internal view returns (uint256 used) {
        uint256 before = gasleft();
        // staticcall so a revert is caught, not propagated; 200M gas ceiling.
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (statement, b)));
        used = before - gasleft();
        assertFalse(ok, "tampered bundle must not verify");
    }

    function test_gas_profile() public {
        bytes memory full = _bundle();
        uint256 len = full.length;
        emit log_named_uint("bundle length", len);
        uint256[9] memory num = [uint256(1), 2, 3, 4, 5, 6, 7, 8, 9];
        for (uint256 i; i < 9; ++i) {
            bytes memory b = _bundle();
            uint256 at = len * num[i] / 10;
            b[at] = b[at] ^ hex"01";
            emit log_named_uint("gas at revert, fraction", num[i]);
            emit log_named_uint("  bytes", at);
            emit log_named_uint("  gas", _gasAt(b));
        }
    }
}
