// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

contract SizeCheckTest is Test {
    function test_size() public {
        WhirVerifier v = new WhirVerifier(address(new TerminalWeight()), bytes32(0));
        emit log_named_uint("runtime bytes", address(v).code.length);
    }
}