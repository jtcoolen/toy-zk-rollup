// Pins the ABI selectors the off-chain tooling hardcodes, computed by the
// EVM's own keccak256 opcode - the same one ShieldedPool dispatches on. If a
// signature ever changes, this test fails before the settle or state scripts
// silently send or parse garbage calldata.
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

contract SelectorPinsTest is Test {
    function test_apply_block_selector_pin() public pure {
        require(bytes4(keccak256("applyBlock(uint256[],bytes)")) == 0x0cb000b5, "selector drift");
    }

    function test_view_selector_pins() public pure {
        require(bytes4(keccak256("blockNumber()")) == 0x57e871e7, "blockNumber drift");
        require(bytes4(keccak256("currentRoot()")) == 0xfdab463d, "currentRoot drift");
        require(bytes4(keccak256("currentNullifierRoot()")) == 0x222d1bed, "nullifierRoot drift");
    }
}
