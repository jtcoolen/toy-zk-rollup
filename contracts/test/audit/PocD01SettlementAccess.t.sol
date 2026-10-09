// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {WhirVerifier} from "../../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../../src/verifier/TerminalWeight.sol";
import {ShieldedPool} from "../../src/ShieldedPool.sol";

/// AUDIT PoC D01 / D05 (settlement access and data availability), using only the
/// committed honest block vectors. Each test asserts the reported behaviour is
/// present on the audited revision.
contract PocD01SettlementAccessTest is Test {
    string internal constant VECTORS = "test/vectors/block_genesis.json";
    string internal constant BUNDLE = "test/vectors/block_composed_bundle.bin";

    WhirVerifier verifier;
    uint256[] statement;
    bytes32 genesisRoot;

    function setUp() public {
        string memory j = vm.readFile(VECTORS);
        statement = vm.parseJsonUintArray(j, ".statement");
        genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");
        verifier = new WhirVerifier(address(new TerminalWeight()));
    }

    /// D01: no caller restriction, and the only on-chain record of a block is
    /// its roots and fee - no output commitment or nullifier reaches L1, so a
    /// party that settles a block it does not share leaves everyone else unable
    /// to rebuild the tree. The operator's own (now stale) block then reverts.
    function test_poc_d01_any_sender_settles_and_event_carries_no_leaves() public {
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));
        bytes memory proof = vm.readFileBinary(BUNDLE);

        vm.recordLogs();
        vm.prank(address(0xBAD));
        pool.applyBlock(statement, proof);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(pool.blockNumber(), 1, "applied by an arbitrary sender");
        // BlockApplied(uint256 indexed, bytes32, bytes32, bytes32, bytes32, uint256):
        // five data words - roots and fee only.
        assertEq(logs[logs.length - 1].data.length, 5 * 32, "no per-transfer data on L1");

        // A block built by anyone else from the genesis state no longer applies.
        vm.expectRevert();
        pool.applyBlock(statement, proof);
    }

    /// D05: the statement carries no chain id / pool address, so the same
    /// (statement, proof) settles on any pool deployed at the same genesis.
    function test_poc_d05_block_replays_across_pools() public {
        ShieldedPool a = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));
        ShieldedPool b = new ShieldedPool(verifier, address(0xC0C), genesisRoot, bytes32(0));
        bytes memory proof = vm.readFileBinary(BUNDLE);
        a.applyBlock(statement, proof);
        vm.prank(address(0xBAD));
        b.applyBlock(statement, proof);
        assertEq(a.currentRoot(), b.currentRoot(), "same block applied to both pools");
    }
}
