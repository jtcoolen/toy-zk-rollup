// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";

/// Audit regressions (toy-zk-rollup-crypto-audit-report-2026-10-09). Ported
/// from the audit branch's PoC files, INVERTED: the audit PoCs asserted the
/// vulnerable behaviour was present; these assert the fixed contracts reject
/// exactly what the PoCs exploited, on the same committed vectors.
///
/// V-01: the CONFIG (the whole circuit description) travels inside the bundle
/// and was never compared with a pinned value - one verifier accepted proofs
/// of any circuit, and a statement-only circuit moved the pool's roots.
contract AuditRegressionV01Test is Test {
    /// The block vectors' CONFIG digest (Deploy.s.sol's default).
    bytes32 internal constant BLOCK_CFG =
        0x7d61ae57323bdb9c8a4c72178820ecd8a07835699ca5b27fd2fcf29045d96c16;

    string internal constant FORGED = "test/vectors/audit/poc_f01_forged_block.json";
    string internal constant FORGED_BUNDLE = "test/vectors/audit/poc_f01_forged_bundle.bin";

    /// PocF01 test 1 inverted: the pinned verifier accepts the block proof
    /// and rejects the fibonacci-chain proof - one verifier, one circuit.
    function test_pinned_verifier_accepts_one_circuit_only() public {
        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()), BLOCK_CFG);

        uint256[] memory blockStatement =
            vm.parseJsonUintArray(vm.readFile("test/vectors/block_genesis.json"), ".statement");
        assertTrue(
            verifier.verify(blockStatement, vm.readFileBinary("test/vectors/block_composed_bundle.bin")),
            "block circuit proof still verifies"
        );

        uint256[] memory fibStatement = vm.parseJsonUintArray(
            vm.readFile("test/vectors/recursion_chain_sidecar.json"), ".statement"
        );
        vm.expectRevert(WhirVerifier.ConfigNotPinned.selector);
        verifier.verify(fibStatement, vm.readFileBinary("test/vectors/recursion_chain_bundle.bin"));
    }

    /// PocF01 test 2 inverted: the forged statement-only bundle - a valid
    /// proof of a circuit that constrains nothing - cannot move a pinned
    /// pool's roots. The forged CONFIG is not the block CONFIG.
    function test_forged_block_bundle_rejected_by_pinned_pool() public {
        string memory j = vm.readFile(FORGED);
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes32 genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");

        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()), BLOCK_CFG);
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));
        vm.prank(address(0xB0B));
        pool.setOperator(address(this), true);

        vm.expectRevert(WhirVerifier.ConfigNotPinned.selector);
        pool.applyBlock(statement, vm.readFileBinary(FORGED_BUNDLE));
        assertEq(pool.blockNumber(), 0, "forged block did not apply");
        assertEq(pool.currentRoot(), genesisRoot, "roots untouched");
    }

    /// H-01 inverted: the same forged bundle against an UNPINNED verifier
    /// (bytes32(0), the audit-revision behaviour) still cannot apply, because
    /// settlement is now operator-gated: the arbitrary sender the PoC used is
    /// refused before anything else runs.
    function test_forged_block_rejected_by_operator_gate() public {
        string memory j = vm.readFile(FORGED);
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes32 genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");

        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()), bytes32(0));
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));

        vm.prank(address(0xBAD));
        vm.expectRevert(ShieldedPool.NotOperator.selector);
        pool.applyBlock(statement, vm.readFileBinary(FORGED_BUNDLE));
    }

    /// PocD01 inverted: an arbitrary sender cannot settle at all, so the
    /// "settle and withhold the leaves" freeze is bounded to the operator set.
    function test_stranger_cannot_settle_honest_block() public {
        string memory j = vm.readFile("test/vectors/block_genesis.json");
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes32 genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");

        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()), BLOCK_CFG);
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));
        bytes memory proof = vm.readFileBinary("test/vectors/block_composed_bundle.bin");

        vm.prank(address(0xBAD));
        vm.expectRevert(ShieldedPool.NotOperator.selector);
        pool.applyBlock(statement, proof);
        assertEq(pool.blockNumber(), 0, "nothing applied by a stranger");
    }

    /// PocD05 inverted: the same (statement, proof) cannot settle on a pool
    /// whose pinned chain differs - the cross-chain replay half of M-01.
    function test_block_does_not_replay_on_foreign_chain() public {
        string memory j = vm.readFile("test/vectors/block_genesis.json");
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes32 genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");
        bytes memory proof = vm.readFileBinary("test/vectors/block_composed_bundle.bin");

        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()), BLOCK_CFG);
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));
        vm.prank(address(0xB0B));
        pool.setOperator(address(this), true);

        uint256 pinned = pool.CHAIN_ID();
        vm.chainId(pinned + 1);
        vm.expectRevert(
            abi.encodeWithSelector(ShieldedPool.ChainMismatch.selector, pinned, pinned + 1));
        pool.applyBlock(statement, proof);
    }
}
