// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";

/// End-to-end replay of the settlement proof: the full batch transcript walk
/// plus all five WHIR opening rounds, driven from the composed bundle the
/// generator produces from a real settle_block_circuit proving run.
contract WhirVerifierTest is Test {
    WhirVerifier internal verifier;

    /// Instance 5's public values at the pinned settlement shape.
    uint256[] internal statement;

    function setUp() public {
        verifier = new WhirVerifier();
        statement.push(0);
        statement.push(1);
        statement.push(377841674);
    }

    function _bundle() internal view returns (bytes memory) {
        return vm.readFileBinary("test/vectors/composed_bundle.bin");
    }

    /// The linchpin: the real proof verifies against the real statement.
    function test_verify_accepts_the_real_proof() public view {
        assertTrue(verifier.verify(statement, _bundle()));
    }

    /// A tampered public value must not verify: the statement check is the
    /// seam between "a valid proof" and "a valid proof of THIS statement".
    function test_verify_rejects_wrong_statement() public {
        uint256[] memory bad = new uint256[](3);
        bad[0] = 0;
        bad[1] = 1;
        bad[2] = 377841675;
        vm.expectRevert(abi.encodeWithSelector(WhirVerifier.StatementMismatch.selector, 2));
        verifier.verify(bad, _bundle());
    }

    /// A statement of the wrong length is rejected before anything is absorbed.
    function test_verify_rejects_statement_length() public {
        uint256[] memory bad = new uint256[](2);
        vm.expectRevert(
            abi.encodeWithSelector(WhirVerifier.StatementLengthMismatch.selector, 3, 2)
        );
        verifier.verify(bad, _bundle());
    }

    /// Flipping a bit deep inside the proof section breaks a Merkle root or a
    /// fold, so the walk reverts somewhere in the round replay.
    function test_verify_rejects_tampered_proof() public {
        bytes memory b = _bundle();
        uint256 at = b.length / 3;
        b[at] = b[at] ^ hex"01";
        vm.expectRevert();
        verifier.verify(statement, b);
    }

    /// Truncating the proof is rejected by the section table.
    function test_verify_rejects_truncated_proof() public {
        bytes memory b = _bundle();
        bytes memory short = new bytes(b.length / 2);
        for (uint256 i; i < short.length; ++i) {
            short[i] = b[i];
        }
        vm.expectRevert();
        verifier.verify(statement, short);
    }

    /// A wrong magic is rejected outright.
    function test_verify_rejects_bad_magic() public {
        bytes memory b = _bundle();
        b[0] = 0x58;
        vm.expectRevert(WhirVerifier.BadMagic.selector);
        verifier.verify(statement, b);
    }
}
