// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// End-to-end replay of the settlement proof: the full batch transcript walk
/// plus all five WHIR opening rounds, driven from the composed bundle the
/// generator produces from a real settle_block_circuit proving run.
/// Satellite stand-ins for the failure paths: one answers with the wrong
/// reply length, one with the right length and the wrong magic. Both must
/// fail closed through SatelliteCallFailed, never pass.
contract StubWrongLength {
    fallback() external {
        assembly {
            mstore(0, 1)
            mstore(32, 2)
            return(0, 64)
        }
    }
}

contract StubWrongMagic {
    fallback() external {
        assembly {
            mstore(0, 0)
            mstore(32, 1)
            mstore(64, 2)
            return(0, 96)
        }
    }
}

contract WhirVerifierTest is Test {
    WhirVerifier internal verifier;
    TerminalWeight internal satellite;

    /// Instance 5's public values at the pinned settlement shape.
    uint256[] internal statement;

    function setUp() public {
        satellite = new TerminalWeight();
        verifier = new WhirVerifier(address(satellite));
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

    // V-03 regression: each round's opening root must equal the commitment
    // digest the batch phase absorbed for that round's role (r0 main,
    // r1 quotient, r2 preprocessed, r3 permutation). Offsets below are the
    // digest BYTES of the round's batchCommitment blob in composed_bundle.bin
    // (u32 length word at 133672 / 308824, digest payload right after).
    // Before the fix a substituted root was rejected only later, by the
    // round's own Merkle walk - never against the absorbed digest.
    function test_verify_rejects_round_root_not_bound_to_digest() public {
        bytes memory b = _bundle();
        // Round 0 (main role): flip one digest byte.
        b[133676] = b[133676] ^ hex"01";
        vm.expectRevert(abi.encodeWithSelector(WhirVerifier.RoundRootMismatch.selector, 0));
        verifier.verify(statement, b);
    }

    function test_verify_rejects_round1_root_not_bound_to_digest() public {
        bytes memory b = _bundle();
        // Round 1 (quotient role).
        b[308828] = b[308828] ^ hex"01";
        vm.expectRevert(abi.encodeWithSelector(WhirVerifier.RoundRootMismatch.selector, 1));
        verifier.verify(statement, b);
    }

    // V-02 regression: every STATEMENT opening point must equal zeta * G_L^q.
    // Offsets are the packed ext WORDS of the points in composed_bundle.bin's
    // STATEMENT section (32-byte word right after its u32 length word):
    // round 0 matrix 0 point 0 at byte 762628, round 0 matrix 2 point 1 at
    // 762760. Before the fix a substituted point flowed into the terminal
    // weight's equality groups unchecked.
    function test_verify_rejects_opening_point_not_zeta() public {
        bytes memory b = _bundle();
        // Flip one limb byte of round 0 / matrix 0 / point 0 (the local point
        // must be exactly zeta).
        b[762628] = b[762628] ^ hex"01";
        vm.expectRevert(
            abi.encodeWithSelector(WhirVerifier.OpeningPointMismatch.selector, 0, 0)
        );
        verifier.verify(statement, b);
    }

    function test_verify_rejects_opening_point_not_zeta_next_row() public {
        bytes memory b = _bundle();
        // Round 0 / matrix 2 / point 1: the next-row point must be zeta * G_14.
        b[762760] = b[762760] ^ hex"01";
        vm.expectRevert(
            abi.encodeWithSelector(WhirVerifier.OpeningPointMismatch.selector, 0, 1)
        );
        verifier.verify(statement, b);
    }

    /// No satellite, no verifier: the constructor refuses a zero address and
    /// an address with no code, so a deployment can never pin nothing.
    function test_constructor_requires_a_pinned_satellite() public {
        vm.expectRevert(WhirVerifier.SatelliteUnpinned.selector);
        new WhirVerifier(address(0));
        // An address with no code (an EOA) is equally unpinnable.
        vm.expectRevert(WhirVerifier.SatelliteUnpinned.selector);
        new WhirVerifier(address(0xB0B));
    }

    /// The codehash is re-checked before every call: swapping the satellite's
    /// code after construction fails closed, before the frame is even packed.
    function test_verify_rejects_swapped_satellite_code() public {
        vm.etch(address(satellite), address(new StubWrongMagic()).code);
        vm.expectRevert(WhirVerifier.SatelliteUnpinned.selector);
        verifier.verify(statement, _bundle());
    }

    /// A satellite pinned at construction that answers with a malformed
    /// reply is still caught: the engine trusts the PINNED code (the
    /// codehash re-check), so shape checks moved out of the engine, but a
    /// garbage weight/value pair fails the terminal identity. Fail-closed
    /// either way - a lying satellite can never make verification pass.
    function test_verify_rejects_wrong_length_reply() public {
        address s = address(new TerminalWeight());
        vm.etch(s, address(new StubWrongLength()).code);
        WhirVerifier v = new WhirVerifier(s); // pins the stub's codehash
        // Garbage weight/value: the terminal identity (claim == weight*eval)
        // is the fail-closed net. eval is 0 at this shape, so expected = 0
        // and the actual is the proof's claimed terminal value.
        vm.expectRevert(abi.encodeWithSelector(
            WhirVerifier.TerminalClaimMismatch.selector,
            0,
            5145738483257368734721048007920492166929493615645799605964670266337445019648
        ));
        v.verify(statement, _bundle());
    }

    /// ... and one with the right length and the wrong MAGIC likewise: the
    /// stale reply words cannot satisfy the claim equation.
    function test_verify_rejects_wrong_magic_reply() public {
        address s = address(new TerminalWeight());
        vm.etch(s, address(new StubWrongMagic()).code);
        WhirVerifier v = new WhirVerifier(s);
        vm.expectRevert(abi.encodeWithSelector(
            WhirVerifier.TerminalClaimMismatch.selector,
            0,
            5145738483257368734721048007920492166929493615645799605964670266337445019648
        ));
        v.verify(statement, _bundle());
    }
}
