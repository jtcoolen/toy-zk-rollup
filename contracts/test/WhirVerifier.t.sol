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
        verifier = new WhirVerifier(address(satellite), 0xffb29fe8ec40aa096a33e45823ec3525d224fe4458522e7f68f2c944dffd1443);
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

    /// M-03 regression: a statement word congruent to the proof's public value
    /// mod p but not canonical (pv + p) must NOT verify. Before the fix the
    /// bare mulmod comparison accepted it, so one proof verified for many
    /// statement arrays and the raw non-canonical word reached the constraint
    /// identity as an AIR public value.
    function test_verify_rejects_noncanonical_statement_alias() public {
        uint256[] memory bad = new uint256[](3);
        bad[0] = 0;
        bad[1] = 1;
        // FIELD_P = 2130706433: congruent to 377841674 mod p, not canonical.
        bad[2] = 377841674 + 2130706433;
        vm.expectRevert(abi.encodeWithSelector(WhirVerifier.StatementMismatch.selector, 2));
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

    // V-01 regressions: the CONFIG section is the circuit description, so a
    // deployment pins keccak256(CONFIG) and a proof of some OTHER circuit is
    // rejected before anything is decoded. setUp's verifier pins the
    // settlement vectors' CONFIG digest.

    /// The same verifier, pinned to the BLOCK circuit's CONFIG, must refuse
    /// the settlement proof: two unrelated circuits, one verifier address.
    /// This is the audit's forged-block shape (V-01) - the statement check
    /// cannot catch it because the attacker's proof is valid for its own
    /// (attacker-chosen) CONFIG.
    function test_verify_rejects_foreign_circuit_config() public {
        WhirVerifier blockPinned = new WhirVerifier(
            address(new TerminalWeight()),
            0xb46b4403210bab3dc9ba9bb906a50408a07443129f274e47c44b722be5f151ec
        );
        vm.expectRevert(WhirVerifier.ConfigNotPinned.selector);
        blockPinned.verify(statement, _bundle());
    }

    /// One byte inside the CONFIG - the constraint programs, the schedules -
    /// is a different circuit, not a corrupted proof: same rejection.
    function test_verify_rejects_tampered_config_section() public {
        bytes memory b = _bundle();
        // Byte 16 is the first CONFIG word; the CONFIG runs 33333 words.
        b[16] = b[16] ^ hex"01";
        vm.expectRevert(WhirVerifier.ConfigNotPinned.selector);
        verifier.verify(statement, b);
    }

    /// The pin is what gates: an unpinned verifier (bytes32(0), test-only)
    /// still accepts the same bytes, so the rejection above is the digest
    /// check and not an incidental decode failure.
    function test_unpinned_verifier_accepts_the_same_bundle() public {
        WhirVerifier unpinned = new WhirVerifier(address(new TerminalWeight()), bytes32(0));
        assertTrue(unpinned.verify(statement, _bundle()), "unpinned accepts");
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

    // M-04 regression: proof-supplied extension elements must have canonical
    // lanes (< p). The transcript absorbs lanes mod p while KoalaBearExt4
    // add/sub carry across lanes, so a lane >= p changes arithmetic without
    // changing the transcript - proof malleability. Terminal 0's packed word
    // starts at byte 133440 of composed_bundle.bin (limb 0 at bits 224..248).
    function test_verify_rejects_noncanonical_terminal_lane() public {
        bytes memory b = _bundle();
        // Add p to limb 0 of terminal 0: 1094973264 + 2130706433 = 0x498e_7f71
        // -> 0x498e_7f71 + 0x7f00_0001 = 0xc88e_7f72, written BE.
        b[133440] = hex"c8";
        b[133441] = hex"8e";
        b[133442] = hex"7f";
        b[133443] = hex"72";
        vm.expectRevert(WhirVerifier.NonCanonicalExt.selector);
        verifier.verify(statement, b);
    }

    /// Same rule on the _extArr path: round 0's first bound evaluation starts
    /// at byte 133712 (limb 0 = 0x245b0a0c); adding p gives 0xa35b0a0d.
    function test_verify_rejects_noncanonical_bound_eval_lane() public {
        bytes memory b = _bundle();
        b[133712] = hex"a3";
        b[133713] = hex"5b";
        b[133714] = hex"0a";
        b[133715] = hex"0d";
        vm.expectRevert(WhirVerifier.NonCanonicalExt.selector);
        verifier.verify(statement, b);
    }

    /// M-05: every proof shape quantity is pinned to the CONFIG. Round 0's
    /// oodAnswerLens stream (byte 296260, values [2,2,2]) must equal the
    /// CONFIG schedOodSamples per round. Inflating the first entry to 3 is a
    /// pure value lie - it shifts nothing downstream - so the shape check
    /// fires before anything consumes it.
    function test_verify_rejects_inflated_ood_answer_len() public {
        bytes memory b = _bundle();
        b[296260] = hex"03";
        vm.expectRevert(abi.encodeWithSelector(WhirVerifier.RoundShapeMismatch.selector, 0, 4));
        verifier.verify(statement, b);
    }

    /// M-05 fail-closed backstop: a header whose PROOF word count lies is
    /// rejected before the walk can alias bytes across the section boundary
    /// (the STATEMENT framing check trips first here; the end-of-section
    /// cursor check is the second net).
    function test_verify_rejects_proof_length_mismatch() public view {
        bytes memory b = _bundle();
        // prfWords is u32 LE at bytes 12..15: 157313 = 0x26681 -> +1 = 0x26682.
        b[12] = hex"82";
        b[13] = hex"66";
        b[14] = hex"02";
        b[15] = hex"00";
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(WhirVerifier.verify, (statement, b)));
        assertFalse(ok, "lying header must not verify");
    }

    /// No satellite, no verifier: the constructor refuses a zero address and
    /// an address with no code, so a deployment can never pin nothing.
    function test_constructor_requires_a_pinned_satellite() public {
        vm.expectRevert(WhirVerifier.SatelliteUnpinned.selector);
        new WhirVerifier(address(0), bytes32(0));
        // An address with no code (an EOA) is equally unpinnable.
        vm.expectRevert(WhirVerifier.SatelliteUnpinned.selector);
        new WhirVerifier(address(0xB0B), bytes32(0));
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
        WhirVerifier v = new WhirVerifier(s, bytes32(0)); // pins the stub's codehash
        // Garbage weight/value: the terminal identity (claim == weight*eval)
        // is the fail-closed net. eval is 0 at this shape, so expected = 0
        // and the actual is the proof's claimed terminal value.
        vm.expectRevert(abi.encodeWithSelector(
            WhirVerifier.TerminalClaimMismatch.selector,
            0,
            26680360537610394956755466636881435314427446113443067873233211526931481100288
        ));
        v.verify(statement, _bundle());
    }

    /// ... and one with the right length and the wrong MAGIC likewise: the
    /// stale reply words cannot satisfy the claim equation.
    function test_verify_rejects_wrong_magic_reply() public {
        address s = address(new TerminalWeight());
        vm.etch(s, address(new StubWrongMagic()).code);
        WhirVerifier v = new WhirVerifier(s, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(
            WhirVerifier.TerminalClaimMismatch.selector,
            0,
            26680360537610394956755466636881435314427446113443067873233211526931481100288
        ));
        v.verify(statement, _bundle());
    }
}
