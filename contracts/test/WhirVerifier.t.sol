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

    /// A satellite pinned at construction that answers with the wrong reply
    /// LENGTH is a SatelliteCallFailed, not a silent false.
    function test_verify_rejects_wrong_length_reply() public {
        address s = address(new TerminalWeight());
        vm.etch(s, address(new StubWrongLength()).code);
        WhirVerifier v = new WhirVerifier(s); // pins the stub's codehash
        vm.expectRevert(WhirVerifier.SatelliteCallFailed.selector);
        v.verify(statement, _bundle());
    }

    /// ... and one with the right length and the wrong MAGIC likewise.
    function test_verify_rejects_wrong_magic_reply() public {
        address s = address(new TerminalWeight());
        vm.etch(s, address(new StubWrongMagic()).code);
        WhirVerifier v = new WhirVerifier(s);
        vm.expectRevert(WhirVerifier.SatelliteCallFailed.selector);
        v.verify(statement, _bundle());
    }
}
