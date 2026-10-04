// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {IWhirVerifier} from "../src/interfaces/IWhirVerifier.sol";
import {BlockStatement} from "../src/BlockStatement.sol";

/// A verifier whose behaviour the test pins. It is `view` like the real seam,
/// so it records nothing; instead it accepts only the claim it was told to
/// accept, which pins verbatim passthrough: if the pool altered the statement
/// or the proof on the way in, the hash would not match and the pool would
/// revert with NotVerified.
contract StubVerifier is IWhirVerifier {
    bool public result = true;
    bool public shouldRevert;
    /// keccak256(abi.encode(statement, proof)) this stub accepts; zero
    /// accepts anything. Set by the test before each block it expects to pass.
    bytes32 public acceptedClaim;

    function setResult(bool r) external { result = r; }
    function setRevert(bool r) external { shouldRevert = r; }
    function setAcceptedClaim(bytes32 c) external { acceptedClaim = c; }

    function verify(uint256[] calldata statement, bytes calldata proof)
        external view override returns (bool)
    {
        require(!shouldRevert, "malformed proof");
        if (acceptedClaim != bytes32(0)) {
            if (keccak256(abi.encode(statement, proof)) != acceptedClaim) return false;
        }
        return result;
    }
}

/// Exposes BlockStatement.decode so a test can call it.
contract DecodeHarness {
    function decode(uint256[] calldata statement) external pure returns (BlockStatement.Block memory) {
        return BlockStatement.decode(statement);
    }
}

/// The settlement state machine, driven by a real prover block.
///
/// Statement, roots, nullifier and output commitment all come from
/// `block_vectors.json`, produced by `prove_client_transfer`: a real SPHINCS+
/// spend of a funded note through the transfer circuit. The pool starts from
/// the EMPTY tree while the vector block names the funded-note root, so the
/// root limbs are rewritten to the state the pool is actually in - the stub
/// does not check the statement, and the WHIR verifier is pinned elsewhere.
contract ShieldedPoolTest is Test {
    string internal constant VECTOR = "test/vectors/block_vectors.json";

    /// The block statement is the transfer statement plus the shape header
    /// [n, nin, nout] the block circuit exports in front of it.
    uint256 internal constant HEADER_LIMBS = 3;

    /// The transfer's root limbs start after header(3) + nullifier(16) + output(16).
    uint256 internal constant ROOT_LIMB_OFFSET = 3 + 32;

    /// The empty commitment-tree root, pinned by MerkleVectors.t.sol.
    bytes32 internal constant EMPTY_ROOT =
        0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757;

    ShieldedPool pool;
    StubVerifier verifier;
    DecodeHarness decoder;

    uint256[] statement;
    bytes proof;
    bytes32 rootBefore;
    bytes32 nullifierBefore;
    bytes32 nullifierAfter;
    bytes32 outputLeaf;
    bytes32 poolRootAfter;
    uint64 fee;

    function setUp() public {
        string memory j = vm.readFile(VECTOR);
        uint256[] memory transfer = vm.parseJsonUintArray(j, ".statement");
        statement = new uint256[](HEADER_LIMBS + transfer.length);
        statement[0] = 1; // one transfer
        statement[1] = 1; // one input
        statement[2] = 1; // one output
        for (uint256 i; i < transfer.length; ++i) {
            statement[HEADER_LIMBS + i] = transfer[i];
        }
        // Any bytes stand in for the proof: the stub records them verbatim and
        // never parses them. The real proof bytes are pinned by the WHIR tests.
        proof = hex"deadbeef00112233";
        rootBefore = _asBytes32(vm.parseJsonBytes(j, ".root_before_hex"));
        nullifierBefore = _asBytes32(vm.parseJsonBytes(j, ".nullifier_before_hex"));
        nullifierAfter = _asBytes32(vm.parseJsonBytes(j, ".nullifier_after_hex"));
        outputLeaf = _asBytes32(vm.parseJsonBytesArray(j, ".outputs_hex")[0]);
        poolRootAfter = _asBytes32(vm.parseJsonBytes(j, ".pool_root_after_hex"));
        fee = uint64(vm.parseJsonUint(j, ".total_fee"));

        verifier = new StubVerifier();
        // Empty genesis: no leaves, empty nullifier map (bytes32(0) sentinel).
        bytes32[] memory noLeaves = new bytes32[](0);
        pool = new ShieldedPool(verifier, address(0xB0B), noLeaves, bytes32(0));
        decoder = new DecodeHarness();
    }

    function _asBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "digest must be 32 bytes");
        assembly {
            out := mload(add(b, 0x20))
        }
    }

    /// Write one digest into the statement as LimbCodec limbs: limb i packs
    /// digest byte 2i (low) and byte 2i+1 (high), byte 0 = MSB.
    function _putDigest(uint256[] memory s, uint256 offset, bytes32 d) private pure {
        for (uint256 i; i < 16; ++i) {
            uint256 b0 = (uint256(d) >> (8 * (31 - 2 * i))) & 0xff;
            uint256 b1 = (uint256(d) >> (8 * (30 - 2 * i))) & 0xff;
            s[offset + i] = b0 | (b1 << 8);
        }
    }

    /// Rewrite the transfer's commitment root and nullifier-before limbs so the
    /// block extends whatever state the pool is in. The stub verifier does not
    /// check the statement, so this only drives the state machine; the WHIR
    /// verifier is pinned by the phase tests.
    function _withRoots(uint256[] memory s, bytes32 newRoot, bytes32 newNfBefore)
        internal pure returns (uint256[] memory out)
    {
        out = new uint256[](s.length);
        for (uint256 i; i < s.length; ++i) {
            out[i] = s[i];
        }
        _putDigest(out, ROOT_LIMB_OFFSET, newRoot);
        _putDigest(out, ROOT_LIMB_OFFSET + 16, newNfBefore);
    }

    function test_decode_matches_the_provers_public_values() public view {
        BlockStatement.Block memory b = decoder.decode(statement);
        assertEq(b.transfers.length, 1, "one transfer");
        assertEq(b.rootBefore, rootBefore, "rootBefore");
        assertEq(b.nullifierBefore, nullifierBefore, "nullifierBefore");
        assertEq(b.nullifierAfter, nullifierAfter, "nullifierAfter");
        assertEq(b.totalFee, fee, "totalFee");
        assertEq(b.transfers[0].outputs[0], outputLeaf, "output commitment");
        assertEq(b.transfers[0].nullifiers.length, 1, "one nullifier");
    }

    function test_applyBlock_advances_both_roots() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), pool.currentNullifierRoot());
        verifier.setAcceptedClaim(keccak256(abi.encode(s, proof)));
        pool.applyBlock(s, proof);
        assertEq(pool.blockNumber(), 1, "block number");
        assertEq(pool.currentRoot(), poolRootAfter, "root advanced by the output leaf");
        assertEq(pool.currentNullifierRoot(), nullifierAfter, "nullifier root chained");
        assertEq(pool.leafCount(), 1, "one leaf appended");
    }

    /// The stub only accepts the exact (statement, proof) pair it was told
    /// about, so a pool that edited either on the way in reverts NotVerified.
    function test_verifier_receives_the_statement_and_proof_verbatim() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), pool.currentNullifierRoot());
        verifier.setAcceptedClaim(keccak256(abi.encode(s, proof)));
        pool.applyBlock(s, proof); // passes only on a verbatim handover
        assertEq(pool.blockNumber(), 1, "applied");
        // And a different proof for the same statement is rejected.
        vm.expectRevert(ShieldedPool.NotVerified.selector);
        pool.applyBlock(s, hex"00");
    }

    function test_reverts_when_the_verifier_says_no() public {
        verifier.setResult(false);
        vm.expectRevert(ShieldedPool.NotVerified.selector);
        pool.applyBlock(statement, proof);
    }

    function test_malformed_proof_reverts_through_the_seam() public {
        verifier.setRevert(true);
        vm.expectRevert("malformed proof");
        pool.applyBlock(statement, proof);
    }

    function test_rejects_a_block_that_does_not_extend_the_state() public {
        // The vector block names the funded-note root; a fresh pool is at the
        // empty root, so this block must not apply.
        assertEq(pool.currentRoot(), EMPTY_ROOT, "pool starts at the empty root");
        vm.expectRevert(
            abi.encodeWithSelector(ShieldedPool.RootMismatch.selector, EMPTY_ROOT, rootBefore));
        pool.applyBlock(statement, proof);
    }

    function test_blocks_chain_across_transfers() public {
        pool.applyBlock(
            _withRoots(statement, pool.currentRoot(), pool.currentNullifierRoot()), proof);
        assertEq(pool.currentRoot(), poolRootAfter, "first block landed");
        // Second block: same statement, roots rewritten to where the first
        // block landed.
        pool.applyBlock(_withRoots(statement, poolRootAfter, nullifierAfter), proof);
        assertEq(pool.blockNumber(), 2, "two blocks");
        assertEq(pool.leafCount(), 2, "two leaves");
        // Two identical leaves close a complete height-1 subtree; the root
        // folds empty subtrees above it.
        bytes32 pair = keccak256(abi.encodePacked(outputLeaf, outputLeaf));
        bytes32 empty1 = keccak256(abi.encodePacked(bytes32(0), bytes32(0)));
        bytes32 expect = pair;
        for (uint256 h = 1; h < 32; ++h) {
            expect = keccak256(abi.encodePacked(expect, empty1));
            empty1 = keccak256(abi.encodePacked(empty1, empty1));
        }
        assertEq(pool.currentRoot(), expect, "two-leaf root");
        assertEq(pool.currentNullifierRoot(), nullifierAfter, "nullifier root re-chained");
    }

    function test_fees_withdraw_only_to_the_recipient() public {
        vm.deal(address(pool), fee);
        vm.expectRevert(ShieldedPool.NotFeeRecipient.selector);
        pool.withdrawFees();
        vm.prank(address(0xB0B));
        pool.withdrawFees();
        assertEq(address(pool).balance, 0, "drained");
        assertEq(address(0xB0B).balance, fee, "recipient paid");
    }
}
