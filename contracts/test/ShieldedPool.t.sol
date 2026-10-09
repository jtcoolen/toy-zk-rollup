// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {IWhirVerifier} from "../src/interfaces/IWhirVerifier.sol";
import {BlockStatement} from "../src/BlockStatement.sol";
import {LimbCodec} from "../src/LimbCodec.sol";

/// A verifier whose behaviour the test pins. It is view like the real seam,
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
/// Statement, roots, fold root and fee all come from block_vectors.json,
/// produced by prove_client_transfer plus the folded block-statement builder:
/// a real SPHINCS+ spend of a funded note through the transfer circuit, folded
/// (D-089) into [header, statementRoot, rootBefore, rootAfter, nfBefore,
/// nfAfter, fee]. The pool is deployed at the Poseidon2 EMPTY root while the
/// vector block names the funded-note root, so the endpoint limbs are
/// rewritten to the state the pool is actually in - the stub does not check the
/// statement, and the WHIR verifier is pinned elsewhere. D-088: both roots are
/// attested, so the rewrite sets the pair (rootBefore, rootAfter) the pool must
/// chain and store.
contract ShieldedPoolTest is Test {
    string internal constant VECTOR = "test/vectors/block_vectors.json";

    /// The folded statement for one transfer: header(3) + statementRoot(16) +
    /// four digests + fee(4) = 87 limbs.
    uint256 internal constant STATEMENT_LIMBS = 87;

    /// The fold root sits right after the header [n, nin, nout].
    uint256 internal constant FOLD_LIMB_OFFSET = 3;

    /// The block rootBefore sits right after the fold root.
    uint256 internal constant ROOT_LIMB_OFFSET = 3 + 16;

    /// The Poseidon2 empty commitment-tree root (D-088 hasher): the root of a
    /// depth-32 tree of zero leaves under the Poseidon2 sponge/perm fold. The
    /// pool is deployed here; the vector block names a different (funded) root,
    /// so the honest block must be rejected on continuity.
    bytes32 internal constant EMPTY_ROOT =
        0x7a92872da0d9532a933f5f5a8d140b60bba8c80cde1fe868edc23b538844d82e;

    ShieldedPool pool;
    StubVerifier verifier;
    DecodeHarness decoder;

    uint256[] statement;
    bytes proof;
    bytes32 statementRoot;
    bytes32 rootBefore;
    bytes32 rootAfter;
    bytes32 nullifierBefore;
    bytes32 nullifierAfter;
    uint64 fee;

    function setUp() public {
        string memory j = vm.readFile(VECTOR);
        statement = vm.parseJsonUintArray(j, ".statement");
        assertEq(statement.length, STATEMENT_LIMBS, "folded statement is 87 limbs for n=1");
        // Any bytes stand in for the proof: the stub records them verbatim and
        // never parses them. The real proof bytes are pinned by the WHIR tests.
        proof = hex"deadbeef00112233";
        statementRoot = _asBytes32(vm.parseJsonBytes(j, ".statement_root_hex"));
        rootBefore = _asBytes32(vm.parseJsonBytes(j, ".root_before_hex"));
        rootAfter = _asBytes32(vm.parseJsonBytes(j, ".root_after_hex"));
        nullifierBefore = _asBytes32(vm.parseJsonBytes(j, ".nullifier_before_hex"));
        nullifierAfter = _asBytes32(vm.parseJsonBytes(j, ".nullifier_after_hex"));
        fee = uint64(vm.parseJsonUint(j, ".total_fee"));

        verifier = new StubVerifier();
        // Empty genesis: the Poseidon2 empty root, empty nullifier map
        // (bytes32(0) sentinel: the contract computes the prover empty root).
        pool = new ShieldedPool(verifier, address(0xB0B), EMPTY_ROOT, bytes32(0));
        // H-01: settlement is operator-gated; 0xB0B (the fee recipient) is
        // the seeded operator and admits this test contract.
        vm.prank(address(0xB0B));
        pool.setOperator(address(this), true);
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

    /// Rewrite the block commitment-root pair and nullifier-before limb so
    /// the block extends whatever state the pool is in and lands wherever the
    /// test wants. The stub verifier does not check the statement, so this only
    /// drives the state machine; the WHIR verifier is pinned by the phase tests.
    function _withRoots(uint256[] memory s, bytes32 newRoot, bytes32 newRootAfter, bytes32 newNfBefore)
        internal pure returns (uint256[] memory out)
    {
        out = new uint256[](s.length);
        for (uint256 i; i < s.length; ++i) {
            out[i] = s[i];
        }
        _putDigest(out, ROOT_LIMB_OFFSET, newRoot);
        _putDigest(out, ROOT_LIMB_OFFSET + 16, newRootAfter);
        _putDigest(out, ROOT_LIMB_OFFSET + 32, newNfBefore);
    }

    function test_decode_matches_the_provers_public_values() public view {
        BlockStatement.Block memory b = decoder.decode(statement);
        assertEq(b.numTransfers, 1, "one transfer");
        assertEq(b.statementRoot, statementRoot, "statement fold root");
        assertEq(b.rootBefore, rootBefore, "rootBefore");
        assertEq(b.rootAfter, rootAfter, "rootAfter");
        assertEq(b.nullifierBefore, nullifierBefore, "nullifierBefore");
        assertEq(b.nullifierAfter, nullifierAfter, "nullifierAfter");
        assertEq(b.totalFee, fee, "totalFee");
    }

    /// M-03 regression: the shape-count header limbs are u16 in the circuit
    /// (shape_header uses u16::try_from), so decode must reject an out-of-range
    /// count instead of skipping it. An unchecked header position is an F_p
    /// value the pool never reads but the constraint identity consumes raw.
    function test_decode_rejects_out_of_range_shape_count() public {
        uint256[] memory bad = new uint256[](statement.length);
        for (uint256 i; i < statement.length; ++i) {
            bad[i] = statement[i];
        }
        // Position 1 is transfer 0's input count: one past the u16 bound.
        bad[1] = 0x1_0000;
        vm.expectRevert("shape count out of range");
        decoder.decode(bad);

        // Position 2 is transfer 0's output count: a full field element.
        bad[1] = statement[1];
        bad[2] = 2130706432;
        vm.expectRevert("shape count out of range");
        decoder.decode(bad);
    }

    /// The fold root the decoder reads must be the digest the prover recorded -
    /// the statement own limbs and the native fold agree byte for byte. The
    /// contract cannot open the fold; pinning it against the prover own value
    /// is what makes the export trustworthy at the boundary.
    function test_statement_root_is_pinned_by_the_statement() public view {
        BlockStatement.Block memory b = decoder.decode(statement);
        bytes32 fromLimbs = LimbCodec.digestFromLimbs(statement, FOLD_LIMB_OFFSET);
        assertEq(fromLimbs, statementRoot, "fold limbs vs recorded fold root");
        assertEq(b.statementRoot, fromLimbs, "decoder reads the fold at the right offset");
    }

    function test_applyBlock_advances_both_roots() public {
        // The attested pair: this block starts where the pool is and lands on
        // the roots the prover attests (rewritten to the pool own state).
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        verifier.setAcceptedClaim(keccak256(abi.encode(s, proof)));
        pool.applyBlock(s, proof);
        assertEq(pool.blockNumber(), 1, "block number");
        assertEq(pool.currentRoot(), rootAfter, "attested root stored");
        assertEq(pool.currentNullifierRoot(), nullifierAfter, "nullifier root chained");
    }

    /// The stub only accepts the exact (statement, proof) pair it was told
    /// about, so a pool that edited either on the way in reverts NotVerified.
    function test_verifier_receives_the_statement_and_proof_verbatim() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        verifier.setAcceptedClaim(keccak256(abi.encode(s, proof)));
        // A different proof for the same statement is rejected. First, while
        // the statement still extends the pool state: continuity passes and
        // the verifier's refusal is what rejects it (H-01 ordering).
        vm.expectRevert(ShieldedPool.NotVerified.selector);
        pool.applyBlock(s, hex"00");
        // The right pair applies: passes only on a verbatim handover.
        pool.applyBlock(s, proof);
        assertEq(pool.blockNumber(), 1, "applied");
    }

    function test_reverts_when_the_verifier_says_no() public {
        // Continuity now runs before verification (H-01: bound the griefing
        // cost), so this block must extend the state to reach the verifier.
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        verifier.setResult(false);
        vm.expectRevert(ShieldedPool.NotVerified.selector);
        pool.applyBlock(s, proof);
    }

    function test_malformed_proof_reverts_through_the_seam() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        verifier.setRevert(true);
        vm.expectRevert("malformed proof");
        pool.applyBlock(s, proof);
    }

    /// H-01 regression: a stranger cannot settle. The audit's attack was any
    /// party applying a valid block and withholding the per-transfer data;
    /// the operator gate bounds that to the named set.
    function test_applyBlock_requires_an_operator() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        address stranger = address(0xDEAD);
        assertFalse(pool.isOperator(stranger), "stranger is no operator");
        vm.prank(stranger);
        vm.expectRevert(ShieldedPool.NotOperator.selector);
        pool.applyBlock(s, proof);
        // The seeded operator (fee recipient) can settle, and can rotate.
        vm.prank(address(0xB0B));
        pool.setOperator(stranger, true);
        assertTrue(pool.isOperator(stranger), "rotation admitted");
        // Only an operator rotates: the stranger cannot add more.
        vm.prank(address(0xFEED));
        vm.expectRevert(ShieldedPool.NotOperator.selector);
        pool.setOperator(address(0xFEED), true);
    }

    /// M-01 (contract-side half): the pool pins the chain it was deployed on
    /// and refuses settlement anywhere else - the same deployment state
    /// synced or migrated to a different chain id cannot settle there. The
    /// pool-address half of M-01 needs the statement schema to carry the
    /// binding (circuit-side, tracked with the circuit audit work).
    function test_applyBlock_refuses_a_different_chain() public {
        uint256[] memory s = _withRoots(
            statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot());
        uint256 pinned = pool.CHAIN_ID();
        assertEq(pinned, 31337, "pinned at deploy");
        vm.chainId(pinned + 1);
        vm.expectRevert(
            abi.encodeWithSelector(ShieldedPool.ChainMismatch.selector, pinned, pinned + 1));
        pool.applyBlock(s, proof);
        vm.chainId(pinned);
        pool.applyBlock(s, proof); // back home: applies
        assertEq(pool.blockNumber(), 1, "settled at home");
    }

    function test_rejects_a_block_that_does_not_extend_the_state() public {
        // The vector block names the funded-note root; a fresh pool is at the
        // empty root, so this block must not apply.
        assertEq(pool.currentRoot(), EMPTY_ROOT, "pool starts at the empty root");
        vm.expectRevert(
            abi.encodeWithSelector(ShieldedPool.RootMismatch.selector, EMPTY_ROOT, rootBefore));
        pool.applyBlock(statement, proof);
    }

    /// A statement whose length disagrees with its own header must not decode:
    /// the folded length is 81 + 6n, so a truncated or padded statement is not
    /// one this prover could have exported for that header.
    function test_decode_rejects_a_length_that_disagrees_with_the_header() public {
        // Same header (n = 1), one limb short.
        uint256[] memory short_ = new uint256[](statement.length - 1);
        for (uint256 i; i < short_.length; ++i) {
            short_[i] = statement[i];
        }
        vm.expectRevert("statement length disagrees with header");
        decoder.decode(short_);

        // One limb of trailing junk after the fees.
        uint256[] memory long_ = new uint256[](statement.length + 1);
        for (uint256 i; i < statement.length; ++i) {
            long_[i] = statement[i];
        }
        vm.expectRevert("statement length disagrees with header");
        decoder.decode(long_);

        // A header claiming two transfers over a one-transfer statement.
        uint256[] memory lying = new uint256[](statement.length);
        for (uint256 i; i < statement.length; ++i) {
            lying[i] = statement[i];
        }
        lying[0] = 2;
        vm.expectRevert("statement length disagrees with header");
        decoder.decode(lying);
    }

    function test_blocks_chain_across_transfers() public {
        pool.applyBlock(
            _withRoots(statement, pool.currentRoot(), rootAfter, pool.currentNullifierRoot()),
            proof);
        assertEq(pool.currentRoot(), rootAfter, "first block landed");
        // The same block verbatim must fail: its rootBefore names the state the
        // first block started from, not the one after it. (Rewriting rootBefore
        // would be a different block - and the real proof would not verify
        // against rewritten limbs; the WHIR side pins that, not this test.)
        vm.expectRevert(
            abi.encodeWithSelector(ShieldedPool.RootMismatch.selector, rootAfter, rootBefore));
        pool.applyBlock(statement, proof);
        // A second block that continues from the first applies: the roots are
        // rewritten so the pair chains. The fold root is unchanged - the stub
        // does not check it, and the continuity check is the contract whole
        // contribution.
        pool.applyBlock(
            _withRoots(statement, rootAfter, nullifierAfter, nullifierAfter),
            proof);
        assertEq(pool.blockNumber(), 2, "two blocks");
        assertEq(pool.currentRoot(), nullifierAfter, "second attested root stored");
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
