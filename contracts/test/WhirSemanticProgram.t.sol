// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {KeccakChallenger} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {SemanticBlob} from "./utils/SemanticBlob.sol";

/// Replays the WHIR verifier transcript at the PROTOCOL level.
///
/// The sibling WhirTranscriptReplay test replays a byte stream. This replays the
/// OPERATION stream, which is the level the verifier is written at: each entry says
/// observe this, sample that, check a proof-of-work witness. The distinction matters
/// because the byte stream is not reproducible - a squeeze flushes a partially-filled
/// output buffer, so how many bytes it absorbs depends on how many rejection samples
/// happened upstream, and two recordings of the SAME proof differ at squeeze sites.
/// The operation stream is identical across witnesses, measured over four.
///
/// The vector comes from crates/prover/tests/whir_semantic_program.rs, which proves
/// with the production config and VERIFIES through the recorder. Verification passing
/// is the evidence that the recorded operations are the ones p3 actually ran. So that
/// test and this one together make Solidity agree with Rust without either being the
/// other reference - the property a settlement verifier needs.
///
/// This test is what found two real bugs in the vendored challenger: observeBase did
/// not invalidate buffered output, and checkWitness omitted the squeeze that folds
/// pending input into the digest before the witness is absorbed.
///
/// The blob format itself is read by SemanticBlob, shared with WhirProofVectorsTest:
/// two readers of one format can drift into agreeing with each other instead of with
/// the prover, which is the failure mode the vector methodology exists to rule out.
contract WhirSemanticProgramTest is Test {
    using KeccakChallenger for KeccakChallenger.State;
    using SemanticBlob for SemanticBlob.Blob;

    /// The blob is the whole spec: header, schedule and five payloads in one binary.
    /// Read with `readFileBinary` so there is no hex copy to keep in step with it.
    string internal constant BLOB = "test/vectors/whir_semantic_program.bin";

    /// Production shape: 25 variables, 4 WHIR rounds, 257 terminal queries. Pinned so
    /// a regeneration that silently changed the config fails here rather than quietly
    /// narrowing what the contract is tested against.
    uint256 internal constant PINNED_SAMPLES = 224;
    uint256 internal constant PINNED_WITNESSES = 23;
    bytes32 internal constant PINNED_CONST_STATE =
        0xa8eac9b8e75e9fab0bc7981fce47e33fea382bea2cf648185268c6ad07a1eea7;

    /// Replays every recorded operation on the EVM sponge and asserts every recorded
    /// sample. If the Solidity sampler consumed bytes in a different order, or with a
    /// different rejection bound, a sample would mismatch at the site named in the log.
    function test_replay_semantic_program() public view {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        SemanticBlob.Walk memory w = SemanticBlob.walk(b, true, false);

        // Every payload consumed exactly. A short read means the schedule and the
        // payloads disagree, which would leave a verifier absorbing the wrong bytes at
        // some later, unnamed site.
        assertEq(w.cursor.constants, b.constLen, "constant payload not fully read");
        assertEq(w.cursor.variables, b.varLen, "variable payload not fully read");
        assertEq(w.cursor.samples, b.sampleLen, "sample payload not fully read");
        assertEq(w.cursor.uniform, b.uniformLen, "uniform payload not fully read");
        assertEq(w.cursor.witnesses, b.witnessLen, "witness payload not fully read");
        assertEq(b.sampleLen / 4, PINNED_SAMPLES, "sample count");
        assertEq(b.witnessLen / 4, PINNED_WITNESSES, "witness check count");
        assertTrue(w.state.outputIndex <= SemanticBlob.DIGEST_LEN, "output index out of range");
    }

    /// A golden that survives regenerating the vector.
    ///
    /// The chaining state after the FULL replay is not pinnable: the proof is
    /// HVZK-blinded, so every regeneration changes the proof data, and with it every
    /// sample and the final state. Verified by recording the same witness three times
    /// - the schedule and the config-fixed constant payload were byte-identical, while
    /// the variable, sample, uniform and witness payloads all moved.
    ///
    /// The config-fixed constants are exactly the part a verifier hard-codes, so
    /// absorbing them through the challenger and pinning the result pins the things
    /// that must not drift: little-endian word encoding in observeBase, buffer growth,
    /// and the flush-chaining rule that hashes the previous digest forward. A pure
    /// Python sponge written from the p3 source reaches the same state.
    function test_config_fixed_constants_reach_pinned_state() public view {
        SemanticBlob.Blob memory b = SemanticBlob.load(BLOB);
        (KeccakChallenger.State memory st, uint256 absorbed) = SemanticBlob.absorbConstants(b);
        assertEq(absorbed, b.constLen, "not every constant absorbed");
        assertEq(st.debugInputHash(), PINNED_CONST_STATE, "chaining state over config-fixed constants");
    }
}
