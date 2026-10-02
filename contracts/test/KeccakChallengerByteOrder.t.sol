// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KeccakChallenger} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

/// Byte-order probe: does the vendored `KeccakChallenger` reproduce the exact
/// challenge stream that `p3_challenger::SerializingChallenger32<Keccak256>`
/// produces?
///
/// The ground truth is `contracts/test/vectors/transcript_vectors.json`, recorded
/// by the Rust prover's `TraceChallenger` from a real transcript. The first
/// observed word is the Montgomery form of `0xdeadbeef` (`b5c7220a`), and the
/// four bytes squeezed next are `22 63 54 73`, which `SerializingChallenger32`
/// reads as a little-endian `u32` to give `alpha = 1934910242`.
///
/// This test exists because the vendored sampler's byte order cannot be settled
/// by reading it: it pops a `uint32` off the *end* of the digest block, and
/// whether that lands on the same four bytes p3 reads depends on how the digest
/// is laid out in the `bytes32`. Only running it settles the question.
contract KeccakChallengerByteOrderTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    /// The Montgomery form of 0xdeadbeef, as the Rust transcript absorbs it.
    bytes internal constant FIRST_OBSERVED = hex"b5c7220a";

    /// The alpha the Rust transcript derived from absorbing FIRST_OBSERVED.
    uint256 internal constant EXPECTED_ALPHA = 1_934_910_242;

    function test_vendored_sampler_reproduces_rust_alpha() public pure {
        KeccakChallenger.State memory state;
        state.observeBytes(FIRST_OBSERVED);
        uint256 alpha = state.sampleBase();
        assertEq(alpha, EXPECTED_ALPHA, "vendored sampler diverges from p3 byte order");
    }
}
