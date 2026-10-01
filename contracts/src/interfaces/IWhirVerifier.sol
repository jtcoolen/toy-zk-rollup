// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The proof-verification seam.
///
/// The pool needs one thing from a prover: "this statement is backed by a proof
/// that verifies". How that is established is somebody else's problem, injected
/// at construction. That keeps the settlement state machine — the part holding
/// money — independent of the proof system, so the WHIR verifier can be
/// swapped, upgraded, or stubbed in tests without touching it.
///
/// Implementations must be pure functions of their inputs: no storage reads that
/// could make verification depend on anything but the proof and the statement.
interface IWhirVerifier {
    /// Verify `proof` against `statement`.
    ///
    /// Returns true only if the proof is valid for exactly this statement. A
    /// statement is the flat array of base-field limbs the prover exported,
    /// including the shape header; the verifier does not interpret it.
    ///
    /// Reverts (rather than returning false) on a malformed proof, so a
    /// malformed proof never silently becomes "valid".
    function verify(uint256[] calldata statement, bytes calldata proof) external view returns (bool);
}
