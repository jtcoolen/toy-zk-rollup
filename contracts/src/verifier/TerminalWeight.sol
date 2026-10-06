// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "./WhirGadgets.sol";

/// @title TerminalWeight
/// @notice The terminal-weight satellite (D-086 step A).
///
/// The verifier's last phase - the batched constraint polynomial at the full
/// folding randomness, and the public polynomial at the closing randomness -
/// is the largest single block of verifier bytecode (evalConstraintsPoly,
/// constraintWeight, the eq/select evaluators) and it runs once per batch
/// round - a handful of times per verify, never in the per-query path. This
/// contract owns that computation so the pinned core fits under EIP-170 with
/// room to spare. The library functions are internal, so they inline HERE and
/// nowhere else: one source of truth, no duplication in WhirVerifier.
///
/// # Frame protocol (raw calldata, no ABI codec)
///
/// The caller staticcalls this contract with a contiguous word frame (no
/// selector; every call lands in fallback). All words are 32-byte
/// big-endian, canonical field elements exactly as the verifier holds them:
///
/// ```text
/// word 0        magic 0x5457_4947_4854 ("TWIGHT")
/// word 1        n, then n words of allR
/// next          m = constraint count; per constraint, 6 header words:
///                 k, gamma, initialPower, mode, nGroups, nSel
///   mode 1 (wire groups): nGroups eq-length words, then the flat eq words
///               (sum of lengths). The satellite's eqCdBase is the absolute
///               calldata byte offset of those words - the same
///               calldata-relative trick the core uses against the proof
///               bundle, so the big eq section is read, never decoded.
///   mode 0 (derived):     nGroups groups of exactly k words each.
///   then nSel selVars words.
/// next          nFinal, then finalPoly (nFinal words)
/// next          nRand, then randomness (nRand words)
/// ```
///
/// The frame must end exactly at calldatasize; anything else is malformed
/// and reverts. The reply is the raw 96-byte frame [magic, weight, value].
///
/// # Trust
///
/// This is a pure function of the frame: it touches no state and reverts on
/// any malformed input. The caller performs the terminal equality
/// folded == weight * value itself, so a faulty or malicious satellite can
/// only make verification FAIL - never pass. The verifier pins this
/// contract's codehash at construction and re-checks it before every call.
contract TerminalWeight {
    /// @notice Frame magic: ASCII "TWIGHT".
    uint256 public constant MAGIC = 0x5457_4947_4854;

    /// @notice The frame did not start with the magic.
    error BadFrame();
    /// @notice The frame carries trailing or missing words.
    error BadFrameLength();

    /// @notice Parse the frame, evaluate the terminal weight and value, and
    /// reply [magic, weight, value]. No mutability modifier: a fallback may
    /// not be declared pure/view, but this body reads no state and the caller
    /// staticcalls it, so ETH can never enter and nothing is written.
    fallback() external {
        uint256[] memory allR;
        WhirGadgets.ConstraintWeight[] memory constraints;
        uint256[] memory finalPoly;
        uint256[] memory randomness;
        assembly ("memory-safe") {
            // Raw staticcall: the frame IS the calldata, starting at byte 0.
            let c := 0
            if iszero(eq(calldataload(0), MAGIC)) {
                mstore(0, 0xe9459814) // BadFrame()
                revert(0, 4)
            }
            c := 32

            // --- allR ---
            let n := calldataload(c)
            c := add(c, 32)
            allR := mload(0x40)
            mstore(allR, n)
            calldatacopy(add(allR, 32), c, mul(n, 32))
            c := add(c, mul(n, 32))
            mstore(0x40, add(add(allR, 32), mul(n, 32)))

            // --- constraints ---
            let m := calldataload(c)
            c := add(c, 32)
            constraints := mload(0x40)
            mstore(constraints, m)
            let cb := add(constraints, 32)
            // ConstraintWeight has dynamic members, so Solidity lays its
            // memory array out as POINTS: m words here, each the address of
            // a 224-byte block (7 words) allocated after them. Inline
            // structs would be read back as garbage pointers.
            mstore(0x40, add(cb, mul(m, 32)))
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                let base := mload(0x40)
                mstore(0x40, add(base, 224))
                mstore(add(cb, mul(i, 32)), base)
                let k := calldataload(c)
                let gamma := calldataload(add(c, 32))
                let ipow := calldataload(add(c, 64))
                let mode := calldataload(add(c, 96))
                let nGroups := calldataload(add(c, 128))
                let nSel := calldataload(add(c, 160))
                c := add(c, 192)
                // Field order: [0]numVariables [1]gamma [2]initialPower
                // [3]eqPoints(+96) [4]eqCdBase(+128) [5]eqLens(+160)
                // [6]selVars(+192).
                mstore(base, k)
                mstore(add(base, 32), gamma)
                mstore(add(base, 64), ipow)

                if eq(mode, 1) {
                    // Wire groups stay in OUR calldata: eqLens to memory,
                    // eqCdBase = absolute offset of the flat words here.
                    let lens := mload(0x40)
                    mstore(lens, nGroups)
                    calldatacopy(add(lens, 32), c, mul(nGroups, 32))
                    c := add(c, mul(nGroups, 32))
                    mstore(0x40, add(add(lens, 32), mul(nGroups, 32)))
                    mstore(add(base, 160), lens)
                    mstore(add(base, 128), c) // eqCdBase
                    let total := 0
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        total := add(total, mload(add(add(lens, 32), mul(j, 32))))
                    }
                    c := add(c, mul(total, 32))
                }
                if eq(mode, 0) {
                    // Derived groups: ragged memory array, k words each.
                    let pts := mload(0x40)
                    mstore(pts, nGroups)
                    let pd := add(pts, 32)
                    mstore(0x40, add(pd, mul(nGroups, 32)))
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        let grp := mload(0x40)
                        mstore(grp, k)
                        calldatacopy(add(grp, 32), c, mul(k, 32))
                        c := add(c, mul(k, 32))
                        mstore(0x40, add(add(grp, 32), mul(k, 32)))
                        mstore(add(pd, mul(j, 32)), grp)
                    }
                    mstore(add(base, 96), pts) // eqPoints; eqCdBase stays 0
                }

                // selVars (absent when nSel == 0, matching the verifier).
                if nSel {
                    let sv := mload(0x40)
                    mstore(sv, nSel)
                    calldatacopy(add(sv, 32), c, mul(nSel, 32))
                    c := add(c, mul(nSel, 32))
                    mstore(0x40, add(add(sv, 32), mul(nSel, 32)))
                    mstore(add(base, 192), sv)
                }
            }

            // --- finalPoly ---
            let nFinal := calldataload(c)
            c := add(c, 32)
            finalPoly := mload(0x40)
            mstore(finalPoly, nFinal)
            calldatacopy(add(finalPoly, 32), c, mul(nFinal, 32))
            c := add(c, mul(nFinal, 32))
            mstore(0x40, add(add(finalPoly, 32), mul(nFinal, 32)))

            // --- randomness ---
            let nRand := calldataload(c)
            c := add(c, 32)
            randomness := mload(0x40)
            mstore(randomness, nRand)
            calldatacopy(add(randomness, 32), c, mul(nRand, 32))
            c := add(c, mul(nRand, 32))
            mstore(0x40, add(add(randomness, 32), mul(nRand, 32)))

            if iszero(eq(c, calldatasize())) {
                mstore(0, 0x09a205cc) // BadFrameLength()
                revert(0, 4)
            }
        }

        uint256 weight = WhirGadgets.evalConstraintsPoly(allR, constraints, false);
        uint256 value = KoalaBearExt4.evaluate_hypercube(finalPoly, randomness);
        assembly ("memory-safe") {
            mstore(0, MAGIC)
            mstore(32, weight)
            mstore(64, value)
            return(0, 96)
        }
    }
}
