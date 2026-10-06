// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "../../src/verifier/WhirGadgets.sol";

/// Reference implementation of the terminal identity for the JSON-driven
/// harnesses:
///
///     eval_constraints_poly(all_r) * final_poly(final_r)
///
/// Production computes this in the pinned TerminalWeight satellite (D-086 step
/// A); the harnesses compute it here, in a separate contract, for the same
/// reason twice over. It is an independent second opinion on the satellite's
/// answer, and it keeps the eval chain out of the harness's own stack frame -
/// inlined into the final phase, evalConstraintsPoly's live set pushes the
/// via-IR scheduler past the stack limit.
///
/// Unlike the satellite this takes the constraint weights over the ABI codec,
/// so it only handles constraints whose eq groups live in memory (the derived
/// OOD/selector groups the harnesses build), not the wire eq section.
contract TerminalRef {
    /// The right-hand side of the terminal identity, with all_r assembled here:
    /// every folding randomness in protocol order, closing point appended.
    function expected(
        uint256[] memory allRandomness,
        uint256[] memory closing,
        WhirGadgets.ConstraintWeight[] memory constraints,
        uint256[] memory finalPoly
    ) external pure returns (uint256) {
        uint256[] memory allR = new uint256[](allRandomness.length + closing.length);
        for (uint256 i; i < allRandomness.length; ++i) {
            allR[i] = allRandomness[i];
        }
        for (uint256 i; i < closing.length; ++i) {
            allR[allRandomness.length + i] = closing[i];
        }
        uint256 weight = WhirGadgets.evalConstraintsPoly(allR, constraints, false);
        uint256 value = KoalaBearExt4.evaluate_hypercube(finalPoly, closing);
        return KoalaBearExt4.mul(weight, value);
    }
}
