// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, stdJson} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";

/// External shims over the library internal functions.
///
/// Two reasons, both mechanical. `vm.expectRevert` only observes a revert at a
/// LOWER call depth than the cheatcode call, and a library internal call inlines to
/// nothing, so a guard in a direct call would be reported as "call didn't revert at
/// a lower depth". And the shims take the constraint as a single `calldata`
/// struct rather than five parallel arrays: seven parameters pushes the Yul
/// stack past its limit in the ABI decoder, with an error that names neither the
/// function nor the cause.
///
/// Not production surface: the library is `internal` so nothing deploys it.
contract WhirGadgetsHarness {
    function expandFromUnivariate(uint256 z, uint256 n) external pure returns (uint256[] memory) {
        return WhirGadgets.expandFromUnivariate(z, n);
    }

    function eqEval(uint256[] calldata p_, uint256[] calldata q) external pure returns (uint256) {
        return WhirGadgets.eqEval(p_, q);
    }

    function selectEval(uint256[] calldata point, uint256 z) external pure returns (uint256) {
        return WhirGadgets.selectEval(point, z);
    }

    function powersCombination(uint256[] calldata values, uint256 base)
        external
        pure
        returns (uint256)
    {
        return WhirGadgets.powersCombination(values, base);
    }

    function constraintWeight(uint256[] calldata localR, WhirGadgets.ConstraintWeight calldata c)
        external
        pure
        returns (uint256)
    {
        return WhirGadgets.constraintWeight(localR, c);
    }

    function evalConstraintsPoly(
        uint256[] calldata allR,
        WhirGadgets.ConstraintWeight[] calldata constraints,
        bool isSuffix
    )
        external
        pure
        returns (uint256)
    {
        // calldata -> memory copy, which is what the library signature asks for.
        WhirGadgets.ConstraintWeight[] memory cs =
            new WhirGadgets.ConstraintWeight[](constraints.length);
        for (uint256 i; i < constraints.length; ++i) {
            cs[i] = constraints[i];
        }
        return WhirGadgets.evalConstraintsPoly(allR, cs, isSuffix);
    }
}

/// The multilinear gadget layer, replayed against vectors produced by the p3
/// functions the prover itself calls.
///
/// Every gadget is asserted against its own expected value instead of being folded
/// into one end-to-end check, because these are the pieces the WHIR core composes
/// and a single pass/fail would not say which convention broke. The conventions at
/// risk are all silent: `expandFromUnivariate` filled little-endian,
/// `selectEval` pairing the first coordinate with the first power, a constraint
/// weight starting at `gamma^1` where it should start at `gamma^0`. Each yields
/// a perfectly valid field element and a broken proof system.
///
/// The constraint-weight cases are the load-bearing ones. They come from
/// `VariableOrder::eval_constraints_poly` over real `Constraint` values holding
/// real `EqStatement` and `SelectStatement` groups, so the expected value is the
/// native verifier's own output including its grouping and power-shift rules, not a
/// reading of them. That distinction is the whole method here: a misread convention
/// written out as an expected value produces a test that agrees with itself.
contract WhirGadgetsTest is Test {
    using stdJson for string;

    string internal constant VECTOR = "test/vectors/whir_gadgets.json";

    /// The packed extension one, used for the empty-product assertions.
    uint256 internal constant EXT_ONE = uint256(1) << 224;

    WhirGadgetsHarness internal harness = new WhirGadgetsHarness();

    /// One extension element: four canonical coefficients, low order first.
    function extAt(string memory json, string memory path) internal pure returns (uint256) {
        uint256[] memory coeffs = json.readUintArray(path);
        require(coeffs.length == 4, "extension element must have 4 coefficients");
        return KoalaBearExt4.pack([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
    }

    /// An array of `n` extension elements, packed in order. `n == 0` gives an
    /// empty array, which is a case the vectors exercise rather than a gap.
    function extArray(string memory json, string memory path, uint256 n)
        internal
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = extAt(json, string.concat(path, "[", vm.toString(i), "]"));
        }
    }

    function test_vector_file_has_the_expected_shape() public view {
        string memory json = vm.readFile(VECTOR);
        assertEq(json.readString(".scheme"), "whir_gadgets", "scheme");
        assertEq(json.readString(".field"), "koalabear_ext4", "field");
        assertEq(json.readUint(".dimension"), 4, "extension degree");
        // Asserted so a regenerated file with fewer cases fails here rather than
        // quietly testing less.
        assertEq(json.readUint(".num_expand"), 5, "expand cases");
        assertEq(json.readUint(".num_eq"), 5, "eq cases");
        assertEq(json.readUint(".num_select"), 5, "select cases");
        assertEq(json.readUint(".num_pow"), 8, "pow cases");
        assertEq(json.readUint(".num_powers"), 7, "powers cases");
        assertEq(json.readUint(".num_constraints"), 6, "constraint cases");
        // The rules are recorded in the file, so a reader who finds the vectors
        // without finding this test still learns what they pin.
        assertEq(
            json.readString(".expand_rule"),
            "point[i] = z^(2^(num_variables-1-i)), big-endian: coordinate 0 is the highest power",
            "expand rule"
        );
        assertEq(json.readString(".prefix_rule"), "local_r = all_r[n-k..]", "prefix rule");
        assertEq(
            json.readString(".suffix_rule"),
            "local_r = reverse(all_r[n-k..])",
            "suffix rule"
        );
    }

    /// `expand_from_univariate`, including the empty point.
    function test_expand_from_univariate_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_expand");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".expand[", vm.toString(i), "]");
            uint256 z = extAt(json, string.concat(ck, ".z"));
            uint256 vars = json.readUint(string.concat(ck, ".num_variables"));
            uint256[] memory want = extArray(json, string.concat(ck, ".point"), vars);
            uint256[] memory got = harness.expandFromUnivariate(z, vars);
            assertEq(got.length, want.length, "point length");
            for (uint256 j; j < want.length; ++j) {
                assertEq(got[j], want[j], "coordinate");
            }
            // The big-endian convention, asserted structurally as well as against
            // the vectors. Coordinate j holds z^(2^(n-1-j)), so the LAST coordinate is
            // z itself and each EARLIER one is the square of the one after it:
            // got[j] == square(got[j+1]). A little-endian fill passes the value check
            // only when z is a fixed point of squaring, which drawn elements are not,
            // but this names the offending case instead of failing on the last one.
            //
            // (Written the other way round this assertion failed while every value
            // check passed - which is the useful property of pinning a convention
            // structurally as well as numerically: it disagrees with a wrong reading
            // of the rule even when the implementation is correct.)
            if (vars > 0) {
                assertEq(got[vars - 1], z, "last coordinate is z");
                for (uint256 j = 1; j < vars; ++j) {
                    assertEq(
                        KoalaBearExt4.square(got[j]),
                        got[j - 1],
                        "each coordinate squares to the one before it"
                    );
                }
            }
        }
    }

    /// `Point::eval_eq`, including the empty product.
    function test_eq_eval_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_eq");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".eq[", vm.toString(i), "]");
            uint256 vars = json.readUint(string.concat(ck, ".num_vars"));
            uint256[] memory p_ = extArray(json, string.concat(ck, ".p"), vars);
            uint256[] memory q = extArray(json, string.concat(ck, ".q"), vars);
            uint256 want = extAt(json, string.concat(ck, ".value"));
            assertEq(harness.eqEval(p_, q), want, "eq value");
            // The empty product is one. A loop seeded with zero gets this wrong, and
            // it is reachable: a zero-variable constraint is a constant.
            if (vars == 0) {
                assertEq(want, EXT_ONE, "empty eq is one");
            }
            // eq is symmetric in its arguments. The identity makes that obvious and a
            // mis-transcribed term breaks it, so this is a second, independent look
            // at the same value.
            assertEq(harness.eqEval(q, p_), want, "eq is symmetric");
        }
    }

    /// `Point::eval_select`.
    function test_select_eval_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_select");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".select[", vm.toString(i), "]");
            uint256 vars = json.readUint(string.concat(ck, ".num_vars"));
            uint256 z = extAt(json, string.concat(ck, ".var"));
            uint256[] memory point = extArray(json, string.concat(ck, ".point"), vars);
            uint256 want = extAt(json, string.concat(ck, ".value"));
            assertEq(harness.selectEval(point, z), want, "select value");
            if (vars == 0) {
                assertEq(want, EXT_ONE, "empty select is one");
            }
            // z = 1 makes every factor one, so the product is one for ANY point.
            // Independent of the vectors, and it catches a factor written as
            // (z^(2^k) + 1) or with the offset dropped, both of which still produce
            // plausible values at a random z.
            assertEq(
                harness.selectEval(point, EXT_ONE),
                EXT_ONE,
                "select at z=1 is one"
            );
        }
    }

    /// `pow_const_base`: the two-adic domain point of a query index.
    function test_pow_const_base_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_pow");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".pow[", vm.toString(i), "]");
            uint256 generator = json.readUint(string.concat(ck, ".generator"));
            uint256 index = json.readUint(string.concat(ck, ".index"));
            uint256 want = extAt(json, string.concat(ck, ".value"));
            assertEq(WhirGadgets.powConstBase(generator, index), want, "domain point");
        }
        // Index 0 is the identity and index = order wraps back to it, which pins the
        // generator really being a subgroup generator rather than an arbitrary
        // element with a similar name.
        uint256 g = json.readUint(".pow[0].generator");
        assertEq(WhirGadgets.powConstBase(g, 0), EXT_ONE, "gen^0 is one");
        assertEq(
            WhirGadgets.powConstBase(g, 256),
            WhirGadgets.powConstBase(g, 0),
            "gen^order is one"
        );
    }

    /// `eval_powers_combination`, including the empty combination.
    function test_powers_combination_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_powers");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".powers[", vm.toString(i), "]");
            uint256 count = json.readUint(string.concat(ck, ".num_values"));
            uint256[] memory values = extArray(json, string.concat(ck, ".values"), count);
            uint256 base = extAt(json, string.concat(ck, ".base"));
            uint256 want = extAt(json, string.concat(ck, ".value"));
            assertEq(harness.powersCombination(values, base), want, "powers value");
            // The empty combination is ZERO, not one. A Horner loop seeded with ONE
            // returns one for empty input, and an empty group is a real case: a
            // round with no OOD samples.
            if (count == 0) {
                assertEq(want, 0, "empty sum is zero");
            }
            // One term combines to itself at any base: catches a sequence starting at
            // gamma^1 instead of gamma^0.
            if (count >= 1) {
                uint256[] memory one = new uint256[](1);
                one[0] = values[0];
                assertEq(
                    harness.powersCombination(one, base),
                    values[0],
                    "single term is itself"
                );
            }
        }
    }

    /// Build the single constraint a case describes.
    function caseConstraint(
        string memory json,
        string memory ck,
        uint256 k
    )
        internal
        pure
        returns (WhirGadgets.ConstraintWeight memory c)
    {
        c.numVariables = k;
        c.gamma = extAt(json, string.concat(ck, ".gamma"));
        uint256 nEq = json.readUint(string.concat(ck, ".num_eq_points"));
        c.eqPoints = new uint256[][](nEq);
        for (uint256 e; e < nEq; ++e) {
            c.eqPoints[e] = extArray(
                json,
                string.concat(ck, ".eq_points[", vm.toString(e), "]"),
                k
            );
        }
        uint256 nSel = json.readUint(string.concat(ck, ".num_sel_vars"));
        c.selVars = extArray(json, string.concat(ck, ".sel_vars"), nSel);
    }

    /// Evaluate one case with a given initial power and variable order.
    function evalCase(
        uint256[] memory allR,
        WhirGadgets.ConstraintWeight memory c,
        uint256 initialPower,
        bool isSuffix
    )
        internal
        view
        returns (uint256)
    {
        WhirGadgets.ConstraintWeight[] memory cs =
            new WhirGadgets.ConstraintWeight[](1);
        c.initialPower = initialPower;
        cs[0] = c;
        return harness.evalConstraintsPoly(allR, cs, isSuffix);
    }

    /// The batched constraint polynomial: both variable orders and both
    /// `initial_power` settings, against the native verifier's own function.
    ///
    /// Four expected values per case, which is the point. Prefix and Suffix differ,
    /// and fresh and carried differ by exactly one power of gamma. A port that
    /// ignores the variable order passes two of four; one that hardcodes
    /// `initial_power = 0` passes two the other way.
    function test_eval_constraints_poly_matches() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_constraints");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".constraints[", vm.toString(i), "]");
            uint256 nR = json.readUint(string.concat(ck, ".num_all_r"));
            uint256[] memory allR = extArray(json, string.concat(ck, ".all_r"), nR);
            uint256 k = json.readUint(string.concat(ck, ".num_variables"));
            uint256 gamma = extAt(json, string.concat(ck, ".gamma"));
            WhirGadgets.ConstraintWeight memory c = caseConstraint(json, ck, k);

            uint256 prefixFresh = evalCase(allR, c, 0, false);
            uint256 suffixFresh = evalCase(allR, c, 0, true);

            assertEq(
                prefixFresh,
                extAt(json, string.concat(ck, ".prefix_fresh")),
                "prefix fresh"
            );
            assertEq(
                suffixFresh,
                extAt(json, string.concat(ck, ".suffix_fresh")),
                "suffix fresh"
            );
            assertEq(
                evalCase(allR, c, 1, false),
                extAt(json, string.concat(ck, ".prefix_carried")),
                "prefix carried"
            );
            assertEq(
                evalCase(allR, c, 1, true),
                extAt(json, string.concat(ck, ".suffix_carried")),
                "suffix carried"
            );

            // The carried weight is the fresh weight times gamma, exactly. That is
            // what initial_power = 1 means, and it is a relation between two of the
            // four values rather than a fifth expected number, so it catches a shift
            // applied in the wrong place - inside the combination instead of after
            // it, for instance, which would scale only part of the sum.
            assertEq(
                KoalaBearExt4.mul(prefixFresh, gamma),
                evalCase(allR, c, 1, false),
                "carried is fresh times gamma"
            );
            assertEq(
                KoalaBearExt4.mul(suffixFresh, gamma),
                evalCase(allR, c, 1, true),
                "carried is fresh times gamma (suffix)"
            );

            // Prefix and Suffix must actually differ, or the two order assertions
            // would be satisfied by an implementation that ignores the flag and a
            // vector file that happened to agree.
            if (k > 1) {
                assertTrue(prefixFresh != suffixFresh, "orders must differ for k > 1");
            }
        }
    }

    /// `constraintWeight` on its own, at an explicitly sliced local point, so a
    /// failure says whether the slicing or the weighting broke.
    function test_constraint_weight_matches_the_batched_polynomial() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_constraints");
        for (uint256 i; i < cases; ++i) {
            string memory ck = string.concat(".constraints[", vm.toString(i), "]");
            uint256 nR = json.readUint(string.concat(ck, ".num_all_r"));
            uint256[] memory allR = extArray(json, string.concat(ck, ".all_r"), nR);
            uint256 k = json.readUint(string.concat(ck, ".num_variables"));
            WhirGadgets.ConstraintWeight memory c = caseConstraint(json, ck, k);

            // Slice by hand, the prefix way, and compare against the library doing
            // it. With one constraint the two must agree exactly.
            uint256[] memory localR = new uint256[](k);
            for (uint256 j; j < k; ++j) {
                localR[j] = allR[nR - k + j];
            }
            c.initialPower = 0;
            assertEq(harness.constraintWeight(localR, c),
                evalCase(allR, c, 0, false), "prefix slice agrees with the library");

            uint256[] memory revR = new uint256[](k);
            for (uint256 j; j < k; ++j) {
                revR[j] = allR[nR - 1 - j];
            }
            assertEq(harness.constraintWeight(revR, c),
                evalCase(allR, c, 0, true), "suffix slice agrees with the library");
        }
    }

    /// The slicing rule on its own. An arity-1 constraint reads only the LAST
    /// accumulated challenge, because the earlier ones were bound by earlier rounds
    /// and are already substituted into the claim. So changing an earlier challenge
    /// cannot change the result while changing the last one must. For k = 1 prefix
    /// and suffix select the same coordinate, which is why this test is about the
    /// slice and not the order.
    function test_arity_one_reads_only_the_last_challenge() public view {
        uint256[] memory allR = new uint256[](3);
        allR[0] = KoalaBearExt4.fromBase(7);
        allR[1] = KoalaBearExt4.fromBase(11);
        allR[2] = KoalaBearExt4.fromBase(13);

        WhirGadgets.ConstraintWeight memory c;
        c.numVariables = 1;
        c.gamma = KoalaBearExt4.fromBase(3);
        c.eqPoints = new uint256[][](1);
        c.eqPoints[0] = new uint256[](1);
        c.eqPoints[0][0] = KoalaBearExt4.fromBase(5);

        uint256 base = evalCase(allR, c, 0, false);

        uint256[] memory earlier = new uint256[](3);
        earlier[0] = KoalaBearExt4.fromBase(999);
        earlier[1] = KoalaBearExt4.fromBase(4242);
        earlier[2] = allR[2];
        assertEq(
            evalCase(earlier, c, 0, false),
            base,
            "arity 1 must ignore every challenge but the last"
        );

        uint256[] memory later = new uint256[](3);
        later[0] = allR[0];
        later[1] = allR[1];
        later[2] = KoalaBearExt4.fromBase(17);
        assertTrue(
            evalCase(later, c, 0, false) != base,
            "arity 1 must depend on the last challenge"
        );
    }

    /// A constraint asking for more variables than the run accumulated is a bug in
    /// the caller. The alternatives are reading out of bounds or silently clamping
    /// to a wrong point, and a wrong point here is a verifier that accepts
    /// everything.
    function test_too_many_variables_reverts() public {
        uint256[] memory allR = new uint256[](2);
        allR[0] = KoalaBearExt4.fromBase(1);
        allR[1] = KoalaBearExt4.fromBase(2);

        WhirGadgets.ConstraintWeight memory c;
        c.numVariables = 3;
        c.gamma = KoalaBearExt4.fromBase(3);

        WhirGadgets.ConstraintWeight[] memory cs = new WhirGadgets.ConstraintWeight[](1);
        cs[0] = c;

        vm.expectRevert(
            abi.encodeWithSelector(WhirGadgets.NotEnoughChallenges.selector, 3, 2)
        );
        harness.evalConstraintsPoly(allR, cs, false);
    }

    /// `eqEval` on mismatched points reverts rather than dropping the extra
    /// coordinates, which would silently evaluate a different polynomial.
    function test_eq_eval_length_mismatch_reverts() public {
        uint256[] memory a = new uint256[](2);
        a[0] = KoalaBearExt4.fromBase(1);
        a[1] = KoalaBearExt4.fromBase(2);
        uint256[] memory b = new uint256[](1);
        b[0] = KoalaBearExt4.fromBase(3);

        vm.expectRevert(
            abi.encodeWithSelector(WhirGadgets.PointLengthMismatch.selector, 2, 1)
        );
        harness.eqEval(a, b);
    }
}
