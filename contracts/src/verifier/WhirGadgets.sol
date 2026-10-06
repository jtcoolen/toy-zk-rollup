// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBear} from "../../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";

/// The multilinear arithmetic the WHIR verifier core is built out of.
///
/// WHY THIS IS A SEPARATE LIBRARY
///
/// `WhirVerifierCore` will be a long function with a lot of state, and the
/// arithmetic it performs is not specific to one place in it: the equality
/// polynomial appears in the constraint weights, the selection polynomial appears
/// in the constraint weights, the powers combination appears both in the round
/// claim update and in the final weight batching. Pulling them out here means each
/// is pinned by its own vector, so when the core misbehaves the question is which
/// primitive, not which line.
///
/// EVERY FUNCTION HERE IS PINNED AGAINST THE FUNCTION THE PROVER CALLS
///
/// `contracts/test/vectors/whir_gadgets.json` comes from
/// `crates/prover/tests/whir_gadget_vectors.rs`, which calls
/// `Point::expand_from_univariate~, `Point::eval_eq~, `Point::eval_select~ and
/// `VariableOrder::eval_constraints_poly~ directly, on real `Constraint` values
/// holding real `EqStatement` and `SelectStatement` groups. Nothing in the file
/// is a reimplementation of a formula read off the reference, which is the failure
/// mode this whole port has been avoiding: a misread convention produces a
/// plausible-looking expected value and a test that agrees with itself.
///
/// THE CONVENTIONS THAT ARE EASY TO READ BACKWARDS
///
/// - `expandFromUnivariate` is BIG-ENDIAN: coordinate 0 is `z^(2^(n-1))~, the
///   LAST coordinate is `z`. The natural loop fills the other way.
/// - `selectEval` consumes the point from the LAST coordinate while `var` is
///   still `var^(2^0)`, squaring once per factor. Pairing first coordinate with
///   first power looks equivalent and is not.
/// - `constraintWeight` batches equality terms at `gamma^0` and selection terms
///   at `gamma^n_eq`, THEN shifts the whole thing by `gamma^initialPower`. A
///   round constraint carries the running claim at `gamma^0` so its fresh
///   statements start at `gamma^1`; the initial constraint starts at `gamma^0`.
///   Getting that wrong shifts every term by one power of a secret challenge,
///   which no transcript can detect because the challenge is what the transcript
///   produced.
///
/// All values are packed extension elements in CANONICAL coefficient form, the
/// convention everywhere else in `src/verifier/`. The transcript wants Montgomery;
/// that conversion belongs to the transcript layer (`SumcheckCore.toMontgomery`),
/// not here.
library WhirGadgets {
    /// The extension field one, packed.
    uint256 private constant ONE = uint256(1) << 224;

    /// Raised when a point and a value disagree about how many variables they have.
    error PointLengthMismatch(uint256 expected, uint256 actual);

    /// Raised when a constraint claims more variables than the run accumulated.
    error NotEnoughChallenges(uint256 numVariables, uint256 accumulated);

    /// `selectEval` was handed a domain point that is not a lifted base element.
    /// Every protocol caller uses `powConstBase`, which lifts; anything else
    /// means the caller broke the invariant.
    error NonBaseDomainPoint();

    /// One constraint's weight data: everything needed to evaluate its weight
    /// polynomial at a local folding point.
    ///
    /// Mirrors `ConstraintWeightData` in the reference recursion, which mirrors
    /// `p3_sumcheck::constraints::Constraint`. `eqPoints` is the OOD group and
    /// `selVars` the STIR group, in that order, because that is the order p3-whir
    /// builds them and the order fixes which power of `gamma` weights which term.
    struct ConstraintWeight {
        /// Multilinear arity of this constraint's polynomial.
        uint256 numVariables;
        /// The batching challenge, packed.
        uint256 gamma;
        /// Exponent of `gamma` weighting the first statement: 0 for the initial
        /// constraint, 1 for every round constraint.
        uint256 initialPower;
        /// OOD points, each `numVariables` coordinates. EMPTY when
        /// `eqCdBase` is set (production keeps the wire groups in calldata).
        uint256[][] eqPoints;
        /// Absolute calldata byte offset of the flat eq-point words, or 0 to
        /// read `eqPoints` from memory (derived groups, JSON-driven tests).
        uint256 eqCdBase;
        /// Group lengths over the flat calldata words when `eqCdBase` is set.
        uint256[] eqLens;
        /// STIR domain scalars, one per query, each lifted into the extension.
        uint256[] selVars;
        /// Mode 2 (WBND v5, D-086 step C): absolute calldata byte offset of
        /// the raw STATEMENT section, or 0 when the eq groups come from one of
        /// the sources above. The satellite derives every eq group value from
        /// the statement's opening points (public inputs) plus
        /// `virtualPoints`, instead of reading shipped coordinates.
        uint256 stmCdBase;
        /// Byte length of the statement slice at `stmCdBase`.
        uint256 stmLen;
        /// Which round of the statement section this constraint consumes
        /// (the satellite skips the preceding rounds itself).
        uint256 stmRound;
        /// Virtual-claim univariate points, drawn from the transcript.
        uint256[] virtualPoints;
        /// Mode 2 only: derived group descriptors, three words per group
        /// `[arity, zeta, selIndex]` in shipped group order (matrix groups in
        /// placement order, then the virtual block). The satellite's frame
        /// parse fills this once per frame from the statement section; the
        /// per-query walk below only evaluates. `selIndex` is the bit-reversed
        /// slot index, or `NO_SELECTOR` for virtual groups.
        uint256[] groupDescs;
    }

    /// `groupDescs` selector word marking "no selector bits" (virtual groups).
    uint256 internal constant NO_SELECTOR = type(uint256).max;

    /// Lift a univariate point to the `n`-dimensional multilinear point
    /// `[z^(2^(n-1)), ..., z^2, z]`.
    ///
    /// `n == 0` gives an empty point, which is the correct empty product for every
    /// consumer below - not one, and not a revert.
    function expandFromUnivariate(uint256 z, uint256 n)
        internal
        pure
        returns (uint256[] memory point)
    {
        point = new uint256[](n);
        uint256 cur = z;
        // Fill from the last coordinate backwards, so the last coordinate holds
        // z and each earlier one holds the next square.
        for (uint256 i = n; i > 0; --i) {
            point[i - 1] = cur;
            cur = KoalaBearExt4.square(cur);
        }
    }

    /// The equality polynomial `eq(p, q) = prod_i (1 + 2 p_i q_i - p_i - q_i)`.
    ///
    /// Delegates rather than reimplementing: `KoalaBearExt4.eq_poly_eval` is
    /// already the same algebraic identity `Point::eval_eq` uses, and it is
    /// parity-tested against Rust. Two copies of a formula that must agree is a
    /// maintenance trap; one tested copy is not.
    ///
    /// The empty product is one, which is what makes a zero-variable constraint
    /// evaluate to `gamma`-weighted constants instead of zero.
    function eqEval(uint256[] memory p_, uint256[] memory q)
        internal
        pure
        returns (uint256)
    {
        if (p_.length != q.length) {
            revert PointLengthMismatch(p_.length, q.length);
        }
        return KoalaBearExt4.eq_poly_eval(p_, q);
    }

    /// The selection weight `select(point, z) = prod_k (point[n-1-k] *
    /// (z^(2^k) - 1) + 1)`.
    ///
    /// This is the weight of a STIR claim: the opened row folded to one extension
    /// element is claimed to equal the codeword polynomial evaluated at the domain
    /// point `z`, and `select` is the polynomial that interpolates that statement
    /// over the hypercube. Per coordinate it is one when `z` is 1 and `1 - point_i`
    /// when `z` is 0, which is why it interpolates a claim about one domain point.
    ///
    /// `z` is a base field element in the protocol - a two-adic domain point - and
    /// is passed lifted. Lifting is exact: the canonical embedding is a ring
    /// homomorphism, so squaring in the extension agrees with squaring in the base
    /// and lifting afterwards.
    function selectEval(uint256[] memory point, uint256 z) internal pure returns (uint256) {
        // FAST PATH: z base-lifted. In the protocol z is always a two-adic
        // domain point lifted with fromBase (powConstBase), and powers of a
        // base-lifted element stay base-lifted - the canonical embedding is a
        // ring homomorphism - so every (v - ONE) is a SCALAR and each factor
        // costs four base multiplies instead of an ext sub, ext mul, ext add,
        // ext square and ext mul. The accumulator is carried unpacked in
        // registers (same pattern as KoalaBearExt4.eq_poly_eval): the packed
        // formulation re-shuffled lanes on every op for nothing.
        if (z & ((uint256(1) << 224) - 1) != 0) {
            // Unreachable in the protocol: every z is powConstBase (a lifted
            // two-adic domain point) and the pinned vectors agree. A non-base
            // z here means the caller broke that invariant; reverting beats
            // carrying a second implementation of the same product that no
            // vector exercises.
            revert NonBaseDomainPoint();
        }
        return selectEvalBase(point, z >> 224);
    }

    /// The equality weight of ONE derived group at `localR` (D-086 step C).
    ///
    /// A group is a univariate opening at `zeta` over `arity` stack variables,
    /// optionally pinned to one column slot by `nv = localR.length - arity`
    /// selector bits (`selIndex`, big-endian, bit-reversed slot index). The
    /// reference ships the group's coordinates - `c_i / (1 + c_i)` for
    /// `c_i = zeta^(2^(arity-1-i))` - and evaluates `eq(localR, coords)`.
    /// This derives the SAME value from `zeta` directly with ONE inversion:
    ///
    ///   eq(localR, coords) = prod_i (1 - r_i + r_i*c_i) / prod_i (1 + c_i)
    ///
    /// because `(1-p)(1-q) + p*q` with `q = c/(1+c)` collapses to
    /// `(1 - p + p*c) / (1 + c)`. Selector coordinates are 0/1, so their eq
    /// factors are just `1 - r` and `r`. The denominator is never zero: the
    /// opening point is out-of-domain, so no `1 + c_i` vanishes (the same
    /// guarantee `univariate_eq_point` asserts in Rust).
    function eqGroupValue(
        uint256[] memory localR,
        uint256 arity,
        uint256 zeta,
        uint256 selIndex
    ) internal pure returns (uint256) {
        uint256 nv = localR.length - arity;
        // Virtual groups (NO_SELECTOR): the transcript draw IS the expanded
        // point - coords[i] = zeta^(2^(arity-1-i)) with no bridge transform
        // (verified against the v4 ground-truth eq_points). Each eq factor
        // (1-p)(1-q)+p*q with q = c collapses to 1 - p - c + 2pc: a bare
        // product, no denominator, no inversion.
        if (selIndex == NO_SELECTOR) {
            uint256 raw = KoalaBearExt4.ONE;
            uint256 cc = zeta;
            for (uint256 i = arity; i > 0; --i) {
                uint256 rr = localR[i - 1];
                raw = KoalaBearExt4.mul(
                    raw,
                    KoalaBearExt4.add(
                        KoalaBearExt4.sub(KoalaBearExt4.sub(KoalaBearExt4.ONE, rr), cc),
                        KoalaBearExt4.mul(KoalaBearExt4.add(rr, rr), cc)
                    )
                );
                cc = KoalaBearExt4.square(cc);
            }
            return raw;
        }
        uint256 num = KoalaBearExt4.ONE;
        uint256 den = KoalaBearExt4.ONE;
        uint256 c = zeta;
        // localR[i] pairs with c_i = zeta^(2^(arity-1-i)): walking i downwards
        // from arity-1 starts at zeta^(2^0) and squares, same order as
        // expand_from_univariate fills from the back.
        for (uint256 i = arity; i > 0; --i) {
            uint256 r = localR[i - 1];
            // num *= (1 - r) + r*c ; den *= 1 + c
            num = KoalaBearExt4.mul(
                num,
                KoalaBearExt4.add(
                    KoalaBearExt4.sub(KoalaBearExt4.ONE, r), KoalaBearExt4.mul(r, c)
                )
            );
            den = KoalaBearExt4.mul(den, KoalaBearExt4.add(KoalaBearExt4.ONE, c));
            c = KoalaBearExt4.square(c);
        }
        // Selector bits, big-endian: bit (nv-1-j) of selIndex pins localR[arity+j].
        for (uint256 j; j < nv; ++j) {
            uint256 r = localR[arity + j];
            uint256 bit = (selIndex >> (nv - 1 - j)) & 1;
            num = KoalaBearExt4.mul(
                num, bit == 1 ? r : KoalaBearExt4.sub(KoalaBearExt4.ONE, r)
            );
        }
        return KoalaBearExt4.mul(num, KoalaBearExt4.inv(den));
    }

    /// `selectEval` with the base-lifted scalar `v0` (z = lift(v0)).
    ///
    /// Same product, same coordinate order (point[n-1] pairs with v^(2^0));
    /// pinned by the same vectors - the generator's `var` is base-lifted in
    /// every case, so this path is what the vectors actually exercise.
    function selectEvalBase(uint256[] memory point, uint256 v0)
        internal
        pure
        returns (uint256 acc)
    {
        uint256 len = point.length;
        unchecked {
            uint256 c0 = 1; // acc = ONE, unpacked
            uint256 c1 = 0;
            uint256 c2 = 0;
            uint256 c3 = 0;
            uint256 pp;
            assembly ("memory-safe") {
                pp := add(point, 0x20)
                let P := 0x7f000001
                let M := 0xffffffff
                let W := 3
                let v := v0
                for { let i := len } gt(i, 0) { i := sub(i, 1) } {
                    let pv := mload(add(pp, shl(5, sub(i, 1))))
                    let a0 := shr(224, pv)
                    let a1 := and(shr(192, pv), M)
                    let a2 := and(shr(160, pv), M)
                    let a3 := and(shr(128, pv), M)
                    // w = v - 1 (base field).
                    let w := sub(v, 1)
                    if iszero(v) { w := sub(P, 1) }
                    // term = point * w + ONE (scalar mul: +1 in lane 0 only).
                    // Unreduced: e < P^2 (~2^62) and the accumulator product
                    // stays under 10 P e (~2^97), so the four accumulator mods
                    // below are the only reductions this coordinate needs.
                    let e0 := add(mul(a0, w), 1)
                    let e1 := mul(a1, w)
                    let e2 := mul(a2, w)
                    let e3 := mul(a3, w)
                    // acc *= term.
                    let u0 := add(mul(c0, e0), mul(W, add(add(mul(c1, e3), mul(c2, e2)), mul(c3, e1))))
                    let u1 := add(add(mul(c0, e1), mul(c1, e0)), mul(W, add(mul(c2, e3), mul(c3, e2))))
                    let u2 := add(add(add(mul(c0, e2), mul(c1, e1)), mul(c2, e0)), mul(W, mul(c3, e3)))
                    let u3 := add(add(add(mul(c0, e3), mul(c1, e2)), mul(c2, e1)), mul(c3, e0))
                    c0 := mod(u0, P)
                    c1 := mod(u1, P)
                    c2 := mod(u2, P)
                    c3 := mod(u3, P)
                    // v <- v^2 (base field), skipped on the last pass.
                    if gt(i, 1) { v := mod(mul(v, v), P) }
                }
            }
            acc = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    /// `generator^index` lifted into the extension.
    ///
    /// The reference computes this as a product of precomputed constants, one per
    /// set bit of the index, because it is inside an arithmetic circuit where a
    /// per-bit multiply-add is cheaper than an exponentiation gate. Here the
    /// exponent is a plain `uint256` and `KoalaBear.pow` is a square-and-multiply
    /// loop over at most 32 bits, so the direct route is both cheaper and easier to
    /// see right. The vectors pin the VALUE, not the method, which is the only
    /// thing the protocol cares about.
    ///
    /// `generator` is a canonical base field element, not packed and not
    /// Montgomery. `index` is the query index the transcript sampled.
    function powConstBase(uint256 generator, uint256 index) internal pure returns (uint256) {
        return KoalaBearExt4.fromBase(KoalaBear.pow(generator, index));
    }

    /// `sum_i values[i] * base^i`, by Horner from the top.
    ///
    /// The batching primitive: WHIR folds many claims into one by weighting each
    /// with a successive power of a sampled challenge, so the prover cannot pick
    /// which claims cancel. The empty combination is ZERO, not one - a loop seeded
    /// with `ONE` instead of accumulating from the first element returns one for an
    /// empty input, and an empty group is a real case: a round with no OOD samples.
    function powersCombination(uint256[] memory values, uint256 base)
        internal
        pure
        returns (uint256)
    {
        uint256 acc = 0;
        for (uint256 i = values.length; i > 0; --i) {
            acc = KoalaBearExt4.add(KoalaBearExt4.mul(acc, base), values[i - 1]);
        }
        return acc;
    }

    /// One constraint's weight polynomial at `localR`.
    ///
    /// Equality terms take `gamma^0..`, selection terms `gamma^n_eq..`, and the
    /// whole sum is then shifted by `gamma^initialPower`. The shift is applied
    /// AFTER the combination, which is what makes it a single multiply rather than
    /// a re-seeded power sequence.
    function constraintWeight(
        uint256[] memory localR,
        ConstraintWeight memory c
    )
        internal
        pure
        returns (uint256 w)
    {
        // Horner directly over the two groups instead of materialising the
        // value array: powersCombination consumes values from the top down
        // (values[len-1] first), so walking the groups backwards computes the
        // identical sum with no allocation and no second pass. This runs once
        // per query per round, and the array was pure overhead.
        w = 0;
        uint256 gamma = c.gamma;
        for (uint256 i = c.selVars.length; i > 0; --i) {
            w = KoalaBearExt4.add(
                KoalaBearExt4.mul(w, gamma), selectEval(localR, c.selVars[i - 1])
            );
        }
        if (c.stmCdBase != 0) {
            // Mode 2 (D-086 step C): every eq group value is DERIVED from the
            // statement section (public opening points) and the transcript-
            // drawn virtual points - nothing proof-supplied. The descriptors
            // were built once per frame by the satellite's parse; this is the
            // same backwards Horner walk the other sources take.
            uint256[] memory d = c.groupDescs;
            for (uint256 i = d.length / 3; i > 0; --i) {
                uint256 b = (i - 1) * 3;
                w = KoalaBearExt4.add(
                    KoalaBearExt4.mul(w, gamma),
                    eqGroupValue(localR, d[b], d[b + 1], d[b + 2])
                );
            }
        } else if (c.eqCdBase == 0) {
            for (uint256 i = c.eqPoints.length; i > 0; --i) {
                w = KoalaBearExt4.add(
                    KoalaBearExt4.mul(w, gamma), eqEval(localR, c.eqPoints[i - 1])
                );
            }
        } else {
            // Wire groups stay in calldata: 773 KB decoded to memory and
            // ragged-copied only to be read once each, per round. Copy one
            // group into a reused scratch (padding-checked exactly as the old
            // _extArr decode did) and evaluate. Every group has exactly
            // localR.length coordinates - eqEval would revert otherwise.
            uint256 cdBase = c.eqCdBase;
            uint256[] memory lens = c.eqLens;
            uint256 off = 0;
            for (uint256 i; i < lens.length; ++i) { off += lens[i]; }
            uint256[] memory scratch = new uint256[](localR.length);
            for (uint256 i = lens.length; i > 0; --i) {
                uint256 len = lens[i - 1];
                off -= len;
                if (len != localR.length) { revert("LEN"); }
                assembly ("memory-safe") {
                    let src := add(cdBase, mul(off, 32))
                    let dst := add(scratch, 32)
                    let PAD := sub(shl(128, 1), 1)
                    for { let j := 0 } lt(j, len) { j := add(j, 1) } {
                        let x := calldataload(add(src, shl(5, j)))
                        if and(x, PAD) { mstore(0, 0) revert(0, 0) }
                        mstore(add(dst, shl(5, j)), x)
                    }
                }
                w = KoalaBearExt4.add(
                    KoalaBearExt4.mul(w, gamma), KoalaBearExt4.eq_poly_eval(localR, scratch)
                );
            }
        }
        // initialPower is 0 or 1 in this protocol; the loop keeps it general and
        // costs nothing when it is zero.
        for (uint256 s; s < c.initialPower; ++s) {
            w = KoalaBearExt4.mul(w, gamma);
        }
    }

    /// The batched constraint polynomial at the accumulated folding randomness.
    ///
    /// Each constraint sees only the LAST `k` of the `n` accumulated challenges,
    /// because the earlier ones were bound by earlier rounds and are already
    /// substituted into the claim. Under SUFFIX binding those `k` are reversed:
    /// suffix folding binds the highest variable first, so the challenge order is
    /// the reverse of the variable order a constraint reads.
    ///
    /// This is the last thing the verifier computes. The whole proof reduces to
    /// `claimed_eval == evalConstraintsPoly(...) * evalMultilinear(finalPoly,
    /// lastR)`, so an error here accepts or rejects every proof, always, and no
    /// transcript replay can see it: this consumes only challenges the transcript
    /// already produced correctly.
    function evalConstraintsPoly(
        uint256[] memory allR,
        ConstraintWeight[] memory constraints,
        bool isSuffix
    )
        internal
        pure
        returns (uint256)
    {
        uint256 n = allR.length;
        uint256 total = 0;
        for (uint256 i; i < constraints.length; ++i) {
            uint256 k = constraints[i].numVariables;
            if (k > n) {
                revert NotEnoughChallenges(k, n);
            }
            uint256[] memory localR = new uint256[](k);
            for (uint256 j; j < k; ++j) {
                // Prefix: all_r[n-k+j]. Suffix: the same slice, reversed.
                localR[j] = isSuffix ? allR[n - 1 - j] : allR[n - k + j];
            }
            total = KoalaBearExt4.add(total, constraintWeight(localR, constraints[i]));
        }
        return total;
    }
}
