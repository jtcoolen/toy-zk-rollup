// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "./KoalaBear.sol";

library KoalaBearExt4 {
    uint256 internal constant DEGREE = 4;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant PACKED_MODULUS = (uint256(KoalaBear.MODULUS) << 224)
        | (uint256(KoalaBear.MODULUS) << 192) | (uint256(KoalaBear.MODULUS) << 160)
        | (uint256(KoalaBear.MODULUS) << 128);
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant DTH_ROOT = 2_113_994_754;

    error BaseScalarOutOfRange(uint256 value);

    function pack(uint256[4] memory coeffs) internal pure returns (uint256 packed) {
        unchecked {
            packed =
                (coeffs[0] << 224) | (coeffs[1] << 192) | (coeffs[2] << 160) | (coeffs[3] << 128);
        }
    }

    function unpack(uint256 packed) internal pure returns (uint256[4] memory coeffs) {
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let sum := add(a, b)

            // Each lane sum ∈ [0, 2M-2]; mod gives the canonical reduction.
            out := or(
                or(
                    shl(224, mod(shr(224, sum), modulus)),
                    shl(192, mod(and(shr(192, sum), mask), modulus))
                ),
                or(
                    shl(160, mod(and(shr(160, sum), mask), modulus)),
                    shl(128, mod(and(shr(128, sum), mask), modulus))
                )
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let tmp :=
                sub(add(a, 0x7f0000017f0000017f0000017f00000100000000000000000000000000000000), b)

            // Each lane ∈ [1, 2M-1]; mod gives the canonical reduction.
            out := or(
                or(
                    shl(224, mod(shr(224, tmp), modulus)),
                    shl(192, mod(and(shr(192, tmp), mask), modulus))
                ),
                or(
                    shl(160, mod(and(shr(160, tmp), mask), modulus)),
                    shl(128, mod(and(shr(128, tmp), mask), modulus))
                )
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return _mul_packed(a, b);
    }

    function square(uint256 a) internal pure returns (uint256) {
        return _squarePacked(a);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        if (value >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(value);
        }
        return value << 224;
    }

    function mulBase(uint256 a, uint256 scalar) internal pure returns (uint256) {
        if (scalar >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(scalar);
        }
        return _scalar_mul(a, scalar);
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");

        uint256 prodConj = _frobenius(a);
        for (uint256 i = 2; i < DEGREE; ++i) {
            prodConj = _frobenius(mul(prodConj, a));
        }

        uint256[4] memory lhs = unpack(a);
        uint256[4] memory rhs = unpack(prodConj);
        uint256 norm = _norm(lhs, rhs);

        return _scalar_mul(prodConj, KoalaBear.inv(norm));
    }

    function mul_by_w(uint256 a) internal pure returns (uint256) {
        return _scalar_mul(a, KoalaBear.W);
    }

    function extrapolate_012(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return _extrapolate012Fast(e0, e1, e2, r);
    }

    /// `prod_i (1 + 2 p_i q_i - p_i - q_i)` with the accumulator held in
    /// REGISTERS, not packed between coordinates.
    ///
    /// The packed-lane formulation (mul/add/sub per coordinate through the
    /// public ops) re-shuffles lanes - shifts, masks, mods - on every
    /// operation even though nothing crosses the pack boundary until the
    /// product is done. Measured on the real block proof this function is the
    /// single largest consumer (the terminal identity), and a microbench put
    /// the packed version at ~1.6k gas per coordinate against ~350 here:
    /// unpack p_i and q_i once, carry (c0..c3) in registers, reduce each lane
    /// exactly once per stage. Same algebra as `_mul_packed` (the W=3
    /// reduction x^4 = W), same result, pinned by the Ext4 parity suite and
    /// the whir_gadget vectors.
    ///
    /// Lane bounds: inputs are canonical (< p < 2^31), products < 2^62, sums
    /// of four products < 2^64, times W still < 2^66 - no wraparound, so each
    /// lane reduces exactly once per stage. The +3p in the term lanes keeps
    /// the subtraction positive before the mod (2pq < 2p and a + b < 2p).
    function eq_poly_eval(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 acc)
    {
        uint256 len = p.length;
        if (len != q.length) {
            revert("LEN");
        }
        unchecked {
            uint256 c0 = 1; // acc = ONE, unpacked
            uint256 c1 = 0;
            uint256 c2 = 0;
            uint256 c3 = 0;
            uint256 pp;
            uint256 qp;
            assembly ("memory-safe") {
                pp := add(p, 0x20)
                qp := add(q, 0x20)
                let P := 0x7f000001
                let M := 0xffffffff
                let W := 3
                for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                    let pv := mload(add(pp, shl(5, i)))
                    let qv := mload(add(qp, shl(5, i)))
                    let a0 := shr(224, pv)
                    let a1 := and(shr(192, pv), M)
                    let a2 := and(shr(160, pv), M)
                    let a3 := and(shr(128, pv), M)
                    let b0 := shr(224, qv)
                    let b1 := and(shr(192, qv), M)
                    let b2 := and(shr(160, qv), M)
                    let b3 := and(shr(128, qv), M)

                    // DEFERRED REDUCTION. `mod` distributes over the additions
                    // and the extension multiply is a sum of products, so the
                    // intermediate lanes only need to stay congruent mod P and
                    // small enough not to wrap 2^256. Worst case here: t < 10 P^2
                    // (~2^66), e < 21 P^2 (~2^67), u = c*e + 3*(3 terms) < 10 P*e
                    // (~2^101) - four orders of magnitude below the word limit.
                    // So the only reductions that survive are the four on the
                    // accumulator: twelve mod ops per coordinate collapse to four,
                    // bit-identical (parity-tested against the Rust Point::eval_eq
                    // through the pinned vectors).
                    let t0 := add(mul(a0, b0), mul(W, add(add(mul(a1, b3), mul(a2, b2)), mul(a3, b1))))
                    let t1 := add(add(mul(a0, b1), mul(a1, b0)), mul(W, add(mul(a2, b3), mul(a3, b2))))
                    let t2 := add(add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), mul(W, mul(a3, b3)))
                    let t3 := add(add(add(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0))

                    // term = 2pq + 1 - a - b (the +1 in lane 0 only), unreduced;
                    // the 3P bias keeps every lane non-negative before the mod.
                    let e0 := add(add(add(t0, t0), mul(3, P)), add(1, sub(sub(P, a0), b0)))
                    let e1 := add(add(add(t1, t1), mul(3, P)), add(sub(P, a1), sub(P, b1)))
                    let e2 := add(add(add(t2, t2), mul(3, P)), add(sub(P, a2), sub(P, b2)))
                    let e3 := add(add(add(t3, t3), mul(3, P)), add(sub(P, a3), sub(P, b3)))

                    // acc *= term.
                    let u0 := add(mul(c0, e0), mul(W, add(add(mul(c1, e3), mul(c2, e2)), mul(c3, e1))))
                    let u1 := add(add(mul(c0, e1), mul(c1, e0)), mul(W, add(mul(c2, e3), mul(c3, e2))))
                    let u2 := add(add(add(mul(c0, e2), mul(c1, e1)), mul(c2, e0)), mul(W, mul(c3, e3)))
                    let u3 := add(add(add(mul(c0, e3), mul(c1, e2)), mul(c2, e1)), mul(c3, e0))
                    c0 := mod(u0, P)
                    c1 := mod(u1, P)
                    c2 := mod(u2, P)
                    c3 := mod(u3, P)
                }
            }
            acc = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function evaluate_hypercube(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evals.length;
        require(size != 0 && _isPowerOfTwo(size), "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        if (point.length == 0) {
            return evals[0];
        }
        // dims 1 and 2 have no unrolled path: WHIR folds 4 dimensions per
        // round (rows of 16) and the closing sumcheck appends 3, so those
        // shapes never occur in this protocol. The general loop below folds
        // them correctly (in place - no caller reads evals after the fold);
        // unrolling them cost 4 inlined fold copies of EIP-170 margin for a
        // shape no vector exercises.
        // dims 3 (the closing sumcheck's 3 randomness) also takes the general
        // loop: 6 folds x ~100 gas of loop overhead, once per round - noise
        // next to the EIP-170 margin it returns. The loop mutates evals in
        // place; the final phase reads finalPoly one last time here.
        if (point.length == 4) {
            uint256 l0 = _fold_once(evals[0], evals[8], point[0]);
            uint256 l1 = _fold_once(evals[1], evals[9], point[0]);
            uint256 l2 = _fold_once(evals[2], evals[10], point[0]);
            uint256 l3 = _fold_once(evals[3], evals[11], point[0]);
            uint256 l4 = _fold_once(evals[4], evals[12], point[0]);
            uint256 l5 = _fold_once(evals[5], evals[13], point[0]);
            uint256 l6 = _fold_once(evals[6], evals[14], point[0]);
            uint256 l7 = _fold_once(evals[7], evals[15], point[0]);
            uint256 m0 = _fold_once(l0, l4, point[1]);
            uint256 m1 = _fold_once(l1, l5, point[1]);
            uint256 m2 = _fold_once(l2, l6, point[1]);
            uint256 m3 = _fold_once(l3, l7, point[1]);
            uint256 n0 = _fold_once(m0, m2, point[2]);
            uint256 n1 = _fold_once(m1, m3, point[2]);
            return _fold_once(n0, n1, point[3]);
        }

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _fold_once(evals[j], evals[j + size], point[i]);
                }
            }
        }

        return evals[0];
    }

    function _fold_once(uint256 a0, uint256 a1, uint256 r) internal pure returns (uint256 out) {
        // out = a0 + r * (a1 - a0), fused: unpack the three operands once and
        // carry the difference through the extension multiply without the
        // intermediate pack/reduce cycles of sub(); mul(); add(). The
        // difference lanes are kept unreduced in [1, 2P) by pre-adding P -
        // the extension multiply reduces every lane mod P anyway, and the
        // final add reduces again, so the result is bit-identical to the
        // three-call formulation (same formulas as eq_poly_eval).
        assembly ("memory-safe") {
            let P := 0x7f000001
            let M := 0xffffffff
            let W := 3
            let x0 := shr(224, a0)
            let x1 := and(shr(192, a0), M)
            let x2 := and(shr(160, a0), M)
            let x3 := and(shr(128, a0), M)
            let d0 := add(sub(shr(224, a1), x0), P)
            let d1 := add(sub(and(shr(192, a1), M), x1), P)
            let d2 := add(sub(and(shr(160, a1), M), x2), P)
            let d3 := add(sub(and(shr(128, a1), M), x3), P)
            let c0 := shr(224, r)
            let c1 := and(shr(192, r), M)
            let c2 := and(shr(160, r), M)
            let c3 := and(shr(128, r), M)

            let t0 := add(mul(c0, d0), mul(W, add(add(mul(c1, d3), mul(c2, d2)), mul(c3, d1))))
            let t1 := add(add(mul(c0, d1), mul(c1, d0)), mul(W, add(mul(c2, d3), mul(c3, d2))))
            let t2 := add(add(add(mul(c0, d2), mul(c1, d1)), mul(c2, d0)), mul(W, mul(c3, d3)))
            let t3 := add(add(add(mul(c0, d3), mul(c1, d2)), mul(c2, d1)), mul(c3, d0))
            t0 := mod(t0, P)
            t1 := mod(t1, P)
            t2 := mod(t2, P)
            t3 := mod(t3, P)

            out :=
                or(
                    or(shl(224, mod(add(x0, t0), P)), shl(192, mod(add(x1, t1), P))),
                    or(shl(160, mod(add(x2, t2), P)), shl(128, mod(add(x3, t3), P)))
                )
        }
    }

    /// Scalar multiplication lane-by-lane, WITHOUT a memory array.
    ///
    /// The obvious implementation unpacks into a `uint256[4] memory`, scales,
    /// and repacks; the allocation alone measured ~1,465 gas per call
    /// (`FieldMicroBench`), and `eq_poly_eval` calls this once per coordinate
    /// of every eq point, so it sat on the identity's hot path. Shifting lanes
    /// through registers instead keeps the same semantics (each lane is a
    /// canonical base element, `KoalaBear.mul` reduces) at a fraction of the
    /// cost.
    function _scalar_mul(uint256 a, uint256 scalar) internal pure returns (uint256 out) {
        unchecked {
            uint256 m = COEFF_MASK;
            uint256 c0 = KoalaBear.mul(a >> 224, scalar);
            uint256 c1 = KoalaBear.mul((a >> 192) & m, scalar);
            uint256 c2 = KoalaBear.mul((a >> 160) & m, scalar);
            uint256 c3 = KoalaBear.mul((a >> 128) & m, scalar);
            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _frobenius(uint256 a) internal pure returns (uint256) {
        return _repeated_frobenius(a, 1);
    }

    function _repeated_frobenius(uint256 a, uint256 count) internal pure returns (uint256) {
        uint256 power = count % DEGREE;
        if (power == 0) {
            return a;
        }

        uint256 z = KoalaBear.pow(DTH_ROOT, power);
        uint256 running = 1;
        uint256[4] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], running);
                running = KoalaBear.mul(running, z);
            }
        }

        return pack(coeffs);
    }

    function _norm(uint256[4] memory a, uint256[4] memory b) internal pure returns (uint256) {
        uint256 wCoeff;

        unchecked {
            for (uint256 i = 1; i < DEGREE; ++i) {
                wCoeff = KoalaBear.add(wCoeff, KoalaBear.mul(a[i], b[DEGREE - i]));
            }
        }

        return KoalaBear.add(KoalaBear.mul(a[0], b[0]), KoalaBear.mul(KoalaBear.W, wCoeff));
    }

    function _mul_packed(uint256 a, uint256 b) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;
        uint256 b0 = b >> 224;
        uint256 b1 = (b >> 192) & COEFF_MASK;
        uint256 b2 = (b >> 160) & COEFF_MASK;
        uint256 b3 = (b >> 128) & COEFF_MASK;

        unchecked {
            uint256 c0 = a0 * b0 + KoalaBear.W * (a1 * b3 + a2 * b2 + a3 * b1);
            uint256 c1 = a0 * b1 + a1 * b0 + KoalaBear.W * (a2 * b3 + a3 * b2);
            uint256 c2 = a0 * b2 + a1 * b1 + a2 * b0 + KoalaBear.W * (a3 * b3);
            uint256 c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _squarePacked(uint256 a) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;

        unchecked {
            uint256 a0a0 = a0 * a0;
            uint256 a0a1 = a0 * a1;
            uint256 a0a2 = a0 * a2;
            uint256 a0a3 = a0 * a3;
            uint256 a1a1 = a1 * a1;
            uint256 a1a2 = a1 * a2;
            uint256 a1a3 = a1 * a3;
            uint256 a2a2 = a2 * a2;
            uint256 a2a3 = a2 * a3;
            uint256 a3a3 = a3 * a3;

            uint256 c0 = a0a0 + KoalaBear.W * (a2a2 + (2 * a1a3));
            uint256 c1 = (2 * a0a1) + KoalaBear.W * (2 * a2a3);
            uint256 c2 = (2 * a0a2) + a1a1 + KoalaBear.W * a3a3;
            uint256 c3 = (2 * a0a3) + (2 * a1a2);

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }


    function _extrapolate012Fast(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 q1Packed;
        uint256 q2Packed;

        // Branchless q1/q2 computation using constant biases.
        // q2 = (c0 + c2 - 2*c1) / 2 mod M  →  mulmod(c0+c2+2M - 2*c1, invTwo, M)
        // q1 = (4*c1 - c2 - 3*c0) / 2 mod M →  mulmod(4*c1+4M - c2 - 3*c0, invTwo, M)
        // The constant biases (2M, 4M) prevent underflow:
        //   q2 arg ∈ [2, 4M-2], q1 arg ∈ [4, 8M-4]. mulmod handles these.
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff
            let invTwo := 1065353217
            let twoM := 0xfe000002 // 2 * M
            let fourM := 0x1fc000004 // 4 * M

            // --- Lane 0 (bits 224-255) ---
            let c0 := shr(224, e0)
            let c1 := shr(224, e1)
            let c2 := shr(224, e2)

            q2Packed := shl(224, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            q1Packed := shl(
                224,
                mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M)
            )

            // --- Lane 1 (bits 192-223) ---
            c0 := and(shr(192, e0), mask)
            c1 := and(shr(192, e1), mask)
            c2 := and(shr(192, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(192, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(192, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            // --- Lane 2 (bits 160-191) ---
            c0 := and(shr(160, e0), mask)
            c1 := and(shr(160, e1), mask)
            c2 := and(shr(160, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(160, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(160, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            // --- Lane 3 (bits 128-159) ---
            c0 := and(shr(128, e0), mask)
            c1 := and(shr(128, e1), mask)
            c2 := and(shr(128, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(128, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(128, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )
        }

        return add(e0, mul(r, add(q1Packed, mul(r, q2Packed))));
    }

    function _isPowerOfTwo(uint256 x) internal pure returns (bool) {
        return x & (x - 1) == 0;
    }
}
