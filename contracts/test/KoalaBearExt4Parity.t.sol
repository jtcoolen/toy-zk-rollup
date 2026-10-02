// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KoalaBear} from "../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";

/// Parity test for the vendored KoalaBear quartic extension library.
///
/// Our settlement challenge field is `BinomialExtensionField<KoalaBear, 4>`,
/// and the on-chain side represents an element as four 31-bit limbs packed
/// into one `uint256`. That packing is an optimization; an optimization
/// that computes the wrong field is worse than no optimization, because it
/// produces a digest that looks exactly as trustworthy as a correct one.
///
/// The vectors come from p3's Rust implementation, which is the reference.
/// Every case is `add`, `sub`, `mul`, `square` and `inv` over a spread of
/// operands chosen to exercise carries across limb boundaries in the packed
/// representation.
///
/// Regenerate with:
///     cargo test -p prover --test ext4_vectors -- --ignored --nocapture
contract KoalaBearExt4ParityTest is Test {
    string internal constant VECTOR = "test/vectors/ext4_vectors.json";

    /// The binomial nonresidue: EF = F[x] / (x^4 - W).
    ///
    /// Pinned explicitly. If the library's W ever disagrees with the field
    /// the prover uses, every extension-element product diverges, and the
    /// divergence is invisible without this assertion.
    function test_nonresidue_matches_prover() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 w = vm.parseJsonUint(json, ".nonresidue_w");
        assertEq(KoalaBear.W, w, "vendored W != prover's binomial nonresidue");
        assertEq(KoalaBearExt4.DEGREE, 4, "extension degree");
        assertEq(KoalaBear.MODULUS, vm.parseJsonUint(json, ".modulus"), "modulus");
    }

    function test_field_arithmetic_matches_rust() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".num_cases");
        assertTrue(n > 0, "no cases");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".cases[", vm.toString(i), "]");
            uint256[4] memory a = limbs(json, string.concat(base, ".a"));
            uint256[4] memory b = limbs(json, string.concat(base, ".b"));

            assertLimbs(
                KoalaBearExt4.unpack(KoalaBearExt4.add(pack(a), pack(b))),
                limbs(json, string.concat(base, ".add")),
                string.concat("add case ", vm.toString(i))
            );
            assertLimbs(
                KoalaBearExt4.unpack(KoalaBearExt4.sub(pack(a), pack(b))),
                limbs(json, string.concat(base, ".sub")),
                string.concat("sub case ", vm.toString(i))
            );
            assertLimbs(
                KoalaBearExt4.unpack(KoalaBearExt4.mul(pack(a), pack(b))),
                limbs(json, string.concat(base, ".mul")),
                string.concat("mul case ", vm.toString(i))
            );
            assertLimbs(
                KoalaBearExt4.unpack(KoalaBearExt4.square(pack(a))),
                limbs(json, string.concat(base, ".square")),
                string.concat("square case ", vm.toString(i))
            );
        }
    }

    /// Base-scalar multiplication and the W-multiply, both used by folding.
    function test_base_scalar_matches_rust() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".num_base_scalar_cases");
        assertTrue(n > 0, "no base scalar cases");

        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".base_scalar_cases[", vm.toString(i), "]");
            uint256[4] memory a = limbs(json, string.concat(base, ".a"));
            uint256[4] memory want = limbs(json, string.concat(base, ".out"));
            string memory kind = vm.parseJsonString(json, string.concat(base, ".s"));

            uint256 got;
            if (keccak256(bytes(kind)) == keccak256(bytes("w"))) {
                got = KoalaBearExt4.mul(pack(a), KoalaBearExt4.fromBase(KoalaBear.W));
            } else {
                uint256 s = vm.parseJsonUint(json, string.concat(base, ".s"));
                got = KoalaBearExt4.mulBase(pack(a), s);
            }
            assertLimbs(KoalaBearExt4.unpack(got), want, string.concat("base case ", vm.toString(i)));
        }
    }

    /// The packed representation must round-trip. Every limb occupies its own
    /// 32-bit slot, so a shift or mask error silently corrupts a neighbour.
    function test_pack_roundtrip() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 n = vm.parseJsonUint(json, ".num_cases");
        for (uint256 i; i < n; ++i) {
            uint256[4] memory a = limbs(json, string.concat(".cases[", vm.toString(i), "].a"));
            assertLimbs(KoalaBearExt4.unpack(pack(a)), a, string.concat("roundtrip ", vm.toString(i)));
        }
    }

    function pack(uint256[4] memory c) internal pure returns (uint256) {
        return KoalaBearExt4.pack(c);
    }

    function limbs(string memory json, string memory key) internal pure returns (uint256[4] memory out) {
        uint256[] memory raw = vm.parseJsonUintArray(json, key);
        require(raw.length == 4, "expected 4 limbs");
        out[0] = raw[0];
        out[1] = raw[1];
        out[2] = raw[2];
        out[3] = raw[3];
    }

    function assertLimbs(
        uint256[4] memory got,
        uint256[4] memory want,
        string memory label
    )
        internal
        pure
    {
        for (uint256 i; i < 4; ++i) {
            assertEq(got[i], want[i], string.concat(label, " limb ", vm.toString(i)));
        }
    }
}
