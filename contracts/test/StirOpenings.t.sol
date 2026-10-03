// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, stdJson} from "forge-std/Test.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {StarkMerkle} from "../src/verifier/StarkMerkle.sol";
import {StirOpenings} from "../src/verifier/StirOpenings.sol";

/// External shims over the library internal functions.
///
/// `vm.expectRevert` only observes a revert at a LOWER call depth than the
/// cheatcode call, and a direct library call inlines to nothing, so a revert in
/// `extLeaf` would unwind through the test frame and be reported as "call
/// didn't revert at a lower depth". These wrappers give the revert somewhere to
/// come from. They are not production surface: the library is `internal`
/// precisely so nothing deploys it.
contract StirOpeningsHarness {
    function extLeaf(uint256[] calldata limbs) external pure returns (bytes32) {
        return StirOpenings.extLeaf(limbs);
    }

    function foldRow(uint256[] calldata row, uint256[] calldata randomness)
        external
        pure
        returns (uint256)
    {
        return StirOpenings.foldRow(row, randomness);
    }

    function openAndFold(
        bytes32 root,
        uint256 index,
        uint256 depth,
        uint256[] calldata limbs,
        uint256[] calldata row,
        bytes32[] calldata siblings,
        uint256[] calldata randomness
    ) external pure returns (uint256) {
        return StirOpenings.openAndFold(root, index, depth, limbs, row, siblings, randomness);
    }
}

/// STIR openings replayed against vectors from the real settlement MMCS.
///
/// Vectors come from `crates/prover/tests/stir_vectors.rs`, which commits
/// through `ExtensionMmcs<KoalaBear, BinomialExtensionField<KoalaBear,4>,
/// MerkleTreeMmcs<Keccak256>>` - the scheme `prover::config::Mmcs` builds -
/// opens it with the prover own multiproof, and recovers one full path per query
/// with `restore_and_recompute_paths`. The expected values are therefore the
/// prover output, not a second implementation of the same idea.
///
/// Each query asserts four independent things, because one end-to-end "verify
/// returns true" would hide which of them broke:
///   1. the leaf digest, where the extension-row encoding lives;
///   2. the path, against the committed root at the right depth;
///   3. the fold, where the multilinear basis lives;
///   4. the domain point and the final-phase Horner value.
///
/// The vector file carries explicit `num_*` counts. forge JSON selectors have no
/// array-length operator, and a `.length` path fails with "must return exactly
/// one JSON value" - which reads like a malformed file rather than an unsupported
/// selector, so it is a bad way to discover the limit.
contract StirOpeningsTest is Test {
    using stdJson for string;

    string internal constant VECTOR = "test/vectors/stir_vectors.json";

    StirOpeningsHarness internal harness = new StirOpeningsHarness();

    /// One extension element: four canonical coefficients, low order first.
    function extAt(string memory json, string memory path) internal pure returns (uint256) {
        uint256[] memory coeffs = json.readUintArray(path);
        require(coeffs.length == 4, "extension element must have 4 coefficients");
        return StirOpenings.ext4([coeffs[0], coeffs[1], coeffs[2], coeffs[3]]);
    }

    /// An array of `n` extension elements packed in order.
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

    /// The flattened row: every element coefficients concatenated, low order
    /// first. This is the shape `ExtensionMmcs` hashes.
    function flatRow(string memory json, string memory path, uint256 n)
        internal
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](n * 4);
        for (uint256 i; i < n; ++i) {
            uint256[] memory coeffs =
                json.readUintArray(string.concat(path, "[", vm.toString(i), "]"));
            require(coeffs.length == 4, "extension element must have 4 coefficients");
            for (uint256 k; k < 4; ++k) {
                out[i * 4 + k] = coeffs[k];
            }
        }
    }

    /// The vectors describe three cases, and the count is asserted rather than
    /// assumed so a regenerated file with fewer cases fails here instead of
    /// quietly testing less.
    function test_vector_file_has_the_expected_shape() public view {
        string memory json = vm.readFile(VECTOR);
        assertEq(json.readUint(".num_cases"), 3, "case count");
        assertEq(json.readUint(".cases[0].width_ext"), 16, "row width");
        assertEq(json.readUint(".cases[0].width_base"), 64, "flattened width");
        assertEq(json.readUint(".cases[0].depth"), 6, "depth");
        assertEq(json.readUint(".cases[0].num_queries"), 3, "query count");
        // The leaf rule is recorded in the file, so a reader who finds the
        // vectors without finding this test still learns what they pin.
        assertEq(
            json.readString(".leaf_rule"),
            "keccak256(concat of width_base 4-byte little-endian to_unique_u32 limbs, no prefix)",
            "leaf rule drifted from what the contract implements"
        );
    }

    /// Everything one case contributes to its queries, held in memory rather
    /// than in locals. The per-query assertion set needs a dozen values; kept as
    /// loop locals the IR runs off the end of the stack, and the resulting
    /// "Variable ... is 1 too deep" names none of the culprits.
    struct Ctx {
        string json;
        string ck;
        string base;
        string label;
        bytes32 root;
        uint256 depth;
        uint256 widthExt;
        uint256 widthBase;
        uint256 generator;
        uint256[] randomness;
        uint256[] finalPoly;
    }

    /// Every query in every case: leaf, path, fold, domain point, Horner.
    function test_replays_every_stir_opening() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 cases = json.readUint(".num_cases");
        for (uint256 ci; ci < cases; ++ci) {
            checkCase(ci);
        }
    }

    /// Load one case and walk its queries.
    function checkCase(uint256 ci) private view {
        string memory json = vm.readFile(VECTOR);
        Ctx memory c;
        c.json = json;
        c.ck = string.concat(".cases[", vm.toString(ci), "]");
        c.root = json.readBytes32(string.concat(c.ck, ".root_hex"));
        c.depth = json.readUint(string.concat(c.ck, ".depth"));
        c.widthExt = json.readUint(string.concat(c.ck, ".width_ext"));
        c.widthBase = json.readUint(string.concat(c.ck, ".width_base"));
        c.generator = json.readUint(string.concat(c.ck, ".domain_generator"));
        c.randomness = extArray(
            json,
            string.concat(c.ck, ".randomness"),
            json.readUint(string.concat(c.ck, ".num_randomness"))
        );
        c.finalPoly = extArray(
            json,
            string.concat(c.ck, ".final_poly"),
            json.readUint(string.concat(c.ck, ".num_final_poly"))
        );

        uint256 queries = json.readUint(string.concat(c.ck, ".num_queries"));
        for (uint256 q; q < queries; ++q) {
            c.base = string.concat(c.ck, ".queries[", vm.toString(q), "]");
            c.label = string.concat("case ", vm.toString(ci), " q", vm.toString(q));
            checkQuery(c, q);
        }
    }

    function checkQuery(Ctx memory c, uint256 q) private pure {
        uint256 index = c.json.readUint(string.concat(c.base, ".index"));
        uint256[] memory limbs = flatRow(c.json, string.concat(c.base, ".row_ext"), c.widthExt);
        assertEq(limbs.length, c.widthBase, "flattened row width");
        checkLeaf(c, limbs);
        checkPath(c, index, limbs);
        checkFold(c, limbs);
        checkDomainPoint(c, index, q);
    }

    /// 1. The leaf. This is where the extension-row encoding lives: 64
    /// wire-form limbs, 256 bytes, no prefix.
    function checkLeaf(Ctx memory c, uint256[] memory limbs) private pure {
        assertEq(
            StirOpenings.extLeaf(limbs),
            c.json.readBytes32(string.concat(c.base, ".leaf_hex")),
            string.concat("leaf differs at ", c.label)
        );
    }

    /// 2. The path authenticates that leaf at that index and depth.
    function checkPath(Ctx memory c, uint256 index, uint256[] memory limbs) private pure {
        bytes32[] memory siblings = c.json.readBytes32Array(string.concat(c.base, ".siblings_hex"));
        assertEq(siblings.length, c.depth, "path depth");
        assertEq(
            c.json.readUint(string.concat(c.base, ".num_siblings")),
            c.depth,
            "vector depth disagrees with itself"
        );
        assertTrue(
            StarkMerkle.verify(c.root, index, StirOpenings.extLeaf(limbs), siblings, c.depth),
            string.concat("path rejected at ", c.label)
        );
    }

    /// 3. The fold, at the round folding randomness. The row is re-derived from
    /// the same flattened limbs the leaf was hashed from, so a fold that agreed
    /// with a row the leaf did not commit to would be caught by 1 and 2 first.
    function checkFold(Ctx memory c, uint256[] memory limbs) private pure {
        uint256[] memory row = packRow(limbs);
        assertEq(row.length, c.widthExt, "row width");
        assertExtEq(
            StirOpenings.foldRow(row, c.randomness),
            c.json.readUintArray(string.concat(c.base, ".fold")),
            string.concat("fold at ", c.label)
        );
    }

    /// 4. The domain point g^index and the final-phase Horner value at it.
    /// Emitted independently of the fold on purpose: their equality is the WHIR
    /// identity and belongs to the end-to-end proof test, not to a Merkle
    /// vector file.
    function checkDomainPoint(Ctx memory c, uint256 index, uint256 q) private pure {
        uint256 point = StirOpenings.domainPoint(c.generator, index);
        assertExtEq(
            point,
            c.json.readUintArray(string.concat(c.base, ".domain_point")),
            string.concat("domain point at ", c.label)
        );
        assertExtEq(
            StirOpenings.horner(c.finalPoly, point),
            c.json.readUintArray(string.concat(c.ck, ".horner[", vm.toString(q), "]")),
            string.concat("horner at ", c.label)
        );
    }

    /// Re-pack flattened canonical limbs into extension elements, four at a
    /// time. The inverse of `flatRow`, and asserted as such below.
    function packRow(uint256[] memory limbs) internal pure returns (uint256[] memory row) {
        require(limbs.length % 4 == 0, "flattened row must be a multiple of 4 limbs");
        row = new uint256[](limbs.length / 4);
        for (uint256 i; i < row.length; ++i) {
            row[i] = StirOpenings.ext4(
                [limbs[i * 4], limbs[i * 4 + 1], limbs[i * 4 + 2], limbs[i * 4 + 3]]
            );
        }
    }

    function assertExtEq(uint256 packed, uint256[] memory want, string memory label) internal pure {
        require(want.length == 4, "expected 4 coefficients");
        uint256[4] memory got = KoalaBearExt4.unpack(packed);
        for (uint256 k; k < 4; ++k) {
            assertEq(got[k], want[k], string.concat(label, " coefficient ", vm.toString(k)));
        }
    }

    /// flatRow and packRow are inverses. Cheap, and it means the row the fold
    /// consumes is provably the row the leaf hashed rather than a parallel read
    /// that could drift.
    function test_row_flatten_and_pack_round_trip() public view {
        string memory json = vm.readFile(VECTOR);
        string memory base = ".cases[0].queries[0]";
        uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), 16);
        uint256[] memory packed = packRow(limbs);
        assertEq(packed.length, 16, "packed width");
        assertEq(packed[0], extAt(json, string.concat(base, ".row_ext[0]")), "element 0");
        assertEq(packed[15], extAt(json, string.concat(base, ".row_ext[15]")), "element 15");
        assertEq(flatRow(json, string.concat(base, ".row_ext"), 16).length, 64, "flat width");
    }

    /// The combined entry point does authentication and folding in one call.
    function test_open_and_fold_matches_the_parts() public view {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256 widthExt = json.readUint(string.concat(ck, ".width_ext"));
        uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), widthExt);
        uint256[] memory row = extArray(json, string.concat(base, ".row_ext"), widthExt);
        bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
        uint256[] memory randomness = extArray(json, string.concat(ck, ".randomness"), 4);

        uint256 combined = StirOpenings.openAndFold(
            json.readBytes32(string.concat(ck, ".root_hex")),
            json.readUint(string.concat(base, ".index")),
            json.readUint(string.concat(ck, ".depth")),
            limbs,
            row,
            siblings,
            randomness
        );
        assertEq(combined, StirOpenings.foldRow(row, randomness), "combined differs");
    }

    /// A canonical limb must NOT hash to the prover leaf.
    ///
    /// The negative half of the encoding claim. Without it a reader cannot tell
    /// whether `extLeaf` converts because it must or because it happens to, and
    /// the Montgomery discussion in the library header is unfalsifiable. Both
    /// digests are 32 valid bytes, which is exactly why the positive test alone
    /// is not enough.
    function test_canonical_limbs_hash_differently() public view {
        string memory json = vm.readFile(VECTOR);
        string memory base = ".cases[0].queries[0]";
        uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), 16);
        bytes32 expected = json.readBytes32(string.concat(base, ".leaf_hex"));

        bytes32 raw = StarkMerkle.leafFromLimbs(limbs);
        assertTrue(raw != expected, "canonical limbs must not reproduce the prover leaf");
        assertEq(StirOpenings.extLeaf(limbs), expected, "wire limbs must reproduce it");
    }

    /// One flipped limb changes the leaf, so the path check rejects. A leaf
    /// function with a collision or a silent truncation would let this through.
    function test_tampered_row_is_rejected() public {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256 index = json.readUint(string.concat(base, ".index"));
        uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), 16);
        uint256[] memory row = extArray(json, string.concat(base, ".row_ext"), 16);
        bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
        uint256[] memory randomness = extArray(json, string.concat(ck, ".randomness"), 4);

        limbs[0] = limbs[0] + 1;
        vm.expectRevert(
            abi.encodeWithSelector(StirOpenings.OpeningNotAuthenticated.selector, index)
        );
        harness.openAndFold(
            json.readBytes32(string.concat(ck, ".root_hex")),
            index,
            json.readUint(string.concat(ck, ".depth")),
            limbs,
            row,
            siblings,
            randomness
        );
    }

    /// A truncated path is a second-preimage attempt, not an opening: a shorter
    /// path can reach a trusted root through a subtree. Depth is part of the
    /// check, not an optimisation.
    function test_truncated_path_is_rejected() public {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256 index = json.readUint(string.concat(base, ".index"));
        uint256 depth = json.readUint(string.concat(ck, ".depth"));
        uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), 16);
        uint256[] memory row = extArray(json, string.concat(base, ".row_ext"), 16);
        bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
        uint256[] memory randomness = extArray(json, string.concat(ck, ".randomness"), 4);

        bytes32[] memory shortPath = new bytes32[](depth - 1);
        for (uint256 i; i < shortPath.length; ++i) {
            shortPath[i] = siblings[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(StirOpenings.OpeningNotAuthenticated.selector, index)
        );
        harness.openAndFold(
            json.readBytes32(string.concat(ck, ".root_hex")),
            index,
            depth,
            limbs,
            row,
            shortPath,
            randomness
        );
    }

    /// A row whose width is not `1 << randomness.length` cannot be folded: the
    /// multilinear reading would silently drop elements and still return a value.
    function test_wrong_row_width_reverts() public {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[0]";
        string memory base = string.concat(ck, ".queries[0]");
        uint256[] memory row = extArray(json, string.concat(base, ".row_ext"), 16);
        uint256[] memory randomness = extArray(json, string.concat(ck, ".randomness"), 4);

        uint256[] memory shortRow = new uint256[](row.length - 1);
        for (uint256 i; i < shortRow.length; ++i) {
            shortRow[i] = row[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(
                StirOpenings.RowWidthMismatch.selector, row.length, row.length - 1
            )
        );
        harness.foldRow(shortRow, randomness);
    }

    /// A limb at or above the modulus is not a field element. Accepting one
    /// would hash bytes no honest prover produced, and the failure would surface
    /// as an unrelated path rejection.
    function test_limb_at_the_modulus_reverts() public {
        uint256[] memory limbs = new uint256[](4);
        limbs[0] = 0x7f00_0001;
        vm.expectRevert(abi.encodeWithSelector(StirOpenings.LimbOutOfRange.selector, 0x7f00_0001));
        harness.extLeaf(limbs);
    }

    /// The duplicate-index case: two queries at one index share a path prefix, so
    /// the prover pruned their siblings into one. Each restored per-query path
    /// must still be complete and self-sufficient, which is the property the
    /// per-query verification model depends on.
    function test_duplicate_index_queries_both_verify() public view {
        string memory json = vm.readFile(VECTOR);
        string memory ck = ".cases[2]";
        uint256 depth = json.readUint(string.concat(ck, ".depth"));
        bytes32 root = json.readBytes32(string.concat(ck, ".root_hex"));
        uint256 i0 = json.readUint(string.concat(ck, ".queries[0].index"));
        uint256 i1 = json.readUint(string.concat(ck, ".queries[1].index"));
        assertEq(i0, i1, "case 2 is the duplicate-index case");

        bytes32[] memory firstPath;
        for (uint256 q; q < 2; ++q) {
            string memory base = string.concat(ck, ".queries[", vm.toString(q), "]");
            uint256[] memory limbs = flatRow(json, string.concat(base, ".row_ext"), 16);
            bytes32[] memory siblings = json.readBytes32Array(string.concat(base, ".siblings_hex"));
            bytes32 opened = StirOpenings.extLeaf(limbs);
            assertEq(
                opened,
                json.readBytes32(string.concat(base, ".leaf_hex")),
                string.concat("duplicate leaf q", vm.toString(q))
            );
            assertTrue(
                StarkMerkle.verify(root, i0, opened, siblings, depth),
                string.concat("duplicate path q", vm.toString(q), " rejected")
            );
            if (q == 0) {
                firstPath = siblings;
            } else {
                // Two queries at one index open the same row, so each restored
                // path must be that same full path. If they ever differ the
                // restore walk changed shape and the per-query model needs
                // re-examining before anything else does.
                for (uint256 k; k < firstPath.length; ++k) {
                    assertEq(
                        siblings[k],
                        firstPath[k],
                        string.concat("duplicate paths diverge at level ", vm.toString(k))
                    );
                }
            }
        }
    }
}
