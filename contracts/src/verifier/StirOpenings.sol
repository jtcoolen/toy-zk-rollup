// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBear} from "../../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {StarkMerkle} from "./StarkMerkle.sol";

/// The STIR opening layer: turn an opened row into one claimed extension
/// element, authenticated against a commitment the transcript already bound.
///
/// WHAT A STIR OPENING IS
///
/// A WHIR round commits to a codeword as a Merkle tree whose rows are
/// `1 << folding_factor` extension elements. To open it the prover reveals a
/// row at a transcript-chosen index, plus its authentication path. The
/// verifier cannot use a row directly: the rest of the protocol works with one
/// extension element per query. So it folds the row - reads it as a multilinear
/// polynomial over `folding_factor` variables and evaluates it at the folding
/// randomness the previous sumcheck produced. That fold is the opening claim:
/// "the committed codeword, folded at r, takes this value at this domain point".
///
/// Three things can go wrong and each has its own check here:
///
/// - the row is not the row the commitment holds  -> `verifyOpening`
/// - the fold is computed against the wrong basis  -> `foldRow`
/// - the row is read as base elements when it is extension, or the reverse
///                                                  -> `extLeaf`
///
/// THE LEAF IS THE DANGEROUS ONE
///
/// Round 0 opens a BASE-field tree. Every later round opens an `ExtensionMmcs`,
/// which is not a different tree: it is the same tree over a different row type,
/// where each extension element is reinterpreted as DIMENSION base limbs
/// (`ExtensionMmcs::verify_multi_batch` calls `flatten_to_base` and widens the
/// dimensions by DIMENSION). So a 16-element extension row is a 64-limb row,
/// and its leaf is `keccak256` over 256 bytes, not 64.
///
/// Those bytes are the little-endian MONTGOMERY form of each limb, because the
/// inner tree hashes `RawDataSerializable::into_byte_stream`, which is
/// `to_unique_u32` - the same wire form the transcript absorbs. A verifier that
/// hashed canonical limbs produces a perfectly valid 32-byte digest that simply
/// is not the prover leaf, and nothing downstream notices: the path check fails
/// with no hint that the encoding rather than the data was wrong. Hence
/// `extLeaf` takes canonical limbs and converts, so the conversion cannot be
/// forgotten by a caller, and `StirOpeningsTest` pins the leaf against the
/// prover bytes.
///
/// THE FOLD BASIS
///
/// `KoalaBearExt4.evaluate_hypercube` folds `point[0]` across the HALF-SIZE
/// stride, i.e. against the most significant bit of the row index, then works
/// down. p3 `eval_multilinear_recursive` consumes its point from the other end
/// syntactically but lands in the same place: its `x0` is the coefficient of the
/// top half, so `x[i]` and `point[i]` bind the same bit. Verified against
/// `Poly::eval_ext` over the generated vectors rather than by reading alone,
/// because "reads the same" is exactly the argument that was wrong about
/// `extrapolate_012` (D-048).
///
/// WHY PER-QUERY PATHS
///
/// p3 amortises openings across queries with a shared pruned frontier. This
/// verifies each query path on its own, which repeats the hashes two paths
/// share. That is a deliberate first version: it bounds one query's work by a
/// constant, which is what lets D-039 split a chunk across transactions, and
/// the amortised walk is a local swap with the same contract - same root, fewer
/// hashes. Ground truth for every value here is
/// `crates/prover/tests/stir_vectors.rs`.
library StirOpenings {
    /// KoalaBear modulus.
    uint256 private constant P = 0x7f00_0001;

    /// Montgomery radix R = 2^32 mod p, the wire form multiplier.
    ///
    /// Not 2^31: off by a factor of two and every result is still a field
    /// element, which is the failure mode with the least diagnostic value.
    uint256 private constant MONTGOMERY_R = 0x01ff_fffe;

    /// A row is not the same width as a claim, and a proof that swaps them is
    /// the attack this constant exists to catch.
    error RowWidthMismatch(uint256 expected, uint256 actual);

    /// The path did not reproduce the commitment.
    error OpeningNotAuthenticated(uint256 index);

    /// A limb reached the wire-form encoder from outside the field.
    error LimbOutOfRange(uint256 value);

    /// Canonical to wire form, the byte sequence the prover hashes and absorbs.
    function toWire(uint256 canonical) internal pure returns (uint256) {
        if (canonical >= P) {
            revert LimbOutOfRange(canonical);
        }
        return (canonical * MONTGOMERY_R) % P;
    }

    /// Leaf digest of one extension-field row given as canonical base limbs.
    ///
    /// `limbs` is the row flattened: `width_ext * 4` values, coefficient order
    /// low-to-high within each element. The limbs are converted to wire form
    /// here rather than taken already converted so that the encoding cannot be
    /// skipped; `StarkMerkle.leafFromLimbs` writes what it is handed, so a
    /// caller that passed canonical limbs would get a wrong leaf silently.
    ///
    /// The conversion and the byte encoding happen in one pass into the final
    /// buffer. The obvious version - map to wire form into a `uint256[]`, then
    /// hand it to `StarkMerkle.leafFromLimbs` - measured 40.8k gas per leaf against
    /// 22.3k here, because it allocates and zeroes a 3.2 KB intermediate array and
    /// reads it back (`StirOpeningsGasTest` brackets both). One pass also means the
    /// range check and the conversion cannot be separated by a future edit.
    function extLeaf(uint256[] memory limbs) internal pure returns (bytes32) {
        bytes memory row = new bytes(limbs.length * 4);
        for (uint256 i; i < limbs.length; ++i) {
            uint256 v = limbs[i];
            if (v >= P) {
                revert LimbOutOfRange(v);
            }
            // Wire form, then little-endian. `v` is below 2^31 and R below
            // 2^25, so the product cannot overflow and the compiler reduces it
            // without a wide-multiply path.
            uint256 w = (v * MONTGOMERY_R) % P;
            assembly ("memory-safe") {
                let dst := add(add(row, 0x20), mul(i, 4))
                mstore8(dst, and(w, 0xff))
                mstore8(add(dst, 1), and(shr(8, w), 0xff))
                mstore8(add(dst, 2), and(shr(16, w), 0xff))
                mstore8(add(dst, 3), and(shr(24, w), 0xff))
            }
        }
        return StarkMerkle.leaf(row);
    }

    /// Pack four canonical base coefficients into the extension element they
    /// describe, low coefficient first.
    function ext4(uint256[4] memory coeffs) internal pure returns (uint256) {
        return KoalaBearExt4.pack(coeffs);
    }

    /// Lift a base element into the extension: coefficient 0 is the value, the
    /// rest zero. This is the canonical embedding, not a basis choice.
    function liftBase(uint256 value) internal pure returns (uint256) {
        return KoalaBearExt4.fromBase(value);
    }

    /// Fold one opened row to a single extension element.
    ///
    /// `row` holds `1 << randomness.length` packed extension elements, the row
    /// as committed. `randomness` is the previous round's folding point, packed,
    /// in the order the transcript produced it: `randomness[0]` binds the most
    /// significant bit of the position within the row.
    ///
    /// The row is copied because `evaluate_hypercube` contracts in place, and
    /// the caller still needs the row to hash. At 16 elements that copy is cheap
    /// and it removes a whole class of "the fold ate my input" bugs.
    function foldRow(uint256[] memory row, uint256[] memory randomness)
        internal
        pure
        returns (uint256)
    {
        uint256 expected = uint256(1) << randomness.length;
        if (row.length != expected) {
            revert RowWidthMismatch(expected, row.length);
        }
        uint256[] memory scratch = new uint256[](row.length);
        for (uint256 i; i < row.length; ++i) {
            scratch[i] = row[i];
        }
        return KoalaBearExt4.evaluate_hypercube(scratch, randomness);
    }

    /// Horner evaluation of a polynomial given as packed extension coefficients
    /// with `coeffs[0]` the constant term, matching p3 `SelectStatement::verify`.
    ///
    /// This is the final-phase check: the fold of an opened row must equal the
    /// final polynomial, sent in the clear, evaluated at the query domain point.
    /// The final phase has no Merkle path to check because the polynomial is
    /// public, so this arithmetic IS the verification.
    function horner(uint256[] memory coeffs, uint256 x) internal pure returns (uint256) {
        uint256 acc = 0;
        for (uint256 i = coeffs.length; i > 0; --i) {
            acc = KoalaBearExt4.add(KoalaBearExt4.mul(acc, x), coeffs[i - 1]);
        }
        return acc;
    }

    /// The domain point WHIR assigns a query index: `g^index` on the folded
    /// domain, lifted into the extension. `p3_whir::domain::WhirDomain::query_point
    /// `is literally `two_adic_generator(log_folded_domain_size).exp_u64(index)`.
    function domainPoint(uint256 generator, uint256 index) internal pure returns (uint256) {
        return liftBase(KoalaBear.pow(generator, index));
    }

    /// Authenticate one opened row and return its fold.
    ///
    /// `depth` is checked as well as the root: a path truncated to a subtree
    /// can still reach a trusted root, so the geometry the transcript bound has
    /// to be part of the check rather than implied by it.
    ///
    /// `limbs` is the canonical flattened row, `row` the same row packed as
    /// extension elements. Both are passed because the leaf needs the flat form
    /// and the fold needs the packed one; a caller that derived one from the
    /// other inconsistently is caught by the width checks below.
    ///
    /// Two row shapes are legal. An EXTENSION row contributes four limbs per
    /// element (WHIR's later rounds open extension-valued rows). A BASE row -
    /// round 0, where the queried matrix is the trace itself - contributes one
    /// limb per element, and the caller has already lifted each limb into the
    /// extension for the fold. The leaf bytes are the same construction in both
    /// cases (Montgomery wire form, little-endian), so the authentication path
    /// does not care which shape it is authenticating; only the width relation
    /// between the two views differs.
    function openAndFold(
        bytes32 root,
        uint256 index,
        uint256 depth,
        uint256[] memory limbs,
        uint256[] memory row,
        bytes32[] memory siblings,
        uint256[] memory randomness
    ) internal pure returns (uint256) {
        // Extension rows: four limbs per element. Base rows: one limb per
        // element, pre-lifted by the caller into `row`.
        if (limbs.length != row.length * KoalaBearExt4.DEGREE && limbs.length != row.length) {
            revert RowWidthMismatch(row.length * KoalaBearExt4.DEGREE, limbs.length);
        }
        bytes32 leaf = extLeaf(limbs);
        if (!StarkMerkle.verify(root, index, leaf, siblings, depth)) {
            revert OpeningNotAuthenticated(index);
        }
        return foldRow(row, randomness);
    }
}
