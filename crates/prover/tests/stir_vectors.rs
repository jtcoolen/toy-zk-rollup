//! Ground-truth vectors for the STIR opening layer of the settlement verifier.
//!
//! Run with:
//!
//! ```text
//! cargo test -p prover --test stir_vectors -- --ignored --nocapture
//! ```
//!
//! ## What this pins, and what it deliberately does not
//!
//! A WHIR round STIR phase does four things the contract must reproduce: draw
//! query indices from the transcript, authenticate each opened row against the
//! round commitment, fold that row to one extension element at the round folding
//! randomness, and in the final phase evaluate the final polynomial at the
//! query domain point.
//!
//! The index DRAWS are already pinned end to end by `whir_semantic_program.bin`,
//! which replays every uniform-bit draw through the Solidity challenger against
//! the recorded values. Re-deriving them here would be a second copy of the same
//! assertion and would need a whole proof to do it. So this file pins the parts
//! that recording does NOT cover:
//!
//! 1. The extension-field LEAF ENCODING. Round 0 opens a base-field tree; every
//!    later round opens an `ExtensionMmcs`, which reinterprets each extension
//!    element as DIMENSION base limbs and hashes the row as width * DIMENSION
//!    little-endian Montgomery words. A verifier that hashed width extension
//!    elements instead, or used canonical rather than Montgomery limbs, computes
//!    a digest that is a perfectly good 32 bytes and simply wrong.
//! 2. The AUTHENTICATION PATH: which sibling sits at each level, and in which
//!    order the list runs. Recovered from the real pruned multiproof through
//!    `restore_and_recompute_paths`, so it is the prover own walk rather than a
//!    reimplementation of it.
//! 3. The FOLD: `Poly::eval_ext(row`, randomness), the multilinear reading of an
//!    opened row at the round folding randomness.
//! 4. The DOMAIN POINT and the final-phase HORNER evaluation, the two pieces the
//!    final STIR check compares the fold against.
//!
//! ## Why per-query full paths rather than the pruned multiproof
//!
//! p3 amortises. `verify_batch_pruned` walks a frontier and merges paths sharing a
//! parent, so a sibling shared by two queries travels once. That walk is around
//! a hundred and fifty lines of group bookkeeping: contiguous-run detection, a
//! lead path owning each level siblings, matrix injection at layer boundaries,
//! and a consistency check that merged group members opened the same row.
//!
//! The same crate exposes `restore_and_recompute_paths`, which runs the IDENTICAL
//! walk with recording enabled and returns one complete, self-sufficient path per
//! query. Solidity then checks each path alone with StarkMerkle.computeRoot,
//! which exists and is already tested.
//!
//! The cost is real and stated rather than hidden: duplicated siblings where
//! paths share a prefix, so a larger proof and more hashes. At the settlement
//! shape, a handful of queries at depth around 12, that is a few hundred bytes
//! and a few thousand gas per query. Two things make it the right first version:
//! D-039 splits a chunk verification across transactions, so one query per unit
//! of work bounds each transaction by a constant instead of by how the sampled
//! indices happened to cluster; and the amortised walk is a strictly local change
//! with a clear contract, same root fewer hashes, which is exactly the shape of a
//! later optimisation. Getting the LEAF right matters more than the hash count,
//! because a wrong leaf is silent and a redundant hash is not.
//!
//! ## What is NOT asserted here
//!
//! The fold and the Horner value are emitted as independent numbers, not as an
//! asserted equality. Their agreement is the WHIR final-phase identity, and it
//! depends on how the prover builds the committed codeword from the final
//! polynomial, a code-switching relation this file would have to reimplement in
//! order to assert. Reimplementing the relation to check the relation is how a
//! vector file ends up testing itself. The end-to-end proof test asserts it.
//!
//! ## Determinism
//!
//! Every value comes from a splitmix64 stream with a constant seed, so the file
//! is byte-reproducible. Unlike the semantic program there is no HVZK blinding
//! here: this is a bare Merkle tree, not a proof.

use p3_commit::{ExtensionMmcs, Mmcs};
use p3_field::{
    BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, RawDataSerializable, TwoAdicField,
};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Dimensions;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use pq_hash::Keccak256Commitment;
use serde_json::json;

use prover::config::F;
use prover::whir::Challenge;

/// Extension degree the settlement WHIR folds in. `prover::whir::Challenge` is
/// this type; naming it here makes the vector file self-describing even if the
/// alias moves.
const DIMENSION: usize = 4;

/// Folding factor per round, matching `prover::whir::FOLDING_FACTOR`. One row
/// opens 1 << `FOLDING_FACTOR` extension elements, which is what the fold consumes
/// as a multilinear over `FOLDING_FACTOR` variables.
const FOLDING_FACTOR: usize = 4;

/// Log-height of the committed matrix: `domain_size` >> `folding_factor`, the shape
/// WHIR actually opens.
const LOG_HEIGHT: usize = 6;

/// Queries per case. Small on purpose: the point is the encoding and the path.
/// The last case duplicates its second index so the shared-sibling handling in
/// the prover walk is exercised rather than dodged.
const QUERIES: usize = 3;

/// Cases: one clean, one with a duplicate index, one more.
const CASES: u64 = 3;

/// The settlement tree, spelled out rather than aliased, so the file records
/// which scheme it describes even if `config::Mmcs` is later re-aliased.
type FieldHash = SerializingHasher<Keccak256Hash>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type SettledMmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;
type SettledExtMmcs = ExtensionMmcs<F, Challenge, SettledMmcs>;

/// Deterministic canonical u32 for (seed, row, column).
fn word(seed: u64, row: usize, col: usize) -> u32 {
    let mut z = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ ((row as u64) << 32) ^ (col as u64);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // Reduce rather than mask. Masking can exceed the modulus, and a limb above
    // the modulus is not a field element.
    let reduced = z % u64::from(<F as PrimeField32>::ORDER_U32);
    u32::try_from(reduced).expect("remainder is below the u32 modulus")
}

/// One deterministic extension element, coefficients low-order first.
fn ext(seed: u64, row: usize, col: usize) -> Challenge {
    <Challenge as BasedVectorSpace<F>>::from_basis_coefficients_fn(|k| {
        F::from_u32(word(seed, row, col * DIMENSION + k))
    })
}

/// keccak256 cross-checked against the two implementations the project relies
/// on: p3-keccak is what the prover commits with, tiny-keccak models the EVM
/// opcode the Solidity side calls. If they diverge, nothing on-chain means
/// anything.
fn keccak(bytes: &[u8]) -> [u8; 32] {
    let via_p3 = Keccak256Hash {}.hash_slice(bytes);
    let via_tiny = *Keccak256Commitment::keccak256(bytes).as_bytes();
    assert_eq!(via_p3, via_tiny, "p3-keccak and tiny-keccak disagree");
    via_p3
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

/// Extension coefficients as canonical u32s, low order first.
fn ext_json(v: &Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField32::as_canonical_u32)
        .collect()
}

/// Lift a base element into the extension: coefficient 0 is the value, the rest
/// zero. The canonical embedding, not a basis choice to get wrong.
fn lift(x: F) -> Challenge {
    <Challenge as BasedVectorSpace<F>>::from_basis_coefficients_fn(
        |k| if k == 0 { x } else { F::ZERO },
    )
}

/// Horner evaluation with coeffs[0] the constant term, matching `p3_sumcheck`
/// `SelectStatement::verify`: p(x) = `c_0` + `x(c_1` + `x(c_2` + ...)).
fn horner(coeffs: &[Challenge], x: Challenge) -> Challenge {
    coeffs
        .iter()
        .copied()
        .rev()
        .fold(Challenge::ZERO, |acc, c| acc * x + c)
}

/// One linear pass: commit, open, restore paths, re-verify each path against the
/// root, fold, emit. Splitting it into helpers would pass the line limit by moving
/// the assertions somewhere a reader has to chase, and the value of this function is
/// that the whole chain is visible in order - the assertions are the point.
#[allow(clippy::too_many_lines)]
#[test]
#[ignore = "regenerates contracts/test/vectors/stir_vectors.json"]
fn stir_opening_vectors() {
    let height = 1usize << LOG_HEIGHT;
    let width_ext = 1usize << FOLDING_FACTOR;
    let width_base = width_ext * DIMENSION;

    let inner = SettledMmcs::new(
        SerializingHasher::new(Keccak256Hash {}),
        CompressionFunctionFromHasher::new(Keccak256Hash {}),
        0,
    );
    let mmcs = SettledExtMmcs::new(inner.clone());

    // The domain generator WHIR query_point uses for a folded domain of this
    // size: F::two_adic_generator(log_folded_domain_size).
    let domain_gen = F::two_adic_generator(LOG_HEIGHT);

    // Base-field dimensions, which is what the inner tree sees: ExtensionMmcs
    // widens every row by DIMENSION and leaves the height alone.
    let dims = vec![Dimensions {
        height,
        width: width_base,
    }];

    let mut cases = Vec::new();
    for seed in 0..CASES {
        let rows: Vec<Vec<Challenge>> = (0..height)
            .map(|r| (0..width_ext).map(|c| ext(seed, r, c)).collect())
            .collect();
        let matrix = RowMajorMatrix::new(rows.iter().flatten().copied().collect(), width_ext);
        let (cap, data) = mmcs.commit(vec![matrix]);
        let roots = cap.roots();
        assert_eq!(roots.len(), 1, "cap height 0 commits one root");
        let root = roots[0];

        let mut indices: Vec<usize> = (0..QUERIES)
            .map(|q| word(seed, 1000 + q, 7) as usize % height)
            .collect();
        if seed == CASES - 1 {
            indices[1] = indices[0];
        }

        // The prover own multiproof, then complete per-query paths recovered
        // from it by the same walk verification uses.
        let (values, proof) = mmcs.open_multi_batch(&indices, &data);
        // Extension rows flattened to base limbs: the shape the inner tree hashes.
        let opened_base: Vec<Vec<Vec<F>>> = values
            .iter()
            .map(|per_matrix| {
                per_matrix
                    .iter()
                    .map(|row| Challenge::flatten_to_base(row.clone()))
                    .collect()
            })
            .collect();
        let opened_refs: Vec<Vec<&[F]>> = opened_base
            .iter()
            .map(|per_matrix| per_matrix.iter().map(std::vec::Vec::as_slice).collect())
            .collect();
        let paths = inner
            .restore_and_recompute_paths(&dims, &indices, &opened_refs, &proof)
            .expect("the prover own multiproof must restore");
        assert_eq!(paths.len(), indices.len());

        // Folding randomness: one extension element per variable the fold
        // consumes. randomness[0] is the HIGH bit of the row index, which is
        // p3 convention and the one KoalaBearExt4.evaluate_hypercube follows.
        let randomness: Vec<Challenge> = (0..FOLDING_FACTOR).map(|k| ext(seed, 500, k)).collect();

        let mut queries = Vec::new();
        for (q, &index) in indices.iter().enumerate() {
            let row = &rows[index];
            let flat = &opened_base[q][0];
            assert_eq!(flat.len(), width_base, "flattened row width");

            // Leaf: the inner tree own hash of the flattened row.
            let leaf_bytes_in: Vec<u8> = F::into_byte_stream(flat.iter().copied())
                .into_iter()
                .collect();
            assert_eq!(
                leaf_bytes_in.len(),
                width_base * 4,
                "one row is width_base limbs of 4 bytes"
            );
            let leaf = keccak(&leaf_bytes_in);

            let path = &paths[q];
            assert_eq!(path.leaf_index, index, "path must carry its own index");
            assert_eq!(path.siblings.len(), LOG_HEIGHT, "path depth");

            // Re-verify with the exact rule StarkMerkle.computeRoot implements, so
            // the emitted path is known to authenticate under the convention the
            // contract uses BEFORE a Solidity test is asked to agree with it.
            let mut current = leaf;
            for (level, sib) in path.siblings.iter().enumerate() {
                let go_right = (index >> level) & 1 == 1;
                let pair = if go_right {
                    [sib.as_slice(), current.as_slice()].concat()
                } else {
                    [current.as_slice(), sib.as_slice()].concat()
                };
                current = keccak(&pair);
            }
            assert_eq!(current, root, "restored path must reach the committed root");

            // The fold the contract computes.
            let fold = Poly::new(row.clone()).eval_ext::<F>(&Point::new(randomness.clone()));

            // The final-phase query point: g^index on the folded domain.
            let point = domain_gen.exp_u64(index as u64);

            queries.push(json!({
                "index": index,
                "num_siblings": path.siblings.len(),
                "row_ext": row.iter().map(ext_json).collect::<Vec<_>>(),
                "leaf_bytes_hex": hex(&leaf_bytes_in),
                "leaf_hex": hex(&leaf),
                "siblings_hex": path.siblings.iter().map(|s| hex(s)).collect::<Vec<_>>(),
                "fold": ext_json(&fold),
                "domain_point": ext_json(&lift(point)),
            }));
        }

        // The final polynomial, sent in the clear, and the Horner value at each
        // query domain point. Emitted alongside the fold, not asserted equal to
        // it: see the module header.
        let final_poly: Vec<Challenge> = (0..height).map(|i| ext(seed, 900, i)).collect();
        let horner_values: Vec<_> = indices
            .iter()
            .map(|&i| ext_json(&horner(&final_poly, lift(domain_gen.exp_u64(i as u64)))))
            .collect();

        cases.push(json!({
            "seed": seed,
            "root_hex": hex(&root),
            "depth": LOG_HEIGHT,
            "height": height,
            "width_ext": width_ext,
            "width_base": width_base,
            "domain_generator": domain_gen.as_canonical_u32(),
            // Explicit counts throughout: the forge JSON selector syntax has no
            // array-length operator, so a test that wants to iterate must be told
            // how many there are. Deriving the count from a `.length` path fails
            // with "must return exactly one JSON value", which reads like a
            // malformed file rather than an unsupported selector.
            "num_queries": queries.len(),
            "num_randomness": randomness.len(),
            "num_final_poly": final_poly.len(),
            "num_horner": horner_values.len(),
            "randomness": randomness.iter().map(ext_json).collect::<Vec<_>>(),
            "queries": queries,
            "final_poly": final_poly.iter().map(ext_json).collect::<Vec<_>>(),
            "horner": horner_values,
        }));
    }

    let out = json!({
        "num_cases": cases.len(),
        "note": "Generated by `cargo test -p prover --test stir_vectors -- --ignored`. Do not edit by hand.",
        "scheme": "ExtensionMmcs<KoalaBear, BinomialExtensionField<KoalaBear,4>, MerkleTreeMmcs<F, u8, SerializingHasher<Keccak256Hash>, CompressionFunctionFromHasher<Keccak256Hash,2,32>, 2, 32>>",
        "leaf_rule": "keccak256(concat of width_base 4-byte little-endian to_unique_u32 limbs, no prefix)",
        "node_rule": "keccak256(left || right), no prefix",
        "fold_convention": {
            "siblings_ordered": "leaf_to_root",
            "sibling_side": "left when index bit set, right when clear",
            "matches": "contracts/src/verifier/StarkMerkle.sol::computeRoot"
        },
        "fold_rule": "Poly::eval_ext(row_as_ext4, randomness); randomness[0] is the high bit of the row index",
        "domain_point_rule": "F::two_adic_generator(log_folded_domain_size) ^ index",
        "horner_rule": "final_poly[0] is the constant term",
        "cases": cases,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/vectors/stir_vectors.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n")
        .expect("write stir_vectors.json");
    println!("wrote {} cases to {}", cases.len(), path);
}
