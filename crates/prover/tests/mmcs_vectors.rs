//! Ground-truth vectors for the settlement Merkle tree, generated from the
//! *real* `prover::config::Mmcs` so the Solidity verifier has byte-exact
//! openings to replay.
//!
//! Run with:
//!
//! ```text
//! cargo test -p prover --test mmcs_vectors -- --ignored --nocapture
//! ```
//!
//! ## Why the fold convention is searched, not assumed
//!
//! The Merkle proof is a flat list of sibling digests. Two independent choices
//! are not visible from that type: whether the list runs leaf-to-root or
//! root-to-leaf, and which side the sibling sits on for a given index bit. That
//! is four conventions, and `contracts/src/MerkleProof.sol` pins exactly one of
//! them. Getting it wrong is silent: both sides produce a 32-byte digest and
//! only one is the right one.
//!
//! So this generator does not assert a convention up front. It recomputes the
//! root under all four, requires that one reproduces the committed cap, requires
//! the winner be the same for every index, and then requires that winner to be
//! the one the Solidity side implements. If Plonky3 ever changes its ordering the
//! assert fires here instead of on-chain.
//!
//! ## The hash is the opcode
//!
//! Leaf = `keccak256(limb_0 || ... || limb_{w-1})` where each limb is the
//! 4-byte little-endian `to_unique_u32` (Montgomery) form - the same bytes
//! `SerializingChallenger32` absorbs. Node = `keccak256(left || right)`. No
//! domain separators, no length prefixes, no digest masking: both are plain
//! `keccak256` calls, so Solidity pays the ~30-gas opcode and implements
//! nothing. Every digest is cross-checked against `tiny_keccak` through
//! `pq_hash::Keccak256Commitment`, an implementation independent of `p3-keccak`.

use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::{PrimeCharacteristicRing, PrimeField32, RawDataSerializable};
use p3_keccak::Keccak256Hash;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use pq_hash::Keccak256Commitment;
use serde_json::json;

use prover::config::F;

/// The settlement MMCS, spelled out so the vector file records which scheme it
/// describes even if `config::Mmcs` is later re-aliased.
type FieldHash = SerializingHasher<Keccak256Hash>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type SettledMmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;

/// Deterministic field element for `(row, column)` via splitmix64, so
/// neighbouring cells differ and a transposed row cannot hash the same.
fn cell(row: usize, col: usize) -> F {
    let mut z = (((row as u64) << 32) | col as u64) ^ 0x9E37_79B9_7F4A_7C15;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // Reduce rather than assume the modulus, so this stays correct if the
    // field changes.
    // The remainder is below the modulus by construction, so the narrowing
    // to u32 cannot truncate.
    let reduced = z % u64::from(<F as PrimeField32>::ORDER_U32);
    F::from_u32(u32::try_from(reduced).expect("remainder is below the u32 modulus"))
}

/// Canonical leaf bytes for one row: the 4-byte little-endian `to_unique_u32`
/// of each limb, concatenated. This is `RawDataSerializable::into_byte_stream`,
/// which is what `SerializingHasher` feeds the hasher and what the transcript
/// absorbs, so one codec serves both.
fn leaf_bytes(row: &[F]) -> Vec<u8> {
    F::into_byte_stream(row.iter().copied())
        .into_iter()
        .collect()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let via_p3 = Keccak256Hash {}.hash_slice(bytes);
    let via_tiny = *Keccak256Commitment::keccak256(bytes).as_bytes();
    // The whole settlement design rests on these agreeing: p3-keccak is what
    // the prover commits with, tiny-keccak models the EVM `keccak256` opcode
    // the Solidity side calls. If they ever diverge nothing on-chain means
    // anything.
    assert_eq!(via_p3, via_tiny, "p3-keccak and tiny-keccak disagree");
    via_p3
}

/// Fold a leaf to a root under one of the four candidate conventions.
fn fold(
    leaf: [u8; 32],
    index: usize,
    siblings: &[[u8; 32]],
    leaf_to_root: bool,
    sibling_left_on_one: bool,
) -> [u8; 32] {
    let mut current = leaf;
    for level in 0..siblings.len() {
        let sib = if leaf_to_root {
            siblings[level]
        } else {
            siblings[siblings.len() - 1 - level]
        };
        let bit_set = (index >> level) & 1 == 1;
        current = keccak(&if bit_set == sibling_left_on_one {
            [sib.as_slice(), current.as_slice()].concat()
        } else {
            [current.as_slice(), sib.as_slice()].concat()
        });
    }
    current
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! rather than push_str(&format!(..)): no intermediate String
        // per byte.
        write!(&mut out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

#[test]
#[ignore = "regenerates contracts/test/vectors/mmcs.json"]
fn generate_mmcs_vectors() {
    // A power-of-two height avoids the padding/injection path entirely, so the
    // tree the vectors describe is the plain binary tree Solidity walks.
    const HEIGHT: usize = 16;
    const WIDTH: usize = 3;
    const CAP_HEIGHT: usize = 0;

    let mmcs = SettledMmcs::new(
        SerializingHasher::new(Keccak256Hash {}),
        CompressionFunctionFromHasher::new(Keccak256Hash {}),
        CAP_HEIGHT,
    );

    let values: Vec<F> = (0..HEIGHT)
        .flat_map(|row| (0..WIDTH).map(move |col| cell(row, col)))
        .collect();
    let matrix = RowMajorMatrix::new(values, WIDTH);
    let dimensions = vec![Dimensions {
        width: WIDTH,
        height: HEIGHT,
    }];

    let (cap, prover_data) = mmcs.commit(vec![matrix]);
    let roots = cap.roots();
    assert_eq!(roots.len(), 1 << CAP_HEIGHT, "cap width");
    let root = roots[0];

    // Open every index, so the vectors cover both sides at every level rather
    // than a hand-picked subset that happens to dodge an edge case.
    let mut cases = Vec::new();
    let mut winners: Vec<Vec<(bool, bool)>> = Vec::new();

    for index in 0..HEIGHT {
        let opening = mmcs.open_batch(index, &prover_data);
        let (opened_values, proof) = opening.unpack();

        // Gate 1: the real verifier accepts its own opening.
        let opening_ref = BatchOpeningRef {
            opened_values: &opened_values,
            opening_proof: &proof,
        };
        mmcs.verify_batch(&cap, &dimensions, index, opening_ref)
            .expect("real verifier rejected its own opening");

        let row = &opened_values[0];
        assert_eq!(row.len(), WIDTH, "opened row width");

        let leaf = leaf_bytes(row);
        let leaf_digest = keccak(&leaf);

        // Gate 2: which conventions reproduce the committed root?
        let mut ok = Vec::new();
        for &leaf_to_root in &[true, false] {
            for &sibling_left_on_one in &[true, false] {
                let got = fold(
                    leaf_digest,
                    index,
                    &proof,
                    leaf_to_root,
                    sibling_left_on_one,
                );
                if got == root {
                    ok.push((leaf_to_root, sibling_left_on_one));
                }
            }
        }
        assert!(
            !ok.is_empty(),
            "no fold convention reproduced the root at index {index}"
        );
        winners.push(ok);

        cases.push(json!({
            "index": index,
            "row_u32": row.iter().map(PrimeField32::to_unique_u32).collect::<Vec<_>>(),
            "leaf_bytes_hex": hex(&leaf),
            "leaf_digest_hex": hex(&leaf_digest),
            "siblings_hex": proof.iter().map(|d| hex(d)).collect::<Vec<_>>(),
            "root_hex": hex(&root),
        }));
    }

    // The convention must hold for every index. One that works for a single row
    // means the fold is not the shape Solidity implements.
    let first = winners[0].clone();
    for (index, w) in winners.iter().enumerate() {
        assert_eq!(&first, w, "fold convention differs at index {index}");
    }

    // `MerkleProof.sol::computeRoot` walks leaf-to-root and puts the sibling on
    // the LEFT when the index bit is set. If this fires, the Solidity fold and
    // the prover disagree and the fix belongs on whichever side drifted.
    assert!(
        first.contains(&(true, true)),
        "MerkleProof.sol convention (leaf-to-root, sibling-left-on-one) does not reproduce the prover root; accepted were {first:?}"
    );

    let out = json!({
        "note": "Generated by `cargo test -p prover --test mmcs_vectors -- --ignored`. Do not edit by hand.",
        "scheme": "MerkleTreeMmcs<F, u8, SerializingHasher<Keccak256Hash>, CompressionFunctionFromHasher<Keccak256Hash, 2, 32>, 2, 32>",
        "leaf_rule": "keccak256(concat of 4-byte little-endian to_unique_u32 limbs, no prefix)",
        "node_rule": "keccak256(left || right), no prefix",
        "fold_convention": {
            "siblings_ordered": "leaf_to_root",
            "sibling_side": "left when index bit set, right when clear",
            "matches": "contracts/src/MerkleProof.sol::computeRoot",
        },
        "height": HEIGHT,
        "log_height": HEIGHT.ilog2(),
        "width": WIDTH,
        "cap_height": CAP_HEIGHT,
        "root_hex": hex(&root),
        "case_count": cases.len(),
        "cases": cases,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/vectors/mmcs.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n")
        .expect("write mmcs.json");
    println!("wrote {} cases to {}", cases.len(), path);
}
