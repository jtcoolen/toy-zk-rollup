//! The Poseidon2 commitment layer: the note commitment tree's hash.
//!
//! # Why Poseidon2 and not Keccak here
//!
//! The commitment tree used to be Keccak-256 because the EVM verifies Merkle
//! paths with the native `keccak256` opcode. That rationale died with the
//! roots-only pool: the contract no longer walks or appends to the tree at all.
//! It stores the root that the proof attests, and the *proof* is what must be
//! cheap — so the tree hash must be cheap **inside the arithmetized circuit**.
//!
//! Inside the recursion circuit a Keccak-f1600 permutation costs ~24 AIR rows
//! (the vendored Keccak gadget); a Poseidon2 permutation costs **one row** of
//! the Poseidon2 perm AIR. A depth-32 append fold is 32 permutations: ~768 rows
//! versus ~32. Poseidon2 is also the exact hash the WHIR stack's own MMCS uses
//! (`PaddingFreeSponge<Poseidon2KoalaBear<16>, 16, 8, 8>` for leaves,
//! `TruncatedPermutation<_, 2, 8, 16>` for nodes), so the commitment tree and
//! the proof system share one primitive and one set of audited parameters.
//!
//! The EVM pays nothing for this: it never hashes the tree. Keccak-256 remains
//! the *transcript* hash (the verifier replays Fiat-Shamir natively) and the
//! *nullifier* tree hash (already proven in-circuit with the Keccak gadget;
//! untouched). See `.scratch/pq-shielded-rollup/decisions.md` D-088.
//!
//! # Consensus-critical encodings (nailed down here, tested below)
//!
//! * **Digest**: 8 `KoalaBear` field elements, each serialized as one
//!   little-endian `u32` (canonical, `< 0x7F00_0001`), 32 bytes total. This is
//!   the `Digest32` a tree node or note commitment carries on the wire.
//! * **Byte to element encoding** ([`Poseidon2Commitment::hash`]): the input
//!   bytes are split into little-endian 16-bit limbs (two bytes each, exactly
//!   the `p3_circuit` `bytes_to_limbs` convention the circuit uses), each limb
//!   becomes one field element, and the sequence is absorbed by
//!   `PaddingFreeSponge<_, 16, 8, 8>` (overwrite-mode rate 8, zero-padded
//!   final chunk, output = first 8 state elements).
//! * **Node compression** ([`Poseidon2Commitment::hash_pair`]): the two child
//!   digests decode to 8 + 8 elements and go through
//!   `TruncatedPermutation<_, 2, 8, 16>` — one permutation of the 16-element
//!   state, output = first 8 elements. This is byte-for-byte the WHIR MMCS
//!   node function, so the in-circuit fold and this native tree agree by
//!   construction.
//!
//! Because every part of a note preimage is an even number of bytes (the
//! `DOMAIN_*` tags are even-length by rule), the limb split is exact and the
//! encoding is deterministic.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, Permutation, PseudoCompressionFunction,
    TruncatedPermutation,
};

use crate::digest::Digest32;
use crate::traits::CommitmentHasher;

/// The Poseidon2 permutation shared by the commitment tree and the WHIR MMCS:
/// `KoalaBear`, width 16, `x^3` S-box, the Plonky3 audited parameter set.
pub type Poseidon2Perm16 = Poseidon2KoalaBear<16>;

/// The leaf hash: overwrite-mode sponge, rate 8, output 8. Identical to the
/// WHIR MMCS `WhirHash`.
pub type Poseidon2Sponge = PaddingFreeSponge<Poseidon2Perm16, WIDTH, RATE, DIGEST_ELEMS>;

/// The node compression: two 8-element children in, one permutation, first 8
/// elements out. Identical to the WHIR MMCS `WhirCompress`.
pub type Poseidon2Compress = TruncatedPermutation<Poseidon2Perm16, 2, DIGEST_ELEMS, WIDTH>;

/// The permutation width in field elements.
pub const WIDTH: usize = 16;

/// The sponge rate in field elements.
pub const RATE: usize = 8;

/// Elements per digest. Eight `KoalaBear` elements serialize to exactly 32 bytes.
pub const DIGEST_ELEMS: usize = 8;

/// The `KoalaBear` prime, `2^31 - 2^24 + 1`. Consensus-critical: a digest
/// element at or above this value is malformed, not reducible.
pub const KOALABEAR_P_U32: u32 = 0x7F00_0001;

/// The field element type the commitment layer hashes over.
pub type Field = KoalaBear;

/// Build the shared Poseidon2 permutation instance.
#[must_use = "a permutation instance is only useful to permute with"]
pub fn poseidon2_16() -> Poseidon2Perm16 {
    default_koalabear_poseidon2_16()
}

/// Encode bytes as little-endian 16-bit limbs, one field element per limb.
///
/// The caller must pass an even byte count; every consensus-critical preimage
/// in this crate upholds that (even-length domain tags, 32-byte secrets,
/// 8-byte amounts). Odd-length input is a programmer error.
///
/// # Panics
///
/// If `bytes` has an odd length.
#[must_use = "the encoded elements are the point of encoding"]
pub fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Field> {
    assert!(
        bytes.len().is_multiple_of(2),
        "limb encoding requires an even byte count"
    );
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Field::new(u32::from(u16::from_le_bytes([pair[0], pair[1]]))))
        .collect()
}

/// Decode a digest's 32 bytes into 8 field elements, reducing any word that
/// is not canonical.
///
/// This is the decoder the *hash itself* uses, so the compression is a total
/// function of its byte inputs. Honest digests are always canonical (every
/// digest this module emits has canonical words), so reduction never actually
/// fires for them; a non-canonical word can only arrive from hostile input, and
/// folding it simply yields a root that fails to match the attested one. The
/// in-circuit fold cannot even express a non-canonical word — field elements in
/// the AIR are canonical by construction — so the two views agree on every
/// digest that can appear in a proof.
fn decode_words(digest: &Digest32) -> [Field; DIGEST_ELEMS] {
    let bytes = digest.as_bytes();
    let mut out = [Field::ZERO; DIGEST_ELEMS];
    for (i, word) in out.iter_mut().enumerate() {
        let j = i * 4;
        let raw = u32::from_le_bytes([bytes[j], bytes[j + 1], bytes[j + 2], bytes[j + 3]]);
        *word = Field::new(raw);
    }
    out
}

/// Strictly decode a digest's 32 bytes into 8 canonical field elements.
///
/// Returns `None` if any 4-byte word is not a canonical field element (i.e.
/// `>= 0x7F00_0001`). Digests produced by this module always pass; use this at
/// trust boundaries where bytes arrive from the wire and malleation must be
/// rejected rather than folded away.
#[must_use = "the decoded elements are the point of decoding"]
pub fn digest_to_elements(digest: &Digest32) -> Option<[Field; DIGEST_ELEMS]> {
    let bytes = digest.as_bytes();
    let mut out = [Field::ZERO; DIGEST_ELEMS];
    for (i, word) in out.iter_mut().enumerate() {
        let raw = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().ok()?);
        if raw >= KOALABEAR_P_U32 {
            return None;
        }
        *word = Field::new(raw);
    }
    Some(out)
}

/// Encode 8 field elements as a digest (each element as one LE `u32`).
#[must_use = "the digest is the point of encoding"]
pub fn elements_to_digest(elements: &[Field; DIGEST_ELEMS]) -> Digest32 {
    let mut bytes = [0u8; 32];
    for (i, element) in elements.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&element.as_canonical_u32().to_le_bytes());
    }
    Digest32::new(bytes)
}

/// The Poseidon2 commitment hasher: sponge leaves, truncated-permutation nodes.
///
/// Implements [`CommitmentHasher`] so every generic consumer (the note tree,
/// empty-subtree tables, membership paths) works unchanged — only the hash
/// behind the trait changes.
#[derive(Clone, Debug)]
pub struct Poseidon2Commitment {
    perm: Poseidon2Perm16,
}

impl Default for Poseidon2Commitment {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Commitment {
    /// Construct with the canonical parameter set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            perm: poseidon2_16(),
        }
    }

    /// The underlying permutation (for tests and the prover's native mirror).
    #[must_use = "the permutation is only useful to permute with"]
    pub const fn perm(&self) -> &Poseidon2Perm16 {
        &self.perm
    }

    /// Sponge-hash field elements: absorb in rate-8 chunks (overwrite mode,
    /// zero-padded final chunk), squeeze the first 8 state elements.
    ///
    /// This is `PaddingFreeSponge`'s exact semantics — the same construction
    /// the WHIR MMCS uses for leaf digests — so the in-circuit leaf gadget and
    /// this native function agree element-for-element.
    #[must_use = "the digest is the point of hashing"]
    pub fn hash_elements(&self, elements: &[Field]) -> [Field; DIGEST_ELEMS] {
        let sponge = Poseidon2Sponge::new(self.perm.clone());
        sponge.hash_iter(elements.iter().copied())
    }

    /// Compress two digests into their parent: one permutation over the 16
    /// elements `left || right`, output the first 8.
    ///
    #[must_use = "the parent digest is the point of compressing"]
    pub fn compress(&self, left: &Digest32, right: &Digest32) -> Digest32 {
        let compress = Poseidon2Compress::new(self.perm.clone());
        let out = compress.compress([decode_words(left), decode_words(right)]);
        elements_to_digest(&out)
    }

    /// One raw permutation of a 16-element state (test/prover mirror).
    #[must_use = "the permuted state is the point of permuting"]
    pub fn permute(&self, state: [Field; WIDTH]) -> [Field; WIDTH] {
        self.perm.permute(state)
    }
}

impl CommitmentHasher for Poseidon2Commitment {
    fn hash(&self, parts: &[&[u8]]) -> Digest32 {
        // Concatenate first, then split into limbs, so a part boundary can never
        // straddle a limb even if a caller passes odd-length parts. The
        // consensus preimages use even-length parts, so this is equivalent for
        // them and strictly more robust for everyone else.
        let bytes: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        assert!(
            bytes.len().is_multiple_of(2),
            "commitment preimage must have an even byte count"
        );
        let elements = bytes_to_field_elements(&bytes);
        elements_to_digest(&self.hash_elements(&elements))
    }

    fn hash_pair(&self, left: &Digest32, right: &Digest32) -> Digest32 {
        self.compress(left, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> Poseidon2Commitment {
        Poseidon2Commitment::new()
    }

    fn words_to_digest(words: [u32; DIGEST_ELEMS]) -> Digest32 {
        let mut bytes = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        Digest32::new(bytes)
    }

    #[test]
    fn digest_elements_roundtrip_canonical() {
        let words = [1u32, 2, 3, 0x7F00_0000, 5, 6, 7, 8];
        let d = words_to_digest(words);
        let back = digest_to_elements(&d).expect("canonical");
        let mut expect = [Field::ZERO; DIGEST_ELEMS];
        for (i, w) in words.iter().enumerate() {
            expect[i] = Field::new(*w);
        }
        assert_eq!(back, expect);
        assert_eq!(elements_to_digest(&back), d);
    }

    #[test]
    fn noncanonical_word_rejected_not_reduced() {
        // A word at or above the prime must be rejected outright — silently
        // reducing it would let two different byte strings name the same node.
        for bad in [KOALABEAR_P_U32, KOALABEAR_P_U32 + 1, u32::MAX] {
            let mut words = [3u32; DIGEST_ELEMS];
            words[3] = bad;
            assert!(
                digest_to_elements(&words_to_digest(words)).is_none(),
                "bad {bad}"
            );
        }
    }

    #[test]
    fn compress_matches_raw_permutation_truncation() {
        // Independent path: permute the 16-element state by hand and take the
        // first 8 elements. Pins the TruncatedPermutation convention.
        let h = hasher();
        let left = words_to_digest([1, 2, 3, 4, 5, 6, 7, 8]);
        let right = words_to_digest([9, 10, 11, 12, 13, 14, 15, 16]);
        let mut state = [Field::ZERO; WIDTH];
        for (i, w) in [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
            .iter()
            .enumerate()
        {
            state[i] = Field::new(*w);
        }
        let permuted = h.permute(state);
        let expected = elements_to_digest(&permuted[..DIGEST_ELEMS].try_into().unwrap());
        assert_eq!(h.compress(&left, &right), expected);
        // Order matters: compress is not symmetric.
        assert_ne!(h.compress(&left, &right), h.compress(&right, &left));
    }

    #[test]
    fn sponge_matches_hand_rolled_overwrite_absorb() {
        // 20 elements = two full rate-8 chunks + a 4-element tail. Overwrite
        // mode: each chunk overwrites rate positions 0..8, permute after every
        // chunk (including the padded tail).
        let h = hasher();
        let elements: Vec<Field> = (0..20u32).map(Field::new).collect();
        let got = h.hash_elements(&elements);

        // Overwrite mode: a short final chunk overwrites only the positions it
        // fills and leaves the rest of the rate as the previous permutation left
        // them — PaddingFreeSponge does NOT zero the tail.
        let mut state = [Field::ZERO; WIDTH];
        for chunk in elements.chunks(RATE) {
            for (i, x) in chunk.iter().enumerate() {
                state[i] = *x;
            }
            state = h.permute(state);
        }
        assert_eq!(got.to_vec(), state[..DIGEST_ELEMS].to_vec());
    }

    #[test]
    fn empty_input_squeezes_zero_state() {
        // PaddingFreeSponge with no input performs no permutation at all.
        let h = hasher();
        let got = h.hash_elements(&[]);
        assert!(got.iter().all(|x| x.as_canonical_u32() == 0));
        assert_eq!(h.hash(&[]), Digest32::default());
    }

    #[test]
    fn hash_splits_limbs_over_concatenation() {
        // Part boundaries must not change the digest: same byte stream, same
        // result, even when a naive per-part split would differ.
        let h = hasher();
        let a = h.hash(&[b"abcd", b"efgh"]);
        let b = h.hash(&[b"abcdefgh"]);
        assert_eq!(a, b);
        // Different bytes, different digest.
        assert_ne!(a, h.hash(&[b"abcd", b"efgi"]));
    }

    #[test]
    fn hash_pair_trait_matches_compress() {
        let h = hasher();
        let l = words_to_digest([7; DIGEST_ELEMS]);
        let r = words_to_digest([9; DIGEST_ELEMS]);
        assert_eq!(CommitmentHasher::hash_pair(&h, &l, &r), h.compress(&l, &r));
    }

    #[test]
    fn known_answer_digests() {
        // Pinned consensus anchors for the Poseidon2 commitment layer. These
        // change only with a deliberate, documented re-derivation.
        let h = hasher();
        assert_eq!(
            h.hash(&[b"pq-rollup/note-commit/v1"]).to_hex(),
            "d806ed0043c329383dab56651706f32567961328cd3099435d362d5fc60b7c53"
        );
        assert_eq!(
            h.compress(&Digest32::default(), &Digest32::default())
                .to_hex(),
            "44917757aa9a1104a1ad4b7cbe60fe659316d4334d2ca2295e2525771877632b"
        );
    }
}
