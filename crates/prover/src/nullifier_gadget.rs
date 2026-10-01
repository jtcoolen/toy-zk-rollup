//! In-circuit non-membership for the nullifier map.
//!
//! The native side of this lives in [`shielded::nullifier_tree`]; this module is
//! the circuit mirror. It proves two things about one nullifier, against two
//! roots that the settlement contract tracks:
//!
//! ```text
//!   fold(empty[h], siblings)  == nullifier_root_before    (absent)
//!   fold(nf,       siblings') == nullifier_root_after     (inserted)
//! ```
//!
//! # Why the shape is fixed
//!
//! A circuit cannot have a data-dependent number of rows, so the variable part
//! of the native witness — how far down the tree the empty subtree starts — is
//! replaced by a compile-time budget. `FOLD_DEPTH` is the number of levels the
//! absence fold runs. The prover must supply a witness whose empty subtree
//! reaches at least `NULLIFIER_TREE_DEPTH - FOLD_DEPTH`, i.e. the map must be
//! sparse enough at that level. That is a capacity parameter in the same spirit
//! as `LOG_MAX_LDE`: too small and proving fails loudly, never silently.
//!
//! Emptiness is downward-closed inside a containing subtree, so if the subtree
//! at height `h` is empty then so is the one at any lower `h0 ≤ h`. That is
//! what lets a fixed `h0 = NULLIFIER_TREE_DEPTH - FOLD_DEPTH` stand in for a
//! larger true `h`, padding the bottom of the fold with empty-subtree
//! constants.
//!
//! # Where the address bits come from
//!
//! The address is the nullifier, and the nullifier is already computed in this
//! circuit as `H(DOMAIN_NULLIFIER || sk_d || rho)`. The direction bits are
//! decomposed from those digest limbs, so the prover never chooses an address —
//! it is derived from the witness that produced the nullifier. A prover who
//! could pick the address could route a spend around the empty-subtree check.
//!
//! # Cost, stated plainly
//!
//! The absence fold is `FOLD_DEPTH` Keccak-f. The insert fold runs from the
//! leaf all the way to the root — `NULLIFIER_TREE_DEPTH` Keccak-f — because the
//! empty-collapse that makes absence cheap only applies when *both* children
//! are empty, and the inserted leaf is not. Sparsity does not help the insert
//! direction. At 24 rows per Keccak-f that is roughly
//! `24 · (FOLD_DEPTH + 256)` rows per nullifier.

use p3_circuit::ops::KECCAK256_DIGEST_LIMBS;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use pq_hash::CommitmentHasher;
use pq_hash::Digest32;
use shielded::nullifier_tree::{NonInclusionWitness, NullifierMap, NULLIFIER_TREE_DEPTH};

use crate::transfer::const_limbs;
use crate::whir_recursion::{Challenge, F};

/// Levels the absence fold covers.
///
/// Sets how dense the nullifier map may get: the prover needs the subtree at
/// height `NULLIFIER_TREE_DEPTH - FOLD_DEPTH` to be empty, so with the address
/// spread uniformly this supports on the order of `2^FOLD_DEPTH` spent
/// nullifiers before a transfer can no longer be witnessed. 32 is far past any
/// realistic deployment while keeping the absence fold at 32 hashes.
pub const FOLD_DEPTH: usize = 32;

/// The height the absence fold starts at.
const FOLD_START: usize = NULLIFIER_TREE_DEPTH - FOLD_DEPTH;

/// A nullifier's non-membership witness, in circuit-ready form.
///
/// Built from a native [`NonInclusionWitness`] by [`prepare_witness`], which
/// pads the variable-length native path out to the circuit's fixed shape.
#[derive(Clone, Debug)]
pub struct NullifierWitness {
    /// Siblings for levels `FOLD_START..NULLIFIER_TREE_DEPTH`, leaf-to-root.
    /// Exactly [`FOLD_DEPTH`] of them.
    pub siblings: Vec<Digest32>,
    /// The map's empty-subtree digests for heights `0..=FOLD_START`, indexed by
    /// height. These are the siblings the insert fold uses below `FOLD_START`,
    /// and the starting node of the absence fold.
    pub lower_empties: Vec<Digest32>,
}

/// The empty-subtree digests for heights `0..=up_to`, indexed by height.
///
/// Same recurrence as the native map: `empty[0]` is the zero digest and
/// `empty[h] = H(empty[h-1], empty[h-1])`. Derived here from the caller's
/// hasher so the constants the circuit starts from are produced by the same
/// hash function that produced the roots it is checked against.
#[must_use]
pub fn empty_subtrees<H: CommitmentHasher>(hasher: &H, up_to: usize) -> Vec<Digest32> {
    let mut empties = Vec::with_capacity(up_to + 1);
    empties.push(Digest32::default());
    for _ in 0..up_to {
        let last = *empties.last().unwrap_or_else(|| unreachable!("seeded"));
        empties.push(hasher.hash_pair(&last, &last));
    }
    empties
}

/// Lift a native witness into the circuit's fixed shape.
///
/// The native witness starts wherever the empty subtree actually begins; the
/// circuit starts at a fixed [`FOLD_START`]. Emptiness is downward-closed
/// inside a containing subtree, so when the true start is *higher* than
/// `FOLD_START` the extra bottom levels are just empty-subtree constants and
/// padding them changes nothing.
///
/// When the true start is *lower*, the map is denser than this circuit can
/// attest to, and that is an error rather than something to paper over: the
/// prover would have no valid witness, and silently folding from a higher
/// level would claim emptiness that does not hold.
///
/// # Errors
///
/// Returns a message if the map is too dense for [`FOLD_DEPTH`].
pub fn prepare_witness<H: CommitmentHasher>(
    map: &NullifierMap<H>,
    witness: &NonInclusionWitness,
) -> Result<NullifierWitness, String> {
    if witness.start_height < FOLD_START {
        return Err(format!(
            "nullifier map too dense for this circuit: the empty subtree containing              the address starts at height {}, below the circuit floor of {FOLD_START}              (FOLD_DEPTH = {FOLD_DEPTH})",
            witness.start_height
        ));
    }
    let mut siblings = Vec::with_capacity(FOLD_DEPTH);
    for height in FOLD_START..witness.start_height {
        siblings.push(map.empty_at(height));
    }
    siblings.extend_from_slice(&witness.siblings);
    if siblings.len() != FOLD_DEPTH {
        return Err(format!(
            "witness padding produced {} siblings, expected {FOLD_DEPTH}",
            siblings.len()
        ));
    }
    Ok(NullifierWitness {
        siblings,
        lower_empties: empty_subtrees(map.hasher(), FOLD_START),
    })
}

/// Decompose 16 digest limbs into 256 little-endian bits.
///
/// Limb `i` holds bits `16i .. 16i+16`, so bit `b` of the digest is bit
/// `b % 16` of limb `b / 16`. This matches the native `addr_bit`, which reads
/// bit `i` from byte `i / 8` little-endian within the byte, because each 16-bit
/// limb is two little-endian bytes.
fn digest_bits(
    builder: &mut CircuitBuilder<Challenge>,
    limbs: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut bits = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
    for limb in limbs.iter().take(KECCAK256_DIGEST_LIMBS) {
        let mut part = builder.decompose_to_bits::<F>(*limb, 16)?;
        bits.append(&mut part);
    }
    if bits.len() != NULLIFIER_TREE_DEPTH {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: NULLIFIER_TREE_DEPTH,
            actual: bits.len(),
        });
    }
    Ok(bits)
}

/// Fold `start` upward through `siblings`, one level per sibling.
///
/// Direction at each level is taken from `bits`, so the caller controls how the
/// path is chosen and the prover cannot steer it.
fn fold_up(
    builder: &mut CircuitBuilder<Challenge>,
    start: Vec<ExprId>,
    start_height: usize,
    siblings: &[Digest32],
    bits: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut current = start;
    for (offset, sibling) in siblings.iter().enumerate() {
        let level = start_height + offset;
        let sibling_limbs = const_limbs(builder, sibling.as_bytes());
        let go_right = bits[level];
        builder.assert_bool(go_right);

        // `go_right = 1` puts the sibling on the left, matching the native
        // fold where the node's own address bit selects the side the sibling
        // occupies.
        let mut left = Vec::with_capacity(KECCAK256_DIGEST_LIMBS);
        let mut right = Vec::with_capacity(KECCAK256_DIGEST_LIMBS);
        for limb in 0..KECCAK256_DIGEST_LIMBS {
            left.push(builder.select(go_right, sibling_limbs[limb], current[limb]));
            right.push(builder.select(go_right, current[limb], sibling_limbs[limb]));
        }
        current = builder.keccak256_compress(&left, &right)?;
    }
    Ok(current)
}

/// Constrain a nullifier's absence and its insertion, returning the two roots.
///
/// `nullifier_limbs` must be the in-circuit digest of the nullifier, so the
/// address bits are derived rather than declared. The returned limb vectors are
/// the roots the transfer's statement must export; the settlement contract
/// checks each against the root it holds.
///
/// # Errors
///
/// Returns [`CircuitBuilderError`] if the witness is short, or if a digest limb
/// cannot be decomposed.
pub fn constrain_nullifier_non_membership(
    builder: &mut CircuitBuilder<Challenge>,
    nullifier_limbs: &[ExprId],
    witness: &NullifierWitness,
) -> Result<(Vec<ExprId>, Vec<ExprId>), CircuitBuilderError> {
    if witness.siblings.len() != FOLD_DEPTH {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: FOLD_DEPTH,
            actual: witness.siblings.len(),
        });
    }
    if witness.lower_empties.len() != FOLD_START + 1 {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: FOLD_START + 1,
            actual: witness.lower_empties.len(),
        });
    }

    let bits = digest_bits(builder, nullifier_limbs)?;

    // Absence: start from the empty-subtree constant at FOLD_START. The
    // constant is not a witness, so nothing is being trusted about it — the
    // fold either reaches the root or the nullifier was not absent.
    // `lower_empties` is indexed by height and its length is checked above, so
    // this index cannot fail. A silent default would substitute a zero digest
    // and weaken the fold, so the failure is explicit instead.
    let start_digest = witness
        .lower_empties
        .get(FOLD_START)
        .ok_or(CircuitBuilderError::MissingOutput)?;
    let start = const_limbs(builder, start_digest.as_bytes());
    let root_before = fold_up(builder, start, FOLD_START, &witness.siblings, &bits)?;

    // Insertion: the same sibling path, but starting from the nullifier's own
    // digest at the leaf level, with the empty-subtree constants below
    // FOLD_START.
    // Only the first FOLD_START entries are siblings here. `lower_empties`
    // carries heights `0..=FOLD_START`, and the top one is the absence fold's
    // *starting node*, not a level the insert fold consumes — including it
    // would push the insert fold one level past the root.
    let mut insert_siblings = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
    insert_siblings.extend_from_slice(&witness.lower_empties[..FOLD_START]);
    insert_siblings.extend_from_slice(&witness.siblings);
    let root_after = fold_up(
        builder,
        nullifier_limbs.to_vec(),
        0,
        &insert_siblings,
        &bits,
    )?;

    Ok((root_before, root_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::const_limbs;
    use pq_hash::{Digest32, Keccak256Commitment, Nullifier};

    fn nf(bytes: [u8; 32]) -> Nullifier {
        Nullifier::from_digest(Digest32::new(bytes))
    }

    /// Build a circuit that folds `probe`'s witness and asserts the two roots
    /// equal the supplied expectations, then run it.
    ///
    /// A successful run means the in-circuit fold produced exactly those roots;
    /// a constraint violation means it did not. This is the native/circuit
    /// equivalence check — the circuit is never trusted to agree with the map,
    /// only tested against it.
    fn fold_and_check(
        probe: &Nullifier,
        witness: &NullifierWitness,
        expect_before: &[u8; 32],
        expect_after: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = CircuitBuilder::<Challenge>::new();
        builder.enable_keccak_f1600::<F>();

        // The address is the nullifier digest. In the real transfer this is
        // computed in-circuit from sk_d and rho; here it is a constant, which
        // exercises the same bit decomposition and the same fold.
        let nullifier_limbs = const_limbs(&mut builder, probe.as_bytes());
        let (root_before, root_after) =
            constrain_nullifier_non_membership(&mut builder, &nullifier_limbs, witness)?;

        for (actual, expected) in [(&root_before, expect_before), (&root_after, expect_after)] {
            let expected_limbs = const_limbs(&mut builder, expected);
            for limb in 0..KECCAK256_DIGEST_LIMBS {
                let diff = builder.sub(actual[limb], expected_limbs[limb]);
                builder.assert_zero(diff);
            }
        }

        let circuit = builder.build()?;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[])?;
        runner.set_private_inputs(&[])?;
        runner.run()?;
        Ok(())
    }

    #[test]
    fn circuit_fold_matches_native_map() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        for seed in 1u8..=4 {
            assert!(map.insert(&nf([seed; 32])));
        }
        let probe = nf([200u8; 32]);
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");

        let before = map.root_before(&w, &probe);
        let after = map.root_after(&w, &probe);
        fold_and_check(&probe, &prepared, before.as_bytes(), after.as_bytes())
            .expect("circuit fold must reproduce the native roots");
    }

    #[test]
    fn circuit_rejects_a_wrong_root_before() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        for seed in 1u8..=4 {
            assert!(map.insert(&nf([seed; 32])));
        }
        let probe = nf([200u8; 32]);
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");

        let mut bogus = *map.root_before(&w, &probe).as_bytes();
        bogus[0] ^= 1;
        let after = map.root_after(&w, &probe);
        assert!(
            fold_and_check(&probe, &prepared, &bogus, after.as_bytes()).is_err(),
            "a wrong root_before must violate a constraint"
        );
    }

    #[test]
    fn circuit_rejects_a_wrong_root_after() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        for seed in 1u8..=4 {
            assert!(map.insert(&nf([seed; 32])));
        }
        let probe = nf([200u8; 32]);
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");

        let before = map.root_before(&w, &probe);
        let mut bogus = *map.root_after(&w, &probe).as_bytes();
        bogus[31] ^= 0x80;
        assert!(
            fold_and_check(&probe, &prepared, before.as_bytes(), &bogus).is_err(),
            "a wrong root_after must violate a constraint"
        );
    }

    #[test]
    fn circuit_rejects_a_witness_of_the_wrong_length() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        assert!(map.insert(&nf([1u8; 32])));
        let probe = nf([200u8; 32]);
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let mut prepared = prepare_witness(&map, &w).expect("fits fold budget");
        prepared.siblings.pop();

        let mut builder = CircuitBuilder::<Challenge>::new();
        builder.enable_keccak_f1600::<F>();
        let limbs = const_limbs(&mut builder, probe.as_bytes());
        assert!(constrain_nullifier_non_membership(&mut builder, &limbs, &prepared).is_err());
    }

    #[test]
    fn dense_map_is_reported_not_silently_padded() {
        // A nullifier differing from the probe at bit 0 forces start_height 0,
        // far below the circuit floor. That must be an explicit error: padding
        // it anyway would assert an emptiness that does not hold.
        let mut map = NullifierMap::new(Keccak256Commitment);
        let probe = [0u8; 32];
        let near = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        assert!(map.insert(&nf(near)));
        let w = map.non_inclusion_witness(&nf(probe)).expect("probe absent");
        let err = prepare_witness(&map, &w).expect_err("must refuse a dense map");
        assert!(err.contains("too dense"), "unexpected error: {err}");
    }

    #[test]
    fn padding_a_higher_start_height_is_exact() {
        // When the true start is above FOLD_START the bottom levels are empty
        // constants, so the padded fold must still land on the same roots.
        let mut map = NullifierMap::new(Keccak256Commitment);
        let far = {
            let mut b = [0u8; 32];
            b[31] = 0x80;
            b
        };
        assert!(map.insert(&nf(far)));
        let probe = nf([0u8; 32]);
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        assert_eq!(w.start_height, 255, "only the top bit differs");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");
        fold_and_check(
            &probe,
            &prepared,
            map.root_before(&w, &probe).as_bytes(),
            map.root_after(&w, &probe).as_bytes(),
        )
        .expect("padded fold must match the native roots");
    }
}
