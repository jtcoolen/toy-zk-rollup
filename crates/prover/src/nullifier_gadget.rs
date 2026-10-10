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
//! # Hasher
//!
//! The fold is Poseidon2 - the same permutation, and the same table, the note
//! Merkle tree uses. It used to be Keccak-f[1600], which cost 24 wide rows per
//! level and made the nullifier fold the widest instance in the client proof;
//! D-092 batch 82 moved it here. The collision margin is the sponge's, not
//! SHA3's - a reduction the operator accepted (D-092).
//!
//! # Why the shape is fixed
//!
//! A circuit cannot have a data-dependent number of rows, so the variable part
//! of the native witness - how far down the tree the empty subtree starts - is
//! replaced by a compile-time budget. `FOLD_DEPTH` is the number of levels the
//! absence fold runs. The prover must supply a witness whose empty subtree
//! reaches at least `NULLIFIER_TREE_DEPTH - FOLD_DEPTH`, i.e. the map must be
//! sparse enough at that level. That is a capacity parameter in the same spirit
//! as `LOG_MAX_LDE`: too small and proving fails loudly, never silently.
//!
//! Emptiness is downward-closed inside a containing subtree, so if the subtree
//! at height `h` is empty then so is the one at any lower `h0 <= h`. That is
//! what lets a fixed `h0 = NULLIFIER_TREE_DEPTH - FOLD_DEPTH` stand in for a
//! larger true `h`, padding the bottom of the fold with empty-subtree
//! constants.
//!
//! # Where the address bits come from
//!
//! The address is the nullifier, and the nullifier is already computed in this
//! circuit as `H(DOMAIN_NULLIFIER || sk_d || rho)`. The direction bits are
//! decomposed from that digest's exported limbs, so the prover never chooses an
//! address - it is derived from the witness that produced the nullifier. A
//! prover who could pick the address could route a spend around the
//! empty-subtree check. Only the low [`NULLIFIER_TREE_DEPTH`] bits are the
//! address, matching the native map's masked address.
//!
//! # Cost, stated plainly
//!
//! The absence fold is `FOLD_DEPTH` Poseidon2 permutations. The insert fold
//! runs from the leaf all the way to the root - `NULLIFIER_TREE_DEPTH`
//! permutations - because the empty-collapse that makes absence cheap only
//! applies when *both* children are empty, and the inserted leaf is not.
//! Sparsity does not help the insert direction. At one permutation row per
//! level that is `FOLD_DEPTH + NULLIFIER_TREE_DEPTH` permutation rows per
//! nullifier, on the same narrow table the note tree already pays for.

use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use pq_hash::CommitmentHasher;
use pq_hash::Digest32;
use shielded::nullifier_tree::{NonInclusionWitness, NullifierMap, NULLIFIER_TREE_DEPTH};

use crate::commitment_gadget::{
    DIGEST_EXT, DigestExpr, digest_to_ext, export_digest_limbs, p2_compress,
};
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

/// The number of 16-bit digest limbs the address bits are read from: the low
/// `NULLIFIER_TREE_DEPTH` bits of the digest, one limb per 16 bits.
const ADDR_LIMBS: usize = NULLIFIER_TREE_DEPTH / 16;

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
            "nullifier map too dense for this circuit: the empty subtree containing \
             the address starts at height {}, below the circuit floor of {FOLD_START} \
             (FOLD_DEPTH = {FOLD_DEPTH})",
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

/// Decompose the low [`NULLIFIER_TREE_DEPTH`] address bits from a digest's
/// exported limbs.
///
/// Limb `i` holds digest bits `16i .. 16i+16` little-endian (each limb is two
/// little-endian bytes), which matches the native `addr_bit`: bit `i` of the
/// address is bit `i % 16` of limb `i / 16`. Bits at or above
/// `NULLIFIER_TREE_DEPTH` are not the address and are never read - the native
/// map masks them out the same way, so the two sides agree on which digests
/// collide.
fn digest_bits(
    builder: &mut CircuitBuilder<Challenge>,
    limbs: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut bits = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
    for limb in limbs.iter().take(ADDR_LIMBS) {
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

/// A digest constant as circuit expressions.
///
/// # Errors
///
/// [`CircuitBuilderError::MissingOutput`] if the digest is not a canonical
/// field-element encoding - which for a witness digest means corruption, since
/// every honest digest is a Poseidon2 output.
fn const_digest(
    builder: &mut CircuitBuilder<Challenge>,
    digest: &Digest32,
) -> Result<DigestExpr, CircuitBuilderError> {
    let ext = digest_to_ext(digest).ok_or(CircuitBuilderError::MissingOutput)?;
    Ok([builder.define_const(ext[0]), builder.define_const(ext[1])])
}

/// Fold `start` upward through `siblings`, one Poseidon2 permutation per level.
///
/// Direction at each level is taken from `bits`, so the caller controls how the
/// path is chosen and the prover cannot steer it.
///
/// H-03: siblings arrive as already-built expressions - witnesses for the
/// note-specific path, constants only for the public empty-subtree levels.
/// Preprocessed columns are committed publicly and unblinded, so a constant
/// sibling path would reveal the nullifier's position to whoever holds the
/// verifying key.
fn fold_up(
    builder: &mut CircuitBuilder<Challenge>,
    start: DigestExpr,
    start_height: usize,
    siblings: &[DigestExpr],
    bits: &[ExprId],
) -> Result<DigestExpr, CircuitBuilderError> {
    let mut current = start;
    for (offset, sibling_expr) in siblings.iter().enumerate() {
        let level = start_height + offset;
        let go_right = bits[level];
        builder.assert_bool(go_right);

        // `go_right = 1` puts the sibling on the left, matching the native
        // fold where the node's own address bit selects the side the sibling
        // occupies.
        let left = [
            builder.select(go_right, sibling_expr[0], current[0]),
            builder.select(go_right, sibling_expr[1], current[1]),
        ];
        let right = [
            builder.select(go_right, current[0], sibling_expr[0]),
            builder.select(go_right, current[1], sibling_expr[1]),
        ];
        current = p2_compress(builder, &left, &right)?;
    }
    Ok(current)
}

/// Constrain a nullifier's absence and its insertion, returning the two roots.
///
/// `nullifier` must be the in-circuit digest of the nullifier, so the address
/// bits are derived rather than declared. The returned digests are the roots
/// the transfer's statement must export; the settlement contract checks each
/// against the root it holds.
///
/// # Errors
///
/// Returns [`CircuitBuilderError`] if the witness is short, if a digest is not
/// canonical, or if a limb cannot be decomposed.
pub fn constrain_nullifier_non_membership(
    builder: &mut CircuitBuilder<Challenge>,
    nullifier: &DigestExpr,
    witness: &NullifierWitness,
    private: &mut Vec<Challenge>,
) -> Result<(DigestExpr, DigestExpr), CircuitBuilderError> {
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

    let limbs = export_digest_limbs(builder, nullifier)?;
    let bits = digest_bits(builder, &limbs)?;

    // H-03: the note-specific sibling path is a *witness*, allocated once and
    // shared by both folds - the same expressions feed the absence fold and the
    // insert fold, so the two folds provably walk the same path. A free path is
    // no weaker than a constant one: both folds are pinned to roots the
    // statement exports, and a path that does not fold to them witnesses
    // nothing.
    let mut sibling_exprs = Vec::with_capacity(witness.siblings.len());
    for sibling in &witness.siblings {
        let packed = digest_to_ext(sibling).ok_or(CircuitBuilderError::MissingOutput)?;
        let exprs = builder.alloc_private_inputs(DIGEST_EXT, "nullifier.sibling");
        private.push(packed[0]);
        private.push(packed[1]);
        sibling_exprs.push([exprs[0], exprs[1]]);
    }

    // Absence: start from the empty-subtree constant at FOLD_START. The
    // constant is not a witness, so nothing is being trusted about it - the
    // fold either reaches the root or the nullifier was not absent.
    // `lower_empties` is indexed by height and its length is checked above, so
    // this index cannot fail. A silent default would substitute a zero digest
    // and weaken the fold, so the failure is explicit instead.
    let start = witness
        .lower_empties
        .get(FOLD_START)
        .ok_or(CircuitBuilderError::MissingOutput)?;
    let start = const_digest(builder, start)?;
    let root_before = fold_up(builder, start, FOLD_START, &sibling_exprs, &bits)?;

    // Insertion: the same sibling path, but starting from the nullifier's own
    // digest at the leaf level, with the empty-subtree constants below
    // FOLD_START.
    // Only the first FOLD_START entries are siblings here. `lower_empties`
    // carries heights `0..=FOLD_START`, and the top one is the absence fold's
    // *starting node*, not a level the insert fold consumes - including it
    // would push the insert fold one level past the root.
    // The lower levels are the public empty-subtree digests - identical for
    // every transfer of this shape, so constants remain the right encoding
    // (H-03 constrains only note-specific values).
    let mut insert_siblings: Vec<DigestExpr> = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
    for empty in &witness.lower_empties[..FOLD_START] {
        insert_siblings.push(const_digest(builder, empty)?);
    }
    insert_siblings.extend_from_slice(&sibling_exprs);
    let root_after = fold_up(builder, *nullifier, 0, &insert_siblings, &bits)?;

    Ok((root_before, root_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_gadget::DIGEST_LIMBS;
    use crate::transfer::const_limbs;
    use crate::whir_recursion::{Challenge, F};
    use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
    use p3_poseidon2_circuit_air::KoalaBearD4Width16;
    use crate::whir_recursion::whir_perm;
    use pq_hash::{Digest32, Nullifier, Poseidon2Commitment};

    /// A nullifier whose digest is a canonical field encoding: every digest
    /// the real system holds is a Poseidon2 output, and the fold parses digests
    /// as field elements, so test probes must be too.
    fn nf(tag: &[u8]) -> Nullifier {
        Nullifier::from_digest(Poseidon2Commitment::default().hash(&[b"probe", tag]))
    }

    /// Build a circuit that folds `probe`'s witness and asserts the two roots
    /// equal the supplied expectations, then run it.
    ///
    /// A successful run means the in-circuit fold produced exactly those roots;
    /// a constraint violation means it did not. This is the native/circuit
    /// equivalence check - the circuit is never trusted to agree with the map,
    /// only tested against it.
    fn fold_and_check(
        probe: &Nullifier,
        witness: &NullifierWitness,
        expect_before: &[u8; 32],
        expect_after: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = CircuitBuilder::<Challenge>::new();
        builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            whir_perm(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

        // The address is the nullifier digest. In the real transfer this is
        // computed in-circuit from sk_d and rho; here it is a constant, which
        // exercises the same bit decomposition and the same fold.
        let ext = digest_to_ext(&Digest32::new(*probe.as_bytes())).expect("canonical");
        let probe_digest: DigestExpr = [
            builder.define_const(ext[0]),
            builder.define_const(ext[1]),
        ];
        let mut private = Vec::new();
        let (root_before, root_after) =
            constrain_nullifier_non_membership(&mut builder, &probe_digest, witness, &mut private)?;

        for (actual, expected) in [(&root_before, expect_before), (&root_after, expect_after)] {
            let got = export_digest_limbs(&mut builder, actual)?;
            let want = const_limbs(&mut builder, expected);
            for limb in 0..DIGEST_LIMBS {
                let diff = builder.sub(got[limb], want[limb]);
                builder.assert_zero(diff);
            }
        }

        let circuit = builder.build()?;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[])?;
        runner.set_private_inputs(&private)?;
        runner.run()?;
        Ok(())
    }

    fn populated_map() -> NullifierMap<Poseidon2Commitment> {
        let mut map = NullifierMap::new(Poseidon2Commitment::default());
        for seed in 1u8..=4 {
            assert!(map.insert(&nf(&[seed])));
        }
        map
    }

    #[test]
    fn circuit_fold_matches_native_map() {
        let map = populated_map();
        let probe = nf(b"probe");
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");

        let before = map.root_before(&w, &probe);
        let after = map.root_after(&w, &probe);
        fold_and_check(&probe, &prepared, before.as_bytes(), after.as_bytes())
            .expect("circuit fold must reproduce the native roots");
    }

    #[test]
    fn circuit_rejects_a_wrong_root_before() {
        let map = populated_map();
        let probe = nf(b"probe");
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
        let map = populated_map();
        let probe = nf(b"probe");
        let w = map.non_inclusion_witness(&probe).expect("probe absent");
        let prepared = prepare_witness(&map, &w).expect("fits fold budget");

        let before = map.root_before(&w, &probe);
        let mut bogus = *map.root_after(&w, &probe).as_bytes();
        bogus[31] ^= 0x80;
        assert!(
            fold_and_check(&probe, &prepared, &before.as_bytes(), &bogus).is_err(),
            "a wrong root_after must violate a constraint"
        );
    }
}
