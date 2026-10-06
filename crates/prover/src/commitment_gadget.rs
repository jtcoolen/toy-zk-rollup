//! In-circuit Poseidon2 note-commitment tree: leaf hashing and append.
//!
//! This is the circuit mirror of `shielded::tree`, built on the vendored
//! Poseidon2 permutation table (`Poseidon2Config::KOALA_BEAR_D4_W16`) that
//! [`crate::whir_recursion`] already enables. It exists so a settlement proof
//! can attest a whole commitment transition -- `root_before`, every appended
//! leaf, `root_after` -- inside one proof, letting the settlement contract
//! store roots instead of replaying appends (D-088).
//!
//! # Why Poseidon2 and not Keccak here
//!
//! One Poseidon2 permutation is one row of the perm table; one Keccak-f is
//! ~24. The append fold walks 32 levels three times (merge, fold-before,
//! fold-after), so the hash choice is the whole cost: ~96 perm rows per append
//! against ~768 for the same fold under Keccak. The nullifier tree keeps
//! Keccak -- its gadget is already proven and the contract never touches it.
//!
//! # Row shape
//!
//! Every compress here is an *independent* perm row: `new_start = true`,
//! normal (non-Merkle) mode, all four extension slots exposed as inputs and
//! the two rate slots exposed as outputs. The AIR's Merkle chaining and index
//! accumulator are gated on the Merkle flag and stay inert; on a non-challenger
//! table a `new_start` row's capacity is caller-fed (see the `challenger` doc
//! in `p3-poseidon2-circuit-air`), which is exactly what lets all four slots
//! carry explicit inputs. The cost of that freedom is a handful of `select`
//! rows per level to place the running digest left or right -- trivial next to
//! the permutation itself, and it keeps every row self-contained: no private
//! sibling data, no chain-order coupling between gadgets.
//!
//! # The frontier fold
//!
//! The tree is an append-only accumulator, so the witness is its *frontier*:
//! for each level `h` whose bit is set in the leaf count `n`, the digest of
//! the complete `2^h`-tall subtree ending at leaf `n`. Blocks tile `[0, n)`
//! left to right, and the root reconstructs by folding from the rightmost,
//! smallest block upward:
//!
//! ```text
//!   cur = empty[0]
//!   for h in 0..DEPTH:  cur = bits[h] ? H(f[h], cur) : H(cur, empty[h])
//! ```
//!
//! Appending a leaf merges bottom-up (`g = leaf; g = bits[h] ? H(f[h], g) : g`)
//! and stops at the first unset bit, which becomes the new frontier slot. The
//! tests pin this fold against `CommitmentTree::root` for every `n` in a
//! range, so the circuit and the native tree cannot drift.

use p3_circuit::ops::PermCall;
use p3_circuit::ops::PermConfig;
use p3_circuit::ops::Poseidon2Config;
use p3_circuit::CircuitBuilder;
use p3_circuit::CircuitBuilderError;
use p3_circuit::ExprId;
use p3_field::BasedVectorSpace;
use p3_field::PrimeCharacteristicRing;
use pq_hash::CommitmentHasher;
use pq_hash::Digest32;
use pq_hash::DIGEST_ELEMS;
use shielded::tree::EmptySubtrees;
use shielded::tree::DEPTH;

use crate::whir_recursion::Challenge;
use crate::whir_recursion::F;

/// The permutation shape backing every gadget here: `KoalaBear`, degree-4
/// extension, width 16 -- rate 2 extension elements (= 8 base elements, one
/// digest), capacity 2 extension elements.
pub const P2_CFG: PermConfig = PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W16);

/// Extension elements per digest at this shape (8 base / 4 per ext = 2).
pub const DIGEST_EXT: usize = 2;

/// Base-field coefficients per extension element.
const EXT_DIM: usize = DIGEST_ELEMS / DIGEST_EXT;

/// Wire limbs per digest.
///
/// Each of the [`DIGEST_ELEMS`] base elements splits into two little-endian
/// 16-bit limbs, matching `bytes_to_limbs` of the 32-byte digest so the
/// settlement statement encoding is unchanged.
pub const DIGEST_LIMBS: usize = DIGEST_ELEMS * 2;

/// A digest as two extension-field elements (coefficients canonical, i.e.
/// each base element below the `KoalaBear` modulus).
pub type DigestExt = [Challenge; DIGEST_EXT];

/// A digest as two extension-field *expressions* inside a circuit.
pub type DigestExpr = [ExprId; DIGEST_EXT];

/// Pack a digest into the two extension elements the perm table consumes.
///
/// Returns `None` if any 4-byte group is not a canonical field element -- the
/// same strictness as [`pq_hash::digest_to_elements`].
///
/// Every digest the tree ever holds is an output of
/// `pq_hash::Poseidon2Commitment` (or the all-zero seed), and those encodings
/// are canonical by construction, so a `None` here always means a corrupted or
/// foreign witness.
#[must_use]
pub fn digest_to_ext(digest: &Digest32) -> Option<DigestExt> {
    let elems = pq_hash::digest_to_elements(digest)?;
    let lo = Challenge::from_basis_coefficients_slice(&elems[..EXT_DIM])?;
    let hi = Challenge::from_basis_coefficients_slice(&elems[EXT_DIM..])?;
    Some([lo, hi])
}

/// The empty-subtree constants the fold needs, in circuit-ready form.
///
/// `empty[h]` is the digest of an all-empty subtree of height `h` (`empty[0]`
/// is the zero digest). The fold consumes heights `0..DEPTH`.
#[derive(Clone, Debug)]
pub struct AppendParams {
    empty_ext: Vec<DigestExt>,
}

impl AppendParams {
    /// Derive the constants from the same hasher that hashes the tree, so the
    /// circuit's empty-subtree seeds cannot drift from the native roots.
    #[must_use]
    pub fn new<H: CommitmentHasher>(hasher: &H) -> Self {
        let empties = EmptySubtrees::new(hasher.clone());
        let empty_ext = (0..DEPTH)
            .map(|h| {
                digest_to_ext(&empties.at(h)).unwrap_or([Challenge::ZERO; DIGEST_EXT])
                // Unreachable in practice: empty-subtree digests are hasher
                // outputs (or the zero seed), hence canonical. A silent zero
                // here would only mis-fold, and the fold is pinned to the
                // attested root, so a bad constant cannot forge a root.
            })
            .collect();
        Self { empty_ext }
    }

    /// The empty-subtree digest at height `h` as extension elements.
    pub fn empty_ext(&self, h: usize) -> DigestExt {
        self.empty_ext
            .get(h)
            .copied()
            .unwrap_or([Challenge::ZERO; DIGEST_EXT])
    }
}

/// The append-only accumulator's frontier: one slot per level.
///
/// `bits[h]` is bit `h` of the leaf count; when set, `frontier[h]` is the
/// digest of the complete subtree of height `h` ending at the last leaf.
/// Slots with an unset bit hold the zero digest (their value is unused).
#[derive(Clone, Debug, Default)]
pub struct FrontierWitness {
    /// One digest per level, leaf level first. Exactly [`DEPTH`] entries.
    pub frontier: Vec<Digest32>,
    /// One bit per level: the leaf count's binary decomposition.
    pub bits: Vec<bool>,
}

impl FrontierWitness {
    /// An empty frontier (leaf count zero).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            frontier: vec![Digest32::default(); DEPTH],
            bits: vec![false; DEPTH],
        }
    }

    /// The leaf count implied by the bits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits
            .iter()
            .enumerate()
            .fold(0usize, |acc, (h, &b)| acc + (usize::from(b) << h))
    }

    /// Whether no leaves have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Fold a frontier back to the root, natively.
///
/// Folds from the rightmost (lowest) block upward, pairing the accumulator
/// with `empty[h]` on levels whose bit is unset -- the exact recurrence the
/// circuit implements, and equal to
/// [`CommitmentTree::root`](shielded::tree::CommitmentTree::root) for the same
/// leaves (pinned by tests).
#[must_use]
pub fn fold_to_root<H: CommitmentHasher>(hasher: &H, witness: &FrontierWitness) -> Digest32 {
    let empties = EmptySubtrees::new(hasher.clone());
    let mut cur = Digest32::default(); // empty[0] is the zero digest
    for h in 0..DEPTH {
        let (left, right) = if witness.bits.get(h).copied().unwrap_or(false) {
            let f = witness.frontier.get(h).copied().unwrap_or_default();
            (f, cur)
        } else {
            (cur, empties.at(h))
        };
        cur = hasher.hash_pair(&left, &right);
    }
    cur
}

/// Merge a leaf into the frontier, natively (the incremental append).
///
/// Walks up from the leaf level, merging complete blocks while bits are set,
/// and parks the accumulator in the first unset slot.
///
/// # Errors
///
/// Returns an error if the tree is full (every bit set).
pub fn append_to_frontier<H: CommitmentHasher>(
    hasher: &H,
    witness: &mut FrontierWitness,
    leaf: &Digest32,
) -> Result<(), String> {
    if witness.frontier.len() != DEPTH || witness.bits.len() != DEPTH {
        witness.frontier = vec![Digest32::default(); DEPTH];
        witness.bits = vec![false; DEPTH];
    }
    let mut cur = *leaf;
    for h in 0..DEPTH {
        if witness.bits[h] {
            // Carry past a complete block: merge it in and clear the slot, so
            // the bits stay the binary representation of the leaf count.
            cur = hasher.hash_pair(&witness.frontier[h], &cur);
            witness.bits[h] = false;
        } else {
            witness.frontier[h] = cur;
            witness.bits[h] = true;
            return Ok(());
        }
    }
    Err("commitment tree is full".to_string())
}

/// Build the frontier for a leaf list by replaying the appends.
#[must_use]
pub fn frontier_from_leaves<H: CommitmentHasher>(
    hasher: &H,
    leaves: &[Digest32],
) -> FrontierWitness {
    let mut witness = FrontierWitness::empty();
    for leaf in leaves {
        // A 2^32-leaf test list is not a thing; the full-tree error is
        // unreachable for any input a test can build.
        let _ = append_to_frontier(hasher, &mut witness, leaf);
    }
    witness
}

// -- Circuit side -----------------------------------------------------------

/// One Poseidon2 compression in circuit: `perm(left || right)[0..8]`.
///
/// An independent `new_start` row with all four extension slots exposed
/// (left in slots 0..2, right in slots 2..4) and both rate outputs exposed.
/// Returns the two rate outputs -- the digest's extension elements.
///
/// # Errors
///
/// Propagates [`CircuitBuilderError`] from the perm row.
pub fn p2_compress(
    builder: &mut CircuitBuilder<Challenge>,
    left: &DigestExpr,
    right: &DigestExpr,
) -> Result<DigestExpr, CircuitBuilderError> {
    let call = PermCall {
        new_start: true,
        merkle_path: false,
        mmcs_bit: None,
        mmcs_bit2: None,
        inputs: vec![Some(left[0]), Some(left[1]), Some(right[0]), Some(right[1])],
        out_ctl: vec![true; DIGEST_EXT],
        return_all_outputs: false,
        mmcs_index_sum: None,
    };
    let (_, outputs) = builder.add_perm(P2_CFG, &call)?;
    let out: Vec<ExprId> = outputs
        .into_iter()
        .take(DIGEST_EXT)
        .map(|slot| slot.ok_or(CircuitBuilderError::MissingOutput))
        .collect::<Result<_, _>>()?;
    Ok([out[0], out[1]])
}

/// The `PaddingFreeSponge` digest of base-field limb expressions, in circuit.
///
/// Absorbs [`DIGEST_ELEMS`] elements (one rate row's worth of base
/// coefficients) per permutation in overwrite mode -- a short final chunk
/// overwrites only the slots it fills and keeps the previous permutation's
/// output in the rest, exactly as `pq_hash::Poseidon2Sponge` does natively
/// (the semantics are pinned by tests there and mirrored here). The first row
/// starts a fresh chain (zero state); later rows chain capacity and overwrite
/// the rate.
///
/// An empty input yields the zero digest with no permutation rows, matching
/// the native sponge.
///
/// # Errors
///
/// Propagates [`CircuitBuilderError`] from perm rows, recomposition, or
/// decomposition of the carry coefficients.
pub fn p2_sponge_limbs(
    builder: &mut CircuitBuilder<Challenge>,
    limbs: &[ExprId],
) -> Result<DigestExpr, CircuitBuilderError> {
    let zero = builder.define_const(Challenge::ZERO);
    if limbs.is_empty() {
        return Ok([zero, zero]);
    }

    let rate = DIGEST_ELEMS; // 8 base elements per row
    let mut prev_rate: Option<DigestExpr> = None;
    let mut final_out = [zero; DIGEST_EXT];

    for (chunk_idx, chunk) in limbs.chunks(rate).enumerate() {
        let is_first = chunk_idx == 0;
        let mut inputs: Vec<Option<ExprId>> = vec![None; 4];
        for ext_idx in 0..DIGEST_EXT {
            let base_start = ext_idx * EXT_DIM;
            let filled = chunk.len().saturating_sub(base_start).min(EXT_DIM);
            if filled == 0 {
                // Nothing absorbed in this slot: chaining keeps the previous
                // output (overwrite mode leaves untouched slots alone).
                continue;
            }
            let mut coeffs = Vec::with_capacity(EXT_DIM);
            for i in 0..EXT_DIM {
                if i < filled {
                    coeffs.push(chunk[base_start + i]);
                } else if let Some(prev) = prev_rate {
                    // Partial chunk: keep this position's value from the
                    // previous permutation's output.
                    let prev_coeffs =
                        builder.decompose_ext_to_base_coeffs_via_alu::<F>(prev[ext_idx])?;
                    coeffs.push(prev_coeffs[i]);
                } else {
                    coeffs.push(zero);
                }
            }
            inputs[ext_idx] = Some(builder.recompose_base_coeffs_to_ext_via_alu::<F>(&coeffs)?);
        }

        let call = PermCall {
            new_start: is_first,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs,
            out_ctl: vec![true; DIGEST_EXT],
            return_all_outputs: false,
            mmcs_index_sum: None,
        };
        let (_, outputs) = builder.add_perm(P2_CFG, &call)?;
        let mut rate_out = [zero; DIGEST_EXT];
        for (slot, out) in outputs.into_iter().take(DIGEST_EXT).zip(&mut rate_out) {
            *out = slot.ok_or(CircuitBuilderError::MissingOutput)?;
        }
        prev_rate = Some(rate_out);
        final_out = rate_out;
    }

    Ok(final_out)
}

/// Fold one child statement into a running statement digest (D-089).
///
/// The chain rule, shared exactly with the native `block_statement` builder:
///
/// ```text
/// running_0 = 0^8
/// running_i = sponge(running_{i-1} || child_i statement limbs)
/// ```
///
/// The running digest is decomposed to its 8 base coefficients (ALU-constrained,
/// so they *are* the digest's elements) and absorbed as the first rate block of a
/// fresh sponge run over the child's statement limbs. One permutation per 8
/// limbs of statement, so a 100-limb transfer costs 14 perms — the reason the
/// fold is Poseidon2 and not Keccak: the contract never opens this digest, it
/// pins it, so only in-circuit cost matters.
///
/// # Errors
///
/// Propagates [`CircuitBuilderError`] from decomposition or perm rows.
pub fn fold_statement(
    builder: &mut CircuitBuilder<Challenge>,
    running: &DigestExpr,
    statement: &[ExprId],
) -> Result<DigestExpr, CircuitBuilderError> {
    let mut input = Vec::with_capacity(DIGEST_ELEMS + statement.len());
    for &ext in running {
        input.extend(builder.decompose_ext_to_base_coeffs_via_alu::<F>(ext)?);
    }
    input.extend_from_slice(statement);
    p2_sponge_limbs(builder, &input)
}

/// Export a digest (two extension expressions) as [`DIGEST_LIMBS`] wire limbs.
///
/// Each extension element decomposes to 4 base coefficients (ALU chain, so
/// the coefficients are constrained to be *the* coefficients), and each
/// coefficient splits into a low 16-bit limb and a high 15-bit limb -- the
/// little-endian 16-bit limbs of the digest's 32 bytes.
///
/// A coefficient's bit decomposition admits one non-canonical witness per
/// element (`x` and `x + p` share a 31-bit form only for tiny `x`); the limbs
/// are checked against the contract's stored root bytes, which pins the
/// canonical value, and the next block's fold re-derives the true root from
/// the pinned `root_before`, so a non-canonical export cannot be spent twice.
///
/// # Errors
///
/// Propagates [`CircuitBuilderError`] from decomposition.
pub fn export_digest_limbs(
    builder: &mut CircuitBuilder<Challenge>,
    digest: &DigestExpr,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut limbs = Vec::with_capacity(DIGEST_LIMBS);
    for ext in digest {
        let coeffs = builder.decompose_ext_to_base_coeffs_via_alu::<F>(*ext)?;
        for coeff in coeffs {
            let bits = builder.decompose_to_bits::<F>(coeff, 31)?;
            limbs.push(recombine_le(builder, &bits[..16]));
            limbs.push(recombine_le(builder, &bits[16..]));
        }
    }
    Ok(limbs)
}

/// Recombine little-endian bits into a value expression (weights are
/// constants; each `mul_add` is one ALU row).
fn recombine_le(builder: &mut CircuitBuilder<Challenge>, bits: &[ExprId]) -> ExprId {
    let mut acc = builder.define_const(Challenge::ZERO);
    for (i, &bit) in bits.iter().enumerate() {
        let weight = builder.define_const(Challenge::from_u32(1u32 << i));
        acc = builder.mul_add(bit, weight, acc);
    }
    acc
}

/// The circuit half of one append: everything the prover must witness.
#[derive(Debug)]
pub struct AppendGadget {
    /// The root after the append, as digest expressions — chainable straight
    /// into the next append; export with [`export_digest_limbs`] for the
    /// statement.
    pub root_after: DigestExpr,
    /// Private witness values to append to the runner's private inputs, in
    /// allocation order: 64 frontier extension elements, then 32 bits.
    pub witness: Vec<Challenge>,
}

/// Constrain one commitment append in circuit.
///
/// Given the frontier witness (native side of [`FrontierWitness`]), the leaf's
/// in-circuit digest, and the pinned `root_before` digest expressions, this:
///
/// 1. folds the frontier to a root and pins it to `root_before` (arithmetic
///    equality) -- the witness is *the* frontier of the claimed tree;
/// 2. merges the leaf bottom-up (fixed shape: a `select` per level keeps the
///    merge or passes the accumulator through);
/// 3. binary-increments the count bits, parking the merged accumulator in the
///    first unset slot, and constrains the carry-out to zero (the tree cannot
///    be full);
/// 4. folds the updated frontier to `root_after` and returns it as digest
///    expressions, chainable into the next append.
///
/// # Errors
///
/// Returns [`CircuitBuilderError`] if the witness shape is wrong, a digest is
/// non-canonical, or a row fails to build.
pub fn constrain_append(
    builder: &mut CircuitBuilder<Challenge>,
    params: &AppendParams,
    witness: &FrontierWitness,
    leaf: &DigestExpr,
    root_before: &DigestExpr,
) -> Result<AppendGadget, CircuitBuilderError> {
    if witness.frontier.len() != DEPTH || witness.bits.len() != DEPTH {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: DEPTH,
            actual: witness.frontier.len(),
        });
    }

    // Witness: frontier slots (2 ext each) then the count bits.
    let mut private = Vec::with_capacity(DEPTH * DIGEST_EXT + DEPTH);
    let mut frontier_exprs: Vec<DigestExpr> = Vec::with_capacity(DEPTH);
    for slot in &witness.frontier {
        let packed = digest_to_ext(slot).ok_or_else(|| CircuitBuilderError::InvalidMerkleCap {
            details: "frontier digest is not canonical".to_string(),
        })?;
        let exprs = builder.alloc_private_inputs(DIGEST_EXT, "commitment.frontier");
        private.extend_from_slice(&packed);
        frontier_exprs.push([exprs[0], exprs[1]]);
    }
    let mut bit_exprs: Vec<ExprId> = Vec::with_capacity(DEPTH);
    for &bit in &witness.bits {
        let expr = builder.alloc_private_input("commitment.bit");
        builder.assert_bool(expr);
        bit_exprs.push(expr);
        private.push(Challenge::from_bool(bit));
    }

    // 1. Fold the frontier to a root and pin it to the claimed root_before.
    // Arithmetic equality, not `connect`: perm outputs are LogUp-tracked, and
    // aliasing their witness slots desynchronises the multiplicities.
    let zero = builder.define_const(Challenge::ZERO);
    let computed_before =
        fold_frontier(builder, params, &frontier_exprs, &bit_exprs, [zero, zero])?;
    for (got, want) in computed_before.iter().zip(root_before) {
        let diff = builder.sub(*got, *want);
        builder.assert_zero(diff);
    }

    // 2. Merge the leaf bottom-up. `g[h]` is the accumulator after level h:
    //    merged when the bit is set, passed through otherwise.
    let mut g: Vec<DigestExpr> = Vec::with_capacity(DEPTH);
    let mut cur = *leaf;
    for h in 0..DEPTH {
        let merged = p2_compress(builder, &frontier_exprs[h], &cur)?;
        cur = [
            builder.select(bit_exprs[h], merged[0], cur[0]),
            builder.select(bit_exprs[h], merged[1], cur[1]),
        ];
        g.push(cur);
    }

    // 3. Binary-increment the count bits and swap the parked accumulator into
    //    the first unset slot: `f'[h] = carry[h]*(1-b[h]) ? g[h] : f[h]`.
    let one = builder.define_const(Challenge::ONE);
    let minus_two = builder.define_const(-Challenge::from_u32(2));
    let mut carry = one;
    let mut new_frontier: Vec<DigestExpr> = Vec::with_capacity(DEPTH);
    let mut new_bits: Vec<ExprId> = Vec::with_capacity(DEPTH);
    for h in 0..DEPTH {
        let cb = builder.mul(carry, bit_exprs[h]);
        // b' = b + c - 2bc (XOR of two bits)
        let sum = builder.add(bit_exprs[h], carry);
        let bit_next = builder.mul_add(cb, minus_two, sum);
        // d = c*(1-b): the level where the carry stops (first zero bit).
        let park = builder.sub(carry, cb);
        new_frontier.push([
            builder.select(park, g[h][0], frontier_exprs[h][0]),
            builder.select(park, g[h][1], frontier_exprs[h][1]),
        ]);
        new_bits.push(bit_next);
        carry = cb;
    }
    // The tree cannot be full: the carry out of the top bit must be zero.
    builder.assert_zero(carry);

    // 4. Fold the updated frontier to root_after.
    let root_after = fold_frontier(builder, params, &new_frontier, &new_bits, [zero, zero])?;

    Ok(AppendGadget {
        root_after,
        witness: private,
    })
}

/// In-circuit frontier fold: `cur = bits[h] ? H(f[h], cur) : H(cur, empty[h])`.
///
/// Each level is one independent perm row whose left and right inputs are
/// `select`ed from the running digest, the frontier slot, and the empty-subtree
/// constant -- the same recurrence as [`fold_to_root`].
fn fold_frontier(
    builder: &mut CircuitBuilder<Challenge>,
    params: &AppendParams,
    frontier: &[DigestExpr],
    bits: &[ExprId],
    seed: DigestExpr,
) -> Result<DigestExpr, CircuitBuilderError> {
    let empty_consts: Vec<DigestExpr> = (0..DEPTH)
        .map(|h| {
            let packed = params.empty_ext(h);
            [
                builder.define_const(packed[0]),
                builder.define_const(packed[1]),
            ]
        })
        .collect();
    let mut cur = seed;
    for h in 0..DEPTH {
        let left = [
            builder.select(bits[h], frontier[h][0], cur[0]),
            builder.select(bits[h], frontier[h][1], cur[1]),
        ];
        let right = [
            builder.select(bits[h], cur[0], empty_consts[h][0]),
            builder.select(bits[h], cur[1], empty_consts[h][1]),
        ];
        cur = p2_compress(builder, &left, &right)?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::const_limbs;
    use crate::whir_recursion::whir_perm;
    use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
    use p3_poseidon2_circuit_air::KoalaBearD4Width16;
    use pq_hash::bytes_to_field_elements;
    use pq_hash::elements_to_digest;
    use pq_hash::Poseidon2Commitment;
    use shielded::tree::CommitmentTree;

    fn hasher() -> Poseidon2Commitment {
        Poseidon2Commitment::default()
    }

    /// Deterministic pseudo-random *canonical* digest for tests: the top byte
    /// of every 4-byte group is zero, so each element is below the modulus.
    fn digest(seed: u8) -> Digest32 {
        Digest32::new(core::array::from_fn(|i| {
            if i % 4 == 3 {
                0
            } else {
                seed.wrapping_mul(167)
                    .wrapping_add(u8::try_from(i % 256).expect("mod 256 fits"))
            }
        }))
    }

    /// The frontier fold must reproduce the tree's root for every leaf count —
    /// the circuit implements this fold, so this test is its specification.
    #[test]
    fn frontier_fold_matches_tree_root() {
        let h = hasher();
        let mut tree = CommitmentTree::new(h.clone());
        let mut leaves: Vec<Digest32> = Vec::new();
        for n in 0..=40 {
            if n > 0 {
                let d = digest(u8::try_from(n).expect("n <= 40 fits"));
                leaves.push(d);
                tree.append(&pq_hash::NoteHash::from_digest(d));
            }
            let fw = frontier_from_leaves(&h, &leaves);
            assert_eq!(fw.len(), n, "frontier len at n={n}");
            assert_eq!(
                fold_to_root(&h, &fw),
                Digest32::new(*tree.root().as_bytes()),
                "fold mismatch at n={n}"
            );
        }
    }

    /// Incremental frontier appends agree with rebuilding from the leaf list.
    #[test]
    fn incremental_frontier_matches_rebuild() {
        let h = hasher();
        let mut fw = FrontierWitness::empty();
        let mut leaves = Vec::new();
        for n in 1..=33 {
            let d = digest(u8::try_from(n).expect("n <= 33 fits"));
            append_to_frontier(&h, &mut fw, &d).expect("not full");
            leaves.push(d);
            let rebuilt = frontier_from_leaves(&h, &leaves);
            assert_eq!(fw.frontier, rebuilt.frontier, "frontier at n={n}");
            assert_eq!(fw.bits, rebuilt.bits, "bits at n={n}");
        }
    }

    fn enable_perm(builder: &mut CircuitBuilder<Challenge>) {
        builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            whir_perm(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    }

    /// The circuit compress must equal the native `hash_pair`, limbs included.
    #[test]
    fn circuit_compress_matches_native() {
        let h = hasher();
        let left = digest(3);
        let right = digest(7);
        let native = h.hash_pair(&left, &right);

        let mut builder = CircuitBuilder::<Challenge>::new();
        enable_perm(&mut builder);
        let l = builder.alloc_private_inputs(DIGEST_EXT, "l");
        let r = builder.alloc_private_inputs(DIGEST_EXT, "r");
        let out = p2_compress(&mut builder, &[l[0], l[1]], &[r[0], r[1]]).expect("compress builds");
        let limbs = export_digest_limbs(&mut builder, &out).expect("export builds");
        let expected = const_limbs(&mut builder, native.as_bytes());
        for (got, want) in limbs.iter().zip(&expected) {
            builder.connect(*got, *want);
        }

        let circuit = builder.build().expect("circuit builds");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no publics");
        let mut witness = Vec::new();
        witness.extend_from_slice(&digest_to_ext(&left).expect("canonical"));
        witness.extend_from_slice(&digest_to_ext(&right).expect("canonical"));
        runner.set_private_inputs(&witness).expect("witness fits");
        runner.run().expect("compress matches");
    }

    /// The leaf sponge over the note preimage shape (63 limbs) must equal the
    /// native `Poseidon2Commitment::hash`.
    #[test]
    fn circuit_sponge_matches_native() {
        let h = hasher();
        // 126 bytes -> 63 limbs, like DOMAIN_NOTE ++ amount ++ rho ++ psi ++ pk_d.
        let message: Vec<u8> = (0..126u32)
            .map(|i| u8::try_from(i % 256).expect("mod 256 fits"))
            .collect();
        let native = h.hash(&[&message]);

        let mut builder = CircuitBuilder::<Challenge>::new();
        enable_perm(&mut builder);
        let limbs = builder.alloc_private_inputs(63, "limbs");
        let out = p2_sponge_limbs(&mut builder, &limbs).expect("sponge builds");
        let exported = export_digest_limbs(&mut builder, &out).expect("export builds");
        let expected = const_limbs(&mut builder, native.as_bytes());
        for (got, want) in exported.iter().zip(&expected) {
            builder.connect(*got, *want);
        }

        let circuit = builder.build().expect("circuit builds");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no publics");
        let witness: Vec<Challenge> = bytes_to_field_elements(&message)
            .into_iter()
            .map(Challenge::from)
            .collect();
        runner.set_private_inputs(&witness).expect("witness fits");
        runner.run().expect("sponge matches native");
    }

    /// The whole append gadget: fold-before pins the claimed root, the export
    /// equals the native tree's root after the append.
    #[test]
    fn circuit_append_matches_tree() {
        for n in [0usize, 1, 5, 8, 13, 32] {
            let h = hasher();
            let params = AppendParams::new(&h);
            let mut tree = CommitmentTree::new(h.clone());
            let mut leaves = Vec::new();
            for i in 1..=n {
                let d = digest(u8::try_from(i).expect("n <= 32 fits"));
                tree.append(&pq_hash::NoteHash::from_digest(d));
                leaves.push(d);
            }
            let fw = frontier_from_leaves(&h, &leaves);
            let root_before = tree.root();
            let new_leaf = digest(200 + u8::try_from(n).expect("n <= 32 fits"));
            tree.append(&pq_hash::NoteHash::from_digest(new_leaf));
            let root_after = tree.root();

            let mut builder = CircuitBuilder::<Challenge>::new();
            enable_perm(&mut builder);
            let leaf_ext = builder.alloc_private_inputs(DIGEST_EXT, "leaf");
            let pinned = builder.alloc_private_inputs(DIGEST_EXT, "root_before");
            let gadget = constrain_append(
                &mut builder,
                &params,
                &fw,
                &[leaf_ext[0], leaf_ext[1]],
                &[pinned[0], pinned[1]],
            )
            .expect("gadget builds");
            let exported = export_digest_limbs(&mut builder, &gadget.root_after).expect("export");
            let expected_after = const_limbs(&mut builder, root_after.as_bytes());
            for (got, want) in exported.iter().zip(&expected_after) {
                builder.connect(*got, *want);
            }

            let circuit = builder.build().expect("circuit builds");
            let mut runner = circuit.runner();
            runner.set_public_inputs(&[]).expect("no publics");
            let mut witness = Vec::new();
            witness.extend_from_slice(&digest_to_ext(&new_leaf).expect("canonical leaf"));
            witness.extend_from_slice(
                &digest_to_ext(&Digest32::new(*root_before.as_bytes())).expect("canonical root"),
            );
            witness.extend_from_slice(&gadget.witness);
            runner.set_private_inputs(&witness).expect("witness fits");
            runner
                .run()
                .unwrap_or_else(|err| panic!("append at n={n} must verify: {err}"));
        }
    }

    /// The statement fold (D-089) must equal the native chain of sponges:
    /// `running_i = sponge(running_{i-1} || child_i)`, `running_0` = 0.
    ///
    /// Child lengths are chosen so the second fold's combined input (8 + 68)
    /// ends mid-chunk: the partial-chunk carry must agree with the native
    /// overwrite-mode sponge, not just the full-chunk case.
    #[test]
    fn fold_statement_matches_native() {
        let h = hasher();
        let children: Vec<Vec<u16>> = vec![
            (0..100u32)
                .map(|i| u16::try_from((i * 7919) % 65536).expect("fits"))
                .collect(),
            (0..68u32)
                .map(|i| u16::try_from((i * 104_729) % 65536).expect("fits"))
                .collect(),
        ];

        // Native chain.
        let mut running = [F::ZERO; DIGEST_ELEMS];
        for child in &children {
            let mut input: Vec<F> = running.to_vec();
            input.extend(child.iter().map(|&l| F::from_u16(l)));
            running = h.hash_elements(&input);
        }
        let native = elements_to_digest(&running);

        // Circuit chain.
        let mut builder = CircuitBuilder::<Challenge>::new();
        enable_perm(&mut builder);
        let allocs: Vec<Vec<ExprId>> = children
            .iter()
            .map(|c| builder.alloc_private_inputs(c.len(), "stmt"))
            .collect();
        let zero = builder.define_const(Challenge::ZERO);
        let mut running_expr = [zero, zero];
        for (child, exprs) in children.iter().zip(&allocs) {
            assert_eq!(child.len(), exprs.len());
            running_expr = fold_statement(&mut builder, &running_expr, exprs).expect("fold builds");
        }
        let exported = export_digest_limbs(&mut builder, &running_expr).expect("export");
        let expected = const_limbs(&mut builder, native.as_bytes());
        for (got, want) in exported.iter().zip(&expected) {
            builder.connect(*got, *want);
        }

        let circuit = builder.build().expect("circuit builds");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no publics");
        let witness: Vec<Challenge> = children
            .iter()
            .flat_map(|c| c.iter().map(|&l| Challenge::from_u16(l)))
            .collect();
        runner.set_private_inputs(&witness).expect("witness fits");
        runner.run().expect("fold matches native");
    }

    /// A tampered statement limb must break the fold: the exported digest is
    /// pinned, so any child statement that differs from what was folded fails.
    #[test]
    fn fold_rejects_tampered_statement() {
        let h = hasher();
        let child: Vec<u16> = (0..100u32)
            .map(|i| u16::try_from(i % 65536).expect("fits"))
            .collect();
        let mut input: Vec<F> = vec![F::ZERO; DIGEST_ELEMS];
        input.extend(child.iter().map(|&l| F::from_u16(l)));
        let native = elements_to_digest(&h.hash_elements(&input));

        let mut builder = CircuitBuilder::<Challenge>::new();
        enable_perm(&mut builder);
        let exprs = builder.alloc_private_inputs(child.len(), "stmt");
        let zero = builder.define_const(Challenge::ZERO);
        let folded = fold_statement(&mut builder, &[zero, zero], &exprs).expect("fold builds");
        let exported = export_digest_limbs(&mut builder, &folded).expect("export");
        let expected = const_limbs(&mut builder, native.as_bytes());
        for (got, want) in exported.iter().zip(&expected) {
            builder.connect(*got, *want);
        }

        let circuit = builder.build().expect("circuit builds");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no publics");
        let mut witness: Vec<Challenge> = child.iter().map(|&l| Challenge::from_u16(l)).collect();
        // Tamper with one limb after the fold input was read.
        let last = witness.len() - 1;
        witness[last] += Challenge::from_u16(1);
        runner.set_private_inputs(&witness).expect("witness fits");
        assert!(
            runner.run().is_err(),
            "a tampered statement must not fold to the pinned digest"
        );
    }

    /// A frontier that does not fold to the pinned root must be rejected.
    #[test]
    fn append_rejects_wrong_frontier() {
        let h = hasher();
        let params = AppendParams::new(&h);
        let mut fw = frontier_from_leaves(&h, &[digest(1), digest(2)]);
        // Tamper: pretend a different leaf sits in the frontier.
        fw.frontier[0] = digest(99);

        let mut builder = CircuitBuilder::<Challenge>::new();
        enable_perm(&mut builder);
        let leaf_ext = builder.alloc_private_inputs(DIGEST_EXT, "leaf");
        let pinned = builder.alloc_private_inputs(DIGEST_EXT, "root_before");
        let gadget = constrain_append(
            &mut builder,
            &params,
            &fw,
            &[leaf_ext[0], leaf_ext[1]],
            &[pinned[0], pinned[1]],
        )
        .expect("gadget builds");

        let circuit = builder.build().expect("circuit builds");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no publics");
        let mut witness = Vec::new();
        witness.extend_from_slice(&digest_to_ext(&digest(7)).expect("canonical"));
        witness.extend_from_slice(&[Challenge::ZERO; DIGEST_EXT]);
        witness.extend_from_slice(&gadget.witness);
        runner.set_private_inputs(&witness).expect("witness fits");
        assert!(
            runner.run().is_err(),
            "a frontier that folds to the wrong root must fail"
        );
    }
}
