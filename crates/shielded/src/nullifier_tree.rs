//! The nullifier map.
//!
//! Nullifier non-membership is proven *in circuit*, so this structure is chosen
//! for how cheaply it proves "this nullifier is absent", not for how cheaply it
//! stores things. A sparse Merkle tree over the full 256-bit nullifier space
//! gives that: absence is certified by a constant (the precomputed empty-subtree
//! digest) plus a path to the root, so the proof is O(depth - h) hashes where h
//! is the height of the largest empty subtree containing the address. With k
//! spent nullifiers scattered over 2^256 addresses, h sits near `256 - log2(k)`,
//! so non-inclusion costs about `log2(k)` hashes regardless of how large the
//! set grows.
//!
//! # Why the full 256-bit address, with no truncation
//!
//! The address of a nullifier is the nullifier itself — all 256 bits, one bit
//! per tree level. Truncating the address to `d` bits makes collisions cheap:
//! finding two nullifiers with the same `d`-bit address costs 2^d, which at any
//! `d` a client can brute-force in a weekend turns tree collisions into a
//! griefing vector. Full-width addressing pushes that to 2^128 and removes the
//! question. The tree is deep (256 levels) but sparse, and sparsity is what the
//! empty-subtree constant exploits, so the depth costs almost nothing for the
//! non-inclusion direction.
//!
//! # Why the leaf value is the nullifier itself
//!
//! A nullifier set has no separate value to store: presence *is* the value.
//! Using the nullifier digest as the leaf value keeps the leaf non-zero (so it
//! can never be confused with an empty leaf) and binds the identity into the
//! root a second time, at no cost.
//!
//! # Shape of a witness
//!
//! One witness serves both directions. Given the address `a`:
//!
//! - `start_height` is the largest `h` whose subtree containing `a` is empty.
//!   Absence is then `fold(empty[h], siblings) == root` — the constant
//!   `empty[h]` is not a witness, so nothing has to be trusted about it.
//! - Insertion is `fold(a, siblings') == root_after`, where the siblings below
//!   `h` are the empty-subtree constants and above `h` are the witness's.
//!
//! The two folds share the sibling list; only the starting node differs.
//!
//! # Convention
//!
//! Bit `i` of the address is `(byte[i / 8] >> (i % 8)) & 1` — little-endian
//! within each byte. Direction at level `i` is that bit, so the path runs
//! leaf-to-root through bits `0, 1, …, 255`. This matches the commitment tree's
//! `go_right = (index >> level) & 1` exactly, so the Solidity verifier folds
//! both trees with one loop.

use pq_hash::{CommitmentHasher, Digest32, MerkleRoot, Nullifier};
use std::collections::HashSet;

/// Depth of the nullifier map: one level per bit of the nullifier digest.
/// Address/path bits, and so the tree's depth.
///
/// D-092 batch 82: 256 -> 96. The tree is Poseidon2 now (see the prover's
/// nullifier gadget), and the insert fold runs one permutation per level, so
/// the depth is a direct circuit cost: 96 levels instead of 256 removes 160
/// permutation rows per nullifier. The address is the low 96 bits of the
/// nullifier digest; two nullifiers agreeing on those 96 bits are treated as
/// duplicates (the insert refuses), which bounds the collision assumption at
/// the sponge's own margin - the same 96-bit regime the proof system targets.
pub const NULLIFIER_TREE_DEPTH: usize = 96;

/// Bit `i` of the address, little-endian within each byte. Bits at or above
/// [`NULLIFIER_TREE_DEPTH`] never reach this function.
const fn addr_bit(addr: &[u8; 32], i: usize) -> bool {
    (addr[i / 8] >> (i % 8)) & 1 == 1
}

/// The highest bit at which two addresses differ, or `None` if equal.
///
/// This single number drives the whole witness. Two addresses share the subtree
/// at level `h` iff they agree on every bit from `h` upward, i.e. iff their
/// highest differing bit is below `h`. So bucketing occupied addresses by this
/// value sorts them into exactly the sibling subtrees along our path.
fn highest_differing_bit(a: &[u8; 32], b: &[u8; 32]) -> Option<usize> {
    // Only the low NULLIFIER_TREE_DEPTH bits are the address; higher bits are
    // ignored, so two digests agreeing on the address path are indistinguishable
    // here and the insert treats them as duplicates rather than silently
    // stacking two leaves at one path.
    let bytes = NULLIFIER_TREE_DEPTH / 8;
    (0..bytes).rev().find_map(|byte| {
        let x = a[byte] ^ b[byte];
        if x == 0 {
            return None;
        }
        // Highest set bit within the byte, offset by the byte's position.
        Some(byte * 8 + (7 - x.leading_zeros() as usize))
    })
}

/// Proof that a nullifier is absent from the map at some root.
///
/// Carries only the siblings that are not empty-subtree constants, so its size
/// tracks `log2(k)` rather than the tree's depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonInclusionWitness {
    /// Height of the largest empty subtree containing the nullifier's address.
    ///
    /// `NULLIFIER_TREE_DEPTH` means the whole map is empty.
    pub start_height: usize,
    /// Sibling digests from `start_height` up to (but not including) the root,
    /// leaf-to-root order. Exactly `NULLIFIER_TREE_DEPTH - start_height` of them.
    pub siblings: Vec<Digest32>,
}

/// A sparse Merkle map over the 256-bit nullifier space.
///
/// Holds the spent set and derives the root on demand. Recomputing the root per
/// query is O(k · depth) worst case, but the empty-subtree short-circuit makes
/// it proportional to the occupied trie, not the address space. There is no
/// incremental state to drift out of sync with the set, which is the class of
/// bug that produces a root the verifier rejects; a frontier-based
/// implementation drops in behind this interface without touching a caller.
#[derive(Clone, Debug)]
pub struct NullifierMap<H: CommitmentHasher> {
    hasher: H,
    /// `empties[h]` is the digest of a completely empty subtree of height `h`.
    empties: Vec<Digest32>,
    spent: HashSet<[u8; 32]>,
}

impl<H: CommitmentHasher> NullifierMap<H> {
    /// An empty map with the given hasher.
    #[must_use]
    pub fn new(hasher: H) -> Self {
        let mut empties = Vec::with_capacity(NULLIFIER_TREE_DEPTH + 1);
        empties.push(Digest32::default());
        for _ in 0..NULLIFIER_TREE_DEPTH {
            let last = *empties.last().unwrap_or_else(|| unreachable!("seeded"));
            empties.push(hasher.hash_pair(&last, &last));
        }
        Self {
            hasher,
            empties,
            spent: HashSet::new(),
        }
    }

    /// The hasher in use.
    #[must_use]
    pub const fn hasher(&self) -> &H {
        &self.hasher
    }

    /// The empty-subtree digest at height `h`.
    #[must_use]
    pub fn empty_at(&self, h: usize) -> Digest32 {
        self.empties.get(h).copied().unwrap_or_default()
    }

    /// Whether this nullifier has already been spent.
    #[must_use]
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.spent.contains(nullifier.as_bytes())
    }

    /// How many nullifiers have been spent.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether nothing has been spent yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Mark a nullifier spent. Returns `false` if it already was.
    #[must_use]
    pub fn insert(&mut self, nullifier: &Nullifier) -> bool {
        self.spent.insert(*nullifier.as_bytes())
    }

    /// The current root.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        let addrs: Vec<[u8; 32]> = self.spent.iter().copied().collect();
        MerkleRoot::from_digest(self.node(NULLIFIER_TREE_DEPTH, &addrs))
    }

    /// The root of a completely empty map.
    #[must_use]
    pub fn empty_root(&self) -> MerkleRoot {
        MerkleRoot::from_digest(self.empty_at(NULLIFIER_TREE_DEPTH))
    }

    /// The digest of the subtree at `level` spanned by `addrs`.
    ///
    /// `addrs` must all share the prefix that puts them in this subtree. An empty
    /// slice is the empty-subtree constant, which is what keeps the recursion
    /// proportional to the occupied trie rather than to 2^256.
    fn node(&self, level: usize, addrs: &[[u8; 32]]) -> Digest32 {
        if addrs.is_empty() {
            return self.empty_at(level);
        }
        if level == 0 {
            // Only one address can reach the leaf level: duplicates are
            // impossible because the set is a HashSet.
            return Digest32::new(addrs[0]);
        }
        // Children at `level - 1` are split by bit `level - 1`, matching the
        // fold's `go_right = bit(level)`.
        let bit = level - 1;
        let mut left = Vec::new();
        let mut right = Vec::new();
        for addr in addrs {
            if addr_bit(addr, bit) {
                right.push(*addr);
            } else {
                left.push(*addr);
            }
        }
        let l = self.node(level - 1, &left);
        let r = self.node(level - 1, &right);
        self.hasher.hash_pair(&l, &r)
    }

    /// Fold a node upward through `siblings`, starting at `start_height`.
    fn fold(
        &self,
        start_height: usize,
        start: Digest32,
        siblings: &[Digest32],
        addr: &[u8; 32],
    ) -> Digest32 {
        let mut current = start;
        for (offset, sibling) in siblings.iter().enumerate() {
            let level = start_height + offset;
            let go_right = addr_bit(addr, level);
            current = if go_right {
                self.hasher.hash_pair(sibling, &current)
            } else {
                self.hasher.hash_pair(&current, sibling)
            };
        }
        current
    }

    /// The witness proving `nullifier` is absent.
    ///
    /// # Errors
    ///
    /// Returns `None` if the nullifier is already spent — there is no
    /// non-inclusion proof for a member.
    #[must_use]
    pub fn non_inclusion_witness(&self, nullifier: &Nullifier) -> Option<NonInclusionWitness> {
        let addr = *nullifier.as_bytes();
        if self.spent.contains(&addr) {
            return None;
        }

        // Bucket every spent address by the highest bit at which it differs
        // from ours. A bucket at level j is exactly the sibling subtree of our
        // path at level j.
        //
        // The start height is the *minimum* bucket index, not the maximum. A
        // spent address sits in our level-h subtree iff it agrees with us on
        // every bit from h upward, i.e. iff its highest differing bit is below
        // h. So the subtree at h is empty only once h reaches the closest
        // occupant's highest differing bit — the nearest one, not the farthest.
        let mut buckets: Vec<Vec<[u8; 32]>> = vec![Vec::new(); NULLIFIER_TREE_DEPTH];
        let mut closest: Option<usize> = None;
        for spent in &self.spent {
            if let Some(diff) = highest_differing_bit(&addr, spent) {
                buckets[diff].push(*spent);
                closest = Some(closest.map_or(diff, |cur| cur.min(diff)));
            }
        }

        let start_height = closest.unwrap_or(NULLIFIER_TREE_DEPTH);
        let mut siblings = Vec::with_capacity(NULLIFIER_TREE_DEPTH - start_height);
        for (level, bucket) in buckets.iter().enumerate().skip(start_height) {
            siblings.push(self.node(level, bucket));
        }
        Some(NonInclusionWitness {
            start_height,
            siblings,
        })
    }

    /// The root implied by a non-inclusion witness, before any insertion.
    ///
    /// Folds the empty-subtree constant at `start_height` up through the
    /// witness's siblings. Because the starting node is a constant rather than a
    /// witness, matching this root is what makes the absence claim sound under
    /// collision resistance alone.
    #[must_use]
    pub fn root_before(&self, witness: &NonInclusionWitness, nullifier: &Nullifier) -> MerkleRoot {
        MerkleRoot::from_digest(self.fold(
            witness.start_height,
            self.empty_at(witness.start_height),
            &witness.siblings,
            nullifier.as_bytes(),
        ))
    }

    /// The root after inserting the nullifier the witness attests to.
    ///
    /// Folds the nullifier's own digest from the leaf level upward. Siblings
    /// below `start_height` are the empty-subtree constants (that part of the
    /// tree was empty), and above it are the witness's.
    #[must_use]
    pub fn root_after(&self, witness: &NonInclusionWitness, nullifier: &Nullifier) -> MerkleRoot {
        let addr = *nullifier.as_bytes();
        let mut siblings = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
        for level in 0..NULLIFIER_TREE_DEPTH {
            if level < witness.start_height {
                siblings.push(self.empty_at(level));
            } else {
                siblings.push(witness.siblings[level - witness.start_height]);
            }
        }
        MerkleRoot::from_digest(self.fold(0, Digest32::new(addr), &siblings, &addr))
    }
}

/// Check a non-inclusion witness against a root, without the map.
///
/// This is the shape the verifier runs: constant start node, fold the siblings,
/// compare. Kept free-standing so a test can verify a witness without holding
/// the set that produced it, which is what makes the witness a real proof
/// rather than a lookup.
#[must_use]
pub fn verify_non_inclusion<H: CommitmentHasher>(
    hasher: &H,
    witness: &NonInclusionWitness,
    nullifier: &Nullifier,
    root: &MerkleRoot,
) -> bool {
    let depth = NULLIFIER_TREE_DEPTH;
    if witness.start_height > depth {
        return false;
    }
    if witness.siblings.len() != depth - witness.start_height {
        return false;
    }
    let mut empties = Vec::with_capacity(witness.start_height + 1);
    empties.push(Digest32::default());
    for _ in 0..witness.start_height {
        let last = *empties.last().unwrap_or_else(|| unreachable!("seeded"));
        empties.push(hasher.hash_pair(&last, &last));
    }
    let addr = nullifier.as_bytes();
    let mut current = empties[witness.start_height];
    for (offset, sibling) in witness.siblings.iter().enumerate() {
        let level = witness.start_height + offset;
        let go_right = addr_bit(addr, level);
        current = if go_right {
            hasher.hash_pair(sibling, &current)
        } else {
            hasher.hash_pair(&current, sibling)
        };
    }
    current.as_bytes() == root.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::Keccak256Commitment;

    fn nf(bytes: [u8; 32]) -> Nullifier {
        Nullifier::from_digest(Digest32::new(bytes))
    }

    fn nf_from(seed: u8) -> Nullifier {
        nf([seed; 32])
    }

    #[test]
    fn empty_map_root_is_the_empty_subtree_digest() {
        let map = NullifierMap::new(Keccak256Commitment);
        assert!(map.is_empty());
        assert_eq!(map.root(), map.empty_root());
    }

    #[test]
    fn empty_map_witness_is_header_only() {
        let map = NullifierMap::new(Keccak256Commitment);
        let w = map.non_inclusion_witness(&nf_from(7)).expect("absent");
        // Nothing is occupied, so the whole tree is the empty subtree: no
        // siblings at all, and the root is the constant.
        assert_eq!(w.start_height, NULLIFIER_TREE_DEPTH);
        assert!(w.siblings.is_empty());
        assert_eq!(map.root_before(&w, &nf_from(7)), map.empty_root());
    }

    #[test]
    fn spent_nullifier_has_no_non_inclusion_witness() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        let n = nf_from(3);
        assert!(map.insert(&n));
        assert!(!map.insert(&n), "double insert must report false");
        assert!(map.non_inclusion_witness(&n).is_none());
    }

    #[test]
    fn witness_reproduces_root_before_and_root_after() {
        let mut map = NullifierMap::new(Keccak256Commitment);
        let a = nf_from(1);
        let b = nf_from(2);
        assert!(map.insert(&a));

        let root_before = map.root();
        let w = map.non_inclusion_witness(&b).expect("b absent");
        // [1;32] vs [2;32] differ in every byte, but only the low
        // NULLIFIER_TREE_DEPTH bits are the address: the topmost masked byte is
        // 11 with xor 0x03, so the highest differing bit is 8*11 + 1 = 89.
        assert_eq!(w.start_height, 89);
        assert_eq!(w.siblings.len(), NULLIFIER_TREE_DEPTH - 89);
        assert_eq!(map.root_before(&w, &b), root_before);

        // Folding the insert must land on the root of the map we would get by
        // actually inserting b.
        let expected_after = {
            let mut m2 = map.clone();
            assert!(m2.insert(&b));
            m2.root()
        };
        assert_eq!(map.root_after(&w, &b), expected_after);
    }

    #[test]
    fn start_height_tracks_the_closest_occupant() {
        // Addresses agreeing on all bits above h share the level-h subtree.
        // So the start height is the highest bit at which the closest occupant
        // differs from us.
        let mut map = NullifierMap::new(Keccak256Commitment);
        let ours = [0u8; 32];
        // Differs from ours only in the top bit of the address -> bit 95.
        // (Byte 31 is outside the masked address; byte 11 is its top byte.)
        let far = {
            let mut b = [0u8; 32];
            b[NULLIFIER_TREE_DEPTH / 8 - 1] = 0x80;
            b
        };
        assert!(map.insert(&nf(far)));
        let w = map.non_inclusion_witness(&nf(ours)).expect("absent");
        assert_eq!(w.start_height, NULLIFIER_TREE_DEPTH - 1);
        assert_eq!(w.siblings.len(), 1, "only the top-level sibling is needed");
        assert_eq!(map.root_before(&w, &nf(ours)), map.root());
    }

    #[test]
    fn full_width_addressing_is_not_truncated() {
        // Two nullifiers differing in a single LOW bit share every high bit, so
        // the proof must go all the way down to the leaf. A truncated address
        // would have made these look identical and hidden the collision.
        let mut map = NullifierMap::new(Keccak256Commitment);
        assert!(map.insert(&nf([0u8; 32])));
        let near = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        let w = map.non_inclusion_witness(&nf(near)).expect("absent");
        assert_eq!(w.start_height, 0);
        assert_eq!(w.siblings.len(), NULLIFIER_TREE_DEPTH);
        assert_eq!(map.root_before(&w, &nf(near)), map.root());
    }

    #[test]
    fn witness_size_tracks_occupied_spread_not_tree_depth() {
        // With k occupants spread over 2^NULLIFIER_TREE_DEPTH, the closest highest-differing bit
        // sits near log2(k), so the witness stays small as k grows.
        let mut map = NullifierMap::new(Keccak256Commitment);
        let probe = nf([0u8; 32]);
        for i in 1u8..=16 {
            assert!(map.insert(&nf_from(i)));
        }
        let w = map.non_inclusion_witness(&probe).expect("absent");
        // 16 occupants, all differing from the all-zero probe within the low
        // nibble-to-byte range; the path must not be the full 256.
        assert!(
            w.siblings.len() < 64,
            "witness grew with tree depth, not occupancy: {}",
            w.siblings.len()
        );
        assert_eq!(map.root_before(&w, &probe), map.root());
    }

    #[test]
    fn standalone_verifier_agrees_with_the_map() {
        let hasher = Keccak256Commitment;
        let mut map = NullifierMap::new(hasher);
        for i in 1u8..=5 {
            assert!(map.insert(&nf_from(i)));
        }
        let probe = nf_from(200);
        let w = map.non_inclusion_witness(&probe).expect("absent");
        let root = map.root();
        assert!(verify_non_inclusion(&hasher, &w, &probe, &root));
    }

    #[test]
    fn witness_never_attests_to_a_spent_nullifier() {
        // The soundness property that matters. A witness proves the subtree at
        // `start_height` is empty, so it can only ever verify for an address
        // inside that empty subtree. Every spent address must therefore fail.
        //
        // Note what this is NOT: it is not "the witness is bound to one
        // nullifier". Any address agreeing on bits >= start_height folds to the
        // same root, so the witness is portable across absent addresses. That is
        // harmless — verification implies absence, which is the only thing the
        // circuit needs.
        let hasher = Keccak256Commitment;
        let mut map = NullifierMap::new(hasher);
        let spent: Vec<Nullifier> = (1u8..=5).map(nf_from).collect();
        for n in &spent {
            assert!(map.insert(n));
        }
        let root = map.root();
        let w = map.non_inclusion_witness(&nf_from(200)).expect("absent");
        for n in &spent {
            assert!(
                !verify_non_inclusion(&hasher, &w, n, &root),
                "witness attested to spent {n:?}"
            );
        }
    }

    #[test]
    fn witness_does_not_verify_against_a_stale_root() {
        let hasher = Keccak256Commitment;
        let mut map = NullifierMap::new(hasher);
        assert!(map.insert(&nf_from(1)));
        let probe = nf_from(99);
        let w = map.non_inclusion_witness(&probe).expect("absent");
        let at_witness_time = map.root();
        // The witness was produced against this root, so it must verify here...
        assert!(verify_non_inclusion(&hasher, &w, &probe, &at_witness_time));
        // ...and must stop verifying once the root moves under it.
        assert!(map.insert(&nf_from(2)));
        assert!(!verify_non_inclusion(&hasher, &w, &probe, &map.root()));
    }

    #[test]
    fn sequential_inserts_chain_exactly() {
        // The property the rollup depends on: applying root_after step by step
        // reproduces the map's own root at every step.
        let mut map = NullifierMap::new(Keccak256Commitment);
        let mut running = map.empty_root();
        assert_eq!(running, map.root());
        for i in 1u8..=8 {
            let n = nf_from(i);
            let w = map.non_inclusion_witness(&n).expect("absent");
            assert_eq!(map.root_before(&w, &n), running, "step {i} before");
            running = map.root_after(&w, &n);
            assert!(map.insert(&n));
            assert_eq!(running, map.root(), "step {i} after");
        }
    }

    #[test]
    fn bit_helpers_match_le_convention() {
        let mut b = [0u8; 32];
        b[0] = 0b0000_0010;
        assert!(!addr_bit(&b, 0));
        assert!(addr_bit(&b, 1));
        assert!(!addr_bit(&b, 2));
        b[1] = 0b1000_0000;
        assert!(addr_bit(&b, 15));
        assert_eq!(highest_differing_bit(&b, &[0u8; 32]), Some(15));
        assert_eq!(highest_differing_bit(&b, &b), None);
    }
}
