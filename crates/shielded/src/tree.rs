//! The note commitment tree.
//!
//! A fixed-depth, append-only Merkle tree over note commitments. The chain
//! stores only the root; a prover shows a *path* to prove a note exists without
//! revealing which note it is.
//!
//! # Why fixed depth
//!
//! A variable-height tree makes the root depend on the leaf count, so the
//! verifier has to guess a path length and the root commits to less than it
//! should. Every production shielded pool uses a fixed depth with the empty
//! subtree hashes precomputed: the path is always `DEPTH` long, the root always
//! commits to the full capacity, and the Solidity verifier loops a known number
//! of times. That is the standard choice, so it is this one.
//!
//! # Why the path format is nailed down here
//!
//! The Solidity verifier walks the same paths. If Rust says "siblings ordered
//! leaf-to-root, side chosen by the index bit" and Solidity assumes something
//! else, proofs either fail forever or — worse — accept the wrong thing. So the
//! format is defined once, in this file, and tested against a golden vector the
//! contract consumes.
//!
//! # Hash choice
//!
//! Poseidon2 over `KoalaBear` via [`CommitmentHasher`] (D-088). The tree is
//! no longer verified by the EVM at all: the proof attests each append and the
//! contract only stores roots, so the hash only has to be cheap *in-circuit*,
//! where one Poseidon2 permutation is one AIR row (a Keccak-f would be ~24).
//! The nullifier tree keeps Keccak — its gadget is already proven in-circuit
//! and the contract never touches it either. See the layering in the map.

use pq_hash::{CommitmentHasher, Digest32, MerkleRoot, NoteHash};

/// The tree's fixed depth, i.e. the number of hashes from leaf to root.
///
/// 32 levels gives 2^32 leaves, matching the size budget of every deployed
/// shielded pool, and keeps the verifier's loop bound constant.
pub const DEPTH: usize = 32;

/// View a note commitment as a plain digest for tree folding.
///
/// A free function rather than a method: `NoteHash` belongs to `pq-hash`, and an
/// inherent impl on it here would not compile.
#[must_use]
pub(crate) const fn leaf_digest(leaf: &NoteHash) -> Digest32 {
    Digest32::new(*leaf.as_bytes())
}

/// The digest of an empty subtree of each height, computed once per hasher.
///
/// `empty[0]` is the zero digest (an empty leaf), and `empty[h]` is the hash of
/// two `empty[h - 1]`s. A partially-filled tree substitutes these for the
/// branches that have no leaves yet, which is what makes the root independent of
/// how much of the tree is actually populated.
#[derive(Clone, Debug)]
pub struct EmptySubtrees<H: CommitmentHasher> {
    hasher: H,
    empty: Vec<Digest32>,
}

impl<H: CommitmentHasher> EmptySubtrees<H> {
    /// Precompute the empty-subtree digests up to `DEPTH`.
    #[must_use]
    pub fn new(hasher: H) -> Self {
        let mut empty = Vec::with_capacity(DEPTH + 1);
        empty.push(Digest32::default());
        for _ in 0..DEPTH {
            let last = *empty.last().unwrap_or_else(|| unreachable!("seeded"));
            empty.push(hasher.hash_pair(&last, &last));
        }
        Self { hasher, empty }
    }

    /// The digest of an empty subtree of height `h`.
    ///
    /// `h` is 0 at the leaf level.
    #[must_use]
    pub fn at(&self, h: usize) -> Digest32 {
        self.empty.get(h).copied().unwrap_or_default()
    }

    /// The root of a completely empty tree.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot::from_digest(self.at(DEPTH))
    }

    /// The hasher.
    #[must_use]
    pub const fn hasher(&self) -> &H {
        &self.hasher
    }
}

/// An authentication path: the sibling digest at each level, leaf-to-root.
///
/// Always [`DEPTH`] long. The leaf's index says which side each sibling sits on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipPath {
    /// Sibling digests, leaf-to-root, exactly [`DEPTH`] of them.
    pub siblings: Vec<Digest32>,
    /// The leaf's index; bit `i` selects the side of `siblings[i]`.
    pub index: usize,
}

impl MembershipPath {
    /// The number of sibling digests. Always [`DEPTH`] for a well-formed path.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.siblings.len()
    }

    /// Whether the path carries no siblings. Never true for a well-formed path
    /// at a nonzero depth, but present so `len` is not alone.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Recompute the root from a leaf commitment.
    ///
    /// Folds each sibling in on the side its index bit indicates. Returns
    /// `None` if the path is malformed (wrong length) or the index exceeds the
    /// tree's capacity — a path cannot prove a position the tree cannot hold.
    #[must_use]
    pub fn compute_root<H: CommitmentHasher>(
        &self,
        hasher: &H,
        leaf: &NoteHash,
    ) -> Option<MerkleRoot> {
        if self.siblings.len() != DEPTH {
            return None;
        }
        // Capacity is 2^DEPTH; compared in u64 so the shift is valid on any
        // target width (DEPTH is 32, which would overflow a 32-bit usize).
        if (self.index as u64) >= (1u64 << DEPTH) {
            return None;
        }
        let mut current = leaf_digest(leaf);
        for (level, sibling) in self.siblings.iter().enumerate() {
            let go_right = (self.index >> level) & 1 == 1;
            current = if go_right {
                hasher.hash_pair(sibling, &current)
            } else {
                hasher.hash_pair(&current, sibling)
            };
        }
        Some(MerkleRoot::from_digest(current))
    }
}

/// A fixed-depth, append-only Merkle tree over note commitments.
///
/// Holds the leaves and derives the root on demand by folding in
/// [`EmptySubtrees`] for the unpopulated branches. Recomputing per query is
/// O(n) per root, so a long run is quadratic — but there is no incremental
/// state that can drift out of sync with the leaves, which is the class of bug
/// that produces a root the verifier rejects. The interface is what is stable;
/// a frontier-based implementation drops in behind it without touching a
/// caller.
#[derive(Clone, Debug)]
pub struct CommitmentTree<H: CommitmentHasher> {
    empties: EmptySubtrees<H>,
    leaves: Vec<Digest32>,
}

impl<H: CommitmentHasher> CommitmentTree<H> {
    /// An empty tree with the given hasher.
    #[must_use]
    pub fn new(hasher: H) -> Self {
        Self {
            empties: EmptySubtrees::new(hasher),
            leaves: Vec::new(),
        }
    }

    /// The number of leaves appended so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether nothing has been appended.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The root of a completely empty tree at this depth.
    #[must_use]
    pub fn empty_root(&self) -> MerkleRoot {
        self.empties.root()
    }

    /// Append a commitment and return its index.
    ///
    /// # Panics
    ///
    /// If the tree is full (2^`DEPTH` leaves). Reaching this is a protocol
    /// failure, not a runtime condition to recover from.
    pub fn append(&mut self, leaf: &NoteHash) -> usize {
        assert!(
            (self.leaves.len() as u64) < (1u64 << DEPTH),
            "commitment tree is full"
        );
        let index = self.leaves.len();
        self.leaves.push(leaf_digest(leaf));
        index
    }

    /// The current root.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot::from_digest(self.node(0, self.leaves.len(), DEPTH))
    }

    /// The digest of the subtree covering leaves `[start, end)` at `height`.
    ///
    /// `height` counts up from the leaves: 0 is a single leaf, `DEPTH` is the
    /// whole tree. Recurses by splitting the range in half and substituting the
    /// empty-subtree digest for a half that contains no leaves.
    fn node(&self, start: usize, end: usize, height: usize) -> Digest32 {
        if start >= end {
            return self.empties.at(height);
        }
        if height == 0 {
            return self.leaves[start];
        }
        let mid = start + (1usize << (height - 1));
        let mid = mid.min(end);
        let left = self.node(start, mid, height - 1);
        let right = self.node(mid, end, height - 1);
        self.empties.hasher().hash_pair(&left, &right)
    }

    /// The path proving `index` is a leaf under the current root.
    ///
    /// # Errors
    ///
    /// Returns `None` if `index` is out of range.
    #[must_use]
    pub fn path(&self, index: usize) -> Option<MembershipPath> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::with_capacity(DEPTH);
        // The sibling at height h is the neighbouring 2^h-tall subtree. Walk
        // from the top down so each block's bounds are exact. `node` requires
        // its `start` to be aligned to 2^h, which holds because `block_start`
        // is aligned to 2^(h+1).
        for h in (0..DEPTH).rev() {
            let half = 1usize << h;
            let block = half << 1;
            let block_start = (index / block) * block;
            let is_left_half = index < block_start + half;
            let sibling = if is_left_half {
                // Our leaf is in the left half; the sibling is the right half,
                // truncated at the frontier so unpopulated leaves read as empty.
                let right_start = block_start + half;
                let right_end = (block_start + block).min(self.leaves.len());
                self.node(right_start, right_end, h)
            } else {
                // Our leaf is in the right half, so the whole left half exists.
                self.node(block_start, block_start + half, h)
            };
            siblings.push(sibling);
        }
        // The loop produced root-to-leaf order; the path is leaf-to-root.
        siblings.reverse();
        Some(MembershipPath { siblings, index })
    }

    /// The hasher in use.
    #[must_use]
    pub const fn hasher(&self) -> &H {
        self.empties.hasher()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendPublicKey;
    use pq_hash::Poseidon2Commitment;

    fn leaf(seed: u8, value: u64) -> NoteHash {
        crate::note::Note::new(
            value,
            [seed; 32],
            [seed.wrapping_add(1); 32],
            SpendPublicKey::from_bytes([seed.wrapping_add(2); 32]),
        )
        .commit(&Poseidon2Commitment::default())
    }

    #[test]
    fn empty_tree_root_is_the_precomputed_empty_root() {
        let t = CommitmentTree::new(Poseidon2Commitment::default());
        assert!(t.is_empty());
        assert_eq!(t.root(), t.empty_root());
    }

    #[test]
    fn empty_root_is_not_the_zero_digest() {
        // The empty root is a hash chain, not zeros. If this were zero, an
        // attacker could forge an "empty" tree state trivially.
        let e = EmptySubtrees::new(Poseidon2Commitment::default());
        assert_ne!(e.root(), MerkleRoot::default());
        assert_eq!(e.at(0), Digest32::default());
    }

    #[test]
    fn every_appended_leaf_has_a_path_that_recomputes_the_root() {
        let mut t = CommitmentTree::new(Poseidon2Commitment::default());
        let leaves: Vec<NoteHash> = (1..=7u8).map(|s| leaf(s, u64::from(s) * 100)).collect();
        for l in &leaves {
            t.append(l);
        }
        let root = t.root();
        for (i, l) in leaves.iter().enumerate() {
            let p = t.path(i).expect("in range");
            assert_eq!(p.len(), DEPTH);
            assert_eq!(
                p.compute_root(&Poseidon2Commitment::default(), l),
                Some(root),
                "leaf {i} must authenticate to the root"
            );
        }
    }

    #[test]
    fn paths_verify_across_tree_shapes() {
        // The empty-branch substitution is the subtle part; cover boundaries
        // around powers of two. Counts are u8 so no truncating cast is needed.
        for n in [1u8, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
            let mut t = CommitmentTree::new(Poseidon2Commitment::default());
            let leaves: Vec<NoteHash> = (0..n).map(|s| leaf(s, 1)).collect();
            for l in &leaves {
                t.append(l);
            }
            let root = t.root();
            for (i, l) in leaves.iter().enumerate() {
                let p = t.path(i).expect("in range");
                assert_eq!(
                    p.compute_root(&Poseidon2Commitment::default(), l),
                    Some(root),
                    "n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn path_for_wrong_leaf_does_not_reach_the_root() {
        let mut t = CommitmentTree::new(Poseidon2Commitment::default());
        let leaves: Vec<NoteHash> = (1..=4u8).map(|s| leaf(s, 100)).collect();
        for l in &leaves {
            t.append(l);
        }
        let p = t.path(0).unwrap();
        assert_ne!(
            p.compute_root(&Poseidon2Commitment::default(), &leaves[1]),
            Some(t.root())
        );
    }

    #[test]
    fn out_of_range_path_is_none() {
        let mut t = CommitmentTree::new(Poseidon2Commitment::default());
        t.append(&leaf(1, 1));
        assert!(t.path(1).is_none());
    }

    #[test]
    fn root_changes_with_every_append() {
        let mut t = CommitmentTree::new(Poseidon2Commitment::default());
        let mut seen = Vec::new();
        for s in 1..=5u8 {
            t.append(&leaf(s, 1));
            seen.push(t.root());
        }
        let unique: std::collections::HashSet<_> = seen.iter().copied().collect();
        assert_eq!(unique.len(), 5, "every append must move the root");
    }

    #[test]
    fn tree_is_append_only_and_order_matters() {
        let mut a = CommitmentTree::new(Poseidon2Commitment::default());
        let mut b = CommitmentTree::new(Poseidon2Commitment::default());
        a.append(&leaf(1, 10));
        a.append(&leaf(2, 20));
        b.append(&leaf(2, 20));
        b.append(&leaf(1, 10));
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn a_stale_path_stops_verifying_after_the_tree_grows() {
        // Paths are snapshots: a path taken at one root must not verify against
        // a later root. This is why the root is a public input to every transfer.
        let mut t = CommitmentTree::new(Poseidon2Commitment::default());
        let a = leaf(1, 10);
        t.append(&a);
        let old_root = t.root();
        let p = t.path(0).unwrap();
        t.append(&leaf(2, 20));
        assert_ne!(old_root, t.root());
        assert_ne!(
            p.compute_root(&Poseidon2Commitment::default(), &a),
            Some(t.root())
        );
    }

    #[test]
    fn malformed_path_length_is_rejected() {
        let p = MembershipPath {
            siblings: vec![Digest32::default(); DEPTH - 1],
            index: 0,
        };
        assert_eq!(
            p.compute_root(&Poseidon2Commitment::default(), &leaf(1, 1)),
            None
        );
    }
}
