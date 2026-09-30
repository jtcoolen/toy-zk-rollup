//! The transfer: the statement the STARK proves.
//!
//! A transfer consumes existing notes and creates new ones. Its validity is a
//! handful of rules, and the whole point of the rollup is that the chain checks
//! the *proof* of those rules rather than the rules' inputs.
//!
//! # The rules
//!
//! 1. **Balance.** `sum(input values) == sum(output values) + fee`. Without this,
//!    value is created from nothing. This is the only rule that touches amounts,
//!    which is why amounts must be provable in-circuit rather than revealed.
//! 2. **Ownership.** Each input's `pk_d` matches the key that authorized the
//!    spend.
//! 3. **Nullification.** Each input's nullifier is published, so the note cannot
//!    be spent twice.
//! 4. **Membership.** Each input commits to a leaf under the current root.
//!
//! Rules 2–4 are about keys and paths and cost no amount reasoning. Rule 1 is
//! the reason this is a ZK system and not a transparent ledger.
//!
//! # Why this module exists separately from the AIR
//!
//! This is the *executable specification* of the rules, in plain arithmetic. The
//! AIR is the same rules expressed as polynomial constraints. Keeping both lets a
//! reader understand the rule here, and lets a test check that the two agree on
//! the same inputs. When they disagree, the proof is wrong, and this file is how
//! you find out which one moved.

use pq_hash::{CommitmentHasher, Digest32, MerkleRoot, NoteHash, Nullifier, ShieldedHasher};

use crate::note::Note;

/// The largest representable value.
///
/// The circuit proves amounts with 31-bit `KoalaBear` limbs, so a `u64` amount is
/// split into two limbs and each is range-checked. This bound is the *protocol*
/// bound, tighter than what two limbs could encode, so that the total supply is
/// fixed and addition of any two legal values cannot overflow a `u64`.
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// A transfer's balance error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceError {
    /// Inputs and outputs plus fee do not balance.
    Imbalanced,
    /// A value exceeded [`MAX_VALUE`].
    ValueTooLarge,
}

impl core::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Imbalanced => write!(f, "transfer does not balance"),
            Self::ValueTooLarge => write!(f, "value exceeds the protocol maximum"),
        }
    }
}

impl std::error::Error for BalanceError {}

/// Check the conservation law.
///
/// This is rule 1, isolated so it can be tested against adversarial inputs
/// without a prover. The AIR enforces the same equation over field elements;
/// this enforces it over integers, which is what a human can read.
///
/// # Errors
///
/// [`BalanceError::ValueTooLarge`] if any value exceeds [`MAX_VALUE`], and
/// [`BalanceError::Imbalanced`] if the sums do not match.
pub fn check_balance(inputs: &[u64], outputs: &[u64], fee: u64) -> Result<(), BalanceError> {
    // Check the bound first: with every value < 2^62, a sum of a handful of them
    // cannot overflow u64, so the arithmetic below is safe without checked ops.
    for v in inputs.iter().chain(outputs).chain(core::iter::once(&fee)) {
        if *v > MAX_VALUE {
            return Err(BalanceError::ValueTooLarge);
        }
    }
    let in_sum: u64 = inputs.iter().sum();
    let out_sum: u64 = outputs.iter().sum();
    if in_sum == out_sum + fee {
        Ok(())
    } else {
        Err(BalanceError::Imbalanced)
    }
}

/// A spend: one input note plus the evidence that unlocks it.
///
/// The `path` is the Merkle authentication path proving the commitment sits under
/// `root`. It is carried here rather than in the note because the same note has
/// many valid paths over time as the tree grows.
#[derive(Clone, Copy, Debug)]
pub struct Spend<'a> {
    /// The note being spent.
    pub note: &'a Note,
    /// The spending secret, used only to compute the nullifier. Never stored.
    pub sk_d: &'a [u8; 32],
    /// Sibling hashes from leaf to root.
    pub path: &'a [Digest32],
    /// The position of the leaf in the tree.
    pub index: usize,
}

/// A transfer statement: what the prover knows and what the verifier sees.
///
/// The public part is exactly [`TransferPublic`]: nullifiers, output commitments,
/// the root, and the fee. Everything else stays in the witness.
#[derive(Clone, Debug)]
pub struct Transfer<'a> {
    /// The notes being consumed.
    pub spends: Vec<Spend<'a>>,
    /// The notes being created.
    pub outputs: Vec<Note>,
    /// The fee paid to the sequencer.
    pub fee: u64,
}

/// The public surface of a transfer: everything the chain sees.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferPublic {
    /// One nullifier per input. Published so double-spends are detectable.
    pub nullifiers: Vec<Nullifier>,
    /// One commitment per output. Appended to the tree.
    pub outputs: Vec<NoteHash>,
    /// The tree root the inputs were proven against.
    pub root: MerkleRoot,
    /// The fee.
    pub fee: u64,
}

impl Transfer<'_> {
    /// Compute the public statement from the witness.
    ///
    /// This is the function the AIR mirrors: given the same witness, the public
    /// values the circuit commits to must be identical to these.
    ///
    /// The two hashers are separate generic parameters because the traits are
    /// deliberately unrelated — one type satisfying both would defeat the
    /// compile-time separation the `pq-hash` crate exists to provide.
    ///
    /// `root` is supplied rather than derived: the prover learns it from the tree
    /// service, and the circuit takes it as a public input.
    #[must_use]
    pub fn public<C, S>(&self, commitment: &C, shielded: &S, root: MerkleRoot) -> TransferPublic
    where
        C: CommitmentHasher,
        S: ShieldedHasher,
    {
        let nullifiers = self
            .spends
            .iter()
            .map(|s| s.note.nullifier(shielded, s.sk_d))
            .collect();
        let outputs = self.outputs.iter().map(|n| n.commit(commitment)).collect();
        TransferPublic {
            nullifiers,
            outputs,
            root,
            fee: self.fee,
        }
    }

    /// The input amounts, for the balance check.
    #[must_use]
    pub fn input_values(&self) -> Vec<u64> {
        self.spends.iter().map(|s| s.note.value()).collect()
    }

    /// The output amounts, for the balance check.
    #[must_use]
    pub fn output_values(&self) -> Vec<u64> {
        self.outputs.iter().map(Note::value).collect()
    }

    /// Check rule 1 over the witness.
    ///
    /// # Errors
    ///
    /// Propagates [`BalanceError`] from [`check_balance`].
    pub fn check_balance(&self) -> Result<(), BalanceError> {
        check_balance(&self.input_values(), &self.output_values(), self.fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendPublicKey;

    fn note(value: u64, seed: u8) -> Note {
        Note::new(
            value,
            [seed; 32],
            [seed.wrapping_add(1); 32],
            SpendPublicKey::from_bytes([seed.wrapping_add(2); 32]),
        )
    }

    #[test]
    fn balanced_transfer_passes() {
        assert_eq!(check_balance(&[10, 20], &[25], 5), Ok(()));
    }

    #[test]
    fn zero_fee_balances() {
        assert_eq!(check_balance(&[30], &[30], 0), Ok(()));
    }

    #[test]
    fn creating_value_fails() {
        // The single most important test in the system.
        assert_eq!(
            check_balance(&[10], &[20], 0),
            Err(BalanceError::Imbalanced)
        );
    }

    #[test]
    fn destroying_value_fails() {
        assert_eq!(
            check_balance(&[20], &[10], 0),
            Err(BalanceError::Imbalanced)
        );
    }

    #[test]
    fn fee_must_be_exact() {
        assert_eq!(check_balance(&[10], &[5], 4), Err(BalanceError::Imbalanced));
    }

    #[test]
    fn oversized_value_is_caught_before_arithmetic() {
        assert_eq!(
            check_balance(&[MAX_VALUE + 1], &[], 0),
            Err(BalanceError::ValueTooLarge)
        );
        assert_eq!(
            check_balance(&[], &[MAX_VALUE + 1], 0),
            Err(BalanceError::ValueTooLarge)
        );
        assert_eq!(
            check_balance(&[], &[], MAX_VALUE + 1),
            Err(BalanceError::ValueTooLarge)
        );
    }

    #[test]
    fn max_value_is_legal_and_does_not_overflow() {
        // Two MAX_VALUEs fit in u64, which is why the bound exists.
        assert_eq!(
            check_balance(&[MAX_VALUE, MAX_VALUE], &[MAX_VALUE], MAX_VALUE),
            Ok(())
        );
    }

    #[test]
    fn empty_transfer_balances() {
        assert_eq!(check_balance(&[], &[], 0), Ok(()));
    }

    #[test]
    fn transfer_reads_its_own_witness() {
        let a = note(30, 1);
        let b = note(25, 2);
        let sk = [9u8; 32];
        let spend = Spend {
            note: &a,
            sk_d: &sk,
            path: &[],
            index: 0,
        };
        let t = Transfer {
            spends: vec![spend],
            outputs: vec![b],
            fee: 5,
        };
        assert_eq!(t.input_values(), vec![30]);
        assert_eq!(t.output_values(), vec![25]);
        assert_eq!(t.check_balance(), Ok(()));
    }

    #[test]
    fn transfer_detects_its_own_imbalance() {
        let a = note(30, 1);
        let b = note(40, 2);
        let sk = [9u8; 32];
        let t = Transfer {
            spends: vec![Spend {
                note: &a,
                sk_d: &sk,
                path: &[],
                index: 0,
            }],
            outputs: vec![b],
            fee: 0,
        };
        assert_eq!(t.check_balance(), Err(BalanceError::Imbalanced));
    }
}
