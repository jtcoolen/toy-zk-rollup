//! The transfer AIR: what one shielded transfer proves.
//!
//! ## The relation
//!
//! Per input note:
//!
//! 1. **Ownership** — `pk_d = H_sha3(DOMAIN_PK ‖ sk_d)`. The prover knows a
//!    preimage of the spend key, which is what makes the note spendable. Without
//!    this the *sender*, who knows the full commitment preimage but not `sk_d`,
//!    could pick any random `sk_d'`, compute a matching nullifier, and drain the
//!    note (D-018).
//! 2. **Commitment** — the leaf is `H_keccak(DOMAIN_NOTE ‖ value ‖ rho ‖ psi ‖ pk_d)`,
//!    the exact preimage [`shielded::Note::commit`] produces.
//! 3. **Membership** — the leaf folds through a sibling path to the published root.
//! 4. **Nullifier** — `nf = H_sha3(DOMAIN_NULLIFIER ‖ sk_d ‖ rho)`, published so
//!    a second spend of the same note is detectable.
//!
//! Globally:
//!
//! 5. **Value conservation** — `Σ inputs = Σ outputs + fee`, column-wise over
//!    16-bit limbs with a biased carry chain (D-017).
//!
//! ## Why nothing here is Poseidon2
//!
//! The transfer's own hashes are Keccak-256 (the Merkle tree, replayable by the
//! native `keccak256` opcode) and SHA3-256 (nullifiers, spend-key derivation).
//! Poseidon2 appears only in the recursion layer, which re-verifies *this* proof.
//!
//! ## The public statement
//!
//! The statement is exactly [`TransferPublic`]: nullifiers, output commitments,
//! the root, the fee. It is exported through the statement table, so
//! `CircuitVerifier::verify(&proof, statement)` binds the proof to those bytes
//! and to nothing else.
//!
//! ## What this does *not* yet prove
//!
//! Nullifier **non-membership**. The circuit proves the inputs are in the tree; it
//! does not prove the nullifiers have not been spent before. That gap is closed
//! by the on-chain nullifier set, which rejects a replayed nullifier before it
//! ever reaches the verifier. See the ticket for the in-circuit sparse-Merkle
//! upgrade that removes the reliance on the node ordering them.

use std::fmt;

use p3_circuit::ops::{bytes_to_limbs, KECCAK256_DIGEST_LIMBS};
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitBuilderError, ExprId, StatementExport, StatementSchema, Traces,
};
use p3_field::PrimeCharacteristicRing;

use shielded::keys::DOMAIN_PK;
use shielded::note::{DOMAIN_NOTE, DOMAIN_NULLIFIER};
use shielded::{Transfer, TransferPublic};

use crate::sha3_block::sha3_256_single_block;
use crate::whir_recursion::{Challenge, F};

/// Trace height the transfer settlement is sized at.
///
/// WHIR derives a mandatory grinding budget from the arity of the polynomial it
/// commits to, and `WhirConfig` *refuses to build* when the required bits exceed
/// the budget. The transfer circuit stacks to 23 variables — 32-level Keccak
/// Merkle folds per input dominate the trace — which needs 17 ground bits at the
/// 96-bit target. A config declared at 22 variables only budgets 14, so the
/// prover panics inside the PCS rather than returning an error.
///
/// Declaring one level higher budgets 18 bits, covering the 17 required with a
/// bit of headroom for a slightly larger circuit. The verifier's cost is
/// unchanged: grinding is prover-side work checked with a single hash.
pub const LOG_MAX_LDE: usize = 24;

/// A `u64` amount as little-endian 16-bit limbs. Four limbs, because the
/// circuit's limb width is 16 bits, not the field's 31.
const VALUE_LIMBS: usize = 4;

/// Range-check width for a non-top amount limb.
const LIMB_BITS: usize = 16;

/// Range-check width for the top amount limb: 62 − 3·16.
///
/// This makes the circuit enforce the same `MAX_VALUE < 2^62` domain bound the
/// native balance check enforces, so the two never disagree about what a legal
/// amount is.
const TOP_LIMB_BITS: usize = 14;

const _: () = assert!(shielded::MAX_VALUE < (1u64 << 62));

/// Range-check width for a balance carry.
///
/// Eight bits is deliberately generous against the honest range (the carries land
/// in `[0, bias + 1]`) and deliberately tight against the field: the widest term
/// in a balance constraint is `2^16 · 2^8 ≈ 2^24`, which keeps every column
/// equation far below the `KoalaBear` modulus. That is what makes the field
/// equality a true *integer* equality rather than a congruence that could be
/// satisfied by a multiple of the modulus.
const CARRY_BITS: usize = 8;

/// The most inputs or outputs a single transfer may have.
///
/// The carry bound above is stated in terms of this, so it is capped here rather
/// than assumed.
const MAX_PARTIES: usize = 16;

/// A circuit amount: its limbs as expressions, and the witness values behind them.
///
/// Allocation and witnessing happen together so the two cannot drift out of
/// order — the failure mode that silently mis-wires a `CircuitRunner`.
struct Amount {
    exprs: Vec<ExprId>,
    limbs: [u16; VALUE_LIMBS],
}

impl Amount {
    /// Allocate a private amount and range-check every limb.
    ///
    /// The top limb gets `TOP_LIMB_BITS`, the rest `LIMB_BITS`, so the amount is
    /// constrained to `[0, 2^62)`.
    fn private(
        builder: &mut CircuitBuilder<Challenge>,
        value: u64,
    ) -> Result<Self, CircuitBuilderError> {
        let limbs = split_value(value);
        let exprs = builder.alloc_private_inputs(VALUE_LIMBS, "transfer.amount");
        for (i, &expr) in exprs.iter().enumerate() {
            let bits = if i + 1 == VALUE_LIMBS {
                TOP_LIMB_BITS
            } else {
                LIMB_BITS
            };
            builder.decompose_to_bits::<F>(expr, bits)?;
        }
        Ok(Self { exprs, limbs })
    }
}

/// A private byte string as 16-bit limbs, with the witness values alongside.
///
/// Construction validates the limbs it hands out: each is range-checked to 16
/// bits, so a caller cannot accidentally feed an out-of-range limb into a hash
/// and have the circuit's byte interpretation diverge from the witness's.
struct Secret {
    exprs: Vec<ExprId>,
    witness: Vec<Challenge>,
}

impl Secret {
    /// Allocate a private byte string as range-checked 16-bit limbs.
    ///
    /// # Errors
    ///
    /// Propagates a builder error if a limb cannot be decomposed.
    fn new(
        builder: &mut CircuitBuilder<Challenge>,
        bytes: &[u8],
        label: &'static str,
    ) -> Result<Self, CircuitBuilderError> {
        let limbs = bytes_to_limbs(bytes);
        let exprs = builder.alloc_private_inputs(limbs.len(), label);
        for &expr in &exprs {
            claim_private(builder, expr);
            builder.decompose_to_bits::<F>(expr, LIMB_BITS)?;
        }
        let witness = limbs
            .iter()
            .map(|&limb| Challenge::from_u16(limb))
            .collect();
        Ok(Self { exprs, witness })
    }
}

/// Give a private input the bus claim the prover requires of every witness.
///
/// The `WitnessChecks` bus needs a creator row for each witness, and only
/// `Const`/`Public` rows, ALU rows, and non-primitive *outputs* create one. A
/// limb that feeds only a Keccak permutation is a non-primitive *input*, which
/// never creates, so the prover rejects the whole circuit as unsatisfiable.
/// Multiplying by one is the cheapest row that creates the witness without
/// adding any constraint beyond what the limb already carries.
fn claim_private(builder: &mut CircuitBuilder<Challenge>, expr: ExprId) {
    let one = builder.define_const(Challenge::ONE);
    let _ = builder.mul(expr, one);
}

/// Split a `u64` into four little-endian 16-bit limbs.
const fn split_value(value: u64) -> [u16; VALUE_LIMBS] {
    [
        (value & 0xffff) as u16,
        ((value >> 16) & 0xffff) as u16,
        ((value >> 32) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
    ]
}

/// Constant limbs for a byte string.
fn const_limbs(builder: &mut CircuitBuilder<Challenge>, bytes: &[u8]) -> Vec<ExprId> {
    bytes_to_limbs(bytes)
        .into_iter()
        .map(|limb| builder.define_const(Challenge::from_u16(limb)))
        .collect()
}

/// The 8-byte little-endian length prefix `pq_hash::Sha3_256Shielded` puts in
/// front of every part of a hashed preimage.
///
/// The circuit must hash the *same bytes* the native hasher hashes. This is the
/// single place that framing is re-expressed, and
/// [`sha3_statement_matches_native`] pins it against
/// [`pq_hash::ShieldedHasher::hash_to_digest`].
const fn len_header(len: usize) -> [u8; 8] {
    (len as u64).to_le_bytes()
}

/// SHA3-256, in-circuit, over a length-prefixed domain and some witness parts.
///
/// Builds the same byte string `Sha3_256Shielded::hash_to_digest(domain, parts)`
/// builds — `len(domain)‖domain‖len(p₁)‖p₁‖len(p₂)‖p₂…` — with each `pᵢ` given
/// as witness limbs instead of bytes, then hashes it in one block.
///
/// Every part's byte length is `2 · limbs`, so the framing stays even and the
/// whole preimage fits one rate block for the sizes this protocol uses.
fn sha3_framed(
    builder: &mut CircuitBuilder<Challenge>,
    domain: &[u8],
    parts: &[&[ExprId]],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut message = const_limbs(builder, &len_header(domain.len()));
    message.extend(const_limbs(builder, domain));
    for part in parts {
        message.extend(const_limbs(builder, &len_header(2 * part.len())));
        message.extend(part.iter().copied());
    }
    sha3_256_single_block::<Challenge, F>(builder, &message)
}

/// A witnessed transfer circuit, ready to be settled.
pub struct TransferCircuit {
    circuit: Circuit<Challenge>,
    traces: Traces<Challenge>,
    schema: StatementSchema,
    statement: Vec<F>,
}

impl fmt::Debug for TransferCircuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferCircuit")
            .field("public_len", &self.circuit.public_flat_len)
            .field("private_len", &self.circuit.private_flat_len)
            .field("statement_len", &self.schema.base_len())
            .finish_non_exhaustive()
    }
}

impl TransferCircuit {
    /// The exported statement: the exact slice `verify(&proof, statement)` must be
    /// called with.
    #[must_use = "the statement is what the settlement verifier must be called with"]
    pub fn statement(&self) -> &[F] {
        &self.statement
    }
}

/// Build and witness a transfer circuit against a published [`TransferPublic`].
///
/// `public` is the single source of truth for the statement *and* for the root
/// the inputs are proven against: the circuit recomputes the root from the
/// sibling paths and connects it to `public.root`, so a path that does not fold
/// to that root cannot be witnessed at all.
///
/// # Errors
///
/// Returns a builder error if a preimage has an odd byte length (limbs pack two
/// bytes), if a Keccak-f call is malformed, or — via the witness runner — if the
/// transfer is unbalanced, since no carry chain witnesses a false balance.
pub fn build_transfer_circuit(
    transfer: &Transfer<'_>,
    public: &TransferPublic,
) -> Result<TransferCircuit, Box<dyn std::error::Error>> {
    let parties = transfer.spends.len().max(transfer.outputs.len() + 1);
    if parties > MAX_PARTIES {
        return Err(format!(
            "a transfer may have at most {MAX_PARTIES} inputs or outputs, got {parties}"
        )
        .into());
    }

    let mut builder = CircuitBuilder::<Challenge>::new();
    builder.enable_keccak_f1600::<F>();

    let mut private: Vec<Challenge> = Vec::new();
    let mut statement: Vec<ExprId> = Vec::new();
    let mut input_amounts: Vec<Amount> = Vec::new();
    let mut output_amounts: Vec<Amount> = Vec::new();

    // ---- Inputs: ownership, membership, nullifier -----------------------
    for spend in &transfer.spends {
        let sk = Secret::new(&mut builder, spend.sk_d, "transfer.sk_d")?;
        let rho = Secret::new(&mut builder, spend.note.rho(), "transfer.rho")?;
        let psi = Secret::new(&mut builder, spend.note.psi(), "transfer.psi")?;
        let amount = Amount::private(&mut builder, spend.note.value())?;
        private.extend(sk.witness.iter().copied());
        private.extend(rho.witness.iter().copied());
        private.extend(psi.witness.iter().copied());
        private.extend(amount.limbs.iter().map(|&l| Challenge::from_u16(l)));

        // (1) Ownership. `pk_d` is derived, never supplied: the only way to
        // produce a witness here is to know `sk_d`.
        let pk_d = sha3_framed(&mut builder, DOMAIN_PK, &[&sk.exprs])?;

        // (2) Commitment, over the exact native preimage.
        let mut leaf_msg = const_limbs(&mut builder, DOMAIN_NOTE);
        leaf_msg.extend(amount.exprs.iter().copied());
        leaf_msg.extend(rho.exprs.iter().copied());
        leaf_msg.extend(psi.exprs.iter().copied());
        leaf_msg.extend(pk_d.iter().copied());
        let leaf = builder.keccak256_limbs::<F>(&leaf_msg)?;

        // (3) Membership: fold to the root, mirroring
        // `MembershipPath::compute_root`, and bind the fold to the published root.
        let folded = fold_membership(&mut builder, &leaf, spend.path, spend.index, &mut private)?;
        let root_limbs = const_limbs(&mut builder, public.root.as_bytes());
        for (got, want) in folded.iter().zip(&root_limbs) {
            builder.connect(*got, *want);
        }

        // (4) Nullifier.
        let nullifier = sha3_framed(&mut builder, DOMAIN_NULLIFIER, &[&sk.exprs, &rho.exprs])?;
        statement.extend(nullifier);

        input_amounts.push(amount);
    }

    // ---- Outputs ------------------------------------------------------
    for note in &transfer.outputs {
        let rho = Secret::new(&mut builder, note.rho(), "output.rho")?;
        let psi = Secret::new(&mut builder, note.psi(), "output.psi")?;
        let amount = Amount::private(&mut builder, note.value())?;
        private.extend(rho.witness.iter().copied());
        private.extend(psi.witness.iter().copied());
        private.extend(amount.limbs.iter().map(|&l| Challenge::from_u16(l)));

        // The recipient's spend key is public to the sender, so it is a
        // constant: the output commitment is pinned, not chosen.
        let mut leaf_msg = const_limbs(&mut builder, DOMAIN_NOTE);
        leaf_msg.extend(amount.exprs.iter().copied());
        leaf_msg.extend(rho.exprs.iter().copied());
        leaf_msg.extend(psi.exprs.iter().copied());
        leaf_msg.extend(const_limbs(&mut builder, note.pk_d().as_bytes()));
        let commitment = builder.keccak256_limbs::<F>(&leaf_msg)?;
        statement.extend(commitment);

        output_amounts.push(amount);
    }

    // ---- The published root and the fee -------------------------------
    statement.extend(const_limbs(&mut builder, public.root.as_bytes()));

    let fee = Amount::private(&mut builder, transfer.fee)?;
    private.extend(fee.limbs.iter().map(|&l| Challenge::from_u16(l)));
    statement.extend(fee.exprs.iter().copied());

    // ---- (5) Value conservation ---------------------------------------
    constrain_balance(
        &mut builder,
        &input_amounts,
        &output_amounts,
        &fee,
        &mut private,
    )?;

    // ---- Statement ----------------------------------------------------
    let exports: Vec<StatementExport> = statement
        .iter()
        .map(|&expr| StatementExport::Base(expr))
        .collect();
    let schema = builder.set_statement_exports::<F>(&exports)?;
    let circuit = builder.build()?;

    let statement_values = statement_limbs(public);
    if statement_values.len() != schema.base_len() {
        return Err(format!(
            "statement width mismatch: circuit exports {}, TransferPublic flattens to {}",
            schema.base_len(),
            statement_values.len()
        )
        .into());
    }

    let mut runner = circuit.runner();
    runner.set_public_inputs(&[])?;
    runner.set_private_inputs(&private)?;
    let traces = runner.run()?;

    Ok(TransferCircuit {
        circuit,
        traces,
        schema,
        statement: statement_values,
    })
}

/// Fold a leaf through a sibling path to the root, mirroring
/// [`shielded::MembershipPath::compute_root`]: bit `i` of the index selects
/// which side `siblings[i]` sits on.
///
/// The index is a *witness*, not a constant, so the side selection is a circuit
/// select driven by a boolean-constrained bit. Making it a constant would let the
/// prover pick the fold that suits it.
fn fold_membership(
    builder: &mut CircuitBuilder<Challenge>,
    leaf: &[ExprId],
    siblings: &[pq_hash::Digest32],
    index: usize,
    private: &mut Vec<Challenge>,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut current = leaf.to_vec();
    for (level, sibling) in siblings.iter().enumerate() {
        let sibling_limbs = const_limbs(builder, sibling.as_bytes());
        let go_right = (index >> level) & 1 == 1;
        let bit = builder.alloc_private_input("merkle.bit");
        private.push(if go_right {
            Challenge::ONE
        } else {
            Challenge::ZERO
        });
        builder.assert_bool(bit);

        // `bit = 1` puts the sibling on the left, matching the native fold where
        // the node's own index bit selects the side the *sibling* occupies.
        let mut left = Vec::with_capacity(KECCAK256_DIGEST_LIMBS);
        let mut right = Vec::with_capacity(KECCAK256_DIGEST_LIMBS);
        for limb in 0..KECCAK256_DIGEST_LIMBS {
            left.push(builder.select(bit, sibling_limbs[limb], current[limb]));
            right.push(builder.select(bit, current[limb], sibling_limbs[limb]));
        }
        current = builder.keccak256_compress(&left, &right)?;
    }
    Ok(current)
}

/// Constrain `Σ inputs = Σ outputs + fee` over 16-bit limbs (D-017).
///
/// ## The carry chain
///
/// A field equality between the two totals would be unsound: both sides can
/// exceed the `KoalaBear` modulus, so a congruence is not an equality. Instead
/// the check runs column-wise with a carry, exactly like schoolbook subtraction,
/// and every term is kept small enough that the field equation *is* the integer
/// equation.
///
/// Per column `j`, with `Aⱼ` the sum of input limbs and `Bⱼ` the sum of output
/// limbs plus the fee limb:
///
/// ```text
///   Aⱼ + 2¹⁶·dⱼ₊₁ = Bⱼ + dⱼ + bias·(2¹⁶ − 1)
/// ```
///
/// Summing over `j` with weight `2¹⁶ʲ` telescopes the carries to
/// `d₀ − 2¹⁶ⁿ·dₙ + bias·(2¹⁶ⁿ − 1)`, which vanishes exactly when `d₀ = dₙ = bias`.
/// Pinning both ends to the same constant is therefore the whole proof of
/// conservation.
///
/// ## Why the bias
///
/// The unbiased carries can be negative, and a negative field element is huge —
/// it would fail its own range check. Adding `bias` shifts the whole chain into
/// the non-negative range. With `bias ≥ n_inputs` the carries stay in
/// `[0, bias + 1]`, which [`CARRY_BITS`] covers with room to spare while keeping
/// `2¹⁶ · d` under the modulus.
///
/// An unbalanced transfer has no integer carry chain at all: the recurrence
/// demands a non-integral `d`, so the honest witness does not exist and any
/// field-level workaround fails the range check.
fn constrain_balance(
    builder: &mut CircuitBuilder<Challenge>,
    inputs: &[Amount],
    outputs: &[Amount],
    fee: &Amount,
    private: &mut Vec<Challenge>,
) -> Result<(), CircuitBuilderError> {
    let bias = inputs.len().max(outputs.len() + 1) as u64;
    let mask: u64 = (1 << LIMB_BITS) - 1;
    let two_16 = builder.define_const(Challenge::from_u64(1u64 << LIMB_BITS));
    let bias_expr = builder.define_const(Challenge::from_u64(bias));
    let offset_expr = builder.define_const(Challenge::from_u64(bias * mask));

    let mut carry_expr = bias_expr;
    let mut carry_val = bias;

    for j in 0..VALUE_LIMBS {
        let a_expr = sum_exprs(builder, inputs.iter().map(|a| a.exprs[j]));
        let b_expr = {
            let mut acc = fee.exprs[j];
            for out in outputs {
                acc = builder.add(acc, out.exprs[j]);
            }
            acc
        };
        let a_val: u64 = inputs.iter().map(|a| u64::from(a.limbs[j])).sum();
        let out_val: u64 = outputs.iter().map(|o| u64::from(o.limbs[j])).sum();
        let b_val: u64 = u64::from(fee.limbs[j]) + out_val;

        // The last column's carry-out is pinned to the bias; interior carries are
        // witnessed and range-checked.
        let (next_expr, next_val) = if j + 1 == VALUE_LIMBS {
            (bias_expr, bias)
        } else {
            let value = (b_val + carry_val + bias * mask - a_val) >> LIMB_BITS;
            let expr = builder.alloc_private_input("balance.carry");
            private.push(Challenge::from_u64(value));
            builder.decompose_to_bits::<F>(expr, CARRY_BITS)?;
            (expr, value)
        };

        // Aⱼ + 2¹⁶·dⱼ₊₁ − Bⱼ − dⱼ − bias·(2¹⁶ − 1) = 0
        let lhs = builder.mul_add(two_16, next_expr, a_expr);
        let carries = builder.add(b_expr, carry_expr);
        let rhs = builder.add(carries, offset_expr);
        let diff = builder.sub(lhs, rhs);
        builder.assert_zero(diff);

        carry_expr = next_expr;
        carry_val = next_val;
    }
    Ok(())
}

/// Sum expressions with a chain of additions.
fn sum_exprs(
    builder: &mut CircuitBuilder<Challenge>,
    exprs: impl Iterator<Item = ExprId>,
) -> ExprId {
    let mut acc = builder.define_const(Challenge::ZERO);
    for expr in exprs {
        acc = builder.add(acc, expr);
    }
    acc
}

/// The statement limbs of a [`TransferPublic`], in the order the circuit exports
/// them: nullifiers, output commitments, root, fee.
///
/// This is the byte-level contract with the Solidity verifier.
fn statement_limbs(public: &TransferPublic) -> Vec<F> {
    let mut out = Vec::new();
    for nf in &public.nullifiers {
        out.extend(
            bytes_to_limbs(nf.as_bytes())
                .iter()
                .map(|&l| F::from_u16(l)),
        );
    }
    for cm in &public.outputs {
        out.extend(
            bytes_to_limbs(cm.as_bytes())
                .iter()
                .map(|&l| F::from_u16(l)),
        );
    }
    out.extend(
        bytes_to_limbs(public.root.as_bytes())
            .iter()
            .map(|&l| F::from_u16(l)),
    );
    out.extend(split_value(public.fee).iter().map(|&l| F::from_u16(l)));
    out
}

/// Prove a witnessed transfer circuit under the Keccak WHIR settlement config.
///
/// The circuit's only non-primitive operations are Keccak-f[1600] and the
/// statement table, so only those two tables are registered — no Poseidon2, no
/// recompose. The returned verifier binds the statement: `verify(&proof, pis)`
/// accepts only for the `pis` the circuit was built with.
///
/// # Errors
///
/// Returns the settlement config error if `log_max_lde` is below the protocol's
/// minimum trace height, or a prover error if preparation or proving fails.
pub fn settle_transfer_circuit(
    tc: &TransferCircuit,
    log_max_lde: usize,
) -> Result<
    (
        p3_circuit_prover::BatchStarkProof<crate::whir::Config>,
        p3_circuit_prover::CircuitVerifier<crate::whir::Config>,
    ),
    Box<dyn std::error::Error>,
> {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
        StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
    use p3_circuit_prover::ConstraintProfile;

    let settlement = crate::whir::config(0, log_max_lde)?;
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(KeccakF1600Preprocessor),
        Box::new(StatementPreprocessor::new(tc.schema.clone())),
    ];
    let air_builders: Vec<Box<dyn NpoAirBuilder<crate::whir::Config, 4>>> = vec![
        Box::new(KeccakF1600AirBuilder::<4>),
        Box::new(StatementAirBuilder::<4>::new(tc.schema.clone())),
    ];

    let mut prover = BatchStarkProver::new(settlement)
        .with_table_packing(p3_recursion::ProveNextLayerParams::default().table_packing);
    prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
    prover.register_table_prover(Box::new(StatementProver::<4>::new(tc.schema.clone())));

    let prepared = prover.prepare_circuit(
        &tc.circuit,
        &preprocessors,
        &air_builders,
        ConstraintProfile::Standard,
    )?;
    let proof = prepared.prove(&tc.traces)?;
    Ok((proof, prepared.verifier()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::{Keccak256Commitment, Sha3_256Shielded, ShieldedHasher};
    use shielded::keys::{derive_spend_pk, SpendPublicKey};
    use shielded::transfer::Spend;
    use shielded::tree::{CommitmentTree, DEPTH};
    use shielded::Note;

    /// A tiny deterministic byte source. Test fixtures only — production `rho`,
    /// `psi` and `sk_d` come from a CSPRNG in the wallet.
    fn seed(byte: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = byte
                .wrapping_mul(31)
                .wrapping_add(u8::try_from(i % 256).expect("mod 256 fits"));
        }
        out
    }

    /// A note whose `pk_d` is the honest SHA3 derivation of `sk_d`, so the
    /// circuit's ownership check has a real preimage behind it.
    ///
    /// The three seeds are offset from `byte` so a note's `rho`, `psi` and `sk_d`
    /// differ from each other and from other notes'. Offsets are applied with
    /// wrapping arithmetic: the fixture is not a checked cast, and a plain `+`
    /// panics on `byte + 200` in a debug build.
    fn funded_note(byte: u8, value: u64) -> (Note, [u8; 32]) {
        let sk_d = seed(byte);
        let pk_d = derive_spend_pk(&Sha3_256Shielded, &sk_d);
        let note = Note::new(
            value,
            seed(byte.wrapping_add(100)),
            seed(byte.wrapping_add(200)),
            pk_d,
        );
        (note, sk_d)
    }

    /// A tree holding `notes`, plus a membership path for each.
    ///
    /// Every path is captured *after* the tree reaches its final root. A path
    /// taken mid-append folds to that earlier snapshot's root, so using it
    /// against the final root is unsatisfiable — a real prover reads the path and
    /// the root from one tree state for the same reason.
    fn tree_with(
        notes: &[Note],
    ) -> (
        CommitmentTree<Keccak256Commitment>,
        Vec<Vec<pq_hash::Digest32>>,
    ) {
        let mut tree = CommitmentTree::new(Keccak256Commitment);
        for note in notes {
            tree.append(&note.commit(&Keccak256Commitment));
        }
        let paths = (0..notes.len())
            .map(|i| tree.path(i).expect("path exists").siblings)
            .collect();
        (tree, paths)
    }

    /// End to end: a balanced 2-in / 2-out transfer builds, proves, and verifies
    /// against its own statement.
    #[test]
    fn transfer_proves_and_verifies() {
        let (a, sk_a) = funded_note(1, 1_000);
        let (b, sk_b) = funded_note(2, 2_500);
        let (tree, paths) = tree_with(&[a, b]);
        let root = tree.root();

        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let outputs = vec![
            Note::new(3_000, seed(20), seed(21), recipient),
            Note::new(400, seed(22), seed(23), recipient),
        ];

        let transfer = Transfer {
            spends: vec![
                Spend {
                    note: &a,
                    sk_d: &sk_a,
                    path: &paths[0],
                    index: 0,
                },
                Spend {
                    note: &b,
                    sk_d: &sk_b,
                    path: &paths[1],
                    index: 1,
                },
            ],
            outputs,
            fee: 100,
        };
        transfer.check_balance().expect("fixture balances");

        let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, root);
        let tc = build_transfer_circuit(&transfer, &public)
            .expect("a balanced transfer with valid paths should witness");

        let (proof, verifier) = settle_transfer_circuit(&tc, LOG_MAX_LDE)
            .expect("settlement should prove the transfer circuit");
        verifier
            .verify(&proof, tc.statement())
            .expect("verifier should accept the honest transfer");
    }

    /// The statement is the security boundary of settlement: the same proof must
    /// be rejected against a different statement, or the chain would record
    /// whatever public values it liked.
    #[test]
    fn settlement_rejects_a_different_statement() {
        let (a, sk_a) = funded_note(3, 500);
        let (tree, paths) = tree_with(&[a]);
        let root = tree.root();
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(11));

        let transfer = Transfer {
            spends: vec![Spend {
                note: &a,
                sk_d: &sk_a,
                path: &paths[0],
                index: 0,
            }],
            outputs: vec![Note::new(400, seed(30), seed(31), recipient)],
            fee: 100,
        };
        let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, root);
        let tc = build_transfer_circuit(&transfer, &public).expect("should witness");
        let (proof, verifier) = settle_transfer_circuit(&tc, LOG_MAX_LDE).expect("should prove");

        let mut tampered = tc.statement().to_vec();
        tampered[0] += F::ONE;
        assert!(
            verifier.verify(&proof, &tampered).is_err(),
            "a tampered nullifier must not verify"
        );
    }

    /// An unbalanced transfer has no witness at all: the carry recurrence
    /// demands a non-integral carry, so the circuit is unsatisfiable rather than
    /// merely rejected later.
    #[test]
    fn unbalanced_transfer_cannot_be_witnessed() {
        let (a, sk_a) = funded_note(4, 500);
        let (tree, paths) = tree_with(&[a]);
        let root = tree.root();
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(12));

        let transfer = Transfer {
            spends: vec![Spend {
                note: &a,
                sk_d: &sk_a,
                path: &paths[0],
                index: 0,
            }],
            // 501 out of 500 in: conservation is false.
            outputs: vec![Note::new(501, seed(40), seed(41), recipient)],
            fee: 100,
        };
        let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, root);
        assert!(
            build_transfer_circuit(&transfer, &public).is_err(),
            "an unbalanced transfer must not witness"
        );
    }

    /// A path that does not fold to the published root cannot be witnessed: the
    /// fold is connected to the root, so a wrong sibling produces a conflict.
    #[test]
    fn wrong_membership_path_cannot_be_witnessed() {
        let (a, sk_a) = funded_note(5, 500);
        let (tree, mut paths) = tree_with(&[a]);
        let root = tree.root();

        // Spend a note that is *not* under this root.
        let outsider = funded_note(77, 500).0;
        let wrong_root = {
            let mut other = CommitmentTree::new(Keccak256Commitment);
            other.append(&outsider.commit(&Keccak256Commitment));
            other.root()
        };
        assert_ne!(root, wrong_root, "fixtures must differ");

        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(13));
        let transfer = Transfer {
            spends: vec![Spend {
                note: &a,
                sk_d: &sk_a,
                path: &mut paths[0],
                index: 0,
            }],
            outputs: vec![Note::new(400, seed(50), seed(51), recipient)],
            fee: 100,
        };
        // Public root is the *other* tree's root; the fold cannot reach it.
        let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, wrong_root);
        assert!(
            build_transfer_circuit(&transfer, &public).is_err(),
            "a path that folds to a different root must not witness"
        );
    }

    /// The in-circuit SHA3 framing must equal the native one, byte for byte.
    ///
    /// This is the pin that keeps `sha3_framed` from drifting from
    /// `Sha3_256Shielded::hash_to_digest`. The circuit computes the digest and
    /// is connected to the natively computed digest as constants; any mismatch in
    /// the length-prefix framing, the `0x06` pad, or the limb order makes the
    /// witness inconsistent and the build fails.
    #[test]
    fn circuit_sha3_matches_native_sha3() {
        let cases: [(&[u8], &[&[u8]]); 3] = [
            (DOMAIN_PK, &[&seed(1)]),
            (DOMAIN_NULLIFIER, &[&seed(2), &seed(3)]),
            (b"pq-rollup/empty/v1", &[]),
        ];

        for (domain, parts) in cases {
            let native = Sha3_256Shielded.hash_to_digest(domain, parts);

            let mut builder = CircuitBuilder::<Challenge>::new();
            builder.enable_keccak_f1600::<F>();
            let mut witness = Vec::new();
            let mut circuit_parts = Vec::new();
            for part in parts {
                let secret =
                    Secret::new(&mut builder, part, "test.part").expect("secret allocates");
                witness.extend(secret.witness.iter().copied());
                circuit_parts.push(secret.exprs);
            }
            let refs: Vec<&[ExprId]> = circuit_parts.iter().map(Vec::as_slice).collect();
            let computed =
                sha3_framed(&mut builder, domain, &refs).expect("sha3_framed should build");
            let expected = const_limbs(&mut builder, native.as_bytes());
            for (got, want) in computed.iter().zip(&expected) {
                builder.connect(*got, *want);
            }

            let circuit = builder.build().expect("circuit should build");
            let mut runner = circuit.runner();
            runner.set_public_inputs(&[]).expect("no public inputs");
            runner
                .set_private_inputs(&witness)
                .expect("private inputs should fit");
            runner.run().unwrap_or_else(|err| {
                panic!(
                    "sha3 framing mismatch for {}: {err}",
                    String::from_utf8_lossy(domain)
                )
            });
        }
    }

    /// The circuit's amount range must reject a value above the protocol bound.
    #[test]
    fn oversized_amount_cannot_be_witnessed() {
        let value = shielded::MAX_VALUE + 1;
        let mut builder = CircuitBuilder::<Challenge>::new();
        builder.enable_keccak_f1600::<F>();
        let amount = Amount::private(&mut builder, value)
            .expect("allocation is fine; the bound is enforced by the witness");
        let circuit = builder.build().expect("circuit should build");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no public inputs");
        runner
            .set_private_inputs(&amount.limbs.map(Challenge::from_u16))
            .expect("witness fits");
        assert!(
            runner.run().is_err(),
            "a value above MAX_VALUE must fail its top-limb range check"
        );
    }

    /// The spend-key derivation the circuit performs must match `derive_spend_pk`,
    /// which is what makes D-018's ownership argument hold in-circuit.
    #[test]
    fn circuit_pk_derivation_matches_native() {
        let sk_d = seed(6);
        let native: SpendPublicKey = derive_spend_pk(&Sha3_256Shielded, &sk_d);
        let mut builder = CircuitBuilder::<Challenge>::new();
        builder.enable_keccak_f1600::<F>();
        let secret = Secret::new(&mut builder, &sk_d, "test.sk").expect("secret allocates");
        let computed =
            sha3_framed(&mut builder, DOMAIN_PK, &[&secret.exprs]).expect("should build");
        let expected = const_limbs(&mut builder, native.as_bytes());
        for (got, want) in computed.iter().zip(&expected) {
            builder.connect(*got, *want);
        }
        let circuit = builder.build().expect("build");
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("no public inputs");
        runner
            .set_private_inputs(&secret.witness)
            .expect("witness fits");
        runner.run().expect("circuit pk_d must equal native pk_d");
    }

    /// The Merkle fold must mirror `MembershipPath::compute_root` at the real
    /// depth, for both index parities.
    #[test]
    fn merkle_fold_matches_native_at_every_depth() {
        for index in [0usize, 1, 2, 3, DEPTH - 1, 7] {
            let mut tree = CommitmentTree::new(Keccak256Commitment);
            // Pad so the leaf sits at `index`.
            for i in 0..index {
                tree.append(
                    &Note::new(
                        1,
                        seed(u8::try_from(i).expect("fits")),
                        seed(0),
                        SpendPublicKey::default(),
                    )
                    .commit(&Keccak256Commitment),
                );
            }
            let leaf = Note::new(1, seed(0), seed(0), SpendPublicKey::default())
                .commit(&Keccak256Commitment);
            let actual_index = tree.append(&leaf);
            assert_eq!(actual_index, index);
            let path = tree.path(index).expect("path").siblings;
            let root = tree.root();

            let mut builder = CircuitBuilder::<Challenge>::new();
            builder.enable_keccak_f1600::<F>();
            let mut witness = Vec::new();
            let leaf_exprs = const_limbs(&mut builder, leaf.as_bytes());
            let folded = fold_membership(&mut builder, &leaf_exprs, &path, index, &mut witness)
                .expect("fold should build");
            let expected = const_limbs(&mut builder, root.as_bytes());
            for (got, want) in folded.iter().zip(&expected) {
                builder.connect(*got, *want);
            }
            let circuit = builder.build().expect("build");
            let mut runner = circuit.runner();
            runner.set_public_inputs(&[]).expect("no public inputs");
            runner.set_private_inputs(&witness).expect("witness fits");
            runner
                .run()
                .unwrap_or_else(|e| panic!("fold mismatch at index {index}: {e}"));
        }
    }
}
