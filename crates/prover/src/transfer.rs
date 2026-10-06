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
//! 2. **Commitment** — the leaf is `H_p2(DOMAIN_NOTE ‖ value ‖ rho ‖ psi ‖ pk_d)`,
//!    the Poseidon2 sponge digest [`shielded::Note::commit`] produces with a
//!    `pq_hash::Poseidon2Commitment` hasher (D-088).
//! 3. **Membership** — the leaf folds through a sibling path to the published
//!    root, one Poseidon2 permutation per level.
//! 4. **Nullifier** — `nf = H_sha3(DOMAIN_NULLIFIER ‖ sk_d ‖ rho)`, published so
//!    a second spend of the same note is detectable.
//!
//! Globally:
//!
//! 5. **Value conservation** — `Σ inputs = Σ outputs + fee`, column-wise over
//!    16-bit limbs with a biased carry chain (D-017).
//! 6. **Commitment-tree transition** — every output leaf is appended to the
//!    commitment tree *in circuit* (D-088): the frontier witness is pinned to
//!    `root`, each output's leaf is merged bottom-up, and the resulting root is
//!    published as `root_after`. The settlement contract therefore stores the
//!    root instead of re-deriving it — the proof attests the whole transition.
//!
//! ## Three hashes, each doing one job
//!
//! * **SHA3-256** — nullifiers and spend-key derivation: never Merkle-folded,
//!   so its cost is a handful of permutations per spend and nothing more.
//! * **Poseidon2** — the commitment tree and everything the circuit must *prove
//!   about* the tree: membership folds and output appends. Arity-16 over
//!   `KoalaBear`, one permutation per node — cheap in circuit, which is what
//!   made the in-circuit append of D-088 affordable.
//! * **Keccak-f[1600]** — the nullifier map only. That tree stays Keccak
//!   because the *contract* replays nullifier-absence folds with the native
//!   `keccak256` opcode; the transfer proves each nullifier's absence
//!   in-circuit and the contract re-checks the fold cheaply.
//!
//! The commitment tree moved from Keccak to Poseidon2 in D-088 precisely because
//! the contract no longer folds it: with the append inside the proof, the
//! contract stores roots rather than re-deriving them (see `ShieldedPool`).
//!
//! ## The public statement
//!
//! The statement is exactly [`TransferPublic`]: nullifiers, output commitments,
//! the commitment root before and after, the nullifier-map root before and
//! after, and the fee. It
//! is exported through the statement table, so
//! `CircuitVerifier::verify(&proof, statement)` binds the proof to those bytes
//! and to nothing else.
//!
//! ## Nullifier non-membership is proven here
//!
//! Property 4 is stronger than "publish the nullifier so a replay is
//! detectable". Each spend runs the sparse-Merkle fold from
//! [`crate::nullifier_gadget`] against the nullifier-map root it inherited, so
//! the proof itself attests that the nullifier was absent — and yields the root
//! after inserting it. The thread runs `before → … → after`, which makes the
//! ordering of nullifiers inside a transfer binding, and lets the settlement
//! contract chain transfers without ever holding a nullifier set (D-032).

use std::fmt;

use p3_circuit::ops::{bytes_to_limbs, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitBuilderError, ExprId, StatementExport, StatementSchema, Traces,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::Poseidon2Config;

use pq_hash::Digest32;
use shielded::keys::DOMAIN_PK;
use shielded::note::{DOMAIN_NOTE, DOMAIN_NULLIFIER};
use shielded::{Note, Transfer, TransferPublic};

use crate::commitment_gadget::{
    self, append_to_frontier, digest_to_ext, export_digest_limbs, p2_compress, p2_sponge_limbs,
    AppendParams, DigestExpr, DigestExt, FrontierWitness, DIGEST_LIMBS,
};
use crate::nullifier_gadget::{constrain_nullifier_non_membership, NullifierWitness};
use crate::sha3_block::sha3_256_single_block;
use crate::whir_recursion::{whir_perm, Challenge, F};

/// Default trace height budget for transfer settlement.
///
/// WHIR derives a mandatory grinding budget from the arity of the polynomial it
/// commits to, and `WhirConfig` *refuses to build* when the required bits exceed
/// the budget. The transfer circuit's arity grows with what it does: a 1-in/1-out
/// transfer needs 19 ground bits, a 2-in/2-out needs 20. The nullifier gadget
/// added roughly 290 Keccak-f per spend (32 absence + 256 insert), which is
/// what pushed this up from 24.
///
/// This constant is the default for the *largest shape the tests exercise*, not
/// a protocol parameter: `settle_transfer_circuit` takes `log_max_lde` per
/// call, so a node sizes each circuit to its own measured arity.
///
/// **Over-provisioning is not free.** The prover pads to the declared height, so
/// a larger budget means a larger LDE and more work — roughly 2.7x between
/// v=25 and v=27 on a fan-in-2 block. Under-provisioning panics inside the PCS
/// rather than returning an error, which is why the value is measured rather
/// than guessed.
///
/// The verifier's cost is unchanged either way: grinding is prover-side work
/// checked with a single hash.
pub const LOG_MAX_LDE: usize = 26;

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
pub(crate) fn const_limbs(builder: &mut CircuitBuilder<Challenge>, bytes: &[u8]) -> Vec<ExprId> {
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

/// Constrain one transfer's five properties into an existing builder.
///
/// This is [`build_transfer_circuit`] minus the builder's creation, statement
/// installation, and witness run, so a larger circuit — a block — can lay
/// several transfers and a recursion edge into *one* builder and export a single
/// combined statement. The transfer's own constraints are unchanged; only the
/// ownership of the builder moves.
///
/// Returns the transfer's statement expressions in the order
/// `[nullifiers…, output_commitments…, root, root_after, nullifier_root_before,
/// nullifier_root_after, fee]`, which the caller places inside its own
/// statement export list.
///
/// `nullifier_witnesses` is one [`NullifierWitness`] per spend, in spend order,
/// each prepared against the nullifier map as it stands *before* that spend's
/// nullifier is inserted. The witnesses are what let the circuit prove absence
/// without holding the map.
///
/// `frontier` is the commitment tree's frontier witness at `public.root`
/// (D-088): the digests and count bits that let the circuit re-derive the
/// append of each output leaf without holding the tree. It must be the frontier
/// of the tree whose root is `public.root` -- the gadget pins it there before
/// appending, so a mismatched frontier makes the transfer unwitnessable.
/// A transfer with no outputs may pass [`FrontierWitness::empty`].
///
/// # Errors
///
/// Returns [`CircuitBuilderError`] if a preimage has an odd byte length (limbs
/// pack two bytes), a Keccak-f call is malformed, or the witness slice does not
/// line up with the number of spends.
pub fn constrain_transfer(
    builder: &mut CircuitBuilder<Challenge>,
    transfer: &Transfer<'_>,
    public: &TransferPublic,
    nullifier_witnesses: &[NullifierWitness],
    frontier: &FrontierWitness,
    private: &mut Vec<Challenge>,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let parties = transfer.spends.len().max(transfer.outputs.len() + 1);
    if parties > MAX_PARTIES {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: MAX_PARTIES,
            actual: parties,
        });
    }

    let mut statement: Vec<ExprId> = Vec::new();
    let mut input_amounts: Vec<Amount> = Vec::new();
    let mut output_amounts: Vec<Amount> = Vec::new();

    if nullifier_witnesses.len() != transfer.spends.len() {
        return Err(CircuitBuilderError::InvalidDimension {
            expected: transfer.spends.len(),
            actual: nullifier_witnesses.len(),
        });
    }

    // The nullifier-map root, threaded through the spends. Each spend proves its
    // own absence against the current root and advances it by inserting its
    // nullifier; the final value must equal `public.nullifier_roots.after`.
    // Starting from `before` rather than a fresh constant is what makes the
    // ordering of nullifiers inside a transfer binding.
    let mut nf_root = const_limbs(builder, public.nullifier_roots.before.as_bytes());

    // The published commitment root as extension-field constants: both the
    // spends' membership folds and the outputs' frontier fold are pinned to
    // this value, so one digest parse serves all of them. A non-canonical root
    // (an element at or above the modulus) has no field representation at all,
    // which is an error, not a silent truncation.
    let root_ext = digest_to_ext(&Digest32::new(*public.root.as_bytes())).ok_or(
        CircuitBuilderError::InvalidDimension {
            expected: DIGEST_LIMBS,
            actual: 0,
        },
    )?;

    // ---- Inputs: ownership, membership, nullifier -----------------------
    for (spend, nf_witness) in transfer.spends.iter().zip(nullifier_witnesses) {
        let sk = Secret::new(builder, spend.sk_d, "transfer.sk_d")?;
        let rho = Secret::new(builder, spend.note.rho(), "transfer.rho")?;
        let psi = Secret::new(builder, spend.note.psi(), "transfer.psi")?;
        let amount = Amount::private(builder, spend.note.value())?;
        private.extend(sk.witness.iter().copied());
        private.extend(rho.witness.iter().copied());
        private.extend(psi.witness.iter().copied());
        private.extend(amount.limbs.iter().map(|&l| Challenge::from_u16(l)));

        // (1) Ownership. `pk_d` is derived, never supplied: the only way to
        // produce a witness here is to know `sk_d`.
        let pk_d = sha3_framed(builder, DOMAIN_PK, &[&sk.exprs])?;

        // (2) Commitment, over the exact native preimage (D-088: the Poseidon2
        // sponge digest `Note::commit` produces with a Poseidon2 hasher).
        let mut leaf_msg = const_limbs(builder, DOMAIN_NOTE);
        leaf_msg.extend(amount.exprs.iter().copied());
        leaf_msg.extend(rho.exprs.iter().copied());
        leaf_msg.extend(psi.exprs.iter().copied());
        leaf_msg.extend(pk_d.iter().copied());
        let leaf = p2_sponge_limbs(builder, &leaf_msg)?;

        // (3) Membership: fold to the root, mirroring
        // `MembershipPath::compute_root`, and bind the fold to the published root.
        // Arithmetic equality, not `connect`: the fold's last row is a
        // permutation output, and aliasing lookup outputs desynchronises the
        // LogUp multiplicities.
        let folded = fold_membership_p2(builder, leaf, spend.path, spend.index, private)?;
        for (idx, got) in folded.iter().enumerate() {
            let want = builder.define_const(root_ext[idx]);
            let diff = builder.sub(*got, want);
            builder.assert_zero(diff);
        }

        // (4) Nullifier, and its absence from the nullifier map.
        //
        // The nullifier is derived here, so the address the fold walks is the
        // one this spend actually produces — the prover cannot pick a
        // different, emptier address. The fold asserts absence against the
        // current root and yields the root after insertion, which becomes the
        // next spend's starting root.
        let nullifier = sha3_framed(builder, DOMAIN_NULLIFIER, &[&sk.exprs, &rho.exprs])?;
        let (absent, next_root) =
            constrain_nullifier_non_membership(builder, &nullifier, nf_witness)?;
        // Arithmetic equality, not `connect`. From the second spend onward
        // `nf_root` is the *previous spend's* fold output — a live witness
        // expression, not a constant — and `connect` aliases witness slots.
        // Keccak-f is a lookup argument, so aliasing two of its output slots
        // desynchronises the LogUp multiplicities and the witness fails to
        // balance. A subtraction is a plain ALU constraint and leaves the
        // lookup structure alone.
        for (got, want) in absent.iter().zip(&nf_root) {
            let diff = builder.sub(*got, *want);
            builder.assert_zero(diff);
        }
        nf_root = next_root;
        statement.extend(nullifier);

        input_amounts.push(amount);
    }

    // ---- Outputs: hash, append, chain ---------------------------------
    let tree_root = constrain_outputs(
        builder,
        transfer,
        root_ext,
        frontier,
        private,
        &mut statement,
        &mut output_amounts,
    )?;

    // ---- The published roots and the fee ------------------------------
    //
    // The root *before* is exported as constants: the spends' folds and the
    // frontier's pin already bind every witness to it, so the statement value
    // is proven, not supplied.
    statement.extend(const_limbs(builder, public.root.as_bytes()));

    // `root_after` is *computed* above, not supplied: the export lands in the
    // statement, and the statement is what the verifier checks. The published
    // value must equal it or the proof simply does not verify - and the pin
    // below makes a mismatch fail at build time rather than at verify time.
    let computed_after = export_digest_limbs(builder, &tree_root)?;
    let want_after = const_limbs(builder, public.root_after.as_bytes());
    for (got, want) in computed_after.iter().zip(&want_after) {
        let diff = builder.sub(*got, *want);
        builder.assert_zero(diff);
    }
    statement.extend(computed_after);

    // The threaded nullifier root must land on the published `after`. With no
    // spends the thread never moved, so `before == after` is required there —
    // which is exactly what `NullifierRoots::empty` encodes.
    //
    // Both roots are exported. `before` is already pinned as the fold's starting
    // point, but publishing it is what lets the settlement contract chain one
    // transfer's `after` onto the next transfer's `before`.
    let before = const_limbs(builder, public.nullifier_roots.before.as_bytes());
    let after = const_limbs(builder, public.nullifier_roots.after.as_bytes());
    for (got, want) in nf_root.iter().zip(&after) {
        builder.connect(*got, *want);
    }
    statement.extend(before);
    statement.extend(after);

    let fee = Amount::private(builder, transfer.fee)?;
    private.extend(fee.limbs.iter().map(|&l| Challenge::from_u16(l)));
    statement.extend(fee.exprs.iter().copied());

    // ---- (5) Value conservation ---------------------------------------
    constrain_balance(builder, &input_amounts, &output_amounts, &fee, private)?;

    Ok(statement)
}

/// Constrain the output side of a transfer (D-088).
///
/// Each output's leaf is hashed in-circuit and appended to the frontier
/// pinned at `root_before`. The appends chain - output *i*'s `root_after` is
/// output *i+1*'s `root_before` - so the returned root is the tree state
/// after *all* of this transfer's outputs, which the caller publishes as the
/// statement's `root_after`; the settlement contract can then store it
/// without re-deriving anything. Each output's commitment limbs are appended
/// to `statement` and its amount to `output_amounts`, in output order.
fn constrain_outputs(
    builder: &mut CircuitBuilder<Challenge>,
    transfer: &Transfer<'_>,
    root_ext: DigestExt,
    frontier: &FrontierWitness,
    private: &mut Vec<Challenge>,
    statement: &mut Vec<ExprId>,
    output_amounts: &mut Vec<Amount>,
) -> Result<DigestExpr, CircuitBuilderError> {
    let params = AppendParams::new(&pq_hash::Poseidon2Commitment::default());
    // The frontier fold starts at the published root: `constrain_append` pins
    // the witness`s fold to this value before merging anything, so a frontier
    // from any other tree state cannot witness.
    let mut tree_root: DigestExpr = [
        builder.define_const(root_ext[0]),
        builder.define_const(root_ext[1]),
    ];
    for (i, note) in transfer.outputs.iter().enumerate() {
        let rho = Secret::new(builder, note.rho(), "output.rho")?;
        let psi = Secret::new(builder, note.psi(), "output.psi")?;
        let amount = Amount::private(builder, note.value())?;
        private.extend(rho.witness.iter().copied());
        private.extend(psi.witness.iter().copied());
        private.extend(amount.limbs.iter().map(|&l| Challenge::from_u16(l)));

        // The recipient's spend key is public to the sender, so it is a
        // constant: the output commitment is pinned, not chosen.
        let mut leaf_msg = const_limbs(builder, DOMAIN_NOTE);
        leaf_msg.extend(amount.exprs.iter().copied());
        leaf_msg.extend(rho.exprs.iter().copied());
        leaf_msg.extend(psi.exprs.iter().copied());
        leaf_msg.extend(const_limbs(builder, note.pk_d().as_bytes()));
        let commitment = p2_sponge_limbs(builder, &leaf_msg)?;
        statement.extend(export_digest_limbs(builder, &commitment)?);

        // The frontier witness for this append is the tree state after the
        // first `i` outputs of this transfer were appended to `public.root`.
        let step = frontier_step(frontier, i, &transfer.outputs).map_err(|_| {
            CircuitBuilderError::InvalidDimension {
                expected: DIGEST_LIMBS,
                actual: 0,
            }
        })?;
        let append =
            commitment_gadget::constrain_append(builder, &params, &step, &commitment, &tree_root)?;
        private.extend(append.witness.iter().copied());
        tree_root = append.root_after;

        output_amounts.push(amount);
    }
    Ok(tree_root)
}
/// The frontier state after the first `i` outputs of this transfer were appended.
///
/// The circuit's appends chain - output `i`'s root is output `i+1`'s starting
/// point - so each append needs the frontier *at that point*, not the transfer's
/// starting frontier. Deriving it natively (clone, then one merge per preceding
/// output) is cheap: a merge is at most 32 permutations and outputs per transfer
/// are few.
///
/// Errors only if the tree is full (2^32 leaves), which the circuit also
/// refuses: the carry-out of the count increment is constrained to zero.
fn frontier_step(
    frontier: &FrontierWitness,
    i: usize,
    outputs: &[Note],
) -> Result<FrontierWitness, String> {
    let hasher = pq_hash::Poseidon2Commitment::default();
    let mut step = frontier.clone();
    for note in outputs.iter().take(i) {
        let leaf = note.commit(&hasher);
        append_to_frontier(
            &hasher,
            &mut step,
            &pq_hash::Digest32::new(*leaf.as_bytes()),
        )?;
    }
    Ok(step)
}

/// Build and witness a transfer circuit against a published [`TransferPublic`].
///
/// A thin wrapper: create the builder, enable Keccak-f, Poseidon2 and
/// recompose, constrain the transfer, install the statement sink, build, and
/// witness. Every property lives in [`constrain_transfer`].
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
    nullifier_witnesses: &[NullifierWitness],
    frontier: &FrontierWitness,
) -> Result<TransferCircuit, Box<dyn std::error::Error>> {
    let mut builder = CircuitBuilder::<Challenge>::new();
    builder.enable_keccak_f1600::<F>();
    // D-088: the commitment tree is Poseidon2, so the circuit needs the
    // permutation table (membership folds, output appends) and the recompose
    // table (base-coefficient packing the perm rows read). Same shape the
    // recursion circuit enables - one shared KoalaBear D4 width-16 config.
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        whir_perm(),
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let mut private: Vec<Challenge> = Vec::new();
    let statement = constrain_transfer(
        &mut builder,
        transfer,
        public,
        nullifier_witnesses,
        frontier,
        &mut private,
    )?;

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

/// Fold a leaf through a sibling path to the root with Poseidon2 compressions,
/// mirroring [`shielded::MembershipPath::compute_root`] under a
/// [`pq_hash::Poseidon2Commitment`] hasher: bit `i` of the index selects which
/// side `siblings[i]` sits on, and each level is one permutation.
///
/// The index is a *witness*, not a constant, so the side selection is a circuit
/// select driven by a boolean-constrained bit. Making it a constant would let the
/// prover pick the fold that suits it.
///
/// The fold runs on *extension* digest expressions - two elements - not the 16
/// wire limbs the Keccak fold used: Poseidon2 digests are field-native, so each
/// level is two selects and one perm row instead of sixteen selects and a
/// 24-round permutation.
fn fold_membership_p2(
    builder: &mut CircuitBuilder<Challenge>,
    leaf: DigestExpr,
    siblings: &[pq_hash::Digest32],
    index: usize,
    private: &mut Vec<Challenge>,
) -> Result<DigestExpr, CircuitBuilderError> {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        // A non-canonical sibling has no field representation; that is a witness
        // bug, reported as a shape error rather than a silent truncation.
        let sibling_ext = digest_to_ext(sibling).ok_or(CircuitBuilderError::InvalidDimension {
            expected: DIGEST_LIMBS,
            actual: 0,
        })?;
        let sib: DigestExpr = [
            builder.define_const(sibling_ext[0]),
            builder.define_const(sibling_ext[1]),
        ];
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
        let left: DigestExpr = [
            builder.select(bit, sib[0], current[0]),
            builder.select(bit, sib[1], current[1]),
        ];
        let right: DigestExpr = [
            builder.select(bit, current[0], sib[0]),
            builder.select(bit, current[1], sib[1]),
        ];
        current = p2_compress(builder, &left, &right)?;
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
/// them: nullifiers, output commitments, root, root after, nullifier roots, fee.
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
    out.extend(
        bytes_to_limbs(public.root_after.as_bytes())
            .iter()
            .map(|&l| F::from_u16(l)),
    );
    out.extend(
        bytes_to_limbs(public.nullifier_roots.before.as_bytes())
            .iter()
            .map(|&l| F::from_u16(l)),
    );
    out.extend(
        bytes_to_limbs(public.nullifier_roots.after.as_bytes())
            .iter()
            .map(|&l| F::from_u16(l)),
    );
    out.extend(split_value(public.fee).iter().map(|&l| F::from_u16(l)));
    out
}

/// Prove a witnessed transfer circuit under the Keccak WHIR settlement config.
///
/// The circuit's non-primitive operations are Keccak-f[1600] (the nullifier
/// map), Poseidon2 (the commitment tree, D-088), recompose (the base packing
/// the perm rows read), and the statement table; all four are registered. The
/// returned verifier binds the statement: `verify(&proof, pis)`
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
    let settlement = crate::whir::config(0, log_max_lde)?;
    settle_transfer_circuit_with(tc, settlement)
}

/// Prove a witnessed transfer circuit under an arbitrary WHIR configuration.
///
/// This is the same proving run as [`settle_transfer_circuit`], generalised over
/// the STARK configuration so the transfer can be proven under *either* layer of
/// the architecture:
///
/// * the Keccak `OutSC` ([`crate::whir::Config`]) for direct settlement, or
/// * the Poseidon2 `InSC` ([`crate::whir_recursion::InnerWhirConfig`]) when the
///   proof is going to be re-verified inside a recursion circuit.
///
/// Generalising is possible because nothing in the transfer's own relation depends
/// on the commitment scheme. The circuit is `Circuit<Challenge>` in both cases —
/// the same degree-4 extension — and its two non-primitive tables are keyed on
/// the *base* field, `KoalaBear`, which both configurations share:
///
/// * `KeccakF1600Preprocessor` is implemented for `BinomialExtensionField<KoalaBear, 4>`,
/// * `StatementPreprocessor` likewise.
///
/// The PCS and the Fiat-Shamir challenger are the only things that differ, and
/// neither appears in a transfer constraint. They decide *how the proof is
/// committed and hashed*, which is exactly the property that must change between
/// layers, and exactly the property the AIR is indifferent to.
///
/// # Errors
///
/// Returns a prover error if the circuit cannot be prepared or proven under
/// `config` — most commonly a trace-height or grinding-budget mismatch.
pub fn settle_transfer_circuit_with<SC>(
    tc: &TransferCircuit,
    config: SC,
) -> Result<
    (
        p3_circuit_prover::BatchStarkProof<SC>,
        p3_circuit_prover::CircuitVerifier<SC>,
    ),
    Box<dyn std::error::Error>,
>
where
    SC: p3_uni_stark::StarkGenericConfig<Challenge = Challenge> + Send + Sync + Clone + 'static,
    p3_uni_stark::Val<SC>: p3_field::PrimeField64
        + p3_field::Field
        + p3_circuit_prover::config::StarkField
        // D-088: the Poseidon2 and recompose tables are keyed on the base field
        // and implemented per field, exactly like the Keccak preprocessor below -
        // the bound is what lets a caller settle under *either* WHIR config, since
        // both are KoalaBear-based.
        + p3_field::extension::BinomiallyExtendable<4>,
    Challenge: p3_field::ExtensionField<p3_uni_stark::Val<SC>>
        + p3_field::BasedVectorSpace<p3_uni_stark::Val<SC>>
        + From<p3_uni_stark::Val<SC>>
        + p3_circuit_prover::field_params::ExtractBinomialW<p3_uni_stark::Val<SC>>,
    SC::Challenger: p3_challenger::GrindingChallenger<Witness = p3_uni_stark::Val<SC>>,
    p3_uni_stark::PcsProverError<SC>: Send,
    SC::Pcs: Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::Domain: Send + Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as p3_commit::Pcs<Challenge, SC::Challenger>>::Commitment: Sync,
    p3_air::SymbolicExpressionExt<p3_uni_stark::Val<SC>, Challenge>: p3_field::Algebra<p3_uni_stark::SymbolicExpression<p3_uni_stark::Val<SC>>>
        + p3_field::Algebra<Challenge>,
    p3_circuit_prover::batch_stark_prover::KeccakF1600Preprocessor:
        p3_circuit_prover::common::NpoPreprocessor<p3_uni_stark::Val<SC>>,
    p3_circuit_prover::batch_stark_prover::StatementPreprocessor:
        p3_circuit_prover::common::NpoPreprocessor<p3_uni_stark::Val<SC>>,
    p3_circuit_prover::batch_stark_prover::Poseidon2SharedPreprocessor:
        p3_circuit_prover::common::NpoPreprocessor<p3_uni_stark::Val<SC>>,
    p3_circuit_prover::batch_stark_prover::RecomposePreprocessor:
        p3_circuit_prover::common::NpoPreprocessor<p3_uni_stark::Val<SC>>,
    p3_circuit_prover::batch_stark_prover::Poseidon2AirBuilderForConfig<4>:
        p3_circuit_prover::common::NpoAirBuilder<SC, 4>,
    p3_circuit_prover::batch_stark_prover::RecomposeAirBuilder<4>:
        p3_circuit_prover::common::NpoAirBuilder<SC, 4>,
{
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
        Poseidon2AirBuilderForConfig, Poseidon2SharedPreprocessor, RecomposeAirBuilder,
        RecomposePreprocessor, StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
    use p3_circuit_prover::ConstraintProfile;

    // The shared-challenger form of the perm table, matching what the recursion
    // layer registers for its own Poseidon2 rows: one table serves every
    // Poseidon2 shape in the circuit.
    let shared = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<p3_uni_stark::Val<SC>>>> = vec![
        Box::new(KeccakF1600Preprocessor),
        Box::new(Poseidon2SharedPreprocessor::new(vec![shared])),
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(tc.schema.clone())),
    ];
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, 4>>> = vec![
        Box::new(KeccakF1600AirBuilder::<4>),
        Box::new(Poseidon2AirBuilderForConfig::<4>::new(shared)),
        Box::new(RecomposeAirBuilder::<4>::new(1, true)),
        Box::new(StatementAirBuilder::<4>::new(tc.schema.clone())),
    ];

    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(p3_recursion::ProveNextLayerParams::default().table_packing);
    prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
    prover.register_poseidon2_table::<4>(shared);
    prover.register_recompose_table::<4>(true);
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
    use crate::fixtures::{public_and_witnesses, tree_with};
    use pq_hash::{Poseidon2Commitment, Sha3_256Shielded, ShieldedHasher};
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
    /// The transfer, one recursion layer deep.
    ///
    /// This is the integration the settlement story was missing: the same witnessed
    /// transfer circuit is proven twice, and the second proof *verifies the first
    /// inside a circuit*.
    ///
    /// ```text
    ///   transfer circuit --prove--> BatchStarkProof<InnerWhirConfig>   (Poseidon2 WHIR)
    ///                                     |  re-verified in-circuit
    ///                                     v
    ///              batch recursion circuit --prove--> Keccak WHIR proof  (OutSC)
    /// ```
    ///
    /// The point of the round trip is that the statement survives it unchanged. The
    /// recursion circuit binds its own exported statement to the *inner* proof's
    /// statement table, so the Keccak-settled proof that reaches the chain attests
    /// to exactly the `[nullifiers, output commitments, root, root_after,
    /// nullifier roots, fee]` the transfer
    /// was witnessed against — not to "some recursion happened".
    ///
    /// The inner layer must be the Poseidon2 `InSC` because a Keccak wire-cap MMCS
    /// cannot satisfy the recursion engine's field-native cap bound (see
    /// [`crate::whir_recursion`]). That is the whole reason the two configs exist.
    #[test]
    fn transfer_proves_under_recursion_and_keeps_its_statement() {
        use crate::whir_recursion::{
            build_batch_recursion_circuit, settle_recursion_circuit, InnerWhirConfig,
        };

        let (a, sk_a) = funded_note(1, 1_000);
        let (tree, paths) = tree_with(&[a]);

        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let outputs = vec![Note::new(900, seed(20), seed(21), recipient)];

        let transfer = Transfer {
            spends: vec![Spend {
                note: &a,
                sk_d: &sk_a,
                path: &paths[0],
                index: 0,
            }],
            outputs,
            fee: 100,
        };
        transfer.check_balance().expect("fixture balances");

        let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
        let tc = build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
            .expect("a balanced transfer with a valid path should witness");

        // Layer 0: the transfer under the recursion-capable Poseidon2 WHIR config.
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config should build");
        let (inner_proof, inner_verifier) = settle_transfer_circuit_with(&tc, inner.clone())
            .expect("the transfer should prove under the InSC");
        inner_verifier
            .verify(&inner_proof, tc.statement())
            .expect("the InSC verifier should accept the honest transfer");

        // Layer 1: re-verify that proof inside a circuit, binding this circuit's
        // statement to the inner statement table.
        let rc =
            build_batch_recursion_circuit(&inner, &inner_verifier, &inner_proof, tc.statement())
                .expect("the batch recursion circuit should build and witness");

        // Layer 1 settlement: the recursion circuit proven under Keccak WHIR, so
        // what reaches the chain has a Keccak transcript Solidity can replay.
        let (outer_proof, outer_verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE)
            .expect("the recursion circuit should settle under Keccak WHIR");

        // The statement forwarded through both layers is the transfer's own.
        outer_verifier
            .verify(&outer_proof, tc.statement())
            .expect("the settled recursion proof should attest to the transfer statement");

        // And the binding is load-bearing at the far end of the chain: a different
        // statement must be rejected even though the proof is otherwise untouched.
        let mut tampered = tc.statement().to_vec();
        tampered[0] += F::ONE;
        assert!(
            outer_verifier.verify(&outer_proof, &tampered).is_err(),
            "a settled recursion proof must not attest to a statement other than the transfer's"
        );
    }

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

    /// End to end: a balanced 2-in / 2-out transfer builds, proves, and verifies
    /// against its own statement.
    #[test]
    fn transfer_proves_and_verifies() {
        let (a, sk_a) = funded_note(1, 1_000);
        let (b, sk_b) = funded_note(2, 2_500);
        let (tree, paths) = tree_with(&[a, b]);

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

        let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
        let tc = build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
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
        let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
        let tc = build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier)
            .expect("should witness");
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
        let (public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
        assert!(
            build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier).is_err(),
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
            let h = Poseidon2Commitment::default();
            let mut other = CommitmentTree::new(h.clone());
            other.append(&outsider.commit(&h));
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
        let (mut public, nf_witnesses, frontier) = public_and_witnesses(&transfer, &tree);
        public.root = wrong_root;
        assert!(
            build_transfer_circuit(&transfer, &public, &nf_witnesses, &frontier).is_err(),
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

    /// The in-circuit Poseidon2 Merkle fold must mirror
    /// `MembershipPath::compute_root` at the real depth, for both index parities.
    ///
    /// This is the D-088 counterpart of the old Keccak fold test: the tree hash
    /// moved to Poseidon2, so the fold that the spend path uses is now the P2 one.
    #[test]
    fn merkle_fold_matches_native_at_every_depth() {
        let h = Poseidon2Commitment::default();
        for index in [0usize, 1, 2, 3, DEPTH - 1, 7] {
            let mut tree = CommitmentTree::new(h.clone());
            // Pad so the leaf sits at `index`.
            for i in 0..index {
                tree.append(
                    &Note::new(
                        1,
                        seed(u8::try_from(i).expect("fits")),
                        seed(0),
                        SpendPublicKey::default(),
                    )
                    .commit(&h),
                );
            }
            let leaf = Note::new(1, seed(0), seed(0), SpendPublicKey::default()).commit(&h);
            let actual_index = tree.append(&leaf);
            assert_eq!(actual_index, index);
            let path = tree.path(index).expect("path").siblings;
            let root = tree.root();

            let mut builder = CircuitBuilder::<Challenge>::new();
            builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
                whir_perm(),
            );
            builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
            let mut witness = Vec::new();
            let leaf_ext = digest_to_ext(&Digest32::new(*leaf.as_bytes())).expect("canonical");
            let leaf_exprs: DigestExpr = [
                builder.define_const(leaf_ext[0]),
                builder.define_const(leaf_ext[1]),
            ];
            let folded = fold_membership_p2(&mut builder, leaf_exprs, &path, index, &mut witness)
                .expect("fold should build");
            let expected = digest_to_ext(&Digest32::new(*root.as_bytes())).expect("canonical");
            for (got, want) in folded.iter().zip(&expected) {
                let want_c = builder.define_const(*want);
                let diff = builder.sub(*got, want_c);
                builder.assert_zero(diff);
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
