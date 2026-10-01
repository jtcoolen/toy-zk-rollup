# Decisions log

Recorded choices with alternatives considered. Newest first.

## D-023 — Transfer integrated with the recursive prover (fan-in 1, linear chain)

**Status.** Implemented and tested. Closes the gap flagged when the user asked
"have you integrated the transfer circuit to the recursive prover?" — before this,
`transfer` and `whir_recursion` had never been joined.

**Decision.** Three pieces:

1. `transfer::settle_transfer_circuit_with<SC>` — the existing settlement run,
   generalised over the STARK config. Provable under *either* layer because
   nothing in the transfer's relation depends on the commitment scheme: the
   circuit is `Circuit<Challenge>` in both cases, and both of its non-primitive
   tables (`KeccakF1600Preprocessor`, `StatementPreprocessor`) are keyed on the
   *base* field `KoalaBear`, which both configs share. The PCS and the
   Fiat-Shamir challenger are the only things that differ between layers, and
   neither appears in a transfer constraint.
2. `whir_recursion::build_batch_recursion_circuit` — re-verifies a
   `BatchStarkProof<InnerWhirConfig>` inside a circuit and binds the outer
   statement to the inner statement table.
3. `transfer::tests::transfer_proves_under_recursion_and_keeps_its_statement` —
   the round trip, plus rejection of a tampered statement at the far end.

```text
transfer circuit ──prove──▶ BatchStarkProof<InnerWhirConfig>   (Poseidon2 WHIR, InSC)
        │ re-verified in-circuit, exactly one child
        ▼
batch recursion circuit ──prove──▶ Keccak WHIR proof           (OutSC, chain-facing)
```

**Why the trusted entry point.** `verify_trusted_p3_batch_proof_circuit` rather
than `verify_p3_batch_proof_circuit`. The trusted variant derives every table AIR
and every table's public values from the *retained verifier descriptor*, not from
the proof, so a proof cannot choose its own relation. It also runs
`verifier.verify(proof, statement)` before allocating anything, which is what
makes the statement binding real rather than advisory.

**Why not `TrustedPreparedLayer`.** It is the tidy upstream wrapper and was the
first attempt, but its `OutSC` must itself satisfy `WhirRecursionConfig` — so it
cannot take the Keccak `OutSC`, which is the whole point of the settlement layer.
Hand-building with the public backend methods reaches the same result and keeps the
InSC/OutSC split. `TrustedPreparedLayer` is usable for InSC→InSC chaining only.

**Statement binding is per-instance.** The statement table is one instance among
the batch's non-primitive tables; its index comes from
`verifier.statement_layout().table_instance()`. The circuit's statement sink is
installed from *that instance's* AIR public-value targets — the same targets the
in-circuit verifier constrained.

**Topology: fan-in 1, not a tree.** Answering the user's question directly — this
is a linear chain, not tree-shaped aggregation. `BatchStarkProof`'s "batch" is
the *proving-system shape* (several AIR instances folded into one proof:
primitive ALU + Keccak-f + statement), **not** a batch of transfers. Each
`TransferCircuit` is one transfer.

Fan-in 1 first because it is the piece that proves the join works: if a single
child's statement does not survive in-circuit re-verification, neither will N
children's. Fan-in 2 is then a mechanical doubling.

**Not chosen here (deferred to the block layer, D-022).** Tree aggregation via
`TrustedPreparedAggregation` / `PreparedAggregation{,Cross}` /
`build_and_prove_aggregation_layer{,_cross}`. Upstream aggregation is **binary
only**, so folding N transfers costs `2N−1` proofs and `log₂N` sequential depth.
Depth is the expensive axis: each WHIR layer is the slow one, so latency grows
with `log N` while proof count grows linearly either way.

## D-022 — Block metadata binding via statement forwarding (InSC/OutSC split)

**Status.** Designed, not yet implemented. Recorded because the gap is load-bearing:
as of the transfer AIR landing, **no block metadata is bound to any proof**.

**Decision.** Bind L2 block metadata by making it part of the recursive
statement, with the transfer sitting in the inner seat:

| Layer | Proven under | Statement |
|---|---|---|
| 0 — transfer | Poseidon2 WHIR (InSC), field-native caps | `[nullifiers, output_cms, root, fee]` |
| 1 — block/batch | verifies N layer-0 batch proofs | `[chain_id, block_number, timestamp, root_before, root_after, tx_root]` |
| 2 — settlement | Keccak WHIR (OutSC) | forwards the layer-1 statement verbatim |

**Why the transfer must move to the InSC config.** The transfer is currently
settled under the Keccak `OutSC`, whose commitments are the `[u64;4]` wire-cap
MMCS. WHIR recursion requires
`MT: Mmcs<Val, Commitment = MerkleCap<Val, [Val; DIGEST_ELEMS]>>` —
field-native — so a Keccak-committed WHIR proof cannot be re-verified inside a
WHIR recursion circuit. As settled today the transfer proof is single-layer
chain-verifiable but **not recursively aggregatable**, which defeats the point of
recursion (on-chain cost independent of batch size). Proving layer 0 under the
Poseidon2 InSC makes it recursively verifiable; the Keccak `OutSC` stays at the
outer layer, where Solidity replays it with the native `keccak256` opcode. This
is the same split already proven by
`whir_recursion::keccak_settlement_proves_the_recursion_circuit`, with the
transfer in the Fibonacci seat.

**Three things that make the binding real rather than decorative.**

1. *Metadata is constrained, not merely exported.* Exporting an unconstrained
   target into a statement lets the prover write anything there, so the export
   alone proves nothing. `block_number` is constrained in-circuit to
   `prev_block_number + 1`, and every metadata field enters the statement as a
   raw base-field limb.
2. *Root chaining.* Each transfer proves membership against *a* root; nothing
   proves the batch shares one root, or that applying its outputs yields
   `root_after`. Layer 1 asserts a common `root_before` and derives `root_after`
   from the batch output commitments.
3. *The chain enforces liveness and replay.* The verifier contract rejects a
   proof whose `(chain_id, block_number)` is not the next expected pair, so a
   valid-but-old proof fails on the contract's state check rather than on the
   cryptography. `chain_id` in the statement is what makes a proof from a
   different chain unusable — the cross-chain replay protection ZK rollups need.

**Why raw fields and not one metadata hash.** The statement is base-field limbs
and the Solidity verifier reconstructs it from calldata it already has. A
single `H(metadata ‖ roots)` would force the raw fields into calldata *anyway*
(the contract needs the roots to update state) while adding a second hashing
path — in-circuit and in Solidity — that must never drift. Raw limbs remove that
class of bug entirely.

**Alternatives considered.**
- *Bind metadata only at the settlement layer, leaving transfers metadata-free.*
  Rejected: the settlement layer would then be proving a statement it did not
  constrain, which is exactly the "proof of *some* computation" failure the
  statement exists to prevent.
- *Keep the transfer on the Keccak OutSC and aggregate with a non-WHIR layer.*
  Rejected: introduces a second aggregation primitive to audit for no gain; the
  InSC/OutSC split already works.
- *Put the L1 block hash in the statement.* Deferred, not rejected: it gives
  L1-liveness binding but couples proof validity to L1 finality timing. Worth
  doing once the settlement contract exists and the sequencing is settled.

**Open prerequisite.** Nullifier non-membership (D-018 follow-up) must land
before settlement is sound; metadata binding does not substitute for it.

## D-021 — Transfer settlement sized at `LOG_MAX_LDE = 24`

**Decision.** The transfer circuit is settled with a WHIR config declared at 24
variables (`prover::transfer::LOG_MAX_LDE`), one level above the 22 the
recursion circuit uses.

**Why.** WHIR derives a *mandatory* grinding budget from the arity of the
polynomial it commits to, and `WhirConfig::new` refuses to build when the
required bits exceed the declared budget. Measured on our params:

| variables | required ground bits |
|---|---|
| 22 | 14 |
| 23 | 17 |
| 24 | 18 |

A 2-in/2-out transfer stacks to 23 variables — the 32-level Keccak Merkle fold
per input dominates the trace — so a config declared at 22 budgets 14 bits and
the prover dies with `PowBitsExceedBudget { required: 17, budget: 14 }`.
Declaring 24 budgets 18, covering 17 with a bit of headroom.

The verifier pays nothing for this: grinding is prover-side work that the
verifier checks with a single hash, so Solidity gas is identical at 17 or 18
ground bits. The 96-bit target is unchanged; the budget is *below* the target,
which is required — a budget at or above `SECURITY_LEVEL` credits grinding with
the whole target, drops the query count to zero, and makes the proximity test
accept any committed function (`ZeroQueries`).

**Gotcha recorded.** `WhirUniPcs::whir_config` *panics* rather than returning
`Err` on an unschedulable arity ("WHIR parameters are valid for the committed
arity"). Probing heights in a loop therefore cannot work — the first refusal
aborts the process. Size the config up front from `required_pow_bits`.

**Alternatives considered.**
- *Shrink the Merkle depth to fit 22 variables.* Rejected: `DEPTH = 32` is the
  protocol's tree; weakening it to save one LDE level trades a real property for
  a prover-side cost that is free at the verifier.
- *Lower the security target so 22 variables suffices.* Rejected: 96 bits is the
  agreed landing point and the height is not what is tight.

## D-020 — Statement layout is the `TransferPublic` limb sequence

**Decision.** The transfer circuit exports, in order:

```text
[ nullifier_0 … nullifier_{n-1}        (16 limbs each)
, output_cm_0 … output_cm_{m-1}       (16 limbs each)
, root                                (16 limbs)
, fee                                 (4 limbs)  ]
```

all as `StatementExport::Base`. For the 2-in/2-out demo that is
`16·4 + 16 + 4 = 84` base-field statement values.

**Why.** This is `TransferPublic` flattened, so the on-chain settlement call can
reconstruct the expected statement from the calldata it already has and call
`verify(&proof, statement)` with no extra encoding layer. `build_transfer_circuit`
asserts the circuit's exported width equals the `TransferPublic` flattening, so a
layout change on either side fails the build rather than silently desynchronising.

**Security basis.** Statement binding is the whole settlement boundary:
`CircuitVerifier::verify` rejects when the proof's attached public values differ
from the caller's expected statement (`RelationMismatch`). `settlement_rejects_a_different_statement`
asserts exactly that — flip one nullifier limb and the proof must not verify.

**Alternatives considered.**
- *Hash the public values and export one digest.* Rejected: the chain needs the
  nullifiers and commitments *in the clear* to update its own state, so a digest
  would force them into calldata anyway while adding a second binding path to audit.
- *Extension-field exports.* Rejected: every public value here is a base-field
  limb; `Extension` exports cost a coefficient decomposition with lookups for no
  benefit.

## D-019 — Private inputs need an explicit bus claim

**Decision.** Every private input that feeds only a non-primitive operation is
given a creator row by `claim_private` (`mul` by the constant one) at allocation
time, inside `Secret::new`.

**Why.** The prover's `WitnessChecks` bus requires a *creator* row for every
witness, and only `Const`/`Public` rows, ALU rows, and non-primitive **outputs**
create one. A secret limb that flows only into a Keccak permutation is a
non-primitive **input**, which never creates. The circuit builds and witnesses
fine, then the prover rejects it outright:

```text
Private input WitnessId(w569) was never used as an ALU operand — cannot assign
a bus creator; every private input must appear in at least one ALU op
```

Amount limbs escape this because the balance constraints use them in ALU rows;
`sk_d`, `rho` and `psi` limbs feed only hashes, so they needed the explicit
claim. Multiplying by one is the cheapest row that creates the witness and adds
no constraint beyond what the limb already carries.

**Why it lives in `Secret::new`.** Putting the claim at allocation makes it
impossible to obtain a `Secret` whose limbs are unclaimed — the misuse case is
closed by the interface rather than left to a comment. `Secret::new` also
range-checks every limb to 16 bits for the same reason: an unchecked limb would
let the circuit's byte interpretation diverge from the witness's.

**Alternatives considered.**
- *Add a dummy ALU use at each call site.* Rejected: easy to forget on the next
  secret added, and the failure is a prover-time rejection far from the cause.
- *Patch the upstream bus rule to treat NPO inputs as creators.* Rejected: that
  changes the soundness accounting of a shared dependency for a local convenience.

## D-018 — In-circuit ownership = hash-preimage binding (pre-SPHINCS+)

**Decision.** The transfer AIR binds a spend to its owner by constraining
`pk_d = H(DOMAIN_PK ‖ sk_d)` in-circuit, where `pk_d` is the 32 bytes the note
commits to and `sk_d` is the witness secret that also produces the nullifier.
Ownership is therefore a SHA3-256 preimage knowledge proof.

**Why.** Without this binding the circuit is unsound: the *sender* of a note knows
the full preimage (`value, rho, psi, pk_d`) but not `sk_d`, yet the nullifier is
`H(DOMAIN_NULLIFIER ‖ sk_d ‖ rho)`. The sender could pick any random `sk_d'`,
produce a well-formed nullifier, and drain the note. A nullifier that is not bound
to the committed key proves nothing about who authorized the spend.

**Alternatives considered.**
- *SPHINCS+ verified in-circuit* (ticket 10). Correct and the eventual target,
  but a full SLH-DSA verifier AIR is a large separate build; it would block the
  e2e demo. Kept as the upgrade path: the outer `pq-sign` envelope signature the
  node checks stays in place, so this is defense-in-depth, not a replacement.
- *Trust the node's off-chain SPHINCS+ check.* Rejected: the rollup's security
  rests on the proof, not on the node. An honest-verifier-only ownership check
  defeats the purpose of the ZK settlement.

**Security basis.** SHA3-256 preimage resistance (128-bit classical). PQ: no
number-theoretic assumption; a hash-based binding is quantum-resistant to the
same degree as the hash itself.

## D-017 — Balance via a 16-bit multi-precision carry adder

**Decision.** Balance (`Σ inputs = Σ outputs + fee`) is enforced over four
16-bit limbs per value with an explicit biased-carry chain, each limb
range-checked by `decompose_to_bits`.

**Why.** The base field is KoalaBear (~2^31). A u64 value, or a sum of them,
does not fit; a naive field-equality balance would wrap and admit false proofs.
The carry adder is the standard small-field solution and supports the full
`MAX_VALUE = 2^62 − 1` domain range.

**Carry bias.** True carries are signed (a borrow when outputs exceed inputs in a
column). We bias by `B = n_out + 1` so every carry witness is non-negative,
keeping all column sums well under the field modulus (≈ (n_in+n_out+1)·2^16).
Boundary carries are pinned: `d_0 = B` (no carry in) and `d_last = B` (no carry
out), so the chain cannot leak value past the top limb.

**Alternatives considered.**
- *Bound values so the field never wraps* (values < 2^28, few inputs). Rejected:
  silently caps the value range below the domain's `2^62` and would need a
  separate audit of every count/size combination.
- *64-bit limb in an extension field.* Rejected: the Keccak gadgets and the
  recursion both work in 16-bit limbs; mixing limb widths adds a second
  representation to audit for no gain.

## D-016 — SHA3 single-block gadget built on `add_keccak_f1600`

**Decision.** The nullifier's SHA3-256 (FIPS-202, `0x06` pad) is computed by a
`sha3_256_single_block` helper that builds the padded 136-byte block by hand and
runs one `add_keccak_f1600`.

**Why.** The off-the-shelf `keccak256_limbs` pads with `0x01` (original Keccak,
matching the commitment side). The nullifier uses FIPS SHA3 (`0x06` pad) and its
preimage is 110 bytes — a single block — so no sponge loop is needed: only the
domain byte differs. One permutation, constructed state.

**Alternatives considered.**
- *Reuse `keccak256_limbs` for the nullifier.* Rejected: wrong pad byte, would
  not match `Sha3_256Shielded` and the Solidity mirror.
- *Switch the nullifier to Keccak-256 to reuse the gadget.* Rejected: the domain
  model and the wallet already commit to SHA3-256 for nullifiers; changing the
  hash is a consensus break for a convenience.

## D-015 — Merkle path uses `keccak256_compress` + `select`, not the MMCS gadget

**Decision.** In-circuit membership folds the path with
`keccak256_compress(swap(bit, left, right))` per level, mirroring the domain
`MembershipPath::compute_root`.

**Why.** The off-the-shelf `verify_keccak_merkle_path` targets
`MerkleTreeMmcs` *batch* openings with per-level matrix-injection layers and a
multi-root cap. Our shielded tree is a plain binary `H(left ‖ right)` tree of
`Digest32` with an index-bit side selector and no injection. Using the batch
gadget would import machinery that does not match the tree and force the tree into
a shape it is not. The hand-fold is ~12 lines over the same `keccak256_compress`
primitive, so the hash is still off-the-shelf; only the routing is ours.

**Alternatives considered.**
- *Rebuild the shielded tree as a `MerkleTreeMmcs`.* Rejected: the domain tree
  is field-agnostic `Digest32` pairs; forcing field-element matrices would couple
  the tree to the field and complicate the native side for no security gain.
