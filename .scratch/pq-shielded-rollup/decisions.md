# Decisions log

Recorded choices with alternatives considered. Newest first.

## D-029 — Optimized-by-default build profile

**Status.** Done. `.cargo/config.toml`.

**Problem.** Every duration in this log before D-027 was measured on the stock
dev profile, which compiles every Plonky3 crate at `opt-level = 0`. Proving is
compute-bound and the prover *is* the code under test, so an unoptimized build
measures the wrong thing.

**Measured, fan-in-2 block test:**

| profile | test wall |
|---|---|
| dev (opt-level 0) | 466 s |
| optimized (opt-level 3) | **9.2 s** |

**~50× runtime speedup.**

**Why the dev profile was modified rather than asking callers to pass
`--release`:**

- Cargo has **no `[build] profile` key.** Setting it emits
  `warning: unused config key build.profile` and is ignored — plain
  `cargo build` stays unoptimized.
- `cargo test` uses the `test` profile regardless of how `cargo build` is
  configured, so a release `build` setting would not speed up tests anyway.
- `dev` and `release` are **root profiles and cannot inherit from each other**
  (`inherits must not be specified in root profile dev`). The settings must be
  spelled out on `dev` directly.

**Settings on `[profile.dev]`:** `opt-level = 3`, `debug = "line-tables-only"`,
`debug-assertions = true`, `lto = false`, `codegen-units = 16`.

**`debug-assertions` deliberately kept ON.** Release turns them off, and they
have caught real bugs in this project that the release build masked — a `u8`
overflow in a test fixture, and `debug_assert_eq!` checks inside the recursion
crate that catch stacked-arity mismatches. `opt-level = 3` with
`debug-assertions = true` is a valid combination: full speed, overflow checks
still panic. Pinned by a test in `prover/src/lib.rs` so a future profile
reshuffle cannot quietly drop the checks while keeping the speed.

**LTO off, `codegen-units = 16`.** Release's `lto = "thin"` +
`codegen-units = 1` made one test binary take 67+ minutes of CPU to link. The
speedup comes from `opt-level = 3`, not from whole-program LTO.

**Disk cost.** The first optimized build filled the volume: `target/debug`
reached 28 GB with 1.1 GiB free, and a build failed with `No space left on
device`. `debug = "line-tables-only"` (rather than full debuginfo) brings the
full-workspace target to ~4 GB. `cargo clean` recovered 38 GB.

**Consequence:** `cargo test --release` now fails the profile guard test. That
is intended — release drops the overflow checks this project depends on.

## D-028 — Aggregation tree is required at real block sizes (corrects D-026)

**Status.** Open — design conclusion recorded, not yet built.

**Measured scaling (dev profile, `parallel` on, 10-core M2 Pro).**

| Aggregated client transfer proofs | wall | CPU | peak RSS |
|---|---|---|---|
| 1 (fan-in 1, D-023 path) | 230 s | 1077 s | 2.9 GB |
| 2 (fan-in 2, `block.rs`) | 466 s | 2327 s | 5.8 GB |

Marginal cost is **~236 s and ~2.9 GB per additional transfer** — linear in both
time and memory. Each extra transfer adds one client proof plus one in-circuit
verification, and one child's traces held in the same circuit.

**Why D-026's dismissal of the tree was wrong.** D-026 said the tree "trades
circuit size for sequential depth." That is backwards on both axes:

- **Depth.** Fan-in N is *linear* depth in N on one box. A binary tree is
  `log₂ N` sequential levels. Depth improves, it does not worsen.
- **Memory.** A fan-in-N circuit holds all N children's traces at once. At
  N = 256 that is on the order of hundreds of GB — infeasible on one machine.
  The tree keeps every node at fan-in 2, bounding per-node memory.

**The real tradeoff.** The tree costs *more total CPU work* — roughly 2N proofs
of work across all levels versus N — and buys *lower wall clock* by proving each
subtree independently, which fans out across **machines**, not just cores.

```
fan-in N, one box:      N × 236 s            (linear, memory-bound)
binary tree, K boxes:   log₂(N) × ~236 s     (parallel across boxes, bounded mem)
```

Projection at N = 256 over 8 boxes: ~8 levels × 236 s ≈ 31 min, against ~17 h
serially. **This is a projection from measured fan-in numbers, not a measured
tree result** — per-level cost is assumed constant, and higher-level nodes verify
larger circuits than transfer proofs, so the real figure will be somewhat worse.

**What still holds from D-026.** Per-transfer proofs are the shielded property
and must not be collapsed into one natively-witnessed circuit. The tree sits
*above* those proofs; it does not change Layer 0.

**Not yet decided.** Tree fan-in (2 vs 4), whether the chain-link previous-block
proof joins at the root or per-level, and the level-parallel scheduling policy.
Deferred until the node crate drives real block assembly.

## D-027 — Enable `parallel`: the prover was running on one core

**Status.** Done. Default-on feature in `crates/prover/Cargo.toml`.

**Symptom.** The fan-in-2 block test used 22:16 CPU over 22:36 elapsed — 98% of a
single core on a 10-core M2 Pro.

**Cause.** Plonky3 routes every parallel loop (DFT butterflies, LDE rows, Merkle
nodes) through `p3-maybe-rayon`, a shim whose `parallel` feature is **off by
default**. Without it the shim maps `ParallelIterator` onto `core::iter::Iterator`
and `IndexedParallelIterator` onto `ExactSizeIterator` — the parallel code is
present but executes serially. Our `Radix2DitParallel` type name was cosmetic.

**Fix.** A `parallel` feature on the prover crate forwarding to every direct
dependency that exposes the switch (`p3-dft`, `p3-whir`, `p3-sumcheck`,
`p3-uni-stark`, `p3-fri`, `p3-matrix`, `p3-field`, `p3-challenger`,
`p3-lookup`, `p3-merkle-tree`, `p3-util`, plus the git-side `p3-circuit`,
`p3-circuit-prover`, `p3-recursion`, `p3-poseidon2-circuit-air`), enabled in
`default`. Forwarded explicitly rather than relying on feature unification to
reach the shim indirectly.

**Measured (dev profile, fan-in-2 block test).**

| | wall | CPU | peak RSS |
|---|---|---|---|
| before | 1652 s | ~1360 s | — |
| after, 10 threads | **466 s** | 2327 s | 5.8 GB |
| after, `RAYON_NUM_THREADS=6` | 498 s | 1913 s | 5.7 GB |

**3.5× faster.** All-cores beats P-core-only (6) — no benefit to pinning around
the efficiency cores here, so the default is left alone.

**Caveat for anyone reading timings.** Every duration in this log before this entry
is a single-core number. The recursion figures in D-023 in particular were
measured without `parallel`.

## D-026 — D-024 is WRONG: per-transfer proofs are the shielded property, not overhead

**Status.** Correction, made while starting the block circuit. D-024's "wide
circuit" is unusable and must not be built.

**What D-024 claimed.** One transfer circuit already batches up to
`MAX_PARTIES = 16` spends natively, so a block is one wide proof and an
aggregation tree only multiplies cost.

**Why that is false.** `shielded::transfer::Spend` carries the full spend secret:

```rust
pub struct Spend<'a> {
    pub note: &'a Note,
    pub sk_d: &'a [u8; 32],
    pub path: &'a MembershipPath,
    pub index: usize,
}
```

The transfer circuit witnesses `pk_d = H(DOMAIN_PK ‖ sk_d)` and
`nullifier = H(DOMAIN_NULLIFIER ‖ sk_d ‖ rho)` in-circuit. Proving a spend
*requires* `sk_d` as a witness. So a circuit that natively witnesses N transfers
requires whoever builds it to hold **every spender's `sk_d`**.

That is not a rollup, it is a custodial mixer with extra steps. The entire point
of the shielded pool is that each spender produces their own proof on their own
machine and their secret never leaves it. The per-transfer proof is not an
inefficiency to be optimized away — **it is the property being protected.**

D-024 optimised the wrong axis. It minimised proof count by centralising secrets.

**Correct architecture.**

```text
Layer 0  per-transfer proof, produced LOCALLY by each spender (InSC / Poseidon2 WHIR)
         statement: [nullifiers…, outputs…, root_before, fee]
         holds that spender's sk_d; nothing else's
              │
              ▼
Layer 1  block circuit — verifies N transfer proofs + 1 previous block proof,
         all in-circuit (InSC). Never sees any sk_d.
         exports: [chain_id, block_number, timestamp, root_before,
                   nullifiers…, outputs…, fee]
              │
              ▼
Layer 2  settlement wrap under Keccak OutSC → L1 verifies one proof
```

**Fan-in is N+1, in one circuit.** The block circuit verifies N transfer proofs
plus the previous block proof directly. This is what a validity rollup does. A
binary aggregation tree is *optional*, and only earns its keep if the single
block circuit grows too large to prove — it trades circuit size for sequential
depth. It is not the default, and it is not required for correctness or for gas.

> **Corrected by D-028.** "Trades circuit size for sequential depth" is
> backwards. Measured scaling shows fan-in N is linear in N on one box, and the
> tree's real benefit is that each subtree proves independently, so it fans out
> across *machines*. The tree is not optional at real block sizes.

**What survives from D-024.** The observation that in-circuit WHIR verification
is the dominant cost is correct and still governs sizing: it is why block size is
bounded and why `LOG_MAX_LDE` matters. What does not survive is the conclusion
that we should avoid in-circuit verification by widening the witnessed circuit.

**What survives from D-025.** The chain-link shape (block N verifies block N−1,
`chain_id` and `block_number` constrained in-circuit) is unchanged and correct.
The block circuit's fan-in is N transfer proofs + 1 chain proof, not 1.

**Superseded.** D-024's decision to not build aggregation is retained only in
the weak sense that the tree is not the default. Its central claim — that the wide
circuit replaces per-transfer proving — is retracted.

## D-025 — Block topology: native transfers + exactly one in-circuit verification

> **Partially superseded by D-026.** The chain-link shape and the metadata
> constraints below are correct and retained. The claim that the block's N
> transfers are a *native witness* is wrong — that would require the block
> producer to hold every spender's `sk_d`. The transfers arrive as N separate
> locally-produced proofs, verified in-circuit. Fan-in is N+1, not 1.

**Status.** Decision. Follows from D-024 and fixes the shape of the block circuit
before it gets built.

**The tension D-024 left unresolved.** D-024 argued the wide circuit is cheap
because it witnesses N transfers *natively*, with no in-circuit proof
verification. But a recursive block that verifies N per-transfer proofs
in-circuit would throw that advantage away — 16 in-circuit WHIR verifications is
far worse than one wide circuit. So "wide circuit" and "recursive block" are only
compatible if the recursion is pointed at the right thing.

**Decision.** A block circuit contains:

| Part | How it is proven | Count per block |
|---|---|---|
| N transfers (spends, outputs, balance, membership, nullifiers) | **native witness** | N, zero in-circuit verification |
| Previous block's proof | **verified in-circuit** | **exactly 1** |

```text
block circuit (InSC)
  ├── native: N spends + M outputs, one global balance constraint
  ├── native: root_after folded from new outputs onto root_before
  └── in-circuit: verify prev block proof (InSC)
        ├── prev.chain_id      == self.chain_id
        ├── prev.block_number  + 1 == self.block_number
        └── prev.root_after    == self.root_before
```

Exported statement: `[chain_id, block_number, timestamp, root_before, root_after, tx_root]`.

**Why exactly one.** In-circuit WHIR verification is the dominant cost. Pointing
it at the single previous block makes per-block proving work **constant** — one
verification regardless of block size or chain length — while still proving the
entire chain's validity back to genesis. Pointing it at N transfer proofs makes
per-block work grow with block size and buys nothing, because those transfers are
already witnessed natively in the same circuit.

**This is fan-in 1 with state chaining, not aggregation.** The recursion edge is
block→block, not transfer→block. D-023's `build_batch_recursion_circuit` is the
primitive for that edge; D-024's wide circuit is the primitive for the block's
own contents. They compose: the block circuit is a wide transfer circuit with one
recursion edge attached.

**What L1 does.** Verify one WHIR proof per block, check `root_before` against
its stored root, record `root_after`, check `block_number` increments. Constant
work per block. Because the proof chains to genesis, a light client can instead
verify the *latest* proof alone and be convinced of the whole history — the
property that makes this a validity rollup rather than a periodically-audited
chain.

**Refinement: L1 computes `root_after`; the circuit does not.** Appending one
leaf to the depth-32 append-only tree costs one Keccak-f per level — 32
permutations per output, not two. For a 4-output block that is 128 Keccak-f
permutations the circuit does not need to do:

- The proof attests that every transfer is **valid against `root_before`** —
  membership, ownership, nullifier formation, global balance.
- The output commitments are **public**, in the statement.
- L1 applies the canonical state update itself: append the output commitments to
  its own tree, insert the nullifiers into its spent set.

Soundness holds because L1 derives the resulting root deterministically from
public data in the statement, so every honest node derives the same one. The
proof attests to the *validity of the transition*; L1 computes the *result*.
`root_after` drops out of the statement.

**What this moves to L1, and what it does not.** L1 must check each block's
`root_before` against its own stored root, then append the outputs. That is
~32 `keccak256` per output at ~30 gas each — 4 outputs is ~4k hashes of gas,
negligible. Root *continuity* therefore becomes an L1-enforced property rather
than a proof-enforced one. The in-circuit chain link binds `chain_id` and
`block_number` only.

**Honest limit on the light-client claim.** A light client verifying only the
latest proof is convinced of transfer validity and block numbering back to
genesis, but takes the root sequence from L1's storage — which L1 checked at each
block. It is not a standalone root recomputation. Stating it stronger would be
overclaiming.

**Statement becomes** `[chain_id, block_number, timestamp, root_before,
nullifiers…, outputs…, fee]` — the transfers' own public data plus block
metadata, with no derived root to recompute.

**Rejected.**
- *Verifying per-transfer proofs in-circuit.* Multiplies the dominant cost to
  avoid a cost the wide circuit already does not incur.
- *Aggregation tree over transfers.* D-024.
- *Computing `root_after` in-circuit.* Correct but pays `64k` Keccak-f
  permutations for something L1 gets nearly free.
- *No recursion at all (each block proven independently).* Sound, and cheaper per
  block, but loses the chain-to-genesis property and the light-client property.
  The user requires recursion in proofs and in the verifier, and this shape is
  what makes that requirement pay for itself.

## D-024 — No aggregation tree: the transfer circuit is already the wide circuit

**Status.** Decision, prompted by the user asking "are you doing tree-shaped
recursive proof aggregation?" Checking what a tree would buy overturned the
premise of D-023's "fan-in 2 is a mechanical doubling" note.

**Finding.** `build_transfer_circuit` already loops over *every* spend and *every*
output, and `constrain_balance` sums globally:

```text
a_expr = Σ inputs[j]            (all input amounts)
b_expr = fee[j] + Σ outs[j]     (all output amounts)
```

One transfer circuit therefore already batches up to `MAX_PARTIES = 16` spends and
15 outputs into **one proof with one global value-conservation constraint**. A
block is one such proof plus metadata.

**Cost comparison for N transfers per block.**

| Shape | Proofs/block | Depth | L1 gas |
|---|---|---|---|
| Fan-in 1 per transfer | N | 1 each | N× — not a rollup |
| Binary aggregation tree | 2N−1 | log₂ N | 1× |
| Wide circuit (already built) | 1 | 1 | 1× |

The tree reaches the same endpoint as the wide circuit at strictly greater cost:
each aggregation node's circuit is "verify two WHIR proofs in-circuit", a large
circuit, and you build 2N−1 of them.

**The decisive asymmetry.** The wide circuit witnesses N transfers *natively* —
zero in-circuit proof verification. A tree performs `2N−1` in-circuit WHIR
verifications, each one a large circuit. In-circuit verification is the single
most expensive thing this stack does, so the tree multiplies exactly the cost the
wide circuit avoids. Per-block proving work is `O(N)` witness rows versus
`O(N)` full WHIR verifications.

**When a tree would actually be justified.** Only for *distributed proving* —
sharding independent sub-proofs across machines that never share a witness, then
combining. That is a throughput/infrastructure concern, not a proof-size or gas
concern, and it is out of scope for this project. It is the reason aggregation
exists upstream; it is not a reason for us to use it.

**Decision.** Do not build tree aggregation. Block = one wide transfer circuit +
block metadata. Rejected: `TrustedPreparedAggregation` /
`build_and_prove_aggregation_layer{,_cross}` for the block layer.

**Where recursion is load-bearing: the chain, not the block.** Block N verifying
block N−1 with `root_before → root_after` threaded through the statement is
fan-in 1 *with state chaining*. That gives constant-size L1 verification and
O(1) state update per block. D-023's fan-in-1 result is the right primitive for
this; D-023 mislabelled it as a stepping stone to fan-in N rather than the
finished shape.

**Consequence for the fan-in-1 test.** `transfer_proves_under_recursion_and_keeps_its_statement`
is still correct and valuable — it is the chain-link primitive. What it is *not*
is a path to per-transfer-proof aggregation, because that shape is not wanted.

**Sizing note.** A wider block means a bigger circuit and a taller trace, not more
proofs. WHIR's proof size grows logarithmically in trace height, so block size
scales. `MAX_PARTIES = 16` is the current ceiling and is a constant to raise, not
an architectural limit — the binding constraint is `LOG_MAX_LDE` and the
grinding-budget curve (D-021).

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
