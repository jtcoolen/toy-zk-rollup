# Decisions log

Recorded choices with alternatives considered. Newest first.

## D-039 — Splitting the verifier: chunk by WHIR round across transactions, bound by the transcript

**Answers:** how do we verify a 767 KB proof on EVM; how many contracts; how to
split; how to keep it atomic and pass information correctly.

### Measured: the proof size is a fixed base plus a small marginal cost

`block::tests::measure_proof_size_vs_fan_in` (postcard, 96-bit, `lir=1`):

```text
fan_in | block_bytes | bytes_per_transfer | min feasible lde
   1   |   705,995 |            705,995 | 24
   4   |   865,005 |            216,251 | 26
   8   | 1,010,426 |            126,303 | 27
```

Marginal cost per extra transfer: **~43 KB**. Fixed base: **~662 KB**. So
amortization is real and strong — 8 transfers is 126 KB each versus 706 KB
for one — but the base dominates at any small fan-in. The base is the
recursion circuit's own trace (Poseidon2 rounds, statement table, ALU rows),
not the shielded logic.

**Consequence for D-028 (aggregation fan-in):** high fan-in is mandatory for
economics. Target 16–32 transfers per aggregated block; the marginal 43 KB
per transfer is what the chain actually pays.

### Why parameters cannot fix this

Measured this session, all at our actual stacked arity (25):

- **Extension degree is not a lever.** ext4 and ext8 give **identical** query
  counts at every `(lir, pow)`. The schedule solves for queries to hit the
  96-bit target; a larger field does not move it in this regime. (KoalaBear
  supports binomial ext 4 and 8 only; `sol-whir-p3`'s quintic is a
  *trinomial*, a different type our WHIR path will not accept.)
- **`lir` is capped at 3** by KoalaBear's 2^24 two-adicity against arity 25
  (`nv + lir <= 28`).
- **Grinding helps but is prover-limited.** 271 queries at pow=19 → 78 at
  pow=48, but 2^48 hashes per block is beyond a sequencer.
- **Cap height made it worse** (767 KB → 905 KB at cap 8); WHIR re-commits
  every round and serializes the whole cap each time.

### The design: chunk by WHIR round, one round per transaction

Our proof decomposes into **four top-level WHIR runs** (measured: 191 KB,
143 KB, 185 KB, 205 KB), each with 3–4 inner folding rounds. That structure
is the natural cut point.

**Why this is sound by construction — the key insight.** Fiat-Shamir is a
*running hash*. The verifier's challenges are derived from everything
absorbed so far. Splitting *where the bytes are fed in* does not change what
the transcript commits to. So a chunked verifier that carries the sponge
state between transactions is not a weakened verifier — it is the same
verifier, paused.

This is the property that makes the whole scheme safe, and it is why the
alternative (trusting an off-chain "pre-verified" flag) is not needed.

**Contracts: two.**

1. **`ChunkVerifier`** — the verification state machine. Knows nothing about
   shielded transfers. Holds, per `verificationId`:
   ```text
   struct Session {
       bytes32 statementHash;   // committed at begin(); binds the claim
       uint32  roundIndex;      // advances by exactly 1 per step()
       uint32  status;          // OPEN / VERIFIED / DEAD
       bytes   spongeBuffer;    // the Keccak challenger's absorbed bytes
       bytes   outputBuffer;    // its unconsumed sampled bytes
       uint256[] accumulated;  // running sumcheck claim / folding randomness
   }
   ```
   `begin(statement, firstChunk) -> id`, `step(id, chunk)`, `isVerified(id)`.

2. **`ShieldedPool`** — the settlement contract, unchanged in role. Calls
   `begin`, drives `step` until the verifier reports VERIFIED, then applies
   the root transition. It never trusts a bare boolean from anywhere else.

**Why two and not more.** Splitting the *verifier* across contracts does not
help: a transaction's gas limit is per-transaction regardless of how many
contracts it calls. The only thing that raises the budget is more
transactions. So the split must be in *time*, not in *code location*.
Extra contracts would add delegatecall overhead and an attack surface for no
gas benefit.

**Gas budget per step.** From `sol-whir-p3`'s measured 3.64 M gas over ~20
queries (~138 k gas/query) plus 16 gas/byte calldata:

```text
per WHIR round: ~190 KB calldata (~3.0 M gas) + ~65 queries (~9.0 M gas)
              ≈ 12 M gas per transaction
```

Comfortably inside a 30 M block limit, with room for the state-machine
overhead. A full block verification is ~6 transactions (4 rounds + initial
+ final).

### Atomicity and information passing

**Within a transaction:** trivial. EVM reverts atomically; a failed `step`
persists nothing.

**Across transactions:** the state machine makes partial verification
harmless rather than trying to make it impossible.

- `begin` commits `statementHash = keccak256(chainId, blockNumber, statement)`.
  Every subsequent call must present the same `verificationId`, so a step
  cannot be replayed against a different claim.
- `roundIndex` must advance by exactly one. A skipped round is a revert, not
  a silently-missed check.
- Each `step` re-derives its challenges from the **stored sponge state** and
  checks its chunk against them. A tampered intermediate state produces a
  different challenge and fails immediately — the transcript is the
  integrity check on the session, not a hash we added on top.
- The final step checks the closing identity against `statementHash`. Only
  then does `status = VERIFIED`, and only `ShieldedPool` acting on that
  applies the state update.
- **Liveness, not soundness:** a malicious actor can stall verification by
  never submitting the last chunk. Nothing is applied, nothing is lost but
  gas. The sequencer owns the submission schedule, and a block that is not
  finalized within its window is simply not adopted.

**What must NOT be passed between contracts:** any pre-computed "this is
valid" boolean from an off-chain source. The only trusted inputs are the
statement, the proof bytes, and the transcript's own derivation.

### Cross-checks from the two reference repos

**`input-output-hk/plutus-plonky3-exploration`** (Apache-2.0) — same problem
on a far tighter target (Plutus, ~14 M mem/tx). Their result: 186 KB proof
at `log_blowup=8`, 22 queries, verified across **23 transactions** — one
per query plus one for shared work. Per-query 9.47 M mem / 3.23 B cpu.
Confirms: (a) chunking across transactions is the standard answer, (b) our
EVM budget is far more generous, (c) they also found the fixed-work/query
split dominates.

Their `log_blowup` ↔ `num_queries` table matches our `lir` ↔ queries curve
directionally (blowup 2→8 cuts 83→22 queries), which is independent
confirmation that our rate lever behaves as measured.

**`GOATNetwork/bitcoin-stark-verifier`** — WHIR over KoalaBear ext4, *our
exact field*, verified in Bitcoin Script with no `OP_CAT`. Two things worth
taking:

1. **Their `docs/whir-review.pdf`** is a formal account of the STIR and WHIR
   proximity tests — what is checked, what is not, and why. That is directly
   reusable as the correctness reference for our Solidity verifier, and is
   the most valuable artifact either repo offers us.
2. **"The script is built from the proof it verifies"** — a proof-specialized
   verifier. They must do this because Bitcoin Script has no loops; their
   script is 198 MB. **We have loops**, so we write one general verifier.
   Their constraint is our freedom.

Their "what is not checked" list is a useful honesty template for our own
verifier docs: the statement is supplied because it *is* the claim; a
different statement is a different claim, not a cheaper proof of the same
one.

**Not applicable to us:** their Poseidon2-as-algebraic-hash trick exists to
avoid `OP_CAT`. On EVM `keccak256` is a native opcode that hashes arbitrary
bytes, so we keep Keccak and our prefix-free tree convention unchanged.

### Rejected alternatives

- **SNARK-wrap the WHIR proof.** Forbidden (no SNARKs).
- **LeanVM terminal (D-036).** Does not shrink the final proof; adds a zkVM
  to solve a problem our in-circuit recursion already solves.
- **Split the verifier across many contracts in one tx.** No gas benefit —
  the limit is per-transaction.
- **EIP-4844 blobs for the proof.** Contracts cannot read blob contents,
  only their commitments. The verifier needs the bytes. Not usable.
- **Lower the security level.** Cuts queries directly but 96 was already a
  concession from 128; needs a user decision.


## D-038 — MEASURED: the final proof is 767 KB. On-chain verification is infeasible as configured.

**The answer to "how large is the final proof we want to verify in Solidity?"**

Measured on the real fan-in-2 block proof (`block::tests::measure_final_proof_size`,
postcard-serialized, `LOG_MAX_LDE = 25`, 96-bit, `lir = 1`, `pow = 19`):

```text
FINAL PROOF:        767,697 bytes  (742,544 nonzero / 2,515 zero)
STATEMENT:              173 limbs  = 692 bytes
CALLDATA GAS:     ~11,981,316     (16/byte nonzero + 4/byte zero, Cancun)
```

Calldata alone is ~12M gas before a single WHIR round is verified. Against a
30M block gas limit that leaves ~18M for the actual verification of a proof
with **271 queries**. Not viable.

**Decomposition — where the bytes are:**

```text
opening_proof total: 724,094
  round 0: 191,044   (4 whir rounds, 8 evals)   whir0=105,368
  round 1: 143,072   (3 whir rounds, 8 evals)   whir0= 85,305
  round 2: 185,247   (4 whir rounds, 8 evals)   whir0=104,948
  round 3: 204,730   (4 whir rounds, 12 evals)  whir0=104,106
```

Two facts fall out:

1. **The batch has FOUR top-level WHIR proximity proofs**, not one. Each
   commitment phase of the batch STARK (trace, quotient, lookup, …) gets its
   own WHIR folding run. We pay the WHIR overhead four times.
2. **Each phase is dominated by its first WHIR round** (~105 KB of ~190 KB).
   At 177 queries that is ~595 bytes/query, which is a Merkle path: 24
   levels x 32-byte Keccak digests = 768 B. **Merkle paths over the Keccak
   tree are the cost**, exactly as expected for a hash-based PCS.

**Comparison that frames the problem.** `sol-whir-p3`'s KoalaBear-quintic
standalone WHIR: 3,637,880 gas total, 54,436 B calldata, **~20 queries**.
We are at 271 queries and 767 KB — 14x the queries, 14x the bytes.

**Why our query count is so much higher.** Two compounding causes:

- **Many opening claims.** The circuit-prover stacks every table — witness,
  const, public, ALU, Poseidon2, recompose, statement, Keccak-f — into one
  batch. WHIR's initial batching claim costs `log2(claims - 1)` bits of
  security, and the deficit is made up with queries. Their standalone verifier
  opens ONE claim.
- **`lir = 1` forced by arity.** Measured: the fan-in-2 block circuit's
  actual stacked arity is **25** (needs 19 grinding bits; v=25 supplies
  exactly 19, v=24 fails with `PowBitsExceedBudget { required: 19, budget: 18 }`).
  KoalaBear's two-adicity caps the folded domain at 2^24, so
  `nv + lir <= 28` and at nv=25 only `lir <= 3` is reachable. The arity is
  forced by the nullifier gadget's 288 Keccak-f per spend (D-035).

**This is why they built the LeanVM terminal.** The measurement vindicates
their architecture: a full recursive proof over a rich AIR is too large to
verify directly, so they prove the verification inside a VM. We rejected that
(D-036) because our recursion is already in-circuit — but we did not
anticipate that the *final* proof would still be 767 KB.

**Levers, measured (nv=25, total queries / est. size):**

| lir | pow | queries | est. KB | prover-feasible? |
|---|---|---|---|---|
| 1 | 19 | 271 | 756 | yes (current) |
| 1 | 32 | 225 | 628 | yes (~4G hashes) |
| 2 | 24 | 152 | 424 | yes |
| 2 | 32 | 135 | 377 | yes |
| 3 | 32 | 102 | 284 | yes |
| 3 | 48 | 78 | 217 | marginal (2^48) |
| 4 | any | — | — | INFEASIBLE (domain cap) |

Grinding is prover-side and verifier-free (one hash), so moving right/down is
cheap for the chain. But 2^48 is already beyond a sequencer's budget, and
even the best feasible point (~284 KB, ~4.5M gas calldata) plus 102 queries
of Merkle verification is not comfortably inside a block.

**Real fixes, in order of leverage.**

1. ~~**Raise the Merkle cap height.**~~ **MEASURED AND REJECTED.** Cap 8 made
   the proof 905 KB, up from 767 KB. The path shortening is real, but WHIR
   re-commits every folding round and a capped commitment is a
   `2^cap_height`-element Merkle cap serialized *per round* — 256 digests x
   ~15 rounds swamps the saving. The cap would have to be sent once and
   referenced by digest, which the WHIR proof format does not do.
2. **Reduce the number of top-level WHIR runs.** Four proximity proofs is
   four times the fixed cost. Whether the batch can be restructured to commit
   fewer phases is a `p3-circuit-prover` question worth investigating.
3. **Reduce opening claims.** Fewer stacked tables → less security lost at
   batching → fewer queries. The statement/const/public tables may be
   foldable into fewer polynomials.
4. **Shrink the nullifier insert fold** (256 → shared-across-block), which
   lowers `nv` and unlocks a higher `lir`. Biggest structural win, biggest
   change.
5. **Lower the security level.** 96 → 80 cuts queries directly. Needs a
   user decision; 96 was already a concession from 128.

**Not a fix:** SNARK wrapping (forbidden), and their LeanVM terminal (D-036).

**Standing measurement to re-run after every change:**
`cargo test -p prover --lib block::tests::measure_final_proof_size -- --ignored --nocapture`


## D-037 — BLOCKING: our WHIR query count is ~13x theirs; `starting_log_inv_rate` is the lever and `nv` is what pins it

**Status.** Found while generating the Solidity fixed config. Not yet resolved.
This gates the whole on-chain story, so it is recorded before any verifier code
is written — generating a verifier for an infeasible schedule is wasted work.

**The measurement** (`whir::tests::dump_schedule_curve`, `#[ignore]`, 96-bit,
`FoldingFactor::Constant(4)`, `JohnsonBound`, total = rounds + final queries):

```text
lir=1  nv=26: 268 queries   start_dom=2^27   round0=177   <- OURS TODAY
lir=1  nv=22: 275 queries   start_dom=2^23
lir=3  nv=22: 114 queries   start_dom=2^25
lir=4  nv=22:  91 queries   start_dom=2^26
lir=6  nv=18:  59 queries   start_dom=2^24
lir=6  nv=22:  65 queries   start_dom=2^28
lir=3  nv=26: INFEASIBLE    FoldedDomainExceedsCapacity { 25 > 24 }
lir=4  nv=24: INFEASIBLE    FoldedDomainExceedsCapacity { 26 > 24 }
```

**Why this is blocking.** `sol-whir-p3` measures 3,637,880 gas for a whole
KoalaBear-quintic WHIR tx with ~20 queries, of which 54,436 B calldata is
~870k gas. That leaves ~2.7M for compute over ~20 queries — roughly
**135k gas/query**. At 268 queries that is ~36M gas, over the 30M block gas
limit. Our current schedule cannot be verified on an EVM chain.

**The mechanism.** WHIR trades domain size (prover FFT cost) against query
count (verifier gas). Higher `starting_log_inv_rate` = more redundancy per
query = fewer queries for the same security. But the committed domain is
`2^(nv + lir)` and `p3-whir` 0.8.0 caps the **folded** domain at `2^24`
(`FoldedDomainExceedsCapacity`). So:

```text
   bigger circuit (nv)  ->  lower affordable lir  ->  more queries  ->  more gas
```

**Root cause of `nv=26`:** the nullifier gadget (D-035). 288 Keccak-f per
nullifier pushed the transfer's stacked arity from ~22 to 26, which pushed
`LOG_MAX_LDE` from 24 to 26, which pinned `lir` at 1. **Proving nullifier
non-membership in-circuit — the governing requirement — is what made the
on-chain verifier expensive.** That tension is the finding; it is not a
reason to back out of the in-circuit proof.

**Candidate resolutions, in order of preference.**

1. **Stop over-provisioning `nv`.** `config(cap_height, num_variables)` is
   being called with `num_variables = LOG_MAX_LDE`, the *maximum*, not the
   *actual* stacked arity. If the real stacked arity of the block circuit is
   ~22, then `lir=6` becomes affordable at 65 queries — a 4x cut. Measure
   the actual stacked arity and size the config to it. **Do this first.**
2. **Raise `starting_log_inv_rate` deliberately** once (1) fixes the input.
   The table shows each +1 LIR roughly halves queries.
3. **Shrink the nullifier insert fold.** The 256-level insert fold is the bulk
   of the arity. A block-level shared insert (insert N nullifiers sharing the
   top levels once) would cut it from 256N to ~256 + N. Deferred: changes the
   statement shape and cannot live at the transfer layer (D-026).
4. **Lower the security level.** 96 -> 80 cuts queries, but 96 was already a
   concession from the 128 target; going lower needs a user decision.

**Rejected:** wrapping in a SNARK to amortise (forbidden — no SNARKs), and
their LeanVM terminal (D-036 — that solves a different problem).

**Next action.** Measure the actual stacked variable count of the transfer and
block circuits instead of passing `LOG_MAX_LDE`, then re-run the curve at the
real `nv` and pick the highest feasible `lir`. The Solidity fixed config must
be generated from whatever that lands on.


## D-036 — Vendor sol-whir-p3's STANDALONE WHIR verifier; do NOT use their LeanVM terminal

**Status.** `ethereum/sol-whir-p3` @ `18eda721fea91b5304242cc62d1d5f585d7b23ff`
cloned to `.scratch/vendor/sol-whir-p3` for study. Vendoring as a pinned
Foundry lib is the next step.

**Their repo has two verifier paths, and only one is ours.**

| Path | Contract | What the chain verifies |
|---|---|---|
| Standalone WHIR | `WhirVerifier4`, `WhirBlobVerifierNative*` | One multilinear **PCS opening**: WHIR folding rounds, Merkle multiproof openings, WHIR's own sumchecks |
| LeanVM terminal | `LeanVmTwoCommitmentTerminal_*.verifyC1V1` | "LeanVM correctly executed the whole Spartan-WHIR verifier" — a zkVM guest trace |

They need the terminal because a Spartan-WHIR verifier is too large to
re-implement directly in Solidity, so they prove the verification inside a VM
and verify the VM. ~20 extra Solidity files (`LeanVmAir`, `LeanVmGkrSumcheck`,
`LeanVmLogUp`, `LeanVmPoseidon1`, `LeanVmPackedPolynomial`, …) and a
**quintic** field (`KoalaBearExt5`) where the standalone path is `Ext4`.

**We do not need it.** Our recursion is already in-circuit via
`p3-recursion`'s `WhirRecursionBackend`: layer N is a Keccak-transcript WHIR
proof over the recursion circuit. The chain therefore verifies exactly one
WHIR PCS opening — the standalone path. Adopting the terminal would mean
adopting a zkVM to avoid writing a verifier we already have a proof for.

**What the standalone verifier does NOT give us (must generate ourselves).**

1. **The AIR quotient identity.** uni-stark's
   `sum(alpha_i * C_i(trace@z, trace@omega*z)) = quotient@z * Z_H(z)` — the
   Solidity equivalent of `VerifierConstraintFolder`. Their repo has no
   analogue because Spartan's AIR is the VM's, not ours. This is the
   "generate the constraint evaluator from `SymbolicAirBuilder`" item, and it
   is roughly half the verifier effort. Generating rather than hand-writing is
   the anti-drift requirement: a hand-written evaluator silently diverges from
   the Rust AIR the moment either changes.
2. **Our fixed config.** Their `QuarticWhirFixedConfig_lir6_ff5_rsv1` is
   emitted by `spartan-whir-export` from *their* prover's schedule. Ours must
   be emitted mechanically from `p3-whir` 0.8.0's `WhirConfig` accessors —
   `round_parameters()`, `final_round_config()`, `commitment_ood_samples()`,
   `starting_folding_pow_bits()`, `final_sumcheck_rounds()`,
   `n_rounds()`, `max_pow_bits()` — for our parameters: 96-bit,
   `starting_log_inv_rate = 1`, `FoldingFactor::Constant(4)`,
   `JohnsonBound`, `LOG_MAX_LDE = 26`.

**The feasibility signal.** The two proof shapes are near-isomorphic:

```text
ours   WhirProof { initial_ood_answers, initial_sumcheck, rounds[],
                  final_poly: Option<Poly<EF>>, final_pow_witness,
                  final_openings: QueryOpenings, final_sumcheck: Option }
theirs WhirProof { initialCommitment,   initialOodAnswers, initialSumcheck,
                  rounds[], finalPoly, finalPowWitness,
                  finalQueryBatch, finalSumcheck }
```

Round-level: ours `WhirRoundProof { commitment: Option<Com>, ood_answers,
pow_witness, openings: QueryOpenings<F,EF,MultiProof>, sumcheck }` vs theirs
`WhirRoundProof { commitment, oodAnswers, powWitness, queryBatch, sumcheck }`.
Their `QueryBatchOpening {kind, numQueries, rowLen, values, decommitments}`
is a flattened form of our `QueryOpenings::Base|Extension(SharedProofOpening
{ rows, proof })` — the `kind` tag is exactly our Base/Extension discriminant.

**Two transcript facts that make the port tractable.**

- Their `KeccakChallenger.observeBase(value)` appends a little-endian `u32`,
  which is exactly `SerializingChallenger32::observe` (`value.to_unique_u32()
  .to_le_bytes()`). Same byte stream.
- Their `sampleBase` masks with `0x7fffffff` and rejects `>= p` — the same
  rejection-sampling-without-modulo-bias that `SerializingChallenger32::sample`
  does via `pow_of_two_bound`. So challenge values agree bit for bit.
- Their sponge is **not** a duplex: `flush()` hashes the whole input buffer
  including the previous output (`input_buffer.extend_from_slice(&output)`),
  and sampling consumes from `output_buffer`. That matches p3's
  `HashChallenger::flush` exactly — same chaining, same re-hash of the digest.
  This is the single most important thing to get right and it matches.

**Their Merkle uses `0x00`/`0x01` domain prefixes; ours is prefix-free**
(`hash_pair(l, r) = keccak256(l || r)`, no leaf hashing). Adapt THEIR Merkle
helpers to prefix-free rather than the reverse — our tree convention is pinned
by `crates/shielded/tests/contract_vectors.rs` and the golden roots in
`contracts/test/vectors/merkle.json`.

**Skip list.** LeanVM/* (all 20 files), `KoalaBearExt5`, `KoalaBearExt8`,
BabyBear everything, `*Precompile*`, `spartan-whir-export` (different prover).

**Licensing.** Per-file `SPDX-License-Identifier: MIT` throughout the files we
want. Keep the per-file SPDX on vendored files and record provenance in the
commit that adds them.


## D-035 — Fixed-shape nullifier gadget: `FOLD_DEPTH = 32`, and the real cost of a spend

**Status.** Done and wired. `crates/prover/src/nullifier_gadget.rs` (6 tests + a
cost probe), threaded through `constrain_transfer` and the block circuit's
`NullifierChain`.

**The problem a circuit has that the native map does not.** The native
`NonInclusionWitness` has a *variable* length: `start_height` is wherever the
empty subtree containing the address actually begins, and the sibling list is
`256 - start_height` long. A STARK trace cannot have a data-dependent number of
rows. So the variable part becomes a compile-time floor:

```text
FOLD_START = NULLIFIER_TREE_DEPTH - FOLD_DEPTH = 256 - 32 = 224
```

Every absence fold runs exactly 32 levels, starting at height 224.

**Why padding downward is exact, not approximate.** Emptiness is
*downward-closed inside a containing subtree*: if the subtree at height `h` is
empty then so is the one at any `h0 <= h` on the same path. So when the true
`start_height` is above the floor, the extra bottom levels are just
`empty[.]` constants and folding from 224 instead of from the true height
produces the identical root. `prepare_witness` pads with `map.empty_at(h)` for
`h in 224..start_height`.

**Why padding upward would be a bug, and is refused instead.** If the true
`start_height` is *below* 224 the map is denser than this circuit can attest
to. Folding from 224 there would assert an emptiness that does not hold.
`prepare_witness` returns `Err("nullifier map too dense ...")` — never silent
padding. `FOLD_DEPTH` is therefore a capacity parameter in the same spirit as
`LOG_MAX_LDE`: too small and proving fails loudly.

**Capacity.** With addresses uniform, `FOLD_DEPTH = 32` supports on the order
of `2^32` spent nullifiers before a transfer cannot be witnessed. That is far
past any realistic deployment, and the fold stays at 32 hashes.

**Address bits are derived, not declared.** The direction bits come from
`decompose_to_bits` on the *in-circuit* nullifier digest limbs — 16 bits per
limb, 16 limbs, bit `b` of the digest = bit `b % 16` of limb `b / 16`, which
matches the native `addr_bit` because each 16-bit limb is two little-endian
bytes. A prover who could choose the address could route a spend around the
empty-subtree check; deriving it makes that impossible.

**Measured cost: 288 Keccak-f per nullifier.** 32 for the absence fold plus
256 for the insert fold. The insert fold is *not* reduced by sparsity: the
empty-collapse only applies when **both** children are empty, and the inserted
leaf is not. At 24 rows per Keccak-f that is ~6,900 AIR rows per spend. This
is the dominant cost of the transfer circuit by a wide margin — the 32-level
commitment fold is 32 hashes by comparison.

**Consequence for the height budget.** The transfer's WHIR grinding budget rose
from 17 to 19 ground bits (1-in/1-out) and 20 (2-in/2-out), so
`transfer::LOG_MAX_LDE` moved 24 -> 26. Sized by measurement, not headroom:
over-provisioning costs ~2.7x proving time (D-031) and under-provisioning
panics at `pcs.rs:270`.

**Two LogUp traps hit while wiring this.**

1. `builder.connect()` between the threaded root and a fold output broke the
   Keccak lookup multiplicities — `Lookup mismatch (global lookup
   'WitnessChecks'): tuple [...] has net multiplicity 2130706431` — because
   from the second spend onward the threaded root is a *live witness
   expression*, not a constant. Fixed with `sub()` + `assert_zero()`. The
   existing `connect` calls against `const_limbs` are fine; the rule is
   specifically about aliasing two non-constant slots.
2. The same rule already forced `sub()`+`assert_zero()` in the block circuit's
   root anchor; the new `NullifierChain` reuses that helper rather than
   rediscovering it.

**Alternatives considered.**
- *Variable-depth fold with per-branch padding.* Rejected: a circuit cannot
  branch on `start_height` without instantiating every depth.
- *`FOLD_DEPTH = 64` or `128`.* More capacity than needed, and 2x/4x the
  absence-fold cost for a bound we will not approach.
- *Make the insert fold sparse too.* Not possible: inserting at a leaf forces a
  real hash at every level up to the root. An MMR would amortise it but is
  backwards for the non-membership direction (D-034).
- *Batch the insert folds across a block.* Real future optimisation: a block
  inserting N nullifiers could share the top levels once instead of N times.
  Deferred — it changes the statement shape and the contract's read, and the
  per-transfer proof structure (D-026) does not allow it at the transfer layer.


## D-034 — Nullifier accumulator is a sparse Merkle map, full 256-bit address, depth 256

**Status.** Native structure done: `crates/shielded/src/nullifier_tree.rs`, 13
tests green. Circuit gadget is the next step.

**The shape.** A sparse Merkle tree over the *full* 256-bit nullifier space.
The address of a nullifier is the nullifier itself — all 256 bits, one bit per
tree level. The leaf value is the nullifier digest (presence *is* the value).
Empty leaf is the zero digest; `empty[h] = H(empty[h-1], empty[h-1])`.

Non-inclusion is certified by a **constant**, not a traversal: fold
`empty[start_height]` up through the witness's siblings and compare to the
root. `start_height` is the height of the largest empty subtree containing the
address.

**Why the full address, no truncation (user directive, and correct).**
Truncating the address to `d` bits makes two nullifiers collide in position at
2^d work. At `d = 32` that is a weekend of GPU time, which turns tree
collisions into a griefing vector. Full-width addressing puts that at 2^128 and
removes the question. The tree being 256 deep costs almost nothing here because
it is *sparse*, and the empty-subtree constant is what exploits the sparsity.

**Why this is cheap, not expensive.** Bucket each spent address by the highest
bit at which it differs from the probe. A bucket at level `j` is exactly the
sibling subtree of our path at level `j`. With k occupants scattered over
2^256, the closest one differs at roughly bit `log2(k)`, so the witness is
~`log2(k)` siblings and the fold is ~`log2(k)` hashes — independent of the
256 depth. Measured: 16 occupants → witness well under 64 hashes.

**The derivation trap, recorded because it was got wrong twice in one session.**
Two addresses share the level-`h` subtree iff they agree on every bit from `h`
upward, i.e. iff their highest differing bit is **below** `h`. So the subtree
at `h` is empty only once `h` reaches the **closest** occupant's highest
differing bit:

```text
start_height = min over spent b of highest_differing_bit(probe, b)
```

The first instinct — `max`, or `max + 1` — is wrong in both directions. The
first cut used `max + 1` and produced a witness that verified against a root it
should not have.

**What the witness is NOT.** It is not bound to a single nullifier. Any address
agreeing on bits ≥ `start_height` folds to the same root, so a witness is
portable across absent addresses. That is harmless: verification implies
absence, which is the only thing the circuit needs. The test
`witness_never_attests_to_a_spent_nullifier` pins exactly the property that
matters — no spent address ever verifies — rather than a stronger property that
is both false and unnecessary.

**Cost of the insert direction, honestly recorded.** Non-inclusion is
O(log k), but insertion folds from the leaf all the way to the root: 256
Keccak-f per nullifier, *not* reduced by sparsity, because the collapse only
applies when both children are empty. So a transfer pays ~256 + log2(k)
Keccak-f per nullifier. At 24 rows per Keccak-f that is ~6.2k rows per
nullifier — fits a transfer trace comfortably, to be confirmed by measurement.

**Alternatives considered.**
- *Depth 32, truncated address.* Cheapest (≤32 hashes both directions) but the
  2^32 collision griefing is real. Rejected.
- *Depth 128.* Collision-safe at 2^128 and halves the insert cost. Genuinely
  competitive; rejected only because the directive is full-width and the
  measured cost at 256 is acceptable. Revisit if proving time bites.
- *Append-only MMR for nullifiers.* Insertion is cheap but non-inclusion is
  O(n). Exactly backwards from what the circuit needs. Rejected.
- *Contract-side nullifier set.* Forbidden by the governing instruction: the
  Solidity contract tracks state roots, replay resistance is proven in circuit.

**Model.** `midnightntwrk/midnight-zk` `circuits/src/map` is the same
structure and independently confirms the design: their `verify_path` folds from
the leaf with `cond_swap` on the address bits, and non-inclusion is the *same
code path with `value = 0`*. Their default-zero map is why one gadget serves
both directions. Their code is Apache-2.0; ours is written from the structure,
not copied, so no licence obligation attaches to the implementation.

## D-032 — Nullifier non-membership moves in-circuit; the contract stops checking replays

**Status.** Governing pivot, in progress.

**Directive.** "i want state updates under zk, including nullifier. Solidity
contract tracks state roots."

**What changes.** The nullifier replay check moves from the contract into the
proof. `ShieldedPool.sol` as first written holds a `mapping(bytes32 => bool)
nullifierSet` and does two contract-side replay passes. Both are now wrong by
construction and must be deleted. The contract keeps: verify the proof, apply
`root_before -> root_after` for **both** trees, block numbering, fee
accounting.

**Why the contract-side set was the wrong shape.** With a contract nullifier
set, the proof attests only to *membership* of what it spends. Replay
resistance lives in contract storage, so the thing the rollup most needs to
guarantee is the one thing not covered by the proof — and every consumer of
the root (bridges, other chains, light clients) has to re-derive it from
contract state rather than from the proof. Proving absence in circuit makes the
root itself the guarantee.

**Two roots, both tracked and chained.** The commitment tree root (membership)
and the nullifier map root (non-membership). Both belong in the verified
statement; the contract stores both transitions.

**Consequence for existing docs.** `transfer.rs` doc lines 39-40 claim the
nullifier gap "is closed by the on-chain nullifier set", and D-030 says
nullifier uniqueness is "deliberately absent … covered by the settlement
contract". Both are obsolete and must point at the in-circuit proof instead.

## D-031 — Transfer shape is bound into the verified statement as circuit constants

**Status.** Done, commit `b2f2d79`.

**The hole.** The split between each transfer's nullifiers and its output
commitments was supplied by the caller. A prover could declare a split that
makes the contract read an **output commitment as a nullifier**, or skip a real
nullifier, and settle a double spend.

**The fix.** Export the split as circuit constants inside the verified
statement:

```text
[ n, (nin_0,nout_0), ..., (nin_k,nout_k) | child statements... ]
```

`shape_header` is the single source of truth. The circuit exports the limbs via
`define_const`, so the values are *proven*, not supplied; the test rebuilds the
expected statement through the same function, so neither side can drift on
where the header ends and the transfer limbs begin.

**The defence is proof-binding, not a length invariant.** A 0-in/2-out
declaration has exactly the same statement length as 1-in/1-out. No length
check can catch the split shift. Only the fact that the header bytes live
inside the hashed/committed statement does.

**Two facts discovered the hard way, both load-bearing.**
- `define_const` bakes a value into the const trace and allocates **no**
  public-input slot. Pushing header limbs into the public-input vector
  overshoots the circuit width by exactly the header length
  (`PublicInputLengthMismatch { expected: 15358, got: 15363 }`).
- Over-provisioning the height budget is not free: fan-in 2 cost 9.2s at
  v=25 vs 25.1s at v=27. Each fan-in needs its own measured value.

## D-030 — The block circuit needed a shared-root anchor (found while auditing nullifiers)

**Status.** Done. `crates/prover/src/block.rs`, commit `3965a35`.

**Found while.** Auditing what the block statement actually guarantees, on the way
to closing the nullifier gap (D-022 / ticket 02). The nullifier question forced
the question "what does a block statement attest to?", and the answer was not
strong enough.

**The hole.** `build_multi_transfer_circuit` verified each child transfer proof
and concatenated their statements:

```text
[transfer 0: nullifiers..., outputs..., root_0, fee_0,
 transfer 1: nullifiers..., outputs..., root_1, fee_1]
```

Nothing constrained `root_0 == root_1`. Each child was *individually* valid —
its own membership path checks against its own root — so a prover could gather
transfers witnessed against **different tree states** and produce a block whose
statement describes a state transition of a tree that never existed. A
settlement contract applying that statement would move state that no real tree
supports.

This is not the nullifier gap. It is a separate, and arguably worse, hole: the
nullifier gap is closed by an authoritative on-chain set, whereas nothing
downstream could catch a mixed-root block because every individual proof
verifies.

**The fix.** `RootAnchor` adopts the first child's 16 root limbs and constrains
every later child equal to it. It is opaque by construction — `Default` plus a
single `pin` method — so the only way to use it is to feed each child in turn,
which is exactly the invariant. There is no accessor to read or bypass the
pinned value.

**Why not `builder.connect`.** `connect` enforces equality by aliasing witness
slots. The statement table tracks LogUp multiplicities *per instance*, and
aliasing across two children's instances desynchronises them: the witness fails
to balance with `Lookup mismatch (global lookup 'WitnessChecks'): tuple [...] has
net multiplicity 6`. Expressing equality as `sub(a, b)` + `assert_zero` is a
plain ALU constraint that leaves the lookup structure alone. Costs one ALU row
per limb, 16 rows per extra child.

**Shape is declared, not assumed.** `ChildProof` now carries `TransferShape
{ num_nullifiers, num_outputs }`. The root offset is derived from it, and a
shape whose implied statement length disagrees with the actual statement is
rejected *before* any constraint is emitted. Without that check a wrong shape
would silently pin the anchor to the wrong limbs — a soundness bug introduced by
the fix itself. This is the reason the shape is explicit rather than inferred
from the statement length, which would be ambiguous.

**A/B verification.** The negative test is only meaningful if the rejection is
attributable to the anchor. With the anchor body removed, the exact same
mixed-tree input **builds and proves cleanly**; with it restored, the witness is
unsatisfiable and reported as a `Witness conflict`. The test asserts on that
message so a future refactor that silently stops constraining will fail loudly.

**Lesson.** Concatenating verified statements is not the same as constraining
their relationships. Per-child verification proves each part; the *set* needs
its own constraints or it asserts more than it proves.

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
| opt-level 3, **debug-assertions off** | 9.2 s |
| opt-level 3, **debug-assertions on** (shipped) | **23.2 s** |

**~20× runtime speedup** with the shipped profile. The gap between 9.2 s and
23.2 s is `debug-assertions` alone — everything else is identical. That is a
real cost, paid deliberately, for the reasons below.

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

**Measured, shipped profile (opt-level 3, debug-assertions on, rayon on,
10-core M2 Pro, 32 GB).**

| Aggregated client transfer proofs | wall | peak RSS |
|---|---|---|
| 1 (fan-in 1, D-023 path) | 10.7 s | 2.93 GB |
| 2 (fan-in 2, `block.rs`) | 23.2 s | 5.73 GB |

Marginal cost: **~12.4 s and ~2.8 GB per additional transfer.** Linear in both.

**Memory, not time, is the binding constraint.** On a 32 GB machine, allowing
~4 GB for the OS and harness leaves ~28 GB for proving:

```
N_max ≈ 1 + 28 / 2.8 ≈ 11 transfers
```

Time would allow ~34 transfers in 7 minutes; memory caps it at ~11. A
fan-in-N block circuit holds **all N children's traces simultaneously**, so it
cannot be fixed by waiting — it is a hard ceiling per machine.

**Why memory barely improved with the profile change.** Dev and shipped profiles
give nearly identical RSS (2.9 GB at fan-in 1 in both) while differing ~20x in
time. Trace data dominates memory; compiled code does not appear in it at all.
No build setting fixes the memory ceiling.

**Why D-026's dismissal of the tree was wrong.** D-026 said the tree "trades
circuit size for sequential depth." That is backwards on both axes:

- **Depth.** Fan-in N is *linear* depth in N on one box. A binary tree is
  `log₂ N` sequential levels. Depth improves, it does not worsen.
- **Memory.** A fan-in-N circuit holds all N children's traces at once. The
  tree keeps every node at fan-in 2, bounding per-node memory at ~5.7 GB
  regardless of how many transfers the block covers.

**The real tradeoff.** The tree costs *more total CPU work* — roughly 2N proofs
of work across all levels versus N — and buys *lower wall clock* and *bounded
memory* by proving each subtree independently, which fans out across
**machines**, not just cores.

```
fan-in N, one box:      N × 12.4 s,  N × 2.8 GB     (memory-bound at N≈11)
binary tree, K boxes:   log₂(N) × ~23 s, ~6 GB/node  (bounded, parallel)
```

Projection at N = 256 over 8 boxes: ~8 levels × 23 s ≈ 3 min wall, against
~53 min serially and an infeasible ~700 GB of memory for the flat circuit.
**This is a projection from measured fan-in numbers, not a measured tree
result** — per-level cost is assumed constant, and higher-level nodes verify
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

## D-033: Solidity WHIR verifier base = ethereum/sol-whir-p3 (MIT)

**Context.** User pointed at `alxkzmn/spartan-whir-dev` (meta-repo, no license), then its
verifier `alxkzmn/sol-spartan-whir`, then the canonical home `ethereum/sol-whir-p3`
(same tree, 591 entries, pushed 2026-09-13). Chosen as the off-the-shelf base for the
layer-N verifier.

**Verified fit.**
- `KoalaBear.sol`: MODULUS 0x7f000001, W=3 — identical to our `F`.
- `KoalaBearExt4.sol`: quartic binomial extension packed in uint256, assembly add/sub/mul
  — identical shape to our `Challenge = BinomialExtensionField<F, 4>`.
- `KeccakChallenger.observeBase`: absorbs base elements as little-endian u32 — byte-identical
  to our `SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>`.
- Keccak Merkle multiproof verifier — same family as our settlement
  `PaddingFreeSponge<KeccakF, 25, 17, 4>` + `CompressionFunctionFromHasher<_, 2, 4>`.
- Folding factor 4, sumcheck/STIR/PoW/final-poly round machinery — same WHIR protocol.
- License: no root LICENSE file, but every .sol carries `SPDX-License-Identifier: MIT`.
  Valid per-file grant; usable.

**Gaps we must fill (this repo verifies a standalone WHIR PCS opening for Spartan-WHIR,
not a plonky3 uni-stark STARK):**
1. AIR constraint evaluation at the OOD point for OUR recursion circuit
   (Poseidon2-shared + recompose + statement tables) — generated from
   `SymbolicAirBuilder`, per the standing anti-drift plan.
2. Blob codec: their fixtures come from `spartan-whir-export` bound to the `whir-p3`
   FORK at rev fc7d591. We emit registry `p3-whir` 0.8.0, which already has
   `QueryOpenings`/`MT::MultiProof` (their migration doc's "missing multi-index
   opening" is closed upstream). We write our own exporter in `crates/prover` that
   serializes our `WhirProof` into their blob shape; we do NOT use their exporter.
3. Fixed-config regeneration: their `*WhirFixedConfig.sol` hardcodes k22_jb100_pow28 /
   ext5 schedules. Ours: 96-bit, ext4, starting_log_inv_rate=1, BLOCK_LOG_MAX_LDE=25.
   Constants emitted mechanically from our `WhirConfig`.
4. Skipped: LeanVM/Spartan terminal layer, BabyBear variants, precompile experiments.

**Adaptation shape.** Vendor field/challenger/merkle libs unmodified where possible →
port the WHIR round loop mirroring p3-whir 0.8.0's Rust verifier (their round code as
cross-check, not authority) → our exporter + fixed-config generator → generated AIR
constraint evaluator. Rust-emitted test vectors pin every seam.
