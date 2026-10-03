# Decisions log

Recorded choices with alternatives considered. Newest first.
## D-049 — SumcheckCore: the transcript is a chained sponge, and limbs live at bit 128

**Status.** Implemented and green. `contracts/src/verifier/SumcheckCore.sol`
replays all three recorded Rust shapes (1, 4 and 5 rounds) to the exact
final claim, driven by `sumcheck_vectors.json` generated from the real
`SumcheckData::verify_rounds`.

**The three bugs the vector harness caught, none of which a hand-written
test would have.**

1. **Canonical vs Montgomery on the absorb path.** Field arithmetic in
   this codebase is canonical, but `SerializingChallenger32::observe(F)`
   writes `to_unique_u32()`, which is the internal *Montgomery* form.
   Absorbing the canonical `1` instead of `0x01fffffe` desynchronizes
   every subsequent challenge while producing a perfectly well-formed
   digest. Fixed with `toMontgomery(v) = v * R mod p`, `R = 2^32 mod p =
   0x01fffffe` — not `2^31`, which is the natural wrong guess and also
   silently wrong.

2. **The last limb is at bit 128, not bit 0.** `KoalaBearExt4.pack` is
   `c0<<224 | c1<<192 | c2<<160 | c3<<128`; the low 128 bits are always
   zero. Reading `packed & mask` for the fourth limb yields a valid-looking
   zero. Round 0 of the vectors has `c3 == 0`, so round 0 passed and the
   bug only surfaced at round 1 — the classic shape of a bug that a
   single-example spot check confirms rather than catches.

3. **The sponge chains; it does not clear.** `HashChallenger::flush`
   (p3-challenger 0.8.0, `hash_challenger.rs:59-67`) drains
   `input_buffer`, hashes it, then writes the digest **back into
   `input_buffer`** as well as `output_buffer`. So round *n+1* absorbs
   `digest_n || new_bytes`, not `new_bytes` alone. Verified independently:
   `keccak256(prefix || round0_pair)` =
   `64edc676...1963fa3a`, and `keccak256(that || round1_pair)`
   reproduces round 1's sampled bytes exactly. The vendored
   `KeccakChallenger._flush` already chains correctly, so this was a
   thing to *confirm*, not to fix — but it is load-bearing and was not
   previously written down anywhere.

**Why the replay is the right test, not a property test.** Fiat–Shamir is
a running hash whose *order* of absorbs determines every challenge. A
reordered absorb set derives completely different challenges and looks
correct in review. `test_replay_matches_rust` pins the whole interleaved
program; `test_missing_prefix_desynchronizes` proves the coupling is real
by showing that dropping the domain-separator prefix changes the output.

**Reverted decision: use `observeValidatedPackedExt4Pair`.** The vendored
pair absorber byte-swaps limbs big-endian for its own transcript
convention. Ours is little-endian. We absorb each limb through
`observeBase` (which is `_appendBaseLE`) after the Montgomery conversion,
so the wire is `monty(c0).LE || monty(c1).LE || monty(c2).LE ||
monty(c3).LE` per element, `c_a` before `c_inf`.

**Anti-drift.** `prefix_hex` and `round_absorbs_hex` are emitted by the
Rust generator from the real verifier's own trace, never hand-written. A
change to the field, the transcript, or the round count shows up as a
reviewable diff in `sumcheck_vectors.json`.

**Revert this if** p3 changes `flush` to a non-chaining sponge, or if the
packed limb layout changes. Either change breaks `test_replay_matches_rust`
loudly, which is the point.

## D-048 — The vendored sumcheck fold is the WRONG FIELD IDENTITY for us

**Status.** Discovered while generating sumcheck vectors, before writing any
Solidity sumcheck code. This is the single most consequential finding of
the verifier build so far, and it invalidates the plan to port
`WhirVerifierCore4._verifySumcheck` directly.

**What the vendored verifier does.** `sol-whir-p3` folds each sumcheck
round with `KoalaBearExt4.extrapolate_012` — Lagrange interpolation of a
quadratic through the nodes **{0, 1, 2}**:

```
l0 = (r-1)(r-2)/2   l1 = r(2-r)   l2 = r(r-1)/2
C' = e0*l0 + e1*l1 + e2*l2
```

**What our prover does.** p3 0.8.0's WHIR verifier
(`p3_whir::pcs::verifier::mod`, all three call sites) calls
`SumcheckData::verify_rounds(..., Basis::Evaluation)`, whose round
identity is `p3_sumcheck::lagrange::extrapolate_01inf` — interpolation
through **{0, 1, infinity}**:

```
h(r)  = h(0)*(1-r) + h(1)*r + h(inf)*r*(r-1)
C'    = c_a*(1-r) + (C - c_a)*r + c_inf*r*(r-1)      [h(1) = C - h(0)]
```

**Measured divergence.** Over the 256 generated cases, the vendored
{0,1,2} fold agrees with the real Rust fold on 96 and disagrees on
**160 (62.5%)**. The 96 agreements are the degenerate operands (zero,
one, p-1 in the constant limb) — which is precisely why a hand-written
spot-check would have "confirmed" the wrong formula. An independent
reimplementation of `extrapolate_01inf` in Python matches the real Rust
fold in all 256.

Both folds return a well-formed field element. Neither panics. A verifier
built on the vendored fold would reject honest proofs and, worse, its
failure would look like a transcript desynchronization rather than a
wrong-identity bug.

**Second finding: the transcript is versioned and self-describing.** The
vendored Solidity transcript absorbs the round polynomial values as bare
field elements. p3 0.8.0 absorbs, before any round:

```
VERSION = 1
NAME    = "p3-sumcheck-quadratic"
InteractionPattern (the described step sequence)
instance byte: 0 = Evaluation, 1 = Projective
```

Measured on the wire: a one-round replay absorbs **45** base-field
elements, of which only 8 are the two extension values; the rest is the
domain-separator prefix. The prefix is **deterministic per shape** —
verified by replaying each shape twice and comparing byte-for-byte — and
**depends on the round count**, so it is a per-schedule constant, not a
global one.

**Consequences for the build.**

1. Do NOT port `_verifySumcheck`. Write the fold as `extrapolate_01inf`
   and pin it with `sumcheck_vectors.json`, which is generated by the real
   `SumcheckData::verify_rounds` driven through the workspace's traced
   Keccak challenger.
2. The Solidity transcript must absorb the p3 0.8.0 domain separator
   before the first round. Since the prefix is a constant per shape, the
   generated `WhirFixedConfig` should carry it as a byte blob rather than
   the Solidity side reconstructing the `InteractionPattern`.
3. `Basis` is `Evaluation` for all WHIR paths today. The instance byte
   still has to be absorbed, and if a future config used `Projective` the
   fold changes to `extrapolate_01inf(C - c_inf, c_a, c_inf, r)`.

**Alternatives considered.**

- *Port the vendored fold and adapt the prover.* Rejected: our prover is
  p3 0.8.0 and is not going to change its identity to match a third-party
  contract.
- *Reimplement the whole `InteractionPattern` encoder in Solidity.*
  Rejected as far larger and more fragile than embedding the measured
  constant blob. The pattern is fixed by the schedule; there is nothing to
  compute at verification time.
- *Trust the vendored fold because it is "the reference".* Rejected on
  measurement. It is the reference for a different p3 version.

**General lesson, recorded because it generalizes.** A reference verifier
is only a reference for the field and protocol version it was built
against. Where two implementations of the same-named primitive disagree,
the vectors must come from *our* prover's code path, not from the
reference's. This is the second time in this build that generating vectors
from the real library caught something a plausible transcription got wrong
(the first being the Montgomery constant).

## D-047 — Verifier design synthesis: what the three references actually teach us

**Status.** All three reference repos cloned to `.scratch/refs/` and read in
full: `ethereum/sol-whir-p3` (MIT), `input-output-hk/plutus-plonky3-exploration`
(Apache-2.0), `GOATNetwork/bitcoin-stark-verifier`. This entry does **not**
re-decide anything D-036, D-038 or D-039 settled — it records the
*engineering discipline* each repo contributes and the concrete module plan
that follows.

Builds on: D-036 (standalone WHIR path, not LeanVM), D-038 (767 KB proof,
four top-level WHIR runs, Merkle paths are the cost), D-039 (chunk by WHIR
round across transactions, `ChunkVerifier` + `ShieldedPool`, Fiat-Shamir as
a running hash makes pausing sound), D-045 (canonical vs Montgomery
statement/transport), D-046 (HVZK live, R commitment must be verified).

### 1. `sol-whir-p3` — architecture to copy, protocol not to copy

Confirmed D-036's near-isomorphism reading. What is worth taking beyond the
primitives:

- **Four-layer split per schedule.** `*FixedConfig` (generated constants +
  `roundConfig(i)` table) / `VerifierCore` (protocol) / `BlobCodec` (wire)
  / `BlobVerifierNative` (parse+verify). **The schedule is data, not
  control flow.** Our settlement config is fixed forever, so a generated
  config contract is the right home for it.
- **`observePattern(challenger)` as one opaque `hex"..."` blob.** The whole
  Fiat-Shamir domain-separation pattern absorbed in one call. If the pattern
  changes the blob changes, and the diff is reviewable. This is the single
  best idea in the repo and we adopt it verbatim.
- **Three paths per schedule**: native blob (production), typed ABI
  (`verify(commitment, statement, proof)` with structs, for debug/parity),
  decode-and-delegate. We build the **typed path first** — our first
  milestone is parity, not gas.
- **Named errors for every rejection**: `FixedRoundCountMismatch`,
  `MissingFinalQueryBatch`, `FixedStatementShapeMismatch`,
  `FixedStatementArityMismatch`, `FixedFinalPolyLengthMismatch`,
  `FixedRandomnessLengthMismatch`, `CommitmentMismatch(expected, actual)`.
  A mismatch during bring-up is a named condition, not a revert to bisect.
  Adopt wholesale.
- **Validation at the boundary.** `validatePackedExt4{,Calldata}` range-
  checks every field element against `p` as it is read from calldata. A
  limb ≥ p never enters arithmetic. Adopt.
- **Documented compiler settings with measured gas** (`solc 0.8.28`,
  `via_ir`, 833 runs, Prague).

Not transferable: the protocol itself (spartan-whir's WHIR, different
statement shape and domain separator), and their generated config's
provenance (`spartan-whir-export`, which we don't have).

**Their EIP-170 problem is a warning, not our plan.** Their KoalaBear
quintic is 34,898 B runtime — over the 24,576 B limit, measured with a
raised limit. Our verifier must fit under EIP-170 or be split. The
D-039 chunking is in *time*, not code location, so the code itself must
still fit in one contract. Budget for that from the start.

### 2. `plutus-plonky3-exploration` — the anti-drift pipeline

Their whole repo is one mechanism, and it is the answer to ticket 12's
"how do we stop Rust and Solidity drifting apart":

```
prove (Rust)  →  convert (Python)  →  verify (on-chain)
export_proof     convert.py            aiken check
  dumps JSON     auto-detects uni vs   emits a GENERATED test
                 batch, writes a       literal embedding the whole
                 test literal          proof, runs the verifier
```

**The generated test literal is never hand-edited.** Adopt as:
`cargo run -p prover --bin export_solidity_vectors` → JSON → generated
`forge` test file. Our current `block_vectors.json` is static and can go
stale silently; a generated test cannot.

Three more habits worth stealing outright:

- **Every mirrored function cites the upstream line ranges.** "Implements
  `verify` from uni-stark/src/verifier.rs:201–212 and 214–457." When the
  port disagrees, the citation makes it locatable. Every Solidity function
  that mirrors Rust names its Rust function.
- **The transcript order is written as a comment block before the code.**
  Their `verifier.ak` header lists the entire uni-stark absorb/sample
  sequence. That comment *is* the spec the port must match. Cheap to write,
  disproportionately valuable when it diverges.
- **Specialisation is declared, not hidden.** Their table lists every
  hard-wired parameter (field, extension, hash, PCS, challenger, FRI
  params, sizes, ZK) and states that changing any requires coordinated
  edits on both sides.

**The trap they document that we must not miss:** in batch-stark, instance
metadata is observed as *algebra* elements —
`observe_base_as_algebra_element::<Ext2>(x)` embeds x and observes **both**
coefficients, i.e. the bytes of `[x, 0]` — while public values stay base
elements. Base-vs-extension absorption is a classic divergence source. Our
analogue is already pinned by D-045: statement limbs canonical, transcript
limbs Montgomery. Same class, same cure.

### 3. `bitcoin-stark-verifier` — the verification *semantics*

Same field as us (KoalaBear ext4), same protocol family (WHIR), so their
correctness argument transfers directly even though the target (Bitcoin
Script, no `OP_CAT`) does not.

- **The closing identity, stated exactly:**
  `claimed_eval == w(R) · f_M(r_fin)`
  where `R` is the folding randomness accumulated across all sumcheck
  rounds, `w(R)` the accumulated constraint weight at `R`, `f_M` the
  final polynomial, `r_fin` the tail of `R`. Their verifier is organized
  to *reach* this; `final_check()` is the explicit four-coefficient
  extension comparison. Ours must end at the same place, and naming it
  makes the goal testable.
- **"An opening is one unit."** The row is bound to its leaf by
  `merkle::hash_row`, the path recomputes the root, and **that root is
  the absorbed commitment rather than a value taken from the witness.**
  This is the most important line in the whole review. Our Solidity must
  check Merkle openings against the commitment the *transcript saw*, never
  against one the proof asserts.
- **"Challenges are unchooseable."** Every challenge is squeezed *after*
  the values it depends on are absorbed; supplying one instead is a
  soundness error of exactly one. This is a property of the absorb/sample
  *order*, and it is the property a naive port breaks. Our transcript
  trace test (§4) is what enforces it.
- **"Constraints are derived, not supplied."** Each round buries the OOD
  scalars it samples, the shift points its queries produce
  (`domain_gen^index`), and its batching challenge *below* the folding
  randomness; the closing check lifts them back out and evaluates the
  whole weight polynomial from them. Carrying cost `1 + n` extension
  elements per round rather than `n·(1+arity)`. We have no stack-depth
  problem, but the discipline transfers: **never carry forward a scalar the
  transcript can regenerate.**
- **`reference.rs` is the porting pattern.** They keep a plain-Rust mirror
  of every nontrivial routine — `lagrange_weights_01inf`,
  `extrapolate_01inf`, `sumcheck_round`, `eval_multilinear` (from
  `multilinear-util`), `duplexing`/`squeeze` (from `DuplexChallenger`) —
  and **test the Rust mirror against real Plonky3 before trusting the
  script version.** For us: before a Solidity routine is trusted, its Rust
  equivalent is tested against the real prover and its vectors are emitted.
- **A formal "what is checked / what is not" review document.** We write
  the equivalent (§5) rather than let a reader guess.

Not applicable: Poseidon2-as-algebraic-hash (exists to avoid `OP_CAT`; we
have native `keccak256`), `DuplexChallenger` (we use
`SerializingChallenger32<HashChallenger<Keccak256>>`), their
proof-specialized 198 MB script (we have loops, so we write one general
verifier — their constraint is our freedom).

### 4. The transcript trace: the one test that makes everything else cheap

New this session, and the highest-leverage artifact in the plan.

Instrument the settlement prover to record **every** `observe`/`sample`
call with its value and a label, emit JSON. Drive the Solidity challenger
with the same calls and assert the same challenge sequence, byte for byte.

Why this matters more than it looks: a transcript divergence makes *every
subsequent* challenge wrong, so the failure surfaces at the final identity
check thousands of operations later. A trace test localizes it to the
**first differing byte**. That is the difference between a 10-minute debug
and a multi-day one, and it is the only practical way to verify the
Montgomery absorption convention (D-045) end to end.

Nothing builds on `Transcript.sol` or `MerkleVerifier.sol` until their
parity tests pass against a Rust-emitted trace.

### 5. Module plan (aligned with D-039's two-contract split)

```
contracts/src/verifier/
  Transcript.sol          Keccak challenger — vendored, parity-tested
  FieldOps.sol            KoalaBear + Ext4 — vendored
  MerkleVerifier.sol      ADAPTED to prefix-free (D-036), parity-tested
  WhirFixedConfig.sol     GENERATED from p3-whir WhirConfig + observePattern blob
  SumcheckCore.sol        sumcheck rounds → folding randomness R
  StirOpenings.sol        STIR query openings vs ABSORBED commitments
  WhirVerifierCore.sol    proximity check → closing identity
  ConstraintIdentity.sol  ΣαᵢCᵢ(ζ) = Z_H(ζ)·Σⱼ chunkⱼ(ζ)Qⱼ(ζ)
                          GENERATED from SymbolicAirBuilder (D-036 item 1)
  ProofCodec.sol          wire format
  ChunkVerifier.sol       the D-039 session state machine
  WhirVerifier.sol        IWhirVerifier impl over the above
```

Order of work, each step a commit that compiles and passes its own tests:

1. Rust: `export_solidity_vectors` binary — fixed config JSON + proof +
   statement + **transcript trace**.
2. Rust: a small test config (reduced `LOG_TRACE`) whose proof is a few KB,
   for verifier bring-up. **Do not bring up the verifier against 767 KB.**
3. Solidity: `Transcript` + `Merkle` parity tests against the trace.
   Gate: nothing downstream until green.
4. Solidity: `WhirFixedConfig` generated from step 1.
5. `SumcheckCore` → `StirOpenings` → `WhirVerifierCore`, each cited to
   its Rust source, each with vectors from step 1.
6. `ConstraintIdentity` generated from `SymbolicAirBuilder`.
7. `ProofCodec` + `WhirVerifier` (typed path first).
8. Vector tests: accept the real proof; reject every mutation class
   (mutated commitment, mutated statement, mutated opening, truncated
   proof, wrong round count, missing R commitment).
9. `ChunkVerifier` session state machine per D-039; drive it across
   transactions on a local chain.
10. Scale to the production config; re-measure proof size against the
    D-038 lever table.

### 6. What this verifier does NOT check (the honesty section, per bitcoin-stark-verifier)

- **The statement is supplied.** It *is* the claim; a different statement
  is a different claim, not a cheaper proof of the same one. Binding the
  statement to the state transition is `ShieldedPool`'s job and is part of
  the security argument, not the verifier's.
- **Not SHA3.** The shielded layer's SHA3-256 never appears on-chain
  (D-002). Only Keccak-256 at the settlement boundary.
- **Not the SPHINCS+ signature.** Spend authorization is the in-circuit
  nullifier relation; the envelope is checked at admission, off-chain.
- **Not the R-round binding inside the recursion circuit.** D-046 left
  `NO_RANDOM_OPENED_VALUES` in `recursive_pcs.rs`; until that is replaced
  the recursion circuit does not bind the hiding proof's random round, and
  the Solidity verifier must verify the R commitment and its openings
  directly.


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

---

## D-040 — Transcript absorbs base fields in Montgomery form; Solidity must be fed Montgomery limbs

**Date:** proven by test `transcript_trace::tests::field_observes_are_recorded_as_montgomery_little_endian_u32`

**Decision.** `SerializingChallenger32::observe(F)` serializes through
`to_unique_u32()`, which returns the **Montgomery (raw internal)** representation,
not the canonical value. For KoalaBear, `F::from_u32(0x1234)` is observed as
`monty(0x1234) = 0x30ffdb4f`, little-endian bytes `4f db ff 30` — **not**
`34 12 00 00`. The settlement exporter must therefore emit Montgomery-form limbs,
and the Solidity challenger must absorb exactly those bytes.

**Why.** This was discovered by writing the byte-level transcript recorder
(`crates/prover/src/transcript_trace.rs`) and comparing against the canonical
value computed independently as `R = 2^32 mod p` via `1u64.rotate_left(32) % P`.
The vendored `KeccakChallenger.observeBase` requires `value < MODULUS` and appends
a LE u32 — which is consistent with *either* form, so nothing in the vendored code
disambiguates it. Assuming canonical would produce a verifier that accepts nothing
(or worse, accepts the wrong statements) with no error pointing at the cause.

**Alternatives considered.**
- *Convert to canonical at the boundary.* Rejected: the transcript is what it is.
  Converting would mean the Solidity side absorbs different bytes than the Rust
  side, which is the drift this whole exercise exists to prevent.
- *Document only, don't pin.* Rejected: a fact this load-bearing must be a test.
  The pin computes `R` independently rather than calling the same `monty()` the
  prover uses, so it cannot be circular.

**Consequences.**
1. The exporter emits `to_unique_u32()` output, not `as_canonical_u64()`.
2. `BlockStatement.sol`'s limb decoding must be pinned against a Rust-emitted
   golden vector before any trust is placed in it.
3. Sampled values are a separate case: the sampler reads 4 raw bytes, masks with
   `0x7fff_ffff`, and rejects ≥ modulus. The recorder sits **below** the mask, so
   `raw & 0x7fff_ffff == canonical`. Pinned by
   `field_samples_record_the_bytes_actually_returned`.

**Security basis.** Fiat-Shamir soundness depends on prover and verifier deriving
identical challenges. A representation mismatch is a total break of that
identity — not a weakening, a failure to verify. Pinning it as a byte-level test
is the only defense that survives a plonky3 upgrade.

---

## D-041 — Node holds trees, contract holds roots; state advances by replay, never assignment

**Decision.** `PoolState` (crates/node/src/state.rs) holds the full note
`CommitmentTree` and `NullifierMap`. The settlement contract stores two
`bytes32` values and nothing else that matters. There is no `set_root` anywhere:
the only way a root changes is that notes were appended or nullifiers inserted,
and both recompute the root from the structure.

**Why.** The split is deliberately asymmetric. The node can rebuild its trees by
replaying the contract's published `BlockApplied` events — every output
commitment and nullifier is in the verified statement. The contract cannot rebuild
anything from a root; a root is a digest, not a data structure. So the node is a
replaceable service and the contract is the irreplaceable ledger. Losing the node
costs availability until another syncs; losing the contract costs the pool.

**Alternatives considered.**
- *Contract holds a full Merkle tree.* Rejected: on-chain insertion is ~50k gas
  per note against ~200 gas for a root swap, and buys nothing — the tree's
  contents are already on-chain as event data.
- *Node stores only roots, refetches paths on demand.* Rejected: the prover needs
  full paths and the full nullifier trie; refetching is strictly worse than
  holding.

**Security basis.** A `set_root` is the hole through which a node "fixes" a
mismatched root and silently corrupts its own view. Its absence means every root
in the node's history is derivable from operations that were themselves verified.

---

## D-042 — Batch members share the committed tree root and chain the nullifier root

**Decision.** Within a batch, the two roots a transfer witnesses advance on
**different schedules**, and the sequencer tracks both:

| root | behaviour within a batch | why |
|---|---|---|
| tree root | **constant** — every transfer witnesses the same committed root | a transfer's outputs are not spendable until its block lands |
| nullifier root | **chains forward** transfer by transfer | double-spend must be excluded against everything already queued |

`Sequencer` holds a `pending: NullifierMap` projection. `submit` checks against
`pending.root()` (not `state.nullifier_root()`), then advances `pending`. After a
block settles, `pending` is rebuilt from the newly-committed map plus whatever is
still queued.

**Why.** A single check that read both roots from one snapshot could express
neither. The tree root must *not* move within a batch — if transfer B could spend
transfer A's output before A's block landed, the batch would be minting. The
nullifier root *must* move — if B were checked only against committed state, two
queued transfers spending the same note would both pass admission, and the block
would be unwitnessable (or worse, if the chain constraint were absent, a
double-spend).

**Alternatives considered.**
- *Check both against committed state.* Rejected: admits intra-batch double
  spends at admission time; they only fail later, during proving, after CPU is
  spent.
- *Check both against a fully-pending state.* Rejected: would let a transfer
  witness a tree root that includes queued outputs, i.e. spend money that has not
  settled.
- *Rebuild `pending` incrementally on every submit only.* Rejected: after a
  rejection the projection could drift ahead of the ledger. Rebuilding from
  committed state after each block keeps it anchored.

**Security basis.** `PoolState::check_admit_against(public, expected_nf_root)`
takes the nullifier root as an argument precisely so one implementation serves
both the committed and pending cases without duplicating the tree-root check.
Tested by `a_double_spend_across_the_batch_is_rejected_at_admission`.

---

## D-043 — `apply` validates before it mutates (atomic state transitions)

**Decision.** `PoolState::apply` performs all validation on a probe copy before
touching the real state. A rejected transfer leaves the state byte-identical to
how it was found.

**Why.** Found by a failing test, not by review. The first implementation
inserted nullifiers as it checked them, so a transfer whose *second* nullifier
was a duplicate left its *first* nullifier spent — a half-applied transfer that
desynchronizes the two trees and leaves the node unable to build or verify the
next block. The block driver applies transfers one at a time, so this is not a
theoretical concern.

**Alternatives considered.**
- *Transactional wrapper with rollback.* Rejected: rebuilding the map is O(k·depth)
  either way; a probe copy is simpler and has no rollback path to get wrong.
- *Check-then-apply without the probe (check roots after insert).* Rejected: that
  is exactly the bug. The root check must happen before the real insert.

**Consequences.** The duplicate check also catches a transfer that lists the same
nullifier twice (`seen: HashSet`), which a set-based insert would silently
deduplicate rather than reject. Pinned by
`a_transfer_cannot_spend_the_same_nullifier_twice`, whose fixture is built so
that only the intra-batch check can catch it — a deduplicating insert would land
on exactly the claimed `after` root and sail through.

**Security basis.** A state machine that can be left half-advanced by a rejected
input is not a state machine. Atomicity here is what makes "rejected" mean
"nothing happened".

---

## D-044 — One client-walk implementation, shared via a `testkit` feature

**Decision.** `prover::client::prove_client_transfer` is the single
implementation of "build and prove one transfer". The prover's own test
fixtures (`fixtures::nullifier_transition`) **delegate** to it rather than
reimplementing the walk. Downstream crates get the fixtures via the non-default
`testkit` feature.

**Why.** Before this there were two copies of the nullifier-walk logic: one in
`fixtures.rs` (test-only) and the inline sequence in `block.rs`'s tests. Two
copies is how a test starts passing against a state transition the production
prover would not produce. The node's integration tests need the same fixtures to
drive the sequencer realistically, and a third copy in the node would have been
the natural next step.

**Alternatives considered.**
- *Keep fixtures `#![cfg(test)]` and duplicate in node.* Rejected: the node's
  e2e test would then be testing against a fixture the prover never uses.
- *Make fixtures always-public, no feature gate.* Rejected: `seed(11)` is not
  production API and should not appear in a downstream's default feature set.
- *Promote fixtures to their own crate.* Considered; rejected as overkill for
  ~130 lines, and the feature gate keeps the dependency graph unchanged.

**Consequences.** `ClientSpec` now carries the output `Note` rather than an
`out_value`, because the output's `rho`/`psi` must come from a CSPRNG owned by
the wallet. Deriving them from the spent note's randomness — the obvious shortcut
the first draft took — would make the two notes linkable by anyone who learns one
of them, quietly breaking hiding for every transfer the shortcut touches.

**Security basis.** Single implementation means the e2e path tested is the path
shipped. The `testkit` gate keeps test scaffolding out of production builds.

---

## D-045 — SPHINCS+ envelope is defense-in-depth, not the spend authorization

**Decision.** The SPHINCS+ signature in `ShieldedTransfer` is an **outer
envelope**. It is explicitly *not* what authorizes a spend. The in-circuit
nullifier relation (`nf = H(DOMAIN_NF ‖ sk_d ‖ rho)`, with `pk_d` committed in
the note) is what authorizes.

**Why.** The node cannot verify that a revealed SPHINCS+ verifying key
corresponds to a note's `pk_d`: that relation is `pk_d = H(sk_d)` with `sk_d`
secret, and no public function of the verifying key yields it. Making the
binding cryptographic is precisely what in-circuit SPHINCS+ (ticket 10) buys.
Until then the envelope is defense against a *misbehaving wallet*, not a
replacement for the circuit's binding. Stating this in the module doc rather
than glossing it, because a reader who assumes the envelope authorizes the spend
would be wrong in a way that matters.

**What the envelope does buy:**
1. Junk stops at the mempool door — one signature check before any proving CPU.
2. Non-repudiable provenance for submission.
3. The seam ticket 10 closes cryptographically, with the wire format unchanged.

**The signed message** is a domain-separated, length-prefixed encoding of the
public statement (`DOMAIN_TX ‖ counts ‖ digests ‖ roots ‖ fee`), including both
roots so a transfer re-broadcast against different state is a different message.
Injectivity is tested directly: one 64-byte nullifier vs two 32-byte nullifiers
must not collide, which is exactly what the length prefixes buy.

**Alternatives considered.**
- *Sign only the nullifiers.* Rejected: an output or fee could be swapped.
- *Skip the envelope until ticket 10.* Rejected: no mempool DoS protection in
  the interim, and the wire format would have to change later anyway.

**Security basis.** Honest about what is and is not proven. The security story
does not claim more than the cryptography delivers.

## D-046 — HVZK blinding is live: three masks, pooled budget, and the σ^h factor

**Decision.** Honest-verifier zero knowledge is turned on end to end: the WHIR
PCS reports `ZK = true`, every witness commitment is masked, and the verifier
(in Rust now, Solidity later) verifies the hiding shape. This is not optional in
this design — a shielded pool whose proof leaks the witness shape is not
shielded.

**The gap that was closed.** `ZK` was hardcoded `false` in the
`UnivariateStarkPcs` impl, so every blinding branch in uni-stark and
batch-stark was dead code, and the recursion backend additionally rejected
`is_zk != 0` outright at `preflight_whir_context` /
`preflight_trusted_whir_batch`. Both rejections removed; the flag is now true
and the branches are exercised.

**The three masks** (all in
`vendor/p3-recursion/recursion/src/pcs/whir/uni/pcs.rs`), matching
Haböck & Kindi, *A note on adding zero-knowledge to STARKs*
(<https://eprint.iacr.org/2024/1037>) §4.2:

1. **Trace interleave.** Each witness matrix is committed with a random
   companion row interleaved (`with_random_cols` reinterpreted at the
   original width), doubling the committed height. Half the codeword is
   uniformly random.
2. **Quotient chunk masking.** With the Lagrange decomposition
   `q = Σ_i L_i · q_i` (paper eq. 11–12), each chunk is replaced by
   `q̂_i = q_i + v_{H_i} · t_i` for random `t_i` (eq. 13), except the last,
   which is `q̂_d = q_d − v_{H_d} · Σ_{i<d} (c_d⁻¹ c_i) t_i` (eq. 14). The
   recomposition still holds because the extra term is
   `(Π_j v_j) · Σ_i c_i t_i ≡ 0` (eq. 15).
3. **Randomization polynomial R.** A fully random polynomial per instance,
   committed *before* the trace challenge, opened at ζ. The verifier binds it
   through the `random` commitment slot; the STARK's OOD check is against
   `q + R` rather than `q`.

**The bug that ate a day: the σ^h factor.** The mask initially failed with
`OodEvaluationMismatch`. The cause is a vanishing-polynomial convention
difference. This codebase's `vanishing_poly_at_point` is the *normalized*
`v_{gH}(X) = (X/g)^h − 1` (p3-commit `domain.rs:316`), not the
unnormalized `X^h − σ^h`. They differ by the constant `σ^h`:

    X^h − σ_i^h = σ_i^h · v_{H_i}(X)

The mask is applied in the unnormalized form, so the polynomial that actually
enters the paper's identity is `t_i = σ_i^h · T_i`, not `T_i`. The paper's
cancellation condition is `Σ c_i t_i = 0`, so the compensation weights must
carry the ratio `σ_i^h / σ_d^h`:

    mul_i = c_i / c_d · σ_i^h / σ_d^h

Dropping the σ^h leaves a residual `P(X) · Σ c_i σ_i^h T_i` in the
recomposed quotient, which the verifier sees as an OOD mismatch at the first
instance. With the ratio in place the identity closes exactly.

**Lesson recorded.** When porting a paper's mask math into a library, check
the library's vanishing-polynomial normalization *first*. The paper writes
`v_H` abstractly; the library's `v_H` carries a `g^{-|H|}` factor, and every
place the two meet needs the constant tracked.

**Pooled hiding budget, not per-matrix.** The first budget check was per
matrix and rejected legitimate batches: a 1×4 public-input matrix riding in
a 16384-row batch has no randomness of its own but is hidden by the batch.
Hiding is a property of the single *stacked* polynomial the commitment
binds, so the budget is checked once per commitment over
`Σ height × width` of the batch. Same for the R round, whose per-instance
matrices commit as one batch. The rule is paper eq. (17):

    2 · (e · n_F + n_D) ≤ h ≤ |H|

implemented as `required = (EF::DIMENSION · points + query_margin) * 2`
against the pooled random-cell count, where `query_margin` is the WHIR
schedule's actual query count at the *stacked* arity (not the security
level, which over-counts and rejected small-but-legal commitments).

**The quotient's hiding is inherited.** The quotient polynomial is computed
from the already-masked trace, so its off-domain coefficients are already
random; the chunk check is a minimal guard, and the real budget was paid at
trace-commit time. This is why masking the trace buys hiding for the whole
proof and the chunk masks are what make the *quotient's* randomness
independent of the witness.

**Arity slack: 2, with backoff.** Blinding doubles the committed height and
the witness width contributes one more stacked variable, so the grinding
budget must be read at `log_max_lde + 2`, not `log_max_lde`. KoalaBear's
folded-domain capacity caps the stacked arity at 27, so the top of the
supported range (`log_max_lde = 26`) overflows the *requested* arity.
`required_pow_bits` now backs off to the largest feasible arity instead of
failing. This is safe: the budget is an upper bound on what any *feasible*
commit demands, and an arity above the capacity cannot be committed at all,
so there is nothing to under-provision. Verified monotonic: requests ≥ 27
all return the budget at 27.

**Cost.** Paper's model: `C_zk / C_non-zk ≈ 1 + 4 / log|H|` per witness
column. At our block arity (25) that is ~16% proving cost for full witness
hiding. Accepted without hesitation.

**Verification status.** 46/46 prover tests and 279/279 recursion lib tests
green with all three masks live. The vendored unit tests were updated to the
masked semantics: they now assert that the witness survives in the *even*
rows of the committed codeword and that the masked chunk interpolates to the
original chunk evaluations on its own coset (the mask vanishes there) — the
strongest statements that survive blinding.

**Still open (tracked).** The recursion *circuit* must bind the R round:
`recursive_pcs.rs` still carries `NO_RANDOM_OPENED_VALUES` with a comment
claiming no WHIR variant splits off random codewords. That comment is now
false and the target-side mirror of the R openings must be implemented
against `pcs/fri/targets.rs`. Until then the recursion circuit does not
bind the hiding proof's random round, and the Solidity verifier must verify
the R commitment and its openings as well.

---

## D-050 — Settlement Merkle tree is byte-native Keccak-256; do NOT port Keccak-f[1600] to Solidity

**Status.** Supersedes the plan recorded earlier in this session (and implied by
the D-036/D-038 gas discussion) to keep `PaddingFreeSponge<KeccakF, 25, 17, 4>`
and replay that permutation on-chain. Implemented and green as of this commit.

**Decision.** The settlement MMCS is

```text
  MerkleTreeMmcs<F, u8,
                 SerializingHasher<Keccak256Hash>,
                 CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
                 2, 32>
```

i.e. leaf = `keccak256(concat of 4-byte LE `to_unique_u32` limbs)`, node =
`keccak256(left || right)`, digest = 32 raw bytes. Both are the plain EVM
opcode. The Rust side changed; the Solidity side gained no hash code at all.

**Why the earlier plan was wrong.** The two Keccacs in this stack are not the
same function. The transcript already uses `Keccak256Hash` (FIPS-padded,
opcode-replayable, pinned by `TranscriptReplay`). The commitment tree used
`PaddingFreeSponge<KeccakF, 25, 17, 4>` over u64 lanes, which shares the
Keccak-f[1600] permutation but is NOT Keccak-256: no `0x01..0x80` padding,
u64 lane order, 4-lane squeeze. Replaying it means hand-rolling the
permutation in Solidity at roughly 30-50k gas per call. At round 0 the
schedule asks for ~170 queries over ~22 levels, so a few thousand compressions
even after pruning: 80-120M gas, over the block limit. Opcode-native is ~250
gas per node, so the same walk is under a million.

**Alternatives considered.**

1. *Port Keccak-f[1600] to Solidity, keep Rust unchanged.* Rejected. It is the
   only option that preserves the Plonky3 default, and it costs the block gas
   limit. It also makes D-039 chunking-in-time load-bearing for a reason that
   has nothing to do with proof size.
2. *Reuse vendored `sol-whir-p3` `MerkleVerifier.sol`.* Rejected on
   incompatibility, not preference: it hashes `keccak256(0x00 || BE32(v)...)`
   for leaves, `0x01`-prefixes internal nodes, and masks digests to 20 bytes.
   Three independent mismatches, each silent.
3. *SHA-256 like `plutus-plonky3-exploration`.* Rejected. Cardano has a
   SHA-256 builtin; the EVM has no SHA-256 precompile that fits this use (the
   `0x02` precompile is 60 + 12/word and takes a length-prefixed word array,
   and it is the wrong hash for a Keccak transcript anyway).
4. *Switch the transcript to SHA3-256 too.* Rejected, already decided
   (D-002/D-040): SHA3-256 has no EVM precompile at all.

**What made this cheap.** The type-level probe: `MerkleTreeMmcs<F, u8, ...>`
typechecks against `WhirUniPcs` and the settlement challenger with no other
change, because `SerializingChallenger32` already has
`CanObserve<MerkleCap<F, [u8; N]>>` (serializing_challenger.rs:102) which
absorbs digest bytes directly. So the byte-native cap is absorbed byte for byte
and the cap Solidity pins is the cap the transcript bound. No adapter, no
new trait impl.

**Consequences, all verified.**

- `contracts/src/verifier/StarkMerkle.sol` is the whole on-chain commitment
  layer: a leaf codec plus a variable-depth fold. No permutation, no sponge.
- The STARK tree and the shielded note tree now share one fold. `MerkleProof`
  (fixed depth 32, `bytes32` leaves) and `StarkMerkle` (depth from the path,
  hashed rows) agree byte for byte; `StarkMerkleTest` asserts that directly so
  they cannot drift.
- `crates/prover/tests/mmcs_vectors.rs` generates ground truth from the real
  `MerkleTreeMmcs` and *searches* all four fold conventions (leaf-to-root vs
  root-to-leaf x sibling-left-on-one vs on-zero), requires exactly one to
  reproduce the committed cap, requires it to be the same at every index, and
  then requires it to be the one `MerkleProof.sol` implements. The convention
  is pinned by proof rather than by reading Plonky3 source.
- Every digest in that generator is cross-checked between `p3-keccak` and
  `tiny-keccak` (via `pq_hash::Keccak256Commitment`). If those ever diverge,
  nothing on-chain means anything, so the assert belongs in the generator.
- Vendored `sol-whir-p3/merkle/MerkleVerifier.sol` and `whir/WhirStructs.sol
  deleted: zero importers, and their prefix/mask convention is a trap for the
  next person. The three vendored files we DO import remain byte-identical to
  upstream so they stay diffable.
- `spike::commitments_are_keccak_sized` now asserts 32 bytes, not 4 limbs.

**What this does NOT change.** The recursion layer stays Poseidon2 with a
field-native cap (`whir_recursion.rs`), because `WhirRecursionBackend` is
bounded to `MerkleCap<Val, [Val; DIGEST_ELEMS]>` and a byte cap cannot satisfy
that bound in-circuit. The two layers never meet inside one circuit, so the
settlement layer can be byte-native while the inner layer is field-native.
The `DIGEST_ELEMS` doc in `whir_recursion.rs` is updated to say 32 bytes.

**Open cost.** Digest width went 4 limbs -> 32 bytes, so Merkle proofs in the
proof payload are the same 32 bytes per node (they were already 32 bytes on
the wire) but the *cap* is now 32 bytes per root instead of 4 packed limbs.
At cap height 0 that is one 32-byte root, absorbed as 32 bytes instead of 16.
The measured proof sizes in `prover_bench` reflect the new scheme.

---

## D-051 - HVZK blinding is enforced at compile time; three measured floors

**Status.** Implemented and green. Answers the standing instruction "ensure we
only use hvzk whir zk blinding enabled".

**What was already true.** The vendored recursion carries `const ZK: bool = true`
on `WhirUniPcs` (`recursion/src/pcs/whir/uni/pcs.rs:949`), patch item 1 of
`vendor/p3-recursion/PATCHES.md`. Both layers use that same PCS type, so both
were already hiding. What was missing was ENFORCEMENT: nothing failed if an
upstream bump or a re-vendor flipped it back to false.

**Decision - enforce with `const` asserts in the shipped lib.**
`crates/prover/src/lib.rs` gained a private `zk_guard` module with two
`const _: () = assert!(<Config as StarkGenericConfig>::Pcs::ZK)` checks. `ZK` is
an associated const, so this is a compile-time fact: flipping it makes the crate
fail to COMPILE. A test only fires when someone runs it; for a shielded pool,
"could not build" is the guarantee we want. `ZK` is an item of
`p3_commit::UnivariateStarkPcs`, so that trait must be in scope to name it -
imported inside the module with `as _` to avoid widening the root namespace.

**Runtime half** (`crates/prover/tests/hvzk_blinding.rs`, 3 tests) covers what a
constant cannot prove:
- the proof carries `commitments.random` and `opened_values.random`, they are
  non-empty, and at least one opened random value is non-zero - separating
  "blinding compiled in" from "blinding allocated zeros and never sampled";
- two proofs of the SAME statement produce different commitments - the only
  check that catches a fixed RNG seed, since reproducible masking is worthless
  while passing every single-proof assertion;
- the full two-layer path builds and settles over a blinded base proof, and the
  statement binding still rejects a tampered statement afterwards.

**Finding 1 - blinding randomises the TRACE commitment, not just R.** The
assertion "same trace must give the same trace commitment" FAILED: two proofs of
one statement had different `commitments.trace`. Cause: the patched `commit`
folds the mask rows into the committed matrix, so the mask lives inside the
Merkle tree. This is a BETTER property than the one asserted - two proofs of the
same statement are unlinkable at the commitment level, not only at the opening
level - so the test now asserts the difference. Consequence for the node: a block
cannot be identified by its trace commitment, and any prover-side caching keyed
on trace commitment would be unsound.

**Finding 2 - a hard floor on base-proof size for recursion.** Settling a
256-row base proof fails with `num_queries (182) >= folded_domain_size (128);
saturating STIR query counts are not yet supported in-circuit`
(`recursion/src/pcs/whir/params.rs:61`). The schedule buys security with queries
while the final folded domain shrinks with the trace, so small traces saturate.
1024 rows works and the recursion tests already use 1024. Deployment rule: the
per-batch AIR must be padded to at least 1024 rows, checked at config build time
rather than discovered at settlement time.

**Finding 3 - the settlement LDE cannot be shrunk to save calldata.**
`crates/prover/tests/recursion_lde_sweep.rs` walks log_max_lde 17..22 over a
real recursive settlement (152624 witnesses, ~2^17.2):

```text
  17..20  PANIC  PowBitsExceedBudget { required: 17, budget: 11..14 }
  21      PANIC  PowBitsExceedBudget { required: 18, budget: 17 }
  22      ok     2.13 s prove, 8.19 ms verify, 676708 bytes
```

So 676 KB is a FLOOR for this circuit, not slack to tune away: grinding needs
17-18 bits and only log_max_lde 22 leaves room for them. Two secondary notes:
the failure is a PANIC from an `unwrap` in the vendored prover rather than an
`Err`, so the sweep needs `catch_unwind` just to map the boundary; and proof
bytes are non-deterministic run to run (676580 vs 676708) precisely because of
finding 1.

**On the `NO_RANDOM_OPENED_VALUES` stub (D-046 open item): NOT a hole for WHIR.**
`get_fri_random_opened_values` is only consulted when
`PRE_OBSERVES_OPENED_VALUES` is true (`verifier/batch_stark.rs:1528`), and WHIR
sets it false (`pcs/whir/uni/recursive_pcs.rs:384`) because WHIR interleaves its
own opened-value observation. The R commitment IS bound in-circuit by the normal
path: `batch_stark.rs:1275-1317` observes `random_commit` into the challenger and
pushes it into `coms_to_verify` with its own opening points. Patch item 2 in
PATCHES.md is stale bookkeeping and should be dropped from that list, not
implemented.

**Correction to the record.** Commit 9ffd9ed originally claimed the suite ran
unoptimised. Wrong: `.cargo/config.toml` sets `[profile.dev] opt-level = 3` with
`[profile.test] inherits = "dev"`, so tests have always been optimised. Measured
effect of `--release` (thin LTO + codegen-units=1) at 2^22 rows: 10.8 s vs 13.4 s
prove. The commit message was reworded.

**Numbering note.** This file has two ordering eras: D-047/048/049 already
existed at the top (reference synthesis, sumcheck fold, SumcheckCore limbs), so
the two entries added in this session were numbered D-050 (byte-native Keccak
settlement tree) and D-051 (this one). Code comments citing the Keccak switch
were updated from D-047 to D-050; `fixed_config.rs` keeps its D-047, which
legitimately means the reference synthesis.

---

## D-052 - Golden vectors were self-rewriting; add an always-on currency check

**Status.** Fixed and green, with the fix itself tested by mutation.

**The defect.** `crates/prover/tests/golden_vectors.rs` documents itself as
"Ignored by default on purpose... a change shows up as a reviewable diff", but
none of its three generator tests carried `#[ignore]`. Every `cargo test` run
therefore REWROTE three checked-in fixtures - `field_vectors.json`,
`transcript_vectors.json`, `block_vectors.json` - and the generated
`contracts/test/TranscriptReplay.t.sol`. A test that regenerates its own
expectations cannot fail, which is exactly the property the anti-drift design
depends on. It also meant a real transcript or statement change would be
silently absorbed into the JSON instead of showing up as a reviewable diff.

**How it was noticed.** `git status` showed the vector files modified after a
plain workspace test run, with no edit to any generator.

**Decision - split generation from validation.**
1. The three generators now carry `#[ignore]`, matching the module doc that
   already claimed they did. Regeneration stays deliberate, so the diff is
   reviewed.
2. New always-on test `golden_vectors_are_current` READS the fixtures and
   re-derives their deterministic content from the current code: the modulus
   and Montgomery R, the field value table, the transcript program, the derived
   alpha/zeta, the validity of the recorded PoW witness, and the block
   statement plus its Montgomery transcript words.
3. The block statement is re-derived WITHOUT proving, via
   `fixtures::public_and_witnesses_from` + `build_transfer_circuit`, so the
   check costs milliseconds instead of a proving run.
4. `BlockFixture` is now the single definition of the block fixture, shared by
   the generator and the check. Two copies of a fixture is how a vector ends up
   describing a transfer the prover would never produce.

**What the check deliberately does NOT pin.**
- The PoW witness VALUE. `HashChallenger::find_witness` searches candidates in
  parallel batches and returns the first hit with `find_map_any
  (p3-challenger hash_challenger.rs:277)`, so which candidate is returned
  depends on batch layout and is not stable across builds. Its VALIDITY is
  stable, and validity is the assertion that matters - it is the same assertion
  the generated Solidity test makes with its own `checkWitness`.
- Proof bytes or proof length. HVZK blinding folds the mask into the committed
  trace (D-051 finding 1), so two proofs of one statement differ at the
  commitment level by design. Pinning them would fail for a reason that means
  nothing, and a test that fails for no reason gets deleted.

**Side effect worth recording.** The stale fixture proved it: HEAD pinned
`witness_canonical: 532676624` while current code grinds to 7 with an identical
pre-grind state (alpha and zeta unchanged). The committed vector had already
drifted and nothing objected. The regenerated fixtures were re-verified on-chain
(`forge test` on `TranscriptReplay.t.sol` passes against them).

**The fix is tested by mutation.** Four independent corruptions of the fixtures
- a statement limb, a challenge value, an invalid PoW witness, and a `pow_bits
  mismatch - each made `golden_vectors_are_current` FAIL, and it passes again
once restored. A guard that cannot fail is not a guard.

## D-053 - The labelled WHIR transcript is a RECORDED byte program, not a Solidity port

**The problem.** p3-whir 0.8.0 does not drive a bare sponge. It drives
`WhirVerifierTranscript` over a `DomainSeparator` (Spongefish style, IETF
draft-irtf-cfrg-fiat-shamir): a versioned, named, labelled transcript whose seed is

    [protocol_id(64) | pattern_hash(32) | label_len_be(4) | label | 0x80]

packed three bytes per field element behind a length element, with every later step
absorbing a label before its payload. None of that ordering is published as a spec -
it is upstream control flow. A verifier that absorbs the same SET of values in a
different order, or that skips the seed, derives completely different challenges
while looking entirely correct in review.

The only transcript test we had pinned a SYNTHETIC flat program (four observes, two
samples, a 4-bit grind). It passed while the real protocol was unpinned. That is the
gap this closes.

**Options considered.**
1. Port p3-challenger's `fs` pattern machinery (patterns, labels, protocol ids,
   FieldUnit packing) to Solidity and run the labelled transcript natively.
   Rejected: roughly a thousand lines of upstream machinery whose only job is to
   produce a byte stream, and every line of it becomes ours to defend. It also
   cannot be validated against anything except the Rust it imitates, which is the
   circularity D-053 is about.
2. Transcribe the absorb order from reading the Rust source and hardcode it.
   Rejected, and it would have been WRONG: reading p3-whir's source says the
   separator is version 3, name "p3-whir". The seed recorded from a real verify
   decodes to version 1, name "p3-uni-stark" - uni-stark wraps WHIR as a
   sub-transcript, so the OUTER transcript is uni-stark's. A verifier written from
   the reading would have absorbed the wrong protocol id.
3. Record the program from the real verifier and replay it on both sides. CHOSEN.

**The method, and why recording the VERIFIER is the load-bearing choice.** Prove
with the PRODUCTION config, then verify with a TRACED config whose only difference
is the challenger type. If splicing the recorder into the challenger perturbed the
transcript by even one byte, the challenges would desynchronise and verification
would fail. So a green run is itself the proof that recording did not change the
protocol. Recording the PROVER instead carries no such guarantee - a prover and a
verifier can disagree in ways a prover-only run never notices. This is the method
GOATNetwork/bitcoin-stark-verifier uses, and their stated reasoning is the reason it
is the right one: every other test compares a script against a Rust reference, which
establishes that the two agree, not that either is correct.

`Proof<SC>` is keyed on SC and SC names the challenger type, so `Proof<Config>` and
`Proof<TracedConfig>` are distinct Rust types. They bridge through
`postcard::to_allocvec` + `from_bytes`, which doubles as evidence that the wire
format is config-agnostic - exactly what the chain relies on.

**What is pinned.** `crates/prover/tests/whir_transcript_vectors.rs` records 6895
events from a real 16-variable / 1024-row verify. Four always-on tests: the replay
(4131 recorded squeeze bytes reproduced from a fresh sponge), the seed STRUCTURE
(version byte, protocol name, zero padding, label length, 0x80 terminator - asserted
as decoded structure so an upstream change reports as "the version byte moved"
instead of thousands of mismatched bytes), a corrupted-seed test (diverges at event
100), and a dropped-absorb test (diverges at event 99). The generator is `#[ignore]`d
per D-052.

`contracts/test/WhirTranscriptReplay.t.sol` replays the same vector on the vendored
Keccak sponge. Rust agrees with the vector, Solidity agrees with the vector,
therefore Solidity agrees with Rust - with neither implementation serving as the
other's reference.

**Byte order, verified not assumed.** p3 `HashChallenger::sample` pops from the END
of a 32-byte output buffer, so a caller receives digest[31] first. The vendored
`_sampleUint32` consumes the block from its low end and the low byte of a uint32 is
the lowest-addressed byte, so both read digest[31] first. Confirmed by mutation:
reading from the high end makes the Solidity replay fail.

**Vendored patch.** `KeccakChallenger.sampleByte`/`sampleBytes` added
(`contracts/lib/sol-whir-p3/PATCHES.md`). Additive only - no existing function
touched, so an upstream refresh cannot silently change a value the verifier depends
on. The library previously squeezed only field elements, which consume four bytes at
a time and reduce mod the KoalaBear modulus, so it could not reproduce an arbitrary
recorded byte.

**Three mutations confirm the Solidity test bites.** sampleByte consuming 4 bytes
instead of 1: FAIL. Reading from the high end of the block: FAIL. `observeBytes`
forgetting to invalidate the pending output block - the classic sponge bug, and the
one a hand-written verifier is most likely to have: FAIL at squeeze 180.

**The constraint this buys, and pays.** A recorded program is sound only while the
config is fixed: security level, folding factor, arity slack and PoW bits all decide
the schedule, hence the stream. Any config change MUST regenerate the vector. The
vector records num_variables and log_rows so a mismatch is visible, and the replay
asserts the event count. If we later need config flexibility on-chain, the answer is
to generate the label constants at build time from the same Rust recorder rather
than to port the pattern machinery.

**Also fixed on the way.** The event length prefix was widened from 2 to 4 bytes: a
2-byte length silently truncates any absorb over 65535 bytes, and a truncated length
desynchronises every later event into garbage that still parses. Caught while
writing it - `usize::to_le_bytes` is EIGHT bytes on a 64-bit host, so the encoder
and decoder disagreed and the vector decoded as 2 events.


## D-054 - The transcript is an ALGORITHM with constant labels, not a replayable op list

**What D-053 left open.** D-053 recorded the WHIR verifier transcript as a byte
program and replayed it on both sides, and noted the constraint that "a recorded
program is sound only while the config is fixed". That framing was still too
optimistic, and the classifier below is what found it.

**The experiment.** Prove the same AIR shape with several different witnesses and
verify each. An absorb whose bytes are identical across every run cannot depend on
the witness, so it is fixed by the config; an absorb that differs must be carrying
proof data. That split is exactly what a Solidity verifier needs per absorb -
constant in the contract versus read from calldata - and the Rust source does not
state it in a form a verifier author can consume. So it is measured, not read.

To make the witness actually vary, the test AIR had to change: it pinned the first
row to (1,1), so every seed produced one witness. The starting pair is now the
public input, which gives one AIR shape many witnesses.

**The result, and the finding.** The first version asserted the whole event stream
is shape-stable. It FAILED: 6896 vs 6904 events for one statement shape. That is
the protocol, not noise. KoalaBear sampling is rejection sampling - draw 32 bits,
reject at or above the modulus, draw again - so how many draws a squeeze needs
depends on the sponge state, which depends on the proof. The squeeze stream is
proof-dependent in LENGTH as well as in value.

Absorbs are different in kind, and that asymmetry is the useful part:

    absorbs:  2765 events, IDENTICAL schedule across all runs
    squeezes: 4131 or 4135, depending on the proof
    classification: ~1850 config-fixed absorbs (~7400 bytes),
                    ~915 proof-carrying absorbs (~2990 bytes)

**The correction.** The verifier cannot be a replay of a recorded op list, because
the op list is not fixed. It must implement the labelled transcript ALGORITHM, with
the labels as constants and rejection sampling inside the samplers. The recorded
stream stays valuable - it pins the sponge, the byte order and the label ORDER
against a real transcript, which is what D-053 bought and what Solidity now agrees
with - but it is a test vector, not the program.

This does not weaken D-053; it says what D-053 is FOR. Without the recorded stream
we would have no ground truth for the label order, and the reading-based version
would have used the wrong protocol id (p3-whir v3 instead of p3-uni-stark v1).

**What the classifier also settles.** `stratified_queries` is FALSE for our domain
(the trait default, no override), so index assembly takes the identity branch: draw
`num_queries` values of `index_bits` each. That matters because the vendored
sol-whir-p3 sampler draws all bits in ONE call and then sorts and uniquifies - a
different protocol version. Reusing its index layer would have been wrong, and this
is the measurement that says so rather than a judgement call.

**Upstream reuse, decided by layer.** sol-whir-p3 ships a complete, tested
standalone WHIR verifier for KoalaBear + quartic (Ext4) - our exact field config -
with failure fixtures. Their own AGENTS.md states the verifier assumes Keccak with
0x00 leaf / 0x01 node prefix bytes and absorbs a `whirFsPattern` as field elements:
the PRE-labelled whir-p3 transcript, not p3-whir 0.8.0 versioned DomainSeparator.
So the split is:
  - REUSE as a second implementation to cross-check arithmetic: extension-field
    folding, multilinear evaluation, Horner, the row-evaluation kernels.
  - DO NOT reuse: transcript layer, Merkle prefixing (D-050 already rejected it),
    index derivation (different protocol), fixed-config constants.

**Honesty about the artifact.** `whir_transcript_program.json` is a MEASUREMENT
SUMMARY, not a pin. Grinding is nondeterministic, so the constant/variable split
drifts by about one absorb between generations (1849/916 then 1850/915). Nothing
asserts those counts; the assertion that matters is the one that does not drift -
the absorb schedule is identical across runs. A future change that made the absorb
count itself vary would be a real protocol change and would fail.

**Also fixed.** The KoalaBear modulus comment said `2^31 - 2^27 + 1`, which is
BabyBear; the value in the file, 2_130_706_433, is `2^31 - 2^24 + 1`. Checked rather
than transcribed, and the comment now says so, because a wrong modulus makes every
rejection-sampling bound in the verifier wrong.

**Addendum, same ticket - the constructive half.** "Not a replayable op list" is only
half a result; the other half is what IS fixed, and it took one more collapse to see
it. Group the event stream into SITES: a maximal run of squeezes becomes one squeeze
site, absorbs stay single sites. On that view the transcript is shape-stable:

    2847 sites = 2765 absorb sites + 82 squeeze sites
    site kinds and positions: identical across runs
    absorb site sizes:        identical across runs
    absorb byte stream:       identical across runs (10388 bytes)
    squeeze site byte counts: 8 distinct values across runs - the rejection variance

So the verifier is written against the SITE sequence: 82 sampler calls at positions
fixed by the config, each drawing however many bytes rejection sampling needs. That
is an implementable specification, and the test asserts it rather than assuming it.

Two views ship in `whir_transcript_program.json` because they answer different
questions, and conflating them is exactly what made the first assertion fail:
`program` is the run-0 event stream (the fixture - pins sponge, byte order, label
order; Solidity replays it byte for byte), `site_program` is the collapsed view (the
shape; a squeeze site carries its run-0 byte COUNT, not its bytes, because the count
is the shape and the bytes were one proof's luck). A consistency check confirms the
two views agree on totals: 4143 squeeze bytes and 10388 absorb bytes either way.

One more structural fact worth pinning: every absorb is either 1 byte or a 4-byte
field element, never anything else. The labelled layer packs everything through
`FieldUnit`, so labels and field values arrive as 4-byte elements, and a
byte-at-a-time path carries the rest. Event boundaries are therefore a granularity
artifact - one 32-byte digest may appear as one absorb or as 32 - which is why the
byte stream and the site sequence are the assertions that mean something, and a bare
event count is not one of them.

## D-055 - The verifier is generated from a SEMANTIC transcript program, not a byte program

Date: 2026-02-11. Status: ACCEPTED, supersedes the "replay the byte program" half of D-053.

**Problem.** D-053 recorded the transcript as a stream of byte events and D-054 found the
byte stream is not replayable. The follow-up measurement killed the last hope for it: two
recordings of the SAME witness differ at 2 sites, and both are squeeze sites
(`whir_transcript_vectors.rs::assert_absorb_schedule`). A squeeze flushes a partially
filled output buffer, so its absorbed size depends on how much unconsumed output was
pending, which depends on how many rejection samples happened upstream. Rejection sampling
is invisible at the byte level and its footprint is not stable. Byte-level recording is the
wrong level of abstraction.

**Decision.** Record at the PROTOCOL level. `crates/prover/src/semantic_trace.rs` wraps the
production challenger and logs whole operations - observe a base element, observe a
commitment, sample an extension element, sample N bits, sample N uniform bits, verify a
proof-of-work witness - never bytes. `tests/whir_semantic_program.rs` proves with the
production config, ships the proof over postcard, and verifies it through the recorder.
Verification passing IS the proof that the recorder did not perturb the transcript.

**Measured, over 4 independent witnesses - one shape, zero mismatches:**

| quantity | value |
| --- | --- |
| operations | 3551 = 2518 observe_base + 7 observe_bytes + 224 sample + 779 uniform_bits + 23 check_witness |
| run-length encoded operations | **147** (588 bytes as a 4-byte table) |
| observation positions fixed by the config | **1849** (contract literals) |
| observation positions carrying proof data | 676 (read from calldata) |
| extension samples | 224, every run exactly 4, so always the quartic |
| uniform-bit widths | 8, 9, 10, 11, 12 (STIR query indices) |
| witness-check widths | 1 x8, 3 x4, 5 x4, 7 x1, 8 x6 |

The shape is identical across witnesses while the byte stream is not. That is exactly the
property needed: 147 operations is a schedule the contract carries as data, and each
operation is implemented once as an algorithm with a real rejection sampler.

**The trap that found this.** `GrindingChallenger::check_witness` has a trait default of
observe-then-sample-bits, but `SerializingChallenger32` OVERRIDES it to squeeze the output
buffer first, so a proof-of-work candidate is hashed against a digest of the transcript
rather than its pending input. Inheriting the default in the recorder desynced the sponge
and a valid proof failed with `InvalidPowWitness`. Forwarding it fixed the run.

Generalised, this is the rule for any forwarding recorder: **override exactly the methods
the inner type overrides.** A trait default written in terms of other trait methods
composes correctly through a forwarder, because it re-enters the forwarder and each hop
forwards; a default the inner type REPLACED does not, because the forwarder silently
reinstates the generic behaviour. Hence `check_witness` had to be forwarded and
`UniformGrindingChallenger` did not - `SerializingChallenger32` does not override it, so the
default reaches `self.observe` and `self.sample_uniform_bits`, both of which forward. The
asymmetry is invisible in the trait definitions and cost a debugging cycle.

**Alternatives considered.**

- *Replay the recorded byte stream* (D-053 as written). Rejected: not replayable, per the
  squeeze finding, and a verifier that replays a recording proves nothing about transcripts
  it did not see.
- *Derive labels from protocol names.* Rejected: the `label` field is itself a serialized
  pattern of big-endian u32s and the same protocol name carries a different
  `pattern_hash` per phase (`p3-sumcheck-quadratic` differs at all 10 occurrences). Labels are
  measured DATA, not derivable. Still true, and the constant absorbs stay hardcoded data.
- *Byte-level recording plus logged rejection counts.* Rejected: recovers the same
  information by reverse-engineering the sampler, is more fragile than recording the
  operation directly, and couples the artifact to one challenger implementation.

**Consequences.**
- `contracts/test/vectors/whir_semantic_program.json` is the verifier spec. The always-on
  `whir_semantic_program_artifact_has_the_pinned_shape` pins 3551 ops, the 7-way event mix,
  147 RLE runs and 1849 config-fixed values, so the artifact cannot rot silently (D-052).
- The Solidity verifier is GENERATED from this artifact: a 147-entry schedule table plus
  the 1849 config-fixed literals, with the samplers implemented as algorithms.
- The byte-level artifact stays as a sponge cross-check only, never as a program.

## D-056 - Two real bugs in the vendored challenger, found by protocol-level replay

**Status.** Implemented and green. 54 forge tests, 159 Rust tests, clippy clean.

**The parity test did its job.** `contracts/test/WhirSemanticProgram.t.sol` walks
the 3,551-operation semantic program against the vendored `KeccakChallenger` and
asserts every sampled value. It failed on the FIRST sample, and the two bugs it
exposed were both in the vendored library, not in the recording.

### Bug 1 - `observeBase` did not invalidate buffered output

p3 `HashChallenger::observe` starts with `output_buffer.clear()`. The vendored
`observeBytes` reproduced that with `outputIndex = 0`; `observeBase` did not. So
after an `observeBase`, a following sample RESUMED a block squeezed before the
observed value existed. Every sample after the first observe-after-sample was wrong.

Worth naming why this survived: it is invisible from inside the library. No unit
test of the challenger alone can see it, because it only manifests when a sample
follows an observe, which is the shape of the WHIR loop and not of a sampler test.

### Bug 2 - `checkWitness` skipped the squeeze

p3 `SerializingChallenger32::check_witness` is
`if bits == 0 { true } else { self.squeeze(); self.witness_passes(bits, witness) }`.
The squeeze samples and discards ONE byte. In the WHIR flow the output buffer is
always empty there because the round just observed a commitment, so the squeeze
FLUSHES - it folds everything observed so far into a digest - and only then is the
witness appended on top of that digest. Skipping it hashes the witness against the
PREVIOUS digest and rejects a valid proof of work.

This is the same class of bug as D-055: a wrapper that reimplements a method instead
of forwarding it loses whatever the original did sideways. Here the sideways effect
was a flush.

### Canonical vs Montgomery - the asymmetry is correct, not a bug

The first mismatch looked like a sponge bug and was partly a recording bug. The
recorder stored samples with `to_unique_u32`, which is Montgomery form, while the
sponge hands out a raw masked sample whose canonical value IS the transcript output.
Measured: `recorded == canonical * R mod P` for every sample, R = 2^32 mod P.

- OBSERVE is recorded as `to_unique_u32` (Montgomery), because that is literally the
  byte sequence p3 absorbs: `value.to_unique_u32().to_le_bytes()`.
- SAMPLE is recorded as `as_canonical_u32`, because that is the value the transcript
  produced. An on-chain sampler returns the same raw value, so canonical is what lets
  a verifier compare without knowing the Montgomery constant.

Each side is recorded in the form a verifier has to reproduce. Getting this wrong is
a silent 1-of-224-sample class of error, which is what the parity test is for.

### Three independent implementations agree

The Solidity challenger, a pure-Python sponge written from the p3 source (with a
pure-Python Keccak-f[1600] written from the Keccak spec, self-tested against known
digests), and a second Python walk over the JSON event log all reproduce all 224
samples, 779 uniform-bit draws and 23 proof-of-work checks, and reach the same
chaining state. None of the three is the reference for another.

### The full-replay digest is NOT pinnable - pin the config-fixed prefix instead

A first version pinned the chaining state after the whole replay. It broke on the
next regeneration. Measured over three recordings of the SAME witness:

- schedule: byte-identical
- config-fixed constant payload (7,396 B): byte-identical
- variable / sample / uniform / witness payloads: all changed

That is HVZK blinding doing its job - the proof is randomised, so the transcript is
randomised. Pinning a per-proof value makes the test fail every time the vector is
refreshed, which teaches people to delete assertions. So:

- `test_replay_semantic_program` asserts every sampled value IN THE SAME RUN, which
  is the real parity check and needs no pin.
- `test_config_fixed_constants_reach_pinned_state` absorbs only the 1,849 config-fixed
  constants and pins that state. Verified stable across all three regenerations.
  It pins exactly the part a verifier hard-codes: little-endian word encoding in
  `observeBase`, buffer growth, and the flush-chaining rule.

Alternatives rejected:
- Pin the full-replay digest and regenerate it each time. Rejected: a pin that must
  be updated whenever the artifact is regenerated is not a regression test.
- Embed the 7,396 constant bytes as a Solidity literal. Rejected: 7 KB of hex in a
  test file, duplicating an artifact already on disk.
- Keep the blob as hex inside the JSON. Rejected: `vm.readFileBinary` exists, so the
  hex was a second copy of the same 13,570 bytes that could drift from the .bin. It
  HAD already drifted, which is what moved the first pin. The .bin is now the single
  artifact the contract reads.

### Vendoring policy amended

PATCHES.md claimed every patch was additive, "a new function, never a modified one".
That rule is now broken deliberately: a bug against the reference implementation is
not something to work around by adding a correct function next to a wrong one,
because callers pick the wrong one by accident. Patch 2 modifies two functions and
the doc says so, with the replay test named as the guard if an upstream refresh loses
the patch.
