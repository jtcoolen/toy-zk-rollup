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

## D-058 — the gadget layer is pinned against the native function, not a reading of it

`WhirGadgets.sol` ports the five multilinear primitives WHIR composes:
`expandFromUnivariate`, `eqEval`, `selectEval`, `powConstBase`, `powersCombination`,
plus `constraintWeight` / `evalConstraintsPoly`.

**Decision.** The golden file is emitted by calling the p3 functions themselves,
not by reimplementing their formulas in the test:

- `Point::expand_from_univariate`, `Point::eval_eq`, `Point::eval_select`
  (p3-multilinear-util) directly.
- `VariableOrder::eval_constraints_poly` (p3-sumcheck) driven by real `Constraint`
  values built with the public `Constraint::new` / `new_with_existing_claim`,
  holding real `EqStatement` and `SelectStatement` groups, in the order p3-whir
  builds a round constraint: `Statements::Eq` (OOD) then `Statements::Select`
  (STIR). Verified at `p3-whir-0.8.0/src/pcs/prover/mod.rs:345-350` and
  `pcs/verifier/mod.rs:297-302`.
- `p3_field::dot_product` over `shifted_powers` for the powers combination.

**Why.** Every one of these has a convention that reads backwards — big-endian
`expand_from_univariate`, which end of `select_eval` consumes `var` first, whether a
constraint weight starts at `gamma^0` or `gamma^1`. A hand-written expected value
from a misread convention produces a test that agrees with itself. Pinning the
native function makes the vectors independent of my reading.

`eval_constraints_poly` is the load-bearing case: it is the last thing the verifier
computes (`claimed_eval == eval_constraints_poly(...) * eval_multilinear(final_poly,
last_r)`) and it consumes only challenges the transcript already produced, so a
transcript replay cannot see a wrong grouping or power shift. Only this can.

**Both variable orders, both initial powers.** Each case emits four values
(prefix/suffix x fresh/carried). They differ, so a port that ignores
`variable_order` passes two of four and one that hardcodes `initial_power = 0`
passes two the other way. The test also asserts `carried == fresh * gamma` as a
relation between two of the four, which catches a shift applied inside the
combination rather than after it.

**Alternatives considered.**
- *Mirror the formulas in the test.* Rejected: that is a self-consistency check, not
  a cross-implementation one. This is the failure mode the whole port has avoided.
- *Wait and pin the gadgets through a full WHIR transcript replay.* Rejected:
  `eval_constraints_poly` is invisible in the transcript (above), and the other four
  would only fail as one opaque `verify returned false` with no location.
- *Port `gadgets.rs` circuit-by-circuit including its `pow_const_base` constant
  product.* Rejected: that shape exists because a circuit gate is cheaper to keep
  uniform than to special-case. On the EVM `KoalaBear.pow` is a 32-bit
  square-and-multiply loop and cheaper. The vectors pin the value, which is all the
  protocol constrains.

**Incidental findings.**
- `KoalaBearExt4.eq_poly_eval` is already `Point::eval_eq`, so `eqEval` delegates
  rather than duplicating a formula that must agree.
- `var` is a reserved keyword in Solidity; the `selectEval` parameter is `z`.
- A harness shim with 7 parameters overflows the Yul stack inside the ABI decoder,
  with an error naming neither function nor cause. Constraint passed as one
  `calldata` struct instead.
- forge JSON selectors have no length operator, so the vectors carry explicit
  `num_vars` / `num_values` counts next to the arrays they describe.
- A structural assertion written backwards (`square(got[j-1]) == got[j]` instead of
  `square(got[j]) == got[j-1]`) failed while every value assertion passed — which is
  the useful property: pinning a convention structurally disagrees with a wrong
  reading even when the implementation is correct.

Measured: `evalConstraintsPoly` over the 6 cases at 3.17M gas, `constraintWeight`
2.18M — both dominated by ABI decoding across the external shim, not the arithmetic.
Inside the core these are internal calls.

---

## D-060 - The WHIR core takes opening points as inputs, never as blob bytes

**Status**: accepted
**Date**: 2026-10-03
**Depends on**: D-059

### Context

Writing \`WhirVerifierCore.verifyInitial\` required knowing, exactly, which transcript
absorbs are config-fixed bytes and which are proof data. Two premises I had carried
from the earlier transcript walk turned out to be wrong, and both were caught by
evidence rather than by reasoning.

### Finding 1 - a caller-fixed opening point absorbs NOTHING

\`p3_sumcheck::layout::Verifier::add_claim_at\` builds its opening shape with
\`PointSource::Given\`, and the source comment is explicit: *"A caller-fixed point
contributes no step. This description therefore holds no challenge."* Only the
evaluations reach the wire.

I had assumed the opening points were absorbed and tried to mark them as proof data
in the classifier. The generator's own ambiguity guard rejected it - the point words
were not contiguous anywhere - which is what exposed the truth. In production the
STARK layer DRAWS the opening points after observing the commitment, so they are
inputs to the WHIR core in any case. A core that read them from a hard-coded blob
would verify "the proof opens at the points the blob names" instead of "the proof
opens at the points the caller declares": the difference between a bound claim and a
free one.

The single-word VAR absorbs I had earlier labelled "point absorbs" were the
evaluation limbs - which is exactly the set the zero-limb bug was misclassifying.

### Finding 2 - the claimed-eval order is the CONSTRAINT order, not the transcript order

\`layout::constraint(alpha)\` emits concrete-claim equality groups FIRST, then the
virtual block. \`Constraint::combine_evals\` walks groups with a running exponent, so
the combined claim is

    claimed = sum_i evals[i] * gamma^i        i = 0 .. n-1, from gamma^0

over \`[concrete evals..., virtual OOD answers...]\`. The TRANSCRIPT order is the
reverse (virtual claims are registered first). Getting these two confused is
invisible to the sponge - every sample still matches - and only shows up in the
final algebraic identity, so the initial-phase test asserts the combined claim
directly.

Verified numerically against the prover's own \`combine_evals\` output (now exported
as \`initial_claimed_eval\`) before a line of the Solidity dot product was written.
\`initial_eq_group_lens\` is exported too: it is \`[2, 2, 1]\` here - one group per
concrete claim, then the virtual block - and a group of length zero would shift the
powers, so the flat dot product is only valid because no group is empty. The
production shape has the same property; a shape that produced an empty group would
need the shift handled explicitly.

### The schedule is read from the artifact, not hard-coded

The initial phase's constant runs are 54 / 78 / 78 / 169 / 37 words: commitment
separator, one block per concrete claim, the virtual claim plus batching separator,
and the sumcheck's own domain separator. The test reads the run lengths from
\`.fixed_absorb\` rather than embedding them, so a regenerated artifact with a
different shape fails loudly instead of silently absorbing the wrong span.

### Rejected alternatives

1. **Hard-code the run lengths in the test.** The whole point of the artifact is that
   the contract and the prover agree by construction, not by my transcription.
2. **Have the core absorb the commitment.** The STARK layer owns that absorb
   (\`p3_sumcheck::layout::observe_commitment\`); duplicating it here would double-count
   it in the batch transcript. The test absorbs it explicitly to document the
   handover.
3. **Derive the fingerprints from config instead of absorbing bytes.** Rejected in
   D-059 and unchanged; the zero-limb incident is a second data point for why.

### Consequences

- \`WhirVerifierCore.verifyInitial\` is pinned by \`contracts/test/WhirInitialPhase.t.sol\`
  on alpha, the combined claim, the folded claim, and all four reduction coordinates.
- \`initial_claimed_eval\`, \`initial_eq_evals\`, \`initial_eq_group_lens\`,
  \`initial_sumcheck_ca\` and \`initial_sumcheck_cinf\` are new artifact fields.
- A real byte-order bug surfaced on the way: the constant payload is little-endian
  u32, and a 16-bit lane swap is not a 32-bit reversal. \`observeBase\`'s
  \`value < MODULUS\` check is what caught it - a good argument for keeping that
  require rather than trusting the caller.

## D-061 - Prove the settlement batch under a semantic config, not a second config

The contract must verify the outermost `BatchStarkProof`, which means the WHIR proof it
carries must be a real Keccak proof - the transcript the contract replays has to be the
transcript the prover actually ran. The tempting shortcut was to build a second
`StarkConfig` over a purely-abstract challenger and prove twice; that produces a proof
for a transcript nobody verifies.

**Decision**: `SemConfig = StarkConfig<SemPcs, Challenge, SemChallenger>` where
`SemChallenger` forwards every absorb, sample and witness check to the production
`SerializingChallenger32<HashChallenger<u8, Keccak256Hash, 32>>` and only records. The
proof is a genuine Keccak proof, so `verify_batch(&sem_config, ...)` accepts it and the
recorded program is the verifier's real byte stream. The relation is unchanged: the
settlement preprocessors depend only on the base field and the AIR builders and table
provers are generic over `SC`, so `settle_sem` replicates `settle_recursion_circuit`
line for line with only the config swapped.

**Rejected**: rebuilding `CircuitTableAir` over a second config from the production
`CircuitVerifier`. Rejected because the proof and the verifier would then disagree about
which config's transcript they speak, which is exactly the class of bug that survives to
mainnet.

## D-062 - Program equality is the correctness criterion for the batch transcript

Reading `verify_batch` and re-implementing its phase order is a transcription, and a
transcription can silently reorder one absorb.

**Decision**: the test runs the real `p3_batch_stark::verify_batch` under the semantic
config (program `P_native`) and a hand-driven phase-by-phase replay (program
`P_manual`), and asserts the two event streams are identical, event for event. A missing,
extra or reordered absorb or draw diverges the streams, so the contract's phase sequence
is the verifier's sequence by construction. Measured: 29,902 events, identical.

**Consequence**: `manual_replay` in the test is the specification `BatchTranscript.sol`
is written from, and it is checked against the library rather than against my reading of
it.

## D-063 - The bus layout is trusted-setup metadata, recomputed on-chain

The per-lookup LogUp challenge pairs are not drawn from the transcript; they are
computed as `prefix[bus] = alpha + (bus + 1) * beta^W` from two drawn challenges and a
bus layout that comes from the AIRs. Shipping the pairs in the proof would let a prover
hand the contract a layout that matches its own claim rather than the circuit's.

**Decision**: the artifact exports per-instance bus ids, `max_message_width` and
`next_bus` as trusted-setup metadata. The Solidity test recomputes `gamma = beta^W` and
every prefix from `alpha`, `beta` and the bus ids and checks them against the exported
pairs. The settlement shape has exactly one global bus (`next_bus = 1`, `W = 5`), so the
recomputation is cheap: one iterated power and one addition per lookup.

**Rejected**: exporting the pairs as proof data and trusting them.

## D-064 - Opening points are inputs, never blob bytes

Unchanged from D-060 and reconfirmed by the export: the opening argument's points (zeta,
zeta_next, the quotient chunk domains) are derived from the public statement and the
drawn challenges, so they are computed by the contract, never absorbed as constants.
The artifact exports them for cross-checking only.

## D-065 - Blob format v2: a constant-commitment op and a 4-byte uniform op

Two facts about the batch layer broke the v1 format:

1. The **preprocessed commitment is genuinely config-fixed**. A batch with preprocessed
   AIRs commits the same matrices in every proof, so classification finds the digest
   identical across runs - and it is not even present in `BatchProof`, so the contract
   must carry it as a literal. v1 asserted commitments were always proof data and errored.
2. **WHIR query indices are drawn at the full LDE domain width** - 21 bits at
   `log_max_lde = 22` - and v1's uniform payload was 2 bytes.

**Decision**: add `OP_CONST_COMMITMENT = 6` (digest read from the constant payload) and
`OP_UNIFORM_BITS_32 = 7` (4-byte big-endian word), and bump the format version to 2.
Additive ops would have left v1 streams byte-identical, but a v1 reader would misparse a
v2 stream, so the version moved and all three artifacts were regenerated. The version
field exists precisely so a reader can refuse a stream it cannot parse; using it is the
point of having it.

**Rejected**: widening the uniform payload in place (silently misaligns v1 readers), and
encoding wide draws as several 2-byte words (splits one logical draw across schedule
entries for no benefit).

**Incidental fix**: `SemanticBlob.countDigests` counted schedule *entries* rather than
*runs*, so any blob whose commitment runs merged under run-length encoding under-sized
the recorded digest array and the walk panicked out of bounds. The batch blob (21 proof
digests in 22 runs) exposed it.

## D-066 - The AIR constraint program is trusted-setup data, exported as a flat op DAG

The settlement AIRs are generated by the prover (Poseidon2, recompose and statement
table circuits), so their constraints cannot be hand-written in Solidity. They are
fixed by the circuit, like the bus layout (D-063): the verifier descriptor already
reconstructs the AIRs from trusted metadata, so the constraint program is trusted
setup too.

**Decision**: export each instance's symbolic constraints from Rust as a post-order
op list over a fixed leaf/op alphabet (19 codes: base/ext constants, main local/next,
preprocessed local/next, permutation local/next, permutation challenges, permutation
values, public values, periodic columns, the three selectors, and add/sub/mul/neg),
plus the roots in emission order - the order the verifier's Horner fold walks. The
Solidity side is a stack machine over that list. Flat arrays throughout, because
`forge-std`'s `parseJsonUintArray` cannot express nested arrays; `num_chunks` is
exported as a scalar for the same reason.

**Rejected**: hand-porting the six AIRs (they are generated and will change with the
circuit), and emitting Solidity source per circuit (regenerating and recompiling
contracts per circuit change is worse ops than shipping a data file the existing
verifier reads).

**Measured**: 7,361 flattened nodes across the six settlement instances (largest
instance: 5,085). The symbolic builder clones `Arc`s instead of sharing them, so
pointer-identity memoization dedupes leaves but not shared subtrees - a naive
expansion would emit 22,083. Hash-consing the export is an M8 size lever.

## D-067 - Real selectors with four extension inversions per instance, not a star fold

The M6 plan proposed clearing the selector denominators inside the fold: substitute
`is_first -> zh*s2`, `is_last -> zh*s1`, `is_transition -> s2` and claim the star
fold equals `acc * s1 * s2`, removing every runtime inversion.

**That is unsound.** A constraint with no selector has denominator 1, so the
per-constraint star/real ratio is not the common factor `s1*s2`; no single factor
can be pulled out of the alpha fold. Caught while writing the pin, before any
contract depended on it.

**Decision**: evaluate the real selectors. `zh`, `s1 = u-1` and `s2 = u-h_inv`
depend only on `zeta` and the domain, never on a constraint, so the whole constraint
layer pays exactly three extension inversions per instance plus one for
`inv_vanishing` - 24 inversions for the six-instance settlement batch, shared by
every constraint. If those show up in the M8 gas profile, the fix is Montgomery's
trick (batch the four inversions into one), not a different identity.

The quotient recompose is genuinely inversion-free at runtime: its denominators
`Z_j(first_i)` are domain-only constants, so the export ships
`invD_i = (prod_{j!=i} Z_j(first_i))^-1` and each chunk domain's `inv_shift`. The
Rust test asserts this reformulation equals `recompose_quotient_from_chunks` before
pinning the identity, so the trusted constants cannot silently drift.
