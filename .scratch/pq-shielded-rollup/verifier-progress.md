# Solidity WHIR verifier — progress log (living document)

> Revised as I go. Corrections are kept as "CORRECTION" notes rather than
> deleted, so the reasoning trail stays auditable.

Governing instruction: finish the Solidity verifier, then benchmark gas, check
EIP-170 bytecode limits, and address them borrowing design from
`plutus-plonky3-exploration` and `bitcoin-stark-verifier`.

## Milestones

| # | Milestone | State |
|---|-----------|-------|
| M1 | Proof codec + Merkle + STIR fold + sumcheck primitives | done |
| M2 | Initial phase port (`verifyInitial`) pinned to the prover | done, committed `93fbec3` |
| M3 | Per-round phase port (`verifyRound`) + prover-pinned test | done, committed `ea6ae3e` |
| M4 | Final phase port (`verifyFinal`) + prover-pinned test | done (this commit) |
| M5 | Batch STARK transcript layer: prover-pinned replay of `verify_batch`'s sequence | done (this commit) |
| M5b | `BatchTranscript.sol` production contract, pinned by the M5 vectors | done (this commit) |
| M6 | `ConstraintIdentity.sol` (generated AIR constraint identity) | done (this commit) |
| M7 | `ChunkVerifier.sol` (multi-transaction sponge carry) | done (this commit) |
| M8 | Gas benchmark + EIP-170 audit + size reductions (see D-068 reference list) | audit done; reductions deferred |
| M9 | Wallet extension, local-chain settlement E2E, metrics/dashboards | pending |

## M3 — DONE

Key correction found by pinning (kept because it is load-bearing):
- The round loop carries the **folded** claim, not the pre-fold sum.
  `verify_rounds` mutates `claimed_eval` in place inside
  `delegate_initial_fold`, and native hands the *mutated* value to round 0.
  The harness first exported the pre-fold value, which shifted every round
  checkpoint by exactly `folded - prefold` — and nothing caught it except the
  Solidity comparison, because `verify_rounds` folds the claim forward without
  validating the sum. Only the terminal identity does. The Solidity port was
  right; the export was wrong.
- `StirOpenings.openAndFold` now accepts both row shapes: extension rows (4
  limbs/element) and base rows (1 limb/element, pre-lifted). Round 0 opens the
  trace itself, which is base-field.
- `expectRevert` cannot observe a revert inside an inlined library call (same
  call depth); the round test wraps the call in an external harness contract.

## M3 — original notes

Done this step:
- Rust harness (`crates/prover/tests/whir_proof_vectors.rs`) now exports every
  checkpoint the round loop needs: per-round claimed/folded claims, folds, OOD
  answers, PoW witnesses, sumcheck {0,1}/{inf} pairs, opened rows (base limbs
  round 0, packed ext later), `round_params`, and per-query Merkle auth paths
  rebuilt with `restore_and_recompute_paths`.
- Explicit `counts.*` keys for every array the Solidity side walks (forge JSON
  selectors have no length operator).
- `MASKED:` debug aids removed from the harness.
- `WhirVerifierCore.verifyRound` written: shape checks first, then commitment →
  OOD point/answer pairs → PoW → uniform-bit indices → open+fold vs the
  PREVIOUS root → round batching draw → gamma-weighted claim fold (carried
  claim at gamma^0) → round sumcheck.
- Artifact regenerated; shape confirmed: 1 round, 75 queries, path depth 8,
  `round_params = [[7, 8, 1, 0]]`, `pow_bits = 0`.

Blockers / open items:
- `WhirInitialPhaseHarness` passed `bytes memory` to `Vm.parseJsonUint`, which
  takes `string calldata`. CORRECTION: forge-std's JSON parsers are string
  based (`vm.readFile` returns `string`), so the harness takes `string memory`.
- Round test must hand the transcript the constant payload for runs 0..7 (runs
  0-4 initial phase, 5 round sumcheck separator, 6 final sumcheck separator),
  because the cursor walks one payload in order. (Already applied.)

## Observations worth keeping

- `restore_and_recompute_paths` wants `opened_values` indexed **per query**
  (`[query][matrix]`), not per matrix. `WrongBatchSize{expected: 75, got: 1}`
  was the tell.
- `json!` outgrew the default recursion limit once the document passed ~40 keys;
  `#![recursion_limit = "256"]` at the top of the test file fixes it.
- Dropping an unfinished `VerifierState` panics and MASKS the real error; the
  only reliable workaround is to print inside `map_err` before returning.
- Round 0 folds opened rows at the INITIAL sumcheck's reduction point, not at
  any round's. `prev_randomness` starts as `Some(initial_randomness)`.
- `WhirDomain::query_point` is a trait method: needs the trait in scope and
  full disambiguation `<Dft as WhirDomain<F, Challenge>>::query_point(...)`.
- `log_folded_domain_size` does double duty: query-index bit width AND Merkle
  depth (`height = domain_size >> folding_factor`). One number, both uses.
- Zero-difficulty sites absorb nothing, so a nonzero witness there must be
  pinned to zero by an explicit check (`NonCanonicalPowWitness`).
- The WHIR transcript's step labels steer the sampler's hierarchy; they are not
  appended bytes. Between the round commitment and the round sumcheck separator
  there is no constant run at all (verified against the semantic blob).
- forge-std `Vm` JSON cheatcodes take `string calldata`, not `bytes`; the
  library-side cheatcode address trick (0x7109...D12D) works from a library as
  long as the argument types match.

## Next actions

1. Fix the harness to `string memory`; rebuild.
2. Run `forge test --match-contract "WhirRoundPhaseTest|WhirInitialPhaseTest"`.
3. Debug any mismatch by bisecting: gamma (transcript) → folds (STIR) →
   claimedEval (batching) → foldedClaim (sumcheck).
4. `cargo fmt --all` + `cargo clippy -p prover --all-targets -- -D warnings`,
   then commit M3.
5. Start M4 (final phase) exports in the same harness.

- `verifyFinal` + `WhirFinalPhase.t.sol` + terminal exports in the vector harness; 91 forge tests green.
## Log

- `verifyRound` spliced into `WhirVerifierCore.sol`; harness exports extended;
  artifact regenerated; round test + shared initial-phase harness written.
  First `forge build` failed on the bytes/string JSON mismatch above.

## M4 complete (final phase)

- `WhirVerifierCore.verifyFinal` mirrors `replay`'s tail: bind the public
  polynomial (`final_poly`), terminal PoW, terminal query indices, per-query
  Merkle open + fold at the last round's randomness, then the STIR check
  `fold == horner(finalPoly, domainPoint)` (the terminal claims are checked
  DIRECTLY against the public polynomial, not batched into the claim), the
  closing sumcheck, and the terminal identity
  `claimed == eval_constraints_poly(all_r) * final_poly(final_r)`.
- The extension tree IS the base tree at 4x row width: terminal path
  reconstruction runs on the base `MerkleTreeMmcs` with
  `width = 4 * (1 << folding_factor)` and rows flattened to base limbs.
- `query_point` returns BASE scalars (`WhirQueryPoint::Univariate(F)`); the
  artifact exports them canonical and the test lifts them.
- `all_r` = initial randomness, then each round's, then the closing
  sumcheck's; each constraint reads the LAST k (Prefix). The constraint list
  for the terminal identity is [initial, round0..n-1] - the FINAL round's
  STIR claims are not in it.
- New exports: `final_poly`, `final_pow_witness`, `final_rows_ext`,
  `final_paths`, `final_folds`, `final_domain_points`, `final_sumcheck_*`,
  `claimed_before/after_final`, `round_domain_points`, plus counts
  `final_poly_len` and `num_final_sumcheck_pow_witnesses`.
- Tests: `WhirFinalPhase.t.sol` pins the closing claim, the closing
  randomness, and (inside `verifyFinal`) the STIR check and terminal
  identity; a tampered public polynomial reverts. 85M gas for the whole
  WHIR core on this shape.


## M5 — batch STARK transcript layer: PLAN (recorded before coding)

### What M5 has to reproduce

The settlement proof is a `BatchStarkProof<crate::whir::Config>`. Its WHIR proof is
the batch proof's `opening_proof`, so the contract must replay
`p3_batch_stark::verify_batch` with the WHIR core as its PCS layer. M5 is the layer
BEFORE and AROUND the delegated WHIR opening argument:

```
new(BatchShape) -> instance_bindings(degree_bits) -> main_phase(main, public_values)
  -> preprocessed_phase(Option<com>) -> lookup_phase(lookups, gadget, pow) -> alpha_lay_out
  -> permutation_phase(Option<com>, terminals) -> alpha (constraint folding)
  -> quotient_phase(quotient_com, Option<random_com>) -> ood_phase(pow) -> zeta
  -> delegate( pcs.verify_with_preprocessing(coms_to_verify, opening_proof, ch, pre_idx) )
  -> finish()
```

### Decisions

- **D-061 Prove under a SEMANTIC settlement config, do not re-plumb the production path.**
  The test builds the same settlement prover as `settle_recursion_circuit` but with
  `SemStarkConfig = StarkConfig<SemPcs, Challenge, SemChallenger>`. The sem challenger
  forwards every absorb/sample to the production Keccak challenger and only RECORDS,
  so the proof is a real Keccak proof and `verify_batch(&sem_config, ...)` accepts it.
  Alternative rejected: reconstructing `CircuitTableAir` over a second config from the
  production `CircuitVerifier` - `table_airs` is generic over the config the prover was
  built with, so a second config means a second prover anyway.
- **D-062 The correctness criterion is PROGRAM EQUALITY, not value equality.**
  The test runs `verify_batch` under the sem config (program P_native) and a hand-written
  phase-by-phase replay (P_manual) and asserts `P_manual == P_native` event for event.
  The Solidity side then replays P_manual's blob and pins alpha, zeta, the lookup layout,
  and the terminal sum. If the two programs match, the contract's sequence is the
  verifier's sequence by construction.
- **D-063 Bus layout is trusted-setup metadata, not proof data.** `lay_out_lookup_challenges`
  derives bus ids from lookup KINDS (global names shared, local fresh) and the widest
  payload; `prefix[i] = alpha + (i+1)*beta^W`. The artifact exports per-instance bus ids,
  `max_message_width`, and `next_bus` (AIR-derived), and the Solidity test RECOMPUTES
  `prefix[i]` from alpha/beta and checks it against the exported per-instance layout.
  Taking alpha/beta as inputs would let a prover choose its own lookup challenges.
- **D-064 Opening points stay inputs (D-060 holds).** `commitments_with_opening_points`
  is exported as a structure (round -> matrix -> domain size, points, opened values) and
  the contract feeds it to the WHIR core's claim builder; no point bytes enter the blob.

### Steps

1. `p3-batch-stark = "0.8.0"` into `[workspace.dependencies]` and prover dev-deps.
2. `crates/prover/tests/batch_stark_vectors.rs`: build inner proof -> recursion circuit ->
   settlement prove under the SEM config; run native `verify_batch`; replay the phases
   manually; assert program equality; export `contracts/test/vectors/batch_stark_vectors.json`
   (+ `.bin` fixed-absorb blob) with shape, degree bits, commitments (hex), opened values,
   terminals, alpha/beta/zeta, per-instance lookup layout, bus ids, opening-argument
   structure, quotient chunk domains, and the fixed runs.
3. `contracts/src/verifier/BatchTranscript.sol`: the phase sequence over
   `KeccakChallenger.State` + the fixed blobs, returning alpha, zeta and the lookup layout.
4. `contracts/test/BatchTranscript.t.sol`: pin alpha, zeta, the recomputed bus prefixes,
   the terminal-sum check, and a tampered-commitment revert.
5. Gate (fmt + clippy -p prover + targeted forge tests), commit M5.


## M5 — DONE: the batch transcript sequence is pinned by the prover

**What was proven.** `crates/prover/tests/batch_stark_vectors.rs` builds the real
settlement batch (inner Fibonacci proof -> recursion circuit -> `BatchStarkProof` under
the semantic config, D-061), runs the library's `p3_batch_stark::verify_batch` through the
recording challenger, and separately drives every phase by hand. The two event streams are
**identical: 29,902 events**. That is D-062 satisfied, and it means the phase order in the
plan above is the library's order, not my reading of it.

**What is pinned on-chain-side.** `contracts/test/BatchTranscript.t.sol` (5 tests) walks
the recorded blob through the Solidity Keccak sponge and checks:
- every sample, uniform draw and PoW witness in the batch layer agrees with the Rust
  verifier, and all five payload cursors end exactly at their lengths (a short read would
  desync a verifier at some later unnamed site);
- the four extension draws sit at the structural pool offsets 0/4/8/12 =
  `lookup_alpha`, `beta`, `constraint_alpha`, `zeta`;
- the first five absorbed digests are main, preprocessed, permutation, quotient, random -
  which is what proves the trusted-setup commitment is absorbed at the right site;
- the bus prefixes recomputed on-chain from `alpha`, `beta` and the trusted-setup bus ids
  equal the exported per-lookup pairs (D-063);
- the LogUp terminals sum to zero;
- flipping one bit of a proof commitment digest makes the walk revert (external harness
  contract, same trick as M3).

**Measured batch shape** (BASE_TRACE=1024 Fibonacci, pinned by
`batch_stark_artifact_shape_is_pinned`): 6 instances, `degree_bits =
[10,9,16,15,14,1]`, one global LogUp bus (`max_message_width = 5`, `next_bus = 1`),
`ext_degree = 4`, is_zk, permutation + random + preprocessed commitments all present, both
PoW witnesses zero. Blob: 122,738 bytes, 775 schedule entries, 716 samples.

**Format change (D-065).** Two facts about the batch layer broke blob v1: the preprocessed
commitment is byte-identical across proofs (trusted setup, and absent from `BatchProof`),
and WHIR query indices are drawn at the full LDE width (21 bits). Added
`OP_CONST_COMMITMENT = 6` and `OP_UNIFORM_BITS_32 = 7`, bumped the format to v2, and
regenerated all three artifacts. Also fixed a real bug the new blob exposed:
`SemanticBlob.countDigests` counted schedule entries instead of runs.

**Gas data point.** Walking the whole batch blob with checking on costs ~55M gas;
record-only ~51M. Affordable in one transaction, but the constraint layer (M6) is where
the real cost sits, so M7 chunking stays on the plan.

## Corrections found while doing M5 (kept because they are load-bearing)

- **`sample_uniform_bits` is a masked little-endian u32**, not a big-endian byte-sourced
  draw: `u32::from_le_bytes(sample_array()) & ((1 << bits) - 1)`. The Solidity side already
  matched (`_sampleUint32` reads the block from its low end); the mismatch was in my
  *payload*, which stored `usize::to_be_bytes()` - 8 bytes on a 64-bit target, misaligning
  every later read. Symptom was a single confusing `bits 21 want 0 got 1134388`.
- **KoalaBear's quartic extension reduces `x^4 = W` with `W = 3`**, not `x^4 = -1`. A
  Node-side cross-check using `-1` disagreed with the Rust export and sent me chasing the
  field library for a while. The on-chain `KoalaBearExt4._mul_packed` was right.
- **The per-lookup challenge list is flat**: each lookup contributes two consecutive
  4-coefficient entries `[prefix, beta]`, so pairs step by 2 while `bus_ids` steps by 1.
- **forge-std has no `parseJsonArray`** in the vendored `Vm`; use `parseJsonUintArray` /
  `parseJsonUint(json, path + "[i]")`. `parseJsonString` on an array fails with
  "expected string, found array", and `.length` is not a valid path segment.
- **Run-length merging means schedule entries != op counts.** Anything that sizes an array
  from the schedule must sum the run field. This was a genuine bug, not a test artifact.

## Next actions

1. **M5b**: `contracts/src/verifier/BatchTranscript.sol` - the production phase sequence
   over `KeccakChallenger.State` driven by proof bytes + trusted setup (not a blob walk),
   returning `alpha`, `beta`, `zeta`, the constraint alpha and the lookup layout; pin it
   against the same `batch_stark_vectors.json`.
2. **M6**: `ConstraintIdentity.sol` generated from `SymbolicAirBuilder` /
   `get_constraint_layout` (`p3-batch-stark/src/symbolic.rs:261`) for the Poseidon2 +
   recompose + statement table AIRs. Largest remaining unknown.
3. **M7** chunking, **M8** gas + EIP-170 audit, **M9** wallet/settlement/metrics.

## M5b — DONE: `BatchTranscript.sol` (production batch layer)

- The phase sequence is now a real contract library, driven natively by
  `BatchTranscriptNativeTest` with blob payload slices, landing on all four exported
  challenges plus the bus-0 pair. The walk test pins the sponge; this pins the sequence.
- `phase_marks` (event offset after each batch phase) are exported by the generator:
  new=87, instance_bindings=111, main=115, preprocessed=116, lookup=125, permutation=154,
  quotient=156, ood=161, delegate starts at 161 of 29,902.
- Corrections (kept): a zero-difficulty grind absorbs NOTHING (my first port absorbed a
  zero word and desynced at the lookup draw - the pin caught it); terminals need
  `SumcheckCore.observeExt4Canonical` (Montgomery), not the raw packed absorber.

## M6 - ConstraintIdentity: PLAN

The last transcript-free layer: after the delegate, `verify_batch` checks per-instance
that the folded constraint identity holds at zeta using the opened values. The AIRs are
generated (Poseidon2/recompose/statement table AIRs), so the constraints must be
GENERATED too: export each instance's symbolic constraint DAG from Rust (trusted setup),
evaluate it in Solidity over the opened values. Steps:
1. Read `p3-batch-stark/src/check_constraints.rs` + the folder: exact identity, alpha
   powers, quotient chunk combination, public-value/periodic handling.
2. Export the constraint IR (op DAG over: main local/next, preprocessed local/next,
   public values, periodic, alpha, zeta, constants, +,-,*,neg,exp) per instance.
3. `ConstraintIdentity.sol`: DAG evaluator in extension-field arithmetic.
4. Pin: folded identity == quotient combination at zeta, per instance, vs the prover.

## M6 - DONE: the constraint identity layer is pinned by the prover

`verify_batch`'s last layer, after the delegated opening argument. Per instance:

    fold(alpha, constraints(zeta)) * inv_vanishing(zeta) == quotient(zeta)

**What exists now**

- `crates/prover/tests/constraint_identity_vectors.rs` (`#[ignore]` generator + Rust pin).
  Proves the settlement batch, replays the batch transcript to recover `zeta` and the
  fold challenge, then per instance calls `get_constraint_layout` +
  `get_symbolic_constraints` (the 4-arg p3-batch-stark versions - `CircuitTableAir`
  implements `Air<InteractionSymbolicBuilder>`, not `SymbolicAirBuilder`), flattens each
  constraint to a post-order op list, evaluates it, and asserts the identity against the
  library's own `recompose_quotient_from_chunks`. Writes
  `contracts/test/vectors/constraint_identity_vectors.json`.
- `contracts/src/verifier/ConstraintIdentity.sol`: `selectors()`, `foldConstraints()`
  (DAG interpreter), `chunkVanishings()`, `recomposeQuotient()`.
- `contracts/test/ConstraintIdentity.t.sol`: reruns selectors, fold, chunk vanishings
  and the recompose in Solidity for all six instances and requires each to match the
  exported value, then checks the identity. 2 tests, 100 forge tests green.

**Measured shape** (BASE_TRACE=1024, pinned): 7,361 flattened nodes over six instances -
inst 0: 52, inst 1: 40, inst 2: 1,963, inst 3: 5,085, inst 4: 116, inst 5: 105.
Constraint counts (K): 8, 4, 105, 196, 8, 12. Gas for the whole constraint layer over
all six instances: **40.2M** (selectors alone: 4.6M). That is on top of the ~55M batch
transcript walk, so the full verifier lands near 100M - under the 130M block gas limit
but large. M8 has real work to do.

**Design correction (do not relitigate)**: the plan's "inversion-free star fold" -
substituting `is_first -> zh*s2`, `is_last -> zh*s1`, `is_transition -> s2` and claiming
`acc_star == acc * s1 * s2` - is **unsound**. Constraints with no selector have
denominator 1, so no single factor can be pulled out of the alpha fold. The sound version
evaluates the **real selectors** and pays three extension inversions per instance
(`s1`, `s2`, `zh`), which depend only on `zeta` and the domain, plus one for
`inv_vanishing`. If those four inversions per instance are too expensive, the fix is
Montgomery's trick (batch the inversions), not a reformulation of the fold.

The quotient recompose genuinely is inversion-free at runtime: its denominators
`Z_j(first_i)` are domain-only constants, so the export ships
`invD_i = (prod_{j!=i} Z_j(first_i))^-1` and each chunk domain's `inv_shift`. The test
asserts that reformulation equals the library's recompose before pinning anything.

**API notes (p3 0.8.0, cost real time)**
- `EF::from_base` does not exist. Lift with
  `<EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(&[x, ZERO, ZERO, ZERO])`.
- `F::from_canonical_u32` does not exist either; `PrimeCharacteristicRing::from_u32` does.
- `Arc::as_ptr` takes `&Arc<T>`; matching on a `&SymbolicExpression` binds the inner enum,
  so memoize on the child `Arc`s (`Arc::as_ptr(x)` where `x: &Arc<_>`), not the root.
- `PolynomialSpace::next_point` returns `Option<Ext>`.
- `BatchVerifierTranscript` panics on drop unless finalized: `transcript.delegate(...)`
  then `transcript.finish()`, i.e. the opening argument must actually be replayed.
- The symbolic builder **clones** `Arc`s rather than sharing them, so pointer-identity
  memoization dedupes leaves but not shared subtrees: 7,361 nodes instead of the 22,083
  a naive expansion produces. Good enough; a real hash-consing pass is an M8 option.

## M7 - DONE: `ChunkVerifier.sol`, the cross-transaction sponge carry

The verifier cannot run in one transaction: transcript walk ~55M + constraint layer
~40M + the WHIR core leaves no headroom under the block gas limit. So the walk runs
one phase per transaction and the Fiat-Shamir sponge crosses the boundary.

**The carry is small and fully serializable.** `KeccakChallenger.State` is
`{bytes inputBuffer; uint256 inputLen; bytes32 outputBlock; uint256 outputIndex}`.
`_flush` hashes exactly `inputLen` bytes from the buffer start, so the buffer's
allocated *capacity* is not state - only the first `inputLen` bytes are. The carry is
those absorbed bytes + `outputBlock` + `outputIndex` + the phase counter + the four
drawn challenges. A few hundred bytes, `abi.encode`d.

`ChunkVerifier.sol`: `begin` then `stepMain / stepPreprocessed / stepLookup /
stepPermutation / stepQuotient / stepOod`, each decoding the carry, demanding its
predecessor phase (`PhaseOutOfOrder`), running exactly one `BatchTranscript` phase,
writing the mutated sponge back, re-encoding. `challenge(carry, which)` refuses a
challenge whose phase has not run. `phaseOf`, `absorbedBytes` for the WHIR handover.

**Pin** (`ChunkVerifier.t.sol`, 3 tests): the chunked walk lands on the same
`.lookup_alpha / .beta / .constraint_alpha / .zeta` as the single-shot native test -
17.6M gas for the whole chunked walk. Two revert tests: cannot skip a phase, cannot
read a challenge early. 103 forge tests green, semgrep clean.

**Correction caught while writing it**: my first draft had a `_asState(c)` helper that
copied `c.sponge` into a `BatchTranscript.State` and claimed the phase's in-place
mutations were "visible to `encode`". They are not - memory struct assignment copies
value fields, so the phase mutated the copy, not `c.sponge`. Every step now copies the
sponge in, runs the phase, and copies `s.sponge` back out explicitly. The pin would
have caught it (the draws would diverge), but fixing it before running is better.

**Gas note for M8**: the chunked walk costs 17.6M vs the native single-shot 18.2M -
the encode/decode boundary is essentially free next to the keccak the phases do. So
splitting across transactions buys gas headroom at no throughput cost.

## M8 - AUDIT: honest gas + EIP-170 (reductions deferred to D-068)

**The headline correction: the gas numbers I had been carrying were wrong.** The pin
tests report 55M (batch walk) and 40M (constraint layer), but those totals are
dominated by forge-std JSON parsing of the 797 KB / 368 KB vector files, not by the
verifier. Measuring with inputs pre-parsed (`VerifierGas.t.sol`, and `gasleft()`
brackets around the verify calls in the WHIR phase pins) gives the honest verify-only
cost:

| layer | verify-only gas | note |
|---|---|---|
| batch transcript walk (settlement shape) | **16.5M** | 7 phases, ~30 keccak flushes |
| WHIR core initial | 0.28M | |
| WHIR core round (x1) | 3.47M | |
| WHIR core final | 3.17M | final sumcheck + STIR openings |
| constraint layer, 6 instances | **8.7M** | selectors 0.28M, fold 8.0M, quotient 0.4M |

The WHIR-core numbers come from `whir_proof_vectors` (the standalone WHIR proof),
the walk and constraint numbers from the settlement batch - different artifacts, so
they bound rather than sum to one settlement total. Order of magnitude: the whole
verifier is **~30M verify-only**, not the ~100M the pin totals implied. It fits a
single transaction with room to spare; M7's chunking is available for headroom but is
not forced by gas.

**Constraint layer breakdown** (per-instance fold, the dominant term): inst3 5.42M,
inst2 2.18M, inst4 0.13M, inst5 0.13M, inst0 0.06M, inst1 0.05M. The fold tracks the
DAG node count exactly (inst3 = 5,085 nodes = 5.4M gas, ~1,065 gas/node). Selectors
are flat ~46K/instance (the four inversions dominate, independent of constraint
count) - so Montgomery-batching them across instances would save at most ~0.2M total.
Not worth it at this scale; recorded so nobody spends M8 time there.

**EIP-170**: `VerifierSizeProbe` (test/utils) references every verifier entry point so
the linker pulls all their code into one artifact. Runtime **15,216 bytes**, margin
**9,360** under the 24,576 limit. A monolithic verifier deploys today. The probe is
the regression tripwire: adding a layer that pushes it past 24,576 fails `--sizes`.

**Gas regression bounds** are now asserted in the pins (initial <1M, round <8M, final
<8M, walk <25M, constraint layer <55M) so a doubling fails CI, not just a benchmark
run.

**Deferred to D-068** (after the recursive proof verifies end to end): the assembly
rewrites (packed-ext4 lane arithmetic, the DAG dispatch, Merkle compression) and the
bytecode-size work, borrowing from bitcoin-stark-verifier / plutus-plonky3-exploration
/ midfall quotient-hybrid. The audit says these are OPTIMIZATIONS now, not blockers -
the verifier fits both limits as written.


## M10 - COMPOSED VERIFIER + POOL E2E

### Done
- ShieldedPool first tests (a7d96e9): 8 tests driven by real prover block data
  (block_vectors.json). Caught a real bug - the pool left currentNullifierRoot=0
  but the prover's genesis block names the empty nullifier-map root (depth-256
  empty-subtree chain). Constructor now computes it at deploy. Stub verifier is
  view (like the real seam) and accepts only keccak(abi.encode(statement,proof))
  it was told, pinning verbatim passthrough.

### The remaining gap to a TRUE e2e (real proof -> real verifier -> pool)
Every layer is pinned against prover output IN ISOLATION:
  - BatchTranscript.sol  <- batch_stark_vectors (settlement shape, program eq)
  - ConstraintIdentity   <- constraint_identity_vectors (settlement shape)
  - WhirVerifierCore     <- whir_proof_vectors (SMALL shape: 11 vars, 1 round)
  - StarkMerkle/StirOpenings/SumcheckCore <- their own vectors
But:
  (a) No composed IWhirVerifier implementation stitches them.
  (b) The WHIR core has NEVER been driven at the settlement shape
      (25 vars, 4 rounds, 170 queries, pow 23) - only the small test shape.
  (c) The batch->WHIR delegate handover (transcript.delegate(pcs.verify...)
      -> WhirVerifierTranscript) has never been pinned.

### Linchpin first (Rust-only, fast to iterate)
Write crates/prover/tests/composed_vectors.rs: at the SETTLEMENT shape, take the
real batch proof's opening_proof and drive WhirVerifierTranscript exactly as
pcs.verify_with_preprocessing does, asserting program equality against the
native run. If this passes, the WHIR core consumes exactly the batch transcript's
delegated challenger at settlement shape -> the Solidity composition is then
mechanical assembly of already-pinned pieces.

### Then (Solidity)
- WhirVerifier.sol: implements IWhirVerifier.verify(statement, proof):
  ProofCodec decode -> BatchTranscript walk -> ConstraintIdentity per instance ->
  delegate to WhirVerifierCore initial/round/final -> return true.
- Wire into ShieldedPool ctor; a pool test feeds the REAL proof bytes (needs a
  block_vectors.bin sidecar) and asserts the whole path.


## M10 LINCHPIN PROVEN (commit 39ac1ca)

The composition claim is now a tested fact, not a plan.

- `tests/whir_walk`: the WHIR verifier-transcript walk (initial fold, round
  loop, terminal phase) lifted out of `whir_proof_vectors.rs` into a shared
  module, plus a new `verify_whir_round` driver taking a `PcsProof`, an
  `OpeningProtocol` and its points, driving the whole run on a caller-owned
  challenger. The small-shape pinned test drives this exact code and still
  passes (program equality, negative controls, shape pin).
- `tests/batch_fixture`: the settlement-batch scaffolding lifted out of
  `batch_stark_vectors.rs`. `manual_replay`/`one_run` gained an optional
  delegate hook: `None` runs the native PCS exactly as `verify_batch` does;
  `Some` replaces the PCS inside `transcript.delegate` on the same challenger.
- `tests/composed_vectors.rs`: the linchpin. Proves the settlement batch,
  replays the batch phases, and inside the delegate rebuilds each of the five
  opening rounds' WHIR config + opening schedule from public ingredients only
  (`padded_arity`, `checked_stacked_num_variables`, `univariate_eq_point` - the
  same construction `round_schedule` performs), drives `verify_whir_round` on
  the batch challenger, and re-checks the claimed openings against the walk's
  bound evaluations with the univariate-eq scales. `one_run` asserts the
  combined event program equals the native run's: **29,902 events, identical.**

Measured settlement shapes (composed_vectors.json, 6.5 MB):
- 5 opening rounds; stacked arities 19/24/22/23/22.
- 3 WHIR folding rounds in batch rounds 0/2/4, 4 in rounds 1/3.
- round 2 opens 32 matrices (per-instance column split); others open 6.
- rounds 1 and 4 open the two-row instances at 2 points.
- phase_marks: delegate opens at event 161, closes at 29902.

Consequence: the batch->WHIR handover is pinned. The Solidity composition is
now mechanical assembly of pieces each already pinned: BatchTranscript.sol up
to the delegate, then WhirVerifierCore per round with the statement exported
here. No vendor patch was needed - every ingredient of round_schedule is public.

## Next: composed Solidity verifier (WhirVerifier.sol)

`IWhirVerifier.verify(statement, proof)` = ProofCodec decode -> BatchTranscript
walk -> ConstraintIdentity per instance -> delegate to WhirVerifierCore
initial/round/final per opening round -> return true. Feed real proof bytes.


## D-069: proof-data zeros reclassified as varying; per-site constant schedules

Measured: the composed blob's all-zero fixed runs are structurally-zero
extension elements - high final_poly coefficients (round 1: 5/16, round 2:
11/64, round 4: 21/64) and zero eval columns (round 3: 30 across four
claims). They are constant across runs only because the circuit zeroes them
structurally; they are proof data, not framing constants.

Options considered:
(a) Keep them fixed and give the final-poly absorb an interleaved
    constant/calldata schedule (Vx12 Cx4 Vx12 Cx4 ...). Rejected: no scalar
    schedule expresses it, the interleaving is proof-shaped, and a forged
    nonzero in a "zero" slot would desync the sponge anyway.
(b) RECLASSIFY every all-zero fixed run as varying (chosen). The contract
    reads proof data from calldata uniformly; every framing run is then a
    nonzero shape constant. Soundness: the transcript only sees the byte
    stream - a prover putting a nonzero where the schedule says calldata
    diverges the sponge from the honest prover's, exactly like any other
    proof mismatch. Framing constants are keccak-derived labels, never zero.
    The small-shape guard (check_no_ambiguous_zeros) already treated an
    isolated fixed zero as a bug; this generalizes that stance.

Consequence for WhirVerifierCore (measured run decomposition, exact):
per composed opening round the framing runs are
    [preClaims x oodSamples, perClaim x nClaims, batching,
     sumcheck x (1 + nWhirRounds)]
- preClaims absorbed ONCE PER virtual claim (oodSamples=2 in rounds 1-4).
- perClaim varies per claim: width- AND arity-dependent (126 for width 4 at
  arity 19; 414/774 at width 76/166; 334 for width-4 column-split matrices
  at arity 22), so it must be a per-claim array from trusted setup, not a
  scalar. Zero-split claims (round 3) split a perClaim run; the split
  positions are trusted-setup schedule data.
- finalPolyConstants = 0 after reclassification (final_poly read whole).
Export: composed_vectors.json round_fixed_runs = per-round framing run
values (hex); lengths are the schedule. Blob shrank 122738 -> 122322 B.


## Claim-region ground truth (phase_offsets instrumentation)

verify_whir_round now records sink.len() at every claim boundary
(WhirRoundWalk.phase_offsets). Exact per-claim decomposition at settlement
shape (C=constant framing words, V=varying eval words, all ext = 4 words):

  round 0 (6 claims w=4):  C126 V16 each
  round 1 (8 claims):      C126 V16, C126 V16, C414 V304, C414 V304,
                           C774 V664, C774 V664, C126 V16, C122 V12
  round 2 (32 claims w=4): C334 V16 each
  round 3 (8 claims):      C134 V24, C118 V8, C346 V208 C28, C346 V208 C28,
                           C206 V60 C4 V32, C206 V60 C4 V32, C150 V40, C126 V16
  round 4 (12 claims):     C142 V32 x4, C222 V112 x2, C174 V64 x2,
                           C206 V96 x2, C174 V64 x2

Facts:
- Per-claim framing constant count = 110 + 4*(width - zero_eval_cols) for the
  simple claims (round 0: 110+16=126; round 2: 334 at arity 22 differs ->
  arity-dependent base, NOT a single formula).
- Round 3 c2/c3 have a TRAILING constant run (C28): structurally-constrained
  eval columns absorbed as constants AFTER the varying evals. c4/c5 have a
  MID-claim constant run (C4) splitting the varying evals (V60 C4 V32).
- The varying eval words are NOT the first-N bound_evals in wire order: the
  constraint layout interleaves equality-statement structure, so eval order on
  the wire is layout order, not matrix order.

CONCLUSION: the claim region is ragged at constraint-group granularity and the
only sound representation is the blob's own schedule. The contract must be a
SCHEDULE-DRIVEN interpreter: walk the WSPR schedule (kind/arg/run), and at
each semantic boundary (sumcheck round, stir opening, terminal sum, constraint
identity) invoke the already-pinned gadget. The scalar InitialSchedule /
FinalSchedule fit the small shape only; at settlement shape they are replaced
by the schedule walk. This is the composed-verifier architecture.
