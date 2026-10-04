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


## D-070: consumption-aligned framing schedule (composed claim region)

The composed claim region is now exported as a schedule the contract slices at
its four consumption points, not at raw fixed-run boundaries.

`round_framing_table` classifies each fixed EVENT (not run) as framing iff it
is before the claims, after the last claim, or within a claim's framing prefix
(leading fixed events before that claim's first varying event). This splits the
merged runs correctly: a claim's trailing constant EVAL run and the next claim's
framing run are physically adjacent (one maximal fixed run) but the event-level
test separates them - the earlier run-level boundary test dropped the next
claim's framing (round 3 showed 6 framings, not 8).

`round_framing_tables` then aligns the framing runs to the contract's
consumption points and exports per round:
  {hex, pre_claims, claim_framings[], batching, seps[]}
where seps has exactly 1 (initial sumcheck) + n_intermediate + 1 (terminal)
entries - verified for all 5 rounds:
  r0 pre=94  b=233 seps=5 | r1 pre=188 b=245 seps=6 | r2 pre=604 b=441 seps=5
  r3 pre=188 b=245 seps=6 | r4 pre=188 b=233 seps=5
(pre_claims is a SUM because the pre-claim region is 1-2 runs; the contract
absorbs it as one block.)

Ground truth from the blob: round 0 region = Cx94 (preClaims) Sx4 (alpha) Vx4
(OOD answer) [Cx126 Vx16]x6 (claims) ... The commitment digest is absorbed at
event 155 by the BATCH layer, before delegate at 161, so the WHIR core transcript
starts at 161 with the digest already in the sponge - matching the small-shape
tests' observeDigest(commitment) then verifyInitial.

Next: WhirComposed.t.sol driving all 5 rounds from composed_vectors.json.


## M7 COMPOSED ROUNDS GREEN (commit 61debf3) - 2025 goal round 5

WhirComposedTest: all 5 composed opening rounds replay end to end in
WhirVerifierCore.sol - initial phase (alpha, batched claim, initial sumcheck,
randomness), every intermediate WHIR round (grinds, OOD answers, Merkle
openings, folds, round batching, folded claim threading), the final phase
(public poly bind, terminal PoW, terminal queries, STIR check, closing
sumcheck) and the terminal identity
claimed == eval_constraints_poly(all_r) * final_poly(final_r).

Three root causes fixed (all pinned in code comments):
1. CLAIM PLACEMENT ORDER. The batched dot product weights concrete claims in
   constraint order (plan_layout: tables by descending arity, ties by
   descending table index, claims within a table in insertion order), NOT
   proof order. Transcript absorbs in proof order; only the dot product is
   permuted. InitialInput.claimPerm (empty = identity).
2. GRIND WITNESSES ARE MONTGOMERY. Blob stores base words in Montgomery;
   checkWitness absorbs raw. JSON export is canonical; the generator converts
   the five pow-witness fields (mont = x*2^32 mod p).
3. PER-ROUND SEEDING. Each opening round seeds the sponge at its own
   round_starts[r] site (r0 at the batch delegate event 161; later rounds
   where the previous walk ended). SemanticBlob.walkTo(stopSite) parks the
   sponge mid-stream for the batch->WHIR handover.

Sidecar gotchas solved: rows_flat/final_rows_ext are RAW canonical limbs
(extLeaf does Montgomery conversion itself, 4 limbs/ext element low-first);
paths + round commitments ship as hex blobs (forge parseJsonBytes32Array
chokes on big arrays; repo pattern is hex + Solidity slicing via assembly
_node); n_inter exported explicitly (forge JSON paths have no .length).

Test threading gotcha: memory reassignment inside a private function is
invisible to the caller - the intermediate loop must RETURN its carried
claim + randomness (Threading struct), not mutate params.

REGRESSION: WhirInitialPhase/RoundPhase/FinalPhase/BatchTranscriptNative/
WhirSemanticProgram/ProofCodec/StarkMerkle all green (36 tests).

NEXT: top-level WhirVerifier.sol implementing IWhirVerifier.verify(statement,
proof). The composed test is the verifier logic fed from a sidecar; the real
entry point must derive the same inputs from the semantic blob (schedule-
driven interpreter, D-070): walk the WSPR schedule, read proof payloads at
the varying cursors, derive framing constants from the fixed payload at the
exported offsets, drive WhirVerifierCore. Then wire into ShieldedPool with
real proof bytes, then gas benchmark + EIP-170 size check (D-068 reductions
if needed).


## D-071: WhirVerifier wire format (settlement bundle)

IWhirVerifier.verify(statement, proof) needs the composed inputs as BYTES, not
JSON. The composed_flat sidecar mixes three trust classes; the bundle splits
them explicitly:

- PROOF (untrusted, from the prover): per-round commitments, bound_evals
  (opening evaluations), OOD answers, sumcheck round values (ca/cinf), grind
  witnesses (Montgomery), opened rows (raw canonical limbs), Merkle paths,
  final poly + final rows + final paths, terminal pow witness.
- STATEMENT (public): per-round matrix shapes (log_size, width) + opening
  points, public values, degree bits.
- CONFIG (trusted setup, D-066 posture): framing tables (keccak-derived
  labels), schedule params (pow_bits, log_folded, ood_samples, num_queries),
  claim_perm, eq_points (univariate_eq_point of the statement points -
  in-circuit derivation needs inversions per point, deferred), per-round
  domain base constants, num_variables, claim widths.

TRANSCRIPT-DERIVED values (alpha, gamma, betas, query indices, folds,
claimed/folded evals, round randomness, batching) are NEVER in the bundle -
the verifier computes them; the test asserts they match the ground truth.
A prover-supplied challenge would be a soundness hole.

Wire format: fixed-order sections, versioned header, u32 LE words, 32-byte
BE packed ext elements, raw byte runs for framing/paths blobs. ProofCodec
cursor primitives do the decoding. Same run as composed_vectors.bin; emitted
by contracts/scripts/gen_bundle.mjs from composed_flat.json + composed_vectors.json.

WhirVerifier.sol = decode -> BatchTranscript walk (batch layer, sites 0..161)
-> per opening round: WHIR core initial/intermediate/final on the delegated
sponge -> terminal identity -> true. WhirComposed.t.sol logic moves into the
contract; the test keeps only decode + expected-value assertions.


## D-072: eq_points are statement-derived, not trusted config (soundness)

The initial constraint's equality points are a function of zeta (drawn in
ood_phase, per-proof) and the trusted shapes/layout: each claim's stacked
point = univariate_eq_point(zeta, log_size_m) placed at the claim's block
offset in the stacked variable space, zeros elsewhere; the virtual OOD claim
gets the sampled point. They CANNOT be static trusted config (zeta changes
per proof) and MUST NOT be prover-supplied unchecked: a prover choosing eq
points proves openings at points of their choice, breaking the link to the
batch statement.

Plan: phase 1 (this round) ships eq_points in the bundle PROOF section and the
contract uses them - correct but with a tracked soundness gap. Phase 2
(next round) implements deriveEqPoints(zeta, shapes) in Solidity mirroring
p3-sumcheck's stacking, validates derived == shipped in the test (proving the
rule), then the contract derives instead of trusting. The composed test already
proves the terminal identity with exactly these points; what remains is proving
they are the ONLY points consistent with zeta.

## Bundle layout shipped (composed_bundle.bin, WBND v1)
header: magic WBND, version u8, cfg_words u32 LE, prf_words u32 LE
cfg: [batchCfgLen, batchCfg..., per-round config..., per-round proof...]
  batchCfg = fixed blob words before delegate (seed, degree bits, public
  values, preprocessed digest)
prf: [batchPrfLen, batchPrf..., per-round proof...]
  batchPrf = varying blob words before delegate (main digest, lookup grind,
  perm digest + terminals, quotient digests, ood grind)
stm: [stmLen, per-round matrix shapes + opening points]


## D-073 — Top-level WhirVerifier: the settlement proof verifies on-chain (DONE)

`contracts/src/verifier/WhirVerifier.sol` is the entry point: WBND v3 bundle
decode -> full batch transcript walk (begin/mainPhase/preprocessedPhase/
lookupPhase/permutationPhase/quotientPhase/oodPhase) -> the SAME sponge handed
to the WHIR core -> all five opening rounds (verifyInitial/verifyRound/
verifyFinal) -> terminal identity. `WhirVerifierTest` drives it from the real
composed bundle: accepts the real proof (960M gas), rejects wrong statement,
wrong length, tampered bytes, truncation, bad magic. All 24 forge suites green.

Wire findings this step pinned (each was a live bug):
- **pv words on the wire are Montgomery** (p3 serializes the internal form);
  the statement is canonical, so the statement check compares
  `mulmod(statement[i], R, p)` against the blob word. The blob absorbs them raw
  (correct); only the statement comparison converts.
- **the blob's var payload is Montgomery too** (same serializer), so the
  generator converts the LogUp terminals back to canonical before packing —
  `observeExt4Canonical` expects canonical limbs. The native test used the
  JSON's canonical values directly, which hid this until the bundle path ran.
- **framingSeps indexing**: [0] frames the initial sumcheck, [1+i] round i, so
  the closing sumcheck's separator is [1 + n_inter].
- **round commitment wiring**: intermediate round i's new root is
  `roundCommitments[i]` (n_inter entries); the batch commitment is only the
  round-0 OPENING root (`prevCommitment`).
- **section offsets are word offsets into the data** (header = 4 words): CONFIG
  at word 4, PROOF at 4 + cfgWords; section length words count words.
- D-072 phase 2 landed: domain points are computed in-circuit as
  `g^(sampled index)` via `FinalInput.domainGenerator` /
  `WhirGadgets.powConstBase`; the proof no longer carries domain_points (v3).
  `round .gamma == verifyInitial alpha` threads constraints[0].gamma;
  intermediate gammas come from `RoundOutput.gamma`.

Sizes: WhirVerifier runtime 17,183 B — fits EIP-170 with 7,393 B margin.
Gas: 960M for the full settlement proof (all 5 rounds) — above the 30M block
target; calldata ~1.88 MB. Both are the D-068 reduction agenda (recursion to
one small proof + assembly hot paths), not correctness issues.

Bundle v3 deltas: PRF gains final_sumcheck_ca/cinf/pow_witnesses per round,
drops domain_points; CFG batch prefix gains the two grind difficulty bits.


## D-074 — Real shielded block verifies on-chain and applies to ShieldedPool (DONE)

`block_program_equality_and_export` proves a real 1-transfer shielded block
(funded_note -> prove_client_transfer -> build_multi_transfer_circuit ->
settle_block_circuit at BLOCK_LOG_MAX_LDE=25) and exports the composed vectors,
bundle, and a small `block_genesis.json` sidecar (statement limbs, genesis
leaves, expected root after). `BlockE2E.t.sol` deploys the real ShieldedPool
with the real verifier and real genesis leaves and:
- applies the real block: proof verifies, currentRoot == expectedRootAfter,
  leafCount 2 (1,600,405,878 gas);
- rejects a tampered proof byte (510M), a wrong statement (184M), and a
  tampered LogUp terminal with the exact TerminalSumNonZero (184M).
MemoryOOG/OutOfGas lessons: never parse the 12 MB vectors JSON in setUp
(sidecar instead); never store the 2.7 MB proof in storage (read from disk
per test).

## D-075 — verify_batch's post-opening checks (part 1 DONE, part 2 = D-076)

verify_batch ends with two checks after the opening argument:
1. `lookup_gadget.verify_terminal_sum(lookup_terminals)` — the batch's LogUp
   terminals must sum to zero. SHIPPED (4049256): WhirVerifier fail-fast sum
   over prf.terminals right after _checkStatement; pinned by BlockE2E tamper
   test and constraint_identity_vectors.rs.
2. Per-instance constraint identity (below) — NOT yet wired. This is the last
   soundness gap: without it a prover could open a fake trace that passes the
   WHIR argument but satisfies no AIR.

## D-076 — Constraint identity on-chain: the plan (IN PROGRESS)

The identity, per instance i (pinned natively by
crates/prover/tests/constraint_identity_vectors.rs):

    fold(constraintAlpha, constraints_i(zeta)) * inv_vanishing_i(zeta)
        == recomposeQuotient(chunks_i, chunkDomains_i, invD_i, zeta)

ConstraintIdentity.sol already implements every piece (DAG interpreter,
selectors, chunk vanishings, quotient recompose) and test/ConstraintIdentity.t.sol
pins it against the exported vectors; what remains is plumbing it into
WhirVerifier.verify with inputs from the SAME proof run as the bundle.

### Input inventory (fib shape, 6 instances)

| input | source | status |
|---|---|---|
| zeta | oodPhase return | discard -> capture |
| constraintAlpha | permutationPhase return | discard -> capture |
| lookupAlpha, beta | lookupPhase returns | capture (for perm challenges) |
| permChallenges[i] | [prefix(bus), beta] per lookup; bus ids + max_message_width are trusted setup | export layout, compute on-chain via BatchTranscript.lookupPair |
| permValues[i] | prf.terminals partitioned by per-instance terminal counts (trusted setup, =1 each) | trivial |
| trace_local/next[i] | main round (r=1) claims at zeta / zeta_next, widths [4,4,76,76,166,166,4,3] | from boundEvals * scale |
| quotient chunks[i] | quotient round (r=2) claims, 4 ext per chunk = flattened base coeffs -> pack limbs | from boundEvals * scale |
| pre local/next[i] | preprocessed round (r=3) claims, widths [6,2,59,59,24,24,10,4] | from boundEvals * scale |
| perm local/next[i] | permutation round (r=4) claims, base-flattened widths [8,8,8,8,28,28,16,16,24,24,16,16] -> pack limbs per 4 | from boundEvals * scale |
| public_values[i] | pv blob (already checked vs statement) | trusted |
| periodic_values | all empty at this shape | empty |
| trace_domain {log_size, shift, inv_shift, h_inv} | fixed by degree_bits | export (trusted) |
| chunk_domains, invD, num_chunks | domain-only constants | export (trusted) |
| constraint programs (nodes/base/ext consts/roots) | get_symbolic_constraints + flattener | export (trusted), ~88 KB fib |
| eq scales per claim | univariate_eq_point(zeta, padded_arity(log_height, 4)).1 = prod_j (1 + zeta^(2^j)) | derive on-chain from zeta |

Key realization: the opened values are EXACTLY the round-0 claims the contract
already absorbs (boundEvals, proof order, claimPerm maps constraint->proof
order), times the eq scale, which is a pure function of zeta and the trusted
matrix shapes. No new proof bytes; the constraint section is pure CONFIG.

Round -> batch-round mapping (fib, pinned by claim widths):
r0 = ZK random round, r1 = main trace, r2 = quotient chunks, r3 = preprocessed,
r4 = permutation. The block proof has the same five rounds (same batch shape).

### Steps

1. Factor the flattener + fold_constraints + ext helpers from
   constraint_identity_vectors.rs into tests/constraint_ir/mod.rs (shared).
2. composed_vectors.rs export: after the composed run, replay the batch
   transcript (as constraint_identity_vectors does) and write a
   `constraint_identity` object into the composed vectors JSON: zeta,
   constraint_alpha, per-instance {program, trace_domain, chunk_domains,
   inv_d, num_chunks, bus layout, terminal count, expected_fold,
   expected_quotient, opened (for the pin test)}. Same run as the bundle, so
   pins match the bundle's proof bytes.
3. gen_composed_flat.mjs / gen_bundle.mjs: emit a CONSTRAINTS section; header
   v4 gains cstWords u32 LE @16. CONFIG/PROOF layout unchanged.
4. WhirVerifier.sol v4: capture the three challenges; during the round loop
   retain per-round (claimWidths, claimPerm, boundEvals, matrix log_sizes) —
   or better, compute each round's opened slices inline and stash them; after
   the loop, per instance assemble ConstraintIdentity.Opened, derive scales
   from zeta, selectors, foldConstraints, recomposeQuotient, require equality.
   New errors: ConstraintIdentityMismatch(index).
5. Regenerate fib vectors + bundle; WhirVerifier.t.sol gains per-instance
   expected_fold/expected_quotient pins; full fib suite green.
6. Regenerate block vectors + bundle (background job ~60 s); BlockE2E green
   with the identity active (tamper tests must still hit their exact errors).
7. Full gate: cargo fmt + clippy + semgrep crypto rules + full forge suite;
   descriptive commits, each compiling + passing relevant tests.

### Decisions inside D-076

- Opened values from round-0 claims * scale (bound by the WHIR proof), NOT
  from the STM audit section (unbound). Alternative rejected: re-deriving
  openings from proof rows would duplicate the WHIR argument.
- Scales derived on-chain from zeta (prod (1+zeta^(2^j))), not shipped:
  shipping them would let a prover steer openings off the verified claims.
- Constraint programs ride in the bundle CONFIG section (deploy-time, pin
  keccak256(config||constraints)); alternative (Solidity source per circuit)
  rejected: the AIRs are generated, and the block shape differs from fib.
- perm challenges computed from (lookupAlpha, beta, bus layout) rather than
  shipped: two extra ext muls per lookup, zero trust.



## D-077 — Merkle-compressed block statement (QUEUED, next after D-076)

User request: replace the block proof's flat per-transfer public inputs with a
Merkle hash over them: statement = (n, input_root) where the tree leaves are
per-transfer public inputs (nullifiers..., outputs..., root, fee).

Design (decided):
- Tree: complete binary Poseidon2 (KoalaBear, width 3) over the n transfer
  leaves, padded to 2^ceil(log2 n) with a dedicated EMPTY constant;
  leaf_i = P2(tag_leaf, H(nullifiers || outputs || root_i || fee_i)) absorbed
  in fixed order; internal = P2(tag_node, L, R); input_root = P2(tag_root,
  subtree_root, n) so the count is bound and leaf-shifting/padding is
  impossible. Domain tags separate this tree from the pool tree (D-05).
- In-circuit: the block circuit already holds every transfer's public inputs
  as witnesses (it verifies each client proof against them); add Poseidon2
  tree-build constraints and expose [n, input_root] as the block statement
  instead of the O(n) flat limbs. Poseidon2 is the in-recursion hash (D-05),
  so the tree is native there; keccak256 in-circuit was rejected (bit
  decomposition cost).
- On-chain: ShieldedPool.applyBlock already receives the leaves as calldata
  (it must append outputs and mark nullifiers), so it recomputes the tree
  root from calldata and compares against the proof statement - O(n) Poseidon2
  hashes, no per-leaf inclusion proofs needed. Requires a Poseidon2-KoalaBear
  implementation in Solidity (~width-3 perm: 16x3 external + 45 internal
  x^7 sboxes + MDS + round constants; est. 5-8k gas/perm, ~100k gas for an
  8-leaf tree - noise next to proof verification).
- Statement stays O(1): [n, input_root, root_before, root_after, total_fee].
  root_before/after/total_fee stay explicit (O(1), cheap continuity check);
  the Merkle tree compresses only the O(n) per-transfer list.
- Benefits: settlement proof's public-value section constant-size; future
  block aggregation composes (n, root) pairs; per-transfer inclusion proofs
  available for light clients (the tree structure buys that for free vs a flat
  Poseidon2 digest - flat digest was the simpler alternative, rejected for
  light-client openness).
- Sequencing: AFTER D-076 part 2 (constraint identity is the soundness gap and
  is mid-flight; its export is shape-agnostic so it re-runs unchanged after
  the circuit change). Block vectors/bundle regenerate once, after D-077.



### D-077 amendment (user): hash choice for the transfer-input tree

User first asked for SHA2-256, then allowed Poseidon2 if SHA2 is too expensive.
It is: the tree is BUILT in-circuit (the circuit holds the transfer public
inputs and must bind the root to the proof), and SHA2-256 over KoalaBear needs
32-bit add-carry emulation for every modular addition (field is mod 2^31-2^24,
SHA2 adds mod 2^32) - roughly 100k constraints per compression. Poseidon2 over
KoalaBear is native in the recursion already (D-05): ~65 constraints per
permutation. The on-chain side must recompute whatever the circuit built, so
the family is Poseidon2 end-to-end (Solidity impl ~5-8k gas/perm, noise next
to proof verification). SHA2's on-chain precompile advantage is moot once the
circuit side is the constraint.

Structure per user notation: a sequential fold, not a padded balanced tree:
root_0 = P2(tag, n); root_i = P2(root_{i-1}, leaf_i);
leaf_i = P2(tag_leaf, H(nullifiers || outputs || root_i || fee_i)) with H the
existing shielded SHA3-256 compressed to field limbs; input_root = root_n.
n is bound into the seed so an empty/short chain cannot collide with a longer
one. Statement stays [n, input_root, root_before, root_after, total_fee].
Balanced-tree inclusion proofs (light clients) are a later option, not v1.



### D-077 finalization: fold, not padded balanced tree

Decided: sequential fold (user's H(H(..H(t1_PI), t2_PI)..) notation).
Rationale (recorded so the tree is not relitigated):
- applyBlock holds every leaf in calldata and recomputes the root from the
  full list; no consumer needs O(log n) inclusion proofs today.
- Fold circuit cost is n perms vs 2^ceil(log2 n)-1 for the padded tree: equal
  or cheaper, no EMPTY padding constant to domain-separate, no depth/index
  logic in circuit or Solidity.
- n bound in the seed (root_0 = P2(tag, n)); leaf_i self-describing (absorbs
  its own num_nullifiers/num_outputs since the shape header leaves the
  statement when the list is compressed).
- Fold chains incrementally: block builders maintain a running root, and
  future block aggregation folds block B from block A's root.
- Migration path kept open: the statement shape [n, input_root, root_before,
  root_after, total_fee] is identical under both constructions, so if
  light-client inclusion proofs become a requirement the swap is a
  circuit+contract change with no statement-format migration.


---

## D-076 part 2 state record (shared builder landed, 2025-10-04)

### Done this step
- `constraint_ir/mod.rs` (642 L) now holds the shared export builder
  `instance_identity_json::<SC, A>`: layout + symbolic constraints -> flattened
  DAG (memoized Flattener) -> opened values -> fold -> both pins
  (`fold * inv_vanishing == quotient`, inversion-free quotient reformulation)
  -> the full JSON block. Bounds: `SC: StarkGenericConfig<Challenge = EF>`,
  `Domain<SC>: PolynomialSpace<Val = F>` (Domain is the p3_uni_stark alias, not
  an assoc type; both settlement configs resolve to the same concrete
  TwoAdicMultiplicativeCoset so emitted JSON is config-independent).
- `constraint_identity_vectors.rs` refactored to call it: the 240-line inline
  loop collapsed to a 30-line per-instance call; regenerated vectors are
  byte-identical in shape (7361 nodes, all pins pass).
- `composed_vectors.rs` gained `constraint_identity_block(verifier, proof, out,
  pis)` computed INSIDE `composed_run_with` - the same proof run whose transcript
  events the bundle ships (a second run would mask fresh randomness and
  desynchronize pins from bundle bytes). Emitted as doc key
  `constraint_identity` for BOTH fib and block exports. Batch-level extras:
  zeta, constraint_alpha, bus_ids + max_message_width (from
  `batch_fixture::bus_layout`), terminal_counts.
  `BatchStarkProof` wraps the inner `BatchProof`: access via
  `proof.proof.opened_values` / `proof.proof.lookup_terminals`.
- `batch_fixture::ReplayOut` gained `trace_domains` (natural domain per
  instance, computed before `commitments_with_opening_points`).
- Verification: composed identity block vs independent pin vectors - ALL
  deterministic parts (nodes/roots/consts/domains/inv_d) match exactly; opened
  shapes match per instance. ConstraintIdentity.t.sol passes on regenerated
  JSON (fold pin 40.2M gas, selectors pin 4.6M). Fib bundle regenerated from
  the fresh run (1,875,624 B); WhirVerifier.t.sol 6/6 green.

### Gate status (pre-existing, NOT introduced here)
`cargo clippy --workspace --all-targets -- -D warnings` fails with 136 errors
concentrated in prover TEST targets (batch_stark_vectors 49, composed_vectors
124 incl. overlap, whir_proof_vectors 17, constraint_identity_vectors 17):
missing backticks in docs, pub(crate)-in-private-module (private_module),
dead code in batch_fixture when a consumer target doesn't use every helper,
pedantic style lints. These predate this step (whir_walk/batch_stark_vectors
untouched here). Decision: fix them as a dedicated lint-hygiene commit before
the final full gate; do not suppress. The per-target clippy on the files this
step touched is clean apart from the same families.

### Next (D-076 part 3)
1. Bundle v4: CONSTRAINTS section (header version 4, `cst_words` u32 LE @16)
   in gen_composed_flat.mjs / gen_bundle.mjs + WhirVerifier decode.
2. Wire ConstraintIdentity into WhirVerifier.verify: capture constraintAlpha
   from permutationPhase + zeta from oodPhase (currently discarded); derive
   opened values from round-0 claim evals (boundEvals x exported scales);
   perm challenges via BatchTranscript.lookupPair + bus layout; perm values =
   terminals (already on the wire); pv from blob; periodic empty.
3. Regenerate fib vectors+bundle, pin + WhirVerifier green; then block
   vectors+bundle (background), BlockE2E green with identity.

## D-076 wiring — pinned derivation rules (numerically verified this session)

The last soundness gap: the contract must recompute the constraint identity
`fold(alpha, C(zeta)) * inv_vanishing(zeta) == quotient(zeta)` per instance,
from opened values it DERIVES (never proof-supplied). All rules below were
verified numerically against `composed_vectors.json` (fib run, all 6
instances, all rounds) with a standalone JS model:

1. **Claimed openings**: `claimed = boundEval * scale(k, point)` element-wise,
   where k = padded arity of the matrix, point = the claim's point, and
   `scale(k, z) = prod_{i<k}(1 + z^{2^i})` in EF4. (This is the export's own
   rescale assert, composed_vectors.rs:361.)
2. **MAIN (round 1) / PREPROCESSED (round 3)**: opened == claimed element-wise
   (ext values). local claims at zeta, next claims at zeta_next.
3. **QUOTIENT (round 2) / PERMUTATION (round 4)**: opened = `fromExt` of each
   group of 4 claimed ext values: Horner at x (the EF4 element [0,1,0,0],
   packed 1<<192): `acc = ((c3*x + c2)*x + c1)*x + c0`. Verified for all 32
   quotient claims and all 12 perm claims.
4. **zeta_next** = zeta * twoAdicGenerator(trace_domain.log_size). Verified.
5. **Claim order**: matrix-major then point (schedule order). Matrix
   boundaries = eq_points_lens (points per matrix). Claim j spans
   claim_widths[j] ext values of boundEvals.
6. **Round→instance map**: rounds 1/3/4 matrix i == instance i; round 2
   matrices grouped by instance, num_chunks[i] consecutive each.
7. **Perm challenges**: per lookup k of instance i: `[prefix(bus_k), beta]`,
   `prefix = lookupAlpha + (bus_k + 1) * beta^W`, W = max_message_width.
   (transcript.rs lay_out_lookup_challenges; prefix formula verified for all
   instances against the export.)
8. **Perm values**: 1 terminal (t.0) per instance with terminal_counts[i];
   terminals are proof-supplied and already sum-checked to zero.
9. **Public values**: statement array for statement_instance only, else empty.
   **Periodic values**: empty at this shape; contract fails closed if a
   program references OP_PERIODIC with an empty array.

## D-076 wiring plan (in progress)

- [x] CONSTRAINTS section v4 in gen_bundle (programs, domains, inv_d, flags,
      per-round arities). EXTENDING now: + bus_ids, max_message_width,
      terminal_counts (needed for perm challenges / perm values).
- [ ] WhirVerifier: accept version 4; decode CONSTRAINTS tail after the round
      loop; capture (lookupAlpha, beta) from lookupPhase, constraintAlpha from
      permutationPhase, zeta from oodPhase; save RoundPrf per round; after the
      round loop derive opened values per instance (rules 1-9) and assert
      fold*invVanishing == recomposeQuotient per instance via
      ConstraintIdentity.
- [ ] WhirVerifier.t.sol green (positive tests now enforce the identity).
- [ ] Regenerate block vectors + bundle; BlockE2E green with identity.
- [ ] Full gate.

Decision: round roles are positional (0 random, 1 main, 2 quotient, 3 pre,
4 perm) and pinned by numRounds == 5 check; alternatives considered: role tags
on the wire (rejected: CONFIG is trusted setup anyway, tags add drift risk).
Decision: fail closed on periodic columns (fib/block have none); shipping
periodic column definitions is a later milestone if any AIR needs them.

### Derivation pipeline — FINAL pinned form (brute-force verified, fib shape)

- `RoundPrf.boundEvals` (packed ext) are in **matrix-major claim order** (NOT
  the walk's arity-sorted claim order; `claim_perm` is walk-internal and not
  needed here). Verified by brute-force offset search for all 4 rounds:
  offsets are exactly the cumulative claim widths.
- Claim j: width cw[j] ext values at offset sum(cw[..j]); matrix = instance
  order (rounds 1/3/4: 1 claim per instance + 1 more if has_next; round 2:
  num_chunks[i] claims of width 4 each); arity from CONSTRAINTS per-round
  arities; point = zeta (first claim of the matrix) or zeta_next_i =
  zeta * twoAdicGenerator(trace_log_size[i]) (second claim).
- claimed = bound * scale(arity, point) element-wise.
- MAIN/PRE opened = claimed element-wise.
- QUOT/PERM opened = fromExt over each 4 consecutive claimed ext values
  (Horner at x = 1<<192 packed).
- Claim widths per round (fib): r1 [4,4,76,76,166,166,4,3] (= main widths,
  next-claims repeated), r2 all 4s, r3 [6,2,59,59,24,24,10,4] (= pre widths),
  r4 [8,8,8,8,28,28,16,16,24,24,16,16] (= 4 * aux_width per claim).
- Perm challenges: per lookup k of instance i: [prefix, beta], prefix =
  lookupAlpha + (bus_k + 1) * beta^W (verified for all instances).
- Perm values: terminals in order of instances with terminal_counts[i].

## D-076 CLOSED — constraint identity enforced on-chain

Wire v4: CONSTRAINTS section (trusted setup) appended to CONFIG: per-instance
flattened AIR program (nodes/base/ext consts/roots), claim-layout flags
(width/pre/aux widths, has_main_next/has_pre_next), trace + chunk domains,
inv_d, statement_instance, bus layout (max_message_width, per-instance bus
ids, terminal flags), per-round claim-group arities.

WhirVerifier.verify now:
- accepts version 4 only;
- captures (lookupAlpha, beta), constraintAlpha, zeta from the batch
  transcript phases;
- keeps each round's boundEvals;
- decodes CONSTRAINTS after the round loop (cursor at CONFIG tail);
- derives every opened value from bound_evals x scale(arity, point) —
  matrix-major claim order (pinned: identity mapping, claim_perm is
  walk-internal), per-instance zeta_next = zeta * twoAdicGenerator(log_i);
  MAIN/PRE element-wise, QUOT/PERM via fromExt4 Horner at x over 4-groups;
  perm challenges [lookupAlpha + (bus+1)*beta^W, beta]; perm values = the
  LogUp terminals in terminal_counts order; public values = the plain
  calldata statement on statement_instance (NOT montgomery — pinned);
- asserts fold(alpha, C(zeta)) * inv_vanishing(zeta) == recomposeQuotient
  per instance (ConstraintIdentity.sol), reverting
  ConstraintIdentityMismatch(i).

Pinned gotchas this session:
- bound_evals are in matrix-major claim order, NOT the walk's arity-sorted
  claim order (brute-force offset search over all 4 rounds: offsets are the
  cumulative claim widths, all match).
- public values are plain base values (foldConstraints lifts them); the
  calldata statement is plain too (pv-bytes check monts it).
- extConsts/inv_d on the wire are flat u32 limbs (pushArr), packed 4-to-1 in
  Solidity (_packQuartics), NOT the raw32 packed form.
- round 2 arities are per-claim (one matrix per quotient chunk).

Tests: fib WhirVerifier 6/6 (accepts real proof, 1.064B gas); full forge
suite 128/128 incl. BlockE2E with the regenerated v4 block bundle (2.83 MB,
constraints 30,887 words). Real block apply gas ~1.6B (unchanged shape).
