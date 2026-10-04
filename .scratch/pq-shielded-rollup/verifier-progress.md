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
| M8 | Gas benchmark + EIP-170 audit + size reductions (see D-068 reference list) | pending |
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
