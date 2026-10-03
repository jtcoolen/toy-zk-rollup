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
| M5 | Batch STARK transcript layer (commitment/OOD/quotient/degree) | pending |
| M6 | `ConstraintIdentity.sol` (generated AIR constraint identity) | pending |
| M7 | `ChunkVerifier.sol` (multi-transaction sponge carry) | pending |
| M8 | Gas benchmark + EIP-170 audit + size reductions | pending |
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
