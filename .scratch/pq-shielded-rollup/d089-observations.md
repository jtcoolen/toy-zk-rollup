# D-089 observations — folded statement root for client public inputs

Directive: "add the folded hash for the client proofs public inputs during
the recursion to expose one public input root for the client proof public
inputs in final recursive proof".

## What landed

1. **Gadget** (`commitment_gadget::fold_statement`): `running_i =
   p2_sponge(running_{i-1} ‖ child_i statement limbs)`, seeded with the zero
   digest. One Poseidon2 permutation per 8 limbs; the fold input prepends the
   running digest decomposed to 8 base coeffs via ALU. Pinned element-for-element
   against the native sponge by `fold_statement_matches_native` (children of 100
   and 68 limbs — the second fold input is 8+68=76, ending mid-chunk, which pins
   the partial-chunk carry path), and `fold_rejects_tampered_statement` proves a
   one-limb change moves the root.

2. **Block circuit** (`block.rs`): the export is now
   `[header(1+2n), statementRoot(16), rootBefore, rootAfter, nfBefore, nfAfter
   (4×16), fee_0(4)…fee_n(4)]` = **81 + 6n limbs** (n=1: 87, was 103; n=2: 93,
   was 205). The fold consumes `verifier_inputs.air_public_targets[statement_instance]`
   — the same targets the in-circuit verifier constrained against each child
   proof — so the exported root binds to the *verified* public inputs, not a
   re-declared copy. Endpoint digests come from new `endpoints()` on the two
   chains (first child's before + last child's after). Fees are read at
   `shape.fee_offset()` and flattened.

3. **Shared native builder** `block::block_statement(shapes, statements)` +
   `fold_statement_native` + `block_statement_len`: the node sequencer, both
   vector generators, and the tests all call it. The node's local copy is gone.

4. **Contract**: `BlockStatement.decode` parses the folded shape;
   `expectedLen(n) = 81 + 6n`; `Block` carries `statementRoot` +
   `numTransfers` + the four digests + `totalFee`. ShieldedPool's apply logic
   is unchanged (continuity + store + emit) — the fold is opaque on-chain by
   design, pinned as a public input the proof attests, same trust model as
   rootAfter. Fixed a duplicated `currentNullifierRoot` write found during the
   rewrite.

## Measurements (measured, not estimated)

- Bundle: 2,964,384 → **2,825,568 B** (statement 103→87 limbs; stm words 769).
- Composed blob: 157,674 → 152,490 B.
- applyBlock e2e gas: 353,975,800 → **331,676,714** (−22.3M; the statement
  calldata shrank and the pv section of the bundle is 16 words shorter).
- Verifier gas pin unchanged in kind (WhirVerifier unchanged).

## Decisions

- **Poseidon2, not Keccak, for the fold.** The contract never opens it; only
  in-circuit cost matters, and the P2 perm tables are already in the block
  circuit. A Keccak fold would need the in-circuit Keccak gadget for zero gain.
- **Fees stay flattened** (4 limbs per transfer) rather than folded-only: the
  pool accrues `totalFee` and must be able to audit it per transfer without
  opening the fold. 4n limbs is negligible.
- **Header keeps (nin, nout) per transfer** even though the decoder no longer
  walks child statements: it is part of what the circuit proved (constants),
  the length check pins it, and dropping it would change the shape header API
  every consumer already uses. Lean: no churn without a security reason.
- **Old per-transfer decode-chain test dropped** (`test_decode_rejects_a_
  broken_commitment_chain`): with the fold there are no per-transfer digests to
  chain on-chain — the chain lives entirely in-circuit now. Replaced by
  `test_decode_rejects_a_length_that_disagrees_with_the_header` (short/padded/
  lying-n) and the statementRoot pin tests.

## Vector/bundle regeneration path (all green)

- `cargo test -p prover --test golden_vectors block_vectors -- --ignored`
- `cargo test -p prover --test composed_vectors block_program_equality_and_export -- --ignored`
- `node contracts/scripts/gen_composed_flat.mjs block_composed_vectors block_composed_flat`
  then `gen_bundle.mjs block_composed_flat block_composed_vectors block_composed_bundle`
  — NOTE: these scripts resolve paths from the REPO ROOT, run them from there.
- BlockE2E termWord pv_len 103 → 87.
- forge suite: 131/131 green. prover lib block:: 4/4. node sequencer 4/4.

## Follow-ups noticed

- The ShieldedPool.t.sol replay test now reverts on the verbatim stale block
  (RootMismatch with args) — cleaner than the old rewritten-roots version.
- D-090 (e2e through the MV3 extension) should exercise produce→settle with
  the folded statement end-to-end; the statement shape is now stable.
