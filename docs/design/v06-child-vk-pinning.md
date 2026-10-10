# V-06 — child verifying key pinned in the block circuit — status: implemented

## Decision
`verify_trusted_p3_batch_proof_circuit` allocates the child's preprocessed commitment
(its verifying-key digest) as a *free public-input witness* (`CommonDataTargets::new`
-> `MerkleCapTargets::new` -> `alloc_public_input_array`) and nothing constrains it.
The child `CircuitVerifier` reaching `build_multi_transfer_circuit` is **client-supplied
and untrusted** (`ClientTransferProof.verifier`: the sequencer stores it, verifies
natively with it, then feeds it to the block circuit), so an attacker can build a
weaker same-shape circuit C', prove on C', and hand verifier(C') + proof(C') to the
sequencer — accepted natively and in-circuit, where the free targets absorb C's root.
Worse than the commitment: `verify_trusted_p3_batch_proof_circuit` first runs
`verifier.verify(proof, statement)` natively and then builds its in-circuit tables
from **the supplied verifier's own relation and AIRs** (`trusted_batch_tables` reads
`verifier.relation()`, `verifier.table_airs()`, `verifier.config()`). Pinning only the
preprocessed commitment does not bind the constraint set — a circuit C' with identical
preprocessed columns but weaker AIRs shares the commitment.
Fix: the block circuit verifies each child against a **canonical verifier the prover
builds itself**, never the client's object:
1. **Canonical construction**: `canonical_child_verifier(inner, shape)` builds a
   deterministic witness-free fixture of the shape and `prepare`s it (no prove) under
   the block's own inner config, yielding the canonical `CircuitVerifier` + its
   preprocessed-commitment pin. One per shape (memo map, pre-pass).
2. **Native**: per child, reject unless the supplied verifier's preprocessed commitment
   equals the canonical pin **and** `child.verifier.relation() == canonical.relation()`
   (`CircuitRelation: PartialEq`). The client's proof is then verified *by the canonical
   verifier* — `verify_trusted_p3_batch_proof_circuit(&child_verifier, ...)`, statement
   packing, and the witness replay all read from the canonical object, so the supplied
   verifier influences nothing after the equality checks.
3. **In-circuit**: constrain the child's preprocessed targets to the canonical
   `MerkleCap` via `MerkleCapTargets::constrain_constant`, so the on-chain block proof
   itself — not just this native build step — attests the child verified under the
   pinned key, even if the native check is bypassed (the prover of the block proof is
   untrusted).
Rejected: pinning only the commitment — a constraint-dropping forge shares the commitment; the relation check closes that half (native only — the recursion API cannot pin an AIR set in-circuit). Rejected: pinning the targets to the *supplied verifier's own* commitment — vacuous
against the forged-verifier attack (the value to pin against must not come from the
untrusted input). Rejected: calling `constrain_trusted_preprocessing` — needs the
backend's `CheckedVerifierResult`, which this lower-level call path does not produce.
Prerequisite met by H-03: the transfer VK is uniform per shape, so a canonical
per-shape value exists.

## Changes
- `vendor/p3-recursion/recursion/src/public_inputs.rs` -> `pub fn preprocessed_commit_targets(&self) -> Option<&Comm>` on `BatchStarkVerifierInputsBuilder` (exposes the `pub(crate)` `common_data.preprocessed.commitment`).
- `crates/prover/src/block.rs` -> new `canonical_child_verifier(inner, shape) -> (CircuitVerifier<InnerWhirConfig>, MerkleCap)` (deterministic fixture + `prepare_transfer_circuit_with`, no prove) + `canonical_child_preprocessed` wrapper; pre-pass memo map keyed by shape; native preprocessed-commitment **and relation** equality checks per child; the in-circuit verifier, statement packing, and witness replay all use the canonical verifier; in-circuit `constrain_constant` after `verify_trusted_p3_batch_proof_circuit`.
- `crates/prover/src/transfer.rs` -> split `prepare_transfer_circuit_with` (prepare-only, returns `PreparedCircuitProver`) out of `settle_transfer_circuit_with`; `TransferCircuit` retains its private inputs + `#[doc(hidden)] forge_append_const_for_test` hook for the V-06 negative test.
- `crates/node/src/sequencer.rs` -> `submit()` admission hardened: the sequencer builds (and caches per shape) the canonical verifier itself, rejects a submission whose verifying key differs (`NonCanonicalVerifier`), and verifies the proof against the canonical verifier — not the client's. Without this a forged VK passes admission (it verifies with its own key) and then kills every batch it is drained into at settle time: batch griefing. `settle_batch` -> `build_multi_transfer_circuit` remains the enforcement point of record.
- `crates/prover/tests/v06_child_vk_pinned.rs` -> new tests (below).
- vectors + pins -> the in-circuit const adds `alloc_const` ops to the block circuit: block CONFIG digest moves and the settlement/chain VKs may move too; regenerate the whole settlement family and update the four pin sites + RecursionChainE2E/GasProfile digests + TerminalClaim constants as in H-03.

## Invariants
- Inside the block circuit, the preprocessed root authenticating every child's fixed-column
  openings is a constant equal to the canonical per-shape child VK digest — never a witness.
- The canonical value is derived from trusted code (deterministic fixture + prepare), never
  from the supplied verifier object.
- Statement layout unchanged (D-088): `[nullifiers…, outputs…, root, root_after, nf_before, nf_after, fee]`.
- The block CONFIG digest transitively pins each child shape's VK digest.

## Acceptance
1. (first to write) `child_proof_under_forged_vk_rejected` — **green**: a same-shape
   child circuit with one extra unused `Op::Const` (`forge_append_const_for_test`) —
   a genuinely different relation + preprocessed commitment whose proof still verifies
   under its own verifier — must fail `build_multi_transfer_circuit` with an error
   naming the canonical mismatch. Pre-fix: built fine (free witness absorbed the forged
   root).
2. `canonical_pin_matches_honest_client_verifiers` — **green**: the canonical pin equals
   the preprocessed commitment carried by honest clients' verifiers for two different
   same-shape fixtures (guards H-03 uniformity and the fixture's fidelity).
3. `honest_block_still_builds_under_the_pin` — **green**: honest child builds the block
   circuit under the pin (positive control).
4. `submit_rejects_a_forged_verifier_at_admission` (crates/node/tests/sequencer.rs) —
   **green**: the forged-VK transfer is rejected at `submit()` with
   `NonCanonicalVerifier` and the mempool stays empty.
5. Existing block/whir_recursion/composed_vectors tests green (modulo known grind
   flakes); forge 197/197 after regen.

## Open questions
- answered: forge candidate = extra-const hook (a different inner config would also
  change the proof shape and could reject for schedule reasons — the extra unused
  `Op::Const` keeps everything else identical).
- answered: prepare-only cost per shape is small (no prove); memo map per build call,
  no cross-call cache needed yet.
- follow-up (separate commit): `build_batch_recursion_circuit` has the same free-target
  shape, but its child verifier is built by the prover itself (not client-supplied) and
  the chain CONFIG pin covers it; add an explicit `expected_child_preprocessed` parameter
  there when the chain crosses a trust boundary.
