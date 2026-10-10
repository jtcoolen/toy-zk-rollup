# h03-preprocessed-to-witness — status: implemented

## Decision

H-03: the transfer circuit bakes note-specific values into preprocessed
columns (public, unblinded), so the sequencer who receives the client's
`CircuitVerifier` can recover the spent leaf position and the recipient
`pk_d`. Fix: move **every note- and tree-specific value** out of
`define_const` and into either (a) private witnesses — membership siblings,
nullifier-map siblings, recipient `pk_d` — or (b) witness-backed *statement
exports* for values that are public anyway — `root_before`, `root_after` pin,
`nullifier_roots.before/after`. The statement bytes are unchanged (same
limbs, same order); only their circuit provenance changes from constant to
witness expression, exactly the pattern `root_after`, the nullifiers, the
output commitments and the fee already use.

Rejected: blinding the preprocessed columns (upstream change; the VK must be
shareable per shape regardless); leaving the roots as constants (tree-specific
values ⇒ VK varies per transfer, which defeats the "one VK per shape" that
V-06's `constrain_trusted_preprocessing` requires).

Side effect that is the real prize: after this, the transfer circuit's
preprocessed data depends only on the *shape* (spend/output counts), which is
the prerequisite V-06 needs to pin a child's preprocessing by digest.

## Changes

- `crates/prover/src/transfer.rs` `fold_membership_p2` — siblings become
  `alloc_private_inputs(2)` per level (digest_to_ext → witness), mirroring
  the frontier-slot pattern in `commitment_gadget::constrain_append`. Index
  bits already witnesses.
- `crates/prover/src/transfer.rs` `constrain_outputs` — recipient `pk_d`
  becomes a `Secret`-style range-checked limb witness instead of
  `const_limbs`. Sound: the commitment is computed from the limbs and
  exported to the statement; value conservation is on amounts, spendability
  is enforced at spend time by the ownership check.
- `crates/prover/src/transfer.rs` `constrain_inputs_and_outputs` —
  `root_before`, `nf_before`, `nf_after` pins become ext witnesses
  (`alloc_private_inputs(2)`), exported to the statement via
  `export_digest_limbs` (same limbs as the old `const_limbs`); the
  `root_after` build-time pin compares against witness limbs instead of
  constants. Statement values unchanged.
- `crates/prover/src/nullifier_gadget.rs` `fold_up` — takes built
  `DigestExpr` siblings; `constrain_nullifier_non_membership` builds
  `witness.siblings` as witnesses (shared by both folds), keeps the
  empty-subtree `start` and `lower_empties` as constants (public,
  shape-level, identical for every transfer).
- `crates/prover/tests/h03_vk_uniformity.rs` — negative test (below).
- Regenerate the settlement-family vectors + update the four pins: the rc
  gadget bakes the child's table shapes, so the block CONFIG digest moves
  again (same drill as V-07).

## Invariants

- The statement encoding is byte-identical to before:
  `[nullifiers, output commitments, root_before, root_after,
  nf_before, nf_after, fee]` (D-088 layout). The block circuit's statement
  binding and the contract's checks are untouched.
- Preprocessed constants may only hold values that are identical for every
  transfer of the same shape (domain tags, empty-subtree digests, balance
  constants).
- The client transfer proof stays ZK (InSC blinding), so the new witnesses
  are hidden from the sequencer.

## Acceptance

1. **First to write** `h03_vk_uniformity.rs::preprocessed_is_shape_only`:
   build two 1-in/1-out transfer circuits against different trees (different
   spent positions, different recipient keys, different roots); assert the
   circuits' preprocessed constant data is identical. Fails today (siblings,
   `pk_d`, roots differ per instance); passes after the fix.
2. `h03_vk_uniformity.rs::tampered_membership_sibling_rejected`: honest
   transfer proves and verifies; replacing one sibling in the membership path
   with a foreign digest makes the fold fail to reach the pinned root (build
   or verify rejects).
3. Existing transfer/nullifier tests green; `cargo test -p prover`; forge
   197/197 after vector regen + pin update.

## Open questions (resolved)

- Resolved: const values are read by scanning `circuit.ops` for
  `Op::Const` (`TransferCircuit::census_consts()`); `generate_preprocessed_columns`
  needs the `D` parameter and is not needed.
- Resolved: `export_digest_limbs` on witness-backed ext expressions works —
  same decomposition path as fold outputs, and the block/contract statement
  checks pass on the regenerated vectors.
- Note: the witness roots each get a `claim_private` (mul-by-one creator row)
  so a spend-less or output-less transfer still witnesses: a bare private
  input feeding only lookup tables has no creator row and the bus rejects.
