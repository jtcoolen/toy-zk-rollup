# STATE — resume pointer

- Current task card: docs/design/v07-poseidon2-sponge-binding.md (status: approved)
- Task: audit fix V-07 — pin in-circuit Poseidon2 sponge chain start (capacity slots)
  and base-bound the partial-chunk tail in crates/prover/src/commitment_gadget.rs.
- Remaining audit findings after V-07: V-08, H-02, H-03 (before V-06), V-06,
  M-01 (pool-address half), M-06..M-10.
- Last gate: forge 197/197 @ d5dd132 (M-11); canonical test cmd: plain
  `cargo test -p prover` (optimized dev profile; NOT --release).
- Next action: write the failing negative test from the task card's Acceptance
  section (AIR-level assert_air_rejects on a non-zero-capacity chain start),
  then implement the fix.
- After any circuit change: regenerate ALL settlement-family vectors together
  and update Deploy.s.sol CONFIG_DIGEST, then full forge suite.
