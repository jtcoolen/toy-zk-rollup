# STATE — resume pointer

- Done: V-07 (Poseidon2 sponge chain-start pin + coeff-lookup tail) committed;
  design doc docs/design/v07-poseidon2-sponge-binding.md status: implemented.
- Next task: H-03 — move membership siblings + recipient pk_d from
  preprocessed constants to witnesses (prerequisite for V-06). Start by
  writing docs/design/h03-preprocessed-to-witness.md per AGENTS.md protocol.
- Remaining audit findings: V-08, H-02, H-03, V-06, M-01 (pool-address half),
  M-06..M-10.
- Last gate: forge 197/197; v8 bundle 262,060 B; test_gas_v8 41,653,563.
  Block CONFIG digest now 0x7d61ae57... (4 pin sites updated).
- Known pre-existing flakes (NOT regressions): grind PoW at
  grinding_challenger.rs:304 (~10%/proof) — retry loops mandatory;
  hvzk_blinding::settlement_proving_is_deterministic fails ~30% at BASELINE
  too (measured 3/8 without the V-07 change) — grind nonce divergence.
- Canonical test cmd: plain `cargo test -p prover` (optimized dev; NOT
  --release — trips proving_keeps_overflow_checks_on). Vector regen needs
  --release + canonical WHIR_* env (see ledger Batch 89/91).
- After any circuit change: regenerate ALL settlement-family vectors together,
  recompute CONFIG digests (cast keccak of bundle[16..16+cfgWords*4]),
  update pins (Deploy.s.sol, BlockE2E, WhirVerifier, AuditRegression),
  full forge suite.
