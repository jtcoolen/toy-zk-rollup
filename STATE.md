# STATE — resume pointer

- Done: V-06 (child verifying key pinned: canonical per-shape verifier built
  by the block circuit; native commitment+relation checks; in-circuit
  constrain_constant) — design doc docs/design/v06-child-vk-pinning.md
  status: implemented. Ledger Batch 93.
- Next task: V-08 — binary Merkle leaf/index binding in the Poseidon2 circuit
  AIR (upstream-shaped). Then H-02, M-01 (pool-address half), M-06..M-10.
- Remaining audit findings: V-08, H-02, M-01 (pool-address half), M-06..M-10.
- Last gate: forge 197/197; prover green modulo grind flake; v8 bundle
  262,828 B; test_gas_v8 41,705,849; test_gas_v7 41,548,254.
  Block CONFIG digest now 0x9d97d952... (4 pin sites + 2 TerminalClaim
  constants updated).
- Known pre-existing flakes (NOT regressions): grind PoW at
  grinding_challenger.rs:304 (~10%/proof) — retry loops mandatory;
  hvzk_blinding::settlement_proving_is_deterministic fails ~30% at BASELINE
  too (measured 3/8 without the V-07 change) — grind nonce divergence.
- Canonical test cmd: plain `cargo test -p prover` (optimized dev; NOT
  --release — trips proving_keeps_overflow_checks_on). Vector regen needs
  --release + canonical WHIR_* env (see ledger Batch 89/91/92/93; script
  /tmp/regen_v07.sh reusable).
- After any circuit change: regenerate ALL settlement-family vectors together,
  recompute CONFIG digests (cast keccak of bundle[16..16+cfgWords*4];
  v6-v8 chain bundles carry cfgWords=0 — digest is the v5 CONFIG),
  update pins (Deploy.s.sol, BlockE2E, WhirVerifier, AuditRegression),
  full forge suite.
