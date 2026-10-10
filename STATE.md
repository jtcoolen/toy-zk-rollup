# STATE — resume pointer

- Done: H-03 (transfer preprocessed constants -> witnesses) committed;
  design doc docs/design/h03-preprocessed-to-witness.md status: implemented.
- Next task: V-06 — constrain_trusted_preprocessing / constrain_constant on
  the child's preprocessed commitment (block.rs + whir_recursion.rs).
  H-03 made the transfer VK uniform per shape, which is its prerequisite.
- Remaining audit findings: V-08, H-02, V-06, M-01 (pool-address half),
  M-06..M-10.
- Last gate: forge 197/197; prover green modulo grind flake; v8 bundle
  263,500 B; test_gas_v8 41,749,534; test_gas_v7 41,539,017.
  Block CONFIG digest now 0xb46b4403... (4 pin sites updated).
- Known pre-existing flakes (NOT regressions): grind PoW at
  grinding_challenger.rs:304 (~10%/proof) — retry loops mandatory;
  hvzk_blinding::settlement_proving_is_deterministic fails ~30% at BASELINE
  too (measured 3/8 without the V-07 change) — grind nonce divergence.
- Canonical test cmd: plain `cargo test -p prover` (optimized dev; NOT
  --release — trips proving_keeps_overflow_checks_on). Vector regen needs
  --release + canonical WHIR_* env (see ledger Batch 89/91/92; script
  /tmp/regen_v07.sh reusable).
- After any circuit change: regenerate ALL settlement-family vectors together,
  recompute CONFIG digests (cast keccak of bundle[16..16+cfgWords*4];
  v6-v8 chain bundles carry cfgWords=0 — digest is the v5 CONFIG),
  update pins (Deploy.s.sol, BlockE2E, WhirVerifier, AuditRegression),
  full forge suite.
