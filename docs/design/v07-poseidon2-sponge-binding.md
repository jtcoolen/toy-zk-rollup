# v07-poseidon2-sponge-binding — status: implemented

## Decision
The in-circuit Poseidon2 sponge (crates/prover/src/commitment_gadget.rs) leaves its
chain-start capacity slots unconstrained: ordinary (non-shared, non-challenger) perm
rows with new_start get a free IV, and the partial-chunk tail recomposes via the ALU
path which ties only the weighted sum, leaving D-1 free dims per coeff. Both let a
malicious prover fork one sponge (e.g. nf = H(DOMAIN_NULLIFIER || sk_d || rho)) into
many digests. Fix: (1) on every first row of a gadget sponge, pass Some(zero) for the
two capacity input slots so the witness bus pins capacity to zero (continuation rows
keep None so normal_chain_sel chains capacity from the previous output); (2) replace
the ALU decompose/recompose pair on the partial-chunk tail with the
_with_coeff_lookups variants, which publish each coeff as base-bound. Rejected: making
the tables shared/challenger-role (changes global AIR roles, breaks other gadgets);
adding a length tag now (optional hardening, tracked as open question).

## Changes (as implemented)
- crates/prover/src/commitment_gadget.rs -> p2_sponge_limbs: when is_first, inputs[DIGEST_EXT..] = Some(zero); else None (continuation rows chain capacity from the previous output).
- crates/prover/src/commitment_gadget.rs -> partial-chunk tail: decompose_ext_to_base_coeffs_with_coeff_lookups + recompose_base_coeffs_to_ext_with_coeff_lookups (same form on both sides of a value; never mix ALU and coeff-lookup decomposition on one expr).
- p2_compress: NO change needed — all four slots are already Some(...) (arity-2 compress; the right operand occupies the capacity slots), so V-07 does not apply.
- block.rs: NO change needed — PcsRecursionBackend::prepare_circuit -> InnerWhirConfig::prepare_circuit_for_verification (crates/prover/src/whir_recursion.rs:409-418) already calls enable_poseidon2_perm + enable_recompose::<F>(generate_recompose_trace::<F, Challenge>).
- fold_statement: NO change needed — its ALU-decomposed running-digest coeffs are base-embedded consts, so the sponge's coeff-lookup recompose accepts them (no CoefficientsNotBaseBound).
- crates/prover/tests/v07_sponge_chain_start.rs -> proof-level negative test (real WHIR prove/verify, not just AIR): forges the chain-start capacity in the Poseidon2 trace + bus witnesses and asserts rejection; honest sponge proves. (AIR-only assert_air_rejects was insufficient: the forgery must survive the bus/table consistency to be a soundness test.)
- crates/prover/Cargo.toml -> dev-dependency p3-test-utils (workspace) for the rejection-oracle harness.
- test/vectors/* -> regenerated ALL settlement-family vectors (chain v5/v6/v7/v8 + composed + block + constraint_identity + wbnd_pin re-encode) + pin updates in Deploy.s.sol, BlockE2E.t.sol, WhirVerifier.t.sol, AuditRegression.t.sol. Only the BLOCK CONFIG moved: 0x7d61ae57... (was 0xf9e90586...); settlement (ffb29fe8) and chain (ddd87cbe) unchanged.

## Invariants
- INV-P2-CHAIN: every gadget sponge's first perm row has capacity == 0; continuation rows chain capacity from previous output (normal_chain_sel).
- INV-P2-TAIL: every recompose feeding a perm input is base-bound (coeff lookups), not free-dim ALU.
- INV-CONFIG-PIN: on-chain CONFIG_DIGEST (Deploy.s.sol) equals keccak of the shipped CONFIG section; any circuit change regenerates vectors + pin together.
- Audit ref: V-07 (Critical), audit of a54c197.

## Acceptance
1. FIRST TO WRITE (negative, currently fails): AIR-level test — build a challenger-role
   Poseidon2CircuitAir (KOALA_BEAR_D4_W16) with a 2-row chain whose FIRST row has
   capacity slots non-zero; assert_air_rejects. Mirror of upstream
   a_non_challenger_table_leaves_its_chain_start_capacity_free (vendor/p3-recursion/poseidon2-circuit-air/src/air.rs:2421) but asserting the PINNED behavior after fix.
2. circuit_compress_matches_native / circuit_sponge_matches_native still pass (honest digests unchanged).
3. Gadget-level regression: a tampered first-row capacity makes the circuit run fail or the on-chain-equivalent digest differ (native check).
4. Full forge suite 197/197 after vector regeneration + Deploy.s.sol pin update.
5. cargo test -p prover green (optimized dev, plain command, retry loop for grind flake).

## Open questions
- RESOLVED (read whir_recursion.rs:409-418): prepare_circuit_for_verification already
  enables poseidon2 perm + recompose on the block-circuit builder. No block.rs change.
- RESOLVED (test run): fold_statement's ALU coeffs are base-bound, so the coeff-lookup
  recompose accepts them; no CoefficientsNotBaseBound in the full suite.
- ask user: optional length/domain tag on the sponge (extra security margin) — in scope now or skip?
