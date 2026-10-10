# v07-poseidon2-sponge-binding — status: approved

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

## Changes
- crates/prover/src/commitment_gadget.rs -> p2_compress: define zero const; inputs[2]=inputs[3]=Some(zero).
- crates/prover/src/commitment_gadget.rs -> p2_sponge_limbs: when is_first, inputs[2]=inputs[3]=Some(zero); else None.
- crates/prover/src/commitment_gadget.rs -> partial-chunk tail: decompose_ext_to_base_coeffs_with_coeff_lookups + recompose_base_coeffs_to_ext_with_coeff_lookups (same form on both sides of a value; never mix ALU and coeff-lookup decomposition on one expr).
- crates/prover/src/block.rs -> ensure builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>) if prepare_circuit does not already enable it (spike).
- crates/prover/tests/ (or gadget test module) -> negative test: AIR rejects a chain-start row with non-zero capacity (assert_air_rejects) + honest gadget tests still match native digests.
- test/vectors/* -> regenerate ALL settlement-family vectors (wbnd_pin::regenerate_committed_bundles) + Deploy.s.sol CONFIG_DIGEST update (circuit change shifts CONFIG digest).

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
- spike: does PcsRecursionBackend::prepare_circuit already call enable_recompose on the
  block-circuit builder? (block.rs has no own call; whir/verifier.rs:996/1194 enable it
  for their own circuits.) Answer by compiling a spike that calls the coeff-lookup
  builder in block.rs and seeing RecomposeCoeffLookupsUnavailable at build time.
- spike: does decompose_ext_to_base_coeffs_with_coeff_lookups error (CoefficientsNotBaseBound)
  when fed an expr that already carries an ALU-recorded decomposition (fold_statement
  path)? If yes, switch fold_statement's running-digest decompose to the same form.
- ask user: optional length/domain tag on the sponge (extra security margin) — in scope now or skip?
