# 12 - Solidity FRI-STARK verifier and the proof ABI

Type: task
Status: open
Blocked by: 07, 11

## Question

What exactly does the L1 verify, in what encoding, and how do we stop the Rust prover
and the Solidity verifier from drifting apart?

## Deliverables

1. **`ProofAbi`** — a single versioned schema for the final proof:
   `version`, `public_inputs[]`, `fri_commitments[]`, `fri_query_paths[]`,
   `final_poly_coeffs[]`, `quotient_commitment`. Defined once, code-generated (or at
   minimum round-trip tested) on both sides.
2. **`StarkVerifier.sol`** — verifies the FRI protocol against `keccak256`, checks the
   DEEP identity and the constraint evaluation.
3. **`ShieldedPool.sol`** — the settlement contract: holds the state root, the
   nullifier root, the batch accumulator; `verifyBatch(proof, publicInputs)` enforces
   the state transition and rejects double-spends.
4. **Vector tests** — Rust emits test vectors (JSON), Solidity consumes them and must
   reach the same accept/reject decision. This is the anti-drift mechanism.

## Security bar

This is the highest-assurance code in the project. Every `require` must be justified.
No unchecked arithmetic. Explicit overflow policy. Revert on any ambiguity.

## Known constraint

No SHA3 precompile on EVM. The verifier uses `keccak256` at `0x20` exclusively —
which is exactly why ticket 02 put Keccak in the Merkle/FRI layer.
