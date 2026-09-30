# 07 - EVM settlement: a Solidity FRI-STARK verifier, no bridge

Type: grilling
Status: resolved
Blocked by: 01, 02, 03

## Question

No SNARKs are allowed, so the L1 cannot verify a STARK by wrapping it. How does an
EVM chain actually check the rollup?

## Answer

**A Solidity verifier that checks the FRI-STARK directly**, using the Keccak-256
precompile for the Merkle/FRI layer.

### Why this is feasible at all

A raw STARK is far too large to verify on L1. The recursion layers exist precisely to
shrink it: each `p3-batch-stark` layer verifies the previous proof(s) and produces a
smaller, constant-shaped one. After enough layers the final proof is a handful of
FRI authentication paths plus a small final polynomial — small enough that a Solidity
loop over ~150–250 queries at ~60k gas per Keccak precompile call lands in the
**1–3M gas** range. That is a normal transaction.

### What the verifier checks

1. Recompute Fiat-Shamir challenges from the public inputs + commitments
   (Poseidon2 in-circuit on the prover side; on the EVM side the challenge schedule
   must match — see the transcript portability ticket).
2. Verify each FRI query's Merkle authentication path with `keccak256` (`0x20`).
3. Check the DEEP/quotient polynomial identity at the challenge points.
4. Check the constraint evaluation against the public inputs.
5. Check the public inputs themselves: old state root, new state root,
   nullifier root, batch commitment, chain id.

### Rejected

- **Multisig / committee bridge.** Cheap, but it is not a rollup — it is a custodial
  sidechain with a proof attached for show. Violates trust-minimization.
- **Wait for an audited third-party STARK verifier.** None exists for our exact
  config (KoalaBear + quintic + Keccak PCS + this recursion shape). Blocking on it
  blocks the whole map.

### The honest cost

We are writing a STARK verifier in Solidity. That is the single most security-critical
piece of code in the project and it is **not** off-the-shelf for our configuration.
It is scoped as its own ticket with its own review bar, and the foundation ships a
skeleton with the ABI fixed so the Rust and Solidity sides cannot drift.

### ABI is the contract

The proof encoding between `pq-prover` and the Solidity verifier is versioned and
generated from one schema. A mismatch must fail loudly at the boundary, never silently
verify the wrong thing.
