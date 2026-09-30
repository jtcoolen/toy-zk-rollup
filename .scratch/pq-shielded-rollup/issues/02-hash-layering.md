# 02 - Hash layering: which hash goes where

Type: grilling
Status: resolved
Blocked by: 01

## Question

The human prefers SHA-3, but the EVM has no SHA3 precompile — so a SHA3-256 Merkle tree
inside the FRI verifier costs ~70M+ gas in Solidity versus ~60k for Keccak-256.
Meanwhile the recursion engine hard-codes Poseidon2 in its transcript. Which hash goes
in which layer?

## Answer

**Layered split.** Three hashes, each chosen for the cost environment it runs in. The
rule that keeps them from bleeding into each other: *a layer's hash is chosen by where it
is verified, not by taste.*

| Layer | Hash | Why |
|---|---|---|
| **Shielded** — note commitment, nullifier derivation, viewing-key derivation | **SHA3-256** (target), **SHA-256** (compiles today) | Human preference; verified only in-circuit, so no EVM cost. Behind `ShieldedHasher` so the swap is config, not refactor. |
| **Commitment / Merkle / FRI** — the PCS layer the EVM walks | **Keccak-256** | Native `keccak256` precompile at `0x20`. Same Keccak-f[1600] core as SHA3, so PQ-equivalent. ~3 orders of magnitude cheaper on-chain than SHA3. |
| **Recursion transcript** — Fiat-Shamir inside the verifier circuit | **Poseidon2** | Granted exception (see [05](05-poseidon2-exception.md)). `p3-recursion`'s `CircuitChallenger` only downcasts to Poseidon1/2. |

### Why not the alternatives

- **SHA3 everywhere** (purest to preference): the Solidity FRI verifier must implement
  SHA3-256 in pure Solidity. Every FRI query verification is a Merkle path walk; at
  ~150 queries × ~32 hashes × ~3k gas, that is ~15M+ gas *per proof layer* before the
  constraint checks. Not viable.
- **SHA-256 everywhere** (cheapest, one hash): loses the SHA3 preference for no gain
  over the layered design, and still leaves Poseidon2 in the transcript anyway.

### The Keccak-vs-SHA3 distinction that makes this safe

SHA3-256 and Keccak-256 are the *same* Keccak-f[1600] permutation with different
domain-separation padding (`0x06` vs `0x01`). Both are PQ under the same assumption
(no structural break of Keccak). Choosing Keccak for the on-chain layer is a **gas**
decision, not a security downgrade. The shielded layer keeps SHA3 because it never
touches the EVM.

### Enforcement

`pq-crypto` exposes three distinct traits — `ShieldedHasher`, `CommitmentHasher`,
`TranscriptPerm` — so a layer cannot silently use another layer's hash. A test asserts
each layer is wired to the expected implementation.
