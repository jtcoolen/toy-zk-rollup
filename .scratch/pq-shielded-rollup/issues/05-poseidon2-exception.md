# 05 - The Poseidon2 exception is scoped to the recursion transcript

Type: grilling
Status: resolved
Blocked by: 02

## Question

The human said "no Poseidon." The recursion engine's in-circuit challenger only
supports Poseidon1/Poseidon2. How is that reconciled without letting Poseidon leak?

## Answer

**Granted by the human, scoped to one seam, enforced mechanically.**

### What was verified

`p3-recursion` abstracts the transcript hash behind a trait:

```rust
pub trait ChallengerPermConfig: Send + Sync {
    fn extension_degree(&self) -> usize;
    fn as_poseidon2(&self) -> Option<&Poseidon2Config> { None }
    fn as_poseidon1(&self) -> Option<&Poseidon1Config> { None }
}
```

But `CircuitChallenger::duplexing()` dispatches **only** on those two downcasts and
`panic!("unsupported challenger permutation")` otherwise. So a SHA3-based transcript
would mean writing a new in-circuit sponge into a third-party crate we do not own.
That is out of scope for the foundation.

### The scope rule

Poseidon2 may appear **only** as the `ChallengerPermConfig` of the recursion backend.
It must not appear in:

- note commitments or nullifier derivation (SHA-256/SHA3 — `ShieldedHasher`)
- the Merkle/PCS layer the EVM walks (Keccak-256 — `CommitmentHasher`)
- any wallet-side derivation path
- any user-facing address or identifier

### Enforcement (not a comment, a gate)

1. **Type boundary.** `ShieldedHasher` and `CommitmentHasher` are distinct traits with
   distinct output newtypes (`NoteHash`, `Nullifier`, `MerkleRoot`). `Poseidon2Config`
   implements neither. The code will not typecheck if Poseidon is wired into a
   non-transcript layer.
2. **Dependency rule.** Only the `pq-prover` crate may depend on
   `p3-poseidon2` / `p3-recursion`. `pq-crypto`, `shielded`, and `wallet` must not.
   Enforced by a CI check over the workspace dependency graph.
3. **Semgrep rule.** `pq-no-poseidon-outside-prover` flags any `poseidon` identifier
   outside `crates/pq-prover/`.

### Why this is honest rather than a loophole

Poseidon2 in the transcript is a **performance** choice inside an unaudited third-party
recursion engine. It is not load-bearing for the *privacy* or *PQ* properties: the
Fiat-Shamir transcript hash being Poseidon2 does not weaken the PQ signature or the
SHA-based commitments. If Poseidon2 were someday broken, the transcript becomes
forgeable — a liveness/availability concern for the prover chain, not a privacy or
PQ-security break of the value system. That is why the exception is tolerable, and why
ticket [15](15-transcript-hash-portability.md) tracks making it swappable.
