# 08 - Session scope: map + compiling foundation

Type: grilling
Status: resolved
Blocked by: 01

## Question

A production PQ shielded rollup plus wallet is many sessions of work. What does *this*
session deliver?

## Answer

**Map + compiling foundation.** The map is the primary artifact; the foundation proves
the map is walkable.

### Definition of done for this session

- [x] Wayfinder map + decision tickets in `.scratch/pq-shielded-rollup/`
- [ ] Cargo workspace that **builds** with the pinned dependency set
- [ ] `pq-crypto`: hash layer + SPHINCS+ behind DI traits, unit-tested
- [ ] `shielded`: domain model (Note / Nullifier / Commitment) + a real transfer AIR
- [ ] `pq-prover`: base STARK proves and verifies natively (KoalaBear + quintic)
- [ ] `node`: state + Merkle + mempool + batch driver, constructor-injected
- [ ] `contracts/`: Solidity verifier skeleton + settlement contract, `solc` compiles
- [ ] `wallet/`: MV3 extension skeleton loads, PQ key custody, send/receive UX
- [ ] Quality gate wired: clippy + cargo-deny + semgrep + fmt all green

### Explicitly NOT in this session

- In-circuit SPHINCS+ (ticket 10) — the foundation uses a **stub** spend-auth gadget
  with the real interface, so the circuit shape is real but the PQ verification is a
  placeholder that is *honest about being a placeholder*.
- Recursion layers actually running (ticket 11) — wired, not yet multi-layer.
- A complete Solidity verifier (ticket 12) — ABI + skeleton + tests, not full FRI.
- Mainnet, audits, economic tuning.

### Why a stub spend-auth is acceptable here but never in production

The stub is a **type-correct, interface-complete** placeholder that verifies nothing.
It is loudly named (`StubSpendAuth`), gated behind a non-default feature flag, and
semgrep + a unit test assert it cannot be selected in a release build. The alternative
— silently shipping a circuit that does not check signatures — is the failure mode we
are designing against.
