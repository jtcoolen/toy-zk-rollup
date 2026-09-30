# Map: Post-Quantum Shielded Pool Rollup on Plonky3

Label: `wayfinder:map`

## Destination

A working design **and compiling foundation** for a post-quantum, trust-minimized
shielded-value pool (Zcash/MantaPay shaped) that proves its own state transitions with
**STARKs only** (Plonky3 + Plonky3-recursion) and settles on an **EVM-compatible chain**
via a Solidity verifier. No SNARKs, no non-PQ primitives, no Poseidon outside the one
granted seam. The map is done when every crate compiles, the base→recursive proof path
runs, the Solidity verifier compiles against the agreed proof ABI, and the wallet
extension loads — with the remaining deep-circuit work captured as tickets, not fog.

## Notes

**This effort overrides the wayfinder default: execution is carried into the map.**
Tickets are decisions *and* the code that instantiates them. The foundation must compile;
full production depth stays ticketed.

### Hard constraints (from the human, non-negotiable)

- **No SNARKs.** STARK/FRI only. EVM verifies a FRI-STARK directly.
- **PQ is a requirement.** No primitive whose security collapses under a quantum
  adversary. That rules out ECDSA/EdDSA/Schnorr everywhere, including the wallet.
- **No Poseidon** — *except* the recursion transcript, explicitly granted (see
  [Poseidon2 exception](issues/05-poseidon2-exception.md)).
- **SHA-2/SHA-3 preferred; 3 preferred.**
- Off-the-shelf, swappable components. Dependency injection / inversion of control.
  Standard choices only, no ad-hoc design. Least amount of code.
- Mission-critical security posture: safe secret handling, robust simple maintainable code.

### Component inventory (verified live, 2026-09-30)

| Role | Component | Version | Status |
|---|---|---|---|
| STARK prover | `p3-uni-stark`, `p3-batch-stark` | 0.8.0 | off-the-shelf |
| Recursion | `p3-recursion` (Plonky3/Plonky3-recursion) | git `main` | **unaudited**, active |
| Field | `p3-koala-bear` + quintic ext (D=5) | 0.8.0 | off-the-shelf |
| SHA-256 native | `p3-sha256` (AArch64/x86/WASM SIMD) | 0.8.0 | off-the-shelf |
| SHA-256 in-circuit | `p3-sha256-air` (prime + binary) | 0.8.0 | off-the-shelf |
| Keccak-f1600 | `p3-keccak`, `p3-keccak-air` | 0.8.0 | off-the-shelf |
| SHA3-256 in-circuit | patch of `p3-keccak-air` padding | — | **ticket 09** |
| PQ signature | `slh-dsa` (SPHINCS+, RustCrypto) | 0.2.0-rc.5 | off-the-shelf (native) |
| PQ KEM (optional) | `ml-kem` 0.3.2 / `ml-dsa` 0.1.1 | — | out of scope for v1 |
| EVM hashes | `keccak256` @ `0x20`, `sha256` @ `0x02` | precompile | **no SHA3 precompile** |

**Critical:** the published crates.io `p3-recursion` 0.1.0 is an **empty placeholder**
(zero dependencies). The workspace must consume it from git. See
[Recursion source of truth](issues/04-recursion-source-of-truth.md).

### Build environment gotchas

- `~/.cargo` is not writable under the file sandbox → `CARGO_HOME` is set to
  `<workspace>/.cargo-home` via `.cargo/config.toml`.
- Toolchain: Rust 1.90.0 at `~/.rustup/toolchains/1.90.0-aarch64-apple-darwin/bin`
  (not on `PATH`). `p3-recursion` is edition 2024 → needs ≥1.85.
- `solc` 0.8.35 and Foundry (`forge`/`cast`/`anvil`) are available at
  `/opt/homebrew/bin` and `~/.foundry/bin`.

### Layered hash policy (the load-bearing decision)

Three hashes, each chosen for a different cost environment. Never mix them by accident:

1. **Shielded layer** (notes, nullifiers, viewing keys) — **SHA3-256** preferred,
   **SHA-256** as the off-the-shelf default that compiles today. Behind
   `ShieldedHasher` so the swap is a config change, not a refactor.
2. **Commitment/Merkle/FRI layer** — **Keccak-256**, because the EVM verifies it with
   the native `0x20` precompile (~60k gas vs ~70M+ for SHA3 in Solidity). Same
   Keccak-f[1600] core, so PQ-equivalent.
3. **Recursion transcript** — **Poseidon2** (granted exception). Confined to
   `ChallengerPermConfig`; must never leak into the shielded or Merkle layers.

### Skills to consult

`grilling`, `domain-modeling` (ADR + glossary format), `research`, `prototype`.

## Decisions so far

<!-- one line per closed ticket; the detail lives in the ticket -->

- [Destination: PQ shielded pool on Plonky3, EVM-settled](issues/01-destination.md): STARK-only, no SNARKs, PQ mandatory, settles on EVM via a Solidity FRI verifier.
- [Hash layering: three-layer split](issues/02-hash-layering.md): SHA3-256 shielded / Keccak-256 Merkle+FRI (precompile) / Poseidon2 recursion transcript only.
- [Field: KoalaBear + quintic extension](issues/03-field-selection.md): 31-bit KoalaBear, D=5 challenge extension, ~128-bit conjecturable security.
- [Recursion source of truth: git, not crates.io](issues/04-recursion-source-of-truth.md): crates.io `p3-recursion` 0.1.0 is an empty stub; pin the git rev.
- [Poseidon2 exception is scoped to the recursion transcript](issues/05-poseidon2-exception.md): granted by the human; enforced by a crate-boundary test.
- [PQ spend authorization: SPHINCS+](issues/06-pq-signature-choice.md): hash-based, so in-circuit verification reuses the SHA AIRs instead of lattice gadgets.
- [EVM settlement: Solidity FRI-STARK verifier](issues/07-evm-settlement.md): trust-minimized, Keccak-256 precompile for FRI Merkle paths, no trusted bridge.
- [Session scope: map + compiling foundation](issues/08-session-scope.md): every crate compiles and the proof path runs; deep PQ circuits stay ticketed.
- [Recursion needs NO fork — VERIFIED](issues/15-transcript-hash-portability.md): `TrustedPreparedLayer<InSC, OutSC, …>` takes two *independent* config types (only `Challenge` is shared). Layer 0 runs on a Poseidon2 `DuplexChallenger` (matches the in-circuit `ChallengerPermConfig`, covered by the granted exception); the final layer runs on a Keccak transcript, which is the only transcript Solidity replays. **Confirmed by a passing test** (`recursion-test`: layer 0 proves under Poseidon2, the wrapping layer proves under Keccak, the Keccak verifier accepts). The one gap that had to be closed: the recursion layer's in-circuit Merkle gadget is Poseidon2-shaped, so both configs commit with a field-native `MerkleCap<F, [F; 8]>`, and Plonky3's Keccak `SerializingChallenger32` only observes `[u64; N]`/`[u8; N]` caps. A newtype (`KeccakOutChallenger`) absorbs each field element as little-endian `u32` — the *same bytes* `CanObserve<F>` already uses — so the wire format is unchanged and Solidity mirrors it with `abi.encodePacked` + `keccak256`. Zero patches to `p3-recursion`.
- [EVM precompile facts corrected](issues/07-evm-settlement.md): `0x01` ecrecover, `0x02` SHA-256, `0x03` RIPEMD-160, `0x04` Identity. There is **no** keccakf1600 precompile; `keccak256` is the native **opcode `0x20`** and computes *original* Keccak (`0x01` pad) — exactly what `p3-keccak` emits. FIPS SHA3-256 (`0x06` pad) has **no** precompile, so a SHA3 transcript would be expensive on-chain while a Keccak transcript is nearly free.
- [Recursion proof size / gas](issues/16-recursion-audit-gate.md): measured KoalaBear+D=5, log_blowup 2 — 332 KB @ 1 layer → 302 KB @ 2 → 300 KB @ 3. Converges ~300 KB ≈ **4.8M gas** in calldata before any verifier compute.

## Not yet specified

- **In-circuit SPHINCS+ cost profile.** WOTS+ chain + FORS + hypertree verification
  inside the transfer AIR will dominate circuit size. How many SHA-256 compression rows
  per spend, and whether it needs its own lookup table or shares the note-hash table, is
  unknown until the gadget is measured. Graduates from ticket 10.
- **Recursion arity / layer count.** How many recursion layers are needed before the
  proof is small enough for the Solidity verifier's gas budget. Depends on the base
  circuit width, which depends on the SPHINCS+ gadget.
- **Nullifier set representation on-chain.** Sparse bitmap vs. Merkleized set vs.
  append-only accumulator with in-circuit non-membership. Each has a different
  settlement cost curve; the choice hangs on the final proof shape.
- **Viewing / audit key design.** Full-view viewing keys vs. diversified addresses vs.
  incoming-only viewing. A wallet feature and a circuit feature at once.
- **Forced-inclusion / liveness story.** What happens when the sequencer censors a
  shielded transaction. Needs the settlement contract's commitment scheme settled first.
- **Secret custody across the prover boundary.** The prover sees witness material
  (spending keys, blinding factors). How that is isolated — process, enclave, or
  user-held — is unresolved and shapes the whole node deployment story.
- **Upgrade path for the recursion circuit.** A circuit change invalidates the
  verifier. Versioning/rollback of the STARK circuit against an immutable-ish Solidity
  verifier is untouched.

## Out of scope

- **Non-PQ primitives anywhere.** ECDSA/EdDSA/Schnorr/secp256k1 for any purpose,
  including wallet identity. Ruled out by the PQ requirement, not by preference.
- **SNARKs of any kind**, including wrapping the STARK in a SNARK to save gas.
  Explicitly excluded by the human.
- **ML-DSA (Dilithium) spend authorization.** Lattice gadgets in-circuit are a large
  cost with no advantage over SPHINCS+ here. May return as a hybrid, as a fresh effort.
- **FHE / MPC-based shielded pools.** Different destination entirely.
- **Non-EVM settlement** (Bitcoin, Cosmos ICS, Celestia DA). The destination is EVM.
- **Interoperability with existing Zcash/Manta chains.** Bridge work is a separate map.
- **Mainnet launch, audits, and economic parameter tuning.** The destination is a
  compiling foundation plus a clear route, not a live network.
