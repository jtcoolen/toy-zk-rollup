# Knowledge Base — PQ Shielded Rollup

Running log of researched facts, measurements, and their sources. Decisions live in
`decisions.md`; this file holds the evidence behind them. Newest first.

---

## 2026-09-13 — Plonky3-STARK vs Spartan-WHIR: efficiency & verifier adaptation cost

### Tooling note
The web_search plugin is broken: its endpoint (`http://127.0.0.1:8080/v1/messages`)
returns 401 ("api key ****ocal is invalid"). Only the user can fix it via
Settings → Plugins → Web search or `DEEPSEEK_SEARCH_BASE_URL`. All research below
was done with `web_fetch` on primary sources instead.

### Sources consulted
- WHIR paper: https://eprint.iacr.org/2024/1586 (Arnon–Chiesa–Fenzi–Yogev)
- SoK FRI→Basefold/STIR/WHIR: https://eprint.iacr.org/2026/1367 (Skatharoudis)
- spartan-whir (Rust, ethereum org): https://github.com/ethereum/spartan-whir
- sol-whir-p3 (Solidity, ethereum org, MIT per-file SPDX):
  https://github.com/ethereum/sol-whir-p3
- Plonky3 recursion book benchmarks:
  https://plonky3.github.io/Plonky3-recursion/appendix/benchmark.html
- Spartan arithmetization notes: https://alinush.github.io/spartan

### Protocol-level difference (what actually differs)
Both families end at WHIR. The difference is the **arithmetization above the PCS**:

| Axis | Plonky3 uni/batch-STARK (ours) | Spartan-WHIR (their stack) |
|---|---|---|
| Relation | AIR: execution trace + low-degree transition/boundary constraints over univariate polynomials | R1CS: matrices A·z ∘ B·z = C·z, multilinear-extended |
| Polynomial world | Univariate (LDE on a multiplicative coset) | Multilinear (MLE over the Boolean cube) |
| Core IOP | DEEP-ALI quotient + FRI/WHIR proximity test | Outer/inner sumcheck over matrix claims + WHIR opening of the witness MLE |
| Constraint degree | Low (AIR rows), quotient absorbs the rest | Cubic per R1CS row, sumcheck rounds absorb the rest |
| Lookup | LogUp native (we use it) | Spartan2 adds lookups; spartan-whir uses tables/SPARK |
| Trusted setup | None | None |
| PQ posture | Hash-based only | Hash-based only |

WHIR itself is a PCS for *constrained Reed–Solomon codes* and supports both
univariate STARK queries and multilinear sumcheck queries — that is why both
stacks can sit on it. Our `p3-whir` 0.8.0 `WhirUniPcs` presents the univariate
STARK interface; spartan-whir uses the multilinear/sumcheck interface.

### Measured numbers (from the sources, not folklore)

**WHIR paper (2024/1586):** degree 2^22, 100-bit security: commit+open 1.2 s,
**63 KiB** communicated, verification **360 µs** native. Verifier "a few hundred
µs" vs several ms for FRI-class verifiers.

**spartan-whir README, SHA-256 2048-byte circuit (605,424 constraints,
1M padded rows, KoalaBear×5, 116-bit target, M4 Pro):**

| Mode | Prove+witgen (ms) | Verify (ms) | Proof size |
|---|---:|---:|---:|
| no-ZK DirectSparse | 46.7 | 31.9 | **483 KB** |
| full-ZK DirectSparse | 68.3 | 49.7 | **1.23 MB** |
| no-ZK Spark | 789.8 | 22.6 | 2.04 MB |
| full-ZK Spark | 889.6 | 40.2 | 2.74 MB |
| Spartan2 full-ZK (P-256) | 287.4 | 36.2 | 78.7 KB |
| ProveKit full-ZK (BN254) | 971.3 | 207.4 | 3.23 MB |

**sol-whir-p3 README (Solidity, standalone WHIR PCS opening, solc 0.8.28,
via-IR, Prague):**

| Verifier | Tx gas | Exec gas | Calldata |
|---|---:|---:|---:|
| KoalaBear quintic | 3.64 M | 2.76 M | 54.4 KB |
| BabyBear quintic | 3.36 M | 2.49 M | 54.1 KB |
| KoalaBear octic | 5.64 M | 4.86 M | 47.8 KB |
| LeanVM terminal (recursive) | 12.9 M | 11.3 M | 106.6 KB |

Their contracts exceed EIP-170 (24.6 KB); they measure with 64 KB limits.
Deployment needs a split verifier or the 4844/blob path.

**Plonky3 STARK (ours), measured in-repo:** layer-N block proof (fan-in 2,
v=25 budget) proves in ~23 s debug / ~9 s opt on M2 Pro. Proof size not yet
serialized — measurement pending (postcard dev-dep added). Literature anchor:
Plonky3 FRI STARKs of similar width land 60–150 KB; WHIR replaces FRI's
~45–60 KB Merkle openings with ~15–25 KB STIR openings, so our layer-N proof
should land **~40–80 KB**, verify ~2–4 M gas with the ported verifier.

### Efficiency verdict for OUR use case
1. **Proof size is dominated by the WHIR opening, not the arithmetization.**
   Both stacks pay ~50–60 KB per WHIR commitment at our security level. Our
   recursion already collapses N transfer proofs into ONE layer-N WHIR
   commitment, so we carry one opening on-chain, not N.
2. **Spartan-WHIR's advantage is prover-side on R1CS-shaped workloads**
   (Circom frontend, generic circuits). Our AIR is hand-written for the shielded
   transfer and already exploits trace structure; converting to R1CS would ADD
   constraints (their SHA-256 R1CS is 75% larger than a lookup-optimized one).
3. **Their full-ZK costs 2.5–5.7× proof size** (masking commitments). We get
   ZK structurally (per-transfer proofs hide amounts; the block circuit sees
   hashes only) — we do NOT pay the Spartan ZK overhead.
4. **Verifier gas is nearly identical** because both are "recompute Keccak
   transcript + check STIR folding + Merkle multiproof". Their 2.76 M exec gas
   for a standalone WHIR opening is our realistic band.
5. **Conclusion: switching our proving stack to Spartan-WHIR buys nothing.**
   We keep Plonky3 batch-STARK + WHIR. We adopt only their Solidity verifier
   *building blocks* (field, challenger, Merkle) — see D-033.

### What adapting sol-whir-p3 actually requires (change estimate)
Reuse as-is (MIT, verified compatible):
- `KoalaBear.sol` (MODULUS 0x7f000001, W=3) — exact match.
- `KoalaBearExt4.sol` — packed quartic binomial ext in uint256; our Challenge
  is the same field. (Their flagship configs use ext5/ext8; ext4 exists and is
  tested.)
- `KeccakChallenger.sol` — `observeBase` = LE u32 per element: byte-identical
  to our `SerializingChallenger32<F, HashChallenger<Keccak256Hash>>`.
- `MerkleVerifier.sol` — Keccak multiproof machinery.

Must change (material work, ~60% of the port):
1. **Merkle leaf/node convention.** Their AGENTS.md: leaves prefixed `0x00`,
   nodes `0x01`. Ours (`crates/shielded/src/tree.rs`): identity leaves, raw
   `keccak(l||r)` nodes. Their Rust honors `keccak_no_prefix=false`; our tree
   is prefix-free. Either re-configure their multiproof to prefix-free (small,
   local change in the leaf/node hashing helpers) or change our tree (breaks
   existing golden vectors). Decision: adapt THEIR helpers to prefix-free —
   our tree convention is already pinned by contract_vectors.rs.
2. **Digest size.** Their Poseidon-based WHIR digest is 8 base elements
   (~32 bytes truncated); our settlement Mmcs is Keccak sponge 4×u64 = 32 B.
   Same on-wire size, different derivation — their MerkleVerifier is Keccak,
   so this aligns at the settlement layer.
3. **Round schedule regeneration.** Their `*WhirFixedConfig.sol` hardcodes
   k22/jb100/pow28-style schedules. Ours: 96-bit, ff=4,
   starting_log_inv_rate=1, BLOCK_LOG_MAX_LDE=25, JohnsonBound. Regenerate
   constants mechanically from our `WhirConfig` (Rust emits JSON; Solidity
   reads generated library). Their scorer/generator scripts are for the
   spartan-whir fork — we write a small emitter instead.
4. **Proof blob codec.** Their blob format is the spartan-whir fork's
   (`whir-p3` @ fc7d591, one opening per STIR query era). Our `p3-whir`
   0.8.0 already emits `QueryOpenings`/`MT::MultiProof` (round-level shared
   decommitment — exactly the shape their migration doc *wishes* for). So our
   exporter is simpler than theirs; we do NOT use `spartan-whir-export`.
5. **The missing layer: AIR constraint evaluation.** Their standalone verifier
   checks a WHIR PCS opening of a committed polynomial. Our layer-N proof is a
   batch-STARK: verifier must also evaluate OUR recursion-circuit AIR
   (Poseidon2-shared + recompose + statement tables, LogUp) at the OOD point
   and check the DEEP quotient identity. That code exists nowhere in their
   repo; it is the generated-from-`SymbolicAirBuilder` piece in our plan.
   This is the single biggest work item (~50% of total verifier effort).

### Risk register (updated)
- EIP-170: their verifier is 35 KB runtime. Ours will be similar or larger
  (generated AIR evaluator adds code). Mitigations: split verifier across 2
  contracts, or delegatecall-composed modules, or EIP-4844 blob for proof
  calldata. Unresolved; decide after first generated verifier measures.
- Their repo has NO root LICENSE but every .sol carries `SPDX-License-Identifier:
  MIT` — usable; keep per-file SPDX on vendored copies, note provenance commit.
- Their `keccak_no_prefix` warning cuts in our favor: prefix-free Keccak is a
  deliberate, documented configuration, not a bug.

---

## 2026-09-13 — Repo landscape (verified via GitHub API)

| Repo | License | Status | Verdict |
|---|---|---|---|
| alxkzmn/spartan-whir-dev | none | meta-repo, submodules only | skip (docs useful) |
| alxkzmn/sol-spartan-whir | none (root) | same tree as below | superseded by ethereum org copy |
| **ethereum/sol-whir-p3** | MIT (per-file SPDX) | active, 2026-09-13 | **adopt building blocks (D-033)** |
| ethereum/spartan-whir | (Rust source of truth) | active | reference only; not our proving stack |
| alxkzmn/whir-p3 | Apache-2.0 | fork of p3-whir | not needed; registry p3-whir 0.8.0 is ahead (MultiProof) |
| privacy-ethereum/sol-whir | MIT | archived 2024 | structural reference only |

Key upstream fact: the "missing multi-index opening" that the spartan-whir-dev
migration doc lists as required upstream work is ALREADY in registry
`p3-whir` 0.8.0 (`QueryOpenings<F,EF,MT::MultiProof>`, `SharedProofOpening`).
Our stack sits on the newer shape; the Solidity side must match OUR codec, not
theirs.

## wasm toolchain facts (wallet-wasm)

- The workspace-local toolchain at `.rustup-home` (1.98.1) carries the
  `wasm32-unknown-unknown` target; the global `~/.rustup` one does not.
  Build wasm with `RUSTUP_HOME=$PWD/.rustup-home PATH=$PWD/.rustup-home/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH`.
- That minimal install's `rust-lld` aborts (SIGABRT) unless
  `libLLVM.dylib` is reachable from `.../bin/../lib/`; a symlink to the
  toolchain's own `lib/libLLVM.dylib` fixes it permanently.
- rand must be depended on with `features = ["std_rng"]` only in wasm-facing
  crates: `thread_rng` pulls getrandom, which does not build for
  wasm32-unknown-unknown. JS supplies entropy via `crypto.getRandomValues`.
- `#[no_mangle]` and `#[export_name]` are both flagged by the
  `unsafe_code` lint in edition 2024; a wasm cdylib cannot export without
  one of them, hence the scoped crate-level allow in wallet-wasm.

