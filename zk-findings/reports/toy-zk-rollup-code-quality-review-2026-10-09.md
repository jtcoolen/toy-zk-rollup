# Code-Quality Review: toy-zk-rollup (architecture, design, implementation)

Revision `a54c197`. Companion to the security report (`toy-zk-rollup-crypto-audit-report-2026-10-09.md`); this document does not re-report vulnerabilities. Six areas were reviewed by dedicated readers (architecture, prover circuits, prover export pipeline, contracts, node, domain crates); testing/tooling and vendoring are from the lead's own measurements. Per instruction, the adversarial verify pass was skipped — treat individual items as reviewer claims with `file:line` evidence, not independently re-checked.

## Verdict

The code is better than its security posture suggests. Function-level craft is high: median function length is 8 lines (Rust) and 13 (Solidity); the transfer relation is written to be reviewed (numbered properties mirrored in the builder); every circuit gadget is pinned against a native twin with a negative test beside it; invariants are enforced at compile time where possible (`const _: () = assert!(Pcs::ZK)`); the node library has zero `unwrap`/`expect` in non-test code; secrets get redacting `Debug`; the dependency policy and build profile are documented in place.

The structural problems are three, and they are the same three that produced the security findings:

1. **Fast design reversals were applied to code but not to the architecture around it.** The hash policy (SHA3/Keccak → Poseidon2, D-088/D-092 "batch 82"), the nullifier-tree depth (256 → 96), and settlement ZK (on → off, batch 89) were changed under a trait seam and a decision log that still describe the old design. At least 13 module/README/map statements are stale, dead hashers remain public API, and nobody owns the cross-cutting parameters.
2. **Research/test scaffolding became the production path.** The settlement bundle is produced by a pipeline built as a test harness: three stages of `serde_json::Value` plumbing, an empirically derived trusted-setup boundary (a two-proof seed-twin diff), env-var-driven soundness parameters read inside library functions, `println!` and writes into `contracts/`, and the production node depending on the prover's `testkit` feature.
3. **The verification surface optimised for gas and size grew without consolidation.** WBND wire versions v5/v7/v8 coexist with in-band feature bits; four hand-rolled raw-word frame protocols are defined twice (pack/parse) with hard-coded struct offsets; five probe forks duplicate 5.5k lines of production verifier code; 68 inline-assembly blocks, 24 without `memory-safe`.

## Scorecard

| Area | Score (1–5) | Why |
|---|---|---|
| Workspace architecture | 3 | Clean dependency direction and a real DI seam, but hash/field/security choices have no single owner and env vars configure soundness inside libraries (ARCH-02, ARCH-03). |
| Prover: circuits | 4 | Reviewable relation, native twins, compile-time invariants; let down by stale docs, dead Keccak registrations, duplicated settle/chain code (PRV-01..04). |
| Prover: export pipeline | 2 | Sound core idea (program equality vs native verifier), but `Value`-typed plumbing (243 string-key sites in `wbnd.rs`), empirical CONFIG/PROOF boundary, stale JS twins, no unit tests (EXP-01..08). |
| Contracts | 3 | Carefully reasoned engine/satellite/codehash architecture and strict build policy; 12 revert sites emit zero selectors, version sprawl, frame protocols without a shared definition, probe-fork duplication (SOL-01..04). |
| Node | 3 | Library is good (atomic `PoolState`, constant-time auth, typed settlement errors); 886-line untested `main.rs`, one actor serialising proving and a 600 s settlement wait, no persistence (NODE-01, -02, -09). |
| Domain crates | 3 | Strong newtypes and pinned encodings; docs describe the superseded design, the "executable spec" covers only the balance rule, wire schema hand-written in six places (DOM-01, -02, -07). |
| Testing & tooling | 2 | 254 Rust tests but 48 are `#[ignore]` generators; tests are mostly parity/replay (64) vs targeted rejection (49, mostly random-byte tampers); gate is local-only and skips tools silently; no CI. |
| Vendoring | 2 | Strategy is reasonable (excluded workspace, documented rationale) but `PATCHES.md` records 1 of 5 changed files, the pristine copy it relies on is absent, and nothing detects drift. `sol-whir-p3/PATCHES.md` is the better model. |

## Cross-cutting themes

- **Design memory lives outside the code it governs.** 8.6k lines in `.scratch/` (`verifier-redesign.md` alone 3.8k); 237 `D-0xx` mentions in code across 35 IDs, only 4 comments point to where decisions live; the most-cited "decision" is a proposal entry; batch journals were never promoted to decisions (ARCH-06, PRV-06). README is stale on hashing, proving crate (`p3-multi-stark`), and the operator set.
- **Configuration by environment.** 12 `env::var` sites in library code, including `WHIR_SECURITY_LEVEL` and soundness regime, evaluated per call and reachable from the production node (ARCH-03, EXP-09). Needs one typed `WhirParams` value resolved at the binary edge.
- **Stringly/untyped intermediate representations.** `serde_json::Value` from `walk_json` to the WBND encoder; errors flattened to `String` at the node actor boundary (every failure is a 422); three error styles in the prover with tests matching message substrings (EXP-01, NODE-03, PRV-05).
- **Version and duplicate sprawl.** WBND v5/v7/v8 + V6 wrapper + chunk verifier; JS and Rust bundle encoders (the "matches JS" pin is Rust-vs-Rust); probe forks; `settle_block_circuit` a verbatim copy of `settle_recursion_circuit_with`; `CommitmentChain`/`NullifierChain` structurally identical (SOL-02, SOL-03, EXP-03, PRV-03, PRV-04).
- **Parity-heavy testing.** Correctness is established by replaying honest vectors; rejection paths are thinly targeted; the classification/framing logic is reachable only through multi-minute ignored proving runs (EXP-08). This is the code-quality face of the security report's main lesson.

## Findings by area

### Architecture
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| ARCH-01 | major | Hash policy reversed under the trait seam; promised enforcement absent | `.scratch/pq-shielded-rollup/map.md:26,61-72` | One superseding decision; delete dead hashers or gate them. |
| ARCH-02 | major | Field/extension/hasher/security level have no single owner; crate root re-exports a dead config | `crates/prover/src/config.rs:44-51`, `whir.rs:64-70` | One `protocol` module owning `F`, `Challenge`, hasher aliases, security parameters. |
| ARCH-03 | major | Soundness/sizing params read from env inside libraries, every call | `crates/prover/src/whir.rs:120-131,147-153` | Typed `WhirParams` with a `canonical()` constructor; resolve env only in `main`/tests. |
| ARCH-04 | major | Test harness promoted to the production settlement pipeline | `crates/prover/src/settlement_replay.rs:1-25`, `composed_export.rs:1-21` | Split a typed `settlement-wire` module from the vector-export path. |
| ARCH-05 | moderate | Production node depends on `prover/testkit`, builds genesis from fixtures | `crates/node/Cargo.toml:15,62` | Non-default `demo` feature / separate demo binary. |
| ARCH-06 | moderate | Design memory split across decision log, batch journal, stale tickets | `decisions.md:1757-1761`, `verifier-redesign.md:3456` | Promote batches to numbered ADRs under `docs/decisions/`. |
| ARCH-07 | moderate | 13 statements still describe superseded hash layering | `crates/pq-hash/src/lib.rs:16-21`, `crates/prover/src/lib.rs:18-22` | One hash-policy table; link everywhere else. |
| ARCH-08 | moderate | Gate local-only, soft on policy tools; deny targets omit wasm32 | `scripts/check.sh:98-115`, `deny.toml:7-12` | CI with `REQUIRE_TOOLS=1`; add wasm32 target. |
| ARCH-09 | minor | Dead/spike code in default build graph | `crates/prover/src/lib.rs:56`, `sha3_block.rs` | Delete or `#[cfg(test)]`. |
| ARCH-10 | minor | Shadowed names, attribute ordering, crate-wide lint widening | `crates/prover/src/whir.rs:120-153` | Fold into `WhirParams`. |

### Prover: circuits
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| PRV-01 | major | Crate/module docs describe the removed SHA3/Keccak-f layer | `crates/prover/src/lib.rs:10-22` | Rewrite to Poseidon2-everywhere; single source. |
| PRV-02 | major | Transfer settlement registers a Keccak-f table nothing uses; `sha3_block` dead | `transfer.rs:987-1004` | Remove registrations; share table set with recursion. |
| PRV-03 | major | `settle_block_circuit` verbatim copy of `settle_recursion_circuit_with`; duplicated where-clauses | `block.rs:769-812`, `whir_recursion.rs:643-701` | One-liner delegation; `shielded_tables(schema)` helper. |
| PRV-04 | moderate | `CommitmentChain`/`NullifierChain` identical; statement layout constants in three places | `block.rs:669-753` | One `RootChain`; single statement-layout module. |
| PRV-05 | moderate | Three error styles; lossy mappings; tests match substrings | `transfer.rs:390-410` | `prover::Error` enum. |
| PRV-06 | moderate | Half the D-0xx/batch references don't resolve; two comment pairs contradict | `transfer.rs:11,23` | In-repo ADRs with headings for every cited ID. |
| PRV-07 | moderate | Gadget substitutes zero digests for malformed input instead of failing | `commitment_gadget.rs:121-141` | Fixed-size `FrontierWitness`; `Result` constructors. |
| PRV-08 | moderate | Private-witness order coupled to allocation order only by convention | `transfer.rs:143-150,413-421` | `WitnessBuilder` pairing alloc with value. |
| PRV-09 | moderate | Public API mixes product with census/sweep scaffolding | `transfer.rs:284-318` | Gate behind `testkit`; private `RecursionCircuit` fields. |
| PRV-10 | minor | Fixtures and table-enable blocks re-implemented | `transfer.rs:1052-1071` | Import from `fixtures`. |
| PRV-11 | minor | Two long builder passes; const-digest helper re-inlined six times | `transfer.rs:358-536` | Extract `constrain_spend`, shared `const_digest`. |
| PRV-12 | minor | Literals and hand-rolled encodings beside owning helpers | `block.rs:292-305`, `transfer.rs:862-897` | Name `FIELD_BITS`/`LIMB_BITS`; reuse `bytes_to_limbs`. |

### Prover: export pipeline
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| EXP-01 | major | Three stages of `serde_json::Value` plumbing where typed structs exist | `whir_walk.rs:566-618`, `composed_export.rs:98-159` | Return a typed `VectorsDoc`; encode from types. |
| EXP-02 | major | Trusted-setup boundary computed empirically by seed-twin diff across five functions | `composed_export.rs:575-686` | Tag provenance at the transcript seam. |
| EXP-03 | major | JS generators stale duplicates still documented as producer; pin is Rust-vs-Rust | `contracts/scripts/gen_bundle.mjs:274-377` | Delete JS encoders; rename pin. |
| EXP-04 | moderate | Five classification views, three dead statements, one module unused | `composed_export.rs:435-497` | Delete or `#[cfg(test)]`. |
| EXP-05 | moderate | Same loops copy-pasted across encoder and classifier | `composed_export.rs:477-513` | `SemEvent` helpers; shared `Sink` packers. |
| EXP-06 | moderate | WBND version is an inline magic number on both sides | `wbnd.rs:943,982` | `enum WireVersion` with capability methods. |
| EXP-07 | moderate | Production entry docstring contradicts code on cost and which proof ships | `composed_export.rs:1213-1267` | Correct docs; assert the shipped proof. |
| EXP-08 | moderate | Classification/framing logic untested except via ignored multi-minute runs | `composed_export.rs:827-1000` | Unit tests on synthetic 20-event programs. |
| EXP-09 | moderate | Library functions read env, print, write into `contracts/` | `composed_export.rs:1252-1259`, `settlement_replay.rs:148-156` | Explicit `SettlementShape` parameter. |
| EXP-10 | minor | Two unrelated `SettlementBundle` types | `export.rs:29-32` | Rename/delete legacy. |
| EXP-11 | minor | `composed_export.rs` mixes five concerns behind blanket lint allows | `composed_export.rs:13-21` | Split into `classify`/`framing`/`vectors_doc`/`settlement_bundle`. |

### Contracts
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| SOL-01 | major | Hand-written revert selectors: 12 sites emit zero bytes, 3 match no declared error | `TerminalWeight.sol:1221,1298` | Compiler-derived selectors; declare missing errors. |
| SOL-02 | major | Five probe forks duplicate 5.5k lines of production verifier | `contracts/test/WhirVerifierP.sol`, `WhirVerifierV8P.sol` | One instrumented engine (`_mark` hook / bench profile). |
| SOL-03 | major | Wire-version sprawl with in-band bits; four `src` files unwired in production | `WhirVerifier.sol:237-242,1048-1052` | Version byte authoritative; delete or deploy V6. |
| SOL-04 | major | Four raw-word frame protocols, no shared definition; struct offsets hard-coded in three files | `WhirVerifier.sol:754-879` | `SatelliteFrames` library owning layouts. |
| SOL-05 | moderate | 68 assembly blocks, 24 unannotated `memory-safe` | `WhirVerifier.sol:1116,1157` | Annotate or justify each; split `_qfold` (294 lines). |
| SOL-06 | moderate | Field constants restated; one restated derivation is wrong | `BatchTranscript.sol:222-224`, `WhirVerifier.sol:1291-1295` | One `KoalaBearWire` library. |
| SOL-08 | moderate | Design-log prose inside contracts has drifted from code | `WhirVerifier.sol:13,237-241` | NatSpec for invariants; narrative to `contracts/docs/`. |
| SOL-09 | moderate | Flat test dir mixes pins with gas probes; 39 MB vectors, 28 files unreferenced | `contracts/foundry.toml`, `contracts/test/vectors/` | `test/{unit,vectors,e2e,bench}`; prune vectors. |
| SOL-07 | minor | Dead/vestigial code in engine, satellite stubs, pool | `WhirVerifier.sol:901-915,1309-1313` | Delete; declare `NonZeroPadding()`. |
| SOL-10 | minor | Inconsistent pragma/license/error style; 13 string requires | `ConstraintIdentity.sol:1-2` | Pin pragma; custom errors. |
| SOL-11 | minor | 25-branch generator if-chain exposed as public ABI | `WhirVerifier.sol:134-196` | Private; table constant or repeated squaring. |

### Node
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| NODE-01 | major | 886-line `main.rs` holds all runtime wiring; untested | `crates/node/src/main.rs:96-513` | Move `config`/`actor`/`http` into the library; prover behind a trait. |
| NODE-02 | major | One actor serialises proving, admission and a 600 s settlement wait | `main.rs:327-348,419-462` | State actor + proving worker (`spawn_blocking`) + settlement task. |
| NODE-03 | moderate | Typed errors become `String`; every failure is 422 | `main.rs:221-245,682-686` | `ApiError: IntoResponse` with proper status codes. |
| NODE-04 | moderate | Demo/fixture code compiled into production binary | `crates/node/Cargo.toml:15`, `main.rs:59-60` | `demo` feature. |
| NODE-05 | moderate | Wallet endpoint returns 501 on success; clients depend on it | `main.rs:610-659` | 202 with explicit body. |
| NODE-06 | moderate | ACL and router are separate string tables; already drifted | `auth.rs:256-302` | One route table builds both. |
| NODE-07 | moderate | Hand-rolled base64url, rate limiter, signature workaround | `auth.rs:305-373`, `main.rs:519-526` | `base64` crate; `tower_governor` keyed by client. |
| NODE-08 | moderate | Ad hoc env/argv parsing, silent defaults | `main.rs:110-133` | `clap` derive with env fallbacks. |
| NODE-09 | moderate | No persistence or restart reconciliation | `main.rs:273-306,761-763` | Storage trait (append-only block log); reconcile with L1. |
| NODE-10 | minor | Dead error variants, helpers, dependencies | `tx.rs:60-71`, `state.rs:74-75` | Delete; add `cargo-machete`. |
| NODE-11 | minor | Metrics inconsistent with design notes | `metrics.rs:55-108` | Use `names::` constants; label by endpoint. |
| NODE-12 | minor | Duplicated construction and request plumbing | `sequencer.rs:227-268` | `new()` delegates to `funded()`; generic `ask<T>`. |

### Domain crates
| ID | Sev | Title | Evidence | Recommendation |
|---|---|---|---|---|
| DOM-01 | major | Docs describe the SHA3/Keccak 256-level design | `crates/pq-hash/src/lib.rs:3-20` | Type aliases define the choice once; no hash names in generic docs. |
| DOM-02 | major | "Executable spec" covers only the balance rule | `crates/shielded/src/lib.rs:6-9`, `transfer.rs:7-19` | `Transfer::validate` enforcing all four rules natively. |
| DOM-03 | moderate | Hasher-trait split nominal; framing unspecified; superseded hashers public | `crates/pq-hash/src/shielded.rs:98-105` | Document framing contract; remove dead hashers. |
| DOM-04 | moderate | `SpendAuth` seam bypassed by every caller; stub feature rotted | `crates/pq-sign/src/lib.rs:3-44` | Remove trait or complete it. |
| DOM-05 | moderate | `NullifierMap` invariants documented, not enforced; root recompute allocates heavily | `nullifier_tree.rs:64-176` | `NullifierAddr` key type; collision-aware insert. |
| DOM-06 | moderate | Vault types don't encode size invariants | `crates/vault/src/lib.rs:174-184,334-358` | Fixed-size arrays; checked cursor. |
| DOM-07 | moderate | Transfer wire schema hand-written in six places with differing validation | `crates/node/src/wire.rs:25-93`, `crates/wallet-wasm/src/lib.rs:358-408` | One shared `TransferWire` type. |
| DOM-08 | moderate | wasm ABI global state; lock invariant only in comments | `crates/wallet-wasm/src/lib.rs:109-169` | Single `State` with `with_state` accessor. |
| DOM-09 | moderate | Popup leaves note randomness to the user | `extension/popup.js:22-26,134-138` | Generate `rho`/`psi` in wasm. |
| DOM-10 | moderate | Committed wasm predates the source change that altered its outputs; gate never builds it | `extension/wallet_wasm.wasm` (only commit `1244c4a`) | Build in gate or `cmp` against committed. |
| DOM-11 | moderate | Newtypes protect public digests, not secrets | `crates/shielded/src/note.rs:49-127` | `SpendSecret`/`Rho`/`Psi` newtypes. |
| DOM-12 | moderate | Hand-picked examples only; `proptest` declared but unused | `crates/pq-hash/Cargo.toml:24-25` | Proptests for encoding injectivity and witness chaining. |

### Testing & tooling (lead measurements)
- **TST-01 (major)** — Test pyramid is parity-heavy: 64 parity/replay/golden-named tests vs 49 rejection-named, and most rejection tests are random byte flips rather than minimal violating inputs. *Fix:* the security report's check-inventory + field-aware differential mutation harness.
- **TST-02 (major)** — 48 of 254 Rust tests are `#[ignore]` vector generators; nearly every `crates/prover/tests/*.rs` is a generator, so what runs by default checks pins, not behaviour. *Fix:* keep generators in an `xtask`; make default tests assert properties.
- **TST-03 (moderate)** — 40 MB of committed vectors; `contracts/test` accounts for 3.16M of the repo's churned lines across 70 commits (500k-line JSON diffs per batch). *Fix:* binary-only vectors, content-addressed, regenerated in CI; prune the 28 unreferenced files.
- **TST-04 (moderate)** — No CI; `check.sh` silently skips `cargo-deny`/`semgrep` when absent; `forge fmt` deliberately excluded. *Fix:* CI running the gate with tools required.
- **TST-05 (minor)** — Build-environment drift: macOS-pinned toolchain paths in `scripts/build_extension.sh` and `.scratch` notes; committed wasm not reproducible.

### Vendoring (lead measurements)
- **VND-01 (major)** — `vendor/p3-recursion/PATCHES.md` lists 1 of 5 changed code files, misdescribes the ZK change, and cites a pristine copy (`.scratch/vendor/p3-recursion-pristine`) that is git-ignored and absent. *Fix:* keep upstream as a pinned submodule/subtree plus `patches/*.patch` applied by a script, and a CI step that re-applies and diffs.
- **VND-02 (moderate)** — The vendored tree builds with upstream's lint profile, so the workspace's deny-by-default lints never see the security-critical patched code. *Fix:* run clippy on the patched crates in the gate.
- **VND-03 (strength)** — `contracts/lib/sol-whir-p3/PATCHES.md` is the model to copy: each patch states why, what, blast radius, and the guarding test.

## Prioritised recommendations

| # | Change | Effort | Payoff | Resolves |
|---|---|---|---|---|
| 1 | One `protocol` module + typed `WhirParams` resolved at the binary edge; remove env reads from libraries | M | Single owner for every soundness parameter | ARCH-02, ARCH-03, EXP-09 |
| 2 | Typed settlement wire (`VectorsDoc`, `WireVersion`) replacing `Value` plumbing; provenance tagged at the transcript seam | L | Compiler separates CONFIG from PROOF; prerequisite for security V-01/V-02/V-03 fixes | EXP-01, EXP-02, EXP-06, SOL-03 |
| 3 | Check inventory + differential mutation harness (Rust reference vs Solidity) in CI | M | Turns the security process into a regression gate | TST-01, security V-02..V-05 |
| 4 | One verifying key per block shape (per-transfer constants become witnesses) | L | Fixes security V-01/V-06/H-03 together; removes per-transfer preprocessed data | PRV-09, DOM-02 |
| 5 | CI with tools required; vendored-patch re-apply/diff check | S | Gate runs every push; drift detected | TST-04, ARCH-08, VND-01, VND-02 |
| 6 | Move decision log into `docs/decisions/` as ADRs; one hash-policy table; purge stale docs | S | Newcomers and reviewers see the current design | ARCH-06, ARCH-07, PRV-01, DOM-01, SOL-08 |
| 7 | Delete dead code: Keccak table registrations, `sha3_block`, superseded hashers, JS encoders, probe forks (replace with one instrumented engine) | M | Less surface to audit | PRV-02, ARCH-09, EXP-03, EXP-04, SOL-02, SOL-07 |
| 8 | Contracts: compiler-derived selectors; `SatelliteFrames` library; `KoalaBearWire` library | M | Removes hand-maintained layouts that can silently desync | SOL-01, SOL-04, SOL-06 |
| 9 | Node: split `main.rs` into library modules; actor split (state / prover worker / settlement); `ApiError`; persistence; `demo` feature | L | Testable runtime; no 600 s stalls; restart-safe | NODE-01..09, ARCH-05 |
| 10 | Domain: shared `TransferWire`; secret newtypes; `Transfer::validate` native spec; proptests | M | One schema; executable spec covers all rules | DOM-02, DOM-07, DOM-11, DOM-12 |

## Metrics appendix

| Metric | Value |
|---|---|
| Rust LOC (non-blank, non-comment) | prover 14.2k (46 files), node 2.6k, shielded 1.3k, wallet-wasm 0.7k, pq-hash 0.5k, recursion-test 0.4k, vault 0.3k, pq-sign 0.2k |
| Solidity LOC | `src` 4.4k (19 files), `test` 9.3k (52 files) |
| Function length | Rust 789 fns, median 8, 14 > 100 lines, 5 > 200; Solidity 163 fns, median 13, 9 > 100, 1 > 200 |
| Longest functions | `TerminalWeight._qfold` 294, `wbnd::encode_bundle_impl` 267, `whir_walk::replay_rounds` 251, `constraint_ir::instance_identity_json` 248, `settlement_replay::manual_replay` 221, `block::build_multi_transfer_circuit` 200 |
| Largest files | `transfer.rs` 1470, `WhirVerifier.sol` 1382, `TerminalWeight.sol` 1379, `block.rs` 1313, `composed_export.rs` 1280 |
| Comment density | 27–33% |
| Inline assembly | 68 blocks, 44 `memory-safe` |
| Tests | 254 Rust (48 ignored), 177 forge in 41 files, 5 zero-test probe forks (48–68 KB each) |
| Hygiene | 358 `unwrap`/`expect` in non-test src (0 in node lib, 0 in core circuit modules), 31 `allow(clippy)`, 18 `unsafe` mentions, 0 TODO |
| History | 70 commits / 3 days / 50 "batch N"; churn 3.16M lines in `contracts/test`; 40 MB tracked vectors |
| Design notes | 8.6k lines in `.scratch/`; 237 `D-0xx` mentions in code (35 IDs) |
