# Post-Quantum Shielded-Pool zk-Rollup (WHIR stack)

A working end-to-end demonstration of a shielded value pool that proves its
own state transitions with **STARKs only** — no SNARKs, no elliptic-curve
crypto anywhere in the trust path — and settles on an EVM chain by replaying
the proof with Solidity's native `keccak256` opcode.

The proof stack is Plonky3 + Plonky3-recursion on the KoalaBear field:
`p3-multi-stark` child proofs, `p3-whir` commitments, recursion through
`p3-recursion`'s `WhirRecursionBackend`, and a generated Solidity verifier
that re-runs the whole WHIR/FRI verification on-chain. Spend authorization is
SPHINCS+ (`slh-dsa`), nullifiers are SHA3-256, and the wallet is a plain
MV3 browser extension whose crypto is the *same Rust crates the node runs*,
compiled to WebAssembly.

```
wallet (MV3 + wasm)         node (Rust)                       settlement (EVM)
+----------------+  HTTP  +-------------------+  bundle   +--------------------+
| SPHINCS+ vault | -----> | sequencer actor   | --------> | ShieldedPool       |
| note commit    | envelope| mempool + proofs | keccak    |  WhirVerifier      |
| note nullifier | 501/422 | block circuit    | transcript|  (keccak256 opcode)|
+----------------+         +-------------------+          +--------------------+
 SHA3-256 nullifiers       transfer proofs (WHIR,         applyBlock: the proof
 Poseidon2 note tree       Poseidon2 transcript)          replays natively;
 SPHINCS+ signatures       block proof (recursed,         roots + fees move,
                           Keccak transcript)            nullifiers retire
```

## What is demonstrated, end to end

1. **Shielded transfers.** A note commits as `Keccak-256(DOMAIN ‖ value ‖
   rho ‖ psi ‖ pk_d)` — the commitment hasher is Keccak so the settlement
   layer can replay it. The commitment tree Merkleizes those leaves with
   **Poseidon2** (the one granted hash seam — the contract never opens it);
   the nullifier map is a **Keccak-256** map. Nullifiers themselves are
   **SHA3-256** over `(DOMAIN ‖ sk_d ‖ rho)` — user-facing privacy material
   gets the FIPS-202 primitive. Spend authorization is a SPHINCS+ signature
   over a canonical statement encoding.
2. **Per-transfer STARKs.** Each transfer is proven with a multi-matrix AIR
   (`p3-multi-stark`) whose WHIR commitments run over a Poseidon2 transcript.
3. **Block = one recursed proof.** The block circuit *verifies its children
   in-circuit* (recursion via `WhirRecursionBackend`), chains their state
   transitions, and folds every child's *verified* public statement into a
   single 256-bit `statementRoot` (D-089). One block proof attests to N
   transfers; the settlement layer sees one root, not N statements.
4. **SNARK-free EVM settlement.** The block proof's WHIR transcript is
   re-instantiated with a **Keccak-256** config, so the generated Solidity
   verifier replays the entire FRI/WHIR verification using only the native
   `keccak256` opcode. `ShieldedPool.applyBlock` checks the proof against the
   statement, pins `statementRoot`, enforces root/nullifier continuity, and
   applies the state update.
5. **A real wallet.** The MV3 extension creates a password-protected SPHINCS+
   vault in wasm, witnesses roots from the node, builds and signs transfers
   locally, and submits them through the same client the headless e2e drives.

## Repository layout

| path | what it is |
|---|---|
| `crates/pq-hash` | SHA3-256 note/nullifier hashing, Poseidon2 trees/commitments |
| `crates/pq-sign` | SPHINCS+ (`slh-dsa`) key/sign/verify wrappers, canonical statement encoding |
| `crates/vault`   | password-derived SPHINCS+ vault format (shared wallet/node) |
| `crates/shielded`| transfer statement, witness, admission rules (`PoolState`) |
| `crates/prover`  | transfer + block circuits, WHIR configs (Poseidon2 + Keccak), statement fold, vector generators |
| `crates/node`    | sequencer actor, HTTP API, tokens/ACL/rate-limit, settlement submitter |
| `crates/wallet-wasm` | the wasm the extension ships (same crates as the node) |
| `crates/recursion-test` | recursion harnesses against upstream `p3-recursion` |
| `contracts/`     | `ShieldedPool`, `BlockStatement` decoder, `LimbCodec`, generated `WhirVerifier` + tests |
| `extension/`     | MV3 wallet (plain JS + wasm; see `extension/README.md`) |
| `vendor/p3-recursion` | the recursion tree (upstream repo, own workspace) |
| `scripts/`       | quality gate + the two end-to-end drivers |
| `.scratch/pq-shielded-rollup/` | the wayfinder map, decision log, per-task observations |

## Prerequisites

- Rust **1.98.1** (pinned in `rust-toolchain.toml`), plus the `wasm32-unknown-unknown`
  target for the extension wasm.
- [Foundry](https://book.getfoundry.sh) (`forge`, `cast`, `anvil`) for settlement + contract tests.
- Node.js ≥ 20 (e2e drivers, vector generators).
- `cargo deny` and `semgrep` for the full quality gate.

This repo keeps tool state inside the workspace: `CARGO_HOME=.cargo-home`
(set via `.cargo/config.toml`) and, for the wasm build, a workspace-local
`RUSTUP_HOME` — see `scripts/build_extension.sh`.

## Run the demo (local chain)

```sh
scripts/e2e_local.sh
```

Brings up anvil, deploys `WhirVerifier` + `ShieldedPool` seeded with the
Poseidon2 genesis root, starts the node with settlement enabled, runs a demo
transfer through the prover, lets the block driver produce + settle, and
asserts the on-chain roots match the node's. Expect several minutes (three
composed proving runs + an on-chain replay; settlement tx ≈ 193 M gas).

## Run the wallet path (headless)

```sh
scripts/e2e_wallet.sh
```

Drives the extension's *own* artifacts — the shipped `wallet_wasm.wasm`
through `extension/wallet.js` and the popup's `node-client.js` — against a
live node, no browser and no chain. Covers the full failure matrix: happy
path (501 = signature verified and the state accepted the statement),
tampered-signature 422, stale-root 422 (bogus and superseded), and a real
double-spend of a settled nullifier → 422. See
`.scratch/pq-shielded-rollup/d090-observations.md`.

To use the extension for real: `chrome://extensions` → Load unpacked →
`extension/`, then follow `extension/README.md` (issue a submitter token with
`target/debug/node token --role submitter --ttl 3600`).

## The node API in one table

| endpoint | role | behavior |
|---|---|---|
| `GET /health` | — | liveness |
| `GET /metrics` | ReadOnly | Prometheus text format |
| `GET /v1/state`, `GET /v1/roots` | ReadOnly | committed state + witness roots |
| `POST /v1/transfer` | Submitter | SPHINCS+ envelope: parse + verify + state admission (double-spend / stale root → 422); valid + admissible → 501 (remote *proof* admission deferred, D-079) |
| `POST /v1/demo/transfer` | Admin | the working demo prover path |
| `POST /v1/block/produce` | Admin | prove + seal the pending block |
| `POST /v1/block/settle` | Admin | submit the settlement bundle to the chain |

Tokens are HMAC-MAC'd bearer tokens (`node token --role <role> --ttl <s>`);
the ACL, rate limiter, and body-size cap are documented in
`crates/node/src/{auth,main}.rs`.

## Tests and the quality gate

```sh
scripts/check.sh          # the full gate: fmt, clippy -D warnings, cargo test,
                          # cargo deny, semgrep crypto rules, forge test
```

Focused runs while iterating:

```sh
cargo test -p prover                      # circuits, vectors (generators are #[ignore])
cargo test -p node                        # sequencer + HTTP unit tests
(cd contracts && forge test -vv)          # Solidity: decoder, pool, full proof replay
node extension/smoke.mjs                  # the shipped wasm ABI
```

Golden vectors under `crates/prover/tests/` pin the proof artifacts the
contracts replay; `check_block_vectors` recomputes the D-089 statement fold
on every `cargo test`, so prover/contract drift fails loudly. Regenerating
vectors: run the `#[ignore]`d generators, then `node contracts/scripts/gen_composed_flat.mjs
block_composed_vectors block_composed_flat` and `gen_bundle.mjs` **from the
repo root**.

## Security model, honestly

- **What the chain verifies.** The block proof itself (WHIR/FRI replay over
  Keccak-256), the statement's shape, `statementRoot` pinning, root/nullifier
  continuity between consecutive blocks, and fee accounting.
- **What the chain trusts.** The deployed verifier contract (generated, then
  reviewed), the genesis root baked at deployment, and the operator set allowed
  to call `applyBlock`. `statementRoot` is pinned as an opaque public input —
  the contract cannot open Poseidon2, and does not need to: the fold consumes
  the *verified* child statements in-circuit, so the root cannot describe
  anything other than the proofs that were verified.
- **Wallet trust boundary.** Keys never leave the wasm vault; the node sees
  nullifiers, commitments, and a SPHINCS+ signature, never secrets.
- **Deferred, and labeled in code**: remote *proof* admission on
  `/v1/transfer` (D-079 — the envelope + state checks above are live), and the
  verifier-size redesign (D-086). Neither weakens settlement: the demo path
  settles through the same verifier the e2e exercises.

## Deeper reading

- `.scratch/pq-shielded-rollup/map.md` — the wayfinder map: destination,
  constraints, ticket ledger.
- `.scratch/pq-shielded-rollup/decisions.md` — decision log (D-001 … D-090).
- `extension/README.md` — wallet setup and the wasm ABI.
- `.scratch/pq-shielded-rollup/verifier-progress.md` and `whir-core-notes.md` —
  the generated `WhirVerifier` and the proof ABI it replays.

## Status

Demo-complete: transfer → block → on-chain verification → wallet loop all
green locally (`scripts/e2e_local.sh`, `scripts/e2e_wallet.sh`, full gate
`scripts/check.sh`). Production hardening is ticketed in the map, not hidden.
