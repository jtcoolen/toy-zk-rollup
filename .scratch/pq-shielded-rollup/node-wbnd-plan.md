# Node WBND plan — prove → encode → settle, in Rust

Status file. Steps A–D are done and committed; E is in progress; F is queued.
This file replaces the earlier copy (lost with the scratch cleanup); decisions
carry the durable rationale, this file carries the working plan and status.

## Context (settled facts the plan builds on)

- Layer stack, all proven on-chain: transfer/fib proof (Poseidon2 WHIR,
  recursed) → recursion/block circuit → settlement proof =
  `BatchStarkProof<crate::whir::Config>` (Keccak config, `crates/prover/src/whir.rs`)
  = exactly what `WhirVerifier.sol` replays via `p3_batch_stark::verify_batch`
  with WHIR core as the PCS layer.
- E2E settlement already demonstrated from scripts: anvil (chain 31337,
  `--block-gas-limit 20000000000 --no-request-size-limit`), `applyBlock` tx
  `0xf8b2540c…` status 0x1, gas ~1.64e9, currentRoot == block_genesis
  pool_root_after_hex.
- Selectors pinned in `contracts/test/SelectorPins.t.sol`:
  applyBlock(uint256[],bytes)=`0cb000b5`, blockNumber=`57e871e7`,
  currentRoot=`fdab463d`, currentNullifierRoot=`222d1bed`.
- Manifest `contracts/deployments/local.json`: verifier
  0x5FbDB2315678afecb367f032d93F642f64180aa3, pool
  0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512, deployer
  0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (anvil key 0), chainId 31337.
- WBND v4 wire: magic `WBND` + version u8=4 @4 + cfg_words u32 LE @8 +
  prf_words u32 LE @12; header 16 B; CONFIG at word 4, PROOF after, STATEMENT
  last (length-prefixed). CONFIG carries the CONSTRAINTS tail (D-076).
- Block bundle v4: 2,825,568 B (cfg 58,837 w, prf 646,782 w, stm 769 w).

## Steps

- [x] **A. `whir_walk` → prover lib** (`5b1bd87`)
- [x] **B. `settlement_replay` → prover lib** (`a990945`)
- [x] **C. `composed_export` + `constraint_ir` → prover lib** (`c1c1fcb`)
- [x] **D. `prover::wbnd` encoder** (`4df43ad`) — `flat_from_vectors` +
  `encode_bundle`, byte-identical to the JS generators, pinned by
  `crates/prover/tests/wbnd_pin.rs` (fib + block artifacts, first-differing-
  byte report). The node no longer needs to shell out to node scripts.
- [ ] **E1. Node binary** (`crates/node/src/main.rs` + `settlement.rs`) — design below.
- [ ] **E2. Local-chain E2E script**: anvil → deploy → node → block → applyBlock
  verified on-chain, all driven by one `scripts/e2e_local.sh`.
- [ ] **F. MV3 wallet extension** (encrypted keystore, SPHINCS+ spend auth,
  tx build/submit UX) + Grafana dashboard + Prometheus wiring.

## Step E design (D-079/D-080, recorded in decisions.md)

### Shape

`node` bin = axum HTTP server + sequencer + settlement sender in one process.

Routes (ACL from `node::auth::Acl::default_policy`, bearer tokens):

| route | role | behavior |
|---|---|---|
| `GET /health` | public | liveness |
| `GET /metrics` | public | Prometheus exposition (`node::metrics::install_recorder` handle) |
| `GET /v1/state` | ReadOnly | block number, roots, mempool depth |
| `GET /v1/roots` | ReadOnly | the two roots only |
| `POST /v1/transfer` | Submitter | wire envelope admission (see seam below) |
| `POST /v1/block/produce` | Admin | run one block cycle synchronously, return artifact summary |
| `POST /v1/admin/issue-token` | Admin | dev convenience: issue a token for a role |

Block cycle (triggered by the admin route or `--block-loop N` seconds):

1. `Sequencer::produce_block()` → `BlockArtifact { statement, proof, verifier, … }`
   (already verifies the block proof natively — the contract rehearsal).
2. Composed export in-memory: `composed_run_with` → doc/blob →
   `wbnd::flat_from_vectors` → `wbnd::encode_bundle` → WBND bytes.
   (Refactor: extract the `export_and_write` tail into `build_vectors_doc`
   returning `(doc, blob)` so nothing touches disk.)
3. Settlement sender (`settlement.rs`): ABI-encode
   `applyBlock(uint256[],bytes)` (selector `0cb000b5`; statement words as
   32-byte BE words), raw JSON-RPC `eth_sendTransaction` from the configured
   unlocked dev account (the node holds NO keys), poll receipt, record
   success/failure metrics.

Metrics: reuse `node::metrics` recorder; add `node_block_prove_seconds`,
`node_settle_seconds`, `node_settle_tx_total{outcome}`, `node_mempool_depth`.

### The child-verifier seam (recorded honestly)

`ClientTransferProof` carries a `CircuitVerifier` that is not wire-serializable.
Options:

- (a) `CircuitVerifier::from_independently_trusted_builtin_artifact` — vendor
  API for rebuilding a verifier from provisioned artifact parts; needs an
  artifact decoder + trust anchor pipeline. Production path, not built yet.
- (b) Rebuild the transfer circuit from public data (every baked constant —
  root, nullifier roots, membership siblings, index bits, output `pk_d` — is
  public; only witnesses are private) via a new verifier-only prover API, then
  `prepare_circuit` without proving. Feasible; deferred.
- (c) **Chosen for E**: the demo client proves in-process (same fixtures as
  `crates/node/tests/sequencer.rs`) and hands the full bundle to the
  sequencer — full child-proof verification, no mocks in the proving path.
  `POST /v1/transfer` accepts the wire envelope (statement + SPHINCS+ signature)
  and performs envelope + state-admission checks; the proof-carrying submit
  lands with (a)/(b). The sequencer docs already call this seam out.

### Settlement sender details (D-080)

- Port of `contracts/scripts/settle_block.mjs`: hand-rolled ABI encoder
  (dynamic array + dynamic bytes after a static selector), no new deps.
- JSON-RPC over `reqwest` (already a dev-dep; promote to dep), POST only,
  plain http for localhost.
- Receipt poll: `eth_getTransactionReceipt` every 2 s up to 600 s (block proof
  calldata is 2.8 MB; anvil accepts it with the raised limits).
- Failure posture: log + metric + keep the artifact for retry; never re-send
  blindly (track submitted block numbers).

## Commands (environment)

```sh
export PATH="/Users/julian/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$HOME/.foundry/bin:$PATH"
export CARGO_HOME=/Users/julian/zk_rollup/.cargo-home
# forge only from /Users/julian/zk_rollup/contracts
# anvil: anvil --chain-id 31337 --block-gas-limit 20000000000 --no-request-size-limit --silent
# pin:   cargo test -p prover --test wbnd_pin
# export regen (fresh randomness! git checkout vectors after unless regenerating deliberately):
#   cargo test -p prover --test composed_vectors composed_program_equality_and_export -- --ignored
#   node contracts/scripts/gen_composed_flat.mjs <flat> <vectors>
#   node contracts/scripts/gen_bundle.mjs <flat> <vectors> <out>
```

## Deferred (do not start before e2e)

- D-077: Poseidon2-KoalaBear fold of block public inputs; ShieldedPool root
  recompute from calldata leaves.
- D-068: gas benchmark + EIP-170 reductions; WhirVerifier ~17.2 KB (7.4 KB margin).
- Test-target lint backlog (136 pre-existing clippy errors) — dedicated hygiene commit.
