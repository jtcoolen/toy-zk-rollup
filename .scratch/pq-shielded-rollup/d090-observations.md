# D-090 observations — wallet e2e with failure paths

Directive: "record e2e testing task with stronger integration test with
metamask/wallet".

## What landed

- **`scripts/e2e_wallet.sh` + `scripts/e2e_wallet.mjs`**: the extension's own
  code — `extension/wallet.js` (the real 246 KB wasm, same arena path the MV3
  popup uses) and `extension/node-client.js` (the same fetch client) — driven
  headless against a live node. No browser, no chain: this is the wallet↔node
  loop; the on-chain leg stays in `scripts/e2e_local.sh`.
- Covered, all green first run:
  1. happy: vault create → noteCommit → noteNullifier → signTransfer →
     local verifyTransfer → POST /v1/transfer → 501 (verified, deferred);
  2. bad-sig: fee tampered after signing → 422 "envelope rejected … signature";
  3. stale-root (bogus): witnessed root '00…' → 422 "state rejected …
     witnessed against root";
  4. real spend: /v1/demo/transfer (child proof) + /v1/block/produce (block
     proof) → the demo response's nullifier is a genuinely settled nullifier;
  5. double-spend: re-spend that nullifier against current roots → 422
     "state rejected: nullifier already spent";
  6. stale-root (real): an envelope witnessed against pre-block roots, replayed
     after the block → 422 (roots moved);
  7. happy again on the new state → 501;
  8. /metrics shows node_tx_rejections_total{reason="envelope"|"state"} moved.
- **Node change (fc246f5)**: /v1/transfer previously answered 501 for every
  well-signed envelope — double-spend and stale-root were invisible on the
  wallet path (they lived only in proof-time admission). Now the submit handler
  routes the parsed statement through the actor (Cmd::CheckAdmit →
  PoolState::check_admit against the committed state). 422 + reason + metric
  label. Actor routing keeps the read on the same state the block driver
  mutates — no lock inversion, no torn reads.

## Decisions

- **Committed-state check, not pending projections, on /v1/transfer.** The
  wallet witnessed /v1/roots (committed). A queued transfer that later makes
  this stale is caught again at proof-time admission (which does check
  pending). Answering the wallet's actual question beats pretending to check
  what it cannot have witnessed.
- **No envelope-replay set.** Re-submitting the same valid envelope is
  idempotent-ish (501 again) and harmless while proof admission is deferred;
  the nullifier check already blocks the meaningful replay (spend twice).
  Revisit when remote proof admission lands: the mempool insert is the replay
  guard then.
- **Driver uses the shipped extension artifacts, not copies.** If wallet.js or
  node-client.js drifts, the e2e breaks — that is the point.
- **Block produced manually via admin token** (driver interval set to 1 h) so
  the test never races the auto-produce loop.

## Runtime

~4 min total: wasm build + smoke, child proof (~70 s), block proof (~2 min).
Logs: /tmp/e2e-wallet-node.log, /tmp/e2e-wallet-wasm.log, run log wherever the
caller redirects.

## Follow-ups

- When D-079's verifier-rebuild path lands, /v1/transfer should accept the
  proof and go through Sequencer::submit (pending projections + proof verify);
  the e2e's 501 expectations become 200s and the double-spend case moves to
  the mempool layer. The script's structure survives that change.
- D-091 README should document scripts/e2e_wallet.sh as the wallet-path test
  and this file's failure matrix.
