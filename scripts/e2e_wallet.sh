#!/usr/bin/env bash
# Wallet-facing end-to-end: node -> real wasm wallet (the extension's own
# wallet.js + node-client.js) -> happy path, bad-sig, stale-root, double-spend.
#
#   scripts/e2e_wallet.sh
#
# No chain needed: this loop is wallet <-> node (envelope validation + state
# admission). The on-chain leg is scripts/e2e_local.sh. The block is produced
# manually (admin token) so the test does not race the auto-driver; the block
# interval is set far out to keep the driver idle.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

export CARGO_HOME=${CARGO_HOME:-$ROOT/.cargo-home}
export PATH="$CARGO_HOME/bin:$HOME/.foundry/bin:$PATH"

NODE=http://127.0.0.1:3000
NODE_PID=""
log() { printf '\n== %s\n' "$*"; }
die() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
cleanup() { [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true; }
trap cleanup EXIT

if ! command -v cargo >/dev/null 2>&1; then
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
  tc=$(ls -1d "$HOME"/.rustup/toolchains/*/bin 2>/dev/null | sort | tail -1)
  [ -n "$tc" ] && export PATH="$tc:$PATH"
fi
command -v cargo >/dev/null 2>&1 || die "cargo not found"
command -v node >/dev/null 2>&1 || die "node not found"

log "build node + extension wasm"
cargo build -p node --quiet
[ -x target/debug/node ] || die "node binary missing"
# The wasm the driver loads is the extension's shipped artifact; rebuild +
# smoke it so the test runs the same bytes the popup ships.
scripts/build_extension.sh > /tmp/e2e-wallet-wasm.log 2>&1 \
  || { tail -20 /tmp/e2e-wallet-wasm.log; die "wasm build/smoke failed"; }

log "start node (no settlement, driver idle)"
export NODE_TOKEN_KEY=$(xxd -p -l 32 /dev/urandom | tr -d '\n')
export NODE_BLOCK_INTERVAL_MS=3600000
ADMIN_TOKEN=$(target/debug/node token --role admin --ttl 3600)
SUBMIT_TOKEN=$(target/debug/node token --role submitter --ttl 3600)
READ_TOKEN=$(target/debug/node token --role readonly --ttl 3600)
export ADMIN_TOKEN SUBMIT_TOKEN READ_TOKEN NODE_URL=$NODE
target/debug/node > /tmp/e2e-wallet-node.log 2>&1 &
NODE_PID=$!
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -H "authorization: Bearer $READ_TOKEN" "$NODE/health" && break
  sleep 0.5
  [ "$_" = 30 ] && { tail -20 /tmp/e2e-wallet-node.log; die "node did not come up"; }
done

log "wallet e2e (proves a child transfer + a block along the way - minutes)"
node scripts/e2e_wallet.mjs || { tail -40 /tmp/e2e-wallet-node.log; die "wallet e2e failed"; }
log "E2E WALLET GREEN"
