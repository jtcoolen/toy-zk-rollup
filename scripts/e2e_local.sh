#!/usr/bin/env bash
# End-to-end local settlement: anvil -> deploy -> node -> demo transfer ->
# auto block production -> applyBlock verified on-chain.
#
#   scripts/e2e_local.sh
#
# Proves a real shielded transfer (SPHINCS+ spend auth, SHA3-256 notes,
# Poseidon2 child WHIR recursed into the block circuit), encodes the WBND v4
# settlement bundle, and has the Solidity verifier replay the whole WHIR
# proof with the native keccak256 opcode. Expect several minutes: three
# composed proving runs per block (two for the bundle's zero-run
# classification, one native verify inside it) plus the on-chain replay.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

export PATH="$HOME/.foundry/bin:$PATH"
export CARGO_HOME=${CARGO_HOME:-$ROOT/.cargo-home}
export PATH="$CARGO_HOME/bin:$PATH"

ANVIL_PID=""
NODE_PID=""
RPC=http://127.0.0.1:8545
NODE=http://127.0.0.1:3000
# Anvil's default dev account 0 - the settlement sender. The node holds no
# keys (D-080): eth_sendTransaction asks the *chain* to sign from this
# unlocked dev account, which is exactly the anvil dev-mode contract.
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

log() { printf '\n== %s\n' "$*"; }
die() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Toolchain discovery: a bare shell (cron, CI runner, fresh terminal without
# rustup's env sourced) has no cargo. Source rustup's env file if present,
# else pick the newest installed toolchain. Fail with instructions, not 127.
if ! command -v cargo >/dev/null 2>&1; then
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
  tc=$(ls -1d "$HOME"/.rustup/toolchains/*/bin 2>/dev/null | sort | tail -1)
  [ -n "$tc" ] && export PATH="$tc:$PATH"
fi
command -v cargo >/dev/null 2>&1 || die "cargo not found: install Rust via rustup or put cargo on PATH"
command -v anvil >/dev/null 2>&1 || die "anvil not found: install Foundry (https://getfoundry.sh)"
command -v forge >/dev/null 2>&1 || die "forge not found: install Foundry (https://getfoundry.sh)"

wait_rpc() { # url, name
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$1" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  die "$2 did not come up at $1"
}

# --- 0. build ---------------------------------------------------------------
log "build (dev profile is optimized)"
cargo build -p node --quiet
[ -x target/debug/node ] || die "node binary missing"

# --- 1. anvil ---------------------------------------------------------------
# The settlement calldata is ~2.8 MB and the proof replay burns ~1.6B gas, so
# anvil needs its request-size and block-gas limits raised (measured in the
# first on-chain settlement, commit b30b2a4).
log "start anvil"
anvil --chain-id 31337 --block-gas-limit 20000000000 --no-request-size-limit \
  > /tmp/e2e-anvil.log 2>&1 &
ANVIL_PID=$!
wait_rpc "$RPC" anvil

# --- 2. deploy --------------------------------------------------------------
# The pool must start at exactly the tree the node witnessed against: the
# node's demo genesis, not the prover-vector genesis. "node genesis" emits
# it in the shape Deploy.s.sol reads (GENESIS_FILE override).
log "node genesis -> deploy"
mkdir -p contracts/deployments
target/debug/node genesis --out contracts/deployments/genesis.json
cd contracts
GENESIS_FILE=deployments/genesis.json forge script script/Deploy.s.sol \
  --rpc-url "$RPC" --broadcast --private-key "$ANVIL_KEY" > /tmp/e2e-deploy.log 2>&1 \
  || { tail -20 /tmp/e2e-deploy.log; die "deploy failed"; }
cd "$ROOT"
grep -q '"pool"' contracts/deployments/local.json || die "manifest missing"
cat contracts/deployments/local.json

# --- 3. node ----------------------------------------------------------------
# A fresh random token key per run; the admin token covers produce/settle and
# the demo prover, the read token covers /health for the final assertions.
log "start node"
export NODE_TOKEN_KEY=$(xxd -p -l 32 /dev/urandom | tr -d '\n')
export NODE_SETTLE=1
export NODE_BLOCK_INTERVAL_MS=5000
export NODE_RPC_URL="$RPC"
ADMIN_TOKEN=$(target/debug/node token --role admin --ttl 3600)
READ_TOKEN=$(target/debug/node token --role readonly --ttl 3600)
target/debug/node > /tmp/e2e-node.log 2>&1 &
NODE_PID=$!
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -H "authorization: Bearer $READ_TOKEN" "$NODE/health" && break
  sleep 0.5
  [ "$_" = 30 ] && { tail -20 /tmp/e2e-node.log; die "node did not come up"; }
done
log "node up: $(curl -sf -H "authorization: Bearer $READ_TOKEN" "$NODE/health")"

# --- 4. a real shielded transfer ---------------------------------------------
# The scripted demo client (D-079c): the node builds the output note, proves
# the child transfer, signs with the fixture SPHINCS+ key, and admits it.
log "submit demo transfer (proves the child transfer - a minute or two)"
curl -sf -X POST -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  --data '{"input_index":0,"out_value":900,"fee":100}' "$NODE/v1/demo/transfer" \
  || { tail -30 /tmp/e2e-node.log; die "demo transfer failed"; }
echo

# --- 5. wait for the block driver to produce + settle ------------------------
log "wait for auto-produce + settlement (several minutes: proving + on-chain replay)"
for i in $(seq 1 180); do # 30 min ceiling
  if grep -q 'auto-settled' /tmp/e2e-node.log; then
    TXHASH=$(grep 'auto-settled' /tmp/e2e-node.log | head -1 | sed 's/.*hash=\(0x[0-9a-f]*\).*/\1/')
    break
  fi
  if grep -q 'auto-settle failed\|auto-produce failed' /tmp/e2e-node.log; then
    tail -40 /tmp/e2e-node.log; die "block driver reported failure"
  fi
  sleep 10
done
[ -n "${TXHASH:-}" ] || { tail -40 /tmp/e2e-node.log; die "no settlement after 30 min"; }
log "settled: tx $TXHASH"

# --- 6. verify on-chain -------------------------------------------------------
POOL=$(node -e 'console.log(require("./contracts/deployments/local.json").pool)')
log "on-chain state"
node contracts/scripts/pool_state.mjs "$TXHASH"
ROOT_ONCHAIN=$(curl -sf -X POST -H 'content-type: application/json' --data \
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$POOL\",\"data\":\"0xfdab463d\"},\"latest\"]}" \
  "$RPC" | sed 's/.*"result":"0x\([0-9a-f]*\)".*/\1/')
NODE_ROOT=$(curl -sf -H "authorization: Bearer $READ_TOKEN" "$NODE/v1/roots" | sed 's/.*"root":"\([0-9a-f]*\)".*/\1/')
echo "pool root:   $ROOT_ONCHAIN"
echo "node root:   $NODE_ROOT"
[ "$ROOT_ONCHAIN" = "$NODE_ROOT" ] || die "root mismatch: pool vs node"
HEIGHT=$(curl -sf -X POST -H 'content-type: application/json' --data \
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$POOL\",\"data\":\"0x57e871e7\"},\"latest\"]}" \
  "$RPC" | sed 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/')
[ "$((HEIGHT))" = 1 ] || die "expected blockNumber 1, got $HEIGHT"
log "metrics"
curl -sf -H "authorization: Bearer $READ_TOKEN" "$NODE/metrics" | grep -E "node_(submits_total|blocks_produced_total|block_prove_seconds_count)" || true
log "E2E GREEN: shielded block proven, verified on-chain, roots agree"
