#!/usr/bin/env bash
# build.sh - produce the extension's wasm artifact and smoke-test it.
#
# Uses the workspace-local toolchain (the one carrying wasm32-unknown-unknown)
# and copies the release artifact into extension/. Run from the repo root or
# anywhere: paths are resolved from this script's location.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TC="$ROOT/.rustup-home/toolchains/1.98.1-aarch64-apple-darwin"
if [[ ! -d "$TC" ]]; then
  echo "error: workspace toolchain not found at $TC" >&2
  echo "see .scratch/pq-shielded-rollup/knowledge-base.md 'wasm toolchain facts'" >&2
  exit 1
fi
export PATH="$TC/bin:$PATH"
export RUSTUP_HOME="$ROOT/.rustup-home"
export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
cd "$ROOT"
cargo build --release -p wallet-wasm --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/wallet_wasm.wasm extension/wallet_wasm.wasm
node extension/smoke.mjs
echo "extension/wallet_wasm.wasm ready ($(wc -c < extension/wallet_wasm.wasm) bytes)"
