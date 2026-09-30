#!/usr/bin/env bash
#
# The single quality gate. Every commit must pass this.
#
# Design: fail fast, fail loud, no partial passes. Each stage prints a banner so a
# failure is obvious in a wall of output.
#
# Environment notes (this machine):
#   - CARGO_HOME is workspace-local because ~/.cargo is not writable in the sandbox.
#   - The Rust toolchain lives under the *real* home's .rustup, so its path is
#     resolved before any HOME override is applied.
#   - semgrep wants to write ~/.semgrep/semgrep.log, so it gets its own HOME
#     override (a workspace dir) applied only to the semgrep invocation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Resolve the Rust toolchain bin dir explicitly.
#
# Callers must NOT pre-set HOME to the semgrep override: this script owns that
# override and applies it only to the semgrep invocation, so `$HOME` here is the
# real home and `$HOME/.rustup` resolves correctly. `RUSTUP_TOOLCHAIN_BIN` can
# override the location explicitly.
find_toolchain_bin() {
  local candidates=(
    "${RUSTUP_TOOLCHAIN_BIN:-}"
    "$HOME/.rustup/toolchains/1.90.0-aarch64-apple-darwin/bin"
  )
  local c
  for c in "${candidates[@]}"; do
    if [ -n "$c" ] && [ -x "$c/cargo" ]; then
      printf '%s' "$c"
      return 0
    fi
  done
  return 1
}

TOOLCHAIN_BIN="$(find_toolchain_bin)" || {
  printf '\n\033[1;31mCould not locate the Rust toolchain. Set RUSTUP_TOOLCHAIN_BIN.\033[0m\n'
  exit 1
}

export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
export PATH="$CARGO_HOME/bin:$TOOLCHAIN_BIN:$PATH"

# semgrep needs a writable HOME; keep it inside the workspace.
SEMGREP_HOME="$ROOT/.home"
mkdir -p "$SEMGREP_HOME"

banner() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
fail()   { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$1"; exit 1; }

# ---------------------------------------------------------------------------
banner "rustfmt"
cargo fmt --all --check || fail "cargo fmt --check (run: cargo fmt --all)"

# ---------------------------------------------------------------------------
banner "clippy (-D warnings)"
cargo clippy --workspace --all-targets -- -D warnings \
  || fail "clippy found warnings or errors"

# ---------------------------------------------------------------------------
banner "tests"
cargo test --workspace || fail "test suite failed"

# ---------------------------------------------------------------------------
banner "cargo-deny (licenses, advisories, duplicate versions)"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check licenses advisories bans || fail "cargo deny"
else
  echo "cargo-deny not installed; skipping (install: cargo install cargo-deny --locked)"
fi

# ---------------------------------------------------------------------------
banner "semgrep (custom post-quantum crypto rules)"
if command -v semgrep >/dev/null 2>&1; then
  HOME="$SEMGREP_HOME" semgrep scan \
    --config "$ROOT/semgrep/pq-crypto.yml" \
    --error \
    crates/ || fail "semgrep found a policy violation"
else
  echo "semgrep not installed; skipping"
fi

# ---------------------------------------------------------------------------
banner "Solidity"
if command -v forge >/dev/null 2>&1 && [ -f "$ROOT/contracts/foundry.toml" ]; then
  ( cd "$ROOT/contracts" && forge build && forge test ) || fail "forge build/test"
else
  echo "forge not available; skipping Solidity"
fi

printf '\n\033[1;32mALL CHECKS PASSED\033[0m\n'
