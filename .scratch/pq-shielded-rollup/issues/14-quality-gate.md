# 14 - Quality gate: static analysis as a hard boundary

Type: task
Status: resolved
Blocked by: 01

## Question

How are "good quality and standards" actually enforced, rather than merely requested?

## Answer

A single `./scripts/check.sh` that runs every gate and fails the build on any finding.
Wired into CI. No gate is advisory.

### The gates

| Tool | Checks | Failure mode |
|---|---|---|
| `cargo fmt --check` | Formatting | hard fail |
| `cargo clippy --all-targets -- -D warnings` | Lints, `clippy::all` + `nursery` + pedantic crypto lints | hard fail |
| `cargo deny check` | License allowlist, advisory (RUSTSEC), duplicate versions, unknown crates | hard fail |
| `semgrep` (custom ruleset) | **Project-specific crypto misuse** | hard fail |
| `cargo test --all` | Unit + property tests | hard fail |
| `solc --via-ir` + `forge test` | Solidity compiles, contract tests pass | hard fail |

### Custom semgrep rules (`semgrep/pq-crypto.yml`)

The generic `p/rust` ruleset fired 13 rules and caught only `unsafe-usage` on our
sample — far too thin for mission-critical crypto. Custom rules encode **this
project's** threat model:

- `pq-no-legacy-signature` — flags `secp256k1`, `ed25519`, `ecdsa`, `schnorr`,
  `ring::signature::Ed25519`. **Enforces the PQ requirement mechanically.**
- `pq-no-legacy-hash` — flags `md5`, `sha1`, `Ripemd`, `blake2b` in security paths.
- `pq-no-poseidon-outside-prover` — enforces the ticket-05 Poseidon scope.
- `pq-no-insecure-rng` — flags `rand::thread_rng` / `OsRng` misuse where a
  `CryptoRng` bound is required; flags `StdRng`/`SmallRng` outside tests.
- `pq-no-unsafe-in-crypto` — flags `unsafe` in `pq-crypto`/`shielded` (allowlist for
  audited trace-alignment code only).
- `pq-no-secret-in-format` — flags `{:?}`/`format!`/`println!`/`tracing` on types
  named `*SecretKey*`, `*Seed*`, `*SpendingKey*`, `*Blinding*`.
- `pq-unwrap-in-production` — flags `.unwrap()` / `.expect()` outside tests in
  mission-critical crates.
- `pq-constant-time-compare` — flags `==` on secret byte slices; requires `constant_time_eq`
  or `subtle::ConstantTimeEq`.
- `pq-zeroize-on-drop` — flags secret-bearing structs lacking `Zeroize`/`ZeroizeOnDrop`.
- `pq-no-hardcoded-key-material` — flags long hex/base64 literals assigned to key-named
  variables.

### Environment notes discovered while wiring this

- `semgrep` crashes writing `~/.semgrep/semgrep.log` under the file sandbox → run with
  `HOME=<workspace>/.home`.
- `brew install` is sandbox-blocked (cache dir denied) → install Rust tools with
  `cargo install --locked` into the workspace `CARGO_HOME`.
- `CARGO_HOME` **cannot** be set from cargo's own `[env]` table ("setting the
  `CARGO_HOME` environment variable is not supported in the `[env]` configuration
  table") → it must be exported by the wrapper script.

### KISS

One script, one entry point. Every gate is a standard tool with a config file checked
into the repo. Nothing custom beyond the semgrep rules, which are themselves just YAML.
