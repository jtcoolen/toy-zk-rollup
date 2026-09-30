# 04 - Recursion source of truth: git, not crates.io

Type: task
Status: resolved
Blocked by: 01

## Question

Where does the workspace get `p3-recursion` from, and what exactly is pinned?

## Answer

**Pin the git rev.** The crates.io release is unusable.

Verified against the sparse index:

```
p3-recursion 0.1.0  deps: []   pubtime: 2025-08-30
```

Zero dependencies. A real recursion crate must depend on `p3-air`, `p3-fri`,
`p3-uni-stark`, `p3-batch-stark`, `p3-circuit`, and friends. The published crate is an
**empty placeholder** — a name reservation, not the library. Depending on it would
compile and then provide nothing.

The real library lives at `github.com/Plonky3/Plonky3-recursion` (active, pushed
2026-09-25). Its own workspace declares `p3-circuit`, `p3-circuit-prover`,
`p3-poseidon2-circuit-air`, etc. as **path** dependencies, so a git dependency on
`p3-recursion` pulls the whole repo and resolves those internally.

### Decision

```toml
p3-recursion = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<pinned>" }
```

Pin a **rev**, not a branch. A branch drift would silently change the verifier circuit,
which invalidates every proof the network has accepted. A rev makes that a deliberate,
reviewed upgrade.

### Standing risk (tracked, not solved here)

The upstream README states plainly: *"This codebase is under active development and
hasn't been audited yet. We do not recommend its use in any production software."*

This is accepted for the foundation. It is **not** accepted for mainnet. The upgrade
path is: pin rev → audit → bump rev. Recorded in
[Recursion audit gate](16-recursion-audit-gate.md).
