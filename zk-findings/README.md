# zk-findings — audit deliverables for toy-zk-rollup

Engagement `toy-zk-rollup-2026-10-09`, audited revision `a54c197`, methodology
[zkcrypto-audit](https://github.com/Yue-Zhou1/zkcrypto-audit) (staged flow:
context → spec-delta → domain auditors → fp-check → report → prior-art index).

| Artifact | Path | Notes |
|---|---|---|
| Findings report | `reports/toy-zk-rollup-crypto-audit-report-2026-10-09.md` | 8 Critical, 3 High, 11 Medium, 8 Low, 7 Info; per-finding root cause, evidence level, remediation; discharged items; remediation priority |
| Report sources | `reports/parts/*.md` | the report is the concatenation of these parts |
| Extracted specification | `spec/toy-zk-rollup-spec.tex` (+ `spec/sections/*.tex`, `spec/preamble.tex`) | what the code *enforces*, section by section, every claim cited to `file:line`; §10 lists documentation-vs-code deltas |
| Specification PDF | `spec/toy-zk-rollup-spec.pdf` | built with `make -C spec` (pdflatex, two passes) |
| Session state | `sessions/toy-zk-rollup-2026-10-09.json` | schema-v2 handoff: trust boundaries, critical paths, route dispositions, fp-check verdicts, artifacts |
| Executable PoCs | `../contracts/test/audit/*.t.sol`, `../crates/prover/tests/poc_audit_f01.rs`, `../contracts/test/vectors/audit/` | V-01, H-01, M-01 (all pass on the audited revision) |

## Evidence levels used in the report

- **PoC (repo)** — a test on this branch that passes on the audited revision.
- **Experiment** — executed in a reviewer scratch copy against the real contracts / committed vectors; to be ported into `contracts/test/audit/`.
- **Structural** — `file:line` evidence with a runnable PoC sketched but not executed.

Per the methodology's Critical/High PoC gate, findings held at *experiment* or
*structural* should be treated as **pending in-repo PoC** in any client-facing
use; the report's "Verification status" section lists exactly which these are.

## Reproducing the in-repo PoCs

```sh
# Solidity (needs forge + solc 0.8.28; forge-std submodule initialised)
cd contracts && forge test --match-path 'test/audit/*.t.sol' -vv

# The V-01 vector generator (ignored by default; proves a forged settlement bundle)
cargo test -p prover --test poc_audit_f01 -- --ignored --nocapture
```
