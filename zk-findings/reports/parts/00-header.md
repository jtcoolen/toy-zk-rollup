# Security Audit Report: toy-zk-rollup (PQ shielded-pool zk-rollup, WHIR stack)

- **Engagement:** `toy-zk-rollup-2026-10-09`
- **Revision audited:** `a54c1976b875f73beafa3aeab5521866ed971399` (branch `claude/friendly-wright-zfku6d` carries the audit artifacts)
- **Methodology:** zkcrypto-audit staged flow (router, context, spec-delta, domain auditors, fp-check, report, zkbugs-index)
- **Companion specification:** `zk-findings/spec/toy-zk-rollup-spec.tex`
- **Session state:** `zk-findings/sessions/toy-zk-rollup-2026-10-09.json`

> This report supports human review. Severities and verdicts should be confirmed by the
> maintainers before any external use.

## Scope

| Area | Paths |
|---|---|
| Settlement contracts | `contracts/src/ShieldedPool.sol`, `BlockStatement.sol`, `LimbCodec.sol` |
| On-chain verifier | `contracts/src/verifier/*` (deployed path: `WhirVerifier`, `WhirVerifierCore`, `TerminalWeight`), `contracts/lib/sol-whir-p3/{field,transcript}` |
| Circuits | `crates/prover/src/{transfer,block,client,nullifier_gadget,commitment_gadget,whir_recursion,whir}.rs` |
| Shielded model | `crates/shielded`, `crates/pq-hash` |
| Vendored recursion (in scope) | `vendor/p3-recursion` (Plonky3-recursion @ `8f9876ef` plus local patches) |
| Application | `crates/node`, `crates/pq-sign`, `crates/vault`, `crates/wallet-wasm`, `extension/` |

Out of scope: upstream Plonky3 crates from crates.io (consulted as the reference for the verifier semantics), economic parameters, deployment infrastructure.

## Methodology

1. **Context.** Trust boundaries, critical paths, roles-and-guarantees table (session state).
2. **Spec delta.** Code compared against its own documentation and the reference Plonky3 / p3-whir verifiers. The extracted specification is the companion LaTeX document.
3. **Domain review.** Four parallel reviews: on-chain verifier; transfer and block circuits; vendored recursion (including a diff against the pinned upstream revision); node, wallet and spend authorization.
4. **Verification.** Critical and High claims require executable evidence. Evidence levels used below:
   - **PoC (repo):** a test committed to this branch that passes on the audited revision.
   - **Experiment:** an executed test in the reviewer's scratch copy against the real contracts or committed vectors; to be ported into the repo.
   - **Structural:** file:line evidence only.
5. **Reporting.** One entry per finding with root cause, impact, evidence and remediation.

## Summary of findings

| ID | Severity | Title | Evidence |
|---|---|---|---|
| V-01 | Critical | Settlement verifier not bound to the block circuit (CONFIG not pinned) | PoC (repo) |
| V-02 | Critical | WHIR opening points not bound to the transcript point zeta | Experiment |
| V-03 | Critical | Per-round WHIR commitments not checked against the batch-phase digests | Experiment + structural |
| V-04 | Critical | Duplicate query indices in the pruned query walk are not checked for consistency | Experiment |
| V-05 | Critical | LogUp terminal count not fixed by the circuit shape | Experiment |
| V-06 | Critical | Child verifying key not pinned in the block (recursion) circuit | Structural |
| V-07 | Critical | In-circuit Poseidon2 sponge does not fully bind its input | Structural |
| V-08 | Critical | Binary Merkle paths in the Poseidon2 circuit AIR do not bind leaf or direction | Structural |
| H-01 | High | Permissionless settlement without on-chain data availability | PoC (repo) |
| H-02 | High | Output-note append position is not constrained | Structural |
| H-03 | High (privacy) | Client verifying key embeds spend position and recipient key | Structural |
| M-01 | Medium | No deployment binding: blocks replay across pools and chains | PoC (repo) |
| M-02 | Medium | SPHINCS+ envelope not bound to the note, proof or identity | Structural |
| M-03 | Medium | Statement words accepted modulo p (aliasing) | Experiment |
| M-04 | Medium | Proof extension elements not range-checked | Experiment |
| M-05 | Medium | WHIR shape taken from proof lengths rather than CONFIG | Structural |
| M-06 | Medium | Node block pipeline is not atomic | Structural |
| M-07 | Medium (privacy) | Hiding budget is pooled; small tables are not hidden | Structural |
| M-08 | Medium | Nullifier not position-bound; output rho is unconstrained | Structural |
| M-09 | Medium | Nullifier absence fold depth makes some notes unspendable | Structural |
| M-10 | Medium (privacy) | Non-ZK settlement proof over witness data not published on L1 | Structural (unquantified) |
| M-11 | Medium | Rate limiter shared per role and path | Structural |
| L-01..L-08 | Low | Vault parsing, stub guard, token hygiene, DA completeness, header split, zeroization, R-commitment claim, SLH-DSA notes | Structural |
| I-01..I-07 | Info | Env-configurable soundness knobs, documentation drift, fixture keys in production build, vestigial fees, gas limits, spent-nullifier oracle, in-circuit minor divergences | Structural |
