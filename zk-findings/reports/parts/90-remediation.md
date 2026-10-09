## Remediation priority

| Priority | Findings | Theme | Gate |
|---|---|---|---|
| P0 (blocking) | V-01, V-02, V-03, V-04, V-05 | On-chain verifier soundness | Fix and add a negative test per finding to `contracts/test/` |
| P0 (blocking) | V-06, V-07, V-08 | Circuit / recursion soundness | Confirm each with an executed PoC first, then fix; V-08 is upstream-shaped |
| P1 | H-01, H-02, M-01, M-06 | Liveness, DA, replay, node consistency | Required before custody |
| P1 | H-03, M-07, M-10 | Privacy of the client proof | Re-audit after the V-06 fix moves per-transfer data out of preprocessed columns |
| P2 | M-02, M-03, M-04, M-05, M-08, M-09, M-11 | Authorization binding, encoding canonicality, shape pinning, nullifier design | — |
| P3 | L-01..L-08 | Robustness, hygiene, dependency, docs | — |
| P3 | I-01..I-07 | Config, fixture keys, docs drift | I-01 and I-03 should be closed before any non-demo deployment |

Several fixes are coupled. Pinning the on-chain CONFIG (V-01) and pinning the child verifying key (V-06) both require a canonical per-shape verifying key, which in turn requires moving the per-transfer constants (membership path, recipient key, roots) out of the preprocessed columns — the same change that fixes the privacy leak H-03. We suggest designing that "one verifying key per block shape" change first and letting V-01, V-06 and H-03 follow from it.

## Verification status and next steps

- **Demonstrated in-repo (tests pass on this branch):** V-01, H-01, M-01.
- **Demonstrated by experiment (scratch), to be ported to `contracts/test/audit/`:** V-02, V-03, V-04, V-05, M-03, M-04.
- **Structural (file:line), runnable PoC sketched, not executed:** V-06, V-07, V-08, H-02, H-03, M-02, M-06..M-11, all Lows.

Per the methodology's Critical/High PoC gate, V-02 through V-08, H-02 and H-03 should be downgraded to "pending PoC" in any client-facing deliverable until their sketched tests are executed in-repo. They are reported at Critical/High here because the root cause is established by code and, for V-02..V-05, by executed experiments against the real contracts; the gate is about in-repo reproducibility, not about doubt over the mechanism.

## Prior art (zkbugs-index)

The index was consulted (`plugins/evidence-and-tooling/index`). Closest documented classes: Fiat-Shamir soundness in Plonky3-family recursion (`zkbugs/openvm-org/openvm/GHSA-4w7p-8f9q-f4g2`, `zkbugs/succinctlabs/sp1/ghsa-8m24-3cfx-9fjw`, both Critical) relate to V-02/V-03/V-05; missing-public-input binding (`external/gnark/audit-contests/missing-public-instance-binding`) relates to V-01/V-06; a private-witness-in-proof leak (`external/risc0/zellic/private-witness-logged`) relates to M-10. None is the same target. The verified findings here are candidates for an org-local index entry once their PoCs are ported in-repo.
