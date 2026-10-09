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

---

## Executive summary

toy-zk-rollup is a post-quantum shielded-pool rollup that proves its state transitions with hash-based STARKs (Plonky3 batch-STARK over the WHIR polynomial commitment, KoalaBear field, recursion through a vendored Plonky3-recursion tree) and settles on an EVM chain through a generated Solidity verifier that replays the proof with a Keccak transcript. The engineering is substantial and, in many places, careful: value conservation, canonical digest encodings, token authentication, and the vault's key derivation are sound, and the reviewers discharged a number of plausible concerns with specific rejecting code (see Discharged).

However, the core security claim — that the on-chain contract accepts a block only when it is backed by a valid proof of the shielded state transition — does not hold on the audited revision. The audit found **eight independent Critical soundness issues**. They fall into two groups:

1. **The proof is not bound to the circuit it is supposed to be a proof of.** The on-chain verifier reads its entire circuit description from the caller-supplied bundle and never pins it (V-01), and the recursion circuit leaves the child verifying key a free witness (V-06). Either one lets a proof of a different, weaker circuit be accepted as a block.
2. **The verifier's internal checks do not enforce what they appear to.** The WHIR opening points are not tied to the transcript evaluation point (V-02); round commitments are not tied to the committed trace/quotient/preprocessed data (V-03); duplicate query openings are not checked for consistency (V-04); the LogUp terminal count is attacker-chosen (V-05); the in-circuit Poseidon2 sponge does not bind its input, so nullifiers are malleable (V-07); and the in-circuit Merkle paths bind neither the leaf nor the path direction, making the recursive proximity test vacuous (V-08).

Each of V-02 through V-08 breaks soundness **even if** V-01 is fixed by pinning the circuit on-chain. Two of the Criticals (V-01 and, through it, the settlement path) are demonstrated end to end with tests committed to this branch; the remainder are supported by executed experiments against the real contracts or by file-and-line structural evidence with runnable PoCs sketched.

Beyond soundness, the design has a **liveness gap**: settlement is permissionless and no per-transfer data reaches L1, so one party can freeze the pool and the operator permanently (H-01, demonstrated), and blocks replay across deployments (M-01, demonstrated). There are **privacy gaps**: the client verifying key reveals which note is spent and the recipient (H-03), small tables may not be hidden (M-07), and the settlement proof is non-ZK over witness data (M-10). The documented SPHINCS+ spend authorization does not actually authorize anything (M-02).

**This system is not ready to custody value.** The verifier and the recursion layer need the soundness fixes above before the demonstrated end-to-end flow means what it claims. We recommend treating V-01 through V-08 as blocking, with V-06, V-07 and V-08 (the circuit-level issues) confirmed by execution before any fix is declared complete, since those are the ones held at structural evidence here.

A companion specification (`zk-findings/spec/`) records what the code actually enforces, section by section, with source citations; its "Specification deltas" section lists where the documentation and the code disagree.

---

# Findings

## [Critical] V-01: Settlement verifier is not bound to the block circuit

**Property:** Soundness (state integrity of `ShieldedPool`).

**Affected:** `contracts/src/verifier/WhirVerifier.sol:21-26, 264-268, 283-318`; `contracts/script/Deploy.s.sol`; `contracts/src/ShieldedPool.sol:144`.

**Root cause.** The verifier reads its whole circuit description from the CONFIG section of the caller-supplied proof bundle: the batch seed, degree bits, the preprocessed digest that identifies the circuit, the grinding parameters, every WHIR round schedule, and the constraint programs evaluated by the `TerminalWeight` satellite. Nothing compares CONFIG with a fixed value. The header comment says "A deployment should pin `keccak256(configSection)`", but neither `WhirVerifier` nor `ShieldedPool` does, and `Deploy.s.sol` deploys the bare `WhirVerifier`. The repo has a pinning wrapper, `WhirVerifierV6`, but nothing deploys it. `applyBlock` has no caller restriction.

**Impact.** A valid proof for *some* circuit is accepted as a valid proof of the block relation. The pool then stores whatever commitment root and nullifier root that proof's public values contain. This covers integrity of every note in the pool, double-spend protection (the nullifier root), and liveness.

**Evidence (PoC, repo):**
- `contracts/test/audit/PocF01ForgedBlock.t.sol::test_poc_f01_one_verifier_accepts_two_unrelated_circuits` (PASS): one `WhirVerifier` instance accepts both the committed block-circuit proof and the committed Fibonacci recursion-chain proof.
- `crates/prover/tests/poc_audit_f01.rs::poc_f01_forged_settlement_proof_for_arbitrary_roots` (ok) and `PocF01ForgedBlock.t.sol::test_poc_f01_forged_block_rewrites_pool_roots` (PASS): a bundle produced by the project's own exporter for a circuit that only exposes its public inputs is accepted by `applyBlock`, from an arbitrary sender. The pool's roots change to values chosen in the test vectors.

**Test gaps.** No negative test feeds a proof of a different circuit to the deployed verifier.

**Remediation.**
- Pin the circuit description on-chain. Make the pool's verifier a wrapper that checks `keccak256(CONFIG)` against an immutable digest before running the engine (the `WhirVerifierV6` pattern), and deploy it from `Deploy.s.sol`. Block circuits differ per shape (n and each child's input/output counts), so either fix one canonical block shape or pin an explicit allow-list of shape digests.
- Bind the digest into the Fiat-Shamir transcript as well, so a proof made under one CONFIG cannot be relabelled.
- Fixing V-01 does **not** fix V-02 to V-08. Each of those breaks soundness with the honest CONFIG in place.
## [Critical] V-02: WHIR opening points are not bound to the transcript point zeta

**Property:** Soundness (the PCS opening is not tied to the point the constraint identity is checked at).

**Affected:** `contracts/src/verifier/WhirVerifier.sol:245-257, 506-513`; `contracts/src/verifier/TerminalWeight.sol:125-205` (`deriveGroupDescs`, point read at `:188`); reference: `p3-batch-stark-0.8.0/src/verifier/mod.rs:164-187`.

**Root cause.** The constraint identity is evaluated at the transcript-derived point `zeta`. But the per-matrix evaluation points that build the terminal-weight equality groups are read verbatim from the bundle's STATEMENT section (`deriveGroupDescs` reads each point as raw calldata and passes it to the weight computation). The STATEMENT bytes are never absorbed into the transcript and the points are never compared with `zeta` or with `zeta * g_trace`. So the WHIR argument proves evaluations at points the prover selects, while the identity treats those evaluations as if taken at `zeta`. The matrix layout (`log_size`, `width`, point count) in STATEMENT is also prover-supplied and only loosely bounded.

**Impact.** The binding between "the committed polynomials evaluated at the DEEP point" and "the constraint identity at `zeta`" is absent. This is the central soundness link of a DEEP-ALI / WHIR verifier.

**Evidence (experiment).** In a scratch copy of `contracts/`, changing a per-matrix opening-point word in the committed `test/vectors/block_composed_bundle.bin` so that it no longer equals `zeta` still yields `verify() == true` (for arity-4 statement-table points, after re-selecting a point that leaves the weight unchanged). Perturbing the same word arbitrarily is rejected only at the final algebraic equality, never by a point-vs-transcript check. This is to be ported to `contracts/test/audit/` as `poc_v02_opening_point_not_bound`.

**Test gaps.** No test checks that a proof's opening points equal the transcript point.

**Remediation.** Do not read opening points from the proof. Derive them in the verifier: `zeta` for the local point and `zeta * g_{trace}` for the next-row point, exactly as `p3-batch-stark` does, and build the terminal-weight groups from those derived values. If the STATEMENT section is retained for audit, absorb it into the transcript and cross-check every point against the derived value, failing closed on mismatch.
## [Critical] V-03: Per-round WHIR commitments are not checked against the batch-phase digests

**Property:** Soundness (the opened polynomials are not tied to the committed trace / preprocessed / quotient / permutation data).

**Affected:** `contracts/src/verifier/WhirVerifier.sol:1027` (round root read from PROOF), `:568, 670`; `contracts/src/verifier/BatchTranscript.sol:91, 100, 124, 139` (digests absorbed); reference: `p3-batch-stark-0.8.0/src/verifier/mod.rs:187, 249, 312, 339`.

**Root cause.** The batch phase absorbs the main (trace) digest, the preprocessed digest (the verifying key), the permutation digest and the quotient digest into the transcript. Each WHIR opening round then reads its own Merkle root from PROOF and uses it only as the root for that round's openings. There is no comparison between a round's root and the corresponding digest that was absorbed. In the reference verifier the opened commitment *is* the observed one by construction (`coms_to_verify.push((commitments.main, ...))` etc.).

**Impact.** Once `zeta` is known, a prover can open freshly committed polynomials unrelated to the trace, quotient, or — critically — the preprocessed (fixed) columns that encode the circuit. Pinning CONFIG and the preprocessed digest (the V-01 fix) does not help, because the fixed columns are never actually opened against that pinned digest.

**Evidence (experiment + structural).** In the honest committed bundle the four round roots equal the main, quotient, preprocessed and permutation digests respectively, which shows the intended equality — but it is never enforced. Replacing a round's root with an unrelated value in a scratch copy is rejected only later, by that round's own Merkle path check against the substituted root, not by any digest comparison. A grep of the verifier finds no use of the absorbed digests as expected roots. To be ported as `poc_v03_round_root_unbound`.

**Test gaps.** No test substitutes a round root and expects rejection before the opening stage.

**Remediation.** For each opening round, require the round's root to equal the digest absorbed for that commitment in the batch phase (main, quotient, preprocessed, permutation), as the reference verifier does. The preprocessed round's root must equal the pinned verifying-key digest.
## [Critical] V-04: Duplicate query indices in the pruned query walk are not checked for consistency

**Property:** Soundness (an unauthenticated opened row enters the fold).

**Affected:** `contracts/src/verifier/TerminalWeight.sol:664-673` (pruned QFOLD walk), `:328-337` (the MROOTS entry with the same code), `:644-647`; reference: `p3-merkle-tree-0.8.0/src/mmcs/mod.rs:563-572` (`InconsistentDuplicateOpenings`).

**Root cause.** The pruned ("QFOLD") query walk sorts the (index, leaf) pairs and drops duplicate indices without comparing their rows. Every query's fold value, including a duplicate's, still enters the claimed evaluation. The reference Merkle verifier rejects two openings at the same index with different rows (`InconsistentDuplicateOpenings`); this verifier silently keeps one.

**Impact.** When the sampled query set contains a repeated index, the prover may supply one honest row and one inconsistent row for that index. The inconsistent row's fold is absorbed without being authenticated against the Merkle root, so the query check for that position constrains nothing. The prover can then continue with a polynomial that is not the fold of the committed data.

**Evidence (experiment).** A depth-2 tree test with query indices `[1,1]`: honest rows `(rowA,rowA)` are accepted; forged rows `(rowA,rowB)` are also accepted, with a different claimed evaluation; the control with distinct indices `[1,2]` and the mismatched row reverts with `PrunedRootMismatch`. The pruned flag is in-band (bit 31 of a path byte-count field) and not tied to the bundle version, and the QFOLD gate is reachable on round 0 of the block proof. The cost of forcing a duplicate in a real round is a modest grind (round 0 has ~159 queries at depth 20; collision probability ~1.2% per attempt). To be ported as `poc_v04_duplicate_query_row`.

**Test gaps.** No negative test exercises a repeated query index with inconsistent rows.

**Remediation.** Match the reference: when two openings share an index, require their rows to be identical, reverting otherwise. Do not drop a duplicate silently.
## [Critical] V-05: LogUp terminal count is not fixed by the circuit shape

**Property:** Soundness (the LogUp "sum of terminals is zero" check can be satisfied without the lookups balancing).

**Affected:** `contracts/src/verifier/WhirVerifier.sol:1218-1240` (terminals decoded from PROOF), `:276-280` (sum check), `BatchTranscript.sol:125-127` (absorbed); `TerminalWeight.sol:1114-1121` (identity consumes only the first `#hasTerminal`); reference: `p3-batch-stark-0.8.0/src/verifier/mod.rs:843` (count fixed by each AIR's lookups).

**Root cause.** The number of LogUp terminals is taken from the proof. The verifier sums all supplied terminals and requires zero, and it absorbs all of them into the transcript, but the constraint identity consumes only the first `#hasTerminal` of them. There is no check that the number supplied equals the number the circuit shape requires (no `tIdx == nTerm` check).

**Impact.** If the real per-instance terminals sum to a nonzero value `S` (the lookups do not balance), the prover can append one extra terminal equal to `-S` before the batching challenge is drawn. The sum is then zero and each instance's identity still uses its own true terminal. The LogUp argument — which is what enforces that looked-up values were actually sent on the bus — is defeated, so for example the statement table can carry values that were never sent.

**Evidence (experiment).** A seventh zero terminal added to the wire passes decoding and the sum check (it fails only later because the transcript shifted). A debug satellite that receives an extra terminal in the identity frame still verifies the honest bundle. To be ported as `poc_v05_extra_terminal`.

**Test gaps.** No test pins the terminal count to the circuit's lookup shape.

**Remediation.** Derive the expected terminal count from the (pinned) circuit shape and require the proof to carry exactly that many, in the order the identity consumes them. Reject any extra or missing terminal.
## [Critical] V-06: Child verifying key is not pinned in the block (recursion) circuit

**Property:** Soundness (the block circuit proves "a valid proof of *some* same-shape circuit", not "of the transfer circuit").

**Affected:** `crates/prover/src/block.rs:379-388, 496-514`; `crates/prover/src/whir_recursion.rs:759-777`; `vendor/p3-recursion/recursion/src/verifier/batch_stark.rs:713-786`; `vendor/p3-recursion/recursion/src/pcs/fri/targets.rs:1071-1079`; `vendor/p3-recursion/recursion/src/backend/whir.rs:1619-1640` (the unused `constrain_trusted_preprocessing`). Cross-reference: this is the same defect agent C recorded as C-01.

**Root cause.** The block circuit verifies each child proof against a verifier object retained from the client's own proving run (`ChildProof.verifier`). `verify_trusted_p3_batch_proof_circuit` fixes the child's AIRs, degree bits, lookups and packing from that object, but it still allocates the child's preprocessed commitment (its verifying-key digest) as a free witness and never constrains it to a known constant. The project never calls the backend's `constrain_trusted_preprocessing`. In this circuit-prover, the preprocessed columns carry all the per-transfer data (membership siblings, nullifier-tree siblings and empty-subtree constants, roots, recipient `pk_d`) baked in as circuit constants, so there is no single canonical child verifying key.

**Impact.** Two consequences compound. First, because the per-transfer data is in the verifying key and the key is a free witness, a block can verify a child proof of any circuit with the same table shapes — including a circuit whose constraints are weaker or absent, or whose exported statement is attacker-chosen. Second, this is independent of V-01: a deployment that pins the on-chain CONFIG still accepts such a child, because the recursion circuit's own structure depends only on the child's shape, not on its constants.

**Evidence (structural).** The allocation of the child commitment as public input (`CommonDataTargets::new` -> `MerkleCapTargets::new` -> `alloc_public_input_array`), the absence of any `constrain_constant` / `constrain_trusted_preprocessing` call at the two recursion sites, and the circuit-prover's unconstrained Public table (`circuit-prover/src/air/public_air.rs:14-20`) together establish it. A runnable PoC is sketched in the circuits review (`poc_b01a_forged_child_mints`, `poc_b01c_settlement_vk_independent_of_child_constants`) but was not executed; this finding is held at **structural** evidence pending that PoC.

**Remediation.** Constrain the child preprocessed commitment targets to the expected constant for each pinned child shape (call `constrain_trusted_preprocessing`, or `constrain_constant` against the retained verifier's commitment). Move per-transfer data out of the preprocessed columns into witness/statement so that one verifying key serves a whole shape, and pin one verifying key per shape. Never accept a verifier object from an untrusted client.
## [Critical] V-07: In-circuit Poseidon2 sponge does not fully bind its input

**Property:** Soundness (nullifier uniqueness and, through it, double-spend prevention).

**Affected:** `crates/prover/src/commitment_gadget.rs:321, 330-344, 347-356`; `vendor/p3-recursion/poseidon2-circuit-air/src/air.rs:854, 1171-1183`; `vendor/p3-recursion/circuit/src/ops/poseidon_perm/executor.rs:124-126`; `vendor/p3-recursion/circuit/src/builder/circuit_builder.rs:1648-1653, 1736-1766`. Cross-reference: agent B's B-02.

**Root cause (two parts, each sufficient).**
- *Free initial capacity.* The first sponge row is emitted with `new_start: true` and only the rate inputs set; the capacity inputs are left unconstrained. On the shared Poseidon2 table the chain-start pin that would force the capacity to zero fires only for challenger rows, not for ordinary `add_perm` rows. Zero capacity is therefore honest-prover behaviour, not an enforced constraint, so every in-circuit sponge digest is `S(message)` under an initial vector the prover may choose.
- *Free partial-chunk tail.* When the final chunk is partially filled, the gadget reuses the ALU-based extension/base recomposition, which (per the builder's own comments) ties only the weighted sum of the coefficients and leaves the remaining coefficient dimensions free. The nullifier preimage's last chunk has free coordinates.

**Impact.** The nullifier `nf = H(DOMAIN_NULLIFIER || sk_d || rho)` is computed by this gadget. Because the digest is not a function of the preimage alone, the owner of a note can derive many distinct nullifiers for it. Each passes the in-circuit absence fold and appears fresh to the node's admission check, so one note can be spent repeatedly, including twice in one block. This does not let an attacker spend *other* users' notes (forging someone's `pk_d` or an existing leaf is still a preimage problem).

**Evidence (structural).** The `new_start` capacity being unpinned on non-challenger rows, the selector gating at `air.rs:854`, and the ALU-recomposition comments establish both parts. Two PoC sketches (`poc_b02a_iv_double_spend`, `poc_b02b_partial_chunk_double_spend`) require a one-line patch to the vendored executor to inject the free value and were not executed; held at **structural** pending that PoC or an AIR-level `check_constraints` test on a single `new_start` row with non-zero capacity.

**Remediation.** Feed the sponge capacity as explicit constant-zero inputs with their own bus constraint (or emit the chain-start capacity pin for every sponge start, not only challenger rows). Use the coefficient-binding recomposition (`with_coeff_lookups`) for the partial final chunk. Consider a length/domain tag in the sponge so the digest commits to the input length.
## [Critical] V-08: Binary Merkle paths in the Poseidon2 circuit AIR bind neither leaf nor direction

**Property:** Soundness (the in-circuit MMCS openings are vacuous, so every in-circuit WHIR query check is vacuous).

**Affected:** `vendor/p3-recursion/poseidon2-circuit-air/src/air.rs:1028, 1192-1214, 1965, 1986-1990, 2046-2063`; `vendor/p3-recursion/circuit/src/ops/mmcs.rs:124-186`; `vendor/p3-recursion/circuit/src/ops/poseidon_perm/executor.rs:816-827, 958-960`; `vendor/p3-recursion/recursion/src/pcs/mmcs.rs:205, 313`. Origin: upstream (present in the pinned revision), on the binary (non-arity-4) path WHIR uses. Cross-reference: agent C's C-02.

**Root cause (two parts).**
- *Leaf digest unbound.* On binary Merkle rows the input-limb bus sends are multiplied by `(1 - merkle_path)`, i.e. zero, and the first path row has `new_start = true`, so the chain constraint does not apply to it either. The leaf digest fed into the first row is therefore not tied to the leaf-hash output.
- *Direction bits unbound.* The path-direction column is only constrained to be boolean. The index-accumulator lookup that would tie the directions to the sampled query index is gated on a flag that every caller leaves disabled (`mmcs_index_sum: None`). So the path directions are not tied to the query index the challenger sampled.

The arity-4 path does bind both, but WHIR rejects arity 4 (`backend/whir.rs:567-575`), so production always takes the binary path.

**Impact.** In the in-circuit WHIR verifier, STIR query openings go through the binary MMCS check. Because that check binds neither the leaf nor the direction, a malicious recursion prover can present arbitrary leaf values for the fold and the final "fold equals polynomial at the domain point" checks. The query phase then constrains nothing, so the in-circuit verifier accepts arbitrary child openings — the WHIR proximity test is not enforced inside the recursion circuit.

**Evidence (structural).** The zeroed input sends on Merkle rows, the `new_start` first row, the always-`None` index-sum argument, and the arity-4-only binding path establish it. The existing recursion tamper tests catch tampering only at witness-generation, not at the AIR level. A PoC (`poc_c02_binary_merkle_leaf_and_index_unbound`, an edited-circuit/honest-key `check_constraints` test) is sketched but was not executed; held at **structural** pending that PoC. This is the highest-value item to confirm by execution.

**Remediation.** On binary Merkle rows, bind the leaf digest to the leaf-hash output (non-zero input sends, or a chain constraint on the first path row) and enable the index-accumulator argument so the direction bits equal the sampled query index bits. Re-audit after enabling. A fix here is upstream-shaped; coordinate with Plonky3-recursion.

## [High] H-01: Permissionless settlement without on-chain data availability

**Property:** Liveness / availability of the shielded pool.

**Affected:** `contracts/src/ShieldedPool.sol:144-179` (no caller check; verify runs first), `:92-99` (event); `crates/node/src/state.rs:10-18` (the "rebuild from events" claim). Cross-reference: agent D's D01.

**Root cause.** `applyBlock` has no `msg.sender` restriction, and the only data a block writes to L1 is the four roots and the total fee. The per-transfer output commitments and nullifiers live only inside the Poseidon2 statement fold (`statementRoot`), which the contract neither stores nor emits. The node keeps no persistent state and never reads L1; it rebuilds its trees from genesis on start.

**Impact.** A party that holds one valid block can settle it and withhold the new leaves. After that, no one else can compute the new commitment-tree frontier or nullifier-map paths, so no further transfer can be witnessed, and the operator's own next block reverts on the continuity check. In the shipped configurations the genesis notes come from public fixture seeds, so the party able to do this is anyone. The pool and node are frozen with no operator recovery path; there is no forced-inclusion or escape hatch.

**Severity note.** Rated High (liveness): the pool holds no L1 funds (fees are burned in-circuit, see I-04), so this freezes shielded value and the service rather than enabling direct theft. If in-pool shielded value is treated as custodied funds, the maintainers may raise this.

**Evidence (PoC, repo):** `contracts/test/audit/PocD01SettlementAccess.t.sol::test_poc_d01_any_sender_settles_and_event_carries_no_leaves` (PASS): an arbitrary sender applies the committed block; the emitted event's data is exactly five words (the roots and fee), carrying no per-transfer data; a second application by anyone else reverts.

**Remediation.** Restrict `applyBlock` to an operator set, or add forced inclusion / an escape hatch so users are not dependent on one party's cooperation. Publish the per-transfer commitments and nullifiers (or the full statement) as calldata or an event so any party can rebuild state. Decode and check continuity before running the ~102M-gas verification to bound griefing cost (see I-05).
## [High] H-02: Output-note append position is not constrained

**Property:** Liveness / integrity of the commitment tree.

**Affected:** `crates/prover/src/commitment_gadget.rs:489-557` (count bits and frontier are private, pinned only by `fold == root_before`); `crates/shielded/src/tree.rs:67, 224-226` (empty leaf is the zero digest). Cross-reference: agent B's B-03.

**Root cause.** In the append gadget the frontier and the count bits are free witnesses, pinned only by "the frontier folds to `root_before`". Because empty positions are the zero digest and empty subtrees have a fixed digest, a valid frontier exists for every count `n' >= n` (the honest count). The chosen count is in neither the statement nor the block chain, so the prover decides where the output leaf is appended.

**Impact.** A prover can append the output at an arbitrary index. Appending near the top of the 2^32 capacity makes every later append overflow the carry check (`assert_zero(carry)`), after which no transfer with outputs can be proven and all shielded value is frozen. Against an honest node, admission does not check the after-root, so a drained batch settles and then the node desyncs from L1, losing the mempool. Reachable with a zero-value transfer.

**Evidence (structural).** The private count/frontier, the pin being only against `root_before`, and the empty-leaf == zero-digest equivalence establish it. PoC sketches `poc_b03a_append_skips_positions` and `poc_b03b_tree_freeze` were not executed; held at **structural**.

**Remediation.** Export the leaf count (before and after) in the transfer statement and chain it across the block, or have the contract track the count, so the append position is pinned and monotone.
## [High] H-03: Client verifying key embeds the spent position and the recipient key (privacy)

**Property:** Privacy (unlinkability of sender-to-note and recipient identity toward the sequencer).

**Affected:** `crates/prover/src/transfer.rs:579, 731-734` (recipient `pk_d` and membership siblings as circuit constants); `vendor/p3-recursion/recursion/src/pcs/whir/uni/pcs.rs:989-1019` (preprocessed columns are public, unblinded); `crates/prover/src/client.rs:77-80`, `crates/node/src/sequencer.rs:50-64` (the verifier and proof go to the sequencer). Cross-reference: agent B's B-04.

**Root cause.** The transfer circuit bakes the spent note's membership siblings (which determine its position) and the recipient's `pk_d` into preprocessed columns as circuit constants. Preprocessed commitments are deterministic and unblinded. The client hands its `CircuitVerifier` (with that preprocessed data) and proof to the sequencer.

**Impact.** The sequencer, or anyone who receives the verifier, can recover the spent leaf index and the recipient `pk_d` — by reconstructing a candidate verifier per index/key and matching the preprocessed commitment, or by solving from the unmasked preprocessed openings, which are linear in the constants. Because `pk_d` is static per key, all of a recipient's incoming notes become linkable. This contradicts the README's "the node sees ... never secrets".

**Evidence (structural).** The constants at the cited lines, the unblinded-preprocessed property, and the data flow to the sequencer establish it. PoC sketch `poc_b04_vk_reveals_spent_index` was not executed; held at **structural**.

**Remediation.** Make the membership path (and index) and the recipient key witnesses, not preprocessed constants, so one verifying key serves a whole shape and reveals nothing note-specific. This change is also required by the V-06 fix (one VK per shape). Re-examine what the non-ZK settlement proof then still exposes (see M-10).

## [Medium] M-01: No deployment binding — blocks replay across pools and chains

**Property:** Soundness of authorization scope / availability.

**Affected:** `contracts/src/BlockStatement.sol:11-15` (no chain id or pool address); `crates/shielded/src/signing.rs:35, 77-98` (spend-auth message has no domain binding); `crates/node/src/main.rs:85, 868-886` (shared fixture genesis). Cross-reference: agent D's D05.

**Root cause.** Neither the block statement nor the spend-authorization message carries a chain id or pool address, and all default deployments share one fixture genesis root. A `(statement, proof)` pair is therefore valid against any pool at the same genesis.

**Impact.** A block settled on pool A can be replayed on pool B by any caller, applying a user's transfer in B without consent and desyncing B's operator (compounding H-01).

**Evidence (PoC, repo):** `contracts/test/audit/PocD01SettlementAccess.t.sol::test_poc_d05_block_replays_across_pools` (PASS): the same block applies to two independently deployed pools.

**Remediation.** Bind the chain id and pool address into the proven statement and into the spend-auth message; use a unique genesis per deployment.

---

## [Medium] M-02: SPHINCS+ envelope is not bound to the note, proof, or identity

**Property:** Soundness of the documented spend-authorization model.

**Affected:** `crates/node/src/wire.rs:42-45, 104-121` (verifying key carried in the envelope); `crates/shielded/src/keys.rs:31-42` (`pk_d = H(DOMAIN_PK || sk_d)`, unrelated to the SPHINCS+ key); `crates/node/src/sequencer.rs:332-345` (only the envelope's own statement is verified). SPHINCS+ is not verified in-circuit or on-chain (issue 10 open). Cross-reference: agent D's D02, agent B's B-12.

**Root cause.** The SPHINCS+ verifying key travels inside the envelope and is bound to nothing — not the note's `pk_d`, not the proof, not an account. The signature is checked only natively by the node, against the key the submitter supplied. Actual spend authority is in-circuit knowledge of `sk_d`.

**Impact.** The envelope authorizes nothing: a relayer or any submitter can take a statement, change the fee or outputs, and re-sign with a fresh key, and the node's signature check passes. The README's and code comments' claims that the signature provides authorization and non-repudiable provenance are false. Today this is contained because `/v1/transfer` returns 501 and the in-process path builds consistent bundles; it becomes **Critical** if any path (remote proof admission, delegated proving) treats the envelope as the authorization.

**Evidence (structural).** The key-in-envelope, the `pk_d` derivation, and the verify-against-self call establish it. PoC sketches `poc_D02_relayer_resigns_edited_statement`, `poc_D02_sequencer_admits_envelope_over_other_statement` not executed; held at **structural**.

**Remediation.** Bind the SPHINCS+ verifying key to the note (e.g. make `pk_d` commit to it) and verify the signature over the exact proven statement — ultimately in-circuit — so authorization is part of the relation the contract checks.

---

## [Medium] M-03: Statement words accepted modulo p (aliasing)

**Property:** Soundness / integrity (one proof verifies for many statement arrays; unchecked header words are attacker-chosen after all challenges).

**Affected:** `contracts/src/verifier/WhirVerifier.sol:426-440` (`_checkStatement` compares `mulmod(statement[i], R, p)`); `TerminalWeight.sol:1135-1137`, `ConstraintIdentity.sol:250-253` (raw word used as the AIR public value); `contracts/src/BlockStatement.sol:85-89` (header positions 1..2n skipped by the pool). Cross-reference: agent A's F-06.

**Root cause.** `_checkStatement` accepts any `statement[i]` congruent mod p to the proof's public value. The raw word is then used as the AIR public value (`shl(224, raw)`), so it can be a non-canonical lane. The pool range-checks position 0 and all digest and fee limbs but not the header positions 1..2n.

**Impact.** Two effects: a single proof verifies against many different statement arrays (malleability); and each unchecked header position is an adaptive `F_p` unknown the attacker chooses after all challenges, which an experiment shows reaching the AIR as a different value than the transcript (`ConstraintIdentityMismatch`). At n=1 there are 2 such unknowns against 4 equations (not obviously exploitable); at n >= 2 there are 4+, which plausibly enables a forgery — so this rises toward High for multi-transfer blocks.

**Evidence (experiment).** `test_alias_header_2p32`, `test_alias_header_plus_p`, `test_pool_applies_aliased_statement`, `test_alias_header_air5` in the reviewer's scratch copy accept aliased words and show the AIR/transcript divergence. To be ported as `poc_m03_statement_aliasing`.

**Remediation.** Require every statement word to be canonical (`< p`) in `_checkStatement`, and range-check the header positions in `BlockStatement.decode`.

---

## [Medium] M-04: Proof extension-field elements are not range-checked

**Property:** Soundness (transcript and arithmetic disagree on non-canonical lanes) / malleability.

**Affected:** `contracts/src/verifier/WhirVerifier.sol:1254-1280` (`_extArr` checks only the low-128 padding, nothing in compact mode), `:1229-1235`; `contracts/lib/sol-whir-p3/transcript/KeccakChallenger.sol:154-179` (transcript reduces each lane mod p); `contracts/lib/sol-whir-p3/field/KoalaBearExt4.sol:33-72` (add/sub carry across lanes). Cross-reference: agent A's F-07.

**Root cause.** Proof-supplied extension elements are not reduced to canonical lanes. The transcript absorbs each lane mod p, but `KoalaBearExt4` add/sub carry and borrow across lanes, so a lane >= p changes arithmetic results while leaving the transcript unchanged. The code comment claiming every consumer reduces mod p is false.

**Impact.** Confirmed: two distinct byte strings verify as the same proof (malleability), because a non-canonical boundEval or terminal is accepted. Beyond malleability, the transcript-vs-arithmetic disagreement is a soundness-erosion surface (borrow errors injected per sumcheck round); exploitability as a forgery was not established.

**Evidence (experiment).** `test_noncanonical_boundEval_accepted`, `test_noncanonical_terminal`, `test_ext_add_carry` in the scratch copy. To be ported as `poc_m04_noncanonical_ext`.

**Remediation.** Range-check every proof-supplied base lane to `< p` at decode (including the compact path), as the row-limb decoders already do.

---

## [Medium] M-05: WHIR shape taken from proof lengths rather than CONFIG

**Property:** Soundness (several reference shape checks are absent; some combinations are only bounded by gas).

**Affected:** `contracts/src/verifier/SumcheckCore.sol:177` (round count from `cA.length`); `contracts/src/verifier/WhirVerifier.sol:584` (row length computed, not read), `:1005` (initial OOD count decoded but unused); `contracts/src/verifier/WhirVerifierCore.sol:278-311` (no `cursor == len` check after the initial phase); `TerminalWeight.sol:1371` (finalPoly length tied only to the closing round count). Reference: `p3-whir-0.8.0/src/pcs/verifier/mod.rs:247-368`. Cross-reference: agent A's F-08.

**Root cause.** The number of sumcheck rounds, the final-polynomial length, the initial OOD-sample count, and the bound-eval counts are taken from proof array lengths rather than being fixed by the (pinned) CONFIG. The reference verifier fixes them from parameters.

**Impact.** Individually bounded today (e.g. extra bound-evals alias an existing eval when `claimPerm` is non-empty; a long final polynomial is limited by gas), but each is a shape the verifier should pin and does not. With an empty `claimPerm` the extra bound-evals would be free values after the batching challenge, which would be Critical; this combination was not shown reachable.

**Remediation.** Derive every WHIR shape quantity from the pinned CONFIG and assert the proof matches, including an end-of-section cursor check after each phase.

## [Medium] M-06: Node block pipeline is not atomic

**Property:** Availability / node-L1 consistency.

**Affected:** `crates/node/src/sequencer.rs:387-417` (batch drained before `settle_batch?`), `crates/node/src/main.rs:423-461, 795-821` (single `pending_settlement` slot; state committed before the bundle can fail), `:274-280` (in-memory state). Cross-reference: agent D's D04.

**Root cause.** `produce_block` drains the mempool before proving/settling can fail; on error the drained nullifiers and outputs are already removed from the pending projection but the committed state is not advanced, so the projection drifts. There is one `pending_settlement` slot that the next produce overwrites, the auto-driver only retries after a new produce, and all state is in memory.

**Impact.** Any transient prover, IO, OOM, or RPC error — or an admin producing while the driver runs — drops blocks, drifts the projection so every later transfer fails its after-root check, and wedges the node until redeploy. A restart returns to genesis.

**Evidence (structural).** The drain-before-settle ordering and the single overwrite slot establish it. PoC sketch `poc_D04_failed_block_drops_batch_and_wedges_node` not executed.

**Remediation.** Make block production transactional: do not mutate the pending projection or the settlement slot until settlement is confirmed; persist state and reconcile against L1 on restart; validate `shape` on submit.

---

## [Medium] M-07: Hiding budget is pooled; small tables are not hidden (privacy)

**Property:** Privacy (zero-knowledge of the client proof).

**Affected:** `vendor/p3-recursion/recursion/src/pcs/whir/uni/pcs.rs:1323-1347` (`check_hiding_budget`, pooled), `:1377-1391` (`query_margin` counts queries only), `:973-976` (`log_min_trace_height = 0`). Cross-reference: agent C's M-01.

**Root cause.** The HVZK masking budget is checked pooled over the whole batch, but each column's openings are linear functionals on that column's own random dimensions. A table with fewer rows than `D * points` leaks `D*points - N` witness dimensions; a one-row table leaks fully. The margin also omits the full leaf revealed per query, the final polynomial sent in clear, the sumcheck messages, and the per-round OOD answers. The patch does not use p3-whir 0.8.0's native hiding-WHIR.

**Impact.** If any secret-bearing table in the client transfer proof is small (below ~8 rows), its witness is recoverable from the proof. Whether the client tables are that small was not determined; large tables are fine.

**Evidence (structural).** The pooled check and per-column leakage argument. PoC sketch `poc_m01_one_row_table_leaks` not executed.

**Remediation.** Enforce the hiding budget per column, count all opened data in the margin, set a minimum trace height for secret-bearing tables, or adopt the native hiding-WHIR adapter.

---

## [Medium] M-08: Nullifier is not position-bound; output rho is unconstrained (faerie gold)

**Property:** Availability (a recipient can be given an unspendable note).

**Affected:** `crates/shielded/src/note.rs:300-302` (`nf = H(DOMAIN_NF || sk_d || rho)`); `crates/prover/src/transfer.rs:566` (output rho is a free witness). Cross-reference: agent B's B-05.

**Root cause.** The nullifier depends on `sk_d` and `rho` but not on the note's position or commitment, and the sender chooses `rho`. Two notes to the same recipient with the same `rho` share one nullifier.

**Impact.** A sender can craft two notes to a recipient that collide on the nullifier; the recipient can spend only one, and the other is permanently unspendable. A griefing / value-destruction vector against recipients.

**Evidence (structural).** PoC sketch `poc_b05_faerie_gold` not executed.

**Remediation.** Bind the nullifier to the note's position or commitment (include the leaf index or `cm` in the nullifier preimage), or derive `rho` deterministically so collisions cannot be induced.

---

## [Medium] M-09: Nullifier absence fold depth makes some notes unspendable

**Property:** Availability.

**Affected:** `crates/prover/src/nullifier_gadget.rs:71-74` (absence fold starts at height 64); `crates/shielded/src/nullifier_tree.rs:78-92, 174-204` (native map mishandles low-96-bit collisions). Cross-reference: agent B's B-06, B-09.

**Root cause.** The absence fold starts at height 64, so address bits 64..95 (the u32 of nullifier element 2) decide the subtree. Any already-spent nullifier sharing those bits makes `prepare_witness` fail, and the native `NullifierMap` dedups on the full 32 bytes while the tree only uses 96 bits.

**Impact.** A note whose nullifier shares the relevant bits with a spent one is frozen forever. The nullifier is deterministic per note, so this is permanent. Probability is roughly `k/p` with `k` spent nullifiers (about 0.1% at 2^21, 0.8% at 2^24). Also a ~2^46.5 self-DoS to force a collision.

**Evidence (structural).** PoC sketch `poc_b06_fold_depth_freeze` not executed.

**Remediation.** Fold over the full address width, or make the absence proof robust to shared high-bit prefixes; align the native map's dedup width with the tree's.

---

## [Medium] M-10: Non-ZK settlement proof is taken over witness data not published on L1 (privacy, unquantified)

**Property:** Privacy.

**Affected:** `crates/prover/src/lib.rs:92-108` (the "deterministic function of public data" claim); the settlement layer dropped blinding in `a54c197`. Cross-reference: agent B's B-07.

**Root cause.** The settlement proof is non-ZK, yet the recursion witness holds the client proofs, the child preprocessed commitment and openings (which are linear in the client's secret constants, see H-03), and the full child statements — only `statementRoot` is published. The claim that every recursion cell is a function of public data is false.

**Impact.** The settlement proof opens LDE combinations of this witness. The leakage toward an observer of the on-chain proof was not quantified, so this is held as an unverified privacy concern pending analysis of how many recursion columns carry child preprocessed openings and how many queries are made.

**Remediation.** Either keep the settlement layer zero-knowledge, or establish and document that the opened combinations reveal nothing about the client secrets; revisit after the H-03 / V-06 fix moves per-transfer data out of preprocessed columns.

---

## [Medium] M-11: Rate limiter shared per role and path

**Property:** Availability.

**Affected:** `crates/node/src/main.rs:575-579` (key is `"{role} {path}"`), `:765-767` (one quota). Cross-reference: agent D's D06.

**Root cause.** The limiter key is the pair (role, path), so all holders of a role share one bucket; unauthenticated traffic is never limited. This contradicts the "per-client" documentation.

**Impact.** One low-privilege token holder can exhaust the shared quota and starve every other client of that role from a given endpoint.

**Evidence (structural).** PoC sketch `poc_D06_one_submitter_starves_another` not executed.

**Remediation.** Key the limiter by client identity (token or peer), not by role; apply a separate limit to unauthenticated traffic.

## Low-severity findings

**L-01 — `SealedVault::from_bytes` panics on crafted length bytes.** `crates/vault/src/lib.rs:336-349` assumes 16/12-byte salt/nonce but both lengths are attacker-controlled and `bytes[pos]` / `bytes[pos..pos+3]` are not bounds-checked. A crafted vault file in the unlock flow panics (and in a native `panic=abort` build, aborts the process). Remediation: bounds-check every length field before indexing. (Agent D D07.)

**L-02 — `insecure-stub` signing feature lacks the claimed release guard.** `crates/pq-sign/src/stub.rs:80-84` gates its `compile_error!` on `#[cfg(test)]`, so a `--release --features insecure-stub` build compiles; the cited `assert_stub_absent_in_release` does not exist. Not reachable today (no crate enables the feature). Remediation: add a crate-level `#[cfg(all(feature="insecure-stub", not(debug_assertions)))] compile_error!`. (Agent D D09.)

**L-03 — Token hygiene.** `crates/node/src/auth.rs:306-373` base64url decoder accepts non-canonical trailing bits, so each token has four valid encodings (malleable); no maximum TTL and `now+ttl` can overflow (`main.rs:851`); a 1-byte key file is accepted (`main.rs:139-146`); no revocation route exists; tokens are deterministic in (role, expiry) with no per-user identity. Remediation: reject non-canonical base64url, cap TTL, require a minimum key length, add rotation/revocation. (Agent D D11.)

**L-04 — Statement completeness / data availability.** `statementRoot` has no on-chain consumer and the per-transfer data is never published, so users cannot prove their own inclusion or rebuild the tree without the sequencer (`contracts/src/ShieldedPool.sol:92-99`, `contracts/src/BlockStatement.sol:17-24`). This is the data-availability root cause behind H-01; tracked separately as a completeness gap. (Agents B B-08, D D15.)

**L-05 — Block header split validated only by sum; membership path length unchecked.** `crates/prover/src/block.rs:181-183, 480-488` accepts any shape with the same `n_in + n_out` (e.g. (2,0) for a (1,1) child); `crates/prover/src/transfer.rs:716-756` never checks `path.len() == DEPTH` (the native `tree.rs:132-134` does). Remediation: bind each child's exact split and assert the path length. (Agent B B-10, B-11.)

**L-06 — wallet-wasm zeroization gaps; keystore tmp-symlink write.** `crates/wallet-wasm/src/lib.rs:158-169, 301-346` returns plain `Vec` copies of password and vault and leaves `sk_d` arrays unwiped; `crates/node/src/keystore.rs:81-101` opens `<path>.tmp` without `O_NOFOLLOW`/`O_EXCL` and writes the secret before checking the target type (a planted symlink receives it). `seal`/`write_private` are not used by the binary. Remediation: wrap secrets in `Zeroizing`; use `O_NOFOLLOW|O_EXCL` and check the target before writing. (Agent D D10, D12.)

**L-07 — R randomization commitment adds no hiding; upstream ZK guard removed.** `vendor/p3-recursion/recursion/src/pcs/whir/uni/pcs.rs:31-35` claims R masks the opened trace values, but R is opened only as a separate claim and never mixed into the trace/quotient arguments; hiding comes entirely from the interleaved random rows. Separately, the local patch removed upstream's `is_zk` guard in `backend/whir.rs` without upstream support or tests. Remediation: correct the doc claim; add regression tests for the enabled ZK path. (Agent C L-01, L-02.)

**L-08 — SLH-DSA parameter notes wrong; pre-release dependency.** `crates/pq-sign/src/lib.rs:21-24` says "128f ~16x faster than 128s" and "8KB signature"; 128f is roughly 3x more verify work than 128s and the signature is 17,088 bytes; `crates/node/src/wire.rs:42` says the verifying key is 64 bytes but it is 32. `slh-dsa 0.2.0-rc.5` is a pre-release with `// TODO context processing` in its verify path. Remediation: correct the rationale that drives the in-circuit cost estimate; pin a released version before production. (Agent D D08, D13.)

## Informational observations

- **I-01 — Soundness knobs are environment-configurable in library code:** `WHIR_SECURITY_LEVEL`, `WHIR_SOUNDNESS_REGIME` / `WHIR_INNER_SOUNDNESS_REGIME`, `WHIR_POW_FLOOR` / `WHIR_INNER_POW_FLOOR`, `WHIR_INNER_RATE`, `WHIR_FOLDING_FINAL`, `WHIR_FINAL_LDE` (`crates/prover/src/whir.rs:126-189`, `whir_recursion.rs:186-193, 314-353`). A deployment that sets these loosely silently weakens security. Pin them in a reviewed config, not process env.
- **I-02 — Documentation drift (spec deltas).** README and comments describe SHA3-256 notes/nullifiers and a Keccak commitment tree (code is Poseidon2 throughout); an "operator set" for `applyBlock` (none exists); a Keccak depth-256 empty nullifier root (code is a Poseidon2 depth-96 constant). `vendor/p3-recursion/PATCHES.md` lists one of five changed code files, misdescribes the ZK patch ("const false->true", "evaluation truncation"), and points to a pristine directory that does not exist. Full list in the specification, section "Specification deltas".
- **I-03 — Fixture keys compiled into the production node.** The node binary is built with the prover `testkit` feature (`crates/node/Cargo.toml:15`), so genesis notes are owned by public fixture keys and the demo genesis / SPHINCS+ keys are public. Combined with H-01/M-01 this is why the shipped configs are exploitable by anyone. Remove `testkit` from the production build.
- **I-04 — Fees are burned; the fee-recipient role is vestigial.** The circuit enforces `in = out + fee` but the contract has no payable path; `withdrawFees` is dead code (`contracts/src/ShieldedPool.sol:88-89, 182-189`).
- **I-05 — Gas.** One verification is ~102M gas, above the L1 block limit (a completeness risk on mainnet); the settlement submitter hard-codes `GAS_LIMIT = 20e9` (above every public chain limit) and has no RPC timeout or TLS and treats one receipt as final (`crates/node/src/settlement.rs`).
- **I-06 — Spent-nullifier oracle.** `/v1/transfer` answers "already spent" for any self-signed nullifier, exposing spent-set membership to any submitter (`crates/node/src/main.rs:619-659`).
- **I-07 — Minor in-circuit divergences from native p3.** 0-bit proof-of-work leaves the witness unconstrained (malleability); the circuit samples query indices by low-bit truncation while native rejection-samples (they diverge only at the sampled value `p-1`, a completeness issue); the in-circuit batch verifier omits `check_multiplicity_height_bound` (matters only combined with V-06). (Agent C I-02..I-04.)

## Discharged / false positives (selected)

The reviewers confirmed the following are **not** issues on the audited revision, each with a rejecting location:
- Value conservation is a true integer equality (biased carry chain, every column term below 2^25; `crates/prover/src/transfer.rs:792-844`); amount and carry limbs are range-checked; no negative values.
- Digest export limbs are canonical (`decompose_to_bits(.,31)` asserts `< p`); roots pass a strict decode.
- Within-transfer and within-block duplicate nullifiers are rejected by the threaded absence chain and the native `seen` set; within-pool replay is blocked by L1 continuity.
- HMAC token verification is constant-time and checks the MAC before parsing; the ACL matches paths exactly and unmatched paths return 404 without the guard.
- Vault crypto is sound: Argon2id (m=64 MiB, t=3, p=1), per-vault random salt and nonce, GCM tag verified before plaintext, no KDF-parameter downgrade.
- Entropy is correctly sourced (OS RNG / `crypto.getRandomValues`, short entropy refused).
- The settlement ABI encoding and selector are correct; the extension CSP is sound.
- The challenger's `sampleBase` rejection bound, byte order, and sponge flush match p3; query indices are uniform.

---

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
