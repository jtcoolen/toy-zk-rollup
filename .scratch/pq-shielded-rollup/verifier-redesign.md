# Verifier redesign proposal — deployment limits & calldata limits (D-086)

Status: PROPOSAL (round 9). Evidence base: GOAT bitcoin-stark-verifier
(pruned.rs, proof_script.rs, README), IOHK plutus-plonky3-exploration
(README + benchmark tables), midfall solidity-verifier (lowering/: calldata.rs,
vk.rs, quotient.rs, render/), plus our own §17-19 measurements at 42d8cea.

## The two problems

1. **Bytecode (EIP-170).** WhirVerifier runtime = 24,536 B, margin **+40 B**.
   Any future optimization that adds code is blocked. The terminal-weight phase
   (42.0M gas, evalConstraintsPoly + evaluate_hypercube) is ~6-8 KB of that
   code and runs exactly ONCE per verify — the ideal extraction candidate.
2. **Calldata / tx size.** WBND v4 bundle = 1,967,592 B. At 16 gas/zero byte
   that is 23.5M gas of pure calldata (12.4% of current 179.9M), and 1.97 MB
   exceeds every practical single-tx gate on a stock node (geth mempool policy
   64 KiB default, RPC body caps) and 78% of a 30M mainnet block.

## What the three projects actually teach (fresh evidence)

**GOAT** — two mechanisms, both directly applicable:
- `pruned.rs`: the WIRE format for openings is Plonky3's **pruned frontier**
  (boundary digests only — `walk_frontier`/`restore_boundaries`, normative
  wire order: level 0 first, groups by ascending parent, missing-child
  positions ascending). GOAT EXPANDS it to full per-query paths only because
  Bitcoin Script has "no place to keep a frontier between queries". **We do not
  have that constraint** — Solidity can hold the frontier in memory and do the
  amortized walk in-circuit, which is strictly better than both shipping full
  paths (our v4) and expanding them.
- Constraints are DERIVED, not shipped: each round's OOD scalars, domain points
  and batching challenge ride below the folding randomness; "a round costs 1+n
  elements, not n·(1+arity), because its points are square-power expansions of
  one scalar". Our intermediate rounds already do this
  (`expandFromUnivariate(out.oodPoints[q], k)`); the shipped eqPoints section
  (773 KB, 38% of the bundle) is the initial constraint's 1,889 groups —
  transcript-deterministic per p3-whir reader.rs (expand_from_univariate of
  drawn points). Same lever, one section away.

**IOHK** — three lessons:
- **Multi-transaction verification is the sanctioned fallback** for a hard
  per-tx limit: "one [tx] per FRI query plus one for the shared work" (22+1
  txs at their params). For us this is a LAST RESORT (state must thread
  transcript state + claims across txs), but it is the answer if a chain
  refuses to raise its tx-size gate.
- **Proof-as-generated-literal** (convert.py → generated .ak test): we already
  mirror this with generated JSON/bin vectors + byte-exact replay tests.
- **Benchmark tables as the project's spine** (docs/benchmark.md): our
  verifier-optimizations.md §1-19 is the same artifact; keep it committed and
  current.

**midfall** — the split mechanics, all three pieces needed:
- `RenderVk::Separate`: verifying key as a **data-only satellite contract**;
  the verifier extcodecopies from it. → our cfg-constants contract.
- `RenderQuotient::ExternalPinned`: the expensive phase split into its own
  contract, **pinned by runtime LENGTH + CODEHASH** captured at construction,
  called by staticcall. → our TerminalWeight satellite.
- **Frame passing**: the satellite receives the caller's memory frame as raw
  calldata (`calldata[0..N) == memory[BASE..BASE+N)`) and returns a compact
  fixed frame with a magic guard; absolute Yul addresses, scratch from 0x80.
  No ABI codec at the boundary.
- `calldata.rs`: repacking is an OFF-CHAIN step driven by the bound VK — the
  contract never reparses; the encoder owns the layout. → our wbnd.rs stays the
  single source of the wire format.

## The redesign

### Contracts (midfall split, coarse boundaries only — D-085)

    WhirConstants   data-only: cfg constants (framing seps, generators,
                    params, domain tables). Deploy once per circuit shape.
    TerminalWeight  evalConstraintsPoly + evaluate_hypercube + the terminal
                    claim check. Pure, stateless. Pinned by codehash+length.
    WhirVerifier    everything else: transcript, initial/intermediate/final
                    phases, query loops. Constructor stores
                    keccak of (constantsCode, weightCode, lengths).
    ShieldedPool    unchanged; holds the WhirVerifier address.

Call mechanics (midfall pattern, no ABI codec):
- Constants: `extcodecopy(constantsAddr + off, dst, n)` replaces the cfg
  section of every proof's calldata. The cfg bytes are already read linearly
  (t.constants/t.constOff cursor) — the loader just points the cursor at
  extcodecopy'd memory once at init.
- TerminalWeight: one staticcall per verify. Verifier packs
  [allR ‖ constraints-descriptor ‖ finalPoly ‖ randomness ‖ folded-claim]
  into one contiguous memory frame, staticcalls with the frame as raw
  calldata; satellite returns [magic ‖ weight ‖ value] and the verifier
  checks magic + does the final equality (or the satellite does the check and
  returns pass/fail + values for the transcript — decide at implementation;
  keeping the equality check in the verifier keeps the trust boundary crisp).
  Overhead: ~2-3K gas per verify, noise against the 42M phase.
- Failure modes: satellite absent → revert PIN_MISSING; codehash mismatch at
  construction → revert PIN_MISMATCH. No delegatecall anywhere: satellites are
  pure and versioned by redeploy + new WhirVerifier.

Frees ~6-8 KB in WhirVerifier → margin goes from +40 B to ~+6 KB, unblocking
the remaining gas queue (assembly Merkle −4.5M, sumcheck inlining −8M).

### Bundle: WBND v5 (GOAT derive-don't-ship)

    v4: 1,967,592 B
    - eqPoints section (773 KB): contract derives each of the 1,889 groups as
      expandFromUnivariate(drawn scalar, k) at weight-eval time. Premise
      CONFIRMED against p3-whir-0.8.0 reader.rs:76-84. Net gas: -9.2M
      calldata + ~+5M derivation = -4M net.
    - cfg constants (180 KB): served by WhirConstants via extcodecopy.
    - Merkle paths (700 KB): ship p3's NATIVE pruned frontier (boundary
      digests, GOAT's normative wire order) instead of expanded per-query
      paths; contract ports walk_frontier/restore_boundaries semantics and
      does the amortized frontier walk once per round (sorted query indices
      are already in-circuit — the transcript squeezes them).
      This is the one piece with real engineering risk: new wire section,
      new contract pass, differential tests (pruned-walk accept == full-path
      accept on every vector; tamper tests per level).
    v5 target: ~320 KB. Calldata floor 23.5M -> ~5.4M gas.

### What this does NOT change

- The ~140M compute floor (§19): this redesign is about LIMITS, not the floor.
  Net gas effect ≈ −4M (calldata) − ~0.1M (call overhead) ≈ −4M.
- Split traces: NO (D-085 — bundle scales with queries×rounds, not trace size;
  N sub-proofs re-pay fixed overhead).
- Security boundary: satellites are pure functions of pinned inputs; the
  transcript, the Fiat-Shamir state, and the final claim equality stay in the
  pinned core. A malicious satellite can only make verification fail or
  return garbage that the core's checks reject — codehash pinning makes even
  that impossible post-deploy.

### Deployment (one command)

    forge script DeployAll: deploy WhirConstants -> TerminalWeight ->
    WhirVerifier(constants, weight) [pins codehashes] -> ShieldedPool(verifier).
    Upgrade = redeploy the set, repoint the pool (or proxy the verifier addr).

### Rejected alternatives

- **Per-phase satellites everywhere** (every round its own contract): per-call
  overhead fatal inside 1,336-iteration loops; midfall splits ONE phase.
- **Full GOAT expansion of paths in-circuit**: GOAT pays the amortization back
  because Script must; we can keep the frontier — expansion would ADD gas.
- **IOHK multi-tx splitting as primary**: threads transcript state across txs,
  huge complexity, only justified under an unraisable 64 KiB gate. Documented
  as last resort.
- **EIP-4844 blob for the proof**: works for mainnet-L1 (384 KB/blob), but adds
  a KZG-trust + point-eval-precompile path; the goal's settlement chain has
  high block limits, so calldata stays. Revisit only if mainnet L1 matters.
- **SNARK-wrap the STARK**: forbidden by goal (no SNARKs).

### Execution order (each step gate-green before the next)

    A. TerminalWeight satellite + codehash pinning        [bytecode unblock]
    B. WhirConstants contract + loader cursor change      [−180 KB calldata]
    C. eqPoints derivation + WBND v5 encoder             [−773 KB calldata]
    D. Pruned-frontier paths (wire + amortized walk)      [−700 KB calldata]
    E. Re-run §18 ceiling table on v5; resume gas queue  [assembly Merkle etc.]

Estimated: A ~1 session, B ~0.5, C ~1, D ~2 (highest risk), E ~0.5.
