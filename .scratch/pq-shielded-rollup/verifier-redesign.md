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


## Round 11 measurements (supersedes the estimates above)

Bundle wire sizes, measured from the shipped artifacts (WBND v4, u32 LE words):

    composed_bundle.bin  1,967,592 B = hdr 16 + cfg 186,092 + prf 1,778,408 + stm 3,072 (+3,076 slack)
      cfg  = batch 492 + schedule 93,628 + constraints 91,964
      per-round PROOF eq section: 7,604 / 192,388 / 45,764 / 69,924 / 71,108 = 386,788 B
      framing_hex bytes: 5,072 / 14,124 / 47,672 / 9,148 / 10,904 = 86,920 B (bulk of schedule)
    block_composed_bundle.bin  2,825,568 B = cfg 235,348 + prf 2,587,128 + stm 3,072
      cfg  = batch 492 + schedule 111,300 + constraints 123,548
      per-round PROOF eq section: 9,156 / 243,364 / 52,004 / 109,604 / 335,620 = 749,748 B

Corrections to the proposal above: the eq section is 387 KB (composed) / 750 KB
(block), NOT 773 KB; the cfg section is 186/235 KB, NOT 180 KB.

**cfg is per-shape, not global.** composed vs block cfg share only 85,967 of
186,092 bytes (first diff at byte 96): the schedule region encodes per-round
shapes (framing tables, generators, params). A WhirConstants satellite is
therefore ONE CONTRACT PER CIRCUIT SHAPE (or shape family), pinned by the
verifier constructor alongside TerminalWeight. That is exactly midfall's
RenderVk::Separate model - the vk satellite is per-circuit.

**Step C premise CONFIRMED numerically.** The shipped per-round eq section is
the initial constraint's groups in batching-power order; group coord count =
the STACKED arity: checked_stacked_num_variables over
(padded_arity(log_height, 4), width) per matrix, i.e.
log2(next_pow2(sum width_i * 2^max(log_i,4))). Composed round 0:
4*(2^10+2^9+2^16+2^15+2^14+2^4) = 464,960 -> 2^19: matches eq_points_lens=19
(25 groups x 19 = 475 coords). Each group derives from the statement's zetas
via univariate_eq_point (expand + y/(1+y) + scale prod(1+y)); the statement
section (3 KB) already ships log_size, width, n_points and packed zetas per
matrix per round - everything needed. The stacking placement rule
(StackedPlacement, plan.rs) is the remaining piece to port.

Gas caveat stands: per-coord Ext4 inv is ~3-4k gas vs 512 gas/coord calldata.
The reformulation eq(y,X) = prod(y_i^2 - y_i + 1)/scale collapses per-coord
inversions to ONE inversion per group (25 in composed r0, ~2.5k in r1), which
makes step C a net gas win as well as a size win - but only if the satellite
derives from raw zetas + placement table (mode 2 frame), not from transformed
coords.

Decision: execute B first (mechanical, no math risk, -186/-235 KB), then C
(derivation, -387/-750 KB), then D (pruned frontier, -700 KB est).


## Round 11, second observation batch (gas reality + step-B mechanics)

Full-verify gas, measured on the real bundles (forge, cancun):

    composed verify  184,634,705 gas   (block proof: 344,501,044)
    reject-fast paths 67-77M (transcript walk dominates before proof fails)

The 36M block gas limit is exceeded 5-10x by EXECUTION, not calldata: calldata
is ~315K/452K gas of the total. Size work (B/C/D) is necessary for the calldata
LIMIT (~1.2 MB hard ceiling at 16 gas/byte with an empty block) and for cost,
but the gas queue (assembly Merkle, sumcheck inlining, hash precompiles) is the
binding constraint for L1 verification. Both tracks stay open; the size track
also closes a soundness gap (cfg is proof-supplied today).

**EIP-170 kills the naive WhirConstants.** A data satellite's cfg is 186 KB;
deployed code is capped at 24,576 B and initcode at 49,152 B. A cfg satellite
must be a CHUNKED SET: ceil(186092/24576) = 8 code contracts of <= 24,576 B
each (initcode = payload + ~10 B wrapper, under the 49 KB limit), addresses
passed to the verifier constructor, each extcodecopy'd once into one memory
buffer (~120K gas total: 8x2600 cold + 3/word copy + memory expansion).
Storage-backed satellites are worse (5,816 cold SLOADs ~ 15M gas).

**Step C beats step B on every axis except effort** and needs no satellite:
the eq section is PROOF data (387/750 KB) and the verifier ALREADY derives
intermediate-round eq from transcript-sampled points. The initial constraint's
groups derive from the per-matrix OOD zetas - which the initial phase samples
itself (transcript-owned, no trust change). Derivation cost with the
eqEval reformulation prod(y_i^2 - y_i + 1)/scale: ~450 gas/coord + one Ext4
inv per group ~ 11M gas added vs 6.2M calldata saved - net +5M on a 184M
verify, -387 KB wire. Put the derivation in TerminalWeight (mode 2 frame:
per-group [arity, zeta word] instead of mode 1 wire groups) - the satellite
has 20 KB of bytecode margin and already owns eq evaluation.

Revised order: C (eq derivation, v5) -> D (pruned frontier) -> B (chunked
cfg satellites, last: biggest mechanical lift, smallest marginal win once
C+D land).


## Round 11, third observation batch (step C spec, CONFIRMED)

The stacking rule is now pinned by direct reproduction against
`composed_flat.json`/`composed_vectors.json`:

- **Group order** = `StackedPlan::try_new` placement order: tables sorted by
  padded arity ascending, iterated in REVERSE (largest table first); within a
  table, one group per column in source-column order.
- **Group coords** = `lift_prefix`: the `arity` univariate-eq coords FIRST
  (`expand_from_univariate(zeta, arity)` big-endian powers, each mapped
  `y = c/(1+c)`), then `19 - arity` selector bits appended (bit =
  `(index >> (nv-1-i)) & 1`, `index = reverse_bits(raw_slot, nv)`,
  `raw_slot = offset >> arity` accumulated as `offset += 2^arity`).
- Validated 24/24 matrix groups for composed round 0 exactly.
- The **25th group** (last statement, `eq_group_lens` tail) is NOT any shipped
  point: it is the initial phase's VIRTUAL claim point — the `drawExt(t)` at
  `WhirVerifierCore.verifyInitial` L260 that the contract currently draws and
  DISCARDS. Same structure: univariate expansion at full stacked arity.
  Intermediate rounds already do exactly this (WhirVerifier L552-554).
- Per-round initial-constraint group counts: 25/501/130/190/202
  (lens 19/24/22/23/22); the wire eq section feeds ONLY `constraints[0]`
  (`eqPointsCdBase`, L452). Intermediate constraints already derive in-circuit.

**Derivation identity (no per-coord inversions):** with
`f_i = eq_1(y_i, r_i)`, `y_i = c_i/(1+c_i)`, `c_i = z^(2^(n-1-i))`:
`prod_i f_i = prod_i (1 - r_i + r_i*c_i) / prod_i (1 + c_i)`, and
`prod_i (1+c_i)` IS the prover's `scale`. So one Ext4 inversion per group
(25..501 per round), `arity` squarings + muls, selector-bit coords cost a
conditional select only. Strictly sounder than today (proof-supplied eq
points become derived), removes 386,788 B from the wire.

**Frame consequence:** the TerminalWeight satellite evaluates the final
identity, so mode-1 frames would re-ship the derived coords and cancel the
savings. Mode 2 must carry per-group `[arity, zeta, selectorIndex]` (3 words
vs 19-24) and derive in the satellite (20,931 B bytecode margin available).

Order stays C -> D -> B.


## Round 11, fourth observation batch (step C spec COMPLETE)

Full group enumeration validated for ALL 5 composed rounds:

- Group sequence = constraint statement order = **placement order** (largest
  table first; equal arities: later source index first). Per table: per POINT
  (statement-major), per COLUMN: group = univ(zeta_point, arity) ++ selector
  bits(rev_bits(slot_base+c, nv)); slot_base advances width*2^arity per TABLE
  (columns shared across a table's points).
- Group counts per round: 24+1, 499+2, 128+2, 188+2, 200+2 (corrected from an
  earlier intermediate 257/105/100 reading) — the tail =
  **commitment_ood_samples** virtual groups (r0: 1, r1-4: 2), each expanded
  at FULL stacked arity, zeta = the transcript-drawn virtual claim point
  (verifyInitial L260 drawExt, currently discarded).
- groupLens tails confirm: [..,1] r0, [..,2] r1-4.
- Matrix-group coords reproduced EXACTLY for r0 (24/24) and r2 (128/128);
  r1/r3/r4 need the per-point enumeration above (groupLens [76,76,166,166,...]
  confirms statement-major).
- **Reformulation validated numerically**: eq(y,r) over a group =
  [prod_{i<arity}(1-r_i+r_i*c_i)] * [prod_{j} bit_j ? r : 1-r] / prod(1+c_i),
  c_i = z^(2^(arity-1-i)) — ONE Ext4 inversion per group, no per-coord
  inversions, no materialised coords.
- Zetas are PUBLIC INPUT (statement section carries per-matrix log_size,
  width, n_points, packed zeta per point) — derivation is trust-preserving.
- Cost: ~1048 groups total x (arity squarings+muls + 1 inv) ~= 1.3M gas vs
  -6.2M calldata gas and -386,788 B wire. Net ~-5M gas, strictly sounder.
- Satellite frame mode 2: per-group [arity, zeta, selIndex] (3 words vs 19-24).
- Need: whir_walk export of initial virtual OOD points into vectors to pin
  the contract's transcript draws.


## Round 11, fifth observation batch (step C DESIGN LOCKED)

All 1039 matrix groups across all 5 rounds reproduce EXACTLY from the
statement section alone (per-table placement: sort by arity asc, iterate
reverse; per table: cols c=0..w-1 claim slots (offset>>arity, rev_bits),
offset += 2^arity per COLUMN; groups = per POINT then per COLUMN, statement-
major). Virtual tail groups: arity = k, zeta = verifyInitial's drawExt
(L260, currently discarded), no selector bits; count = commitment_ood_samples.

**Implementation shape (fits WhirVerifier's 1,057 B margin):**
- Verifier: capture virtualPoints in verifyInitial; locate STATEMENT section
  (stmAbs/stmLen from the header it already decodes — 2 lines); pass
  (stmLen, stmBytes, roundIdx, nVirtual, virtualPoints) into the frame;
  constraints[0] becomes mode 2 (no eqCdBase/eqLens); drop eq section decode
  and cfg eqPointsLens; version 5.
- Satellite: parses the statement slice from the frame, builds group
  descriptors [arity, zeta, selIndex] itself, evaluates each group WITHOUT
  materialising coords:
  w_g = prod_{i<arity}(1-r_i+r_i c_i) * prod_sel(bit? r:1-r) * inv(prod(1+c_i)),
  c_i = z^(2^(arity-1-i)) — ONE inversion per group.
- WhirGadgets.ConstraintWeight gains groupDescs (flat 3/group);
  constraintWeight gains the mode-2 branch (inlines only into the satellite).
- WBND v5: drop per-round eq section + cfg eq_points_lens. STATEMENT section
  unchanged (already carries log_size/width/n_points/zetas).
- Wire: -386,788 B composed / -749,748 B block; frames shrink 386 KB -> ~100 KB.
- Validation plan: e2e (composed + block) is the virtual-draw proof; a
  TerminalWeight unit test compares mode-2 weight vs mode-1 weight against
  the shipped v4 eq section (catches any virtual-draw mismatch exactly).


## Round 13, sixth observation batch (reference gas study: the path to ~30M)

User question: sol-whir-p3 verifies 106.6 KB at 12.9M tx / 11.3M exec —
does 300 KB land at ~30M? Decomposition: 1.75M calldata + ~3M fixed exec
+ ~8.3M size-proportional exec → 300 KB ≈ 4.8M + 3M + 23M ≈ 31M. Yes —
but ONLY for the RECURSIVE proof (~300 KB), never the composed bundle
(1.19 MB v5: calldata alone 19M; at sol-whir-p3's exec ratio ≈ 126M exec
→ ~145M floor). 30M is the recursive-proof target; the size agenda
(C/D/B) is the interim that keeps the composed verifier survivable until
the recursive verifier exists.

All four references cloned under .scratch/refs/ and studied:

**sol-whir-p3** (same proof family; the anchor). Their retained-win list
(docs/verifier-optimization-audit.md): schedule-specific 4-bit fixed-base
exponentiation tables; packed Merkle frontier with strict parent emission
and parity-specific hashing; cached cubic select eval + factored equality
accumulation; radix-80 base-row accumulation; specialized radix-64 final
multilinear evaluator; packed transcript encoding. Their strict >1% gate
killed most micro-opts (general packed ext mul 0.18%; row/Horner fusion
0.72%; Merkle bound hoist REGRESSED) — under via_ir the micro well is
dry; every retained win is structural. Biggest single win was PROOF SHAPE:
grouped LogUp terminal (third helper commitment, shared weights, ONE
Merkle frontier for three roots) = -17.69% tx gas, 10.6M. Their runtime
is 62.7 KB — they went monolithic under EIP-7954's 64 KB limit; we stay
split under 24,576. Both are valid EIP-170 answers. Precompile
experiment: EIP-compatible boundary is EXT8_MUL/EXT8_SQUARE only; a fork
gets ~4x field math (30M → ~15M) but is not mainnet today.

**GOAT** (Bitcoin Script, extreme budget). Confirms step C from the
opposite side: derived constraints = 7.5% of verifier with ZERO hash
permutations vs 1.5 MB supplied list; "a round costs 1+n elements to
carry, not n·(1+arity)". Merkle paths = 60% of permutations, leaf hashing
37%, query share 97.1% → step D (pruned frontier) and path assembly are
the dominant gas, not field math. Parameter lever: lower λ buys FEWER
queries, not cheaper ones — grind bits trade prover work for verifier
bytes.

**midfall** (Halo2/KZG). 1.84M tx gas because pairings do the heavy
lifting inside precompiles; levers: scalar==1 MSM fast path, fuse MSMs,
batch pairings into one ecPairing call, split verifier/VK/quotient into
three contracts (12.6/13.6/21.8 KB runtime). EVM lesson: batch into
precompiles (keccak already; hash precompiles queued) and split by data
(adopted in D-086).

**IOHK plutus-plonky3** (Cardano). Op-count budget for a 414 KB proof:
13.4K SHA256(512b) calls, 15.4K ext muls, 3.5K adds, 1.6K inverses.
On EVM at assembly floors that is ~2M hash + ~4-9M field: the op budget
is NOT the problem; copies/absorbs/loop overhead are — exactly what the
raw-calldata protocol + assembly copies attack. Full verify 727-768M mem
≈ 3x their budget: every VM needs the same structural tricks.

**Path to ~30M for the recursive proof (300 KB), ranked:**
1. Calldata floor 4.8M (irreducible on-chain).
2. Adopt sol-whir-p3 retained techniques wholesale: packed/assembly Merkle
   frontier (our queue item, -4.5M on composed), fixed-base gamma tables,
   factored eq accumulation (= step C), radix final evaluator.
3. Proof-shape wins (we own the recursion circuit): one Merkle frontier
   across roots (their grouped terminal, -17.7%), fewer queries via grind
   (GOAT), log_blowup tuning.
4. Sumcheck absorb batching (our -8M queue item; their transcript bucket
   is small because of packed transcript encoding — ours already is).
5. If the settlement chain ever ships ext-field precompiles: ~2x again.
Realistic band 25-35M. The composed-proof verifier cannot reach this band
at any size (1.19 MB × ~100 gas/B floor ≈ 119M exec + 19M calldata).



---

# D-092 PROPOSAL — The 30M redesign: recursive settlement path

## The arithmetic that fixes the architecture

Measured anchors (all local, this session):
- sol-whir-p3 LeanVM terminal (recursive proof, 106.6 KB): 12.9M tx / 11.3M
  exec = **106 exec gas/byte, 121 total gas/byte**.
- Our composed verifier (v5, 1.19 MB): 184.6M total ≈ **155 total gas/byte**
  (~140 exec/byte). We are ~28% heavier per byte (padding-canonical rejects,
  grind witnesses, constraint-identity layer).
- Our recursion chain (measured, issues/16): 332→302→300 KB converging at
  ~300 KB (KoalaBear D=5, log_blowup 2, fan-in 2). Postcard; WBND-encoded
  size unmeasured.

Naive 300 KB on today's verifier: 4.8M calldata + 42M exec ≈ **47M — misses.**
The composed proof can NEVER reach 30M: even at D-086's 320 KB target the
exec floor (~127M compute for the composed shape) dominates. **30M is only
reachable on the recursive proof.** That is the redesign: settlement verifies
the layer-N recursive proof, not the composed bundle.

The lever that makes it fit: **C/D/B are shape-independent.** They remove eq
points (39% of proof), explicit Merkle paths (38%), and cfg constants (15%)
from ANY WHIR proof. Applied to 300 KB at the same ratios D-086 achieves on
composed (1.97 MB → ~320 KB, -84%): recursive proof lands **~50-120 KB** —
exactly sol-whir-p3's terminal scale, where 121 gas/byte is a MEASURED
result, not an estimate.

## Budget (target ≤30M tx gas, one settlement)

| line | 300 KB raw | after C/D/B (~50-120 KB) |
|---|---:|---:|
| calldata (16/4 gas/B) | 4.8M | 0.8-1.9M |
| exec: Merkle/STIR paths | ~14M | ~2-5M (pruned frontier) |
| exec: sumcheck absorbs | ~8M | ~6-8M (assembly batching) |
| exec: constraint identity | ~12M | ~3-6M (step C derivation, satellite) |
| exec: transcript + fixed | ~3M | ~3M |
| exec: final fold + evals | ~5M | ~2-4M |
| **total** | **~47M** | **~17-28M** |

Margin levers if the top of the band lands: grind-bit/query trade (GOAT:
"lower λ buys fewer queries, not cheaper ones" — same for grind: prover
work trades for verifier bytes AND paths), grouped-frontier terminal
(sol-whir-p3 -17.69% proof-shape win), future ext-field precompiles (~2x
field math on a fork chain).

## Phases

**Phase 0 — finish D-086 on the composed shape (IN PROGRESS).**
C (eq derivation: wire DONE v5, Solidity in progress) → D (pruned frontier)
→ B (cfg satellites) → E (ceiling table). Interim value: composed verifier
survives calldata limits until recursion lands. Real value: every technique
(assembly Merkle walk, factored eq accumulation, pruned-frontier walk,
satellite frame protocol) is built, differential-tested, and gas-measured on
composed vectors FIRST, then reused unchanged on the recursive shape. The
gas queue (assembly Merkle -4.5M, sumcheck inlining -8M) executes here too.

**Phase 1 — recursive proof through the wire (Rust).**
- D-088 DONE (Poseidon2 roots). D-089: fold client-proof public inputs to
  ONE statement root inside the final recursive proof → the on-chain
  statement section becomes (block header fields, one 32-byte root) instead
  of N limbs. The verifier checks root == expected(block); a wrong root is
  a different statement, not a cheaper proof.
- New 'recursion_export.rs' mirroring 'composed_export.rs': flatten the
  layer-N WHIR proof (same protocol: commitments, sumchecks, OOD answers,
  query openings, grind) into the flat sidecar → 'encode_bundle' v5+. The
  WBND encoder is shape-generic already (cfg carries the schedule).
- Measure: WBND-encoded layer-N size (expect ~300 KB pre-C/D/B, ~50-120 KB
  post). Sweep verifier-cost parameters at ≥100 bits: log_blowup ∈ {1,2},
  query grind bits, fan-in. Gate: documented size + soundness budget.
- Deploy a second WhirConstants satellite for the recursion schedule (step
  B machinery, different cfg blob).

**Phase 2 — the recursive verifier (Solidity).**
Same codebase: WhirVerifier + satellites, new schedule cfg + statement
shape. NOT a new verifier — the recursion proof is the same WHIR protocol
over the recursion circuit's AIR. Work items:
- Statement decode path for the folded root (D-089 shape); bind it into the
  transcript exactly as the recursion prover's public-value absorption.
- Run the full C/D/B lever set on this shape (they are cfg-driven; mostly
  free once Phase 0 lands).
- Gas queue applied here is what closes 155→~120 gas/byte: assembly Merkle
  walk, sumcheck absorb batching, fixed-base gamma tables (sol-whir-p3
  retained win), radix final evaluator (their -4.5% win).
- Gate: foundry test with the REAL layer-N proof, ≤30M tx gas, plus reject
  battery (wrong root, wrong block hash, truncated, replayed).

**Phase 3 — proof-shape co-design (only if Phase 2 lands >30M).**
- Grouped terminal (sol-whir-p3's -17.69%): one Merkle frontier across all
  commitments + shared constraint weights. Circuit-side change in the
  recursion AIR; verifier-side: single frontier walk (step D machinery).
- Grind/query retune: security = log_blowup·queries + grind_bits; move
  budget from queries to grind (prover pays, verifier saves paths).
- log_blowup retune at fixed security (fewer queries at lb2 than lb1).

**Phase 4 — settlement integration + e2e.**
- Node settles with the layer-N proof (settlement_bundle path already calls
  encode_bundle); composed verify stays as --audit mode and fallback.
- MetaMask e2e at ≤30M: real wallet, real gas cap, reject-path UX.
- Re-run §18 ceiling table on the recursive shape (step E generalized).

## What is explicitly NOT in the plan
- Splitting traces (D-085: makes both limits worse).
- Per-proof codegen (GOAT proof_script): deploy cost per proof, wrong EVM trade.
- EIP-4844 blob path (KZG trust; settlement chain has high limits).
- SNARK wrap (forbidden).
- Monolithic 64 KB contracts (EIP-7954 not active on our chain; split works).
- Ext-field precompiles (fork-chain only; recorded as Phase-3 multiplier).

## Risks
1. 300 KB is postcard-measured; WBND framing + folded-root statement may
   shift it ±10%. (Measurement is Phase 1 gate 1.)
2. Recursion circuit's AIR constraint tables may not fit the stacked-plan
   assumptions step C encodes (validated on composed shapes only). Gate:
   differential test of statement-derived groups on a recursion proof.
3. 155→~120 gas/byte needs the gas queue to deliver as modelled. Fallback:
   Phase 3 levers exist (grind trade alone can cut paths 30-50%).
4. Soundness chain length: on-chain trust = one recursive proof + statement
   root binding; every layer below is verified by the layer above inside the
   circuit. Documented in the D-090 decision entry, not assumed.


## Round 13, seventh observation batch (step C implementation IN FLIGHT)

D-086 step C, Solidity half. Locked order C -> D -> B; wire half (WBND v5)
already landed and both pin tests pass.

**Done:**
- `WhirVerifierCore.InitialOutput` gained `virtualPoints`; the virtual-claims
  loop now keeps `drawExt(t)` per OOD sample instead of discarding it. Strictly
  sounder: the virtual eq groups are now derived from transcript state the
  verifier itself computed.
- `WhirGadgets.ConstraintWeight` gained mode-2 fields: `stmCdBase` (absolute
  calldata offset of the raw STATEMENT section, 0 = not mode 2), `stmLen`,
  `stmRound`, `virtualPoints`. `constraintWeight` gained the mode-2 branch:
  same backwards Horner into gamma powers, over values from
  `eqValuesFromStatement(c, localR)` (function body pending).
- `TerminalWeight` frame parse gained the mode-2 branch: header is
  `[stmLen, roundIdx, nVirtual, virtualPoints..., raw statement bytes]`;
  constraint blocks grew 224 -> 352 B (11 words) for the new fields.
- Confirmed the STATEMENT wire layout from `wbnd.rs` (L732-761):
  `u32 num_rounds`; per round `u32 n_mats`; per matrix
  `u32 log_size, u32 width, u32 n_points`, then `n_points` packed ext words
  (BE limbs at bits 224/192/160/128 = `pack_ext`). `stmLen` is a u32 LE at
  byte `16 + (cfgWords + prfWords) * 4`.
- Re-read `StackedPlan::try_new` (plan.rs L194-236) as the ground truth for
  placement: stable sort by arity ASC, iterate REVERSE (largest first, ties ->
  later source index first); per table the `width` selectors claim slots
  `raw_index = offset >> arity`, `index = reverse_bits_len(raw_index, nv)`,
  `offset += 2^arity` per COLUMN. Selector bits are appended as the SUFFIX of
  the local point (`lift_prefix`), which is why `evalConstraintsPoly` builds
  `localR` with the round prefix reversed and the stack suffix in order.

**Design correction made en route:** the first draft of the mode-2 branch read a
precomputed `eqValues` array filled by the satellite's parse loop. Wrong: the
group values depend on `localR`, which is per-query, so they cannot be derived
once at parse time. Mode 2 now derives them inside `constraintWeight` per query
(one `KoalaBearExt4.inv` per group, ~1049 groups/round -> ~1.3M gas/round,
still far cheaper than shipping 386 KB).

**Next:** `eqValuesFromStatement` (the derivation), then the satellite's
statement-slice descriptor walk, then `WhirVerifier` v5 wiring (stmLen parse,
constraints[0] mode 2, drop eq decode, version 5), then the mode-2 vs mode-1
parity test. `WhirVerifier.t.sol` is expected to FAIL until this lands (bundle
is v5, verifier still checks version 4) - do not "fix" by reverting artifacts.

## Round 13, eighth observation batch (settlement state: composed vs recursive)

User check: "aren't we already aggregating recursively, so the final proof is
the 300 KB recursive one?" Answer grounded in code:

- Rust recursion EXISTS and WORKS: `whir_recursion.rs`
  (build_recursion_circuit / settle_recursion_circuit /
  build_batch_recursion_circuit), exercised by recursion_bench,
  recursion_lde_sweep, hvzk_blinding; the 332->302->300 KB convergence is
  measured there.
- Settlement does NOT use it yet: node main.rs L453 calls
  `composed_export::settlement_bundle` -> the 1.19 MB composed bundle is what
  goes on-chain. No recursion_export.rs, no WBND-encoded layer-N proof, no
  Solidity path for one.
- So D-092 Phase 1 (recursion_export.rs + size sweep) is precisely the missing
  wire; Phase 2 points the SAME WhirVerifier at it. The composed verifier is
  not throwaway: audit path + differential testbed for every lever.

Also confirmed ground truth for the mode-2 derivation:
`univariate_eq_point` (bridge.rs L41-58): coords = y_i/(1+y_i) with
y_i = zeta^(2^(n-1-i)), scale = prod(1+y_i). eq(localR, coords) therefore
equals prod_i(1-r_i+r_i*coords_i) * inv(prod(1+y_i)) - ONE inversion per
group, matching the locked doc formula. Ext4 exports ONE/TWO/inv;
evalConstraintsPoly localR = allR[n-k+j] (prefix order, stack first,
selector suffix last).


---

## Batch 9 (D-086 step C, continued) — mode-2 derivation: three root causes found

Recording every attempt and what it taught us, per the standing instruction.

### Attempt 1 — 32-byte point stride (WRONG)
First mode-2 walk assumed STATEMENT points were bare 32-byte packed ext
words. Satellite reverted BadStatement() while skipping rounds. Raw calldata
dump of one matrix header showed `... 1 32 <8 words>`: the encoder writes
each point through `blob`/`ext_arr` = **u32 byte-count (32) + 32-byte word**,
so the stride is **36 bytes** (12-byte matrix header + 36 per point). Fixed
`_skipMatrix` to `cursor + 12 + 36*nPoints` and the zeta read to
`_cdWord(mat + 16 + 36*q)`. Lesson: the wire is the encoder's `blob`
composition, not the JSON's logical shape.

### Attempt 2 — u32 LE decode swap (WRONG, twice)
After the stride fix BadStatement persisted. Traced the actual frame:
`mode2: stmLen=0`. The BE-calldataload → LE-u32 swap was wrong in BOTH
`WhirVerifier` StmRef parse and `TerminalWeight._leWordAt`. After
`shr(224, calldataload(at))` the four bytes sit big-endian in the LOW 32
bits (LE LSB at bits 31..24). Correct swap:
`or(or(and(shr(24,w),0xff), and(shr(8,w),0xff00)), or(and(shl(8,w),0xff0000), and(shl(24,w),0xff000000)))`.
First fix attempt used the mirror-image swap — still wrong. Lesson: decode
byte order by tracing the decoded value, not by re-deriving the shift.

### Attempt 3 — TerminalClaimMismatch: arity must be PADDED
Satellite then parsed cleanly but the weight differed. Full Python
differential against v4 ground truth (/tmp/diff8.py) proved the rule:
**arity = max(log_size, FOLDING_FACTOR=4)** — the wire stores the RAW
log_size, the stacking pads (`padded_arity`, composed_export.rs:361;
whir.rs:126). Raw-log_size derivation matched only 20/24, 496/499, 112/128,
184/188, 168/200 positionally — mismatches exactly the log_size<4 matrices;
padded version matched ALL (24/24, 499/499, 128/128, 188/188, 200/200).
Placement rule confirmed: stable sort by padded arity ASCENDING, iterate
REVERSE (largest first, ties later-source-first); per table each of `width`
columns claims slot `reverseBits(offset >> arity, k-arity)`,
`offset += 2^arity` per COLUMN; groups emitted per point, then per column.

### Attempt 4 — virtual groups are RAW expansion, not bridge
Ground-truth check (/tmp/vp.py): the virtual point's shipped coords satisfy
`vp[i] == zeta^(2^(k-1-i))` DIRECTLY (raw expansion), NOT the bridge form
`y/(1+y)` the matrix groups use (`univariate_eq_point`). So the value form
differs: matrix groups → `prod(1-r+r*y)*inv(prod(1+y))` (bridge, one
inversion — locked formula, verified == eq_poly_eval(bridge) numerically);
virtual groups → `prod(1-r-c+2rc)` with c = zeta^(2^(k-1-i)) chain, NO
denominator (verified == eq_poly_eval(raw) numerically, /tmp/vraw.py).
`eqGroupValue` branches on `selIndex == NO_SELECTOR` to pick the raw form.

### Folding-factor plumbing decision
FOLDING_FACTOR is NOT on the WBND wire (not in the config section, not in the
sumcheck params tuple [num_variables, log_folded_domain, ood_samples,
pow_bits]). It IS a fixed-config constant: `WhirFixedConfig.FINAL_FOLDING_FACTOR
= 4` and per-round `RoundConfig.foldingFactor: 4`. Decision: TerminalWeight
imports `WhirFixedConfig` and pads arity with `FINAL_FOLDING_FACTOR` —
Solidity inlines internal uint constants, so ZERO frame change and ZERO
bytecode cost. Rejected: threading ff through the mode-2 frame (WhirVerifier
margin is 688 B; a frame change also breaks the satellite ABI for no gain).

### State after batch 9
- `deriveGroupDescs`: 36-B stride, padded arity in all three passes
  (BadArity check + total, sort key, slot/nv), virtual tail arity = k.
- `eqGroupValue`: NO_SELECTOR → raw product; else bridge product.
- Both e2e tests (test_verify_accepts_the_real_proof,
  test_real_block_applies_to_the_pool) were failing TerminalClaimMismatch;
  expected to pass after these fixes.



---

## Batch 10 — step C GREEN: mode-2 derivation passes the full suite

Applied the three batch-9 corrections:
1. `TerminalWeight` imports `WhirFixedConfig`; new `_arityAt` pads the
   wire's raw log_size to `FINAL_FOLDING_FACTOR` (Solidity inlines the
   constant — zero frame change, zero verifier cost). Used in all three
   passes of `deriveGroupDescs` (BadArity check + total, sort key, slot/nv).
2. `WhirGadgets.eqGroupValue` branches on `selIndex == NO_SELECTOR`:
   virtual groups take the RAW product `prod(1-r-c+2rc)` (no denominator,
   no inversion); matrix groups keep the bridge product.
3. (36-B stride + LE swap already landed in batch 9.)

Result: **full suite 140/140 pass**, including both e2e tests:
- `test_verify_accepts_the_real_proof`: **169.0M gas** (was 184.6M pre-C —
  mode 2 drops the shipped eq groups from the wire AND the frame).
- `test_real_block_applies_to_the_pool`: **249.4M gas** (was 344.5M).
- `cargo fmt` gate fixed (wbnd_pin.rs tuple wrap).

Sizes after: TerminalWeight 6,893 B (margin 17,683), WhirVerifier 23,935 B
(margin 641 — unchanged in substance; the LE-swap fix cost ~47 B).

Step C is DONE: the verifier now derives every terminal eq group from the
public STATEMENT section + transcript draws; nothing proof-supplied enters
the weight. Next per plan: Step D (pruned-frontier Merkle paths, -700 KB
wire, est. -11M/-20M gas), then Step B (chunked cfg satellites).



---

## Batch 11 — step C test parity + gate

Added three mode-2 tests to `TerminalWeight.t.sol` (suite now 8/8):
- `test_frame_mode2_matches_spelled_groups`: a two-matrix statement (raw
  log_sizes 3 and 4 → both padded arity 4, k=5) plus one virtual point;
  the derived frame must equal a mode-0 frame spelling the SAME groups as
  explicit coordinates — bridge form for matrices (with the selector bit
  the placement rule gives: B first/sel 0, A second/sel 1), raw expansion
  for the virtual group. Proves the derivation AND the ordering, not just
  evaluation.
- `test_frame_mode2_matches_the_reference`: same frame vs the independent
  TerminalRef contract.
- `test_mode2_bad_arity_reverts`: k=3 with arity-4 matrices must revert
  BadArity(4, 3) — the PADDED arity in the error, pinning the folding
  floor. Note: `vm.expectRevert` did NOT intercept the caught staticcall
  revert here (it did for the argless errors in the same file); pinned the
  revert data manually via keccak of `abi.encodeWithSelector` instead.
  Lesson: on staticcall-caught reverts, compare bytes directly.

Full suite: **143/143 pass** (140 + 3 new). `cargo fmt` gate fixed.
check.sh re-running; step C is complete end-to-end: impl + e2e + parity +
gate. Next: Step D (pruned-frontier Merkle paths).



---

## Batch 12 — Step D measurement (frontier savings) + pivot to D-092

Step C committed: `1936c24 feat(d086): derive terminal eq groups from the
public statement (mode 2)`. Full gate green (143/143, check.sh ALL PASSED).

Measured the ACTUAL path bytes in the v5 bundle (composed_flat.json):
rounds ship 246-262 paths each, 3,849-5,367 nodes, total 23,495 nodes =
**752 KB** of Merkle paths (paths_hex per round: 123/172/147/163/147 KB).

Pruned-frontier estimate (ancestors-union per tree, random-index model):
a depth-16 tree with 160 queries ships 160x16 = 2,560 nodes but needs
~2+4+...+128 + 8x160 = ~1,534 frontier nodes: ~40% saving at that shape,
~30% at depth 21/182 queries. Realistic total: **~250-300 KB wire, ~7-8M
gas** - LESS than the earlier -700 KB guess (that assumed more sharing than
random indices give). Exact pairing of paths to query indices requires the
Rust structures (flat JSON groups differ: 183 paths of depth 16 vs 160
queries - some queries open two matrices), so the precise frontier must be
computed in the export, not offline.

DECISION: Step D stays queued (worth ~7M gas, medium risk: encoder +
verifier + vectors all move). The goal names D-092 explicitly - the
RECURSIVE 300 KB proof and a redesigned verifier BESIDE the existing one -
so D-092 Phase 1 goes first: recursion proof -> WBND sidecar -> size +
verifier-cost measurement. Steps D/B then apply to the recursive shape
where the same levers are cheaper to land (new library, no migration).



---

## Batch 13 — Can the EXISTING verifier verify the recursive proof? (user question)

Answer: mechanically yes (with a schedule regen + statement rebind), but it
CANNOT land as a settlement tx - and the numbers are now measured, not
estimated.

**Protocol compatibility (the key finding).** The earlier "SemConfig !=
whir::Config, must bridge" note was about RUST TYPES, not wire bytes:
- whir::Config (recursion settle): KoalaBear + BinomialExt4 +
  SerializingChallenger32(HashChallenger Keccak256) [whir.rs:70-89]
- SemConfig (composed path): KoalaBear + BinomialExt4 + SemChallenger =
  the SAME SerializingChallenger32(HashChallenger Keccak256) wrapped in a
  recording sink [settlement_replay.rs:79-89]
Byte streams identical -> the existing verifier's transcript, ext-field
arithmetic (4-limb packing), sumcheck and STIR machinery apply UNCHANGED
to the recursive proof. The WBND encoder is already shape-generic (cfg
carries the schedule).

**Measured sizes (recursion_bench rerun, BASE_TRACE=1024):**
- layer-1 settle proof: **677,572 B postcard** (~10.8M gas calldata alone)
- base proof 130,802 B; settle prove 2.0 s; settle verify 9 ms
- the ~300 KB figure is the LAYER-N convergence (332->302->300 KB), not
  layer 1.

**Gas reality:** at today's ~155 gas/byte: 300 KB -> ~47M (over the
~30-36M block gas limit); 677 KB -> ~105M. So the existing verifier can
verify the recursive proof in a FOUNDRY TEST (foundry's gas cap is high)
but it cannot settle on mainnet. That is exactly the D-092 thesis: the
C/D/B levers + gas queue are what close 47M -> <=30M.

**What running it through the existing verifier actually needs:**
1. recursion_export.rs: flatten layer-N BatchStarkProof<whir::Config> ->
   flat sidecar -> encode_bundle (encoder shape-generic; needs the walk
   instrumentation - composed_export drives verify_whir_round via a replay
   delegate inside the prover; the recursion path needs the same, or a
   SemChallenger swap-in since bytes are identical).
2. Regenerated WhirFixedConfig for the recursion schedule (log_max_lde 22
   vs 25: NUM_VARIABLES, round table, grind bits all differ).
3. Statement rebind: recursion public inputs = D-088 folded root; absorb
   in the prover's order; verifier checks root == expected(block).
4. OPEN QUESTION: does the recursion AIR fit the mode-2 constraint-identity
   shape (statement-derived eq groups), or does the terminal layer need a
   mode 3? The recursion AIR's constants (Poseidon2 round constants) are
   much larger than the composed AIR's - step B satellites matter more here.

DECISION: yes - do this NOW as Phase 1 (it was already the plan's next
step). It validates wire + core on the real recursion shape and produces
the exact gas number the redesign must beat. The redesigned library beside
the existing one then targets <=30M on the SAME vectors.



---

## Batch 14 — MILESTONE M1 recorded: recursive proof through the EXISTING verifier

**M1 (D-092 Phase 1a).** Run a real RECURSIVE proof through the existing
Solidity verifier and measure it. Steps:
1. Build the layer chain to convergence (base -> rc1 -> settle -> rc2 -> ...
   until the proof size stops shrinking; expect ~300 KB postcard).
2. Export layer-N through the EXISTING composed export path - composed_run_with
   is generic over RecursionCircuit, so it should take the layer-N rc unchanged.
3. Regenerate WhirFixedConfig for the layer-N schedule (fixed_config.rs
   generator, --ignored test).
4. Foundry test: existing WhirVerifier verifies the real layer-N bundle;
   reject battery (wrong statement, truncated).
5. Record the gas number. PREDICTION (batch 13): ~40-80M - the number the
   beside-sitting redesign must beat to <=30M.

Structural findings this span (grounding M1):
- The composed bundle IS already a recursive proof: composed_run ->
  fib_recursion() -> settle_sem_for(rc) settles the RECURSION circuit under
  SemConfig, whose challenger bytes are identical to whir::Config's Keccak
  challenger. So "verify a recursive proof" is not new machinery - it is the
  SAME machinery at a different rc.
- Flat/postcard ratio measured: 1.19 MB WBND vs 677,572 B postcard for the
  same layer-1 shape = 1.76x. A 300 KB postcard layer-N proof therefore
  lands ~530 KB flat -> ~82M gas at today's 155 gas/B. The 47M estimate in
  the proposal assumed 300 KB FLAT; the honest number is worse, which makes
  the redesign case STRONGER, not weaker.
- Chain typing: intermediate layers must settle under InnerWhirConfig
  (Poseidon2 InSC) because build_batch_recursion_circuit verifies
  BatchStarkProof<InnerWhirConfig>; only the LAST layer settles under the
  Keccak config. settle_recursion_circuit hardcodes whir::config -> needs a
  generic settle_recursion_circuit_with(rc, config) variant (small refactor;
  check whether the AIR builders are config-generic or whir::Config-keyed).
- No existing 2-layer chain in the tree (build_batch_recursion_circuit is
  used only by transfer.rs, one layer). The 332->302->300 KB convergence
  number needs re-measuring in-tree as part of step 1.

Course correction vs the proposal: Phase 1 originally said "new
recursion_export.rs". CORRECTED: no new export module needed - the export
path is already generic over the circuit; what is missing is the InSC-settle
variant + the chain harness + the schedule regen. Smaller diff than planned.



### M1 execution log (running)

- settle_recursion_circuit_with<SC> landed (whir_recursion.rs): generic over
  SC with the transfer.rs bound pattern + one extra pin the compiler forced:
  Domain::Val = F (preprocessors are keyed on the DOMAIN value type, not
  Val<SC>). settle_recursion_circuit is now a 2-line wrapper. cargo check
  green.
- New ignored test recursion_chain.rs: base fib -> rc1 -> 4x (InSC settle +
  recurse) -> final Keccak settle, printing postcard size per layer.
- First run FAILED at layer 2: PowBitsExceedBudget { required: 19, budget: 18 }
  at InnerWhirConfig::new(LOG_MAX_LDE=22) - the recursion circuit's own trace
  (Poseidon2 rows for the inner proof's Merkle paths) needs arity 23+ once
  the inner proof is itself a recursion proof. Raised chain to LDE 24
  (KoalaBear TWO_ADICITY 24 ceiling; grind budget 24+2-slack... watch for the
  same error at 24 - if it recurs the chain needs the tuned schedule, not a
  bigger LDE).
- Layer sizes so far: base 131,090 B -> layer-1 InSC settle 676,195 B (x5.16).
  The recursion proof is BIGGER than what it proves - convergence to ~300 KB
  needs the fan-in/log_blowup tuned schedule from issues/16, not the default
  protocol_params. If the chain doesn't converge at defaults, M1 measures the
  DEFAULT-schedule size honestly and the tuning becomes an explicit sub-step.
- Verifier schedule source confirmed: the bundle CONFIG carries the schedule
  (WhirFixedConfig.sol is only referenced for FINAL_FOLDING_FACTOR=4, same
  for the recursion shape) - so NO schedule regen is needed to verify a
  recursion-shape bundle; the cfg blob carries it. Batch-14 step 3 dropped.



## Batch 15 - M1 step 1 DONE: layer-chain convergence measured (defaults)

recursion_chain.rs (ignored test, LDE 24, base fib 1024 rows):

    layer 0 (base fib proof)      127,968 B
    layer 1 (InSC settle)         664,996 B  (x5.197)
    layer 2 (InSC settle)         762,311 B  (x1.146)
    layer 3 (InSC settle)         765,767 B  (x1.005)
    layer 4 (InSC settle)         766,151 B  (x1.001)
    final   (Keccak settle)       762,823 B  (x0.996)

HONEST FINDING: with the production schedule (KoalaBear, BinomialExt D=4,
folding 4, rate 1/2, JohnsonBound, min grind) the chain does NOT converge to
300 KB - it plateaus at ~766 KB postcard. The 332->302->300 KB figure in
map.md/issues-16 was measured on the OTHER config (D=5 quintic, log_blowup 2
= rate 1/4) and does not transfer. Correcting the record: the recursion
target for the beside-sitting verifier is a ~766 KB postcard proof, i.e.
~1.35 MB flat at the 1.76x ratio, ~210M gas at today's 155 gas/B for the
EXISTING verifier - not the ~82M estimate (which assumed 300 KB).

Why the plateau sits there: rate 1/2 + folding 4 + 109-bit JohnsonBound
ceiling forces ~182 queries; the recursion circuit's own trace is dominated
by the in-circuit Merkle gadget rows of the proof it re-verifies, so each
layer re-commits roughly the same volume. The tuning lever that moved the
old measurement was log_inv_rate 2 (rate 1/4): fewer queries per bit at the
cost of a bigger LDE. Whether to adopt it is a schedule decision (soundness
is schedule-computed either way; it is a proof-size/LDE tradeoff), recorded
as an open knob, NOT applied silently.

Also proven by the run: statement binding survives the whole chain (final
Keccak verifier accepts only the original pis, rejects fib+1), and the
generic settle works under both InnerWhirConfig and Keccak Config.



## Batch 16 - M1 DONE: existing verifier on the real recursion proof

recursion_chain.rs export_chain_bundle wrote recursion_chain_bundle.bin
(WBND v5, 1,228,244 B flat) for the 2-layer chain (base fib -> rc1 -> 2x
InSC settle+recurse -> Keccak settle), statement [0, 1, fib(1024)=377841674].
contracts/test/RecursionChainE2E.t.sol runs the existing WhirVerifier on it
with ZERO verifier changes - batch 14's wire-compatibility prediction holds
end to end:

    test_real_recursion_chain_verifies   PASS   175,396,812 gas
    test_rejects_wrong_statement         PASS    26,621,625 gas (reverts at stmt check)
    test_rejects_tampered_proof          PASS    43,185,902 gas (reverts mid-walk)
    test_rejects_truncated_proof         PASS   166,634,964 gas (reverts at section table)

THE M1 NUMBER: 175.4M gas. ~5.8x over the 21M/30M targets, ~5x over a
mainnet block. Flat/postcard ratio here 1.81x (1,228,244 / 762,311 - close
to the 1.76x measured on the block shape). Effective rate ~143 gas/B.

Redesign budget breakdown implied (to reach <=30M from 175M):
- calldata alone: 1.23 MB x 16 gas/B non-zero ~= 19.6M (with ~65% zeros at
  4 gas/B: ~12-15M). So even a FREE compute verifier is ~15M on this wire -
  the wire itself must shrink (Step D pruned paths + Step B cfg satellites
  + possibly rate-1/4 schedule) AND compute must drop.
- compute today ~= 175M - ~15M calldata ~= 160M: dominated by the assembly
  Merkle walk over ~182 queries x 5 rounds and the sumcheck absorb loop.
  The gas queue (assembly walk -4.5M, absorb batching -8M...) was sized for
  the 1.19 MB block shape; the recursion shape has MORE rounds of similar
  size, so the same levers apply at ~1.4x scale.

Course note: M1 proves the pipeline works end-to-end TODAY (no verifier
fork needed to verify recursion proofs) and prices the gap honestly.
D-092 Phase 2 (beside-sitting redesign) now has its baseline: beat 175.4M
to <=30M on these exact vectors.



## Batch 17 - D-092 Phase 2 plan (beside-sitting verifier), anchored on M1

Baseline to beat: 175.4M gas on recursion_chain_bundle.bin (1,228,244 B).
Decomposition of the 175M (measured + estimated):
  calldata ~19.6M worst case (1.23 MB x 16 gas/B; ~40% zeros -> ~13M real)
  compute  ~155-160M: 5 rounds x ~182 queries x (Merkle walk + fold) +
           sumcheck absorbs (24+499+128+188+200 groups) + transcript replays.

Phase 2 attack plan (each step measured against the SAME vectors):
 P2a WIRE SHRINK (biggest lever, verifier-agnostic):
   - Step D pruned-frontier paths: paths_hex is 751,840 B of the 1.23 MB;
     frontier pruning measured -30..40% on the block shape -> -250..300 KB.
     Exact frontier must be computed in the Rust export (offline attempt
     failed: some queries open two matrices, batch 13 note).
   - Step B cfg satellites: CONFIG section carries the schedule + Poseidon2
     round constants; recursion shape's cfg is bigger than the block's.
     Chunked code satellites (<=24,576 B each, constructor-pinned) move it
     out of calldata entirely: -calldata 16 gas/B, +deploy once.
   - Schedule knob (rate 1/4 via round_log_inv_rates): halves query count
     (~91 instead of ~182) at +1 LDE bit per layer. Soundness is
     schedule-computed either way; needs the chain to fit LDE 24 at rate 1/4
     (25 would exceed KoalaBear capacity with grind). TEST, don't assume.
 P2b COMPUTE (new library beside the existing one, same wire):
   - assembly Merkle walk (StarkMkle.sol today: ~4.5M on block shape)
   - sumcheck absorb batching (-8M class)
   - mode-2 constraint identity ALREADY WORKS on the recursion shape - the
     M1 export ran through settlement_bundle (constraint identity + mode-2
     frames) and the existing verifier consumed it. No mode 3 needed.
 Target arithmetic: wire 1.23 MB -> ~0.6 MB (D+B) = ~8M calldata; compute
 155M -> ~20M needs the walk+absorb+batching levers at recursion scale.
 30M is plausible but tight; rate-1/4 is the lever that makes it if compute
 doesn't fall far enough (halves both walk and fold work).

Order of work: Step D (Rust export + Solidity walk) -> re-measure -> Step B
-> re-measure -> schedule experiment -> P2b compute library. Each step
lands with a gas number in this file.



## Batch 18 - Step D frontier analysis + schedule experiment plan

Frontier math on the block vectors (offline, /tmp/frontier3.py):
- paths_hex is 751,840 B = 61% of the 1.23 MB recursion bundle - THE wire.
- Query indices are all distinct (262/275 per round) but path counts are
  246/262 and path depths vary per matrix ([14,15,16] round 0): the walk
  opens TWO matrices per round and the query->(matrix,path) pairing is NOT
  recoverable offline. Confirmed twice now: the frontier MUST be computed
  inside whir_walk.rs where dims/indices/proof are in scope.
- Key realization: the prover's MerkleProof IS already a pruned multiproof
  (restore_and_recompute_paths expands it). Step D ships the PRUNED form:
  per depth a node list + skip counts (p3 MerkleProof.layers format), and
  the Solidity walk rebuilds the (depth, sibling-index) -> node map from
  the query indices it already derives from the transcript. Same roots,
  fewer bytes AND fewer hashes (shared segments hash once).

Schedule experiment (cheapest possible big lever, test before building):
- protocol_params round_log_inv_rates is empty = rate 1/2 everywhere. Rate
  1/4 (log_inv_rate 2) roughly HALVES the query count (each query buys 2
  proximity bits) - halving both the walk compute and most of the wire.
- Risk: recursion circuit trace doubles (4x LDE rows) - the chain needed
  LDE 24 at rate 1/2; if rate 1/4 needs 25 it exceeds KoalaBear TWO_ADICITY
  24 and the lever is dead for the chain (may still work for the block).
- Soundness is schedule-computed either way (JohnsonBound ceiling ~109 bits
  at rate 1/2; rate 1/4 list size ~5.8 bits, ceiling still >100). Not a
  security downgrade - a proof-size/LDE tradeoff the solver enforces.
- Experiment: rerun recursion_chain with round_log_inv_rates = vec![2; ...]
  on BOTH configs, print sizes + whether LDE 24 still settles.


---

## Batch 19 — proof-size sweep: what the 1.23 MB is made of, and which WHIR knobs move it

**The wire anatomy of the recursion-chain bundle (1,228,244 B WBND, flat 1,226,997 B):**

| section | bytes | share |
|---|---|---|
| PROOF paths_hex (5 rounds) | 795,675 | 64.8% |
| PROOF rows_flat | 146,560 | 11.9% |
| CONFIG (schedule + constraints) | 182,444 | 14.9% |
| PROOF final_paths_hex | 34,459 | 2.8% |
| PROOF final_rows_ext | 16,128 | 1.3% |
| STATEMENT | 3,072 | 0.25% |
| everything else | ~50,000 | 4% |

Inside CONFIG: ~154 KB is CONSTRAINTS (eq_points — the terminal weight
circuits), ~28 KB framing_hex, 492 B batch config. The schedule itself is
tiny. So the wire is: **paths (65%) + terminal-weight constraints (13%) +
rows (13%)**.

**Paths = queries x depth x 32 B.** The measured schedule (rate 1/2,
folding 4, JohnsonBound, min grind): first sub-round of EVERY round carries
170 queries at depth 18-23; later sub-rounds 38/22/15. Total ~1,160 paths
per proof. This is why query count is the lever that matters.

**Schedule probe (instant, no proving) — `crates/prover/tests/whir_sweep.rs`**

- Grinding budget is a WEAK lever: at arity 24, pow 23 -> 32 buys only
  245 -> 215 queries (-12%) for 512x prover grind work. pow 48 -> 161
  (-34%) but 2^48 prover work is absurd. The solver already allocates
  queries efficiently; grinding cannot get near the 300 KB target.
- Starting inverse rate is the STRONG lever: rate 2 (quarter-rate) at
  arity 24: 262 -> 148 queries (-44%); rate 3: 108 (-59%). Cost: every
  committed domain doubles (one more arity).
- Folding factor 8 also helps a lot (192 queries at rate 1) but the user
  ruled it out: folding 2-4 is sufficient, and folding 8 would churn the
  Solidity terminal (FINAL_FOLDING_FACTOR=4).
- Soundness ladder in p3-security: UniqueDecoding (proven, weakest radius)
  < JohnsonBound (PROVEN at delta = 1 - sqrt(rho) - eta; current) <
  CapacityBound (conjectured). **Standing instruction: always JohnsonBound.**

**Correction to batch 18: rate 2 is NOT "dead for the final layer".**
The claim assumed the final layer must keep the CURRENT recursion-circuit
size at LDE 24: arity 24 + rate 2 = 25 > KoalaBear TWO_ADICITY 24. But
arity is not fixed: (a) a smaller base trace shrinks the recursion circuit
(the circuit re-verifies the inner proof; its trace height tracks the
inner proof size, not the base trace directly), and (b) inner layers at
rate 2 produce SMALLER inner proofs (fewer queries -> shorter paths ->
fewer Poseidon2 rows in the circuit that verifies them), which shrinks the
final circuit below 2^23 rows and leaves room for rate 2 at the final
layer. The ceiling is on the FINAL circuit only; inner layers at rate 2
need their own +1 arity but their circuits are smaller. Empirical sweep
running: `crates/prover/tests/chain_sweep.rs` (env-driven: WHIR_BASE_TRACE,
WHIR_LDE, WHIR_RATE_INNER, WHIR_RATE_FINAL), grid base {64,256,1024} x
rate_inner {1,2} x rate_final {1,2}, results in /tmp/sweep_results.log.

**New API surface (all JohnsonBound, folding 4 unchanged):**
- `whir_recursion::protocol_params_with(pow_bits, starting_log_inv_rate)`
- `whir_recursion::required_pow_bits_with(num_variables, rate)`
- `InnerWhirConfig::new_with(log_max_lde, cap_height, rate)`
- `whir::config_with(cap_height, num_variables, rate)`
- `whir::required_pow_bits_with(num_variables, rate)`
Existing constructors delegate with rate 1 — no behavior change anywhere.

**Next levers after the grid:**
1. Cap height (currently 0): cap_height h shortens EVERY path by h levels
   for 2^h field elements of extra commitment per matrix per layer. At
   ~1,160 paths x 32 B, h=2 saves ~150 KB for ~24 KB. Need to check the
   recursion engine supports cap openings (mmcs.rs says cap_height=0 is
   the single-element cap case — the generic path exists).
2. Step D pruned multiproof (frontier): the paths are already a pruned
   multiproof on the prover side but emitted expanded; the frontier
   encoding removes shared internal nodes — orthogonal to all of the above.
3. CONFIG constraints section (154 KB): the eq_points for the terminal
   weights are schedule-derived; if the redesigned verifier computes them
   instead of reading them, they leave the wire entirely.

---

## Batch 20 — chain grid results: rate 2 is live at EVERY layer (the "dead" claim was wrong)

`crates/prover/tests/chain_sweep.rs` (env: WHIR_BASE_TRACE, WHIR_LDE,
WHIR_RATE_INNER, WHIR_RATE_FINAL, WHIR_LAYERS, WHIR_CAP), 2 InSC layers +
Keccak final, all JohnsonBound, folding 4. Final postcard bytes:

| base | rate_inner | rate_final | layer1 | layer2 | final | vs baseline |
|---|---|---|---|---|---|---|
| 1024 | 1 | 1 | 664,932 | 764,519 | **764,167** | baseline |
| 1024 | 1 | 2 | 665,988 | 765,351 | **527,822** | −31% |
| 1024 | 2 | 1 | 425,497 | 505,038 | 727,879 | −5% |
| 1024 | 2 | 2 | 423,513 | 503,854 | **503,598** | **−34%** |
| 256 | 2 | 1 | — | — | 729,319 | −5% |
| 256 | 2 | 2 | 423,481 | 505,006 | **503,022** | −34% |

**Why rate 2 at the final layer works (correction of batch 18):**
`config_with(cap, lde, rate)` sizes the schedule via
`required_pow_bits_with(lde + ZK_ARITY_SLACK, rate)`, which BACKS OFF the
arity until the schedule builds. The arity that matters is the one the
FINAL circuit actually needs (rc trace x blinding x rate), not the
configured budget of 24. With rate 2 the final settle ran at the backed-off
arity under TWO_ADICITY 24 and verified + tamper-checked. The ceiling only
bites when (circuit arity + 1 + rate) > 24 — and shrinking the circuit
(smaller inner proofs) buys rate headroom back. Exactly the user point:
circuit minimisation and final-layer parameters interact.

**New in-circuit constraint discovered (base=256, rate_inner=1):**
`rc1: InvalidProofShape("final phase: num_queries (177) >=
folded_domain_size (128); saturating STIR query counts are not yet
supported in-circuit")`. When the inner proof is small, its folded domain
can fall BELOW its query count and the recursion circuit refuses it. So
the base trace cannot be shrunk arbitrarily at rate 1 — rate 2 fixes it
here (fewer queries, bigger domain). Rule of thumb: keep inner schedules
at num_queries < folded_domain_size at every layer.

**base=64 fails at the base prove**: HidingBudgetExceeded (mask_height 128
vs 64x2 domain) — HVZK blinding needs trace >= 128 rows. Floor for the
base trace is ~128-256 rows for this AIR.

**Interim best: rate_inner=2 + rate_final=2 at 503 KB postcard (−34%).**
Grid 2 running: WHIR_CAP {2,4} (shortens every path by cap levels; the
recursion engine multiplexes cap entries in-circuit —
vendor/p3-recursion mmcs.rs verify_batch_circuit), rate 3 (probe said 108
queries at arity 24), base 512. Postcard is the chain metric; the WBND
flat/bundle size for the winning config gets measured next (the on-chain
number is the bundle, ~1.6-1.8x postcard today).

---

## Batch 21 — grid 2: rate 3 reaches 422 KB; cap height is dead in the WHIR path

chain_sweep grid 2 (2 InSC layers + Keccak final, base 1024 unless noted):

| rate_inner | rate_final | cap | final postcard | vs baseline |
|---|---|---|---|---|
| 2 | 2 | 0 | 503,598 | −34% |
| 2 | 3 | 0 | **423,089** | **−45%** |
| 3 | 3 | 0 | **422,545** | **−45%** |
| 2 | 2 | 2 | FAIL: rc1 "Not enough op_ids for the restored WHIR Merkle paths" | — |
| 2 | 2 | 4 | FAIL (same) | — |
| 2 | 1 | 2 | FAIL (same) | — |
| 512 base, 2/2 | 502,862 | −34% (base size barely matters once rate dominates) |
| 512 base, 2/3 | 423,313 | −45% |

**Cap height: dead for now.** The generic cap circuit exists in
vendor/p3-recursion/recursion/src/pcs/mmcs.rs (select_cap_entry,
path_depth = max_height_log − cap_height) but the WHIR uni path that
builds the recursion circuit cannot consume a capped opening: rc1 fails
with "Not enough op_ids for the restored WHIR Merkle paths". Wiring cap
height through the WHIR uni recursion path is a vendor change — parked.

**Rate 3 works at both layers** (422 KB, −45%): the arity back-off in
required_pow_bits_with absorbs the extra arity, and the final circuit
still fits under TWO_ADICITY 24. Rate 4 would need arity +2 again; the
probe said it stays feasible at arity 24 (queries 88 at fold 4) but the
circuit ceiling is the question — test next.

**Base trace size is a weak lever** (1024 vs 512 vs 256: ±1% on the
final) once rate dominates: the recursion circuit size is driven by the
inner PROOF size (paths), not the base trace. Floor: base >= 128 rows
(HidingBudgetExceeded below that: mask_height 128).

**Rate plumbing now threaded through the composed export path** so the
WBND bundle can be generated at any rate:
- settlement_replay: settlement_params_for(lde, rate), sem_config_for(+rate),
  settle_sem_for(+rate), one_run_for(+rate) — all default call sites pass 1.
- composed_export: composed_run_with(+rate), settlement_bundle_with_blob(+rate);
  settlement_bundle (node path) delegates at rate 1.
- recursion_chain export test: WHIR_RATE_INNER / WHIR_RATE_FINAL env,
  **defaults now 2/2** — the winning config is the default shape.

Next: regenerate the WBND bundle at 2/2, measure flat size + gas on the
existing verifier, then iterate toward 300 KB (rate 3/3, then per-round
gas decomposition to see what the shrink did to compute).

---

## Batch 22 — rate 2/2 on the wire: 847 KB bundle, 135.8M gas; what is left

Regenerated recursion_chain vectors at rate_inner=2, rate_final=2
(the export test now defaults to 2/2). Committed 68fa622.

| metric | rate 1/1 | rate 2/2 | delta |
|---|---|---|---|
| WBND bundle | 1,228,244 B | **847,572 B** | −31% |
| PROOF section | 1,042,708 B | 662,036 B | −37% |
| paths_hex | 795,675 B | 463,515 B | −42% |
| rows_flat | 146,560 B | 103,936 B | −29% |
| final_paths_hex | 34,459 B | 32,155 B | −7% |
| CONFIG | 182,444 B | 182,444 B | 0% |
| gas (existing verifier) | 175,396,812 | **135,783,102** | −23% |
| reject battery | 26.6/43.2/166.6M | 12.8/18.9/109.5M | all reject |

**The CONFIG (182 KB) did not move** — it is schedule-independent
(constraints/eq_points 154 KB + framing 88 KB... wait, framing is in
CONFIG too: 87,688 B framing_hex + ~101 KB eq_points + claim perms).
At rate 2/2 the CONFIG is now 21.5% of the bundle: the second-largest
section after paths. Two follow-ups:
1. framing_hex (88 KB) is the per-round transcript framing preimages -
   fixed constants the verifier could REGENERATE from the schedule
   instead of reading (the WhirComposed harness already regenerates
   absorbs from fixed constants; same trick applies).
2. eq_points (101 KB) are the terminal-weight equality constraints;
   schedule-derived, same regeneration argument.
Together ~150 KB of the CONFIG is regenerable = ~18% of the wire with
zero parameter risk. This is a wire-format (v6) change, not a parameter
change - it belongs to the redesigned verifier sitting beside the old one.

**Gas decomposition sanity**: 135.8M on 847 KB = 160 gas/B (was 143):
gas fell slower than bytes because per-query compute (sumcheck folds,
constraint weights) did not shrink as fast as paths. The wire is still
the dominant cost: 847 KB x 16 calldata gas/B = 13.6M base + ~122M
compute. Compute reduction is the redesigned verifier job (P2b); the
parameter job is done when paths stop shrinking.

**Iteration budget (user rule: stop after 5 non-improving iterations).**
Iterations so far: (1) rate 2/2: −31% wire, −23% gas. (2) rate 3/3:
−45% postcard in the sweep; bundle export running. (3) rate 4/4 probe
running. (4) layers {0,1} x rate grid running - fewer layers may shrink
the final proof further (the plateau at 4 layers was a rate-1 fact).
Next levers after the grid: v6 wire (regenerate framing/eq_points),
Step D pruned paths (orthogonal, −250 KB class at rate 1).

---

## Batch 23 — full parameter grid: the plateau is ~356 KB postcard (−53%)

chain_sweep grid 3 (base 1024, LDE 24, JohnsonBound, folding 4):

| layers | rate_in | rate_fin | final postcard | vs 764 KB baseline |
|---|---|---|---|---|
| 2 | 2 | 2 | 503,598 | −34% |
| 2 | 2 | 3 | 423,089 | −45% |
| 2 | 3 | 3 | 422,545 | −45% |
| 1 | 2 | 2 | 503,022 | −34% |
| 1 | 3 | 3 | 421,297 | −45% |
| 0 | 2 | 2 | 425,209 | −44% |
| 0 | 3 | 3 | **356,528** | **−53%** |
| 1 | 4 | 4 | 357,857 | −53% |
| 2 | 4 | 4 | **356,545** | **−53%** |

**The plateau is ~356 KB and layer-count-independent at rate 4.** Once
the inner proofs are small (rate >= 3), adding recursion layers stops
costing anything: the final proof is dominated by the FINAL layer schedule
(its own queries x depth), not by the circuit it verifies. layers=0
(one recursion level, the honest minimal rollup shape) matches layers=2
to the byte. Rate 5 probe running; rate 4 already at the floor where
queries x depth stops shrinking (terminal folded domain is the limit).

**WBND bundle sizes (the on-chain wire):**
- rate 2/2: 847,572 B (−31%), gas 135.8M (−23%)
- rate 3/3: 718,772 B (−41.5%), gas pending
- rate 4/4: exporting now

**Why the bundle plateaus above the postcard**: CONFIG is 182 KB of
schedule-independent constants (framing_hex 88 KB + eq_points 101 KB +
claim perms) that no parameter touches. 356 KB postcard + CONFIG + flat
encoding overhead = ~650 KB bundle at best from parameters alone. The
last ~350 KB to the 300 KB target is wire-format work (v6: regenerate
framing + eq_points from the schedule on-chain; Step D pruned paths),
not parameter work. Parameters delivered −53%; the remaining levers are
orthogonal and belong to the redesigned verifier.

**Iteration ledger (user rule: stop after 5 non-improving):**
1. rate 2/2: −31% wire −23% gas (improve)
2. rate 3/3: −41.5% wire (improve)
3. rate 4/4: −53% postcard, bundle pending (improve)
4. rate 5/5: probing
5. layers 0-2 at best rate: no further change (plateau) -> STOP
   parameter iteration after this one; move to wire-format work.

---

## Batch 24 — parameter phase CONVERGED at rate 4/4: 627 KB bundle, 113.8M gas

| metric | rate 1/1 (M1) | rate 4/4 | delta |
|---|---|---|---|
| WBND bundle | 1,228,244 B | **627,136 B** | **−49%** |
| PROOF section | 1,042,708 B | 441,844 B | −58% |
| paths_hex | 795,675 B | 280,475 B | −65% |
| CONFIG | 182,444 B | 182,200 B | 0% |
| gas (existing verifier) | 175,396,812 | **113,754,344** | **−35%** |
| rejects | 26.6/43.2/166.6M | 7.1/8.3/78.6M | all reject |

**Iteration ledger (5 done, last 2 non-improving -> STOP per user rule):**
1. rate 2/2: bundle −31%, gas −23%
2. rate 3/3: bundle −41.5%
3. rate 4/4: bundle −49%, gas −35% (356 KB postcard plateau)
4. rate 5/5: PANIC in vendor p3-recursion whir/uni/pcs.rs:443 — dead
5. layers {0,1,2} at rate 4: 356-358 KB, no change — plateau confirmed

**Rate-4 wire anatomy (627 KB):** paths 280 KB (45%), eq_points 97 KB
(16%), framing_hex 87 KB (14%), rows_flat 67 KB (11%), final_paths 32 KB,
final_rows 14 KB, rest ~50 KB. CONFIG is now 29% of the wire.

**Step D re-measured at rate 4** (/tmp/dedup_r4.py): expanded 8,765
siblings vs pruned 6,894 = −21% = −60 KB (was −250 KB at rate 1: fewer
queries, less sharing to exploit). Still worth it, but the CONFIG
regeneration levers are bigger: framing_hex (87 KB) + eq_points (97 KB)
= 184 KB (29%) of schedule-derived constants the redesigned verifier can
compute instead of read. Together with Step D: 627 − 60 − 184 ≈ 383 KB.
The last stretch to 300 KB needs rows compression (67 KB rows_flat is
already raw field elements; the STATEMENT 3 KB is minimal) or one more
rate notch if the vendor ever fixes rate 5. Honest assessment: ~380 KB
is the realistic v6 floor; 300 KB needs the vendor path or a smaller
terminal schedule.

**Moving to the next task (per user rule): the redesigned verifier**
(D-092 Phase 2) sitting BESIDE the existing one, consuming a v6 wire:
- contracts/src/verifier2/ (new library, existing one untouched)
- v6 wire: framing + eq_points regenerated from schedule (prover emits
  schedule params only), Step D pruned paths (per-depth node lists)
- P2b compute: assembly Merkle walk, sumcheck absorb batching
- statement rebind to the D-088 folded root

---

## Batch 25 — why 356 KB postcard becomes 627 KB on chain; v6 wire plan

User question: the sweep says the final proof is 356 KB, why does the
bundle submitted on chain weigh 627 KB? Full accounting (rate 4/4):

| part | bytes | what it is |
|---|---|---|
| postcard proof | 356,545 | the WHIR proof itself |
| PROOF section | 441,844 | postcard + 85 KB flat-encoding overhead (fixed u32 words vs varints, length prefixes) |
| CONFIG section | 182,200 | framing_hex ~87 KB + CONSTRAINTS node programs ~88 KB + schedules/batch cfg ~7 KB |
| header + STATEMENT | ~3.1 KB | |
| **bundle** | **627,136** | |

**The CONFIG is the bug.** WhirVerifier.sol:24-26 says it outright: "CONFIG
is deploy-time data... A deployment should pin keccak256(configSection)".
Yet every proof carries it: 182 KB x 16 gas/B = ~2.9M gas of calldata +
decode per verify, for bytes that are FIXED per circuit shape (framing
labels, AIR node programs, schedule tables). Nothing in CONFIG depends
on the proof: eq_points are zeta-derived and live in PROOF (D-072), the
framing is AIR+schedule derived, the CONSTRAINTS programs are the AIR.

**v6 wire (fix):** CONFIG moves to the verifier constructor (storage,
keccak-pinned immutable). Bundle v6 = header (ver 6, cfgWords=0) + PROOF
+ stmLen + STATEMENT - identical grammar otherwise, so the parser diff is
tiny: version check + CONFIG source (storage -> memory copy once at verify
start, ~63k gas) + the three CONFIG decoders switch from calldata readers
to memory readers. ConstraintIdentity.Program already supports memory
node words (the JSON test path); v6 uses it. v5 stays supported.

Expected: on-chain proof 627 KB -> ~445 KB (-29%), gas -~2.5M.
To actually reach 300 KB on chain the PROOF section must also shrink:
85 KB flat-encoding overhead (varint packing) + Step D pruned paths
(-60 KB) -> ~300-325 KB. That is the redesigned verifier job (next task).

Vendor note: CONFIG-in-proof was inherited from the v3 wire design; the
node settlement path (composed_export::settlement_bundle) emits v5 and
keeps working; the v6 export is additive.

---

## Batch 26 — the +85 KB flat expansion, itemized (rate 4/4 bundle)

PROOF section 441,844 B vs postcard 356,545 B = +85,299 B. Measured
(/tmp/flat_gap.py, sums to +82,078 of the +85,299; remainder is batch
block framing):

| item | flat wire | postcard | delta | why |
|---|---|---|---|---|
| Merkle paths | 312,864 | 246,944 | **+65,920** | flat carries one EXPANDED path per query (shared siblings repeated); postcard stores a PRUNED multiproof (each shared node once) |
| extension arrays | 45,472 | 16,281 | **+29,191** | flat packs each ext4 element as a 32-byte word (limbs at bits 224/192/160/128); postcard varints each <2^31 limb (1-4 B) |
| u32 arrays | 88,472 | ~102,325 | −13,853 | flat is already lean here (4 B/elem; my postcard estimate over-counts - real postcard uses fixed u32 for field elements) |
| length prefixes | ~820 | 0 | +820 | every flat array carries a u32 count |

**Yes, the redesign can address all of it.** v6 wire = three changes:
1. CONFIG -> constructor (batch 25): −182,200 B
2. pruned paths (Step D): −65,920 B; the Solidity walk already restores
   paths in Rust (restore_and_recompute_paths); the contract walk takes
   one root + per-query paths, so the pruned form needs a per-depth node
   list + a restore pass on chain (the same node set, deduped)
3. varint ext limbs: −29,191 B; 4 limbs of <2^31 each, varint-packed
   (the decoder is a 10-line loop; limbs are canonical field elements)

Arithmetic: 441,844 − 65,920 − 29,191 = 346,733 PROOF + 16 header +
3,072 STATEMENT = **~350 KB calldata** - exactly the user target: post
the 350 KB proof and nothing else. The remaining gap to the 300 KB
aspiration is the u32-array floor (rows_flat 67 KB is raw field data,
already minimal) and would need a rate-5 vendor fix or smaller terminal
schedule - not wire work.

Gas effect: −182 KB CONFIG (−2.9M calldata − decode) − 95 KB proof bytes
(−1.5M calldata) ≈ −4.5M before the restore-walk cost of pruned paths
(the on-chain restore recomputes ~1,871 internal nodes per proof that
the expanded form skips: ~1,871 x 2 Poseidon2-ish hashes... no - the
walk hashes siblings per level either way; pruned saves the DUPLICATE
hashes too: expanded 8,765 sibling-hashes vs pruned 6,894 node-hashes
+ restore overhead ~neutral). Net gas: expect 113.8M -> ~108M.

---

## Batch 27 — v6 wire implemented (Rust export + Solidity wrapper)

Pieces landed, all beside the existing verifier:

* `wbnd.rs`: `encode_bundle_v6_split(flat, jj, bin) -> (bundle, config)`
  - v5 bundle with the CONFIG section excised, header ver=6, cfgWords=0.
  `header()` and `chunk_config(cfg, max)` helpers. v5 path byte-identical.
* `recursion_chain.rs::export_chain_bundle_v6` (ignored): writes
  `recursion_chain_bundle_v6.bin`, `recursion_chain_config.bin`, 8 x
  `recursion_chain_config_chunk_{i}.bin` (24,471 B each), and
  `recursion_chain_sidecar_v6.json` with the keccak256 CONFIG digest.
  Rate 4/4: **v6 bundle 444,936 B** (v5 627,136; -29%), config 182,200 B.
  Rate 2/2 sanity: config 182,444 B - CONFIG is rate-independent as
  predicted (it is the AIR + schedules, not the proof).
* `ConfigChunk.sol`: two-contract design. A contract cannot reference its
  own runtimeCode (E0 circular reference) and runtimeCode is unavailable
  with immutables - so `ConfigChunk` constructor deploys
  `ConfigChunkBody.runtimeCode ++ data ++ uint32(len)`; the body exposes
  dataLen()/read() via extcodecopy of self. Chunk holds ~24.4 KB of
  CONFIG in CODE: no storage, no SLOAD, deposit paid once at deploy.
* `WhirVerifierV6.sol`: constructor(engine, chunks, configDigest) pins
  keccak256(concat chunks) == digest (the v5 header comment finally
  enforced). verify() checks ver==6 && cfgWords==0, re-frames a v5 bundle
  in memory (header + CONFIG from chunks + verbatim v6 tail) and
  staticcalls the frozen v5 ENGINE. v5 stays ground truth; v6 is a
  wrapper, not a fork.

Expected gas: -182,200 B calldata = -3,644,000 gas (16/byte zero-cost
excluded: these are nonzero bytes: 4 B/byte = -728,800 tx-level) plus
the engine no longer decodes CONFIG from calldata... but the wrapper
pays: chunk reads (8 x ~24 KB extcodecopy+abi) + 627 KB memory re-frame
(~1M) + staticcall of a 627 KB payload (abi encode ~1M). Net on-chain
tx saving is the calldata; internal gas roughly cancels. Phase 2 (direct
extcodecopy CONFIG reads inside the engine) removes the re-frame.

Numbers from RecursionChainV6.t.sol land in the next batch.

---

## Batch 28 — v6 wire green: measured numbers

RecursionChainV6.t.sol (rate 4/4 artifacts):

| | v5 (today) | v6 (wrapper) |
|---|---|---|
| calldata bytes | 627,136 | **444,936** (-29%) |
| EVM gas | 113,753,786 | 119,964,953 |
| tx calldata gas (nonzero 16/byte) | 10,034,176 | 7,118,976 |
| total on-chain cost | ~123.8M | ~127.1M |

The wrapper re-frame (8 chunk reads + 627 KB memory copy + staticcall
abi-encode) costs ~6.2M EVM gas - MORE than the 2.9M calldata saving.
That is expected and is exactly the Phase-2 argument: the re-frame is
wasteful scaffolding. Phase 2 moves CONFIG reads INTO the engine
(extcodecopy per CONFIG field, no re-frame, no double read):
113.8M - 2.9M calldata - ~1M CONFIG decode from calldata + ~0.5M
extcodecopy reads = ~110M, and the same change makes the PROOF-only
compaction (varint ext limbs -29 KB, pruned paths -66 KB) stack on top
without any re-frame penalty: ~350 KB calldata target stays alive.

Bugs fixed on the way (all mine, none in v5):
* version byte read: shr(248) of word 0 reads byte 0; correct is
  shr(248, calldataload(+4)).
* prfWords must be copied VERBATIM (already LE on the wire); re-encoding
  a shr(224) big-endian read as LE double-swaps and yields 3.2 billion.
* ConfigChunk: a contract cannot reference its own runtimeCode, and
  runtimeCode is unavailable with immutables - two-contract design
  (ConfigChunk deploys ConfigChunkBody code ++ data ++ uint32 len).
  Body runtime = 561 B, so chunk payload <= 24,011 B; export chunks at
  24,000 and the test re-chunks config.bin at runtime (digest is over
  the concatenation, so the split is free).
* The prover is NON-deterministic across runs (ZK blinding): a fresh
  export never byte-matches a committed bundle. Differential tests must
  compare a bundle against the vectors from the SAME export run.

Files: ConfigChunk.sol, WhirVerifierV6.sol (src/verifier),
RecursionChainV6.t.sol (test), wbnd.rs encode_bundle_v6_split +
chunk_config + header, recursion_chain.rs export_chain_bundle_v6.
v5 artifacts untouched and still the ground truth.

---

## Batch 29 — v6 committed; PROOF compaction belongs to the Phase-2 engine

v6 wire landed (3dd3eac). The remaining +85 KB PROOF expansion cannot go
through the wrapper: any PROOF-encoding change makes the bundle unreadable
to the v5 engine, so the wrapper would have to decode-and-re-encode the
whole PROOF - more re-frame waste. Both compactions belong in the
redesigned engine (D-092 Phase 2), which reads CONFIG from the satellites
via extcodecopy and the compact PROOF from calldata directly:

* varint ext limbs (-29,191 B): ext_arr becomes a varint stream of the
  four <2^31 limbs per ext element; _extArr grows a 10-line varint loop.
* pruned paths (-65,920 B): one shared node once per depth instead of one
  expanded path per query; StirOpenings.verifyMix walks per-query paths
  today, so the pruned form needs a restore pass (the Rust side already
  does exactly this: restore_and_recompute_paths).
* both together: 444,936 -> ~350 KB calldata, the user target.

Gas reality check for the 30M goal: v6 engine path = 113.8M - 2.9M
calldata - ~1M CONFIG decode + ~0.5M extcodecopy = ~110M; PROOF
compaction adds -1.5M calldata -2.8M duplicate hashes +1M restore =
~107M. The 30M target therefore lives ENTIRELY in the compute side (P2b):
constraint folding, sumcheck evals, and the Merkle walk are ~95% of the
remaining gas. Attribution harness (RecursionChainGasProfile) next.

---

## Batch 30 — gas attribution: the truncation curve is not enough

RecursionChainGasProfile ran: gas-at-revert vs truncated bundle is
NON-MONOTONIC (114M at 20% bytes, 18M at 30%). Reason: calldataload
past the end returns zeros, so the engine does not revert at the cut -
it keeps computing on garbage until some later check fails. The curve
measures "when does garbage fail", not "which phase costs what".

What we DO know about the 113.8M:
* CONFIG decode + calldata: ~3.9M (batches 25/28)
* rows_flat/paths_hex raw reads: ~1.5M (calldata copy is free; reads
  are calldataload)
* Merkle walk: 8,765 sibling hashes (expanded paths). StarkMerkle
  verifyMix hashes per level; at keccak-class cost (~200-300 gas incl.
  loop) that is ~2.5M; at Poseidon2-class (~2,500) ~22M. UNMEASURED.
* ConstraintIdentity fold + SumcheckCore evals + transcript: the rest,
  ~85-105M. UNMEASURED.

The 30M target (4x cut) cannot be planned on guesses. Next step is the
attribution instrument: WhirVerifierProfile.sol BESIDE the verifier -
a copy of verify() with gasleft() snapshots at phase boundaries (batch
decode, per-round decode, per-round StirOpenings walk, per-round
ConstraintIdentity fold, per-round SumcheckCore, terminal satellite
call). Same wire, same vectors, emits the table. That table IS the
Phase-2 optimization plan: every remaining optimization (P2b assembly
Merkle walk, sumcheck batching, folding restructure, pruned-path
restore) gets sized against it before any of it gets written.

Phase-2 consolidated plan (beside-sitting redesign, target <=30M):
1. WhirEngine.sol: reads CONFIG from ConfigChunk satellites via
   extcodecopy (no re-frame, no CONFIG calldata): -3.9M.
2. Compact PROOF: varint ext limbs (-29 KB), pruned paths (-66 KB):
   -1.5M calldata, -2.8M duplicate hashes, +1M restore: ~-3.3M net.
   Bundle: ~350 KB (user target).
3. P2b compute (the 4x): sized by the attribution table from step 0.
4. Statement rebind to the D-088 folded root (removes per-proof
   statement hashing).
5. v5 stays byte-exact ground truth; v6 wrapper stays as the migration
   path; WhirEngine replaces the wrapper when it beats 119.96M.

---

## Batch 31 — THE attribution table (WhirVerifierP fork, rate 4/4)

Instrumented fork of the frozen engine (test/WhirVerifierP.sol +
WhirVerifierCoreP.sol: byte-copies with gasleft() snapshots; threading
via two extra Transcript fields - acc[] + base - so no signature churn
and no stack explosions). verifyProfiled returns the accumulator.

Total verify 113.75M; accounted 103.6M (rest: decode + eq expansion +
misc ~10M). The table, in gas:

| phase | gas | share |
|---|---|---|
| terminal identity (5 rounds: 2.1/30.7/8.5/12.1/11.9M) | **65.3M** | **57%** |
| open+fold Merkle walk (2.5-3.2M x 5) | 14.6M | 13% |
| constraint identity (D-076) | 10.0M | 9% |
| initial phases (0.35-2.7M x 5) | 7.6M | 7% |
| final STIR checks (0.47-1.2M x 5) | 3.4M | 3% |
| round sumchecks (0.12-0.16M x 5) | 0.7M | 0.6% |
| gamma/claim folds | 0.7M | 0.6% |
| batch transcript + decodes | 0.5M | 0.4% |
| closing sumchecks | 0.2M | 0.2% |

Standalone bench: a 773 KB word-copy costs 6.9M - the terminal frame
pack (calldata->memory, once per round, ~773 KB at settlement shape)
is therefore ~5-7M per round: THE single biggest identifiable item,
~30M of the 65.3M. The satellite eval itself is the other ~35M.

The 30M target, honestly:
1. Terminal frame: the verifier EXPANDS eq groups (2^k words per OOD
   point) into memory, copies them into the frame, the satellite re-reads
   them. Hand the satellite the UNIVARIATE POINTS (one word each) and
   let it expand in-place: frame 773 KB -> ~2 KB, copy ~30M -> ~0. The
   expansion compute moves into the satellite (same cost, no copy).
   Estimated: -30M. Biggest single win in the whole redesign.
2. Merkle walk 14.6M: pruned paths (-66 KB wire, -2.8M duplicate
   hashes) + assembly verifyMix: target ~6M. Estimated -8M.
3. Constraint identity 10.0M: batch the per-instance folds; target ~5M.
4. Initial phases 7.6M: mostly sumcheck evals on initial claims;
   target ~4M.
Sum: 113.8 - 30 - 8 - 5 - 3.6 = ~67M, then PROOF compaction (-3M
calldata+hashes) and CONFIG extcodecopy (-3.4M) -> ~60M. The last 2x
to 30M needs the satellite eval itself (35M) restructured - field-op
level work in TerminalWeight, Phase 3.

Corrections to earlier guesses: CONFIG decode was guessed ~3.9M, it is
0.4M (decode is cheap, the wire bytes only cost calldata gas). The
Merkle walk was guessed 2.5-22M, it is 14.6M. The truncation-curve
approach (batch 30) was right to distrust itself.

Files: test/WhirVerifierP.sol, test/WhirVerifierCoreP.sol (generated by
/tmp/gen_profile2.py + /tmp/fix_view2.py), test/RecursionChainAttribution.t.sol.

---

## Batch 32 — the terminal 65.3M is SATELLITE MATH, not the frame copy

Batch 31 guessed the ~773 KB frame copy was ~30M of the 65.3M. WRONG for
this shape. FrameSizeProbe (FrameLogger satellite wrapper; WhirVerifierP
now uses a plain call so the wrapper can record) measures the ACTUAL
recursion-shape frames:

  frame bytes/round: 10112 12096 11520 11520 12160  (total 57,408 B)
  satellite gas/round: 2.11M 30.68M 8.45M 12.05M 11.86M (total 65.15M)

The frame is 57 KB total, not 773 KB - the 773 KB figure is the SETTLEMENT
shape (many more wire groups). At the recursion shape the copy is ~0.5M
total (57 KB x ~9 gas/B), i.e. noise. The 65.15M is the satellite EVAL:
evalConstraintsPoly (per-constraint constraintWeight: the backwards Horner
over selVars + eq groups, each eqEval O(k) field muls) +
evaluate_hypercube(finalPoly, randomness) O(2^k).

Round 1 is the outlier (30.7M vs 8-12M): it carries the widest stacked
tables, so the most eq groups x k coordinates. That is the Phase-2 target,
and it is FIELD-OP work inside WhirGadgets/TerminalWeight, not a wire or
frame change. The frame-redesign idea from batch 31 (ship univariate
points, expand in-satellite) is a SETTLEMENT-shape win, not a recursion
one - it does not move the 30M for D-092.

Where the 30M actually lives (recursion shape, rate 4/4):
  satellite eval (TerminalWeight)   65.1M  <- field-op optimisation
  Merkle walk (open+fold)           14.6M  <- pruned paths + asm
  constraint identity (D-076)       10.0M  <- batch the per-instance folds
  initial phases                     7.6M
  final STIR                         3.4M
  everything else                    ~3M
  ---------------------------------------
  TOTAL                            113.8M

Phase-2 field-op levers for the satellite (to study next):
  * KoalaBearExt4 mul/add: check for lazy reduction / Montgomery batching
    across the Horner chain (the mul(w,gamma) then add pattern is a
    textbook fused-multiply-add candidate).
  * eqEval recomputes eq(p,q) per group from scratch; groups share localR,
    so a shared precompute of the (1 - p_i) / p_i factors amortises.
  * evaluate_hypercube is O(2^k) with no reuse across the 5 rounds.

Files: test/FrameSizeProbe.t.sol (FrameLogger + bench), WhirVerifierP.sol
(call not staticcall; frame size into acc[base+11]).

---

## Batch 33 — the 63M is ONE function: eqGroupValue (mode-2 constraints)

TerminalWeightP (fork of the satellite with storage counters; the verifier
uses a plain call now so a fallback can write) splits the 65M:

  parse 30K | derive 1.76M | hypercube 99K | constraint eval 63.1M

And the constraint eval is NOT spread out - per-constraint timing shows ONE
mode-2 constraint per round carries it (the widest stacked table):

| round | dominant constraint gas | k | groups | selVars |
|---|---|---|---|---|
| 0 | 1.28M | 20 | 26 | 16 |
| 1 | **28.98M** | 24 | 501 | 16 |
| 2 | 6.99M | 23 | 130 | 16 |
| 3 | 10.79M | 23 | 190 | 16 |
| 4 | 10.66M | 22 | 202 | 16 |
| sum | **58.7M** | | | |

Gas per group ~55-58K, and the Horner mul(w,gamma) is only ~3.2K of it - so
~54K per group is eqGroupValue itself. Round 1 alone is 25% of the whole
113.8M verify, in a single function.

WHY it is slow: eqGroupValue (WhirGadgets.sol:203) uses the PACKED ext ops
(KoalaBearExt4.mul/add/sub through the public API). The Ext4 docstring
(line 126-135) measures the packed formulation at ~1.6k gas/coordinate vs
~350 for the register-carried form. eq_poly_eval and selectEvalBase were
ALREADY rewritten to the register form (deferred reduction, c0..c3 in
registers); eqGroupValue was not. It is the last hot evaluator still on the
slow path.

THE FIX (highest-value single change found): rewrite eqGroupValue in the
register form, exactly like eq_poly_eval. Both branches:
  * virtual (NO_SELECTOR): prod_i (1 - r - c + 2rc), c = zeta^(2^.) - a
    bare product, no denominator.
  * selector: num = prod (1-r + r*c), den = prod (1+c), one inv at the end.
Both are the same shape eq_poly_eval already carries in registers. Estimated
~4x on the 58.7M -> ~15M, i.e. the whole verify 113.8M -> ~70M from ONE
function. Parity-tested against the existing eqGroupValue vectors.

Second lever (smaller): the 501 groups share localR and gamma. The Horner
mul(w,gamma) per group is ~1.6M/round; could batch, but the eqGroupValue
rewrite is the prize.

Files: test/TerminalWeightP.sol (instrumented satellite), test/FrameSizeProbe.t.sol
(FrameLogger drives it, dumps the per-constraint table).

## Batch 34 — zeta-run sharing: the eval is 63M -> 16.2M

Two changes on top of batch 33's register fusion, both bit-identical (full
forge suite green, 32 suites / ~150 tests, including the recursion chain
E2E v5+v6 and the constraint identity):

**v2 (commit e4e8389)**: _mulBySelectorFactor register fusion + the
telescoped denominator prod_i(1+zeta^(2^i)) = (zeta^(2^arity)-1)/(zeta-1).
Constraint eval 63.1M -> 48.35M; recursion-chain v5 verify 113.8M -> 98.75M.

**v3 (this batch) — RUN SHARING**. Parsing the posted statement (bundle
header is WBND | ver u32 | cfgWords u32 | prfWords u32 — 16 B, not 13)
shows why the naive loop was absurd: round 1's dominant constraint has 501
eq groups, but they come from SIX matrices whose points FAN OUT across
columns — descs are emitted (arity, zeta) per column, so consecutive
descriptors share (arity, zeta) in long runs (76 and 166 columns per
point). The zeta-dependent work — the arity loop and the inversion — was
recomputed 501 times for ~10 distinct answers.

eqGroupValue splits into eqBaseValue (zeta part: arity product + closed-
form denominator) x eqSelectorValue (selector bits: nv ext-muls). The
mode-2 walk in constraintWeight groups consecutive descriptors by
(arity, zeta), computes the base ONCE per run, then per group one ext-mul
(base x selector). Field mult is associative, every op exact mod p: bit-
identical values, same Horner order over the value array.

MEASURED (FrameSizeProbe, block proof):
  constraint eval   48.35M -> 16.23M   (r1 dominant constraint 21.57M -> 6.35M)
  block-proof verify 154.66M -> 122.96M
  recursion-chain attribution: terminal identity 50.65M -> 18.37M
    (r0 1.25M, r1 7.05M, r2 3.11M, r3 3.29M, r4 3.67M)
    TOTAL accounted 88.8M -> 56.6M
  recursion-chain v5 verify 98.75M -> 66.82M (v6 73.03M, re-frame ~6.2M)

Cumulative from batch 31's baseline: satellite eval 65.3M -> 18.4M (-72%),
whole verify 113.8M -> 66.8M (-41%) WITHOUT touching the engine.

WHAT'S LEFT IN THE 16.2M: per-group selector products (nv ext-muls each,
packed ops ~1.6k) and the per-group Horner mul(w,gamma). Next levers, in
order: (a) register-fuse eqSelectorValue like eq_poly_eval (~350/factor);
(b) factor the Horner per run: w' = w*gamma^n + base * horner(sels) turns
two ext-muls per group into one per group + two per run. Both are local to
WhirGadgets.

After that the attribution (recursion chain, v5) is: open+fold 14.6M,
constraint identity 10.0M, initial phases 7.6M, terminal 18.4M, final STIR
3.4M — the engine items now dominate again, which is Phase 2's job.

## Batch 35 — selector/virtual register fusion (eval 16.2M -> 15.1M)

Follow-ups on batch 34, all bit-identical (32 suites green):

* _mulByVirtualFactor: the virtual branch's raw *= 1-r-c+2r(x)c fused in
  registers (4P bias, lane 0 carries +1), twin of _mulBySelectorFactor.
  (First attempt shipped e1/e2/e3 with mul(2,t0) instead of t1/t2/t3 -
  caught by the parity tests, TerminalClaimMismatch, fixed.)
* _mulExt: plain register ext4 product. eqSelectorValue now uses
  _mulExt(s, r) for set bits and _mulBySelectorFactor(s, r, 0) for clear
  bits (its factor is exactly (1-r) + r(x)0).
* FAILED EXPERIMENT, reverted: fusing the mode-2 Horner mul(w, gamma) and
  base x selector via _mulExt made it 0.1M WORSE (15.129 -> 15.244M) -
  the packed KoalaBearExt4.mul is already inlined by the optimizer at
  those sites and the private-assembly call overhead dominates. Lesson:
  register fusion pays where the packed chain is long (arity loops,
  selector products); it does not pay on single muls in hot loops.

Measured: constraint eval 16.23M -> 15.13M; recursion-chain v5 verify
66.82M -> 65.73M; terminal identity 18.37M -> 17.27M; TOTAL accounted
56.6M -> 55.5M.

Remaining in the 15.1M: eqSelectorValue still walks nv (up to 12) packed
sub/mul pairs per group for CLEAR bits only via the fused path; set bits
use _mulExt. The per-group Horner mul+add (~1.6k each x 501 x 5 rounds)
is ~4M and resists fusion (above). The base per run is now cheap. Further
satellite gains need the Phase-2 engine (direct extcodecopy CONFIG, no
re-frame ~6.2M) or a wire change (precomputed selector products per
column - the prover could post the nv-bit selector value... but that is
DERIVED from transcript challenges, not proof data: cannot post).

Next: Phase 2 engine work per the running plan.

## Batch 37 — selector memo (eval 14.8M -> 12.6M)

The zeta-run insight extended: one opening point fans out across its
matrix's columns, and the NEXT point of the same matrix reuses the
IDENTICAL cols[] selector indices - selIndex values repeat across runs
(round 1: 501 groups, ~250 distinct selIndex values). The backwards
factored Horner now memoizes eqSelectorValue per (arity, selIndex) inside
one constraintWeight call: interleaved [seen, value] pairs in one memory
array (two arrays blew the via-IR stack), keyed by selIndex, reset when
nv = k - arity changes (the key space changes with arity).

Cap at nv <= 10: at nv = 16 (round 2, 32 mats) the 128 KB zeroing costs
more than the recompute - cap 13 regressed the block proof by 1.8M, cap
10 wins everywhere.

Measured: constraint eval 14.78M -> 12.61M; recursion-chain v5 verify
65.73M -> 63.24M; terminal identity 17.27M -> 14.79M; TOTAL accounted
55.53M -> 53.05M; block proof 121.86M -> 119.80M. 32 suites green.

Also this batch (36): run-factored Horner + _mulAddExt fused mul-add
(eval 15.13 -> 14.78M) - committed as a27fbac.

Attribution now (recursion chain): terminal 14.79M, open+fold 14.61M,
constraint identity 10.05M, initial phases 7.57M, final STIR 2.81M.

## Batch 38 — Yul jump-table dispatch in the constraint-identity DAG (identity 10.0M -> 9.0M)

_checkIdentity runs a post-order DAG interpreter over ~21k nodes per
recursion-chain verify (instances 2-3 carry 5.9k + 15.3k nodes). The
Solidity if/else-if chain over 19 op codes cost ~10 compares per node.
The whole node loop now lives in ONE Yul block:

* switch -> jump table (solc emits one jump for the whole dispatch);
* ADD/SUB/MUL/NEG register-fused (unpack once, one mod per lane);
* leaf ops exploit the struct layout: Opened's ten arrays sit at
  (op-2)*32 for ops 2..11, so one indexed mload covers eight of them;
  Selectors' first three fields cover ops 12..14 the same way;
* PUBLIC (op 10) is the only lifted leaf needing a special case.

Soundness parity: the Solidity version bounds-checked every array read
automatically. In v5 the CONFIG - the node program itself - rides inside
the bundle, so a tampered bundle is attacker-controlled program data:
without checks a garbage node index expands memory to MemoryOOG (the
tamper-profile test caught exactly this). Per-case bounds checks
(x<n, y<n for arithmetic; x<len for leaves) restore the clean revert at
0.3M cost - cheaper than the 0.7M hoisted variant, and the redundant
op<19 check died to the via-IR stack limit anyway.

Measured: constraint identity 10.05M -> 9.03M; recursion-chain v5 verify
63.24M -> 62.23M; TOTAL accounted 53.05M -> 52.03M. 32 suites green.

Attribution now: terminal 14.79M, open+fold 14.61M, constraint identity
9.03M, initial phases 7.57M, final STIR 2.81M.

## Batch 39 — v6 re-frame rewrite (3.84M -> 0.99M; v6 verify 68.4M -> 64.7M)

Measured the v6 wrapper overhead precisely with a temporary revert-probe:
the re-frame cost 3.84M, not the ~6.2M the digest gap suggested (the
staticcall argument encoding of the 445 KB v5 frame is the other ~1.4M).
Two changes:

* CONFIG: extcodecopy straight from each chunk runtime into the frame
  (data start = codesize - 4 - trailer len), replacing chunk.read() calls
  that allocated + copied every 24 KB twice.
* Tail: one calldatacopy for the 445 KB PROOF+STATEMENT tail instead of
  a 32-byte mstore loop.

v6 verify is now 64.71M vs v5 62.23M: the wrapper costs 2.49M total
(0.99M re-frame + ~1.5M staticcall/encode) and saves 182 KB of calldata
(~7.2M at 40/16 gas-per-byte). Phase 2's direct-extcodecopy engine erases
the remaining 2.5M and keeps the calldata win.

Probe instrumentation removed after measuring. 32 suites green.

## Batch 40 - v6 wrapper: build the engine payload directly (64.71M -> 62.29M)

The v6 wrapper's remaining 2.49M was almost entirely the handoff: build a
445 KB v5 frame, then abi.encodeCall it - which allocates a SECOND 445 KB
buffer and copies the frame into it. Two quadratic memory expansions, one
zeroing pass, one full copy, for bytes that were already contiguous.

Fix: WhirVerifierV6.verify now writes the engine's call payload DIRECTLY in
final ABI layout in one buffer - selector, heads, statement (calldatacopy),
bundle length word, then the v5 bundle: header bytes, CONFIG via
extcodecopy from each chunk, tail via one calldatacopy - and staticcalls it
from that pointer with the reply landing in 64 bytes of slack. One
allocation, one expansion, zero redundant copies.

Result: v6 verify 64.71M -> 62.29M. The wrapper now costs 57K gas TOTAL
over the frozen v5 engine (62.23M) while posting 444,936 B instead of
627,136 B - 182 KB less calldata (~7.2M gas at 40/16 per byte). Net v6 win
vs v5: ~7.15M gas and 182 KB of block space.

Phase-2 note: the planned "direct extcodecopy CONFIG reads inside the
engine" now only saves the 57K wrapper delta - the re-frame it existed to
kill is gone. Phase 2's real work is the compact PROOF (varint limbs,
pruned paths) and the engine attribution items (terminal 14.79M, open+fold
14.61M, constraint identity 9.03M).

Gotchas hit: Solidity address needs uint256(uint160(...)) to enter Yul; a
bytes4 var is ALREADY left-aligned in its word (no shl(224) needed).

32 suites, 156 tests green.

## Batch 41 - v7 wire: compact ext limbs (444,936 -> 422,200 B, 59.29M)

The PROOF section's extension arrays carried each ext4 element as a 32-byte
word with the four <2^31 limbs at bits 224..128 and 16 zero pad bytes -
pure wire waste (batch 26 itemized it at +29 KB vs postcard). v7 ships the
four BE limbs only: 16 bytes per element.

* wbnd.rs: Sink::ext_arr16 writes the compact blob; encode_bundle_v7 /
  encode_bundle_v7_split mirror the v5/v6 paths (v5 stays byte-exact).
  The blob's byte count carries bit 31 as the compact flag: the decoder
  learns the element size IN BAND. A bool threaded from the header version
  through _runRounds/_decodeRoundPrf pushed the via-IR scheduler past the
  stack limit (var_..._mpos 1 too deep) - the in-band flag costs nothing
  and keeps every decoder signature unchanged.
* WhirVerifier.sol: version gate accepts 5 and 7; _extArr reads the flag
  and lifts 16-byte limbs with shl(128, shr(128, calldataload)) - one
  shift pair per element, no per-element pad check.
* WhirVerifierV6.sol: accepts ver 6 or 7 and stamps the frame accordingly
  (v6 -> 5, v7 -> 7). CONFIG is identical between v6 and v7: same chunks,
  same digest.
* export_chain_bundle_v7 (ignored, WHIR_RATE_*=4): writes
  recursion_chain_bundle_v7.bin (422,200 B), config_v7.bin, 8 chunks,
  sidecar_v7.json. Recursion is nondeterministic (ZK blinding) so v7 gets
  its OWN vectors; the v6 vectors stay untouched.

Measured (rate 4/4, own proof run each): v7 bundle 422,200 B (-22,736 =
1,421 ext elements x 16 B, exactly as predicted), verify 59,287,810 gas.
Same-run v6-alone comparison: 59.71M -> 59.29M (-0.42M: 22.7 KB calldata
saving minus the shift-pair decode). v7 through the wrapper: 61.79M vs v6
62.29M. Reject battery passes (wrong statement, tampered byte).

Cumulative on-chain path: v5 627,136 B / 62.23M -> v6 444,936 B / 62.29M
(-182 KB CONFIG) -> v7 422,200 B / 61.79M (-22.7 KB limbs). Next wire
item: pruned Merkle paths (-66 KB est, batch 26) -> ~356 KB, at which
point the posted proof is essentially the postcard proof + framing.

33 suites, 160 tests green.


---

## Batch 42 — v8 wire: PRUNED round paths (encoder done, export running)

Wire composition measured on v7 (422,200 B): expanded Merkle paths are
287,776 B (r0 45,728 / r1 63,264 / r2 60,512 / r3 60,512 / r4 50,464 /
final 7,296) - 68% of the posted bundle. Pruned digest counts (vendor
PrunedMerklePaths): r0 980, r1 1434, r2 1369, r3 1396, r4 1142 unique
siblings vs 1480/1720/1720/1720/1480 expanded - saves ~78 KB. v8 lands
at ~344 KB posted, hitting the ~350 KB ask.

Encoder (wbnd.rs):
- flat_from_vectors passes through round_pruned_paths -> "pruned_hex"
  (concatenated per round) + final_pruned_hex.
- Sink::blob_pruned: same as blob, bit 31 of the byte-count word set
  (IN-BAND flag pattern again - no bool threading).
- encode_bundle_impl gains pruned bool; ver byte 8; encode_bundle_v8_split
  mirrors v7 split (cfgWords=0, CONFIG identical to v6/v7 digest).
- final paths blob stays expanded (7 KB, no sharing to exploit).

Rust capture (done earlier this batch): whir_walk RoundWalk.pruned_paths +
TerminalWalk.final_pruned_paths; composed_export emits both.

DECISION - restore strategy: the engine has 425 B margin, so neither the
frontier walk nor the per-query path check can grow it. GOAT's expand()
recomputes missing siblings bottom-up - which needs the leaf digests,
which the engine computes anyway. So instead of expanding to full paths
and re-verifying per query (double hashing), the satellite does the
AMORTIZED walk and returns the ROOT: MERKLE_ROOTS entry point.
  input:  depth, nq, indices[nq], leafDigests[nq], pruned stream
  output: root (32 B)
Engine per round: loop 1 extLeaf(row) -> leaf digests in memory; one
staticcall -> root; compare vs prevCommitment; loop 2 foldRow per query.
Keccak count drops from sum(nq*depth) = ~8,869 to frontier internal
nodes ~6,441 (-27%), plus -78 KB calldata (-1.2M) and no per-query path
decode. Trust: satellite is codehash-pinned, same trust as engine code.
In-band pruned flag readable at pathsAbs-4 (count word) - no threading.

## Batch 43 - reference verifier research (GOAT / plutus-plonky3 / midfall)

GOATNetwork/bitcoin-stark-verifier (WHIR + Poseidon2 over KoalaBear in
Bitcoin Script, no OP_CAT) - the closest comp, same protocol family:
- pruned.rs: ports of p3 walk_frontier/sibling_offset/restore_paths,
  wire order normative (level 0 first, groups by ascending parent,
  missing-child positions ascending) - matches our plan exactly.
- constraint.rs CLOSING SHAPE: Plonky3 evaluates w(R) and f_M(r_fin)
  separately; constraints ACCUMULATED symbolically, evaluated ONCE at
  the end against R = concat of all alphas; a constraint from round i
  reads the LAST n_c coords of R - "no per-round rewriting". Our
  TerminalWeight already follows this shape.
- eq_eval identity: prod(1 + 2*z_i*r_i - z_i - r_i) - ONE extension
  mul per coordinate instead of two. We already use this (WhirGadgets
  eqEval cites Point::eval_eq).
- combine_answers: Horner for sigma' (t+1 ext muls vs 2t). We already
  do factored Horner (v5).
- budget.rs cost model: "Batching answers into the constraint is not
  what makes a WHIR verifier expensive; OPENING them is." Confirms our
  attribution (open+fold 14.6M + terminal 14.8M = 49% of gas).
- Domain points z_i = domain_gen^index are DERIVED from the squeezed
  index, not sent (a round costs 1+n ext elements, not n*(1+arity)).
  We SEND domain_points per round on the wire - candidate to drop
  (small bytes, but also decode words).
- Their rate schedule: rate += folding-1 per round from starting 4 -
  matches our converged 4/4 grid recurrence.

input-output-hk/plutus-plonky3-exploration (Aiken, FRI-based Plonky3):
- separate proof.ak deserialization module + verify_constraints split;
  benchmark.md per-op costs. Less transferable (FRI not WHIR, Aiken not
  EVM); confirms field-op cost tables approach.

midfall proofs/solidity-verifier (Halo2/KZG BLS12-381, codegen):
- GENERATES the verifier from the VK: all circuit constants become
  compile-time PUSH immediates - zero runtime CONFIG decode. Our
  analogue: bake per-deployment constants (schedule, domain points) as
  immediates in a generated satellite. Decode-side only (~0.5M).
- separate Halo2QuotientEvaluator satellite contract - same EIP-170
  pressure, same satellite answer we already use.
- EIP-2537 precompile smoke tests - irrelevant to hash-based verifiers.

NET for the 30M push: nothing found that beats the amortized-Merkle
satellite (v8) + query-count reduction. The protocol floor is
keccak(row->leaf) per query + frontier keccaks + ext4 field arithmetic
(foldRow, sumcheck, eq evals). To go below ~45M we must cut QUERIES
(more grinding budget at fixed security level - revisit pow_bits grid,
GOAT derives queries from the same tradeoff) or fold the per-query
leaf-hash into the amortized walk (batch rows -> leaves inside the
satellite, one staticcall per round does leaves+root: saves engine
memory traffic, not keccaks).



---

## Batch 44 — v8 pruned Merkle paths + MROOTS satellite; EIP-170 fit (24,456 B)

### v8 wire: pruned per-round Merkle paths
The expanded per-query paths send every frontier sibling nq times over:
round r sends nq*depth words where the distinct siblings number only
~1.4-1.5k. v8 sends each digest ONCE per round (level-major stream,
same order the p3 walk_frontier consumes) plus the query indices the
engine already derives. Wire: 422,200 -> **350,772 B** (v7 -> v8, -71,428).
- Flag: bit 31 of the paths-blob count word (in-band, v6/v7 unchanged).
- New trailer: pruned_lens u32 array (distinct digest count per round:
  980/1434/1369/1396/1142) - the engine cannot derive it pre-walk.
- Final paths blob stays expanded: verifyFinal untouched.

### MROOTS satellite walk (TerminalWeight)
One staticcall per intermediate round replaces nq Solidity path walks.
Frame: [MROOTS, depth, nq, nD, indices(nq), leaves(nq), stream(nD),
expectedRoot] -> reply [MROOTS, root, 0]. Full-Yul walk mirrors
p3 walk_frontier: insertion-sorted unique seeds, per-level group by
shr(1,idx), boundary children pull siblings ascending from the stream,
odd child: right := left; left := stream. Root compared INSIDE the
satellite (expectedRoot is the engine's own prevCommitment, never proof
bytes - sound), reverts PrunedRootMismatch (0xaee6dc69) on mismatch;
the shared _callSatellite bubbles the revert data.
Yul lessons: revert selectors must be LEFT-aligned (shl(224, sel)) or
callers see selector 0; unit-test oracle must dedup queries before
generating the stream and map walk idx -> heap node (n>>lvl)+sibWalk.

### Engine: one call path
_callSatellite(frame, size) now serves TWIGHT and MROOTS: pin re-check,
staticcall, revert bubbling. The reply magic/length checks were REMOVED:
the codehash pin proves the callee is our satellite, which either
returns 96 B echoing the frame's own magic or reverts - a wrong answer
is a revert by construction. (Stub tests now assert fail-closed at
TerminalClaimMismatch instead: a lying satellite still cannot pass.)

### EIP-170 squeeze: 24,941 -> 24,456 (margin 120)
- frame built incrementally in the query loop (_frameOpen/_framePut,
  no side arrays): -103
- shared _callSatellite (was two copies): -88
- root compare moved into satellite frame: -26
- reply magic/size checks dropped (pin covers them): -172 <- the big one
- optimizer_runs 200 -> 100: -96 (gas unchanged within noise; 1000 and
  25 both WORSE - the size optimum is a plateau at 50-100)
WhirVerifier runtime now **24,456 B <= 24,576**. forge build --sizes
still errors on WhirVerifierP (test-only attribution probe, never
deployed): src-only gate is clean.

### Gas at runs=100 (wrapper, full verify)
v7 59,773,747 | v8 60,628,306 (+0.85M exec) but -71,428 B calldata
(~1.14M at 16 gas/B): v8 nets ~0.3M cheaper AND hits the 350 KB ask.

### Next (toward 30M)
- query-count vs grinding grid (GOAT floor): pow_bits up, queries down.
- Phase-2 engine reading CONFIG section directly (~57K).
- statement rebind to D-088 folded root; deeper fusion of foldRow into
  the satellite (leaves+root in one call: saves engine memory traffic,
  not keccaks).

---

## Batch 45 — gas attribution at v8 + the grinding/query grid (D-092)

### Attribution (WhirVerifierP, v5-fork probe, v5 vectors — shape-accurate)
TOTAL accounted 52.48M of 76.8M probe gas (probe carries extra checks).
Fixed / non-query-proportional:
- constraint identity (_checkIdentity): **9.03M** — one shot, independent of queries.
- constraints decode: 0.35M; batch decode 0.007M; transcript 0.07M.
Per round (0..4):
- open+fold queries: 2.61, 3.26, 3.24, 3.24, 2.66M = **15.0M** — scales with numQueries.
- terminal identity (satellite MROOTS): 1.23, 4.89, 2.97, 2.64, 3.06M = **14.8M** — scales with nDigests (pruned paths).
- initial phase: 0.35, 2.33, 2.67, 1.05, 1.19M = 7.6M (sumcheck proof reads).
- final open+STIR: 0.66, 0.56, 0.48, 0.48, 1.22M = 3.4M.
- sumchecks + gamma/claim fold + closing: ~1.9M total.

So the two query-proportional buckets (open+fold 15M, MROOTS 14.8M) are ~30M of
the ~60M. Halving queries halves those: floor from query reduction alone is
~45M -> with 30M fixed cost still there, **30M total is NOT reachable by
grinding alone**; needs the fixed 9M identity + 7.6M initial-phase work moved
into satellites (or fused) as well.

### Grinding/query grid (whir_pow_grid.rs, arity 24, folding 4, JohnsonBound)
rate 4 (current operating point), pow -> total queries (incl terminal):
pow 24 (min feasible) 96 | 28: 90 | 32: 85 | 40: 76 | 48: 64 | 56: 55 | 64: 44 | 72: 33 | 80: 24 | 88: 14
rate 3: 24: 116 | 32: 102 | 48: 78 | 64: 53 | 80: 28
Prover cost: 2^pow hashes per grind point (per query point). pow 24->32 = -11%
queries for 8x grind; pow 24->48 = -33% queries for 256x grind.

### Plumbing
- settlement_params_pow(log_max_lde, rate, pow_floor) in settlement_replay.rs:
  schedule uses max(min feasible, floor). settlement_params_for delegates with 0.
- composed_export::settlement_bundle_with_blob reads WHIR_POW_FLOOR env.
- Wire needs NO change: pow_bits per round already flows through CONFIG
  (sched_pow_bits / final_pow_bits) and the engine reads it from there.

### Measurement in flight
WHIR_POW_FLOOR=32 rate 4/4 v8 export -> measure WBND + gas vs 350,772 B /
60.63M baseline.


## Batch 46 - v8-shaped attribution (WhirVerifierV8P probe)

The v5 probe no longer matched the v8 engine, so a byte-fork of the v8 engine
(test/WhirVerifierV8P.sol) carries gasleft() snapshots at every phase
boundary and writes them to a public profileData array (non-view on purpose:
the V6 wrapper staticcalls its engine, so the probe is called directly with
the CONFIG spliced in exactly as the wrapper splices it: header(16,
cfgWords stamped) + CONFIG + tail). Run on the real floor-30 v8 vectors.

TOTAL accounted 54.99M of the 58.38M wrapper total (the ~3.4M delta is the
wrapper: payload build, 182 KB CONFIG extcodecopy, 330 KB calldatacopy).

| bucket | gas | note |
|---|---|---|
| constraint identity (batch layer) | 9.29M | _checkIdentity, fixed |
| verifyRound (5 rounds) | 14.03M | 2.39/2.99/3.04/3.07/2.54 |
| terminal identity eval (5x) | 14.53M | 1.18/4.83/2.91/2.59/3.02, satellite |
| initial phase (5x) | 7.61M | 0.35/2.33/2.69/1.05/1.19 |
| verifyFinal (5x) | 3.56M | 0.69/0.59/0.50/0.50/1.28 |
| satellite MROOTS (5x) | 3.10M | 0.50/0.70/0.66/0.67/0.56 |
| constraint weight build | 1.41M | expandFromUnivariate + selVars |
| round decode | 1.36M | CONFIG+PROOF per-round decode |
| batch transcript + decode | 0.08M | |

Query/digest-proportional (verifyRound + terminal eval + MROOTS + weight) =
33.1M; fixed (identity + initial + final + decode) = 21.9M; wrapper 3.4M;
calldata floor 330 KB x 16 = 5.3M (inside the wrapper/engine reads).

Structural levers ranked by this table:
1. terminal eval chain 14.5M - already satellite Yul but ~3.4K gas per pruned
   digest; audit the per-digest path for waste and fuse the MROOTS walk into
   the same call (one digest walk per round instead of two).
2. verifyRound 14.0M - ~161K gas per query at 87 queries; the open+fold is
   Solidity-with-Yul-islands; a full Yul kernel is the GOAT/midfall pattern.
3. constraint identity 9.3M - Solidity loop over Opened structs; satellite-
   able like MROOTS (pure field-op program, engine keeps the equality check).
4. initial phase 7.6M - sumcheck absorbs; Yul absorb loop.

Probe notes: fork lives in test/ (imports remapped ../src/verifier, ../lib);
events need non-view (the private chain lost view accordingly); the splice
must read memory bytes at +32 (mload(bnd) is the LENGTH word - first attempt
wrote the length as the magic and died on BadMagic).

## Batch 47 — per-query anatomy + microbench: where the query loop actually goes

Probe deepened (WhirVerifierCoreV8P fork, round stride 24): verifyRound split
into phases1-4 / query loop / phases6-7 / sumcheck, and the query loop into
loadRowFused / framePut / foldRow. Free-pointer trajectory probed per round.

Floor-30 v8 vectors, probe numbers (gasleft overhead inflates ~10-15%):

    per-round (r0..r4, nq = 14/11/11/11/14, rowLimbs 64):
      query loop      2.10  2.62  2.67  2.70  2.23   M   (12.32M total)
        loadRowFused  1.26  1.60  1.60  1.60  1.27   M   (7.33M)
        foldRow       0.79  0.92  0.92  0.92  0.79   M   (4.33M)
        framePut      ~0.02 each (noise)
      phases1-4       0.06-0.08 each; phases6-7 0.11-0.14; sumcheck 0.04
      claim reg (initial) 0.31 2.29 2.65 1.01 1.15  M   (6.42M!)
      initial sumcheck    0.04 each (40K) - sumcheck is CHEAP, registration is not

    free pointer: flat INSIDE the query loop (no per-query allocation creep);
    frame alloc ~6.6KB/round; engine heap peaks ~1.2MB.

Microbench (test/QueryMicrobench.t.sol, exact Yul copy, 64-limb ext rows,
calldata source, 100 iters):

    loop skeleton only (calldataload+swap32+range-check, 2 in-loop switches)  31.2K
    + Montgomery mod + leaf limb stores                                       +9.1K
    + elems RMW (4 read-modify-write limbs per element)                       +8.1K
    + keccak of 256-byte leaf                                                 +0.14K
    total loadRowFused ~48.5K/query; evaluate_hypercube(16,4) 10.9K/query.

    => the two LOOP-INVARIANT switches (rowsCd, rowsAreBase) inside the limb
       loop cost ~490 gas/limb in skeleton - solc switch codegen per iteration.
       The elems path does 4 RMWs per element where 1 store would do.

Levers ranked after batch 47:
  A. Fused query kernel (GOAT pattern): specialize _loadRowFused loops on
     rowsCd/rowsAreBase OUTSIDE the loop; per-element single-store elems
     (4 limbs -> 1 packed word); keep leaf scratch pass. Est -1.5-2M, no wire
     change. EIP-170 margin 120 B is the constraint: specialization must not
     grow the engine (satellite absorbs if needed).
  B. Claim registration 6.42M is the initial phase (not sumcheck!): CONFIG
     parse per claim. Pre-parsed CONFIG (v9) attacks claim reg + identity
     9.3M + weight 1.4M + terminal eval 14.5M = the ~31M CONFIG-walk whale.
     GOAT/midfall both ship pre-compiled program formats for exactly this.
  C. Terminal eval 14.5M already Yul on satellite; per-digest ~2.3K.

## Batch 48 (c72f3e3) — base hot kernel, memory-only generic loader, CIDNTY identity offload

Three changes, one commit, 169/169 green.

1. **_loadRowBaseHot** (WhirVerifierCore): round-0 base-field rows read
   straight from calldata, one limb per element, leaf = keccak(dst, rowLimbs*4).
2. **Generic row loop memory-only**: the fallback loop no longer branches on
   calldata-vs-memory per row (rowsFlat is memory after stage A's final-phase
   change; the hot kernels own the calldata paths).
3. **CIDNTY offload**: the whole constraint-identity check (CONFIG CONSTRAINTS
   parse + Opened reconstruction + DAG eval + quotient recompose) moved from
   the engine into the TerminalWeight satellite behind a magic frame
   ("CIDNTY" = 0x4349444E5459). Frame = magic, zeta/alpha/lookupAlpha/beta,
   terminals, statement, CONFIG CONSTRAINTS raw LE bytes, 4 round bound-eval
   arrays. Satellite parses, evaluates, reverts ConstraintIdentityMismatch
   (same selector as the engine's, so bubbled reverts are indistinguishable)
   or returns the 96-B [magic,0,0] ok reply.

**Why**: the engine was 24,946 B — over EIP-170, undeployable. ConstraintIdentity
is a library, so its DAG interpreter inlined into the engine. After the offload:
WhirVerifier 17,792 B (+6,784 headroom), TerminalWeight 17,805 B (+6,771).

**Gas**: wrapper test_gas_v8 55.04M -> 55.59M (+0.55M: the 92 KB CONFIG frame
copy is now paid at the staticcall). Direct v8 path 54.03M. The +0.55M is the
price of a deployable engine; v9 (CONFIG out of the wire entirely, read from
code satellites via extcodecopy) pays it back with interest.

**Bug found (worth remembering)**: the frame packer used mcopy for the
statement and CONFIG copies with CALDATA offsets (statement.offset,
proof.offset + cfgWord*4). mcopy is memory->memory: it read memory garbage at
those numeric addresses and the satellite saw zeros at cfg while cfgWords was
correct (the count word was mstore'd, not mcopy'd — that's why the frame
length check passed and the parse read n=0). Fix: calldatacopy for both.
Engine-side dump proved the source calldata was right (cdWordAtProofSrc =
0x0600000005000000040000000600000002000000000000000000000008000000 = n=6,
stmInst=5, width=4, preWidth=6, auxWidth=2, skip, skip, numConstraints=8);
satellite-side scan proved the payload never landed in the frame.

**EIP-170 enforcement nuance**: plain `forge build` exits 0 even when a
contract exceeds 24,576 B; only `forge build --sizes` errors. Always gate CI
on --sizes.

**via-IR stub probes infeasible**: extracting the identity body into a stub
function to measure inline cost hit "Variable expr_mpos_366 is 1 too deep in
the stack" scheduler errors under via_ir. The satellite IS the stub now.

**Gas ledger (wrapper test_gas_v8)**: 113.8 -> v2 98.75 -> v3 66.82 -> v4 65.73
-> v6 63.24 -> v7 61.79 -> v8 60.63 -> floor28 58.63 -> floor30 58.38 ->
cb56da2 59.94 -> hot kernel 57.85 -> stage A 55.19 -> +base kernel 55.04 ->
+CIDNTY 55.59 (deployable). Target 30M: remaining whales (batch 46 attribution,
inflated ~10-15%): terminal eval 14.5M, rounds 14.0M, identity 9.3M, initial
7.6M, claim reg 6.4M, foldRow 4.3M, MROOTS 3.1M, calldata floor 5.3M.


## Batch 49 — regenerated V8P attribution probe; fresh phase table (HEAD c72f3e3/d0df2d8)

The probe had drifted (frozen at cb56da2, pre-CIDNTY). Regenerated
`test/WhirVerifierCoreV8P.sol` + `test/WhirVerifierV8P.sol` from the CURRENT
engine + core by anchor-patching (imports rewritten to ../, library renamed
…V8P, Transcript gains acc/base, engine verify() drops view/override and
threads acc; taps identical slots to before). Build clean, probe verifies the
real floor-30 v8 bundle (512,204 B spliced wire).

Fresh probe table (gasleft taps, ~1.6x inflated vs wrapper 55.59M — shares
are the signal; TOTAL accounted 89.46M):

| phase | probe gas | share |
|---|---|---|
| terminal identity (TWIGHT satellite) | 14,538,730 | 16.3% |
| query loop total | 10,501,285 | 11.7% |
| — _loadRowFused | 5,137,428 | 5.7% |
| — StirOpenings.foldRow | 4,343,598 | 4.9% |
| — _framePut | 87,366 | 0.1% |
| constraint identity (CIDNTY satellite) | 8,583,433 | 9.6% |
| verifyInitial claim registration | 7,356,689 | 8.2% |
| verifyInitial sumcheck | 199,962 | 0.2% |
| verifyFinal | 3,381,439 | 3.8% |
| MROOTS satellite | 3,100,576 | 3.5% |
| constraint weight (expand/powConst) | 1,385,057 | 1.5% |
| phases 6-7 (round claim fold) | 624,422 | 0.7% |
| round decode (all 5) | 676,333 | 0.8% |
| phases 1-4 (transcript draws) | 347,889 | 0.4% |
| batch transcript | 71,599 | 0.1% |
| decode + statement | 7,580 | 0.0% |

Per-round (initial claim reg / verifyRound loop / MROOTS / terminal):
r0 309k / 1.81M / 499k / 1.18M · r1 2.27M / 2.22M / 705k / 4.83M ·
r2 2.63M / 2.26M / 662k / 2.91M · r3 1.01M / 2.29M / 673k / 2.59M ·
r4 1.14M / 1.92M / 561k / 3.02M.

Readings:
- The CONFIG-walk family (terminal 14.5 + CIDNTY 8.6 + claim reg 7.4 + weight
  1.4 = 31.9M probe ≈ 36%) is confirmed as the whale cluster; r1's terminal
  identity (4.83M) is the single hottest per-round item.
- foldRow ≈ 78k probe per query (nq 11-14, rowElems 16): ~5k per ext fold
  step — StirOpenings.foldRow is generic Solidity; a hot assembly kernel like
  the loader's is the obvious next cut (est. −1.5M real).
- claim reg varies with each round's bound-eval count (r2 2.63M): pure
  observeExt absorbs; KeccakChallenger per-absorb overhead is the lever.
- fp markers show the query loop allocates nothing per query (fp q0 == fp qn)
  — the loader hot kernels are allocation-free as designed.
- 0x40 slots (acc 16/17) unused in the regen (harmless zeros).

Next (batch 50): hot assembly foldRow in WhirVerifierCore (rowsAreBase-aware
fold of rowElems ext elems against prevRandomness), then KeccakChallenger
absorb-path audit for the claim-reg loop.


## Batch 50 — foldRow exonerated; claim-reg decoded; real-gas budget

Microbenches (FoldRowBench.t.sol, tight loops):
- `StirOpenings.foldRow` 16 elems / 4 randomness (the in-situ shape: every round
  has rowElems=16, |randomness|=4, rowsAreBase=false): **11,099 gas**, 739/fold.
  61 queries total ⇒ foldRow ≤ **0.68M real** across the whole proof. The probe's
  4.34M was nested-tap inflation (~6×), NOT a whale. The hot fold-kernel idea is
  DEAD — 15 fused assembly folds are already near-floor.
- 64-elem/6-dim shape (unused here): 62k, 985/fold.
- `observeExt4Mont`: **1,044 gas** per ext element (4 limbs: mod p + Mont + bswap).
- `observeBasesLE`: **171 gas/word** bulk (10,688-word call), 194 split 8×1336.
  The keccak flush dominates: ~57 gas loop + ~90-110 amortized f1600 per word.

Probe shapes (new taps, stride fixed 24→32 — slots 24..27 were silently
overwritten by round 1's block; caught by #openingEvals printing gas values):
- claim-reg per round (probe): 311k / 2,274k / 2,636k / 1,010k / 1,143k = 7.37M.
- openingEvals: 24 / 499 / 128 / 188 / 200 = **1,039 ext evals** ⇒ 1.08M real.
- perClaimConstants framing sums: 756 / 2,876 / 10,688 / 1,632 / 2,120 =
  **18,072 CONFIG words** ⇒ ~3.1M real — the claim-reg whale is framing absorb,
  already bulk; floor ≈ keccak flush.
- round sumcheck (new tap acc[base+19]): 97k/130k/130k/130k/130k ≈ 0.6M probe —
  negligible.

Real-gas budget (probe ÷1.6, wrapper 55.59M truth):
| item | real M | note |
|---|---|---|
| terminal identity (TWIGHT) | ~9.1 | CONFIG constraint walk, biggest single item |
| query loop | ~6.6 | loadRowFused ~3.2 (52k/q — read it), foldRow 0.68, rest |
| CIDNTY | ~5.4 | +0.55M frame copy of CONFIG |
| claim reg | ~4.6 | framing 3.1 + evals 1.1 + dot 0.4 |
| verifyFinal | ~2.1 | |
| MROOTS | ~1.9 | |
| weight | ~0.9 | |
| calldata floor | ~5-8 | 512 KB wire × 16/4 gas |
| rest | ~2 | decode, sumchecks, phases |

Floor with today's protocol shape ≈ 45-50M. **30M needs protocol-shape cuts, not
more kernel tuning**: v9 pre-compiled CONFIG (GOAT/midfall model) — pre-swapped
framing (raw append), pre-flattened constraint tables, CONFIG out of the wire via
extcodecopy code-satellites (saves ~2.9M calldata + ~1.5M re-frame/frame-copy).
