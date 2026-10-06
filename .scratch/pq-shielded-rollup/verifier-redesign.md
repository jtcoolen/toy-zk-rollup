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

