# Verifier contract optimization — observations & measurements

Phase started after the full gate went green with the wallet + extension.
Goal: measured gas/code-size reductions on the WhirVerifier/ShieldedPool
settlement path, before/after recorded here, e2e kept green throughout.

## 1. Baseline (phase start, forge 1.x, solc 0.8.28, optimizer 200 runs, via_ir)

| Measurement | Value |
|---|---|
| `test_verify_accepts_the_real_proof` (raw `verify()`) | **1,064,286,857 gas** |
| `test_real_block_applies_to_the_pool` (full `applyBlock`) | 1,781,295,114 gas |
| `test_verify_rejects_tampered_proof` (rejects late) | 343,665,206 gas |
| WhirVerifier runtime code size | **24,191 B (EIP-170 margin 385 B)** |
| ShieldedPool runtime code size | 3,826 B |
| WBND v4 block bundle (calldata) | 2,825,568 B |
| Node settlement tx (anvil) | 1,642,317,699 gas |

Component tests (isolated layers):

| Component | Gas |
|---|---|
| Batch transcript walk (`test_gas_batch_transcript_walk`) | 16,477,478 |
| Constraint layer (`test_gas_constraint_layer`) | 37,275,417 |
| One STIR opening, depth 6, 16 ext elems (`openAndFold`) | 41,747 |
| All STIR openings replay (`test_replays_every_stir_opening`) | 6,853,302 |
| WhirRoundPhase single round | 50,261,599 |
| WhirFinalPhase single final | 85,103,556 |

## 2. Top-level decomposition of `verify()` (temporary gasleft brackets, reverted)

Measured on the real settlement proof (instrumented total 1,087.8M; brackets
themselves add ~23M):

| Stage | Gas | Share |
|---|---|---|
| WBND decode (`_decodeBatch*` + `_checkStatement`) | 7,776,345 | 0.7% |
| Terminal sum check | 1,934 | ~0% |
| Batch transcript walk | 94,292 | 0.01% |
| **Opening rounds loop (`_runRound` x 5)** | **895,529,742** | **82%** |
| Constraint identity (`_checkIdentity`) | 93,276,660 | 8.6% |
| (call overhead, statement re-check, alloc) | ~90M | 8% |

The batch transcript walk is negligible — keccak-f[1600] via the native
`keccak256` opcode is not the bottleneck. The WHIR opening rounds are.

## 3. Per-opening-round profile (real proof)

Each opening round r = WHIR initial + n intermediate rounds + final phase.
`openfold` = per-query Merkle open + fold (step 5 of `verifyRound`);
`sample` = sponge query-index draws; `sumcheck` = round sumchecks.

| Round | total | initial | intermediates | final | openfold | sample | sumcheck |
|---|---|---|---|---|---|---|---|
| 0 | 52.1M | 0.90M | ~30.7M | 14.3M | 27.3M | 0.21M | 0.56M |
| 1 | 189.3M | 5.08M | ~48.9M | 105.0M | 47.8M | 0.33M | 0.66M |
| 2 | 140.3M | 9.49M | ~60.5M | 44.7M | 59.4M | 0.43M | 0.57M |
| 3 | 187.2M | 2.24M | ~81.9M | 65.2M | 80.6M | 0.56M | 0.67M |
| 4 | 206.2M | 2.66M | ~86.3M | 75.8M | 85.0M | 0.62M | 0.58M |

Aggregated hot spots (share of the 1,064M baseline):

| Hot spot | Gas | Share |
|---|---|---|
| **Per-query open+fold (intermediate rounds)** | ~300M | 28% |
| **Final phases (terminal queries + closing sumcheck + terminal constraint)** | ~305M | 29% |
| Constraint identity | 93M | 9% |
| Initial phases | 20M | 2% |
| Decode | 8M | 0.7% |
| Sumchecks (all) | 3M | 0.3% |
| Query-index sampling | 2M | 0.2% |

Composed-fixture per-round numbers (recursion proof, small schedule;
bracketed inside `WhirComposed.t.sol`): round0 8.5M, round1 3.9M, round2 2.2M,
round3 1.6M; final phase 11-54M depending on proof. Useful as a cheap
regression signal; the real proof is the target.

## 4. keccak-f[1600] cost model

The sponge (`lib/sol-whir-p3/transcript/KeccakChallenger.sol`) uses the native
`keccak256` opcode per rate-block flush: `30 + 6/word` gas. A Merkle pair-hash
is 42 gas of opcode; measured `StarkMerkle` path verification is ~1.5-2.5K gas
per level including Solidity overhead — i.e. **the opcode is ~2-3% of path
cost; the loop/memory handling is the rest**. Same conclusion for the sponge:
buffer management dominates the permutation. Optimizations must target memory
traffic and loop overhead, not hashing.

## 5. Optimization targets (ranked by measured share)

1. **openfold (~300M)**: `verifyRound` step 5 copies each query row
   element-by-element (`limbs[j] = input.rowsFlat[base + j]`), then copies
   again into `elems`; `_runOneIntermediate` `_slice`s `rowsFlat` per round and
   `_paths` builds `bytes32[][]` word-by-word from a blob. All are
   `mcopy`-able (EIP-5656, cancun target already set) or removable (read
   through an offset instead of copying).
2. **final phases (~305M)**: needs a finer bracket pass inside `verifyFinal`
   before touching (terminal queries vs closing sumcheck vs terminal
   constraint split unknown).
3. **identity (93M)**: `ConstraintIdentity` + `WhirGadgets` weight building;
   `expandFromUnivariate` and per-instance folds.
4. **decode (8M)**: `bytes memory m = proof` copies 2.8 MB calldata->memory
   (~9 gas/word incl. mcopy); most fields could be read from calldata
   directly. Small win, do last.

EIP-170 constraint: margin is 385 B, so every added helper must pay for
itself in removed code. Assembly `mcopy` loops are size-neutral-to-smaller
than Solidity element loops under via_ir.

## 6. Fine-grained per-round profile (second instrumentation pass, reverted)

Brackets inside verifyRound step 5 (row copy vs openAndFold), verifyFinal
(poly-bind vs terminal queries vs closing sumcheck vs terminal identity),
and per-round decode. Instrumented total 1,089.5M (brackets add ~25M):

| Round | decode | identity | row copy | open+fold | term queries | poly-bind | closing | total |
|---|---|---|---|---|---|---|---|---|
| r0 | 6.67M | 10.66M | 10.95M | 16.18M | 3.24M | 0.07M | 0.05M | 52.15M |
| r1 | 20.53M | 100.48M | 19.62M | 27.93M | 4.02M | 0.09M | 0.06M | 189.42M |
| r2 | 23.82M | 36.35M | 24.79M | 34.29M | 7.34M | 0.21M | 0.08M | 140.34M |
| r3 | 32.71M | 58.05M | 34.92M | 45.24M | 6.32M | 0.10M | 0.05M | 187.25M |
| r4 | 37.98M | 64.63M | 36.20M | 48.29M | 9.93M | 0.23M | 0.09M | 206.32M |
| sum | 121.7M | 270.2M | 126.5M | 171.9M | 30.9M | 0.7M | 0.3M | 975.5M |

The **terminal identity is the single largest consumer (270M, ~25%)**, not the
openings. Its cost is extension-field arithmetic: eqEval (2 ext muls per
coordinate) + selectEval (2-3 ext muls per coordinate) over 1,889 eq/sel
points of 22-26 coordinates, dominated by r1 (100M: 585 points x 26 coords).
Ext4 mul pays four full 256-bit `% MODULUS` divisions (~400-600 gas each) -
the field layer is the multiplier behind identity, openAndFold folds, and
sumcheck checks alike.

## 7. Optimization log (before/after, all on test_verify_accepts_the_real_proof)

Baseline 1,064,286,857 gas. Cumulative so far: **-183,313,383 (-17.2%)**.

| # | Commit | Change | After | Delta |
|---|---|---|---|---|
| 1 | `84198c1` | Hoist per-query limbs/elems out of verifyRound loop (Solidity never rewinds free memory; 170-query rounds grew it monotonically, paying expansion+zeroing per query) | 933,914,346 | -130,372,511 |
| 2 | `c55ed7e` | Same hoist in verifyFinal terminal query loop | 922,081,716 | -11,832,630 |
| 3 | `0db21e7` | mcopy the decode copies (_slice, _ragged, _paths). _repeat stays a loop: mcopy copies a region, it does not repeat a pattern | 893,071,405 | -29,010,311 |
| 4 | `d2c1620` | mcopy the per-query row fill from rowsFlat (both query loops) | 880,973,474 | -12,097,931 |

applyBlock (full pool path): 1,781,295,114 -> 1,548,397,349 (-232.9M, -13.1%).
WhirVerifier runtime code: 24,191 -> 23,872 B (EIP-170 margin 385 -> 704 B).
All 130 forge tests pass at every step; e2e path untouched.

Gotchas recorded the hard way:
- `mcopy` scratch via `add(out, len)` corrupts memory under via_ir (out is not
  necessarily the last allocation). Use `mload(0x40)` scratch or a real region.
- Assembly cannot resolve struct member access (`input.rowLimbs`); bind locals
  outside the asm block. `uint256[] memory` -> `uint256` casts need an asm move.
- Library-level `internal` storage vars break `pure` - thread probes through
  output structs instead.

## 8. Proof-size feasibility: can one transaction carry the settlement?

Measured on the real WBND v4 block bundle (block_composed_bundle.bin):

| Quantity | Value |
|---|---|
| Bundle total | **2,825,568 B** (2.83 MB) |
| CONFIG section | 235,348 B (8.3%) - trusted, pinned at deploy |
| PROOF section | 2,587,128 B (91.6%) |
| STATEMENT section | 3,076 B (0.1%) |
| Calldata gas (16/nz + 4/z: 1.48M nz, 1.35M zero) | **29,063,856** |

PROOF section field breakdown (exact, from the encoder):

| Field | Bytes | % of PROOF |
|---|---|---|
| **eq_points (ext)** | **1,499,456** | **58.0%** |
| **paths_hex (Merkle)** | **810,900** | **31.3%** |
| rows_flat (u32) | 146,560 | 5.7% |
| bound_evals (ext) | 60,128 | 2.3% |
| final_paths + final_rows | 51,476 | 2.0% |
| everything else | ~18,600 | 0.7% |

### One-transaction verdict

- **This appchain: yes, proven.** The node E2E settles in one tx (1.64B gas,
  2.83 MB calldata) with `--block-gas-limit 20000000000 --no-request-size-limit`.
  The RPC transport needs a raised body limit: hex-encoded calldata doubles
  the payload (~5.7 MB JSON), which is why the node E2E runs anvil with
  `--no-request-size-limit`.
- **Mainnet-class chain: no.** Calldata alone costs 29.1M gas versus a ~36M
  block gas limit - one settlement would eat ~80% of a block before executing.
  EIP-4844 blobs cannot help: 6 blobs/tx = 786 KiB max, under a third of the
  bundle. The ChunkVerifier multi-tx carry (sponge serialized across calls)
  is the designed answer for constrained chains: split per round, each tx
  carries that round's rows+paths (~30-190 MB/round worst case... realistically
  per-query batches of ~100 queries ≈ 40 KB), state carries the transcript.

### The eq_points finding (the size headline)

The per-round `eq_points` (D-072 phase 1: zeta-derived OOD group points for
the constraint identity) are **massively redundant**: 46,858 packed-ext
entries, only **470 distinct** (99% duplicates - r1 sends 15,210 entries of
which 105 are distinct). They are NOT univariate expansions (checked: entry
squares do not chain), so they cannot be regenerated by expandFromUnivariate;
they are the batch-layer OOD points, a deterministic function of the
transcript-sampled zeta and per-matrix domain constants (config).

Two size plays, in order of risk:
1. **Dedup wire format (WBND v5)**: dictionary of distinct entries + u16 index
   map. 1,499,456 B -> 108,756 B (-92.7%). Bundle 2.83 MB -> **1.43 MB**,
   calldata 29.1M -> ~14.7M gas. Provably safe (same bytes, indexed), but
   touches encoder + decoder + pin tests.
2. **D-072 phase 2 (full derivation)**: recompute eq_points in the contract
   from zeta + config, drop the field entirely: bundle -> **~1.33 MB**, and
   removes their decode cost too (eq_points dominate the 121.7M decode).
   Needs the exact zeta->point mapping ported from p3-batch-stark.

Floor without eq_points: paths 811 KB + rows 147 KB + evals/sumchecks ~130 KB
≈ **1.0 MB ≈ 10.5M calldata gas**. Paths are irreducible per-query Merkle
authentication (the security of the opening); rows are the opened values
themselves. Below ~1 MB you must change the proof system (smaller fields,
fewer queries, or a different PCS), not the wire.

### Compute floor estimate

Gas is dominated by extension-field arithmetic: identity 270M + openAndFold
folds 172M + row copies 126M + decode 122M (pre-mcopy). The Ext4 mul's four
256-bit `% MODULUS` divisions are the single biggest multiplier: every
identity term, every fold, every sumcheck check pays them. KoalaBear admits a
fast reduce (products fit in 64 bits: fold hi*(2^28-2)+lo, then 31-bit fold +
conditional subtract) replacing ~400-600 gas of division with ~100-150 gas of
shifts. Realistic target: identity+openAndFold shrink 30-40% => verify()
toward **~550-600M** without touching the proof system. Beyond that needs
either the eq_points derivation (kills decode + identity r1 spike) or fewer
queries (security-parameter change, out of scope).

DOCEOF && wc -l .scratch/pq-shielded-rollup/verifier-optimizations.md

## 9. Field micro-benchmarks (10k-iteration loops, overhead subtracted)

Temporary harness (deleted after recording). Corrects the §5 assumption that
`% MODULUS` divisions were the field bottleneck: EVM `mod` is priced by WORD
count of the operands, not bit complexity, so a 256-bit `%` costs ~100 gas,
not 400-600. The fast-reduce plan (fold hi*(2^27-1)+lo) is NOT the win it
looked like; the real cost was (a) hidden memory allocations and (b) lane
re-shuffling between packed ops.

| op | before | after |
|---|---|---|
| ext mul (packed) | ~126 | ~126 |
| ext add / sub (packed) | ~109 / ~97 | same |
| _scalar_mul | **~1,465** (uint256[4] memory alloc) | ~124 |
| eqEval(26 coords) | ~50.5k | **~27.6k** (register accumulator) |
| selectEval(26 coords) | ~44.0k | **~16.3k** (base-scalar fast path) |
| computeRoot(20 levels) | ~8.8k | (open) |
| extLeaf(64 limbs) | ~22.3k | (open) |
| foldRow(16 elems) | ~18.2k | (open) |

## 10. Optimization log continued

| # | Commit | Change | verify() | Delta |
|---|---|---|---|---|
| 5 | `dfa55d5` | allocation-free `_scalar_mul` + doubling-as-add in eq term | 668,478,351 | -212,495,123 |
| 6 | `fc31c07` | register accumulators in eq_poly_eval + selectEval base fast path + decode-time padding-canonical check | 608,497,448 | -59,980,903 |

applyBlock: 1,548,397,349 -> 1,033,870,020 -> 945,207,817. Cumulative from
baseline: **-455,789,409 (-42.8%)**. EIP-170 margin: 704 -> 837 -> 158 B
(the register loops cost code size; the dead generic selectEval path was
deleted to claw some back).

### The malleability finding (soundness, found by the tamper test)

`test_verify_rejects_tampered_proof` flips one bit at len/3 - inside the
low-128-bit PADDING of a packed ext element. The old packed `sub` borrowed
across lanes and happened to make the identity mismatch, so the tamper was
rejected by accident. The register rewrite ignores padding (as every other
consumer does), so the tamper passed. Fix: `_extArr`/`_raw32Arr` now reject
nonzero padding at decode - strictly stronger than the accidental
behaviour, covers every consumer, and tampered proofs revert at 138M gas
(decode) instead of 239M (deep identity). Lanes >= P remain tolerated:
they reduce to their canonical value in every consumer, exactly as before.

Lesson: when replacing arithmetic, re-run the NEGATIVE tests first. The
positive test passing proves nothing about rejection paths.

## 11. Open optimization targets (microbench-ranked)

1. `extLeaf` (22.3k/query): 4 mstore8 per limb -> build 32-byte words from 8
   limbs with shifts+or, one mstore per 8 limbs.
2. `foldRow` (18.2k/query): scratch allocation per call + packed folds.
   The caller's elems buffer is refilled per query anyway - fold can consume
   it in place; and evaluate_hypercube's _fold_once chain can run in
   registers like eq_poly_eval did.
3. `computeRoot` (8.8k/query): abi.encodePacked allocates 64 B per level;
   assembly scratch at mload(0x40) removes 20 allocations per query.
4. elems packing loop in both query loops: `uint256[4] memory coeffs` per
   element per query - inline the shifts instead.
5. eq_points dedupe on the wire (WBND v5, §8): -1.39 MB, -14M calldata gas.

## 12. Optimization log continued (open path + decode)

| # | Commit | Change | verify() | Delta |
|---|---|---|---|---|
| 7 | `eb2ff70` | allocation-free open path: extLeaf scratch, computeRoot scratch pair, foldRow no-copy for arity<=4 | 438,095,749 | -170,401,699 |
| 8 | `9aa1942` | inline ext packing in both query loops (no uint256[4] memory per element) | 403,234,145 | -34,861,604 |
| 9 | `e157366` | constraintWeight Horner without the values array | 399,932,547 | -3,301,602 |
| 10 | `554191d` | decode straight from calldata - the 2.8 MB proof copy is gone | 330,926,128 | -68,996,419 |

applyBlock: 945,207,817 -> 555,282,837. Cumulative from baseline:
**-733,360,729 (-68.9%)**. EIP-170 margin: 158 -> 286 B (the allocation-free
rewrites are smaller than what they replaced).

### The two big lessons of this stretch

1. **The proof copy was 92.4M gas by itself.** Measured directly with a
   probe: `bytes memory m = proof` for the 2.8 MB bundle costs 92,440,927
   gas (memory expansion quadratic term + zeroing + refill) vs 269,304 for
   touching calldata. Every reader now takes `bytes calldata` and uses
   `calldataload`/`calldatacopy`. Note: for a calldata bytes param, `x.offset`
   points at the DATA (probed: calldataload(x.offset) = first data byte),
   unlike `bytes memory` where the length word sits at the base.
2. **Per-query allocations were the open path.** extLeaf (256 B row),
   computeRoot (20 x 64 B encodePacked), foldRow (16-word scratch) = ~23
   allocations per query x ~1,267 queries. Replacing each with scratch above
   the free memory pointer (memory-safe region, keccak before anything else
   claims it) removed expansion + zeroing + refill: -170M in one commit.

### foldRow purity fact (worth remembering)

`KoalaBearExt4.evaluate_hypercube` contracts in place ONLY on its general
path (point.length > 4). The unrolled dims 0-4 fold through registers and
never write `evals`. WHIR's folding factor is 4, so the defensive copy in
foldRow was dead weight for every protocol row; arity > 4 keeps the copy.

### Soundness note carried from the tamper test (see §10)

After the calldata refactor the decode-time padding-canonical check moved
with it (calldataload version) - tampered proofs still revert at decode.
The negative tests caught a real regression during the eq/select rewrite;
they keep earning their keep.
## 13. Calldata-direct decode wave: paths, rows (0d9ea16..1acb195)

Continuation of §12. Same principle, bigger payoff: **the proof bytes are
already in calldata; copying them into memory costs twice** (the copy loop
plus quadratic memory expansion at the ~4 MB heap high-water). Every decode
that a consumer touches once should read calldata directly.

| commit | change | verify() gas | delta |
|---|---|---|---|
| (prev) | paths calldata-direct (7f1fc7d) | 301,758,583 | -19.7M |
| 3f20708 | rowsFlat calldata-direct | 251,013,608 | **-50.7M** |
| 1acb195 | bytecode_hash=none (EIP-170 fix) | (no gas change) | - |

applyBlock: 517,040,179 -> 448,922,974. Cumulative from baseline
1,064,286,857: **-813.3M (-76.4%)**.

### rowsFlat: the single biggest decode win (-50.7M)

The per-round rows decode materialized up to 36,640 canonical uint256 words
(1.17 MB) per big round - measured f-rows 1.22/2.19/3.38/4.88/5.21M - only
for the query loop to mcopy each row into a reused limbs buffer anyway.
Now the decode records the absolute calldata byte offset of the flat u32
LE limbs (same pattern as pathsAbs); \`_loadRow\` in the core expands one row
at a time (u32 LE -> canonical uint256 with the _arr byte-swap) into that
buffer. Dual source: \`rowsCdBase == 0\` selects the memory path so the
JSON-driven internal-API harnesses (WhirComposed.t, WhirFinalPhase.t) keep
working unchanged.

Lessons:
- **\`_arr\` prefix counts WORDS (4 B), not bytes** - first attempt treated it
  as bytes and scaled row offsets by 32 instead of 4 -> LimbOutOfRange.
- **Inlining both row-load branches blew the stack** (Yul "1 too deep");
  extracting \`_loadRow(limbs, flatPtr, rowsCd, base, rowLimbs)\` fixed it.
  The query loop body is at the stack-depth edge: new locals go into
  helpers, not the loop.

### EIP-170: 2 bytes OVER (found + fixed)

After 3f20708 WhirVerifier runtime = 24,578 B > 24,576 B limit. forge test
does NOT enforce EIP-170 - only \`forge build --sizes\` shows it (margin
column). Fixed with \`bytecode_hash = "none"\` in foundry.toml: removes the
~41 B solc metadata CBOR appended to the runtime (not code; nothing pins
the code hash). WhirVerifier now 24,537 B, margin +39 B. **Check
\`forge build --sizes\` after every verifier edit from now on - the margin is
single-digit hundreds of bytes.**

### Fresh phase profile (post-7f1fc7d, probe total 325M vs real 301.7M)

| phase | gas |
|---|---|
| batch-decode + cfg-head | 0.08M |
| round-decode total (5 rounds) | 32.4M (rows 16.9M of it) |
| initial run | ~17M |
| intermediates (all rounds) | ~85M |
| final phase (all rounds) | ~50M |
| constraints-decode | 20.9M |
| identity | 18.6M |

Query-level sub-profile (instrumented core copy, test/GasProbeCore.sol):
- per-round openfold loops: 5.4/2.2/1.2/0.9M (round 0..3 intermediates) -
  Merkle path verify + fold, scales with nq x depth.
- final-openfold: ~1-1.9M per round; domainPoints ~30k; closing-sumcheck
  ~25-50k.
- **terminal-weight (evalConstraintsPoly over allR) is the final-phase
  hog: 3.0/16.4/6.1M per round** - Horner over all folding randomness per
  constraint; round 1's 16.4M stands out (most constraints x longest allR).
- eq_points IS live in every round (each _runRound sets
  constraints[0].eqPoints); a decode-skip for rounds 1+ reverts with
  TerminalClaimMismatch - dead-skip attempt reverted. Wire-level dedupe
  (WBND v5) remains the only way to shrink that 1.48 MB.

Probe mechanics (throwaway GasProfileProbe.t.sol + GasProbeCore.sol,
regenerated from source by python; DELETE before gate):
- gasleft deltas must be \`g_before - gasleft()\` (checked arithmetic
  underflows the other way).
- emit in a pure chain: loosen ONLY the emitting chain or deny=warnings
  bites both directions (8961 vs 2018).



## §14 Fused fold + unroll diet (commits `4da1cb4`, `d4552cf`)

### Fused `_fold_once` (`4da1cb4` + `d4552cf`)

`foldRow` = 16.9k gas/query x 1336 queries = **22.6M** of the open path
(probe: leaf 3.7k + merkle 3.6k + foldRow 16.9k per query). Each of the
15 folds/query ran `sub(); mul(); add()` = three pack/unpack cycles over
the same four lanes. The fused version unpacks a0/a1/r once, keeps
difference lanes unreduced in [1,2P) (the ext-mul reduces mod P anyway),
and folds x_i into the raw product sums before ONE per-lane reduction.
Bit-identical to `add(a0, mul(r, sub(a1, a0)))`; all vectors agree.

verify 251,013,608 -> 244,672,378 (`4da1cb4`) -> **244,549,153** (`d4552cf`).
applyBlock 448,922,974 -> **442,742,092**. Cumulative **-819.7M (-77.0%)**.

### EIP-170 whack-a-mole (the fused fold costs ~270 B of code)

The fused body x 15 inlined copies pushed runtime to 24,809 B (-233 over).
Levers tried, measured:

| lever | size delta | gas delta | verdict |
|---|---|---|---|
| `optimizer_runs` 200->100 | -3 B | +85k | no |
| `optimizer_runs` 200->50 | -30 B | +50k | no |
| dims-4 via general loop | -630 B | **+4.9M** | no (also broke non-mutation contract) |
| foldRow >4 scratch copy removed | -26 B | -26k | yes |
| dims 1/2 unrolled paths deleted | -125 B | ~0 | yes (shape never occurs: WHIR folds 4/round, closing sumcheck appends 3) |
| dims 3 unrolled path deleted | -181 B | +~30k | yes (6 folds x 5 rounds, loop overhead is noise) |

Final: runtime **24,432 B, margin +144 B**, 142 tests green.

**Lesson**: with `via_ir` + 200 runs, code size is dominated by inlined
assembly bodies x call sites. Deleting unrolled paths for shapes the
protocol never produces is free gas-wise; the general loop is correct
(in-place) because no caller reads `evals` after the fold EXCEPT the
dims-4 path where the probe test caught a real dependency - keep dims-4
unrolled (it is also the hot one: 15 folds/query).

### Tamper-test weakness found

`test_tampered_final_poly_reverts` did `finalPoly[0] += 1` - the LOW 128
bits of a packed Ext4 word are padding, ignored by lane arithmetic. It
only reverted by accident (via the terminal identity). Fixed to tamper
lane 0 (`+ (1 << 224)`), a real polynomial change -> reverts at the STIR
check. Padding-bit tampering is NOT a real polynomial change; any future
tamper test must touch bits 128-255.

### Query-level profile (probe, per query, 1336 queries total)

| part | gas/query | total |
|---|---|---|
| leaf decode | 3.7k | 4.9M |
| merkle path | 3.6k | 4.8M |
| foldRow (15 folds) | 16.9k | 22.6M |

### Terminal-weight is the final-phase hog (next target)

Per round: domainPoints ~30k, final-openfold 0.84-1.9M, closing-sumcheck
25-50k, **terminal-weight (evalConstraintsPoly over allR) 3.0 / 16.4 / 6.1M**
- round 1 worst (most constraints x longest allR). Suspect: per-constraint
`localR` allocation + `eq_poly_eval` recomputed per constraint instead of
once per point.


## §15 Fresh full profile at b6d7566 + section-size census (probe regenerated)

The probe (GasProfileProbe.t.sol + GasProbeCore.sol + GasProbeStir.sol) was
REGENERATED from current production (old copies had drifted: stale decode,
stale query loop). Regeneration recipe: copy production file, rename lib,
insert emits at section boundaries, strip pure/view from anything touching
gasleft()/emit (transitive closure), fix import paths. Stack-too-deep rules
learned the hard way:
- a timing local must NOT be live across the query loop (verifyRound is at the
  stack edge) - reuse ONE local g between emits inside verifyRound; the
  openfold pair was dropped (query-loop cost = inter-round minus the rest).
- instrument PRIVATE callees (_loadRow, _paths, _slice) instead of the caller:
  a private fn has its own stack; scoped gasleft blocks in _runOneIntermediate
  still blow up.

### verify() accounting at b6d7566 (probe emits, real bundle)

| bucket | total | notes |
|---|---|---|
| round-run (5 rounds) | 139.9M | intermediates 73.4M + final 50.3M + initial 16.1M |
| - inter-round (17) | 73.4M | verifyRound body incl. query loops |
| - stir-leaf (1336 q) | 10.0M | 7,507/q: Montgomery wire encode 64 limbs + keccak |
| - loadrow (1336 q) | 6.0M | 4,498/q: calldata u32 LE -> canonical words |
| - stir-merkle (1336 q) | 5.8M | 4,365/q: depth ~18-20 keccak folds |
| - stir-fold (1336 q) | 0.2M | 162/q - fused hypercube is FREE now |
| - final-openfold (5) | 6.8M | terminal queries: no merkle, horner over 160 coeffs |
| - terminal-weight (5) | 42.0M | evalConstraintsPoly - arithmetic floor (see §14) |
| initial (5) | 16.1M | round-0 phase: base-row opens + init sumcheck |
| identity (1) | 11.6M | constraint identity recompute (D-076) |
| r-claimfold (17) | 1.9M | gamma-power claim fold |
| r-sumcheck (17) | 1.0M | sumcheck verify |
| r-transcript (17) | 1.0M | digest + OOD absorbs + PoW + indices |
| prf-decode (5) | 1.8M | calldata-direct decode is cheap now |
| cfg-decode (5) | 0.8M | |
| constraints-decode | 0.5M | |
| batch-decode + transcript-walk | 0.1M | |

Residual inside intermediates not covered by emits: _paths copy + per-query
array allocs + expandFromUnivariate/powConstBase loops + pack loop ~= 45M.
_paths is the last big memory-copy site -> next target (calldata-direct).

### WBND section census (words on the wire; probe sz-* emits, 5 rounds total)

| section | words | bytes | status |
|---|---|---|---|
| eqPoints | 193,384 | 773 KB | calldata-direct (b6d7566) |
| paths | 187,960 | 752 KB | **STILL COPIED via _paths** |
| rows | 37,088 | 148 KB | calldata-direct (0d9ea16) |
| finalPaths | 9,192 | 37 KB | copied per final phase |
| finalRowsExt | 4,736 | 19 KB | copied |
| boundEvals | 1,039 | 4 KB | copied (small) |
| roots/baseConsts/invDFlat | 650 | 2.6 KB | cfg, copied once |
| scA/scInf/scPow/powWitnesses | ~340 | 1.4 KB | copied |
| everything else | < 500 | | negligible |

Memory high-water at end: 2.07 MB (mfree-end emit). paths is ~750 KB of it.

### Decisions

- D-080 paths calldata-direct: RoundInput gains pathsCdBase/pathsOff;
  StarkMerkle gets a calldata sibling reader; _paths/_repeat deleted if the
  memory path has no test callers. All paths in a round share one depth
  (schedLogFolded[i]) so the grid is regular: query q siblings at
  pathsAbs + (pathOff + q*depth)*32. Expected 10-20M.
- D-081 terminal-weight slice kill: evalConstraintsPoly allocates a localR
  slice per constraint (501 x 24 words in round 1). eq_poly_eval only reads
  p[0..q.length] - pass allR directly, bound by q.length. ~3M.
- D-082 extLeaf single-mstore: replace 4x mstore8 per limb with one
  mstore(shl(224,w)) into an over-allocated buffer (n*4 + 28 slack),
  keccak over n*4. ~3M.
- EIP-170 margin +220 B at b6d7566: offset new code by deleting dead
  extrapolate_012_reference / mulReference (verify emission first).

## §16 Paths calldata-direct + the EIP-170 collapse (commit `9593730`)

D-080 landed. verify 207,507,093 -> **199,476,544** (-8.03M), applyBlock
362,255,177 -> **352,907,822** (-9.35M). Cumulative 1,064.3M -> 199.5M
(**-81.3%**). 145 forge tests green. EIP-170 margin +57 B (24,519 B runtime).

### What shipped

- `RoundInput`/`FinalInput` gained `pathsCdBase`: absolute calldata byte
  offset of the FIRST query's sibling path. All queries in a round share
  `schedLogFolded[i]`, so query q's path is at `pathsCdBase + q*depth*32`.
  `WhirVerifier` sets it from `p.pathsAbs` (+ `cur.pathOff*32` folded in at
  the call site, no separate field - see the stack lesson below).
- `StarkMerkle.computeRootMix/verifyMix`: ONE fold loop, per level
  `switch cdBase case 0 { mload } default { calldataload }`.
- `StirOpenings.openAndFold` takes `(pathsFlat, memOff, siblingsCdBase, ...)`.
  `pathsFlat` is a FLAT `bytes32[]` (query-major) for the JSON harnesses;
  production passes an empty array + nonzero cdBase.
- Deleted `_paths`, `_repeat` from WhirVerifier; harnesses (`WhirRoundPhase`,
  `WhirFinalPhase`, `WhirComposed`) build flat arrays.

### Lessons (cost the whole session)

1. **Two-source = one loop with a switch, never two loops.** A separate
   `openAndFoldCd` + duplicated fold loop cost +458 B and put the contract at
   -238 B under EIP-170. The single mixed loop costs ~35 B.
2. **`pathsCdBase == 0` must be re-zeroed per query.** `cdBase + q*depth*32` is
   nonzero for q>0 even on the memory path, so the switch misread calldata and
   every composed-phase test reverted `OpeningNotAuthenticated`. The call site
   passes `pathsCdBase == 0 ? 0 : pathsCdBase + q*depth*32`. Pinned by tests
   that keep the memory path.
3. **Struct fields are stack slots.** Adding `pathsMemOff` to RoundInput pushed
   `_runOneIntermediate` past the Yul stack edge (`var_j is 2 too deep`) - the
   struct is a single stack item but its field accesses spill. Fold offsets at
   the call site instead of storing them.
4. **Shape guards on memory-only fields cost real bytes.** Dropping the two
   `paths.length == numQueries` checks (unreachable in production, harnesses
   build exact-size arrays) bought back 39 B. `forge test` cannot catch a
   bad-array harness - it panics with an empty revert, not a shape error.
5. **Dead-code deletion is not a size lever.** `extrapolate_012_reference`,
   `mulReference`, `_mulCoeffsReference` were already stripped by the optimizer:
   zero bytecode change. Only code that is *reachable* occupies the budget.

### Updated WBND census (post-D-080)

| section | words | bytes | status |
|---|---|---|---|
| eqPoints | 193,384 | 773 KB | calldata-direct |
| paths | 187,960 | 752 KB | **calldata-direct (9593730)** |
| rows | 37,088 | 148 KB | calldata-direct |
| finalPaths | 9,192 | 37 KB | copied per final phase |
| finalRowsExt | 4,736 | 19 KB | copied |
| boundEvals | 1,039 | 4 KB | copied |
| rest | < 1,500 | | negligible |

Remaining memory copies are now < 60 KB total, so the calldata-direct wave is
essentially finished: the ~490 gas/word copy tax is gone from 96% of the wire.
Next levers are arithmetic, not I/O: D-081 (terminal-weight localR slice kill),
D-082 (extLeaf single-mstore), and the terminal-weight floor itself (42M).

## §17 Fused row loader, deferred fold mods, _packElems (commits 6b31a72, 35abbfa, e6a15e6)

Three landed levers since §16:

1. **Deferred convolution-lane reductions in `_fold_once`** (`6b31a72`). The four
   convolution lanes t_i accumulated products then each took a `mod` before the
   final add; `mod` distributes over the additions that build the lane, so the
   intermediates only need congruence + non-wrapping. Worst lane t3 < 4*2^62 <
   2^65, x3+t3 < 2^66, never wraps; every caller feeds reduced values so the
   bound holds at every fold-tree level. 8 mods -> 4 per fold. Bit-identical.
   verify 199.48M -> 197.96M.

2. **`_packElems` unchecked assembly pack** (`35abbfa`). The Solidity loop that
   packed 4 canonical limbs into one word per element paid a bounds check per
   limb read (~500 gas/element); one assembly pass over the freshly loaded limbs
   cut r-elems 10.07M -> ~6M. verify 197.96M -> 193.15M.

3. **Fused row loader `_loadRowFused`** (`e6a15e6`). The query loop walked each
   opened row three times: `_loadRow` decoded wire limbs into memory, `extLeaf`
   re-read the buffer for the Montgomery-LE leaf encoding, `_packElems` re-read
   it again for the fold elements. One pass straight from calldata now produces
   both the leaf scratch bytes and the packed elements; `openAndFold` splits so
   `openAndFoldLeaf` takes the pre-built digest. The per-query RowWidthMismatch
   check moves to a once-per-round rowLimbs-vs-rowElems check (soundness: the
   loader folds leaf and elements from one decode, so the width relation must
   hold before the first query). verify 193.15M -> 188.75M, applyBlock 346.53M
   -> 342.45M.

**Size discipline lesson**: the first fused version duplicated the decode for
base/ext rows and blew EIP-170 (24,915 B, -313 margin). `forge test` stayed
green the whole time - only `forge build --sizes` shows the margin. The unified
single-loop version (per-limb `switch rowsAreBase`) is 24,373 B (+203) and
within 0.2M gas of the duplicated version: code size beats branch hoisting at
this margin. Also: forge-lint's `incorrect-shift` heuristic flags
`shl(sh, 0xffffffff)` (literal value operand); hoisting the mask to a local
variable silences it without losing the masked-write pattern (the lane
accumulator alternative cost +2.5M gas).

**Calldata-branch bench (recorded from the TerminalWeightBench harness)**:
copying eq groups from calldata into a scratch costs ~140K gas over the memory
path for 501x24 groups (15.60M vs 15.46M) - the copy overhead is negligible
against the arithmetic, which is why the calldata-direct pattern is free to use
wherever it saves a decode pass.

**Probe pipeline state**: `python3 /tmp/probe_pipeline.py && forge build`
regenerates GasProbeVerifier from HEAD sources; profile at 35abbfa in §16
table; i-transcript split (12.69M/2.96M/0.29M) confirmed the sponge absorbs
are the initial-phase cost, not the sumcheck math.

## §18 The ceiling: minimal gas to verify this proof (user question, answered twice)

Bundle: WBND v4, 1,967,592 B payload (cfg 46,523 words + prf 444,602 words),
34.0% zero bytes (669,950), 61,491 words on the wire with header. Current
verify(): 188,749,491 gas at e6a15e6.

### Part 1 - the calldata floor (just passing the proof)

EIP-2028 pricing: 16 gas/nonzero byte, 4 gas/zero byte, +21,000 intrinsic.

    nonzero 1,297,642 B x 16 = 20,762,272
    zero      669,950 B x  4 =  2,679,800
    payload calldata gas      = 23,442,072
    + selector/offset/length/padding = 23,442,168
    + intrinsic 21,000        = 23,463,168  ~= 23.46M

**23.46M gas is the absolute floor for ANY on-chain verification that takes this
proof as calldata** - a contract that does nothing at all. That is 12.4% of the
current 188.75M. No compute optimization touches it; only shrinking the bundle
does (see Part 3).

Is it too large for one transaction? On permissive local/devnet infra: no -
anvil runs with --block-gas-limit 20000000000 --no-request-size-limit and the
whole verify fits. On mainnet-like limits it is borderline-to-impossible:
23.4M calldata gas alone is 78% of a 30M block, and default RPC/txpool size
gates (geth 64 KiB tx, 5 MiB RPC body) reject 1.97 MB without flags. The
execution gas (165M) exceeds any L1 block; this design targets an L2/high-limit
settlement chain, which is what the goal specifies.

### Part 2 - compute floor, bottom-up from measured primitives

Fresh FieldMicroBench anchors at e6a15e6 (per-op, minus ~81 gas loop overhead):
ext mul ~423, ext add/sub ~103, mulBase ~124, square ~313, eq_poly_eval 26-coord
~25.2K, computeRoot depth-20 ~4.5K, foldRow(16) ~11.0K, keccak256(64B)=42 gas
(30+6*2), keccak256(256B)=78.

Protocol work inventory (from the §16 profile, 1,336 total query-folds across
5 rounds + final):

| block | current | floor | why |
|---|---|---|---|
| calldata+intrinsic | 23.46M | 23.46M | EIP-2028, irreducible |
| round-run arithmetic (sumcheck folds, constraint folds, claim folds) | ~126M | ~105M | already deferred-mod + register-carried; ~15% Solidity-overhead slack remains in call boundaries |
| terminal-weight (identity eq groups, 5x501x24) | 42.0M | ~39M | eq_poly_eval measured 22,899 vs arithmetic floor 22,549 per 24-coord group - AT floor; the 3M slack is the per-constraint localR allocation (D-081, queued) |
| initial phase | 16.0M | ~6M | i-transcript 12.69M is per-element observeBase call overhead (~300 gas/elem vs ~40 assembly floor); batched absorbs are the single biggest remaining lever |
| stir-fold (1,336) | 15.3M | ~12M | 11.5K/query vs ~9.5K register-fold floor |
| stir-leaf + decode (1,336) | ~9M | ~5M | fused loader landed; remaining is the per-limb mod+swap chain (floor: one mulmod-free reduce per limb) |
| stir-merkle (1,336) | 6.5M | ~2M | pure keccak floor is 420 gas/query (10x42); Solidity path verify costs 4.9K; full-assembly path verify ~1.5K |
| inter-round glue + transcripts | ~60M | ~48M | sumcheck observe/draw call overhead |
| final phase + identity glue | ~50M | ~40M | horner + claim folds, mostly at floor |
| everything else | ~20M | ~15M | decode, PoW, domain points |

Sum of floors: **~150M gas** (23.5M calldata + ~127M compute). Realistic
landing zone after all identified work: **160-170M** (the last 10% is
call-boundary surgery inside hot loops with stack-depth limits biting).

Sanity cross-check: pure keccak work in the proof is ~2M gas total (sponge
flushes + Merkle), pure ext-field arithmetic is ~90M at a ~250-gas assembly
floor per ext-mul-equivalent, decode ~5M - 117M + calldata = ~140M, consistent
with the table. The proof is arithmetic-dominated: hashing is only ~1.5% of
the floor. This is why the keccak-f[1600] port idea was dead on arrival and
why every real win so far has been field arithmetic or decode passes.

### Part 3 - the size lever (calldata floor is NOT fixed)

Section census: eqPoints ~773 KB (39%), paths ~752 KB (38%), rows 148 KB,
finalPaths 37 KB, finalRowsExt 19 KB, rest small.

- **eqPoints are transcript-deterministic** - the eq evaluation points are
  functions of challenges the verifier already samples. Recomputing them
  in-circuit (the recursion circuit already does exactly this) deletes ~773 KB:
  calldata floor 23.46M -> ~14.2M. Cost: recompute arithmetic (~the terminal
  weight already evaluates eq polys; the points themselves are cheap
  products). This is the single biggest total-gas lever identified anywhere.
- **paths**: batched/folded Merkle opening (one folded check instead of 1,336
  explicit paths) deletes most of 752 KB -> another ~6M calldata gas, at the
  cost of a folding challenge round (D-072 phase 2 territory).
- Both together: bundle 1.97 MB -> ~0.45 MB, calldata floor ~5.4M, total floor
  ~132M.

### What this means for the optimization queue

1. localR kill (D-081): -3M, trivial, queued now.
2. Batched transcript absorbs: -8 to -10M, next biggest compute item.
3. Assembly Merkle path verify: -4.5M.
4. eqPoints recompute (wire format v5): -773 KB calldata (-9.2M) + removes the
   decode/copy pass (~15M) - biggest single item, needs prover-side change.
5. Everything else is call-boundary polish toward the ~150M floor.

## §19 Can we beat 150M? Floor decomposition + deployment architecture (post-absorb-batch)

State at 42d8cea: verify 179,928,504 (applyBlock 331,736,448), EIP-170 margin
+40 B. Fresh eqPoints census from the real block bundle: 1,889 groups
(26+585+130+274+874), each a square-power expansion of ONE univariate the
transcript already draws (p3-whir reader.rs: `expand_from_univariate(transcript.ood_point(), n)`).

### Correction to §18

§18 credited eqPoints derivation with "-9.2M calldata + ~15M compute". The
compute half was wrong: the calldata->scratch copy measured negligible
(15.60M vs 15.46M memory path), and DERIVING each group costs n=24 squares
(~7.5K) that eq_poly_eval does not pay - ~+14M compute across 1,889 groups.
Derivation is a SIZE lever (-773 KB, -9.2M calldata gas, net ~+5M gas), not a
gas lever. §18's "total floor ~132M" becomes ~140M.

### The honest floor decomposition (current protocol shape)

    calldata floor (this bundle)      23.5M   EIP-2028, irreducible per byte
    ext-field arithmetic floor        ~90M    ~250 gas/ext-mul-equivalent in
                                              full assembly; protocol fixes the
                                              op count (folds, eq evals,
                                              sumchecks, constraint weights)
    keccak floor                      ~2M     sponge flushes + 1,336x10 Merkle
    decode/parse floor                ~5M     fused loader already near it
    call-boundary + glue overhead     ~25M    the ONLY big soft target left
    ------------------------------------------------
    hard floor                        ~140M   realistic landing ~150-155M

So: **yes, below 150M is possible, but only by ~10M on gas** - the floor is
protocol-bound, not implementation-bound. Every remaining gas lever is
call-boundary surgery (assembly Merkle -4.5M, sumcheck/fold inlining -8M,
localR kill -1.6M). The bundle-size levers (derivation, path folding,
deploy-once constants) move the 1.97 MB to ~0.3 MB - which is what satisfies
TX-SIZE limits (geth 64 KiB default tx gate, RPC body caps, mainnet block
gas), not the gas number.

### Deployment architecture (the combination answer)

Bytecode limit (EIP-170) - midfall pattern, applied at COARSE phase
boundaries only (per-call overhead is noise per-phase, fatal per-op):

    ShieldedPool (3.8 KB)
      -> WhirVerifier (core loop, 24.5 KB, margin +40 B)
           staticcall -> TerminalWeight satellite  [42M-gas constraint identity;
                        codehash+length pinned at construction; raw memory frame
                        as calldata, no ABI codec - midfall ExternalPinned]
           extcodecopy <- WhirConstants data contract [deploy-once cfg constants,
                        midfall Halo2VerifyingKey pattern; also removes ~180 KB
                        from every proof's calldata]

    Trigger: when the next compute optimization needs >40 B of code, extract
    the terminal-weight phase first (frees ~6-8 KB, costs ~2K gas per verify).

Calldata/tx-size limit - GOAT philosophy (derive, don't ship), WBND v5:
    eqPoints section dropped (derived from transcript draws)      -773 KB
    cfg constants dropped (deploy-once contract)                  -180 KB
    Merkle paths folded (D-072 ph.2: one folded check, not 1,336) -700 KB
    => 1.97 MB -> ~0.32 MB; calldata floor 23.5M -> ~5.4M; fits any chain.

IOHK discipline (already in force): hard specialisation to one circuit shape,
byte-exact mirroring of the Rust verifier as source of truth, benchmark-driven
iteration (this file IS their docs/benchmark.md equivalent).

Mainnet-L1 note: even at 0.32 MB the ~140M compute floor exceeds a 30M block;
the design targets the high-limit settlement chain the goal specifies. If L1
ever matters: EIP-4844 blob for the proof + a cheap blob-hash check on-chain.
