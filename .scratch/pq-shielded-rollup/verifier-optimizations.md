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
