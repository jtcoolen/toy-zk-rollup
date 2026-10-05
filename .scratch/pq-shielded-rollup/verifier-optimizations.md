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

## 6. Optimization log (before -> after)

_(numbers land here as each change is committed; every entry keeps
`forge test` green, and the e2e node settlement re-verified at phase end.)_
