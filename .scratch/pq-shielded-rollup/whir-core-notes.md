# WHIR verifier core — working notes (D-059)

Status: design settled, code starting. Governing instruction: shortest path to a
**working** verifier, optimise later.

## 1. What the decoded semantic program actually says

`contracts/test/vectors/whir_semantic_program.bin` (production shape: 25 vars,
4 rounds, 257 queries) decodes to 175 schedule entries, 2778 transcript
operations:

| kind | ops | meaning |
|------|-----|---------|
| CONST | 1849 | base absorbs fixed by the config/shape |
| VAR | 669 base + 7x32 raw | proof-derived absorbs (evals, OOD answers, caps, separators) |
| SAMPLE | 224 | base draws (ext4 challenges = 4 each) |
| UNIFORM | 779 | STIR index draws |
| WITNESS | 23 | PoW checks |

Head of the program (entry: kind arg run):

```text
 0 CONST 0 67      <- fixed absorption before the first layout separator
 1 COMMIT 4 1      <- raw bytes: layout domain separator (virtual claims)
 2 VAR 0 1         <- bound virtual claim (1 base = one OOD answer coeff? no: bind)
 3 CONST 0 1
 4 SAMPLE 1 4      <- ext4 draw = the virtual-claim point
 5 COMMIT 4 2      <- second separator
 6 SAMPLE 1 4
 7 CONST 0 54
 8 SAMPLE 1 4      <- alpha (batching challenge)
 9 VAR 0 4         <- first round evals
10 CONST 0 86
11 VAR 0 16
12 CONST 0 169
13 SAMPLE 1 4      <- initial sumcheck r0
14 CONST 0 37
15 VAR 0 8          <- sumcheck round coeffs (c0,cinf) x 4 rounds
16 SAMPLE 1 4
...
23 COMMIT 4 1      <- round-0 cap
24 SAMPLE 1 4      <- gamma
25 VAR 0 4
26 WITNESS 8 1     <- round-0 PoW
27 UNIFORM 10 205  <- 205 index draws = 41 queries x 5 bits
```

Load-bearing conclusions:

* The transcript program is **shape-fixed**: 1849 of the absorbs are constants.
  They are the layout/sumcheck **domain separators and shape fingerprints** that
  `p3-sumcheck` absorbs when opening a sub-transcript.
* There are exactly **7 raw-byte absorbs** = 3 layout separators (virtual claims,
  opening claims, batching) + 4 sumcheck separators (initial + 3 round sumchecks).
  Matches the earlier reading of `src/transcript.rs:265,359,469`.
* Therefore the on-chain verifier does **not** need a port of the
  `p3-sumcheck` layout/shape/fingerprint machinery. It absorbs **verbatim byte
  blobs** exported by the prover at the sites the engine structure dictates.
  This is the single biggest reduction in remaining work.

## 2. Decision D-059: export the fixed transcript program, do not port layout shapes

Options considered:

1. **Port `p3-sumcheck` layout shapes + fingerprints to Solidity.** Faithful in
   principle, but `LayoutVerifierTranscript`, `InteractionPattern`,
   `ShapeFingerprint`, `OpeningShape`, `VirtualShape`, `BatchingShape` are ~4k
   lines of Rust whose only on-chain purpose is to produce a handful of byte
   strings. Reimplementing them is exactly the class of bug (a misread
   convention that agrees with itself) that D-058 exists to prevent.
2. **Export the fixed absorption runs as opaque constants** (chosen). The Rust
   side runs the real prover through the semantic sink and emits, per fixed run,
   the exact bytes. The Solidity core absorbs them at structurally known sites.
   Soundness argument: a fixed run is a *challenge-domain separator*, not a
   claimed value. Every proof-derived value (commitment, OOD answer, opening
   value, PoW witness) is written by the core itself at a VAR site, so nothing
   the prover controls is ever replaced by a constant. If a proof-derived value
   were misclassified as fixed, the challenges would diverge and verification
   would fail - and the cross-check test compares the core's own walk against
   the recorded program, so it fails loudly, not silently.
3. **Generic transcript interpreter in Solidity** (execute the schedule blob at
   runtime, filling holes from the proof). Cheapest to write, but it makes the
   verifier's transcript depend on a data blob shipped next to the proof, which
   is the wrong trust boundary: the blob would have to be pinned by the contract
   (hash it) or it is attacker-controlled. Rejected as the primary path; the
   schedule is instead compiled into the generated config contract.

## 3. Shape for the first end-to-end port

Production shape (25 vars / 4 rounds / 257 queries) is the target but not the
first test: 257 queries x ~40k gas cannot fit one transaction (D-039 chunking is
a later step). The core is written generically over the generated config, and
validated first on a **small shape**:

```text
num_variables = 13, folding 4 -> rounds 13 -> 9 -> 5 -> final 1
cap_height = 0, security_level small enough that num_queries stays tiny
pow_bits = 0 (grinding off) so the first port has no PoW path to chase
```

Same code path, different generated constants.

## 4. What the vector generator must emit

One JSON per shape, from the prover's own types (D-058: never a reimplementation):

* `proof_hex` - postcard of `WhirUniProof` (the exact bytes the contract decodes).
* `commitments` - initial cap + one cap per round, as 32-byte hex.
* `points` / `values` - the prescribed opening points and their claimed values,
  in `protocol.iter_openings()` order (matrix-major, then point).
* `claimed_eval` - the initial combined claim.
* `initial_constraint` - `ConstraintWeightData`: num_variables, gamma,
  initial_power = 0, eq_points in placement order.
* `fixed_absorb[]` - the fixed byte runs, in order, each with its index.
* `samples[]` / `uniform[]` / `witnesses[]` - the recorded draws, so the Solidity
  walk can assert every challenge it computes.
* `accept: true` plus negative variants (tampered eval, tampered Merkle sibling,
  wrong claimed_eval) each expected to reject.

## 5. Existing Solidity primitives the core composes (already tested)

| file | provides |
|------|----------|
| `ProofCodec.sol` | postcard cursor over calldata, canonical-varint strict |
| `StarkMerkle.sol` | keccak leaf/path/root over base-field limbs |
| `StirOpenings.sol` | `openAndFold`, `horner`, `domainPoint`, `extLeaf`, `foldRow` |
| `SumcheckCore.sol` | `verifyRounds` ({0,1,inf} fold), `sampleExt4`, `extrapolate01inf` |
| `WhirGadgets.sol` | `expandFromUnivariate` (BE), `eqEval`, `selectEval`, `powConstBase`, `powersCombination`, `constraintWeight`, `evalConstraintsPoly` |
| `WhirFixedConfig.sol` | generated schedule incl. per-round `foldedDomainGen` |
| `lib/sol-whir-p3/transcript/KeccakChallenger.sol` | sponge, `observeValidatedPackedExt4`, `checkWitness`, `sampleBitsUnchecked` |

## 6. Open items tracked here

* `univariate_eq_point` needs an extension inverse - `KoalaBearExt4.inv` exists.
* `lift_prefix` puts selector bits FIRST (Prefix order); `StackedSelector.index`
  is already bit-reversed within its own width - the export must hand the
  Solidity side the *final* coordinate list, never the raw index.
* All shape validation happens **before** any challenger use
  (`uni/pcs.rs:656-785` pre-pass). The core must do the same or a malformed
  proof burns gas before it is rejected.
* Final PoW has **no transcript checkpoint after it** (verifier.rs:270-290).

