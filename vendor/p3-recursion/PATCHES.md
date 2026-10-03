# Local patches to Plonky3-recursion

This tree is a vendored copy of <https://github.com/Plonky3/Plonky3-recursion>,
taken at rev `8f9876efb26cff0f4b837555b478f043c4314240` and then patched.

It is vendored rather than consumed from git because the patch is **load-bearing for
security**, not cosmetic. Upstream hardcodes `const ZK: bool = false` on the WHIR
univariate PCS, which makes every blinding branch in `p3-uni-stark` dead code. In
a shielded pool that is not a performance issue: spend secrets are witnessed
in-circuit, and unblinded trace openings are known-coefficient linear combinations
of every witness cell, so the secret is recoverable from the published proof.

Full rationale: `.scratch/pq-shielded-rollup/decisions.md` (D-046).

## Reproducing the patch

A pristine copy of the upstream rev is kept at
`.scratch/vendor/p3-recursion-pristine`. The complete local diff is:

```sh
diff -ruN .scratch/vendor/p3-recursion-pristine vendor/p3-recursion > zk-blinding.patch
```

And to re-apply onto a fresh checkout of the upstream rev:

```sh
git apply zk-blinding.patch
```

## Patch inventory

Each entry is one logical change. See the code comments at each site for the
mechanics, and D-046 for why.

| # | File | Change |
|---|------|--------|
| 1 | `recursion/src/pcs/whir/uni/pcs.rs` | `const ZK: bool = false` -> `true`; hiding-aware `commit`, `commit_preprocessing`, `get_opt_randomization_poly_commitment`, and evaluation truncation. **Applied.** |

## Item 2: withdrawn, not a hole

The original item 2 read: "Replace the `NO_RANDOM_OPENED_VALUES` stub with a real
implementation of `get_fri_random_opened_values`" in
`recursion/src/pcs/whir/uni/recursive_pcs.rs`. It is **not needed for WHIR**, and
implementing it would add surface for no gain. Verified against the code:

- That stub is only reached when `PRE_OBSERVES_OPENED_VALUES` is true
  (`recursion/src/verifier/batch_stark.rs:1528`).
- WHIR sets `PRE_OBSERVES_OPENED_VALUES = false`
  (`recursion/src/pcs/whir/uni/recursive_pcs.rs:384`), because WHIR interleaves
  its own opened-value observation instead of pre-observing.
- The random commitment is bound in-circuit by the ordinary path anyway:
  `batch_stark.rs:1275-1276` observes `random_commit` into the challenger and
  `:1299-1317` pushes `(random_commit, random_round)` into `coms_to_verify`, so
  the R commitment and its opening points enter the same Merkle/PoW checks as
  every other commitment.

So the stub is unreachable for the PCS we ship. Re-verify this if a future rev
flips `PRE_OBSERVES_OPENED_VALUES` for WHIR, or if a second PCS with
`ZK = true` is added to a batch alongside WHIR. Recorded as D-051.

## Upgrading

To move to a newer upstream rev: re-vendor, re-apply the patch, and re-run the
whole gate. The blinding changes touch the proof *shape*, so every golden vector
under `contracts/test/vectors/` and the Solidity verifier's expected layout must
be regenerated in the same commit that moves the rev. A silently drifted proof
shape is a silently broken bridge.
