# 11 - Recursion layer configuration and arity

Type: grilling
Status: open
Blocked by: 10

## Question

How many recursion layers, what arity per layer, and what FRI parameters, so the final
proof fits the Solidity verifier's gas budget?

## Known from the recursion API

`p3-recursion` exposes `PreparedLayer` / `build_and_prove_next_layer` with a
`FriRecursionConfig` implemented over our `StarkConfig`. Knobs:

- `log_blowup` (LDE rate)
- `max_log_arity` (FRI folding arity per phase)
- `log_final_poly_len`
- `query_pow_bits` (query count)
- `recompose_lanes` (ops packed per AIR row)

## The tension

More layers → smaller final proof → cheaper L1 verification, but more total proving
time and more accumulated circuit complexity. Fewer layers → cheap proving, huge
on-chain proof.

The answer is a number derived from measurement, not taste: target the L1 verifier at
**< 3M gas**, and pick the smallest layer count that gets there.

## Depends on ticket 10

The base circuit width is set by the SPHINCS+ gadget. A wide base needs more recursion
to compress. Cannot be answered before 10 is measured.
