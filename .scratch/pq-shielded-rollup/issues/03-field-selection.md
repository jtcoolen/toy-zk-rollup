# 03 - Field selection: KoalaBear + quintic extension

Type: grilling
Status: resolved
Blocked by: 01

## Question

Which prime field for the STARK and the recursion layers? This drives proof size,
recursion throughput, how SHA limbs are constrained, and which `p3-recursion` code path
is best exercised.

## Answer

**KoalaBear (31-bit) with a quintic (D=5) challenge extension.**

### Why

- `p3-recursion` is most heavily exercised on KoalaBear (326 references vs 285 BabyBear
  in the recursion crate), and its example suite explicitly supports
  `--field koala-bear --quintic`.
- KoalaBear is the **only** field the recursion examples support the quintic extension
  for (`assert_quintic_field` panics otherwise). D=5 buys the security margin we want
  at 31-bit: ~128-bit conjecturable security against the FRI/proximity parameters we
  intend to use.
- 31-bit limbs mean SHA-256's 32-bit words decompose into a fixed small number of
  limbs, which is exactly what `p3-sha256-air` already does.

### Rejected

- **BabyBear** — equally supported but no quintic path; would need D=4, slightly weaker
  per-query margin for the same proof size.
- **Goldilocks (64-bit)** — fewer limbs per SHA word, but the 31-bit-optimized gadgets
  (Poseidon2 W16, the recursion recompose paths) are tuned for Monty-31 fields, so we
  lose more than we gain.

### Consequence

Everything downstream pins `KoalaBear` + `D=5`. Changing the field later means
re-deriving the recursion config and the Solidity verifier's field arithmetic, so this
is a one-way door and is recorded here deliberately.
