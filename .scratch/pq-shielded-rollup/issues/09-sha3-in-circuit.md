# 09 - SHA3-256 in-circuit: patch keccak-air padding

Type: research
Status: resolved (shipped: crates/prover/src/sha3_block.rs, `sha3_framed` in transfer.rs; pinned against pq_hash by `sha3_statement_matches_native`)
Blocked by: 02

## Question

`p3-keccak-air` proves the Keccak-f[1600] permutation. SHA3-256 is the same
permutation with `0x06` domain padding instead of Keccak's `0x01`. How much work is a
SHA3-256 AIR, and is patching upstream the right move or do we wrap?

## What to find out

1. Does `p3-keccak-air` constrain the padding at all, or only the permutation?
   (Read `keccak-air/src/air.rs`, `generation.rs`, `round_flags.rs`.)
2. Where is the absorb/squeeze rate boundary enforced? `RATE_BITS = 1088` is defined in
   `lib.rs` — is it used in constraints or only in trace generation?
3. Is the padding a **trace-generation** concern (free — just fill the input bytes
   correctly) or a **constraint** concern (needs AIR changes)?
4. If it is trace-only: SHA3-256 = `generate_trace_rows` with `0x06` padding + a
   domain-separation prefix. **Wrap, do not fork.**
5. If it is constraint-level: how invasive is a patch, and would upstream take it?

## Why this matters

The shielded layer's preferred hash (ticket 02) is SHA3-256. If this is a wrap, the
shielded layer ships SHA3 today. If it is a fork, the shielded layer ships SHA-256
first and SHA3 lands later — which changes the wallet's address derivation and should
be decided **before** any address format is frozen.

## Known facts already gathered

- `p3-keccak-air` exposes `generate_trace_rows(inputs, extra_capacity_bits)` taking
  raw permutation inputs, and `KeccakAir::generate_random_trace_rows` for benches.
- `p3-sha256-air` exists as a fully-formed in-circuit SHA-256 with prime and binary
  field variants, so a SHA-256 fallback is off-the-shelf regardless.
- SHA3-256 and Keccak-256 differ **only** in the padding byte (`0x06` vs `0x01`).
