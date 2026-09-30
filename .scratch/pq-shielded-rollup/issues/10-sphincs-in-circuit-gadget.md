# 10 - In-circuit SPHINCS+ spend-authorization gadget

Type: prototype
Status: open
Blocked by: 06, 09

## Question

How does SPHINCS+ verification live inside the transfer AIR, and what does it cost?

## Shape of the answer

A `SpendAuthGadget` that, given a circuit `Target` for the message (the spend
authorization digest) and a `Target` for the public key hash, constrains a valid
SPHINCS+ signature. Composed from:

- **WOTS+ chain stepping** — a fixed number of hash iterations per Winternitz digit.
  Reuses the SHA-256 chip.
- **FORS tree** — a small Merkle tree of WOTS+ public keys. Reuses the Merkle gadget.
- **Hypertree / XMSS layers** — the outer tree path. Reuses the Merkle gadget.
- **PRF / hashing of the message** — SHAKE-256 (or SHA-256, per ticket 09).

All of these are the *same two chips* the note layer already uses. That is the whole
point of choosing SPHINCS+.

## What must be measured, not guessed

- SHA-256 compression rows per spend. `slh-dsa-shake-128s` verify touches roughly
  ~1,700 SHA-256-family compressions (WOTS+ ~1,664 + FORS ~2·log + tree ~2·log).
  Against a note layer that needs ~2–4 compressions per note, **one spend costs about
  as much as a thousand note hashes.**
- Whether the SHA chip needs a lookup-table (logup) shape to amortize, and whether it
  can share the table with the note-hash chip.
- Which parameter set minimizes circuit cost — note this is *not* the same as the set
  that minimizes signature size. `slh-dsa-shake-128f` verifies ~16× faster than `128s`
  at the cost of larger signatures. For a circuit-bound system, **`f` may win.**

## Deliverable

A prototype circuit proving a real `slh-dsa` signature verifies, with a measured
row/column count, feeding the decision on parameter set.

## KISS note

Do **not** implement SPHINCS+ from scratch. Generate the witness with `slh-dsa`
natively and constrain only the verification path. The native crate is the reference
implementation; the circuit is a mirror of its verify function, checked against it in
tests.
