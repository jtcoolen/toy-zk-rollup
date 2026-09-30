# 01 - Destination: PQ shielded pool on Plonky3, EVM-settled

Type: grilling
Status: resolved
Blocked by: —

## Question

What is this map finding its way to? A spec, a decision, or a change in place — and how
far does the destination extend?

## Answer

**A working design plus a compiling foundation** for a post-quantum shielded-value pool
in the Zcash/MantaPay shape:

- **Proving**: STARKs only, via Plonky3 (`p3-uni-stark` base layer) and
  Plonky3-recursion (`p3-batch-stark` aggregation layers). **No SNARKs at any layer.**
- **Settlement**: an EVM-compatible chain, verifying the final STARK **directly** in
  Solidity. No trusted bridge, no committee.
- **Privacy model**: notes + nullifiers (Zcash-style), with MantaPay's per-asset
  separation available as a parameterization.
- **PQ**: every primitive is post-quantum. Hash-based signatures (SPHINCS+) for spend
  authorization; SHA-2/SHA-3 family for hashing.
- **Wallet**: a MetaMask-style MV3 extension with good UX and PQ key custody.

The destination is **not** a live network, an audit, or economic tuning. It is: every
crate compiles, the base→recursive proof path runs end to end, the Solidity verifier
compiles against the agreed proof ABI, the wallet loads, and all remaining depth is
captured as tickets rather than fog.

This fixes scope. Anything past it (mainnet, audits, bridges to existing chains, FHE
approaches) is Out of scope on the map.
