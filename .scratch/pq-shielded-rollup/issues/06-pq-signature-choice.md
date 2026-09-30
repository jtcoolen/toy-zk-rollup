# 06 - PQ spend authorization: SPHINCS+ over lattice signatures

Type: grilling
Status: resolved
Blocked by: 02, 03

## Question

A shielded transfer must prove the sender is authorized, **inside the circuit** —
otherwise the prover can forge spends. Which PQ signature is verifiable in-circuit at a
cost we can live with?

## Answer

**SPHINCS+ (`slh-dsa`), hash-based.**

### The deciding argument

In-circuit verification cost is dominated by what primitives the signature's *verify*
path needs:

| Signature | Verify needs in-circuit | Circuit cost |
|---|---|---|
| **SPHINCS+** | SHA-256/SHAKE compressions, Winternitz chain steps, Merkle paths | **Reuses the SHA AIRs we already need** |
| ML-DSA (Dilithium) | NTT/lattice ops, modular reduction over a 2304-degree ring, rejection sampling | New lattice gadgets, ~10⁴+ extra constraints per verify |
| ECDSA/EdDSA | — | **Not PQ. Excluded outright.** |

SPHINCS+ verification is *entirely* hash-based. We are already building in-circuit
SHA-256 (`p3-sha256-air`) for note commitments. The signature verifier reuses that
same chip and its lookup table — no new arithmetic, no new field gadgets. That is the
KISS answer and the cheap answer at the same time.

### Parameters

`slh-dsa` 0.2.0-rc.5, SHAKE-192 / `slh-dsa-shake-128s` as the starting point
(smallest signature, ~8KB, fastest verify). The exact parameter set is a
**performance** decision that graduates once the in-circuit gadget is measured — see
[10](10-sphincs-in-circuit-gadget.md).

### Why not hybrid SPHINCS+ + ML-DSA

Doubles the circuit cost and the key management surface for no gain in this design.
SPHINCS+ is conservative *because* it is hash-based: its security reduces to SHA-2/3
collision and preimage resistance alone. A hybrid would only hedge against a break of
hash functions, which would break our commitment scheme too — so the hedge is not
independent. Rejected.

### RustCrypto caveat

`slh-dsa` is at `0.2.0-rc.5` (RustCrypto's PQ release line). It is well-reviewed
code in the RustCrypto ecosystem but not formally audited. Same posture as
`p3-recursion`: fine for the foundation, gated before mainnet.
