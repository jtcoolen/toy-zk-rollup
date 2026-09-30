# 15 - Transcript hash portability (escape hatch from the Poseidon2 exception)

Type: research
Status: open
Blocked by: 05

## Question

How do we eventually remove the Poseidon2 exception without rewriting the recursion
engine every time?

## What to find out

1. `p3-recursion`'s `ChallengerPermConfig` is already the seam. What would a
   `Sha3ChallengerPermConfig` require?
   - An in-circuit SHA3-256 sponge (from ticket 09).
   - A `CircuitChallenger::duplexing` branch that is not Poseidon1/2. Today that
     branch `panic!`s.
2. Is the `duplexing` dispatch extensible from outside the crate, or does it need an
   upstream PR? (Read `recursion/src/challenger/circuit.rs` dispatch.)
3. What is the circuit cost delta: Poseidon2 W16 vs SHA3-256 sponge for the same
   number of challenges? If SHA3 is within ~2× of Poseidon2 for the recursion
   transcript, the exception is unnecessary and should be removed.
4. Does `p3-challenger`'s native `DuplexChallenger` accept a SHA3 permutation
   natively (i.e. is the *native* side already portable, leaving only the in-circuit
   side)?

## Why it matters

The Poseidon2 exception is the one place the design violates its own stated rule. If
this ticket finds the swap is cheap, the exception disappears and the system becomes
uniformly SHA-based — a materially cleaner story for auditors and for the PQ
property argument.

## Known

- Native side: `p3-challenger::DuplexChallenger<F, P, WIDTH, RATE>` is generic over
  `P: Permutation`, so a SHA3-based `P` should slot in natively today.
- In-circuit side: `CircuitChallenger` hard-dispatches on `as_poseidon2()` /
  `as_poseidon1()` and panics otherwise. **This is the blocker.**
