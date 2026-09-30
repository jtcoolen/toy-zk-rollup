# 16 - Recursion audit gate

Type: task
Status: open
Blocked by: 11

## Question

`p3-recursion` is unaudited and its README says not to use it in production. What is
the gate between "foundation works" and "allowed to hold value"?

## Answer shape

A checklist that must be green before any mainnet deployment:

- [ ] `p3-recursion` pinned rev audited by a named firm, report published.
- [ ] `slh-dsa` pinned rev audited (or RustCrypto ecosystem audit letter accepted).
- [ ] `StarkVerifier.sol` audited separately — it is written by us, not off-the-shelf.
- [ ] Test-vector round-trip suite (ticket 12) runs against the audited revs.
- [ ] Circuit version pinned on-chain; upgrade path exercised on a testnet.
- [ ] Bug bounty live before value-bearing.

## Why this is a ticket and not a note

It blocks a decision (mainnet go/no-go) and it is work someone must do. It is kept
visible on the map so the foundation is never mistaken for something deployable.

## Interim posture

For the foundation and any testnet: unaudited is acceptable **with the pin recorded**
so that when an audit happens, the exact audited artifact is identifiable.
