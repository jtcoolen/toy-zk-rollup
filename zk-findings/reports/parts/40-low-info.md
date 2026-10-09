## Low-severity findings

**L-01 — `SealedVault::from_bytes` panics on crafted length bytes.** `crates/vault/src/lib.rs:336-349` assumes 16/12-byte salt/nonce but both lengths are attacker-controlled and `bytes[pos]` / `bytes[pos..pos+3]` are not bounds-checked. A crafted vault file in the unlock flow panics (and in a native `panic=abort` build, aborts the process). Remediation: bounds-check every length field before indexing. (Agent D D07.)

**L-02 — `insecure-stub` signing feature lacks the claimed release guard.** `crates/pq-sign/src/stub.rs:80-84` gates its `compile_error!` on `#[cfg(test)]`, so a `--release --features insecure-stub` build compiles; the cited `assert_stub_absent_in_release` does not exist. Not reachable today (no crate enables the feature). Remediation: add a crate-level `#[cfg(all(feature="insecure-stub", not(debug_assertions)))] compile_error!`. (Agent D D09.)

**L-03 — Token hygiene.** `crates/node/src/auth.rs:306-373` base64url decoder accepts non-canonical trailing bits, so each token has four valid encodings (malleable); no maximum TTL and `now+ttl` can overflow (`main.rs:851`); a 1-byte key file is accepted (`main.rs:139-146`); no revocation route exists; tokens are deterministic in (role, expiry) with no per-user identity. Remediation: reject non-canonical base64url, cap TTL, require a minimum key length, add rotation/revocation. (Agent D D11.)

**L-04 — Statement completeness / data availability.** `statementRoot` has no on-chain consumer and the per-transfer data is never published, so users cannot prove their own inclusion or rebuild the tree without the sequencer (`contracts/src/ShieldedPool.sol:92-99`, `contracts/src/BlockStatement.sol:17-24`). This is the data-availability root cause behind H-01; tracked separately as a completeness gap. (Agents B B-08, D D15.)

**L-05 — Block header split validated only by sum; membership path length unchecked.** `crates/prover/src/block.rs:181-183, 480-488` accepts any shape with the same `n_in + n_out` (e.g. (2,0) for a (1,1) child); `crates/prover/src/transfer.rs:716-756` never checks `path.len() == DEPTH` (the native `tree.rs:132-134` does). Remediation: bind each child's exact split and assert the path length. (Agent B B-10, B-11.)

**L-06 — wallet-wasm zeroization gaps; keystore tmp-symlink write.** `crates/wallet-wasm/src/lib.rs:158-169, 301-346` returns plain `Vec` copies of password and vault and leaves `sk_d` arrays unwiped; `crates/node/src/keystore.rs:81-101` opens `<path>.tmp` without `O_NOFOLLOW`/`O_EXCL` and writes the secret before checking the target type (a planted symlink receives it). `seal`/`write_private` are not used by the binary. Remediation: wrap secrets in `Zeroizing`; use `O_NOFOLLOW|O_EXCL` and check the target before writing. (Agent D D10, D12.)

**L-07 — R randomization commitment adds no hiding; upstream ZK guard removed.** `vendor/p3-recursion/recursion/src/pcs/whir/uni/pcs.rs:31-35` claims R masks the opened trace values, but R is opened only as a separate claim and never mixed into the trace/quotient arguments; hiding comes entirely from the interleaved random rows. Separately, the local patch removed upstream's `is_zk` guard in `backend/whir.rs` without upstream support or tests. Remediation: correct the doc claim; add regression tests for the enabled ZK path. (Agent C L-01, L-02.)

**L-08 — SLH-DSA parameter notes wrong; pre-release dependency.** `crates/pq-sign/src/lib.rs:21-24` says "128f ~16x faster than 128s" and "8KB signature"; 128f is roughly 3x more verify work than 128s and the signature is 17,088 bytes; `crates/node/src/wire.rs:42` says the verifying key is 64 bytes but it is 32. `slh-dsa 0.2.0-rc.5` is a pre-release with `// TODO context processing` in its verify path. Remediation: correct the rationale that drives the in-circuit cost estimate; pin a released version before production. (Agent D D08, D13.)

## Informational observations

- **I-01 — Soundness knobs are environment-configurable in library code:** `WHIR_SECURITY_LEVEL`, `WHIR_SOUNDNESS_REGIME` / `WHIR_INNER_SOUNDNESS_REGIME`, `WHIR_POW_FLOOR` / `WHIR_INNER_POW_FLOOR`, `WHIR_INNER_RATE`, `WHIR_FOLDING_FINAL`, `WHIR_FINAL_LDE` (`crates/prover/src/whir.rs:126-189`, `whir_recursion.rs:186-193, 314-353`). A deployment that sets these loosely silently weakens security. Pin them in a reviewed config, not process env.
- **I-02 — Documentation drift (spec deltas).** README and comments describe SHA3-256 notes/nullifiers and a Keccak commitment tree (code is Poseidon2 throughout); an "operator set" for `applyBlock` (none exists); a Keccak depth-256 empty nullifier root (code is a Poseidon2 depth-96 constant). `vendor/p3-recursion/PATCHES.md` lists one of five changed code files, misdescribes the ZK patch ("const false->true", "evaluation truncation"), and points to a pristine directory that does not exist. Full list in the specification, section "Specification deltas".
- **I-03 — Fixture keys compiled into the production node.** The node binary is built with the prover `testkit` feature (`crates/node/Cargo.toml:15`), so genesis notes are owned by public fixture keys and the demo genesis / SPHINCS+ keys are public. Combined with H-01/M-01 this is why the shipped configs are exploitable by anyone. Remove `testkit` from the production build.
- **I-04 — Fees are burned; the fee-recipient role is vestigial.** The circuit enforces `in = out + fee` but the contract has no payable path; `withdrawFees` is dead code (`contracts/src/ShieldedPool.sol:88-89, 182-189`).
- **I-05 — Gas.** One verification is ~102M gas, above the L1 block limit (a completeness risk on mainnet); the settlement submitter hard-codes `GAS_LIMIT = 20e9` (above every public chain limit) and has no RPC timeout or TLS and treats one receipt as final (`crates/node/src/settlement.rs`).
- **I-06 — Spent-nullifier oracle.** `/v1/transfer` answers "already spent" for any self-signed nullifier, exposing spent-set membership to any submitter (`crates/node/src/main.rs:619-659`).
- **I-07 — Minor in-circuit divergences from native p3.** 0-bit proof-of-work leaves the witness unconstrained (malleability); the circuit samples query indices by low-bit truncation while native rejection-samples (they diverge only at the sampled value `p-1`, a completeness issue); the in-circuit batch verifier omits `check_multiplicity_height_bound` (matters only combined with V-06). (Agent C I-02..I-04.)

## Discharged / false positives (selected)

The reviewers confirmed the following are **not** issues on the audited revision, each with a rejecting location:
- Value conservation is a true integer equality (biased carry chain, every column term below 2^25; `crates/prover/src/transfer.rs:792-844`); amount and carry limbs are range-checked; no negative values.
- Digest export limbs are canonical (`decompose_to_bits(.,31)` asserts `< p`); roots pass a strict decode.
- Within-transfer and within-block duplicate nullifiers are rejected by the threaded absence chain and the native `seen` set; within-pool replay is blocked by L1 continuity.
- HMAC token verification is constant-time and checks the MAC before parsing; the ACL matches paths exactly and unmatched paths return 404 without the guard.
- Vault crypto is sound: Argon2id (m=64 MiB, t=3, p=1), per-vault random salt and nonce, GCM tag verified before plaintext, no KDF-parameter downgrade.
- Entropy is correctly sourced (OS RNG / `crypto.getRandomValues`, short entropy refused).
- The settlement ABI encoding and selector are correct; the extension CSP is sound.
- The challenger's `sampleBase` rejection bound, byte order, and sponge flush match p3; query indices are uniform.
