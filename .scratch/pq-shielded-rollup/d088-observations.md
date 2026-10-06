# D-088 execution log (running)

## O-1 — Vendored perm-row API (confirmed by reading source)
- `CircuitBuilder::add_perm(PermConfig, &PermCall) -> (NonPrimitiveOpId, Vec<Option<ExprId>>)`
  at vendor/p3-recursion/circuit/src/ops/perm.rs:135. `PermCall` fields:
  new_start, merkle_path, mmcs_bit, mmcs_bit2, inputs (Vec<Option<ExprId>>, width_ext),
  out_ctl (Vec<bool>, rate_ext), return_all_outputs, mmcs_index_sum.
  NOTE: the config-less `PermCall` has NO absorb_len (that's the typed
  Poseidon2PermCall); add_perm passes absorb_len: 0. So a plain add_perm row is
  a merkle/normal row, never a length-tagged sponge row.
- Builder validates geometry at call time (poseidon2_perm/builder.rs:24-36):
  merkle_path requires mmcs_bit Some; non-merkle requires None; mmcs_bit2 iff
  arity-4 shape. KOALA_BEAR_D4_W16 is arity-2 => mmcs_bit2 must be None.
- Private sibling data per row: `perm_private_data(cfg, sibling: Vec<F>)`
  (perm.rs:122) — the executor reads capacity slots from here when inputs
  slots are None (merkle chaining rows).
- `add_mmcs_verify` (ops/mmcs.rs:81) is the reference binary fold:
  * first row: new_start=true, merkle_path=true, inputs[0..rate_ext]=leaf ext,
    mmcs_bit=dir, out_ctl=[false;rate_ext] unless final
  * chain rows (non-first): sibling ext goes in inputs[rate_ext + j]
    (capacity slots), new_start=false, mmcs_bit=Some(zero)
  * final row: out_ctl=[true;rate_ext]; outputs = take(rate_ext) of returned
    Vec<Option<ExprId>>; these are EXT elements whose base coefficients are
    the native digest elements (D4: 2 ext = 8 base = 8-element digest)
  * empty path: connect leaf digest directly to root
- The AIR's merkle placement (per docs mod.rs:14 + mmcs.rs usage): with
  merkle_path=1, the executor places the running hash and the sibling into the
  rate slots according to mmcs_bit; capacity slots carry the *next* row's
  sibling via private data. The exact witness-side placement is what
  commitment_gadget tests must pin empirically (O-2).

## O-2 — Test strategy for the gadget (settles semantics without guessing)
The vendored tests (arity4_mmcs.rs etc.) exercise add_mmcs_verify end-to-end
with the real prover. Our gadget test mirrors that at the smallest scale:
build a tiny circuit with one append gadget, generate witness natively with
pq-hash Poseidon2Commitment, run the circuit witness/air through the same
pipeline the transfer tests already use (fixtures.rs pattern), and assert
accept + root match. If merkle-mode placement differs from my model, the test
fails loudly and I correct the gadget — not the other way around.

## O-3 — Statement-shape coupling census (from grep)
- Keccak commitment sites that must become Poseidon2 with the statement change:
  prover/src/fixtures.rs:122 (tree_with), transfer.rs tests (930,1060,1185),
  prover/tests/golden_vectors.rs (410,446,541,797), composed_vectors.rs:171,
  node/src/state.rs:43,105, node/tests/sequencer.rs:131.
- shielded/tests/contract_vectors.rs stays Keccak until step 7 deletes the
  Solidity MerkleAccumulator it cross-checks.
- wallet-wasm + shielded tree/note tests already Poseidon2 (commit 2ee73fd).

## O-4 — Sponge gadget decision (leaf hashing)
Leaf = PaddingFreeSponge over 63 limbs (126 bytes... NO: 63 FIELD elements =
63 limbs, 8 rate chunks: 7 full + 1 partial of 7). The vendored
add_hash_base_coeffs_overwrite (recursion/src/pcs/mmcs.rs:79) implements
exactly PaddingFreeSponge overwrite semantics for base coeffs, including the
partial-chunk carry (keeps previous perm output in untouched rate slots —
matches my pq-hash test finding). BUT it operates on Target (recursion layer)
not ExprId, and needs recompose_base_coeffs_to_ext_via_alu for full ext
elements. For D4/W16: rate_ext=2 ext slots = 8 base elements per row; 63
elements = 8 rows (7 full ext-pairs + 1 partial). Plan: implement a small
`p2_sponge_limbs` on ExprIds mirroring add_hash_base_coeffs_overwrite's
overwrite logic with recompose/decompose via_alu helpers (same functions the
vendored code uses), then unit-test against pq-hash::Poseidon2Commitment::hash
on the exact DOMAIN_NOTE preimage shape.

## O-5 — Merkle placement read from the AIR (poseidon2-circuit-air/src/air.rs ~990-1100)
Transition (next row merkle, !new_start): local_out rate slot i flows to
next_in[i] when mmcs_bit=0 (running hash is LEFT child) or to
next_in[RATE_EXT+i] when mmcs_bit=1 (running hash RIGHT child). The sibling
occupies the other slot, supplied via the next row's exposed inputs.
=> The chain flow is FORCED: consecutive merkle rows cannot branch. My merge
phase needs pass-through when bit=0 (no compression), which a forced chain
cannot express. DECISION: use independent new_start rows in NORMAL mode
(merkle_path=false, mmcs_bit=None) with explicit select-driven placement:
inputs = [left_ext0, left_ext1, right_ext0, right_ext1] (4 ext = 16 base =
full width), out_ctl=[true,true]. compress(l,r) = perm(l(8)||r(8)||0(8))[0..8]
maps to ext slots [l0,l1,r0,r1] (D=4: ext0=base[0..4], ext1=base[4..8], ext2
=base[8..12], ext3=base[12..16]). This is the vendored
add_hash_base_coeffs_overwrite pattern (new_start + exposed inputs), just
hand-placed. Cost: 4 ext selects per compress instead of free AIR placement —
trivial ALU, and it makes the gadget self-contained (no private-data plumbing).

## O-6 — Append gadget math (corrected; the naive fold is WRONG)
Merge (bottom-up): g[-1] = leaf digest; for h in 0..32:
  merged_h = H(f[h], g[h-1])            (frontier left, running right)
  g[h]     = select(b[h], merged_h, g[h-1])
Fold to root over n' = n+1 bits b'[h] (b' = b XOR carry, carry[h]=AND(b[0..h])):
  cur = empty[0]; for h: cur = select(b'[h], H(g[h], cur), H(cur, empty[h]))
Key lemma (why g[h] is the right subtree at level h when b'[h]=1):
 - carry_in[h]=0, b[h]=1: b'[h]=1, g[h]=merged ✓
 - carry_in[h]=1, b[h]=0: b'[h]=1 and g[h]=g[h-1] (merge skipped) ✓
 - carry_in[h]=1, b[h]=1: b'[h]=0, unused ✓
Each fold row = ONE perm with selected inputs:
  left = select(b'[h], g[h], cur); right = select(b'[h], cur, empty[h]).
root_before consistency: fold(f, b) == pinned root_before (third fold, 32
perms). Total per append: 32 merge + 32 fold + 32 before-fold = 96 perms
(vs ~768 AIR rows for Keccak). Constrain carry_out = AND(all b[h]) = 0 (tree
not full). Bits b[h] are boolean witness; frontier f[h] = 2 ext private
inputs per level.
NATIVE MIRROR MUST BE TESTED FIRST: frontier fold == tree.root() for n in
0..~40 (the Rust tree is the spec).

## O-7 — ext/base plumbing at the statement boundary
Digest = 8 base elements = 2 ext elements (D=4). Statement keeps 16x16-bit
limbs per digest (contract compatibility, LIMBS_PER_DIGEST=16 unchanged):
export = decompose each ext to 4 base coeffs (decompose_ext_to_base_coeffs_
via_alu), then each base element e -> lo(16b) + hi(15b) via bit decomposition
(decompose_to_bits::<F>(e, 31) recombined). Leaf sponge absorbs the 63 limb
exprs directly (limb = base element); partial final chunk (63 = 7x8 + 7)
mirrors PaddingFreeSponge overwrite: ext slot 3 = recompose([e60,e61,e62,
prev_out_base3]) — vendored add_hash_base_coeffs_overwrite does exactly this
with recompose_base_coeffs_to_ext_via_alu / decompose_ext_to_base_coeffs_via_alu.

## O-8 — Executor merkle row semantics CONFIRMED (poseidon_perm/executor.rs:124-260)
Arity-2 merkle row: init_chain_state copies prev output RATE (rate_ext=2 ext)
into state[0..2]; fill_sibling_data writes private sibling (cap_ext=2) into
state[2..4]; exposed inputs overwrite any slot; mmcs_bit=1 swaps rate halves
(apply_merkle_swap). So one merkle row = compress(left,right) with running
hash seeded from the previous row's rate output — a FORCED chain, one row per
compress, no branching. add_mmcs_verify's two-rows-per-level is an artifact of
MMCS opening layout, not needed by us.
DECISION (final): our gadget uses INDEPENDENT new_start rows in NORMAL mode
(merkle_path=false, mmcs_bit=None): inputs[0..4] = [L0,L1,R0,R1] all exposed
(selects), out_ctl=[true,true], return_all_outputs=false. outputs[0..2] =
rate = perm(L(8 base)||R(8 base))[0..8 base] = compress(L,R). Fully explicit,
no private data, no chaining. 4 ext selects per compress = trivial ALU.
Leaf sponge rows: first row new_start=true exposed rate inputs; chained rows
new_start=false merkle=false (init carries FULL width per executor normal
mode), exposed inputs overwrite rate slots only. Partial tail chunk: mixed
ext slot via decompose(prev out ext)->coeff->recompose, exactly vendored
add_hash_base_coeffs_overwrite semantics (matches pq-hash PaddingFreeSponge
test-pinned behavior).

## O-9 — FINAL append-gadget design (AIR-verified, supersedes O-6/O-8 details)
AIR fact (air.rs ~120): on a NON-challenger table a new_start row's capacity is
caller-fed — independent compress rows with all 4 ext slots exposed are legal.
AIR fact (air.rs ~1190-1215, non-compact D4, RATE_EXT==CAPACITY_EXT): merkle
chain transition gated on (!next.new_start && next.merkle_path): local_out
rate -> next_in[0..2] if bit=0 (running hash LEFT) else next_in[2..4] (RIGHT).
Executor order: init(prev rate->[0,1]) -> fill_sibling(private->[2,4]) ->
apply_witness_values(exposed overwrite any slot) -> swap if bit. => on chain
rows expose the SIBLING at ext slots [2,3] in BOTH bit cases (swap lands it
correctly). mmcs_index_sum=None is fine (add_mmcs_verify precedent).
Layout per append (96 perm rows, fixed shape):
  A) 32 MERGE rows, independent (new_start=true, merkle=false, all 4 inputs
     exposed: [f0,f1,g0,g1], out_ctl=[t,t]): g[h] = select(b[h], out, g[h-1]).
  B) 32-row merkle CHAIN fold_before: row0 new_start=true (zero state =
     empty[0] seed), rows h: mmcs_bit=b[h], inputs[2..3]=select(b[h], f[h],
     empty[h]) (2 ext selects), final out_ctl=[t,t]. Result == root_before
     (connect to caller's pinned root).
  C) 32-row merkle CHAIN fold_after with b', f' where increment bits:
     c[0]=1, c[h+1]=c[h]&b[h]; b'[h]=b[h]+c[h]-2bc; d[h]=c[h](1-b[h]);
     f'[h]=select(d[h], g[h], f[h]). Assert carry-out c[DEPTH]=0 (tree not
     full). Same fold shape as B.
Fold lemma (tested natively first): cur=empty[0]; for h: cur = b[h]?H(f[h],cur)
:H(cur,empty[h]) == tree.root() (blocks of n's binary decomposition, ascending
h = rightmost first). Merge: g[-1]=leaf; g[h]=b[h]?H(f[h],g[h-1]):g[h-1].
Frontier update matches zcash incremental tree (break at first zero bit).
Leaf sponge: 8 rows over 63 limbs (7 full ext recomposes + 1 partial mixing
prev rate coeff via decompose/recompose via_alu), first row new_start=true,
rest chained normal mode. Mirrors vendored add_hash_base_coeffs_overwrite.
Export digest->16 limbs: decompose ext->4 base coeffs (via_alu), each coeff
decompose_to_bits::<F>(31), lo=bits[0..16], hi=bits[16..31]. Non-uniqueness
window (coeff vs coeff+p) cannot forge a contract-accepted root: limbs must
match the contract's stored bytes; honest path canonical. Document.

## O-10 — FINAL: uniform independent rows (supersedes O-9 chain plan)
mmcs_index_sum AIR recurrence fires on EVERY (!new_start && merkle) transition
ungated by ctl (air.rs ~1245); executor fills ZERO when mmcs_index_sum=None
(executor.rs:416-422). add_mmcs_verify passes None + real bits and only the
runner (connect checks) is exercised in vendored tests — the AIR recurrence is
a proving-time concern I do not want to inherit. DECISION: all gadget rows are
INDEPENDENT new_start=true, merkle=false rows with ALL 4 ext slots exposed:
  compress(L,R): inputs=[L0,L1,R0,R1], out_ctl=[true,true], outputs take(2).
AIR: merkle chain + mmcs recurrence gated on next.merkle_path => inert.
new_start capacity caller-fed on non-challenger tables (air.rs doc ~121) =>
legal. Cost: 4 ext selects per fold row (trivial ALU vs 1 perm row).
Sponge rows: first new_start=true (zero state, capacity not exposed -> zero),
chained rows new_start=false merkle=false, rate slots exposed (ctl disables
rate chain), capacity chains from prev output (AIR-gated, executor matches).
Frontier math (native mirror FIRST, tested vs tree.root()):
  frontier: for h with bit h of n set: f[h] = complete subtree of height h
  ending at leaf n (blocks tile [0,n) ascending).
  root(f,bits): cur=empty[0]; for h: cur = bits[h]?H(f[h],cur):H(cur,empty[h])
  merge: g[-1]=leaf; g[h]=bits[h]?H(f[h],g[h-1]):g[h-1]
  increment: c[0]=1,c[h+1]=c[h]&b[h]; b'[h]=b[h]^c[h]; assert c[DEPTH]==0
  root_after: cur=empty[0]; for h: cur=b'[h]?H(g[h],cur):H(cur,empty[h])
Export digest->16 limbs: decompose_ext_to_base_coeffs_via_alu then
decompose_to_bits::<F>(coeff,31) -> lo=bits[0..16], hi=bits[16..31]. Off-p
window (p..2^31) cannot forge: limbs must match the contract-stored root and
the next block's fold re-derives the true root from the pinned root_before.

## O-11 — Step 3 landed (commit pending): commitment_gadget.rs
- Uniform independent-row design (O-10) WORKS: compress/sponge/append all pass
  the runner. 6 tests: fold==tree.root (n=0..40), incremental==rebuild,
  circuit compress==native hash_pair, circuit sponge (63 limbs, partial final
  chunk exercises the decompose-carry path)==native Poseidon2Commitment::hash,
  circuit append==tree root at n in {0,1,5,8,13,32}, wrong-frontier rejected.
- BUG FOUND BY TESTS: append_to_frontier must CLEAR bits on carry (bits are the
  binary count, not a monotone set). Circuit side already correct (XOR form).
- digest_to_ext: Challenge::from_basis_coefficients_slice on 4-elem halves;
  Digest32 bytes are LE u32 per base elem (canonical < p), so halves pack
  elems[0..4] -> lo, elems[4..8] -> hi.
- Test digests must be canonical: zero the top byte of each 4-byte group.
- Sponge row shape: inputs[ext] = Some(recomposed) only for slots with filled
  coeffs; None slots chain the previous output (AIR rate-chain disabled by
  out_ctl=true? NO - rate chain is gated on !out_ctl; exposed slots are
  CTL-checked against my recomposed expr, which already embeds the prev-rate
  coeffs for the partial tail, so semantics match PaddingFreeSponge exactly).
- clippy: ok_or with struct literal -> ok_or_else; bool->usize via From;
  needless Result on pure builder fn; doc backticks KoalaBear/PaddingFreeSponge.

## O-12 (step 4, entanglement audit)
The signature changes cascade further than the step plan assumed:
`prove_client_transfer` now takes the P2 tree (source of truth for root,
root_after, frontier), so every caller — block tests, golden/composed vector
generators, node main.rs, sequencer test — must hand it a tree, and the node's
`PoolState` tree itself must become `CommitmentTree<Poseidon2Commitment>` for
the workspace to compile. Steps 4+5+6(node part)+8(mechanical plumbing) are
therefore merged into one green commit; the contract (step 7) and the vector
regeneration that feeds the forge tests stay separate, because the contract's
Keccak accumulator and 3-root statement parsing only break when the *vectors*
regenerate — forge goes red exactly at step 6/7 and is restored there.
Block.rs shape math (statement_len +16, root_after_offset) landed with step 4
since the child-statement length check would otherwise reject every client
proof. RootAnchor becomes a CHAIN (pin first root_before, chain
root_after→next root_before, expose block root_after) — same shape as
NullifierChain; with the append in-circuit the chain is strictly stronger than
the old pin (it also forbids nothing-spent-but-something-appended ordering
lies). Recorded as plan refinement, not a deviation.

## O-13 (step 4, node-side cascade)
The in-circuit append moved a protocol boundary the step plan underweighted:
before D-088 every transfer in a batch witnessed the SAME committed tree root
(the contract re-derived the tree on apply); now each transfer attests its own
`root_after` and the block circuit chains children root_after->root, so the
sequencer must maintain a *pending commitment-tree projection* exactly the way
it already projects the nullifier map. Landed:
* `PoolState::commitment_tree()` accessor (clone, like `nullifier_map()`);
* `Sequencer.pending_tree` + `client_tree()`; `submit` checks against
  `pending_tree.root()` and appends the transfer's outputs on admission;
  `produce_block` rebuilds both projections from committed state + queue;
* `check_admit_against` gained `expected_tree_root` (both roots now come from
  the caller's snapshot - committed or pending - none is hardwired);
* `PoolState::apply` now probe-checks `root_after` against the tree appends
  before mutating (same discipline as the nullifier `after` root);
* wire format: `TransferWire.root_after` + wallet-wasm `stmt_from_json` +
  popup.js/smoke.mjs statement fixtures (popup's manual-send path is
  envelope-only/501, so its root_after is a documented placeholder - the
  proving path is /v1/demo/transfer, which now proves against client_tree()).
Block/node test adapters now advance the tree between chained children - the
adapter mirrors what the sequencer does on apply, which is what makes the
block's commitment-chain tests meaningful instead of accidentally tripping the
chain before the intended failure.

## O-14 (step 6+7 landed; the gas story was wrong and is now measured)

- Roots-only pool landed: ShieldedPool stores attested `rootAfter` (no
  MerkleAccumulator, no leafCount, no output loop). BlockStatement decodes the
  4-digest transfer tail (root, rootAfter, nfBefore, nfAfter) and chains
  rootAfter->root across transfers ("commitment chain broken").
- **The "~150M gas saved" claim was false.** Measured at 42d8cea vs HEAD:
  - pool body alone (stub verifier): 536,961 -> 533,459 gas. The Keccak
    accumulator append of ONE leaf was ~100K gas, never 150M.
  - The 151.8M gap between applyBlock (331.7M) and the standalone verify test
    (179.9M) was the *block proof* being bigger than the batch_stark proof the
    verify test uses - pool-side work was ~0.5M all along.
  - Full e2e applyBlock: 331,732,998 -> 353,975,800 (+22.2M). Cause: the block
    circuit now carries Poseidon2 perm tables, so the composed proof grew
    (bundle 2,825,568 -> 2,964,384 B, +34,704 words) and its replay costs
    correspondingly more. The append work moved on-chain -> in-circuit, and the
    proof carries the cost.
  - Honest framing: roots-only is a correctness/simplicity win (contract can
    never diverge from the prover's tree; one fewer lib; ~4K gas), not a gas
    win. The gas win of D-088 is prover-side: Poseidon2 fold (1 perm/row) is
    cheap enough to afford doing the append in-circuit at all.
- MerkleAccumulator.sol deleted (no production user). MerkleProof.sol stays:
  reference Keccak fold cross-checked against StarkMerkle (StarkMerkle.t.sol)
  and pinned by the regenerated MerkleVectors.t.sol. contract_vectors.rs no
  longer writes merkle.json (the generated test embeds the openings; the JSON
  was never read).
- block_vectors.json: dropped pool_root_after_hex (no pool-side tree to
  mirror); added root_after_hex. block_genesis.json: added genesis_root_hex
  (Poseidon2 root of the funded-note tree); pool_root_after_hex there is now
  the P2 tree-after-append - BlockE2E asserts the pool stores exactly it, so
  it cross-checks the in-circuit fold against an independent Rust tree walk.
- P2 empty root pinned in ShieldedPool.t.sol:
  0x7a92872da0d9532a933f5f5a8d140b60bba8c80cde1fe868edc23b538844d82e.
- forge: 130 tests green (was 146; the drop is mostly the untracked D-086
  probe suites moved out of the tree, plus the deleted accumulator vector
  test; the pool suite gained a decode-chain test and keeps 9). EIP-170:
  WhirVerifier 24,536 B (+40), ShieldedPool 3,267 B. Untracked D-086 probe
  files (GasProbe* etc.) moved to /tmp/d086_probes - GasProbeVerifier exceeds
  EIP-170 and is scratch, not production.

## O-15 (step 8: node/wallet audit + e2e green on roots-only)

- Wallet side needed no code change: wallet-wasm already carries
  root_after in the client statement (d55df1e), popup.js sends
  root_after = current root with the honest comment that the prover
  recomputes the true post-append root (D-079 witness path). The shipped
  wasm artifact was STALE (built pre-D-088) - rebuilt via
  scripts/build_extension.sh (the workspace .rustup-home toolchain carries
  the wasm target; the home toolchain does not) and smoke-verified;
  committed 7264fff.
- pool_state.mjs / settle_block.mjs: no leafCount selector, unaffected.
- scripts/e2e_local.sh GREEN on the roots-only pool (8th consecutive e2e):
  node genesis (2 leaves, genesis_root_hex) -> deploy -> demo transfer ->
  auto produce+settle -> on-chain currentRoot == node root
  (f86bed09...), blockNumber 1, settlement tx 201,142,627 gas.

