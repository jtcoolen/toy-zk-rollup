// Generates contracts/test/vectors/composed_flat.json from composed_vectors.json.
//
// The flat sidecar pre-digests the composed artifact into exactly the shapes the
// Solidity verifier consumes: extension elements packed as
// c0<<224|c1<<192|c2<<160|c3<<128 (canonical limbs), ragged arrays flattened
// with explicit length arrays, and proof-of-work witnesses converted to the
// Montgomery form the Solidity transcript absorbs.
//
// WHY MONTGOMERY POW WITNESSES
//
// The semantic blob stores every base-field word in Montgomery form, and
// KeccakChallenger.checkWitness absorbs the witness with observeBase, which
// takes Montgomery input (the canonical->Montgomery conversion for extension
// elements happens inside observeExt4Canonical; there is no such conversion on
// the witness path). composed_vectors.json keeps every field canonical - it is
// the human-readable ground truth - so this generator converts the five pow
// witness fields: initial_sumcheck_pow_witnesses, pow_witnesses,
// sumcheck_pow_witnesses, final_pow_witness, final_sumcheck_pow_witnesses.
//
// Run from the repo root: node contracts/scripts/gen_composed_flat.mjs
import fs from "node:fs";

const P = 2130706433n;
const R = 1n << 32n; // Montgomery radix for KoalaBear
const mont = (x) => Number((BigInt(x) * R) % P);

const pack = (e) => (BigInt(e[0]) << 224n) | (BigInt(e[1]) << 192n) | (BigInt(e[2]) << 160n) | (BigInt(e[3]) << 128n);
const hexOf = (x) => "0x" + x.toString(16).padStart(64, "0");
const flatExt = (arr) => arr.map((e) => hexOf(pack(e)));
const flatExt2 = (arr) => arr.flat().map((e) => hexOf(pack(e)));
const montList = (arr) => arr.map((x) => mont(x));

const j = JSON.parse(fs.readFileSync("contracts/test/vectors/composed_vectors.json", "utf8"));
const out = {
  round_starts: j.round_starts,
  description:
    "Flat composed verifier artifact: packed ext elements, one flat array per input, Montgomery pow witnesses. Derived from composed_vectors.json (same proving run as composed_vectors.bin). Regenerate with: node contracts/scripts/gen_composed_flat.mjs",
  num_rounds: j.num_rounds,
  rounds: [],
};

for (let r = 0; r < j.num_rounds; r++) {
  const rd = j.rounds[r];
  const w = rd.walk;
  const s = rd.schedule;
  const ft = j.round_framing_tables[r];
  const nInter = w.rounds.params.length;

  // Rows: round 0 opens base-field rows, later rounds open extension rows.
  let ei = 0;
  const rowsFlat = [];
  const rowLens = [];
  const rowsIsBase = [];
  for (let i = 0; i < nInter; i++) {
    if (i === 0) {
      const rows = w.rounds.rows_base;
      rowsFlat.push(...rows.flat());
      rowLens.push(...rows.map((a) => a.length));
      rowsIsBase.push(1);
    } else {
      const rows = w.rounds.rows_ext.slice(ei, ei + w.rounds.query_indices[i].length);
      // Rows are raw canonical base limbs: one per element for base rows,
      // four per element (low limb first) for extension rows. The contract's
      // extLeaf converts canonical limbs to the Montgomery wire form itself.
      rowsFlat.push(...rows.flat().flat());
      rowLens.push(...rows.map((a) => a.length));
      rowsIsBase.push(0);
      ei += rows.length;
    }
  }

  // Paths: round_paths[i] holds query_lens[i] paths of depth sched_log_folded[i].
  // Stored as one hex blob (forge's parseJsonBytes32Array is unreliable on
  // large arrays; the repo pattern is one hex string + Solidity slicing).
  let pathsHex = "";
  const pathLens = [];
  for (let i = 0; i < nInter; i++) {
    for (const p of w.round_paths[i]) {
      pathsHex += p.join("");
      pathLens.push(p.length);
    }
  }

  // Claim permutation: proof order -> constraint (placement) order.
  const arities = rd.matrices.map((m) => m.domain.log_size);
  const claims = [];
  rd.matrices.forEach((m, ti) => m.points.forEach(() => claims.push(ti)));
  const tables = [...new Set(claims)];
  tables.sort((a, b) => arities[a] - arities[b] || a - b);
  tables.reverse();
  const claimPerm = [];
  for (const t of tables) claims.forEach((ti, ci) => { if (ti === t) claimPerm.push(ci); });

  out.rounds.push({
    n_inter: nInter,
    commitment: rd.commitment,
    claim_perm: claimPerm,
    framing_hex: "0x" + ft.hex,
    framing_pre: ft.pre_claims,
    framing_claim: ft.claim_framings,
    framing_batching: ft.batching,
    framing_seps: ft.seps,
    claim_widths: w.claim_widths,
    bound_evals: flatExt2(w.bound_evals),
    initial_ood_answers: flatExt(w.initial_ood_answers),
    initial_sumcheck_ca: flatExt(w.initial_sumcheck_ca),
    initial_sumcheck_cinf: flatExt(w.initial_sumcheck_cinf),
    initial_sumcheck_pow_witnesses: montList(w.initial_sumcheck_pow_witnesses),
    initial_randomness: flatExt(w.initial_randomness),
    initial_claimed_eval: hexOf(pack(w.initial_claimed_eval)),
    claimed_eval: hexOf(pack(w.claimed_eval)),
    gamma: hexOf(pack(w.gamma)),
    alpha: hexOf(pack(w.alpha)),
    eq_points: flatExt2(w.eq_points),
    eq_points_lens: w.eq_points.map((p) => p.length),
    eq_group_lens: w.eq_group_lens,
    num_variables: w.num_variables,
    round_commitments_hex: w.round_commitments.join(""),
    starting_folding_pow_bits: s.starting_folding_pow_bits,
    commitment_ood_samples: s.commitment_ood_samples,
    sched_pow_bits: s.rounds.map((x) => x.pow_bits),
    sched_folding_pow_bits: s.rounds.map((x) => x.folding_pow_bits),
    sched_num_queries: s.rounds.map((x) => x.num_queries),
    sched_ood_samples: s.rounds.map((x) => x.ood_samples),
    sched_log_folded: s.rounds.map((x) => x.log_folded_domain_size),
    sched_log_inv_rate: s.rounds.map((x) => x.log_inv_rate),
    final_pow_bits: s.final_round.pow_bits,
    final_folding_pow_bits: s.final_round.folding_pow_bits,
    final_num_queries: s.final_round.num_queries,
    final_log_folded: s.final_round.log_folded_domain_size,
    final_log_inv_rate: s.final_round.log_inv_rate,
    params: w.rounds.params.flat(),
    ood_answers: flatExt2(w.rounds.ood_answers),
    ood_answer_lens: w.rounds.ood_answers.map((a) => a.length),
    pow_witnesses: montList(w.rounds.pow_witnesses),
    claimed_evals: flatExt(w.rounds.claimed_evals),
    folded_claims: flatExt(w.rounds.folded_claims),
    folds: flatExt2(w.rounds.folds),
    fold_lens: w.rounds.folds.map((f) => f.length),
    ood_points: flatExt(w.rounds.ood_points),
    domain_points: w.rounds.domain_points.flat(),
    domain_point_lens: w.rounds.domain_points.map((d) => d.length),
    round_batching: flatExt(w.rounds.round_batching),
    query_indices: w.rounds.query_indices.flat(),
    query_lens: w.rounds.query_indices.map((q) => q.length),
    round_randomness: flatExt2(w.rounds.round_randomness),
    randomness_lens: w.rounds.round_randomness.map((a) => a.length),
    sumcheck_ca: flatExt2(w.rounds.sumcheck_ca),
    sumcheck_cinf: flatExt2(w.rounds.sumcheck_cinf),
    sumcheck_lens: w.rounds.sumcheck_ca.map((a) => a.length),
    sumcheck_pow_witnesses: montList(w.rounds.sumcheck_pow_witnesses.flat()),
    sumcheck_pow_lens: w.rounds.sumcheck_pow_witnesses.map((a) => a.length),
    rows_flat: rowsFlat,
    row_lens: rowLens,
    rows_is_base: rowsIsBase,
    paths_hex: pathsHex,
    path_lens: pathLens,
    final_poly: flatExt(w.terminal.final_poly),
    final_pow_witness: mont(w.terminal.final_pow_witness),
    final_rows_ext: w.terminal.final_rows_ext.flat().flat(),
    final_row_lens: w.terminal.final_rows_ext.map((a) => a.length),
    final_paths_hex: w.terminal.final_paths.flat().join(""),
    final_path_lens: w.terminal.final_paths.map((q) => q.length),
    final_folds: flatExt(w.terminal.final_folds),
    final_domain_points: w.terminal.final_domain_points,
    final_sumcheck_ca: flatExt(w.terminal.final_sumcheck_ca),
    final_sumcheck_cinf: flatExt(w.terminal.final_sumcheck_cinf),
    final_sumcheck_pow_witnesses: montList(w.terminal.final_sumcheck_pow_witnesses),
    final_randomness: w.terminal.final_randomness ? flatExt(w.terminal.final_randomness) : [],
    claimed_before_final: hexOf(pack(w.terminal.claimed_before_final)),
    claimed_after_final: hexOf(pack(w.terminal.claimed_after_final)),
    terminal_query_indices: w.terminal.query_indices,
  });
}

fs.writeFileSync("contracts/test/vectors/composed_flat.json", JSON.stringify(out));
console.log("wrote contracts/test/vectors/composed_flat.json");
