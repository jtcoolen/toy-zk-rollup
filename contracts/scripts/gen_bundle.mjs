// Generates contracts/test/vectors/composed_bundle.bin: the wire format the
// on-chain WhirVerifier decodes from calldata (D-071).
//
// Three sections, concatenated, each a flat sequence of u32 LE words plus byte
// blobs:
//   CONFIG   trusted-setup data (batch framing prefix, schedule, framing labels,
//            schedule params). Pinned at deploy by keccak256(config section).
//   PROOF    untrusted prover bytes: the batch layer's varying absorbs (main
//            digest, public values, grind witnesses, permutation terminals),
//            commitments, opening evaluations, sumcheck round values, opened
//            rows (raw canonical limbs), Merkle paths, public polynomial, and
//            the per-proof eq_points / domain_points (D-072 phase 1: these are
//            zeta-derived per-proof data, so they live in PROOF, not CONFIG).
//   STATEMENT public shapes and opening points (audit surface).
//
// Transcript-DERIVED values (challenges, folds, claimed evals, randomness,
// query indices) are NEVER in the bundle: the verifier computes them.
//
// Every array is length-prefixed (u32 count, then words). Byte blobs are
// length-prefixed (u32 byte count, then bytes, then zero-pad to 4).
//
// Run from the repo root: node contracts/scripts/gen_bundle.mjs
import fs from "node:fs";

const j = JSON.parse(fs.readFileSync("contracts/test/vectors/composed_flat.json", "utf8"));
const jj = JSON.parse(fs.readFileSync("contracts/test/vectors/composed_vectors.json", "utf8"));

// The active word sink: pushWord/pushArr/pushExtArr/pushBlob append here.
let words = [];
const pushWord = (w) => words.push(w >>> 0);
const pushArr = (arr) => {
  pushWord(arr.length);
  for (const v of arr) pushWord(typeof v === "string" ? parseInt(v, 16) : v);
};
const pushExtArr = (arr) => {
  const bytes = new Uint8Array(arr.length * 32);
  arr.forEach((h, i) => {
    const s = h.startsWith("0x") ? h.slice(2) : h;
    for (let k = 0; k < 32; k++) bytes[i * 32 + k] = parseInt(s.slice(k * 2, k * 2 + 2), 16);
  });
  pushBlob(bytes);
};
const pushBlob = (bytesOrHex) => {
  const bytes =
    typeof bytesOrHex === "string"
      ? (() => {
          const s = bytesOrHex.startsWith("0x") ? bytesOrHex.slice(2) : bytesOrHex;
          const b = new Uint8Array(s.length / 2);
          for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
          return b;
        })()
      : bytesOrHex;
  pushWord(bytes.length);
  for (let i = 0; i < bytes.length; i += 4) {
    let w = 0;
    for (let k = 0; k < 4 && i + k < bytes.length; k++) w |= bytes[i + k] << (8 * k);
    pushWord(w);
  }
};
const pushRaw = (hexstr) => {
  const hex = hexstr.startsWith("0x") ? hexstr.slice(2) : hexstr;
  for (let i = 0; i < hex.length; i += 8) {
    let w = 0;
    for (let k = 0; k < 4; k++) w |= parseInt(hex.slice(i + k * 2, i + k * 2 + 2), 16) << (8 * k);
    pushWord(w);
  }
};
// Run `fn` against a fresh sink and return the words it produced.
function isolate(fn) {
  const saved = words;
  words = [];
  fn();
  const out = words;
  words = saved;
  return out;
}

// ---- batch layer: split the blob's events before the delegate site ----------
// Walk the WSPR schedule; events before the delegate site belong to one
// BatchTranscript phase each (the phase marks say which). We emit each phase's
// payload as a typed piece so the contract feeds BatchTranscript directly with
// no offset math.
//
// CONFIG pieces (fixed): seed words, degree-bit words, preprocessed digest.
// PROOF pieces (varying): main digest, public-value words, lookup grind
// witness, permutation digest, LogUp terminals (ext), quotient digest,
// randomization digest, ood grind witness.
const bin = fs.readFileSync("contracts/test/vectors/composed_vectors.bin");
const schedLen = bin.readUInt16BE(6);
const payloadLens = [8, 12, 16, 20, 24].map((o) => bin.readUInt32BE(o));
const constStart = 28 + schedLen * 4;
const varStart = constStart + payloadLens[0];
const witStart = varStart + payloadLens[1] + payloadLens[2] + payloadLens[3];
const DELEGATE = jj.phase_marks_before_delegate;
const marks = jj.phase_marks; // [{at, phase}] in site order
// The "new" mark at site 87 falls mid-event (the site-0 run spans it), so the
// seed/degree split point is pinned there.
const NEW_SITE = marks.find((m) => m.phase === "new").at;
const seed = [];
const degree = [];
const pvWords = [];
let mainDigest = null, preDigest = null, permDigest = null, quotDigest = null, randDigest = null;
const terminals = []; // packed ext hex (4 canonical limbs at the top of a 32-byte word)
let lookupPow = 0, oodPow = 0;
const lookupPowBits = 0, oodPowBits = 0;
{
  // Phase attribution: an absorb at event site s belongs to the phase whose mark
  // is the FIRST mark strictly after s (marks sit at the SAMPLE that follows the
  // phase's absorbs). Event 0 spans the new mark, so its words split at NEW_SITE.
  const marksSorted = [...marks].sort((a, b) => a.at - b.at);
  const phaseOf = (site) => {
    for (const m of marksSorted) if (m.at > site) return m.phase;
    return "after";
  };
  let cOff = 0, vOff = 0, wOff = 0, site = 0;
  const digestHex = (ws) => {
    const b = new Uint8Array(32);
    const v = new DataView(b.buffer);
    ws.forEach((w, i) => v.setUint32(i * 4, w >>> 0, true));
    return "0x" + Buffer.from(b).toString("hex");
  };
  const P_FIELD = 2130706433n;
  const R_INV = 1057030144n; // 2^-32 mod p: Montgomery -> canonical
  const extHex = (ws) => {
    // The blob's var payload stores SERIALIZED field elements: Montgomery
    // form. The contract's observeExt4Canonical expects canonical limbs and
    // converts on absorb, so convert back here (canonical = mont * R^-1 mod p).
    const hex = ws
      .map((w) => ((BigInt(w >>> 0) * R_INV) % P_FIELD).toString(16).padStart(8, "0"))
      .join("") + "0".repeat(32);
    return "0x" + hex;
  };
  // Site accounting: kind 0/1 run = word count (1 site per word); kind 2/6 run =
  // digest count (8 words per digest, 1 site per digest); kind 3/4/5/7 run =
  // sample/witness count (1 site each).
  for (let e = 0; e < schedLen && site < DELEGATE; e++) {
    const at = 28 + e * 4;
    const kind = bin.readUInt8(at);
    const run = bin.readUInt16BE(at + 2);
    const phase = phaseOf(site);
    if (kind === 0) {
      for (let k = 0; k < run && site + k < DELEGATE; k++) {
        const w = bin.readUInt32LE(constStart + cOff); cOff += 4;
        if (site === 0) (site + k < NEW_SITE ? seed : degree).push(w);
        else if (phase === "main_phase") pvWords.push(w);
      }
    } else if (kind === 6) {
      for (let d = 0; d < run && site + d < DELEGATE; d++) {
        const ws = [];
        for (let w = 0; w < 8; w++) { ws.push(bin.readUInt32LE(constStart + cOff)); cOff += 4; }
        if (phase === "preprocessed_phase") preDigest = digestHex(ws);
      }
    } else if (kind === 1) {
      const ws = [];
      for (let k = 0; k < run && site + k < DELEGATE; k++) { ws.push(bin.readUInt32LE(varStart + vOff)); vOff += 4; }
      if (phase === "permutation_phase") {
        for (let k = 0; k < ws.length; k += 4) terminals.push(extHex(ws.slice(k, k + 4)));
      }
    } else if (kind === 2) {
      for (let d = 0; d < run && site + d < DELEGATE; d++) {
        const ws = [];
        for (let w = 0; w < 8; w++) { ws.push(bin.readUInt32LE(varStart + vOff)); vOff += 4; }
        const h = digestHex(ws);
        if (phase === "main_phase") mainDigest = h;
        else if (phase === "permutation_phase") permDigest = h;
        else if (phase === "quotient_phase") { if (!quotDigest) quotDigest = h; else randDigest = h; }
      }
    } else if (kind === 5) {
      const w = bin.readUInt32LE(witStart + wOff); wOff += 4;
      if (phase === "lookup_phase") lookupPow = w;
      else if (phase === "ood_phase") oodPow = w;
    }
    site += run;
  }
}
const u32leBytes = (arr) => {
  const b = new Uint8Array(arr.length * 4);
  const v = new DataView(b.buffer);
  arr.forEach((w, i) => v.setUint32(i * 4, w >>> 0, true));
  return b;
};
const hexWords = (hex) => {
  const s = hex.slice(2);
  const out = [];
  for (let i = 0; i < 8; i++) out.push(parseInt(s.slice(i * 8, i * 8 + 8), 16) >>> 0);
  return out;
};
console.log("batch: seed", seed.length, "deg", degree.length, "pv", pvWords.length,
  "terminals", terminals.length, "lookupPow", lookupPow, "oodPow", oodPow,
  "digests", [mainDigest, preDigest, permDigest, quotDigest, randDigest].map((d) => (d ? d.slice(2, 10) : "MISSING")).join(","));

// ---- CONFIG ----------------------------------------------------------------
const cfg = [];
{
  // Batch config prefix: seed bytes, degree bytes, preprocessed digest (8 words).
  const batchCfg = isolate(() => {
    pushBlob(u32leBytes(seed));
    pushBlob(u32leBytes(degree));
    pushRaw(preDigest);
    // Batch-layer grind difficulties. The settlement shape uses zero-bit grinds at
    // both sites (the witnesses are pinned to zero); the bits are config, not proof.
    pushWord(lookupPowBits);
    pushWord(oodPowBits);
  });
  cfg.push(batchCfg.length, ...batchCfg);

  pushWord(j.num_rounds);
  pushArr(j.round_starts);
  for (let r = 0; r < j.num_rounds; r++) {
    const rd = j.rounds[r];
    pushWord(rd.n_inter);
    pushArr(rd.claim_perm);
    pushBlob(rd.framing_hex);
    pushArr(rd.framing_pre);
    pushArr(rd.framing_claim);
    pushWord(rd.framing_batching);
    pushArr(rd.framing_seps);
    pushArr(rd.claim_widths);
    pushArr(rd.eq_points_lens);
    pushArr(rd.eq_group_lens);
    pushWord(rd.num_variables);
    pushWord(rd.starting_folding_pow_bits);
    pushWord(rd.commitment_ood_samples);
    pushArr(rd.sched_pow_bits);
    pushArr(rd.sched_folding_pow_bits);
    pushArr(rd.sched_num_queries);
    pushArr(rd.sched_ood_samples);
    pushArr(rd.sched_log_folded);
    pushArr(rd.sched_log_inv_rate);
    pushWord(rd.final_pow_bits);
    pushWord(rd.final_folding_pow_bits);
    pushWord(rd.final_num_queries);
    pushWord(rd.final_log_folded);
    pushWord(rd.final_log_inv_rate);
    pushArr(rd.params);
    pushArr(rd.rows_is_base);
  }
  // Move the per-round words (pushed into the module sink) into cfg.
  while (words.length) cfg.push(words.shift());
}

// ---- PROOF -----------------------------------------------------------------
const prf = [];
{
  // Batch proof prefix: main digest, public-value bytes, lookup pow, perm
  // digest, terminals (ext list), quotient digest, randomization digest, ood pow.
  const batchPrf = isolate(() => {
    pushRaw(mainDigest);
    pushBlob(u32leBytes(pvWords));
    pushWord(lookupPow);
    pushRaw(permDigest);
    pushWord(terminals.length);
    for (const t of terminals) pushRaw(t);
    pushRaw(quotDigest);
    pushRaw(randDigest);
    pushWord(oodPow);
  });
  prf.push(batchPrf.length, ...batchPrf);

  pushWord(j.num_rounds);
  for (let r = 0; r < j.num_rounds; r++) {
    const rd = j.rounds[r];
    pushBlob(rd.commitment);
    pushExtArr(rd.bound_evals);
    pushExtArr(rd.initial_ood_answers);
    pushExtArr(rd.initial_sumcheck_ca);
    pushExtArr(rd.initial_sumcheck_cinf);
    pushArr(rd.initial_sumcheck_pow_witnesses);
    pushArr(rd.rows_flat);
    pushBlob(rd.paths_hex);
    pushBlob(rd.round_commitments_hex);
    pushExtArr(rd.ood_answers);
    pushArr(rd.ood_answer_lens);
    pushArr(rd.pow_witnesses);
    pushExtArr(rd.sumcheck_ca);
    pushExtArr(rd.sumcheck_cinf);
    pushArr(rd.sumcheck_pow_witnesses);
    pushArr(rd.sumcheck_lens);
    pushArr(rd.sumcheck_pow_lens);
    pushExtArr(rd.final_poly);
    pushWord(rd.final_pow_witness);
    pushArr(rd.final_rows_ext);
    pushBlob(rd.final_paths_hex);
    pushExtArr(rd.final_sumcheck_ca);
    pushExtArr(rd.final_sumcheck_cinf);
    pushArr(rd.final_sumcheck_pow_witnesses);
    // D-072 phase 1: zeta-derived per-proof data lives in PROOF.
    pushExtArr(rd.eq_points);
    // domain_points DROPPED (v3): the verifier recomputes g^index from the
    // indices its own transcript samples, so the proof no longer carries them.
  }
  while (words.length) prf.push(words.shift());
}

// ---- STATEMENT ---------------------------------------------------------------
const stm = [];
{
  pushWord(j.num_rounds);
  for (let r = 0; r < j.num_rounds; r++) {
    const mats = jj.rounds[r].matrices;
    pushWord(mats.length);
    for (const m of mats) {
      pushWord(m.domain.log_size);
      pushWord(m.points[0] ? m.points[0].values.length : 0);
      pushWord(m.points.length);
      for (const pt of m.points) {
        // point is [c0,c1,c2,c3] canonical limbs; pack to one 256-bit word.
        const packed =
          (BigInt(pt.point[0]) << 224n) | (BigInt(pt.point[1]) << 192n) |
          (BigInt(pt.point[2]) << 160n) | (BigInt(pt.point[3]) << 128n);
        pushExtArr(["0x" + packed.toString(16).padStart(64, "0")]);
      }
    }
  }
  while (words.length) stm.push(words.shift());
}

const header = new Uint8Array(16);
header.set([0x57, 0x42, 0x4e, 0x44]); // WBND
header[4] = 3; // version 3: + final sumcheck fields, + batch grind bits in CFG, - domain_points
const view = new DataView(header.buffer);
view.setUint32(8, cfg.length, true);
view.setUint32(12, prf.length, true);
const stmOut = [stm.length, ...stm];
const body = new Uint8Array((cfg.length + prf.length + stmOut.length) * 4);
const dv = new DataView(body.buffer);
let off = 0;
for (const w of cfg) { dv.setUint32(off, w >>> 0, true); off += 4; }
for (const w of prf) { dv.setUint32(off, w >>> 0, true); off += 4; }
for (const w of stmOut) { dv.setUint32(off, w >>> 0, true); off += 4; }
fs.writeFileSync("contracts/test/vectors/composed_bundle.bin", Buffer.concat([Buffer.from(header), Buffer.from(body)]));
console.log("wrote composed_bundle.bin", header.length + body.length, "bytes; cfg words", cfg.length, "prf words", prf.length, "stm words", stmOut.length);
