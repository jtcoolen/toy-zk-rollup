//! The WBND settlement wire: the byte-exact Rust port of the JS generators
//! (`gen_composed_flat.mjs` + `gen_bundle.mjs`). The node produces settlement
//! bundles with this code; the contract decodes them. The pin test encodes the
//! committed block vectors and requires byte equality with the committed
//! bundle, so the two implementations cannot drift.
//!
//! Three sections, concatenated, each a flat sequence of u32 LE words plus
//! byte blobs:
//!   CONFIG   trusted-setup data (batch framing prefix, schedule, framing
//!            labels, schedule params) + the constraint-identity programs
//!            (v4, D-076). Pinned at deploy by keccak256(config section).
//!   PROOF    untrusted prover bytes: the batch layer's varying absorbs,
//!            commitments, opening evaluations, sumcheck round values, opened
//!            rows, Merkle paths, public polynomial, per-proof `eq_points`.
//!   STATEMENT public shapes and opening points (audit surface).
//!
//! Transcript-DERIVED values (challenges, folds, claimed evals, randomness,
//! query indices) are NEVER in the bundle: the verifier computes them.

// JSON numbers here are KoalaBear limbs, word counts, and schedule parameters:
// all < 2^32 by construction, so the narrowing casts cannot truncate.
// Infallible-by-construction unwraps: every expect here parses JSON this
// crate itself just produced (or fixed-shape blob bytes), so a failure is
// a bug in the producer, not an input condition. Same precedent as fixtures.rs.
// Doc-style lints (long doc paragraphs, # Errors/# Panics sections, arg/line
// counts) are noise on this generated-artifact machinery: the functions are
// internal encoders whose contracts are pinned by byte-identity tests.
#![allow(
    clippy::too_long_first_doc_paragraph,
    clippy::doc_overindented_list_items,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use serde_json::Value;

const P: u64 = 2_130_706_433;
/// Montgomery radix for `KoalaBear` (2^32 mod p applied as x*R mod p).
const MONT_R: u64 = 1 << 32;
/// 2^-32 mod p: Montgomery -> canonical.
const R_INV: u64 = 1_057_030_144;

const fn mont(x: u64) -> u32 {
    ((x % P) * (MONT_R % P) % P) as u32
}

fn unmont(x: u32) -> u32 {
    (u64::from(x) * R_INV % P) as u32
}

/// Pack four canonical limbs into the 256-bit wire word c0<<224|c1<<192|c2<<160|c3<<128.
fn pack_ext(e: &[u64]) -> [u8; 32] {
    assert_eq!(e.len(), 4, "ext element must have 4 limbs");
    let mut out = [0u8; 32];
    for (i, limb) in e.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&(*limb as u32).to_be_bytes());
    }
    out
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The word sink: everything the encoder emits lands here as u32 LE words.
#[derive(Default)]
struct Sink {
    words: Vec<u32>,
}

impl Sink {
    fn word(&mut self, w: u32) {
        self.words.push(w);
    }
    fn arr(&mut self, arr: &[u32]) {
        self.word(arr.len() as u32);
        self.words.extend_from_slice(arr);
    }
    /// A byte blob: u32 byte count, then the bytes zero-padded to a word.
    fn blob(&mut self, bytes: &[u8]) {
        self.word(bytes.len() as u32);
        let mut i = 0;
        while i < bytes.len() {
            let mut buf = [0u8; 4];
            let n = 4usize.min(bytes.len() - i);
            buf[..n].copy_from_slice(&bytes[i..i + n]);
            self.word(u32::from_le_bytes(buf));
            i += 4;
        }
    }
    /// Packed ext elements (each a 64-hex-char string): byte count + raw bytes.
    fn ext_arr(&mut self, hexes: &[String]) {
        let bytes: Vec<u8> = hexes.iter().flat_map(|h| hex_to_bytes(h)).collect();
        self.blob(&bytes);
    }
    /// Raw hex, no length prefix, packed 4 bytes per LE word.
    fn raw(&mut self, hexstr: &str) {
        let bytes = hex_to_bytes(hexstr);
        let mut i = 0;
        while i < bytes.len() {
            let mut buf = [0u8; 4];
            let n = 4usize.min(bytes.len() - i);
            buf[..n].copy_from_slice(&bytes[i..i + n]);
            self.word(u32::from_le_bytes(buf));
            i += 4;
        }
    }
    fn take(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.words)
    }
}

fn u32le_bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

// ---- flat stage (gen_composed_flat.mjs) -------------------------------------

fn as_arr(v: &Value) -> &Vec<Value> {
    v.as_array().expect("json array")
}

fn as_u64(v: &Value) -> u64 {
    v.as_u64().expect("json u64")
}

fn u32s(v: &Value) -> Vec<u32> {
    as_arr(v).iter().map(|x| as_u64(x) as u32).collect()
}

/// A nested ext list (Vec<Vec<u32>> canonical limbs) as packed hex strings.
fn flat_ext(v: &Value) -> Vec<String> {
    as_arr(v)
        .iter()
        .map(|e| {
            let limbs: Vec<u64> = as_arr(e).iter().map(as_u64).collect();
            format!("0x{}", crate::settlement_replay::hex(&pack_ext(&limbs)))
        })
        .collect()
}

/// A doubly-nested ext list flattened one level (Vec<Vec<Vec<u32>>> -> Vec<String>).
fn flat_ext2(v: &Value) -> Vec<String> {
    as_arr(v).iter().flat_map(flat_ext).collect()
}

fn mont_list(v: &Value) -> Vec<u32> {
    as_arr(v).iter().map(|x| mont(as_u64(x))).collect()
}

fn mont_flat(v: &Value) -> Vec<u32> {
    as_arr(v)
        .iter()
        .flat_map(as_arr)
        .map(|x| mont(as_u64(x)))
        .collect()
}

/// The flat sidecar: pre-digests the composed artifact into exactly the shapes
/// the Solidity verifier consumes (packed ext elements, flattened ragged
/// arrays, Montgomery pow witnesses). Port of `gen_composed_flat.mjs`.
#[must_use]
pub fn flat_from_vectors(j: &Value) -> Value {
    let num_rounds = as_u64(&j["num_rounds"]) as usize;
    let mut rounds = Vec::new();
    for r in 0..num_rounds {
        let rd = &j["rounds"][r];
        let w = &rd["walk"];
        let s = &rd["schedule"];
        let ft = &j["round_framing_tables"][r];
        let n_inter = as_arr(&w["rounds"]["params"]).len();

        // Rows: round 0 opens base-field rows, later rounds open extension rows.
        let mut ei = 0usize;
        let mut rows_flat: Vec<u32> = Vec::new();
        let mut row_lens: Vec<u32> = Vec::new();
        let mut rows_is_base: Vec<u32> = Vec::new();
        for i in 0..n_inter {
            if i == 0 {
                for row in as_arr(&w["rounds"]["rows_base"]) {
                    rows_flat.extend(u32s(row));
                    row_lens.push(as_arr(row).len() as u32);
                }
                rows_is_base.push(1);
            } else {
                let all = as_arr(&w["rounds"]["rows_ext"]);
                let take = as_arr(&w["rounds"]["query_indices"][i]).len();
                for row in &all[ei..ei + take] {
                    for elem in as_arr(row) {
                        rows_flat.extend(u32s(elem));
                    }
                    row_lens.push(as_arr(row).len() as u32);
                }
                ei += take;
                rows_is_base.push(0);
            }
        }

        // Paths: one hex blob + per-path node counts.
        let mut paths_hex = String::new();
        let mut path_lens: Vec<u32> = Vec::new();
        for round_paths in as_arr(&w["round_paths"]) {
            for p in as_arr(round_paths) {
                for node in as_arr(p) {
                    paths_hex.push_str(node.as_str().expect("hex node"));
                }
                path_lens.push(as_arr(p).len() as u32);
            }
        }

        // Claim permutation: proof order -> constraint (placement) order.
        let arities: Vec<u64> = as_arr(&rd["matrices"])
            .iter()
            .map(|m| as_u64(&m["domain"]["log_size"]))
            .collect();
        let mut claims: Vec<usize> = Vec::new();
        for (ti, m) in as_arr(&rd["matrices"]).iter().enumerate() {
            for _ in as_arr(&m["points"]) {
                claims.push(ti);
            }
        }
        let mut tables: Vec<usize> = claims.clone();
        tables.sort_by_key(|&t| (arities[t], t as u64));
        tables.dedup();
        tables.reverse();
        let mut claim_perm: Vec<u32> = Vec::new();
        for &t in &tables {
            for (ci, &ti) in claims.iter().enumerate() {
                if ti == t {
                    claim_perm.push(ci as u32);
                }
            }
        }

        let eq_points: Vec<Vec<Vec<u64>>> =
            serde_json::from_value(w["eq_points"].clone()).expect("eq_points shape");
        rounds.push(serde_json::json!({
            "n_inter": n_inter,
            "commitment": rd["commitment"],
            "claim_perm": claim_perm,
            "framing_hex": format!("0x{}", ft["hex"].as_str().unwrap()),
            "framing_pre": ft["pre_claims"],
            "framing_claim": ft["claim_framings"],
            "framing_batching": ft["batching"],
            "framing_seps": ft["seps"],
            "claim_widths": w["claim_widths"],
            "bound_evals": flat_ext2(&w["bound_evals"]),
            "initial_ood_answers": flat_ext(&w["initial_ood_answers"]),
            "initial_sumcheck_ca": flat_ext(&w["initial_sumcheck_ca"]),
            "initial_sumcheck_cinf": flat_ext(&w["initial_sumcheck_cinf"]),
            "initial_sumcheck_pow_witnesses": mont_list(&w["initial_sumcheck_pow_witnesses"]),
            "initial_randomness": flat_ext(&w["initial_randomness"]),
            "initial_claimed_eval": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["initial_claimed_eval"])))),
            "claimed_eval": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["claimed_eval"])))),
            "gamma": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["gamma"])))),
            "alpha": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["alpha"])))),
            "eq_points": flat_ext2(&w["eq_points"]),
            "eq_points_lens": eq_points.iter().map(|p| p.len() as u32).collect::<Vec<_>>(),
            "eq_group_lens": w["eq_group_lens"],
            "num_variables": w["num_variables"],
            "round_commitments_hex": as_arr(&w["round_commitments"]).iter().map(|h| h.as_str().unwrap()).collect::<String>(),
            "starting_folding_pow_bits": s["starting_folding_pow_bits"],
            "commitment_ood_samples": s["commitment_ood_samples"],
            "sched_pow_bits": as_arr(&s["rounds"]).iter().map(|x| x["pow_bits"].clone()).collect::<Vec<_>>(),
            "sched_folding_pow_bits": as_arr(&s["rounds"]).iter().map(|x| x["folding_pow_bits"].clone()).collect::<Vec<_>>(),
            "sched_num_queries": as_arr(&s["rounds"]).iter().map(|x| x["num_queries"].clone()).collect::<Vec<_>>(),
            "sched_ood_samples": as_arr(&s["rounds"]).iter().map(|x| x["ood_samples"].clone()).collect::<Vec<_>>(),
            "sched_log_folded": as_arr(&s["rounds"]).iter().map(|x| x["log_folded_domain_size"].clone()).collect::<Vec<_>>(),
            "sched_log_inv_rate": as_arr(&s["rounds"]).iter().map(|x| x["log_inv_rate"].clone()).collect::<Vec<_>>(),
            "final_pow_bits": s["final_round"]["pow_bits"],
            "final_folding_pow_bits": s["final_round"]["folding_pow_bits"],
            "final_num_queries": s["final_round"]["num_queries"],
            "final_log_folded": s["final_round"]["log_folded_domain_size"],
            "final_log_inv_rate": s["final_round"]["log_inv_rate"],
            "params": as_arr(&w["rounds"]["params"]).iter().flat_map(|p| as_arr(p).iter().map(|x| as_u64(x) as u32)).collect::<Vec<_>>(),
            "ood_answers": flat_ext2(&w["rounds"]["ood_answers"]),
            "ood_answer_lens": as_arr(&w["rounds"]["ood_answers"]).iter().map(|a| as_arr(a).len() as u32).collect::<Vec<_>>(),
            "pow_witnesses": mont_list(&w["rounds"]["pow_witnesses"]),
            "claimed_evals": flat_ext(&w["rounds"]["claimed_evals"]),
            "folded_claims": flat_ext(&w["rounds"]["folded_claims"]),
            "folds": flat_ext2(&w["rounds"]["folds"]),
            "fold_lens": as_arr(&w["rounds"]["folds"]).iter().map(|f| as_arr(f).len() as u32).collect::<Vec<_>>(),
            "ood_points": flat_ext(&w["rounds"]["ood_points"]),
            "domain_points": as_arr(&w["rounds"]["domain_points"]).iter().flat_map(u32s).collect::<Vec<_>>(),
            "domain_point_lens": as_arr(&w["rounds"]["domain_points"]).iter().map(|d| as_arr(d).len() as u32).collect::<Vec<_>>(),
            "round_batching": flat_ext(&w["rounds"]["round_batching"]),
            "query_indices": as_arr(&w["rounds"]["query_indices"]).iter().flat_map(u32s).collect::<Vec<_>>(),
            "query_lens": as_arr(&w["rounds"]["query_indices"]).iter().map(|q| as_arr(q).len() as u32).collect::<Vec<_>>(),
            "round_randomness": flat_ext2(&w["rounds"]["round_randomness"]),
            "randomness_lens": as_arr(&w["rounds"]["round_randomness"]).iter().map(|a| as_arr(a).len() as u32).collect::<Vec<_>>(),
            "sumcheck_ca": flat_ext2(&w["rounds"]["sumcheck_ca"]),
            "sumcheck_cinf": flat_ext2(&w["rounds"]["sumcheck_cinf"]),
            "sumcheck_lens": as_arr(&w["rounds"]["sumcheck_ca"]).iter().map(|a| as_arr(a).len() as u32).collect::<Vec<_>>(),
            "sumcheck_pow_witnesses": mont_flat(&w["rounds"]["sumcheck_pow_witnesses"]),
            "sumcheck_pow_lens": as_arr(&w["rounds"]["sumcheck_pow_witnesses"]).iter().map(|a| as_arr(a).len() as u32).collect::<Vec<_>>(),
            "rows_flat": rows_flat,
            "row_lens": row_lens,
            "rows_is_base": rows_is_base,
            "paths_hex": paths_hex,
            "path_lens": path_lens,
            "final_poly": flat_ext(&w["terminal"]["final_poly"]),
            "final_pow_witness": mont(as_u64(&w["terminal"]["final_pow_witness"])),
            "final_rows_ext": as_arr(&w["terminal"]["final_rows_ext"]).iter().flat_map(|row| as_arr(row).iter().flat_map(u32s)).collect::<Vec<_>>(),
            "final_row_lens": as_arr(&w["terminal"]["final_rows_ext"]).iter().map(|a| as_arr(a).len() as u32).collect::<Vec<_>>(),
            "final_paths_hex": as_arr(&w["terminal"]["final_paths"]).iter().flat_map(|q| as_arr(q).iter().map(|n| n.as_str().unwrap())).collect::<String>(),
            "final_path_lens": as_arr(&w["terminal"]["final_paths"]).iter().map(|q| as_arr(q).len() as u32).collect::<Vec<_>>(),
            "final_folds": flat_ext(&w["terminal"]["final_folds"]),
            "final_domain_points": as_arr(&w["terminal"]["final_domain_points"]).iter().map(|d| as_u64(d) as u32).collect::<Vec<_>>(),
            "terminal_query_indices": as_arr(&w["terminal"]["query_indices"]).iter().map(|q| as_u64(q) as u32).collect::<Vec<_>>(),
            "final_sumcheck_ca": flat_ext(&w["terminal"]["final_sumcheck_ca"]),
            "final_sumcheck_cinf": flat_ext(&w["terminal"]["final_sumcheck_cinf"]),
            "final_sumcheck_pow_witnesses": mont_list(&w["terminal"]["final_sumcheck_pow_witnesses"]),
            "final_randomness": if w["terminal"]["final_randomness"].is_null() { Vec::<String>::new() } else { flat_ext(&w["terminal"]["final_randomness"]) },
            "claimed_before_final": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["terminal"]["claimed_before_final"])))),
            "claimed_after_final": format!("0x{}", crate::settlement_replay::hex(&pack_ext(&u64s_ref(&w["terminal"]["claimed_after_final"])))),
        }));
    }
    serde_json::json!({
        "round_starts": j["round_starts"],
        "description": "Flat composed verifier artifact (Rust encoder): packed ext elements, one flat array per input, Montgomery pow witnesses.",
        "num_rounds": num_rounds,
        "rounds": rounds,
    })
}

fn u64s_ref(v: &Value) -> Vec<u64> {
    as_arr(v).iter().map(as_u64).collect()
}

// ---- bundle stage (gen_bundle.mjs) -------------------------------------------

/// The batch-layer split of the blob's events before the delegate site: the
/// `BatchTranscript` absorbs the WHIR delegate never sees, attributed to phases
/// by the phase marks (an absorb at event site s belongs to the phase whose
/// mark is the FIRST mark strictly after s; marks sit at the SAMPLE that
/// follows the phase's absorbs).
#[derive(Default)]
struct BatchSplit {
    seed: Vec<u32>,
    degree: Vec<u32>,
    pv_words: Vec<u32>,
    main_digest: Option<String>,
    pre_digest: Option<String>,
    perm_digest: Option<String>,
    quot_digest: Option<String>,
    rand_digest: Option<String>,
    /// Packed ext hex: 4 canonical limbs at the top of a 32-byte word.
    terminals: Vec<String>,
    lookup_pow: u32,
    ood_pow: u32,
}

/// 8 words -> 32 bytes (LE per word) as hex, the digest wire form.
fn digest_hex(ws: &[u32]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for w in ws {
        for b in w.to_le_bytes() {
            use std::fmt::Write as _;
            write!(&mut out, "{b:02x}").expect("writing to a String cannot fail");
        }
    }
    out
}

/// Montgomery word -> canonical 8-hex-char limb.
fn canon_hex(w: u32) -> String {
    format!("{:08x}", unmont(w))
}

fn split_batch(bin: &[u8], jj: &Value) -> BatchSplit {
    let sched_len = u16::from_be_bytes([bin[6], bin[7]]) as usize;
    let payload_lens: [usize; 5] = [8, 12, 16, 20, 24]
        .map(|o| u32::from_be_bytes([bin[o], bin[o + 1], bin[o + 2], bin[o + 3]]) as usize);
    let const_start = 28 + sched_len * 4;
    let var_start = const_start + payload_lens[0];
    let wit_start = var_start + payload_lens[1] + payload_lens[2] + payload_lens[3];
    let delegate = as_u64(&jj["phase_marks_before_delegate"]) as usize;
    let marks: Vec<(usize, String)> = as_arr(&jj["phase_marks"])
        .iter()
        .map(|m| {
            (
                as_u64(&m["at"]) as usize,
                m["phase"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    // The "new" mark falls mid-event (the site-0 run spans it), so the
    // seed/degree split point is pinned there.
    let new_site = marks
        .iter()
        .find(|(_, p)| p == "new")
        .map(|(at, _)| *at)
        .expect("new mark");
    let mut marks_sorted = marks;
    marks_sorted.sort_by_key(|(a, _)| *a);
    let phase_of = |site: usize| -> String {
        for (at, phase) in &marks_sorted {
            if *at > site {
                return phase.clone();
            }
        }
        "after".to_string()
    };

    let read_le = |base: usize, off: usize| {
        u32::from_le_bytes([
            bin[base + off],
            bin[base + off + 1],
            bin[base + off + 2],
            bin[base + off + 3],
        ])
    };

    let mut s = BatchSplit::default();
    // Site accounting: kind 0/1 run = word count (1 site per word); kind 2/6
    // run = digest count (8 words per digest, 1 site per digest); kind 3/4/5/7
    // run = sample/witness count (1 site each).
    let (mut c_off, mut v_off, mut w_off, mut site) = (0usize, 0usize, 0usize, 0usize);
    for e in 0..sched_len {
        if site >= delegate {
            break;
        }
        let at = 28 + e * 4;
        let kind = bin[at];
        let run = u16::from_be_bytes([bin[at + 2], bin[at + 3]]) as usize;
        let phase = phase_of(site);
        match kind {
            0 => {
                for k in 0..run {
                    if site + k >= delegate {
                        break;
                    }
                    let w = read_le(const_start, c_off);
                    c_off += 4;
                    if site == 0 {
                        if site + k < new_site {
                            s.seed.push(w);
                        } else {
                            s.degree.push(w);
                        }
                    } else if phase == "main_phase" {
                        s.pv_words.push(w);
                    }
                }
            }
            6 => {
                for d in 0..run {
                    if site + d >= delegate {
                        break;
                    }
                    let ws: Vec<u32> = (0..8)
                        .map(|_| {
                            let w = read_le(const_start, c_off);
                            c_off += 4;
                            w
                        })
                        .collect();
                    if phase == "preprocessed_phase" {
                        s.pre_digest = Some(digest_hex(&ws));
                    }
                }
            }
            1 => {
                let ws: Vec<u32> = (0..run)
                    .filter(|k| site + k < delegate)
                    .map(|_| {
                        let w = read_le(var_start, v_off);
                        v_off += 4;
                        w
                    })
                    .collect();
                if phase == "permutation_phase" {
                    for chunk in ws.chunks(4) {
                        let limbs: String = chunk.iter().map(|w| canon_hex(*w)).collect();
                        s.terminals
                            .push(format!("0x{limbs}00000000000000000000000000000000"));
                    }
                }
            }
            2 => {
                for d in 0..run {
                    if site + d >= delegate {
                        break;
                    }
                    let ws: Vec<u32> = (0..8)
                        .map(|_| {
                            let w = read_le(var_start, v_off);
                            v_off += 4;
                            w
                        })
                        .collect();
                    let h = digest_hex(&ws);
                    match phase.as_str() {
                        "main_phase" => s.main_digest = Some(h),
                        "permutation_phase" => s.perm_digest = Some(h),
                        "quotient_phase" => {
                            if s.quot_digest.is_none() {
                                s.quot_digest = Some(h);
                            } else if s.rand_digest.is_none() {
                                s.rand_digest = Some(h);
                            }
                        }
                        _ => {}
                    }
                }
            }
            5 => {
                let w = read_le(wit_start, w_off);
                w_off += 4;
                if phase == "lookup_phase" {
                    s.lookup_pow = w;
                } else if phase == "ood_phase" {
                    s.ood_pow = w;
                }
            }
            _ => {}
        }
        site += run;
    }
    s
}

fn hex_strings(v: &Value) -> Vec<String> {
    as_arr(v)
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect()
}

fn u32_vec(v: &Value) -> Vec<u32> {
    u32s(v)
}

/// The CONSTRAINTS isolate: per-instance constraint programs + domain constants
/// (trusted setup, D-076). The opened values are NOT here: the contract
/// derives them from the rounds (boundEvals x scale(k, zeta)), which is what
/// makes the check sound. Mirrors the cst block of `gen_bundle.mjs` exactly.
fn constraints_section(j: &Value, jj: &Value) -> Vec<u32> {
    let ci = &jj["constraint_identity"];
    let mut m = Sink::default();
    let instances = as_arr(ci.get("instances").expect("constraint_identity.instances"));
    m.word(instances.len() as u32);
    m.word(
        ci["statement_instance"]
            .as_u64()
            .map_or(4_294_967_295, |v| v as u32),
    );
    for inst in instances {
        m.word(as_u64(&inst["width"]) as u32);
        m.word(as_u64(&inst["preprocessed_width"]) as u32);
        m.word(as_u64(&inst["aux_width"]) as u32);
        m.word(u32::from(inst["has_main_next"].as_bool().unwrap_or(false)));
        m.word(u32::from(inst["has_pre_next"].as_bool().unwrap_or(false)));
        m.word(as_u64(&inst["num_constraints"]) as u32);
        m.arr(&u32_vec(&inst["nodes"]));
        m.arr(&u32_vec(&inst["base_consts"]));
        m.arr(&u32_vec(&inst["ext_consts"]));
        m.arr(&u32_vec(&inst["roots"]));
        m.word(as_u64(&inst["trace_domain"]["log_size"]) as u32);
        m.word(as_u64(&inst["trace_domain"]["shift"]) as u32);
        m.word(as_u64(&inst["trace_domain"]["inv_shift"]) as u32);
        m.word(as_u64(&inst["trace_domain"]["h_inv"]) as u32);
        m.word(as_u64(&inst["num_chunks"]) as u32);
        for d in as_arr(&inst["chunk_domains"]) {
            m.word(as_u64(&d["log_size"]) as u32);
            m.word(as_u64(&d["shift"]) as u32);
            m.word(as_u64(&d["inv_shift"]) as u32);
        }
        m.arr(&u32_vec(&inst["inv_d"]));
    }
    // Bus layout for the permutation challenges: the widest payload W, then per
    // instance the bus id of each lookup (the contract derives the pair
    // [lookupAlpha + (bus+1)*beta^W, beta] per lookup), then which instances
    // carry a LogUp terminal.
    m.word(as_u64(&ci["max_message_width"]) as u32);
    for i in 0..instances.len() {
        m.arr(&u32_vec(&ci["bus_ids"][i]));
    }
    for i in 0..instances.len() {
        m.word(u32::from(
            ci["terminal_counts"][i].as_bool().unwrap_or(false),
        ));
    }
    // Per-round claim-group arities: the contract computes each group scale
    // from the arity and its own zeta (audit copy, trusted-setup position).
    let num_rounds = as_u64(&j["num_rounds"]) as usize;
    m.word(num_rounds as u32);
    for r in 0..num_rounds {
        let arities: Vec<u32> = as_arr(&jj["rounds"][r]["matrices"])
            .iter()
            .map(|m_| as_u64(&m_["arity"]) as u32)
            .collect();
        m.arr(&arities);
    }
    m.take()
}

/// Encode the WBND v4 bundle from the composed vectors JSON + semantic blob.
///
/// `j` is the flat artifact (`flat_from_vectors`), `jj` the composed vectors,
/// `bin` the blob bytes. Byte-identical to `gen_bundle.mjs`'s output; the pin
/// test proves it against the committed block bundle.
#[must_use]
pub fn encode_bundle(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    let batch = split_batch(bin, jj);

    // CONSTRAINTS (trusted setup, appended to CONFIG in v4).
    let cst = constraints_section(j, jj);

    // ---- CONFIG ----
    let mut cfg: Vec<u32> = Vec::new();
    {
        let mut m = Sink::default();
        m.blob(&u32le_bytes(&batch.seed));
        m.blob(&u32le_bytes(&batch.degree));
        m.raw(batch.pre_digest.as_deref().expect("pre digest"));
        // Batch-layer grind difficulties: the settlement shape uses zero-bit
        // grinds at both sites (the witnesses are pinned to zero); the bits
        // are config, not proof.
        m.word(0);
        m.word(0);
        let batch_cfg = m.take();
        cfg.push(batch_cfg.len() as u32);
        cfg.extend_from_slice(&batch_cfg);

        let mut m = Sink::default();
        let num_rounds = as_u64(&j["num_rounds"]) as usize;
        m.word(num_rounds as u32);
        m.arr(&u32_vec(&j["round_starts"]));
        for r in 0..num_rounds {
            let rd = &j["rounds"][r];
            m.word(as_u64(&rd["n_inter"]) as u32);
            m.arr(&u32_vec(&rd["claim_perm"]));
            m.blob(&hex_to_bytes(rd["framing_hex"].as_str().unwrap()));
            m.arr(&u32_vec(&rd["framing_pre"]));
            m.arr(&u32_vec(&rd["framing_claim"]));
            m.word(as_u64(&rd["framing_batching"]) as u32);
            m.arr(&u32_vec(&rd["framing_seps"]));
            m.arr(&u32_vec(&rd["claim_widths"]));
            m.word(as_u64(&rd["num_variables"]) as u32);
            m.word(as_u64(&rd["starting_folding_pow_bits"]) as u32);
            m.word(as_u64(&rd["commitment_ood_samples"]) as u32);
            m.arr(&u32_vec(&rd["sched_pow_bits"]));
            m.arr(&u32_vec(&rd["sched_folding_pow_bits"]));
            m.arr(&u32_vec(&rd["sched_num_queries"]));
            m.arr(&u32_vec(&rd["sched_ood_samples"]));
            m.arr(&u32_vec(&rd["sched_log_folded"]));
            m.arr(&u32_vec(&rd["sched_log_inv_rate"]));
            m.word(as_u64(&rd["final_pow_bits"]) as u32);
            m.word(as_u64(&rd["final_folding_pow_bits"]) as u32);
            m.word(as_u64(&rd["final_num_queries"]) as u32);
            m.word(as_u64(&rd["final_log_folded"]) as u32);
            m.word(as_u64(&rd["final_log_inv_rate"]) as u32);
            m.arr(&u32_vec(&rd["params"]));
            m.arr(&u32_vec(&rd["rows_is_base"]));
        }
        cfg.extend_from_slice(&m.take());
        cfg.push(cst.len() as u32);
        cfg.extend_from_slice(&cst);
    }

    // ---- PROOF ----
    let mut prf: Vec<u32> = Vec::new();
    {
        let mut m = Sink::default();
        m.raw(batch.main_digest.as_deref().expect("main digest"));
        m.blob(&u32le_bytes(&batch.pv_words));
        m.word(batch.lookup_pow);
        m.raw(batch.perm_digest.as_deref().expect("perm digest"));
        m.word(batch.terminals.len() as u32);
        for t in &batch.terminals {
            m.raw(t);
        }
        m.raw(batch.quot_digest.as_deref().expect("quot digest"));
        m.raw(batch.rand_digest.as_deref().expect("rand digest"));
        m.word(batch.ood_pow);
        let batch_prf = m.take();
        prf.push(batch_prf.len() as u32);
        prf.extend_from_slice(&batch_prf);

        let mut m = Sink::default();
        let num_rounds = as_u64(&j["num_rounds"]) as usize;
        m.word(num_rounds as u32);
        for r in 0..num_rounds {
            let rd = &j["rounds"][r];
            m.blob(&hex_to_bytes(rd["commitment"].as_str().unwrap()));
            m.ext_arr(&hex_strings(&rd["bound_evals"]));
            m.ext_arr(&hex_strings(&rd["initial_ood_answers"]));
            m.ext_arr(&hex_strings(&rd["initial_sumcheck_ca"]));
            m.ext_arr(&hex_strings(&rd["initial_sumcheck_cinf"]));
            m.arr(&u32_vec(&rd["initial_sumcheck_pow_witnesses"]));
            m.arr(&u32_vec(&rd["rows_flat"]));
            m.blob(&hex_to_bytes(rd["paths_hex"].as_str().unwrap()));
            m.blob(&hex_to_bytes(rd["round_commitments_hex"].as_str().unwrap()));
            m.ext_arr(&hex_strings(&rd["ood_answers"]));
            m.arr(&u32_vec(&rd["ood_answer_lens"]));
            m.arr(&u32_vec(&rd["pow_witnesses"]));
            m.ext_arr(&hex_strings(&rd["sumcheck_ca"]));
            m.ext_arr(&hex_strings(&rd["sumcheck_cinf"]));
            m.arr(&u32_vec(&rd["sumcheck_pow_witnesses"]));
            m.arr(&u32_vec(&rd["sumcheck_lens"]));
            m.arr(&u32_vec(&rd["sumcheck_pow_lens"]));
            m.ext_arr(&hex_strings(&rd["final_poly"]));
            m.word(as_u64(&rd["final_pow_witness"]) as u32);
            m.arr(&u32_vec(&rd["final_rows_ext"]));
            m.blob(&hex_to_bytes(rd["final_paths_hex"].as_str().unwrap()));
            m.ext_arr(&hex_strings(&rd["final_sumcheck_ca"]));
            m.ext_arr(&hex_strings(&rd["final_sumcheck_cinf"]));
            m.arr(&u32_vec(&rd["final_sumcheck_pow_witnesses"]));
            // v5 (D-086 step C): the per-round eq section is GONE. The eq
            // groups are now derived on-chain from the STATEMENT section's
            // opening points plus the transcript-drawn virtual claim points
            // (TerminalWeight frame mode 2) - 386 KB of wire bought back, and
            // the groups stop being proof-supplied.
            // domain_points DROPPED (v3): the verifier recomputes g^index from
            // the indices its own transcript samples.
        }
        prf.extend_from_slice(&m.take());
    }

    // ---- STATEMENT ----
    let stm: Vec<u32>;
    {
        let mut m = Sink::default();
        let num_rounds = as_u64(&j["num_rounds"]) as usize;
        m.word(num_rounds as u32);
        for r in 0..num_rounds {
            let mats = as_arr(&jj["rounds"][r]["matrices"]);
            m.word(mats.len() as u32);
            for mat in mats {
                m.word(as_u64(&mat["domain"]["log_size"]) as u32);
                let pts = as_arr(&mat["points"]);
                m.word(
                    pts.first()
                        .map_or(0, |p0| as_arr(&p0["values"]).len() as u32),
                );
                m.word(pts.len() as u32);
                for pt in pts {
                    // point is [c0,c1,c2,c3] canonical limbs; pack to one
                    // 256-bit word.
                    let limbs: Vec<u64> = as_arr(&pt["point"]).iter().map(as_u64).collect();
                    m.ext_arr(&[format!(
                        "0x{}",
                        crate::settlement_replay::hex(&pack_ext(&limbs))
                    )]);
                }
            }
        }
        stm = m.take();
    }

    // ---- header + body ----
    let mut out = vec![0u8; 16];
    out[..4].copy_from_slice(b"WBND");
    out[4] = 5;
    out[8..12].copy_from_slice(&(cfg.len() as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(prf.len() as u32).to_le_bytes());
    for w in &cfg {
        out.extend_from_slice(&w.to_le_bytes());
    }
    for w in &prf {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&(stm.len() as u32).to_le_bytes());
    for w in &stm {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// The WBND v6 bundle: identical grammar, but the CONFIG section is EMPTY
/// (cfgWords = 0) and returned separately so a deployment can pin it at
/// deploy time (chunked code satellites - EIP-170 caps one contract at
/// 24,576 B, so 182 KB needs 8 chunks). The on-chain tx then carries only
/// PROOF + STATEMENT: 627 KB -> ~445 KB at the rate-4 shape (D-092 batch
/// 25). The v5 path is untouched; `encode_bundle` stays byte-exact.
#[must_use]
pub fn encode_bundle_v6(j: &Value, jj: &Value, bin: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mut out, cfg) = encode_bundle_v6_split(j, jj, bin);
    // v6 inlines nothing of CONFIG: the caller ships `cfg` to the satellites.
    out.shrink_to_fit();
    (out, cfg)
}

/// v6 split: (header+PROOF+STATEMENT bundle, CONFIG section bytes). The
/// header keeps the v5 layout with version byte 6 and cfgWords = 0.
#[must_use]
pub fn encode_bundle_v6_split(j: &Value, jj: &Value, bin: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let full = encode_bundle(j, jj, bin);
    let (_magic, _ver, cfgw, prfw) = crate::wbnd::header(&full);
    let cfg_bytes = full[16..16 + cfgw * 4].to_vec();
    let mut out = vec![0u8; 16];
    out[..4].copy_from_slice(b"WBND");
    out[4] = 6;
    out[8..12].copy_from_slice(&0u32.to_le_bytes());
    out[12..16].copy_from_slice(&(prfw as u32).to_le_bytes());
    out.extend_from_slice(&full[16 + cfgw * 4..]);
    (out, cfg_bytes)
}

/// The WBND header: (magic ok, version, cfg words, prf words).
#[must_use]
pub fn header(b: &[u8]) -> (bool, u8, usize, usize) {
    let magic = &b[..4] == b"WBND";
    let ver = b[4];
    let cfgw = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    let prfw = u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize;
    (magic, ver, cfgw, prfw)
}

/// Split CONFIG bytes into code-satellite chunks of at most `max` bytes
/// (EIP-170: 24,576 runtime code; leave headroom for the accessor shell).
#[must_use]
pub fn chunk_config(cfg: &[u8], max: usize) -> Vec<Vec<u8>> {
    cfg.chunks(max).map(<[u8]>::to_vec).collect()
}
