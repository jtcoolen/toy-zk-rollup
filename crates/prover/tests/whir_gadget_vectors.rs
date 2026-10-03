//! Ground-truth vectors for the multilinear gadget layer of the settlement verifier.
//!
//! Run with:
//!
//! ```text
//! cargo test -p prover --test whir_gadget_vectors -- --ignored --nocapture
//! ```
//!
//! ## Why these five, and why against the native functions
//!
//! The WHIR verifier core is arithmetic the contract has to reproduce exactly:
//! lift a univariate challenge to a multilinear point, evaluate the equality and
//! selection weight polynomials, map a query index to its domain point, batch
//! values under powers of a challenge, and finally evaluate the batched
//! constraint polynomial at the accumulated folding randomness. Each is small
//! enough that a port looks obviously right, and each has a convention in it
//! that a reading can get backwards - the big-endian order of
//! `expand_from_univariate`, which end of `select_eval` consumes `var` first,
//! whether the constraint weight starts at `gamma^0` or `gamma^1`.
//!
//! So every value here comes from the function the prover itself calls, not from
//! a reimplementation of it:
//!
//! - `Point::expand_from_univariate`, `Point::eval_eq`, `Point::eval_select`
//!   (p3-multilinear-util)
//! - `VariableOrder::eval_constraints_poly` (p3-sumcheck), driven by real
//!   `Constraint` values holding real `EqStatement` and `SelectStatement`
//!   groups, in the order p3-whir builds them: Eq first, then Select, with
//!   `new_with_existing_claim` reserving `gamma^0` for the carried claim.
//! - `p3_field::dot_product` against `shifted_powers` for the powers
//!   combination, which is what the native combiner uses to weight statements.
//!
//! `eval_constraints_poly` is the last thing the verifier checks - the whole
//! proof reduces to `claimed_eval == eval_constraints_poly(...) *
//! eval_multilinear(final_poly, last_r)` - and it is the one piece whose shape
//! is not visible in any transcript, because it consumes only challenges the
//! transcript already produced. A transcript replay cannot catch a wrong
//! grouping or a wrong power shift here. This can.
//!
//! ## Both variable orders
//!
//! Prefix and Suffix slice the accumulated challenge differently per constraint
//! (last `k`, versus last `k` reversed), so each case is emitted with both
//! results. They differ, which is the point: a contract that ignores
//! `variable_order` would pass one and fail the other.
//!
//! ## Determinism
//!
//! A splitmix64 stream with a constant seed. No HVZK blinding is involved -
//! these are polynomial identities over drawn points, not proofs - so the file
//! is byte-reproducible and can be pinned by hash.

use p3_field::{
    dot_product, BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, TwoAdicField,
};
use p3_multilinear_util::point::Point;
use p3_sumcheck::constraints::statement::eq::EqStatement;
use p3_sumcheck::constraints::statement::select::SelectStatement;
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::strategy::VariableOrder;
use serde_json::json;

use prover::config::F;
use prover::whir::Challenge;

/// Extension degree, spelled out so the file describes itself.
const DIMENSION: usize = 4;

/// Multilinear arities to exercise. 0 and 1 are the degenerate cases where an
/// off-by-one in a loop bound hides; 4 is the folding factor the settlement
/// config actually uses; 8 is past the point where the vendored unrolled
/// specialisations stop and the general loop takes over.
const ARITIES: [usize; 5] = [0, 1, 2, 4, 8];

/// Drawn cases per gadget.
const CASES: usize = 6;

/// Deterministic canonical u32 for (tag, i, k).
fn word(tag: u64, i: usize, k: usize) -> u32 {
    let mut z = tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ ((i as u64) << 32) ^ (k as u64);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // Reduce, never mask: a limb above the modulus is not a field element.
    let reduced = z % u64::from(<F as PrimeField32>::ORDER_U32);
    u32::try_from(reduced).expect("remainder is below the u32 modulus")
}

/// One deterministic extension element, coefficients low-order first.
fn ext(tag: u64, i: usize, k: usize) -> Challenge {
    <Challenge as BasedVectorSpace<F>>::from_basis_coefficients_fn(|j| {
        F::from_u32(word(tag, i * DIMENSION + k, j))
    })
}

/// Lift a base element into the extension: the canonical embedding.
fn lift(x: F) -> Challenge {
    <Challenge as BasedVectorSpace<F>>::from_basis_coefficients_fn(
        |j| if j == 0 { x } else { F::ZERO },
    )
}

/// A base field element in canonical form.
fn base(tag: u64, i: usize) -> F {
    F::from_u32(word(tag, i, 0))
}

/// Extension coefficients as canonical u32s, low order first.
fn ext_json(v: &Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField32::as_canonical_u32)
        .collect()
}

/// Array lengths are emitted as explicit `num_*` fields next to the arrays they
/// describe. forge JSON selectors have no length operator, so a `.length` path
/// fails with "must return exactly one JSON value" - which reads like a malformed
/// file rather than an unsupported selector, and is a poor way to discover the
/// limit. Carrying the count also lets the test assert it instead of inferring it
/// from the array it is about to index.
///
/// A point as a JSON array of extension elements.
fn point_json(p: &[Challenge]) -> Vec<Vec<u32>> {
    p.iter().map(ext_json).collect()
}

/// Build a point of `n` drawn extension elements.
fn drawn_point(tag: u64, i: usize, n: usize) -> Vec<Challenge> {
    (0..n).map(|k| ext(tag + 100, i * 16 + k, 0)).collect()
}

#[test]
#[ignore = "regenerates a golden vector file; run explicitly"]
#[allow(
    clippy::too_many_lines,
    reason = "one emit block per gadget reads better than five helpers with different shapes"
)]
fn emit_whir_gadget_vectors() {
    // ── expand_from_univariate ───────────────────────────────────────────────
    let expand: Vec<_> = ARITIES
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let z = ext(1, i, 0);
            let point = Point::expand_from_univariate(z, n);
            json!({
                "z": ext_json(&z),
                "num_variables": n,
                "point": point_json(point.as_slice()),
            })
        })
        .collect();

    // ── eval_eq ──────────────────────────────────────────────────────────────
    let eq: Vec<_> = ARITIES
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let a = drawn_point(3, i, n);
            let b = drawn_point(7, i, n);
            let value = Point::eval_eq(a.as_slice(), b.as_slice());
            json!({
                "num_vars": n,
                "p": point_json(&a),
                "q": point_json(&b),
                "value": ext_json(&value),
            })
        })
        .collect();

    // ── eval_select ──────────────────────────────────────────────────────────
    //
    // `var` is a base field element in the protocol (a two-adic domain point)
    // and the coordinates are extension elements. Lifting `var` is exact: the
    // embedding is a ring homomorphism, so squaring it in the extension agrees
    // with squaring it in the base field and lifting afterwards.
    let select: Vec<_> = ARITIES
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let point = drawn_point(11, i, n);
            let var = lift(base(13, i));
            let value = Point::eval_select(var, point.as_slice());
            json!({
                "num_vars": n,
                "point": point_json(&point),
                "var": ext_json(&var),
                "value": ext_json(&value),
            })
        })
        .collect();

    // ── pow_const_base ───────────────────────────────────────────────────────
    //
    // The circuit gadget multiplies precomputed constants per set bit; the
    // native verifier just exponentiates. Pin the value, not the method:
    // gen^index over the two-adic subgroup, which is what a STIR query index
    // means. Indices include 0 and the full order so the empty product and the
    // wrap-around are both covered.
    let log_gen = 8usize;
    let order = 1u64 << log_gen;
    let generator = <F as TwoAdicField>::two_adic_generator(log_gen);
    let pow_indices = [0u64, 1, 2, 3, 7, 255, order - 1, order];
    let pow: Vec<_> = pow_indices
        .iter()
        .map(|&index| {
            let value = generator.exp_u64(index);
            json!({
                "generator": PrimeField32::as_canonical_u32(&generator),
                "index": index,
                "value": ext_json(&lift(value)),
            })
        })
        .collect();

    // ── eval_powers_combination ──────────────────────────────────────────────
    //
    // Pinned against p3_field::dot_product over shifted_powers, the primitive
    // the native statement combiner uses to weight constraints by successive
    // powers of its challenge. Empty input is included: the empty combination
    // is zero, and a Horner loop that seeds with one instead of zero is a real
    // and silent mistake.
    let powers: Vec<_> = (0..=CASES)
        .map(|i| {
            let n = i; // 0..CASES, so the first case is empty
            let values: Vec<Challenge> = (0..n).map(|k| ext(17, i * 8 + k, 0)).collect();
            let gamma = ext(19, i, 0);
            let value = dot_product::<Challenge, _, _>(
                values.iter().copied(),
                gamma.shifted_powers(Challenge::ONE),
            );
            json!({
                "num_values": n,
                "values": point_json(&values),
                "base": ext_json(&gamma),
                "value": ext_json(&value),
            })
        })
        .collect();

    // ── eval_constraints_poly ────────────────────────────────────────────────
    //
    // Real Constraint values, built the way p3-whir builds a round constraint:
    // one Eq group (the OOD claims) then one Select group (the STIR claims),
    // batched by gamma. Both constructors are exercised because the initial
    // constraint reserves gamma^0 for nothing while a round constraint reserves
    // it for the carried claim - the difference is one power of gamma across
    // every term, which is exactly the kind of off-by-one that survives review.
    let mut constraints_cases = Vec::new();
    for i in 0..CASES {
        let n = 3 + i; // accumulated challenge length
        let all_r = drawn_point(23, i, n);
        // Per-constraint arity: a round constraint sees fewer variables than the
        // whole run has accumulated, which is what makes the slicing rule
        // observable. Clamped so k <= n always, matching the gadget.
        let k = n.saturating_sub(1 + (i % 2)).max(1);
        let gamma = ext(29, i, 0);

        let n_eq = 1 + (i % 3);
        let n_sel = 1 + ((i + 1) % 3);

        let mut eq = EqStatement::<Challenge>::initialize(k);
        let mut eq_points_json = Vec::new();
        for e in 0..n_eq {
            let pt = drawn_point(31, i * 8 + e, k);
            let eval = ext(37, i * 8 + e, 0);
            eq.add_evaluated_constraint(Point::new(pt.clone()), eval);
            eq_points_json.push(point_json(&pt));
        }

        // Select vars are base field elements: the STIR domain points.
        let sel_vars: Vec<F> = (0..n_sel).map(|s| base(41, i * 8 + s)).collect();
        let sel_evals: Vec<Challenge> = (0..n_sel).map(|s| ext(43, i * 8 + s, 0)).collect();
        let sel = SelectStatement::<F, Challenge>::new(k, sel_vars.clone(), sel_evals.clone());

        let statements = || vec![Statements::Eq(eq.clone()), Statements::Select(sel.clone())];

        let fresh = Constraint::new(gamma, k, statements());
        let carried = Constraint::new_with_existing_claim(gamma, k, statements());
        let challenge = Point::new(all_r.clone());

        constraints_cases.push(json!({
            "num_all_r": all_r.len(),
            "all_r": point_json(&all_r),
            "num_variables": k,
            "gamma": ext_json(&gamma),
            "num_eq_points": n_eq,
            "eq_points": eq_points_json,
            "num_sel_vars": n_sel,
            "sel_vars": sel_vars
                .iter()
                .map(|v| ext_json(&lift(*v)))
                .collect::<Vec<_>>(),
            "prefix_fresh": ext_json(&VariableOrder::Prefix.eval_constraints_poly(std::slice::from_ref(&fresh), &challenge)),
            "suffix_fresh": ext_json(&VariableOrder::Suffix.eval_constraints_poly(&[fresh], &challenge)),
            "prefix_carried": ext_json(&VariableOrder::Prefix.eval_constraints_poly(std::slice::from_ref(&carried), &challenge)),
            "suffix_carried": ext_json(&VariableOrder::Suffix.eval_constraints_poly(&[carried], &challenge)),
        }));
    }

    let doc = json!({
        "scheme": "whir_gadgets",
        "field": "koalabear_ext4",
        "note": "every value is produced by the p3 function the prover itself calls; see crates/prover/tests/whir_gadget_vectors.rs",
        "num_expand": expand.len(),
        "num_eq": eq.len(),
        "num_select": select.len(),
        "num_pow": pow.len(),
        "num_powers": powers.len(),
        "num_constraints": constraints_cases.len(),
        "dimension": DIMENSION,
        "expand_rule": "point[i] = z^(2^(num_variables-1-i)), big-endian: coordinate 0 is the highest power",
        "eq_rule": "product over i of (1 + 2*p[i]*q[i] - p[i] - q[i])",
        "select_rule": "product over k of (point[n-1-k] * (var^(2^k) - 1) + 1), var squared per step",
        "pow_rule": "value = generator^index lifted into the extension",
        "powers_rule": "value = sum_i values[i] * base^i",
        "constraints_rule": "sum over constraints of gamma^initial_power * (sum_i gamma^i * eq(local_r, eq_points[i]) + sum_j gamma^(n_eq+j) * select(local_r, sel_vars[j]))",
        "prefix_rule": "local_r = all_r[n-k..]",
        "suffix_rule": "local_r = reverse(all_r[n-k..])",
        "expand": expand,
        "eq": eq,
        "select": select,
        "pow": pow,
        "powers": powers,
        "constraints": constraints_cases,
    });

    let text = serde_json::to_string_pretty(&doc).expect("serialize");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/vectors/whir_gadgets.json",
    );
    std::fs::write(path, format!("{text}\n")).expect("write vectors");
    println!("wrote {path}");
}
