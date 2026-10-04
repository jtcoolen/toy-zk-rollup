//! Constraint-identity vectors: the last layer of `verify_batch` after the opening
//! argument. Per instance the contract must check that the folded AIR constraints at
//! the out-of-domain point equal the recomposed quotient:
//!
//! ```text
//! fold(alpha, constraints(zeta)) * inv_vanishing(zeta) == quotient(zeta)
//! ```
//!
//! Run with: `cargo test -p prover --test constraint_identity_vectors -- --ignored --nocapture`
//!
//! # Why an IR export
//!
//! The settlement AIRs are generated (Poseidon2 / recompose / statement tables), so
//! the constraints cannot be hand-written in Solidity. They are trusted-setup data:
//! this file runs `get_symbolic_constraints` on the exact AIRs the verifier
//! reconstructs, flattens each constraint's expression DAG to a post-order op list
//! (shared subtrees emitted once, referenced by node index), and exports every opened
//! value the evaluator consumes. The Solidity side is a DAG interpreter.
//!
//! # The on-chain identity (pinned here before porting)
//!
//! The library check is `fold * inv_vanishing == quotient` with real selectors
//! `is_first = zh/s1`, `is_last = zh/s2`, `is_transition = s2` where the trace
//! domain is `gH` (natural domains have shift 1, so `u = zeta`, `zh = u^(2^L) - 1`,
//! `s1 = u - 1`, `s2 = u - h_inv`). Every denominator (`zh`, `s1`, `s2`) depends only
//! on `zeta` and the domain, never on a constraint, so the contract pays three
//! extension inversions per instance (batchable with Montgomery's trick) instead of
//! reformulating the fold.
//!
//! The quotient recompose inverts `Z_j(first_i)`, which is a domain-only constant:
//! the export carries `invD_i = (prod_{j!=i} Z_j(first_i))^-1` and each chunk
//! domain's `inv_shift_j`, so the contract computes
//! `quotient = sum_i q_i * (prod_{j!=i} Z_j(zeta)) * invD_i` with
//! `Z_j(zeta) = (zeta * inv_shift_j)^(2^Lj) - 1` and no runtime inversion there.
//! The test asserts this reformulation equals the library's
//! `recompose_quotient_from_chunks` before pinning the identity.
#![recursion_limit = "256"]

use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt,
};
use p3_air::BaseAir;
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_symbolic_constraints,
};
use p3_batch_stark::verifier::commitments_with_opening_points;
use p3_batch_stark::{BatchShape, BatchVerifierTranscript, CommonData};
use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_commit::{Mmcs, Pcs, PeriodicColumns, PolynomialSpace, UnivariateStarkPcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_lookup::{LogUpGadget, LookupProtocol};
use p3_uni_stark::{recompose_quotient_from_chunks, validate_degree_bits, StarkGenericConfig};
use serde_json::json;

use prover::whir::Challenger;
use prover::whir_recursion::{
    build_recursion_circuit, settle_recursion_circuit, RecursionCircuit, CAP_HEIGHT, LOG_MAX_LDE,
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type WhirPcs = prover::whir::Pcs;
type Config = prover::whir::Config;
type Commitment = <prover::config::Mmcs as Mmcs<F>>::Commitment;

const BASE_TRACE: usize = 1024;

/// Post-order IR node. Arithmetic nodes reference child node indices, so shared
/// subtrees are emitted once and the program is a DAG, not a tree.
#[derive(Clone, Debug)]
enum Node {
    ConstBase(usize),
    ConstExt(usize),
    MainLocal(usize),
    MainNext(usize),
    PreLocal(usize),
    PreNext(usize),
    PermLocal(usize),
    PermNext(usize),
    PermChallenge(usize),
    PermValue(usize),
    Public(usize),
    Periodic(usize),
    IsFirst,
    IsLast,
    IsTransition,
    Add(usize, usize),
    Sub(usize, usize),
    Mul(usize, usize),
    Neg(usize),
}

impl Node {
    // Node indices and constant pool slots are far below 2^32 by construction (the
    // largest settlement DAG is a few thousand nodes), so the narrowing casts below
    // cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    const fn encode(&self) -> [u32; 3] {
        let (tag, x, y) = match *self {
            Self::ConstBase(i) => (0, i, 0),
            Self::ConstExt(i) => (1, i, 0),
            Self::MainLocal(i) => (2, i, 0),
            Self::MainNext(i) => (3, i, 0),
            Self::PreLocal(i) => (4, i, 0),
            Self::PreNext(i) => (5, i, 0),
            Self::PermLocal(i) => (6, i, 0),
            Self::PermNext(i) => (7, i, 0),
            Self::PermChallenge(i) => (8, i, 0),
            Self::PermValue(i) => (9, i, 0),
            Self::Public(i) => (10, i, 0),
            Self::Periodic(i) => (11, i, 0),
            Self::IsFirst => (12, 0, 0),
            Self::IsLast => (13, 0, 0),
            Self::IsTransition => (14, 0, 0),
            Self::Add(a, b) => (15, a, b),
            Self::Sub(a, b) => (16, a, b),
            Self::Mul(a, b) => (17, a, b),
            Self::Neg(a) => (18, a, 0),
        };
        [tag as u32, x as u32, y as u32]
    }
}

/// One instance's flattened constraint program plus the constant pools it indexes.
struct InstanceIr {
    nodes: Vec<Node>,
    base_consts: Vec<u32>,
    ext_consts: Vec<[u32; 4]>,
    /// Constraint roots in GLOBAL emission order (base and ext interleaved by the
    /// layout): the fold `acc = acc*alpha + C_g` walks this list front to back.
    roots: Vec<usize>,
}

/// DAG flattener with pointer-identity memoization. `SymbolicExpr` shares subtrees
/// through `Arc`, so emitting each distinct node once keeps the program linear in
/// distinct nodes rather than exponential in shared subtrees.
struct Flattener {
    ir: InstanceIr,
    seen: HashMap<usize, usize>,
}

impl Flattener {
    fn new() -> Self {
        Self {
            ir: InstanceIr {
                nodes: Vec::new(),
                base_consts: Vec::new(),
                ext_consts: Vec::new(),
                roots: Vec::new(),
            },
            seen: HashMap::new(),
        }
    }

    fn push(&mut self, node: Node) -> usize {
        self.ir.nodes.push(node);
        self.ir.nodes.len() - 1
    }

    fn base_const(&mut self, v: F) -> usize {
        let c = v.as_canonical_u32();
        if let Some(at) = self.ir.base_consts.iter().position(|&x| x == c) {
            at
        } else {
            self.ir.base_consts.push(c);
            self.ir.base_consts.len() - 1
        }
    }

    fn ext_const(&mut self, v: EF) -> usize {
        let c = ext_coeffs(v);
        if let Some(at) = self.ir.ext_consts.iter().position(|x| *x == c) {
            at
        } else {
            self.ir.ext_consts.push(c);
            self.ir.ext_consts.len() - 1
        }
    }

    /// Intern a base-field sub-expression. Returns the node index of its value.
    ///
    /// The root of a constraint is a plain enum value, so it is not memoized; the
    /// shared subtrees below it are `Arc`s and are keyed by pointer identity.
    fn expr(&mut self, e: &SymbolicExpression<F>) -> usize {
        self.expr_ref(e, None)
    }

    fn expr_arc(&mut self, e: &Arc<SymbolicExpression<F>>) -> usize {
        self.expr_ref(e, Some(Arc::as_ptr(e) as usize))
    }

    fn expr_ref(&mut self, e: &SymbolicExpression<F>, memo: Option<usize>) -> usize {
        if let Some(key) = memo {
            if let Some(&at) = self.seen.get(&key) {
                return at;
            }
        }
        let node = match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset } => {
                        if offset == 0 {
                            Node::MainLocal(v.index)
                        } else {
                            Node::MainNext(v.index)
                        }
                    }
                    BaseEntry::Preprocessed { offset } => {
                        if offset == 0 {
                            Node::PreLocal(v.index)
                        } else {
                            Node::PreNext(v.index)
                        }
                    }
                    BaseEntry::Periodic => Node::Periodic(v.index),
                    BaseEntry::Public => Node::Public(v.index),
                },
                BaseLeaf::Constant(c) => Node::ConstBase(self.base_const(*c)),
                BaseLeaf::IsFirstRow => Node::IsFirst,
                BaseLeaf::IsLastRow => Node::IsLast,
                BaseLeaf::IsTransition => Node::IsTransition,
            },
            SymbolicExpr::Add { x, y, .. } => Node::Add(self.expr_arc(x), self.expr_arc(y)),
            SymbolicExpr::Sub { x, y, .. } => Node::Sub(self.expr_arc(x), self.expr_arc(y)),
            SymbolicExpr::Neg { x, .. } => Node::Neg(self.expr_arc(x)),
            SymbolicExpr::Mul { x, y, .. } => Node::Mul(self.expr_arc(x), self.expr_arc(y)),
        };
        let at = self.push(node);
        if let Some(key) = memo {
            self.seen.insert(key, at);
        }
        at
    }

    /// Intern an extension-field sub-expression. A lifted base subtree shares the
    /// same memo table: base nodes evaluate to EF values (a base value is an EF value).
    fn expr_ext(&mut self, e: &SymbolicExpressionExt<F, EF>) -> usize {
        self.expr_ext_ref(e, None)
    }

    fn expr_ext_arc(&mut self, e: &Arc<SymbolicExpressionExt<F, EF>>) -> usize {
        self.expr_ext_ref(e, Some(Arc::as_ptr(e) as usize))
    }

    fn expr_ext_ref(&mut self, e: &SymbolicExpressionExt<F, EF>, memo: Option<usize>) -> usize {
        if let Some(key) = memo {
            if let Some(&at) = self.seen.get(&key) {
                return at;
            }
        }
        let node = match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(b) => {
                    // A lifted base subtree already evaluates to an EF value, so the
                    // wrapper is transparent: reuse the base node and memoize this
                    // pointer onto it so the DAG stays linear.
                    let inner = self.expr(b);
                    if let Some(key) = memo {
                        self.seen.insert(key, inner);
                    }
                    return inner;
                }
                ExtLeaf::ExtConstant(c) => Node::ConstExt(self.ext_const(*c)),
                ExtLeaf::ExtVariable(v) => match v.entry {
                    ExtEntry::Permutation { offset } => {
                        if offset == 0 {
                            Node::PermLocal(v.index)
                        } else {
                            Node::PermNext(v.index)
                        }
                    }
                    ExtEntry::Challenge => Node::PermChallenge(v.index),
                    ExtEntry::PermutationValue => Node::PermValue(v.index),
                },
            },
            SymbolicExpr::Add { x, y, .. } => Node::Add(self.expr_ext_arc(x), self.expr_ext_arc(y)),
            SymbolicExpr::Sub { x, y, .. } => Node::Sub(self.expr_ext_arc(x), self.expr_ext_arc(y)),
            SymbolicExpr::Neg { x, .. } => Node::Neg(self.expr_ext_arc(x)),
            SymbolicExpr::Mul { x, y, .. } => Node::Mul(self.expr_ext_arc(x), self.expr_ext_arc(y)),
        };
        let at = self.push(node);
        if let Some(key) = memo {
            self.seen.insert(key, at);
        }
        at
    }
}

/// Basis coefficients of an extension element, canonical u32.
fn ext_coeffs(v: EF) -> [u32; 4] {
    let s = <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&v);
    [
        s[0].as_canonical_u32(),
        s[1].as_canonical_u32(),
        s[2].as_canonical_u32(),
        s[3].as_canonical_u32(),
    ]
}

fn ext_json(v: &EF) -> Vec<u32> {
    ext_coeffs(*v).to_vec()
}

/// Flat concatenation of basis coefficients: four u32s per element.
fn exts_flat(vs: &[EF]) -> Vec<u32> {
    vs.iter().flat_map(|v| ext_coeffs(*v)).collect()
}

/// The opened values one instance's constraint program consumes, as the contract sees
/// them: everything the opening argument returns plus the transcript challenges.
struct EvalInputs<'a> {
    main_local: &'a [EF],
    main_next: &'a [EF],
    pre_local: &'a [EF],
    pre_next: &'a [EF],
    perm_local: &'a [EF],
    perm_next: &'a [EF],
    perm_challenges: &'a [EF],
    perm_values: &'a [EF],
    public_values: &'a [F],
    periodic_values: &'a [EF],
    is_first: EF,
    is_last: EF,
    is_transition: EF,
}

/// Evaluate the constraint DAG and fold it with `alpha` by Horner, exactly as the
/// verifier folder does: `acc = acc*alpha + C_g` over the roots in emission order.
///
/// The selector leaves carry denominators, but they are per-instance constants
/// (`s1`, `s2`, `zh` depend only on `zeta` and the domain), so the contract pays
/// three extension inversions per instance rather than reformulating the fold.
fn fold_constraints(ir: &InstanceIr, inp: &EvalInputs<'_>, alpha: EF) -> EF {
    let mut stack: Vec<EF> = Vec::with_capacity(ir.nodes.len());
    for node in &ir.nodes {
        let v = match *node {
            Node::ConstBase(i) => lift(F::from_u32(ir.base_consts[i])),
            Node::ConstExt(idx) => {
                let [c0, c1, c2, c3] = ir.ext_consts[idx];
                EF::from_basis_coefficients_slice(&[
                    F::from_u32(c0),
                    F::from_u32(c1),
                    F::from_u32(c2),
                    F::from_u32(c3),
                ])
                .expect("4 coefficients")
            }
            Node::MainLocal(i) => inp.main_local[i],
            Node::MainNext(i) => inp.main_next[i],
            Node::PreLocal(i) => inp.pre_local[i],
            Node::PreNext(i) => inp.pre_next[i],
            Node::PermLocal(i) => inp.perm_local[i],
            Node::PermNext(i) => inp.perm_next[i],
            Node::PermChallenge(i) => inp.perm_challenges[i],
            Node::PermValue(i) => inp.perm_values[i],
            Node::Public(i) => lift(inp.public_values[i]),
            Node::Periodic(i) => inp.periodic_values[i],
            Node::IsFirst => inp.is_first,
            Node::IsLast => inp.is_last,
            Node::IsTransition => inp.is_transition,
            Node::Add(a, b) => {
                let y = stack[b];
                let x = stack[a];
                x + y
            }
            Node::Sub(a, b) => {
                let y = stack[b];
                let x = stack[a];
                x - y
            }
            Node::Mul(a, b) => {
                let y = stack[b];
                let x = stack[a];
                x * y
            }
            Node::Neg(a) => -stack[a],
        };
        stack.push(v);
    }
    let mut acc = EF::ZERO;
    for &root in &ir.roots {
        acc = acc * alpha + stack[root];
    }
    acc
}

/// Lift a base element into the extension field.
fn lift(x: F) -> EF {
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(&[x, F::ZERO, F::ZERO, F::ZERO])
        .expect("4 coefficients")
}

/// log2 of a power-of-two size.
const fn log2_size(n: usize) -> usize {
    n.trailing_zeros() as usize
}

/// The Fibonacci fixture, identical to `batch_stark_vectors.rs`: same statement, same
/// circuit, so the exported IR describes the same batch the transcript blob pins.
fn fib_recursion() -> (Vec<F>, RecursionCircuit) {
    let inner = prover::whir_recursion::InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT)
        .expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let mut a = F::ZERO;
    let mut b = F::ONE;
    for _ in 1..BASE_TRACE {
        let n = a + b;
        a = b;
        b = n;
    }
    let pis = vec![F::ZERO, F::ONE, b];
    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("recursion circuit");
    (pis, rc)
}

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/constraint_identity_vectors.json")
}

fn boxed<E: core::fmt::Debug>(e: E) -> Box<dyn Error> {
    Box::<dyn Error>::from(format!("{e:?}"))
}

/// Prove the settlement batch, replay the batch transcript to recover `zeta` and the
/// fold challenge, flatten every instance's symbolic constraints to a DAG, evaluate
/// the fold at the opened values and pin `fold * inv_vanishing == quotient`. The
/// flattened IR plus every input the fold consumed is written to the vectors file the
/// Solidity pin test reads.
#[test]
#[ignore = "proves the settlement batch (~6s); regenerates the vectors"]
#[allow(clippy::too_many_lines)] // one linear replay of verify_batch's tail; splitting scatters what it pins
fn export_constraint_identity_vectors() -> Result<(), Box<dyn Error>> {
    let (pis, rc) = fib_recursion();
    let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE)?;
    let config = prover::whir::config(CAP_HEIGHT, LOG_MAX_LDE)?;
    let batch = &proof.proof;
    let common: &CommonData<Config> = verifier.common_data();
    let airs = verifier.table_airs::<4>().map_err(boxed)?;
    let public_values = verifier.table_public_values(&pis).map_err(boxed)?;
    let pcs = config.pcs();
    let is_zk = <WhirPcs as UnivariateStarkPcs<EF, Challenger>>::ZK;
    let is_zk_usize = usize::from(is_zk);
    let gadget = LogUpGadget::new();
    let all_lookups = common.lookups.as_slice();

    // Per-instance shape, mirroring verify_batch's pre-transcript loop.
    let mut ext_domain_sizes = Vec::new();
    let mut preprocessed_widths = Vec::new();
    let mut log_num_quotient_chunks = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let (base_db, ext_size) = validate_degree_bits(
            Some(i),
            batch.degree_bits[i],
            is_zk_usize,
            pcs.log_min_trace_height(),
            pcs.log_max_trace_height(),
        )
        .map_err(boxed)?;
        ext_domain_sizes.push(ext_size);
        let pre_w = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);
        let layout = AirLayout {
            preprocessed_width: pre_w,
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        };
        let log_chunks = get_log_num_quotient_chunks_for_domain::<_, EF, _, _>(
            air,
            layout,
            pcs.natural_domain_for_degree(1usize << base_db),
            all_lookups[i].as_ref(),
            is_zk_usize,
            &gadget,
        );
        log_num_quotient_chunks.push(log_chunks);
    }

    // Replay the batch transcript to recover the challenges the fold consumes.
    let shape = BatchShape {
        trace_widths: airs.iter().map(BaseAir::<F>::width).collect(),
        public_value_counts: airs.iter().map(BaseAir::<F>::num_public_values).collect(),
        preprocessed_widths: preprocessed_widths.clone(),
        has_preprocessed_commitment: common.preprocessed.is_some(),
        num_lookup_instances: all_lookups.iter().filter(|c| !c.is_empty()).count(),
        lookup_pow_bits: config.lookup_proof_of_work_bits(),
        has_randomization_commitment: is_zk,
        ood_pow_bits: config.ood_proof_of_work_bits(),
    };
    let mut challenger = config.initialise_challenger();
    let mut transcript =
        BatchVerifierTranscript::<Challenger, F, EF, Commitment>::new(&mut challenger, shape);
    transcript.instance_bindings(&batch.degree_bits);
    transcript.main_phase(batch.commitments.main.clone(), &public_values);
    transcript.preprocessed_phase(common.preprocessed.as_ref().map(|g| g.commitment.clone()));
    let laid_out = transcript
        .lookup_phase(all_lookups, &gadget, batch.lookup_pow_witness)
        .map_err(boxed)?;
    let terminal_values: Vec<EF> = batch
        .lookup_terminals
        .iter()
        .flatten()
        .map(|t| t.0)
        .collect();
    let constraint_alpha =
        transcript.permutation_phase(batch.commitments.permutation.clone(), &terminal_values);
    transcript.quotient_phase(
        batch.commitments.quotient_chunks.clone(),
        batch.commitments.random.clone(),
    );
    let zeta = transcript.ood_phase(batch.ood_pow_witness).map_err(boxed)?;
    let (coms_to_verify, quotient_domains, preprocessed_index) = commitments_with_opening_points(
        &config,
        &airs,
        zeta,
        &batch.commitments,
        &batch.opened_values,
        common,
        &batch.degree_bits,
        &preprocessed_widths,
        &log_num_quotient_chunks,
    )
    .map_err(boxed)?;

    // Finalize the transcript by replaying the delegated opening argument, exactly as
    // `verify_batch` does. Dropping an unfinalized transcript panics, and the WHIR core
    // is what makes these openings sound, so the identity below is only meaningful on
    // top of a verified opening.
    transcript
        .delegate(|ch| {
            pcs.verify_with_preprocessing(
                coms_to_verify,
                &batch.opening_proof,
                ch,
                preprocessed_index,
            )
        })
        .map_err(boxed)?;
    transcript.finish();

    // The cross-AIR terminal sum: no transcript involvement, but the contract checks
    // it too, so it is checked here.
    gadget
        .verify_terminal_sum(&batch.lookup_terminals)
        .map_err(boxed)?;

    let mut instances_json = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let ov = &batch.opened_values.instances[i];
        let lookups_i = all_lookups[i].as_ref();
        let layout = AirLayout {
            preprocessed_width: preprocessed_widths[i],
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        };

        // The global emission order (base and ext interleaved) drives the Horner fold,
        // so the layout and the constraint vectors come from one build.
        let clayout = get_constraint_layout(air, layout, lookups_i, &gadget);
        let (base_constraints, ext_constraints) =
            get_symbolic_constraints(air, layout, lookups_i, &gadget);

        let mut flat = Flattener::new();
        let mut roots = Vec::with_capacity(clayout.total_constraints());
        for g in 0..clayout.total_constraints() {
            if let Some(p) = clayout.base_indices.iter().position(|&x| x == g) {
                roots.push(flat.expr(&base_constraints[p]));
            } else {
                let q = clayout
                    .ext_indices
                    .iter()
                    .position(|&x| x == g)
                    .expect("global index lives in one of the two streams");
                roots.push(flat.expr_ext(&ext_constraints[q]));
            }
        }
        assert_eq!(
            roots.len(),
            base_constraints.len() + ext_constraints.len(),
            "every constraint is a root exactly once"
        );
        let ir = InstanceIr { roots, ..flat.ir };

        // Opened values, exactly as verify_batch hands them to the folder.
        let aux_width = if lookups_i.is_empty() {
            0
        } else {
            lookups_i.len() + 1
        };
        let recompose_perm = |flat_vals: &[EF]| -> Vec<EF> {
            if aux_width == 0 {
                return vec![];
            }
            flat_vals
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| {
                    <EF as p3_field::ExtensionField<F>>::from_ext_basis_coefficients(chunk)
                        .expect("chunk length matches DIMENSION")
                })
                .collect()
        };
        let perm_local = recompose_perm(&ov.permutation_local);
        let perm_next = recompose_perm(&ov.permutation_next);
        let width = BaseAir::<F>::width(air);
        let trace_next_owned = ov
            .base_opened_values
            .trace_next
            .clone()
            .unwrap_or_else(|| vec![EF::ZERO; width]);
        let pre_local = ov
            .base_opened_values
            .preprocessed_local()
            .map(<[EF]>::to_vec)
            .unwrap_or_default();
        let pre_next = ov
            .base_opened_values
            .preprocessed_next()
            .map_or_else(|| vec![EF::ZERO; preprocessed_widths[i]], <[EF]>::to_vec);
        let perm_values: Vec<EF> = batch.lookup_terminals[i].iter().map(|t| t.0).collect();

        let trace_domain = pcs.natural_domain_for_degree(ext_domain_sizes[i] >> is_zk_usize);
        let declared = air.periodic_columns();
        let periodic_columns = PeriodicColumns::new(&declared, trace_domain.size())?;
        let periodic_values = trace_domain.evaluate_periodic_columns_at(periodic_columns, zeta);

        let sels = trace_domain.selectors_at_point(zeta);
        let inp = EvalInputs {
            main_local: &ov.base_opened_values.trace_local,
            main_next: &trace_next_owned,
            pre_local: &pre_local,
            pre_next: &pre_next,
            perm_local: &perm_local,
            perm_next: &perm_next,
            perm_challenges: &laid_out[i],
            perm_values: &perm_values,
            public_values: &public_values[i],
            periodic_values: &periodic_values,
            is_first: sels.is_first_row,
            is_last: sels.is_last_row,
            is_transition: sels.is_transition,
        };
        let fold = fold_constraints(&ir, &inp, constraint_alpha);

        // The library quotient, and the inversion-free reformulation the contract
        // uses: Z_j(zeta) = (zeta * inv_shift_j)^(2^Lj) - 1 with inv_shift_j a
        // trusted domain constant, and invD_i = (prod_{j!=i} Z_j(first_i))^-1.
        let qc_domains = &quotient_domains[i];
        let quotient = recompose_quotient_from_chunks::<Config>(
            qc_domains,
            &ov.base_opened_values.quotient_chunks,
            zeta,
        );
        let zstars: Vec<EF> = qc_domains
            .iter()
            .map(|d| d.vanishing_poly_at_point(zeta))
            .collect();
        // The cross-domain denominators of the recompose depend on no proof data,
        // so their inverse is a trusted constant the export ships with the domains.
        let inv_d: Vec<EF> = qc_domains
            .iter()
            .enumerate()
            .map(|(i2, di)| {
                let prod: EF = qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i2)
                    .map(|(_j, dj)| lift(dj.vanishing_poly_at_point(di.first_point())))
                    .product();
                prod.try_inverse().expect("chunk domains are disjoint")
            })
            .collect();
        let qstar: EF = ov
            .base_opened_values
            .quotient_chunks
            .iter()
            .enumerate()
            .map(|(i2, chunk)| {
                let q = <EF as p3_field::ExtensionField<F>>::from_ext_basis_coefficients(chunk)
                    .expect("chunk length matches DIMENSION");
                let prod: EF = zstars
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i2)
                    .map(|(_, z)| *z)
                    .product();
                q * prod * inv_d[i2]
            })
            .sum();
        assert_eq!(
            qstar, quotient,
            "inversion-free quotient reformulation, instance {i}"
        );

        // The identity the contract checks.
        assert_eq!(
            fold * sels.inv_vanishing,
            quotient,
            "constraint identity mismatch, instance {i}"
        );

        // Trusted domain parameters: the contract recomputes the selectors and the
        // chunk vanishing polynomials from these plus `zeta`, and the pin below
        // checks its answers against the exported ones.
        let trace_log_size = log2_size(trace_domain.size());
        let trace_shift = trace_domain.first_point();
        // `next_point(x) = x * h`, so `h_inv = first_point / next_point(first_point)`.
        let h = trace_domain
            .next_point(trace_shift)
            .expect("coset domains step by a generator")
            / trace_shift;
        let h_inv = h.try_inverse().expect("generator is nonzero");
        // Flat arrays throughout: the Solidity pin parses each field with
        // `parseJsonUintArray`, which cannot express nested arrays.
        let nodes_flat: Vec<u32> = ir.nodes.iter().flat_map(Node::encode).collect();
        let ext_consts_flat: Vec<u32> = ir.ext_consts.iter().flatten().copied().collect();
        let trace_inv_shift = trace_shift.try_inverse().expect("domain shift is nonzero");
        let chunk_domains_json: Vec<_> = qc_domains
            .iter()
            .map(|d| {
                let first = d.first_point();
                json!({
                    "log_size": log2_size(d.size()),
                    "shift": first.as_canonical_u32(),
                    "inv_shift": first.try_inverse().expect("nonzero shift").as_canonical_u32(),
                })
            })
            .collect();
        let quotient_chunks_flat: Vec<u32> = ov
            .base_opened_values
            .quotient_chunks
            .iter()
            .flat_map(|c| {
                ext_coeffs(
                    <EF as p3_field::ExtensionField<F>>::from_ext_basis_coefficients(c)
                        .expect("chunk length matches DIMENSION"),
                )
            })
            .collect();
        instances_json.push(json!({
            "index": i,
            "width": width,
            "num_constraints": ir.roots.len(),
            "nodes": nodes_flat,
            "base_consts": ir.base_consts,
            "ext_consts": ext_consts_flat,
            "roots": ir.roots,
            "trace_domain": {
                "log_size": trace_log_size,
                "shift": trace_shift.as_canonical_u32(),
                "inv_shift": trace_inv_shift.as_canonical_u32(),
                "h_inv": h_inv.as_canonical_u32(),
            },
            "num_chunks": qc_domains.len(),
            "chunk_domains": chunk_domains_json,
            "inv_d": exts_flat(&inv_d),
            "zstars_expected": exts_flat(&zstars),
            "quotient_chunks": quotient_chunks_flat,
            "opened": {
                "main_local": exts_flat(&ov.base_opened_values.trace_local),
                "main_next": exts_flat(&trace_next_owned),
                "pre_local": exts_flat(&pre_local),
                "pre_next": exts_flat(&pre_next),
                "perm_local": exts_flat(&perm_local),
                "perm_next": exts_flat(&perm_next),
                "perm_challenges": exts_flat(&laid_out[i]),
                "perm_values": exts_flat(&perm_values),
                "public_values": public_values[i]
                    .iter()
                    .map(PrimeField32::as_canonical_u32)
                    .collect::<Vec<_>>(),
                "periodic_values": exts_flat(&periodic_values),
            },
            "selectors_expected": {
                "is_first": ext_json(&sels.is_first_row),
                "is_last": ext_json(&sels.is_last_row),
                "is_transition": ext_json(&sels.is_transition),
                "inv_vanishing": ext_json(&sels.inv_vanishing),
            },
            "expected_fold": ext_json(&fold),
            "expected_quotient": ext_json(&quotient),
        }));
    }

    let doc = json!({
        "description": "Constraint-identity vectors for the settlement batch verifier",
        "field": "KoalaBear",
        "extension": 4,
        "base_trace": BASE_TRACE,
        "degree_bits": batch.degree_bits,
        "zeta": ext_json(&zeta),
        "constraint_alpha": ext_json(&constraint_alpha),
        "instances": instances_json,
    });
    let path = artifact_path();
    std::fs::write(&path, serde_json::to_vec_pretty(&doc)?).map_err(boxed)?;
    // Three u32 words per flattened node.
    let total_nodes: usize = instances_json
        .iter()
        .map(|v| v["nodes"].as_array().map_or(0, |arr| arr.len() / 3))
        .sum();
    println!("wrote {}", path.display());
    println!(
        "instances: {}, total DAG nodes: {}",
        instances_json.len(),
        total_nodes
    );
    Ok(())
}
