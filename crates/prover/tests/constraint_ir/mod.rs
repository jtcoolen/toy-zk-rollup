//! Shared constraint-IR machinery: the symbolic-constraint flattener and the
//! fold evaluator both vector exporters (constraint_identity_vectors,
//! composed_vectors) drive on the SAME proof run the bundle ships.
//!
//! The settlement AIRs are generated (Poseidon2 / recompose / statement tables),
//! so the constraints cannot be hand-written in Solidity. They are trusted-setup
//! data: each constraint's expression DAG is flattened to a post-order op list
//! (shared subtrees emitted once, referenced by node index) and the Solidity
//! side is a DAG interpreter (contracts/src/verifier/ConstraintIdentity.sol).
//!
//! Field types are the settlement pair (KoalaBear, quartic extension) both
//! consumers use: production `prover::whir::Config` challenges and the semantic
//! fixture's `Challenge` are the same `BinomialExtensionField<KoalaBear, 4>`.

use std::collections::HashMap;
use std::sync::Arc;

use p3_air::symbolic::{
    BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression, SymbolicExpressionExt,
};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;

/// Base field of the settlement batch.
pub(crate) type F = KoalaBear;
/// Quartic extension the settlement constraints fold into.
pub(crate) type EF = BinomialExtensionField<F, 4>;

/// Post-order IR node. Arithmetic nodes reference child node indices, so shared
/// subtrees are emitted once and the program is a DAG, not a tree.
#[derive(Clone, Debug)]
pub(crate) enum Node {
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
    pub(crate) const fn encode(&self) -> [u32; 3] {
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
pub(crate) struct InstanceIr {
    pub(crate) nodes: Vec<Node>,
    pub(crate) base_consts: Vec<u32>,
    pub(crate) ext_consts: Vec<[u32; 4]>,
    /// Constraint roots in GLOBAL emission order (base and ext interleaved by the
    /// layout): the fold `acc = acc*alpha + C_g` walks this list front to back.
    pub(crate) roots: Vec<usize>,
}

/// DAG flattener with pointer-identity memoization. `SymbolicExpr` shares subtrees
/// through `Arc`, so emitting each distinct node once keeps the program linear in
/// distinct nodes rather than exponential in shared subtrees.
pub(crate) struct Flattener {
    pub(crate) ir: InstanceIr,
    seen: HashMap<usize, usize>,
}

impl Flattener {
    pub(crate) fn new() -> Self {
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
    pub(crate) fn expr(&mut self, e: &SymbolicExpression<F>) -> usize {
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
    pub(crate) fn expr_ext(&mut self, e: &SymbolicExpressionExt<F, EF>) -> usize {
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
pub(crate) fn ext_coeffs(v: EF) -> [u32; 4] {
    let s = <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&v);
    [
        s[0].as_canonical_u32(),
        s[1].as_canonical_u32(),
        s[2].as_canonical_u32(),
        s[3].as_canonical_u32(),
    ]
}

pub(crate) fn ext_json(v: &EF) -> Vec<u32> {
    ext_coeffs(*v).to_vec()
}

/// Flat concatenation of basis coefficients: four u32s per element.
pub(crate) fn exts_flat(vs: &[EF]) -> Vec<u32> {
    vs.iter().flat_map(|v| ext_coeffs(*v)).collect()
}

/// The opened values one instance's constraint program consumes, as the contract sees
/// them: everything the opening argument returns plus the transcript challenges.
pub(crate) struct EvalInputs<'a> {
    pub(crate) main_local: &'a [EF],
    pub(crate) main_next: &'a [EF],
    pub(crate) pre_local: &'a [EF],
    pub(crate) pre_next: &'a [EF],
    pub(crate) perm_local: &'a [EF],
    pub(crate) perm_next: &'a [EF],
    pub(crate) perm_challenges: &'a [EF],
    pub(crate) perm_values: &'a [EF],
    pub(crate) public_values: &'a [F],
    pub(crate) periodic_values: &'a [EF],
    pub(crate) is_first: EF,
    pub(crate) is_last: EF,
    pub(crate) is_transition: EF,
}

/// Evaluate the constraint DAG and fold it with `alpha` by Horner, exactly as the
/// verifier folder does: `acc = acc*alpha + C_g` over the roots in emission order.
///
/// The selector leaves carry denominators, but they are per-instance constants
/// (`s1`, `s2`, `zh` depend only on `zeta` and the domain), so the contract pays
/// three extension inversions per instance rather than reformulating the fold.
pub(crate) fn fold_constraints(ir: &InstanceIr, inp: &EvalInputs<'_>, alpha: EF) -> EF {
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
pub(crate) fn lift(x: F) -> EF {
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(&[x, F::ZERO, F::ZERO, F::ZERO])
        .expect("4 coefficients")
}

/// log2 of a power-of-two size.
pub(crate) const fn log2_size(n: usize) -> usize {
    n.trailing_zeros() as usize
}
