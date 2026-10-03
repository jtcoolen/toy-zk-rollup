//! End-to-end WHIR proof vectors: the smallest proof the settlement verifier's
//! core has to accept, plus everything the contract needs to replay it.
//!
//! Regenerate with:
//!
//! `text
//! cargo test -p prover --test whir_proof_vectors -- --ignored --nocapture
//! `
//!
//! # Why a small shape
//!
//! The settlement schedule is 25 variables, 4 rounds, 257 queries. Porting the
//! verifier core against that shape means debugging a 180 KB proof against a
//! 3000-line Solidity port with no way to bisect. This file drives the SAME code
//! path at a shape small enough that the whole transcript program fits on one
//! screen: one matrix, two columns, stacked arity 10, two WHIR rounds, grinding
//! off. The engine is shape-generic - `WhirConfig` derives every round parameter
//! from `(num_variables, ProtocolParameters)` - so a core that accepts here
//! accepts at 25 variables, and the production schedule stays a separate
//! generated artifact (`WhirFixedConfig.sol`) rather than something the port
//! hardcodes.
//!
//! The schedule is emitted INTO the vector file, so the Solidity test builds its
//! own `RoundConfig[]` from it instead of importing the production table. That
//! keeps the core testable at any shape and forces the production wrapper to be a
//! thin adapter rather than the only caller.
//!
//! # Where every number comes from
//!
//! The rule established across this port (D-058): golden vectors come from the
//! function the prover itself calls, never from a reimplementation of its
//! formula. Concretely:
//!
//! - the proof is produced by `p3_commit::Pcs::open` on the real `WhirUniPcs`
//!   and accepted by `p3_commit::Pcs::verify` - the same entry point the batch
//!   STARK verifier uses, so the rescale check `bound * scale == claimed` is
//!   exercised too;
//! - `claimed_eval`, the batching challenge and the initial constraint's
//!   equality points come from `LayoutVerifier::batching_challenge` /
//!   `constraint` / `Constraint::combine_evals`, driven inside
//!   `WhirVerifierTranscript::delegate_initial_fold` exactly as
//!   `WhirVerifier::replay` drives them;
//! - the fixed byte blobs the contract must absorb are not transcribed from a
//!   reading of the layout code. They are the observation sites a traced
//!   challenger recorded whose value is identical across every witness, which is
//!   the operational definition of "fixed by the config" (D-059).
//!
//! # Determinism
//!
//! Not deterministic, and deliberately so: the mask is drawn from an OS-seeded
//! stream that the caller cannot seed, which is also what makes the fixed/varying
//! classification meaningful. The artifacts are therefore pinned snapshots, and
//! the non-ignored test at the bottom re-checks their SHAPE so a stale file fails
//! loudly instead of silently teaching the Solidity side the wrong schedule.

use p3_challenger::{CanObserve, HashChallenger, SerializingChallenger32};
use p3_commit::{CommitmentOpening, MatrixOpening, OpeningRequest, Pcs as _, PointOpening};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::whir::uni::plan::checked_stacked_num_variables;
use p3_recursion::pcs::whir::uni::{padded_arity, univariate_eq_point, WhirUniPcs};
use p3_sumcheck::constraints::statement::eq::EqStatement;
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::layout::{Layout as _, PrefixProver, Verifier};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_whir::parameters::{
    FoldingFactor, ProtocolParameters, RoundConfig, SecurityAssumption, WhirConfig,
};
use p3_whir::pcs::proof::{PcsProof, WhirProof};
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};
use prover::config::mmcs;
use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::{SemChallenger, SemEvent, SemProgram, SemSink};
use prover::whir::{Challenge, Dft};
use prover::F;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use serde_json::json;
use std::error::Error;

/// Log2 of the witness matrix height, before the mask doubles it.
///
/// Chosen so the stacked arity leaves real intermediate WHIR rounds. The folding
/// schedule stops once six variables remain, so arity 10 folds 4 and sends the
/// rest directly: zero intermediate rounds, and the contract's per-round loop -
/// commitments, OOD samples, STIR queries, round sumchecks - would never run.
/// Arity 11 folds 4 then 4, leaving 3 for the closing sumcheck: one full
/// intermediate round plus the terminal phase, which is the smallest shape that
/// exercises the loop body. Production is 25 variables and derives 4 rounds from
/// the same derivation; the round COUNT comes from the generated schedule, so a
/// core correct at 1 round is correct at 4.
const LOG_ROWS: usize = 9;
/// Columns of the witness matrix. Two is the smallest width that puts selector
/// bits in the stacked layout: one matrix of arity 10 and width 2 stacks to arity
/// 11, so each column carries one selector bit and `StackedSelector::lift_prefix`
/// is exercised rather than skipped.
const WIDTH: usize = 2;
/// WHIR folding factor. Four is the settlement value; a port tested at 2 would
/// never see the quartic sumcheck degree that dominates the real verifier.
const FOLDING: usize = 4;
/// Security level. The vendored WHIR tests use 32, which keeps the query counts -
/// and so the proof - small. Soundness is not what a vector pins.
const SECURITY_LEVEL: usize = 32;
/// Grinding off. Every proof-of-work site then has difficulty zero, which the
/// native verifier pins to a zero witness without absorbing anything
/// (`NonCanonicalPowWitness`), so the first port of the core has no grinding loop
/// to chase. Grinding itself is covered by the production semantic program, where
/// 23 witness checks at difficulties 1..8 are pinned.
const POW_BITS: usize = 0;
/// Distinct witnesses to record. The classification of an observation site as
/// config-fixed rests on the site not moving across witnesses, so it needs more
/// than one; three separates "constant" from "coincidence" once the mask is
/// random, and each extra witness costs a full proof.
const RUNS: usize = 3;
/// Cap height. Zero means the commitment is a single 32-byte digest, which is
/// what the contract absorbs as one `observeHashU8Digest`.
const CAP_HEIGHT: usize = 0;
/// Largest committed height the instance accepts, as a log2. Production uses 22;
/// the value only bounds what the instance will accept, so matching production
/// keeps the vector honest about the config it claims to describe.
const LOG_MAX_LDE: usize = 22;

/// The verifier-side WHIR transcript over the traced challenger.
type SemVerifierTranscript<'a> = WhirVerifierTranscript<'a, SemChallenger, F, Challenge>;

/// The traced PCS type: production types with only the challenger wrapped.
type SemPcs =
    WhirUniPcs<Challenge, F, Dft, prover::config::Mmcs, SemChallenger, PrefixProver<F, Challenge>>;
/// The commitment type the settlement MMCS produces: a Merkle cap of one digest.
type Commitment = <prover::config::Mmcs as p3_commit::Mmcs<F>>::Commitment;
/// The proof type, as the PCS declares it.
type UniProof = <SemPcs as p3_commit::Pcs<Challenge, SemChallenger>>::Proof;

const fn params() -> ProtocolParameters {
    ProtocolParameters {
        security_level: SECURITY_LEVEL,
        pow_bits: POW_BITS,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(FOLDING),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn sem_challenger_with(sink: &SemSink) -> SemChallenger {
    let inner = SerializingChallenger32::new(HashChallenger::new(Vec::new(), Keccak256Hash {}));
    SemChallenger::new(inner, sink.clone())
}

/// A traced PCS over a fresh sink.
fn sem_pcs() -> SemPcs {
    let sink = SemSink::new();
    SemPcs::new(
        params(),
        Dft::default(),
        mmcs(CAP_HEIGHT),
        sem_challenger_with(&sink),
        LOG_MAX_LDE,
    )
}

/// Log2 of the committed (already doubled) height.
const LOG_COMMITTED: usize = LOG_ROWS + 1;

/// Stacked arity of the committed batch, derived the way the verifier derives it.
fn stacked_arity() -> usize {
    checked_stacked_num_variables([(padded_arity(LOG_COMMITTED, FOLDING), WIDTH)])
        .expect("test shape fits")
}

/// The opening schedule this statement implies, rebuilt the way the verifier
/// rebuilds it: from the public shapes, not from the proof.
///
/// This mirrors `round_schedule`, which is `pub(crate)` and so unreachable from
/// here. Rebuilding it from the same public pieces is deliberate: if the two ever
/// disagree, the native `verify` below fails and says so.
fn protocol() -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(LOG_COMMITTED, WIDTH),
        vec![OpeningBatch::new((0..WIDTH).collect(), Vec::new()); 2],
    )])
    .pad_to_min_num_variables(FOLDING)
}

/// The prescribed univariate opening points: `zeta` and its shift, the two a
/// univariate STARK opens a trace at. Two points is also the smallest case where
/// one matrix carries two opening batches, so the batch ordering is something a
/// port can get backwards and be caught.
fn zetas() -> Vec<Challenge> {
    // A genuine extension element, not a base field element wearing an extension
    // type. A base-field zeta makes `expand_from_univariate` emit base-field
    // coordinates, so every equality point in the statement would land in the base
    // field and the contract's extension-field eq-eval path would go untested.
    // Real uni-stark zetas are extension samples; this matches that.
    // All four basis coefficients non-zero, and deliberately so. A sparse zeta makes
    // the evaluations derived from it sparse too, and a zero limb is indistinguishable
    // from a shape constant that happens to be zero: the cross-run classifier sees a
    // word that never moves and files it as config-fixed, so the contract would
    // hard-code a limb of the claimed evaluation instead of reading it from the
    // proof. That is a soundness bug the transcript still walks cleanly, which is what
    // makes it dangerous - see the ambiguity guard below.
    let zeta = Challenge::from_u32(9_999) * Challenge::from_u32(1 << 20)
        + Challenge::from_u32(7)
        + Challenge::from_basis_coefficients_fn(|i| {
            // The same four values 31_337 + 1_000_003 * (i + 1) produces, written
            // out so no usize-to-u32 cast is needed to spell them.
            const COEFFS: [u32; 4] = [1_031_340, 2_031_343, 3_031_346, 4_031_349];
            F::from_u32(*COEFFS.get(i).unwrap_or(&1))
        });
    let domain = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, LOG_COMMITTED)
        .expect("committed height within the field's two-adicity");
    vec![zeta, zeta * Challenge::from(domain.subgroup_generator())]
}

/// The multilinear points the schedule derives from the prescribed zetas, via the
/// public bridge: `univariate_eq_point(zeta, padded_arity)`.
fn super_points() -> Vec<Point<Challenge>> {
    let arity = padded_arity(LOG_COMMITTED, FOLDING).get();
    zetas()
        .iter()
        .map(|&zeta| univariate_eq_point(zeta, arity).0)
        .collect()
}

/// The WHIR config the run actually used, read back from the same parameters.
fn whir_config(arity: usize) -> WhirConfig<Challenge, F, SemChallenger> {
    WhirConfig::new(arity, params()).expect("test shape is a valid WHIR shape")
}

/// Extension coefficients as canonical u32s, low order first - the same encoding
/// every other vector file in this directory uses.
fn ext_json(v: &Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField32::as_canonical_u32)
        .collect()
}

/// A point as a JSON array of extension elements.
fn point_json(p: &Point<Challenge>) -> Vec<Vec<u32>> {
    p.as_slice().iter().map(ext_json).collect()
}

/// Hex for the Solidity side, which reads `hex"..."` literals.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            // Writing into a String cannot fail; ignoring the Result is the documented
            // idiom for `write!` into a `String`.
            let _ = write!(&mut s, "{b:02x}");
            s
        })
}

/// Draw a witness matrix. Fresh OS randomness per run: the mask is random
/// anyway, and a witness that repeated across runs would let a site carrying
/// witness data masquerade as config-fixed.
fn random_matrix(rng: &mut SmallRng) -> RowMajorMatrix<F> {
    let height = 1 << LOG_ROWS;
    let values: Vec<F> = (0..height * WIDTH)
        .map(|_| F::from_u32(rng.random::<u32>() % F::ORDER_U32))
        .collect();
    RowMajorMatrix::new(values, WIDTH)
}

/// The doubled domain the statement declares for the masked trace.
fn domain() -> TwoAdicMultiplicativeCoset<F> {
    TwoAdicMultiplicativeCoset::<F>::new(F::ONE, LOG_COMMITTED)
        .expect("committed height within the field's two-adicity")
}

/// One full prover/verifier cycle at a given witness seed.
struct Run {
    commitment: Commitment,
    /// Univariate claims, `[matrix][point][column]`.
    opened: Vec<Vec<Vec<Vec<Challenge>>>>,
    proof: UniProof,
    /// The VERIFIER-side transcript program: what the contract must reproduce.
    program: SemProgram,
}

/// Commit, open, re-encode through postcard, and verify - recording the verifier's
/// transcript.
///
/// The initial commitment is absorbed by the caller's challenger on BOTH sides:
/// `WhirUniPcs::commit` takes no transcript (it absorbs into a throwaway clone of
/// `challenger_proto`), so the STARK layer is what binds the root. Absorbing it
/// identically on both sides is what keeps every later challenge in step; the
/// production batch-STARK layer adds its own separators around this, and those are
/// captured by the production semantic program artifact.
///
/// The proof is round-tripped through postcard before it is verified, so the bytes
/// the contract will read are the bytes that were checked.
fn prove(seed: u64) -> Result<Run, Box<dyn Error>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let matrix = random_matrix(&mut rng);
    let zetas = zetas();

    let pcs = sem_pcs();
    let (commitment, prover_data) = pcs
        .commit(vec![(domain(), matrix)])
        .map_err(Box::<dyn Error>::from)?;

    let mut prover_ch = sem_challenger_with(&SemSink::new());
    prover_ch.observe(commitment.clone());
    let (opened, proof) = pcs
        .open(
            vec![OpeningRequest {
                prover_data: &prover_data,
                points: vec![zetas.clone()],
            }],
            &mut prover_ch,
        )
        .map_err(Box::<dyn Error>::from)?;

    // The wire format is postcard, and the contract decodes postcard. Verifying the
    // DECODED proof is what makes the `proof_hex` field a checked value rather
    // than a parallel description that could drift from the object it encodes.
    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: UniProof = postcard::from_bytes(&bytes)?;

    let sink = SemSink::new();
    let mut verifier_ch = sem_challenger_with(&sink);
    verifier_ch.observe(commitment.clone());
    let claims = vec![CommitmentOpening {
        commitment: commitment.clone(),
        matrices: vec![MatrixOpening {
            domain: domain(),
            points: zetas
                .iter()
                .zip(&opened[0][0])
                .map(|(&point, values)| PointOpening {
                    point,
                    values: values.clone(),
                })
                .collect(),
        }],
    }];
    pcs.verify(claims, &decoded, &mut verifier_ch)
        .map_err(|e| format!("the native verifier rejected its own proof: {e:?}"))?;

    Ok(Run {
        commitment,
        opened,
        proof: decoded,
        program: sink.program(),
    })
}

/// Everything a faithful replay of the verifier's transcript produces.
///
/// These are the quantities the contract has to arrive at on its own. Exporting
/// them from a replay - rather than reading them out of the prover - is what makes
/// them golden: the Solidity side is checked against values obtained by walking the
/// transcript the same way the native verifier does, and the assertion in the
/// generator test that this replay's event stream is IDENTICAL to the native
/// verifier's transcript pins that the walk is faithful.
struct Replay {
    /// Layout batching challenge `alpha`, the first extension sample the verifier
    /// draws. The contract must recognize this draw: it rebuilds the combined
    /// constraint from it, and a verifier that skipped it would desynchronise the
    /// sponge for every later sample.
    alpha: Challenge,
    /// Batching challenge `gamma` weighting the initial constraint's statements.
    gamma: Challenge,
    /// Initial claimed evaluation, before the sumcheck folds it.
    claimed_eval: Challenge,
    /// The point the initial sumcheck reduces the claim to.
    randomness: Vec<Challenge>,
    /// Equality points of the initial constraint, in batching-power order.
    eq_points: Vec<Point<Challenge>>,
    /// Arity the initial constraint lives in.
    num_variables: usize,
    /// Out-of-domain points, in the order drawn.
    ood_points: Vec<Challenge>,
    /// Per-round batching challenges for the STIR selection statements.
    round_batching: Vec<Challenge>,
    /// Query indices per WHIR round, plus one final entry for the terminal round.
    query_indices: Vec<Vec<usize>>,
    /// The point each round's sumcheck reduces to.
    round_randomness: Vec<Vec<Challenge>>,
    /// The point the closing sumcheck reduces to, when there is one.
    final_randomness: Option<Vec<Challenge>>,
    /// The transcript event stream this replay produced.
    program: SemProgram,
}

/// The output of the intermediate-round phase of a transcript walk.
struct RoundWalk {
    /// Out-of-domain points, in the order drawn.
    ood_points: Vec<Challenge>,
    /// Per-round batching challenges for the STIR selection statements.
    round_batching: Vec<Challenge>,
    /// Query indices per WHIR round.
    query_indices: Vec<Vec<usize>>,
    /// The point each round's sumcheck reduces to.
    round_randomness: Vec<Vec<Challenge>>,
}

/// Walk the intermediate WHIR rounds of the verifier transcript.
///
/// One round is: bind the round commitment, draw and answer the out-of-domain
/// points, check the query proof-of-work, draw the query indices, draw the round
/// batching challenge, then fold with the round sumcheck. The contract performs the
/// identical sequence per round, so this is the shape its loop must match.
fn replay_rounds(
    vt: &mut SemVerifierTranscript<'_>,
    whir: &WhirProof<F, Challenge, prover::config::Mmcs>,
    config: &WhirConfig<Challenge, F, SemChallenger>,
) -> Result<RoundWalk, Box<dyn Error>> {
    let mut walk = RoundWalk {
        ood_points: Vec::new(),
        round_batching: Vec::new(),
        query_indices: Vec::new(),
        round_randomness: Vec::new(),
    };
    for (round_index, (rproof, rp)) in whir
        .rounds
        .iter()
        .zip(config.round_parameters())
        .enumerate()
    {
        vt.commitment(
            rproof
                .commitment
                .as_ref()
                .expect("every intermediate round commits")
                .clone(),
        );
        for &answer in &rproof.ood_answers {
            walk.ood_points.push(vt.ood_point());
            vt.ood_answer(answer);
        }
        vt.query_pow(round_index, rproof.pow_witness)
            .map_err(|e| format!("round {round_index} query pow: {e:?}"))?;
        walk.query_indices.push(vt.query_indices(round_index));
        walk.round_batching.push(vt.round_batching());
        // The round sumcheck folds a claim the contract recomputes from its round
        // constraint, so this walk only needs the reduction point: hand it a scratch
        // claimed sum, exactly as the recursion test's walk does.
        let mut scratch = Challenge::ZERO;
        let r = vt
            .delegate_round_fold(|challenger| {
                rproof.sumcheck.verify_rounds(
                    challenger,
                    &mut scratch,
                    config.round_folding_factor(round_index + 1),
                    rp.folding_pow_bits,
                    Basis::Evaluation,
                )
            })
            .map_err(|e| format!("round {round_index} sumcheck: {e:?}"))?;
        walk.round_randomness.push(r.as_slice().to_vec());
    }
    Ok(walk)
}

/// The output of the terminal phase.
struct TerminalWalk {
    /// Terminal query indices.
    query_indices: Vec<usize>,
    /// The point the closing sumcheck reduces to, when there is one.
    final_randomness: Option<Vec<Challenge>>,
}

/// Walk the terminal phase: bind the final polynomial, check the terminal query
/// proof-of-work, draw the terminal query indices, then run the closing sumcheck.
fn replay_terminal(
    vt: &mut SemVerifierTranscript<'_>,
    whir: &WhirProof<F, Challenge, prover::config::Mmcs>,
    config: &WhirConfig<Challenge, F, SemChallenger>,
) -> Result<TerminalWalk, Box<dyn Error>> {
    let n_rounds = whir.rounds.len();
    let final_poly = whir.final_poly.as_ref().ok_or("missing final polynomial")?;
    vt.final_poly(final_poly.as_slice())
        .map_err(|e| format!("final poly: {e:?}"))?;
    vt.query_pow(n_rounds, whir.final_pow_witness)
        .map_err(|e| format!("terminal query pow: {e:?}"))?;
    let query_indices = vt.query_indices(n_rounds);
    let final_randomness = vt
        .delegate_final_fold(|challenger| {
            let mut scratch = Challenge::ZERO;
            p3_sumcheck::verify_final_sumcheck_rounds(
                whir.final_sumcheck.as_ref(),
                challenger,
                &mut scratch,
                config.final_sumcheck_rounds(),
                config.final_folding_pow_bits(),
                Basis::Evaluation,
            )
        })
        .transpose()
        .map_err(|e| format!("final sumcheck: {e:?}"))?
        .map(|p| p.as_slice().to_vec());
    Ok(TerminalWalk {
        query_indices,
        final_randomness,
    })
}

/// Replay the verifier's transcript in full and read off everything it produces.
///
/// This is not a reimplementation of `gamma` or `claimed_eval`. It is the call
/// sequence `WhirVerifier::replay` performs - `batching_challenge`,
/// `constraint`, `combine_evals`, then per round the commitment, OOD samples,
/// query `PoW`, query indices, round batching and the folded sumcheck - inside the
/// same `delegate_*` brackets, on a transcript that absorbed the same bytes in the
/// same order.
///
/// The whole pattern has to be walked, not just the initial fold: p3's typed
/// transcript refuses to finalize while pattern steps remain, and it panics on drop
/// if it is not finalized. Walking it fully is also what makes the equality check
/// against the native verifier's own transcript possible.
fn replay_verifier(run: &Run) -> Result<Replay, Box<dyn Error>> {
    let arity = stacked_arity();
    let config = whir_config(arity);
    let protocol = protocol();
    let points = super_points();
    let whir = &run.proof.rounds[0].whir;

    let sink = SemSink::new();
    let mut ch = sem_challenger_with(&sink);
    ch.observe(run.commitment.clone());

    let mut layout = Verifier::<F, Challenge>::new(
        &protocol.table_shapes(),
        PrefixProver::<F, Challenge>::strategy(),
    );
    for &eval in &whir.initial_ood_answers {
        layout.add_virtual_eval(eval, &mut ch);
    }
    for (((table_idx, batch), evals), point) in protocol
        .iter_openings()
        .zip(&run.proof.rounds[0].evals)
        .zip(&points)
    {
        layout
            .add_claim_at(table_idx, batch, point, evals, &mut ch)
            .map_err(|e| format!("add_claim_at: {e:?}"))?;
    }

    let shape = WhirShape::new(&config, protocol.num_openings());
    let mut vt = WhirVerifierTranscript::<SemChallenger, F, Challenge>::new(&mut ch, shape);
    let (constraint, alpha, claimed_eval, randomness) = vt.delegate_initial_fold(|challenger| {
        let alpha = layout.batching_challenge(challenger);
        let constraint = layout.constraint(alpha);
        let mut claimed = Challenge::ZERO;
        constraint.combine_evals(&mut claimed);
        let r = whir.initial_sumcheck.verify_rounds(
            challenger,
            &mut claimed,
            config.round_folding_factor(0),
            config.starting_folding_pow_bits(),
            Basis::Evaluation,
        );
        (constraint, alpha, claimed, r)
    });
    let initial_randomness = randomness.map_err(|e| format!("initial sumcheck: {e:?}"))?;
    assert_eq!(
        initial_randomness.num_variables(),
        config.round_folding_factor(0),
        "the initial sumcheck must fold exactly the first round's arity"
    );

    let rounds = replay_rounds(&mut vt, whir, &config)?;
    let terminal = replay_terminal(&mut vt, whir, &config)?;
    vt.finish();

    // The constraint holds only equality statements at this point - the selection
    // group is added per WHIR round, not in the initial phase - which is what makes
    // the flattened point list line up with the `gamma` powers. A Next or Select
    // group would consume powers this flattening cannot see, so it is an error here
    // rather than a silent misalignment.
    let mut eq_points: Vec<Point<Challenge>> = Vec::new();
    for statement in constraint.statements() {
        let Statements::Eq(eq) = statement else {
            return Err("the initial constraint must hold only equality statements".into());
        };
        let eq: &EqStatement<Challenge> = eq;
        eq_points.extend(eq.iter().map(|(p, _)| p.clone()));
    }

    // The contract's query schedule is the per-round sets followed by the terminal
    // set, so the artifact stores them concatenated in that order.
    let mut query_indices = rounds.query_indices;
    query_indices.push(terminal.query_indices);
    Ok(Replay {
        alpha,
        gamma: challenge_of(&constraint),
        claimed_eval,
        randomness: initial_randomness.as_slice().to_vec(),
        eq_points,
        num_variables: constraint.num_variables(),
        ood_points: rounds.ood_points,
        round_batching: rounds.round_batching,
        query_indices,
        round_randomness: rounds.round_randomness,
        final_randomness: terminal.final_randomness,
        program: sink.program(),
    })
}

/// The batching challenge `gamma` that weights the constraint's statements.
///
/// `challenge_powers(shift)` yields `gamma^shift, gamma^(shift+1), ...`, so the
/// first element at `shift = 1` is `gamma` itself.
fn challenge_of(constraint: &Constraint<F, Challenge>) -> Challenge {
    constraint
        .challenge_powers(1)
        .next()
        .expect("challenge_powers is an infinite sequence")
}

/// The maximal runs of config-fixed observations, as byte strings.
///
/// This is the artifact decision D-059 settled on: rather than porting the
/// layout's shape-fingerprint machinery to Solidity so it can regenerate the
/// separators, the contract absorbs the separator bytes verbatim at the
/// structurally known sites. The runs are exported from a real run, so nothing in
/// the contract is transcribed from a reading of the Rust.
///
/// A run contains ONLY bytes the contract may hard-code. A commitment digest is
/// proof data - it moves with every mask draw - so it never joins a run and it
/// breaks one: a contract that absorbed a digest out of a hard-coded blob would be
/// absorbing a stale commitment instead of the proof's. `classify_observations`
/// already answers `None` for every digest position that moved between runs, so
/// "classified fixed" alone is the whole membership rule.
/// Fails if a config-fixed zero sits between two varying observations.
///
/// That pattern is the signature of a zero LIMB of a proof-derived extension element:
/// the limbs either side belong to the same element and move, while the zero limb does
/// not, so cross-run comparison files it as config-fixed. The contract would then
/// absorb a hard-coded zero where it must absorb a limb of the proof's claimed
/// evaluation - the transcript stops binding the claim, and every later sample still
/// looks self-consistent because both sides made the same mistake.
///
/// A zero with a fixed neighbour on either side is a genuine shape constant and is
/// fine; the production artifact carries 839 of them.
///
/// # Errors
///
/// Describes the first ambiguous position found.
fn check_no_ambiguous_zeros(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
) -> Result<(), Box<dyn Error>> {
    let is_zero_fixed = |i: usize| {
        matches!(
            (&fixed[i], &program[i]),
            (Some(words), SemEvent::ObserveBase { .. }) if words.iter().all(|&w| w == 0)
        )
    };
    let varies = |i: usize| fixed[i].is_none();
    for i in 1..program.len().saturating_sub(1) {
        if is_zero_fixed(i) && varies(i - 1) && varies(i + 1) {
            return Err(format!(
                "observation {i} is a fixed zero between two varying observations: a zero                  limb of proof data would be misclassified as config-fixed, so no limb of                  any proof-derived extension element may be zero"
            )
            .into());
        }
    }
    Ok(())
}

fn fixed_runs(program: &SemProgram, fixed: &[Option<Vec<u32>>]) -> Vec<String> {
    let mut runs: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for (i, event) in program.iter().enumerate() {
        let fixed_here = match (&fixed[i], event) {
            (Some(words), SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }) => {
                current.extend(words.iter().flat_map(|w| w.to_le_bytes()));
                true
            }
            _ => false,
        };
        if !fixed_here && !current.is_empty() {
            runs.push(hex(&current));
            current.clear();
        }
    }
    if !current.is_empty() {
        runs.push(hex(&current));
    }
    runs
}

/// The schedule as the contract sees it: one entry per WHIR round, plus the
/// terminal configuration.
///
/// The folded-domain generator is not a p3-whir `RoundConfig` field - the native
/// code recomputes it from the folded domain size - so it is derived here the same
/// way `prover::fixed_config` derives it, keeping the two artifacts consistent.
fn schedule_json(config: &WhirConfig<Challenge, F, SemChallenger>) -> serde_json::Value {
    let round = |r: &RoundConfig| {
        json!({
            "pow_bits": r.pow_bits,
            "folding_pow_bits": r.folding_pow_bits,
            "num_queries": r.num_queries,
            "ood_samples": r.ood_samples,
            "num_variables": r.num_variables,
            "folding_factor": r.folding_factor,
            "log_inv_rate": r.log_inv_rate,
            "domain_size": r.domain_size,
            "log_folded_domain_size": r.log_folded_domain_size,
            "folded_domain_gen": F::two_adic_generator(r.log_folded_domain_size).as_canonical_u32(),
        })
    };
    json!({
        "rounds": config.round_parameters().iter().map(round).collect::<Vec<_>>(),
        "final_round": round(&config.final_round_config()),
    })
}

/// A tampered proof the verifier must reject, and the reason it was built.
///
/// Each control mutates exactly one field the contract reads. If the native
/// verifier accepted any of them, that field carries data nothing checks - a
/// soundness finding in the protocol, and a hole the Solidity port would inherit.
fn rejects(
    label: &str,
    f: impl FnOnce(&mut PcsProof<F, Challenge, prover::config::Mmcs>),
) -> Result<serde_json::Value, Box<dyn Error>> {
    let run = prove(0)?;
    let mut proof = run.proof.clone();
    f(&mut proof.rounds[0]);
    let pcs = sem_pcs();
    let mut ch = sem_challenger_with(&SemSink::new());
    ch.observe(run.commitment.clone());
    let claims = vec![CommitmentOpening {
        commitment: run.commitment.clone(),
        matrices: vec![MatrixOpening {
            domain: domain(),
            points: zetas()
                .iter()
                .zip(&run.opened[0][0])
                .map(|(&point, values)| PointOpening {
                    point,
                    values: values.clone(),
                })
                .collect(),
        }],
    }];
    let outcome = pcs.verify(claims, &proof, &mut ch);
    Ok(json!({
        "label": label,
        "rejected": outcome.is_err(),
        "error": format!("{:?}", outcome.err()),
    }))
}

/// Increment the last coefficient of a slice-backed polynomial.
fn bump_last<T: PrimeCharacteristicRing + Copy>(evals: &mut [T]) {
    if let Some(last) = evals.last_mut() {
        *last += T::ONE;
    }
}

/// One mutation per field the contract reads, each run through the native verifier.
///
/// If the native verifier accepted any of these, that field carries data nothing
/// checks - a soundness finding in the protocol itself, and a hole the Solidity port
/// would inherit. The outcomes are recorded in the artifact, so "rejected" is a
/// checked claim about the proof format rather than a claim about a run nobody can
/// inspect.
fn negative_controls() -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    // Each closure mutates exactly one field. Where a field's container has private
    // internals, the mutation rebuilds the container with the SAME shape and one
    // changed value, so what catches the tamper is the check that matters and not an
    // incidental shape mismatch.
    Ok(vec![
        rejects("claimed eval at point 0 column 0 incremented", |p| {
            let batch = &p.evals[0];
            let mut current = batch.current().to_vec();
            current[0] += Challenge::ONE;
            p.evals[0] = OpeningBatch::new(current, batch.next().to_vec());
        })?,
        rejects("initial OOD answer incremented", |p| {
            p.whir.initial_ood_answers[0] += Challenge::ONE;
        })?,
        rejects("round-0 OOD answer incremented", |p| {
            p.whir.rounds[0].ood_answers[0] += Challenge::ONE;
        })?,
        rejects("final polynomial coefficient incremented", |p| {
            let poly = p.whir.final_poly.as_mut().expect("final poly");
            bump_last(poly.as_mut_slice());
        })?,
        rejects("initial sumcheck evaluation incremented", |p| {
            p.whir.initial_sumcheck.polynomial_evaluations[0][0] += Challenge::ONE;
        })?,
    ])
}

/// Print what the recorded transcript contains, so a regenerated artifact can be
/// eyeballed against the expected shape without opening the JSON.
fn log_program_summary(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    blobs: &[String],
    varying: &[usize],
    arity: usize,
    config: &WhirConfig<Challenge, F, SemChallenger>,
) {
    let mut counts: std::collections::BTreeMap<(&'static str, usize), usize> =
        std::collections::BTreeMap::new();
    for e in program {
        *counts.entry(op_of(e)).or_insert(0usize) += 1;
    }
    println!("stacked arity {arity}, {} WHIR rounds", config.n_rounds());
    for ((kind, arg), n) in &counts {
        println!("  {kind}({arg}) x{n}");
    }
    println!(
        "observations: {} config-fixed in {} runs, {} carry proof data",
        fixed.iter().filter(|v| v.is_some()).count(),
        blobs.len(),
        varying.len()
    );
}

/// Print each negative control's outcome. A `false` here is the interesting case:
/// it would mean the native verifier cannot see that mutation.
fn log_negatives(negatives: &[serde_json::Value]) {
    for n in negatives {
        println!(
            "  reject {:?}: {} ({})",
            n["label"].as_str().unwrap_or_default(),
            n["rejected"].as_bool().unwrap_or(false),
            n["error"].as_str().unwrap_or_default(),
        );
    }
}

/// The config shape the artifact was produced under, as JSON.
///
/// Exported rather than left inline because the Solidity side reads these to size its
/// loops, and because a reader of the generator should see the SHAPE and the
/// PROOF DATA as two separate things.
fn shape_json(arity: usize, config: &WhirConfig<Challenge, F, SemChallenger>) -> serde_json::Value {
    json!({
        "log_rows": LOG_ROWS,
        "log_committed_height": LOG_COMMITTED,
        "width": WIDTH,
        "stacked_num_variables": arity,
        "folding_factor": FOLDING,
        "security_level": SECURITY_LEVEL,
        "pow_bits": POW_BITS,
        "cap_height": CAP_HEIGHT,
        "log_max_lde": LOG_MAX_LDE,
        "n_rounds": config.n_rounds(),
        "commitment_ood_samples": config.commitment_ood_samples(),
        "final_sumcheck_rounds": config.final_sumcheck_rounds(),
        "final_folding_pow_bits": config.final_folding_pow_bits(),
        "starting_folding_pow_bits": config.starting_folding_pow_bits(),
        "num_zetas": 2,
        "num_opening_claims": protocol().num_openings(),
    })
}

/// `opened[round][matrix][point][column]`, flattened to nested JSON arrays.
fn opened_json(opened: &[Vec<Vec<Vec<Challenge>>>]) -> serde_json::Value {
    json!(opened
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|m| {
                    m.iter()
                        .map(|p| p.iter().map(ext_json).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>())
}

#[test]
#[ignore = "proves RUNS times; run deliberately to regenerate the proof vectors"]
fn whir_proof_vectors() -> Result<(), Box<dyn Error>> {
    let runs: Vec<Run> = (0..RUNS as u64).map(prove).collect::<Result<_, _>>()?;
    let base = &runs[0];
    let arity = stacked_arity();
    let config = whir_config(arity);
    let replay = replay_verifier(base)?;
    // The faithfulness check that makes every exported value golden: the transcript
    // this replay walks must produce EXACTLY the event stream the native verifier
    // produced, sample for sample and byte for byte. If a single absorb or draw were
    // missing, reordered or extra, this fails - and every value below would otherwise
    // be a plausible-looking wrong number.
    assert!(
        replay.program == base.program,
        "the exported transcript replay disagrees with the native verifier's transcript"
    );
    let whir = &base.proof.rounds[0].whir;

    // Classify on the VERIFIER-side programs: the contract replays the verifier,
    // so "fixed" has to mean "fixed in the verifier's transcript".
    let programs: Vec<SemProgram> = runs.iter().map(|r| r.program.clone()).collect();
    let (fixed, varying) = classify_observations(&programs);
    check_no_ambiguous_zeros(&base.program, &fixed)?;
    let blobs = fixed_runs(&base.program, &fixed);

    log_program_summary(&base.program, &fixed, &blobs, &varying, arity, &config);

    // Negative controls: one mutation per field the contract reads.
    let negatives = negative_controls()?;
    log_negatives(&negatives);

    let doc = json!({
        "note": "One WHIR proof at a small shape, produced and accepted by the native WhirUniPcs. Every field is read off the native types; see the module docs of crates/prover/tests/whir_proof_vectors.rs.",
        "shape": shape_json(arity, &config),
        "schedule": schedule_json(&config),
        "proof_hex": hex(&postcard::to_allocvec(&base.proof)?),
        "commitment": hex(base.commitment.roots()[0].as_ref()),
        "round_commitments": base.proof.rounds[0]
            .whir
            .rounds
            .iter()
            .map(|r| hex(r.commitment.as_ref().expect("round commitment").roots()[0].as_ref()))
            .collect::<Vec<_>>(),
        "zetas": zetas().iter().map(ext_json).collect::<Vec<_>>(),
        "super_points": super_points().iter().map(point_json).collect::<Vec<_>>(),
        // opened[round][matrix][point][column], flattened to nested JSON arrays.
        "opened": opened_json(&base.opened),
        "bound_evals": base.proof.rounds[0].evals.iter()
            .map(|b| b.current().iter().map(ext_json).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "initial_ood_answers": whir.initial_ood_answers.iter().map(ext_json).collect::<Vec<_>>(),
        "claimed_eval": ext_json(&replay.claimed_eval),
        // The point the initial sumcheck reduces to: the first round folds here.
        "initial_randomness": replay.randomness.iter().map(ext_json).collect::<Vec<_>>(),
        // Explicit counts beside every array: forge's JSON selectors have no length
        // operator, so the Solidity side reads these instead of probing structure.
        "counts": {
            "num_round_commitments": base.proof.rounds[0].whir.rounds.len(),
            "num_query_sets": replay.query_indices.len(),
            "query_set_lens": replay.query_indices.iter().map(Vec::len).collect::<Vec<_>>(),
            "num_fixed_absorb": blobs.len(),
            "num_negatives": negatives.len(),
            "num_schedule_rounds": config.n_rounds(),
            "num_initial_eq_points": replay.eq_points.len(),
            "num_bound_eval_batches": base.proof.rounds[0].evals.len(),
        },
        "alpha": ext_json(&replay.alpha),
        "gamma": ext_json(&replay.gamma),
        "initial_constraint_num_variables": replay.num_variables,
        "initial_eq_points": replay.eq_points.iter()
            .map(|p| p.as_slice().iter().map(ext_json).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        // Everything the rest of the walk produced. The contract recomputes each of
        // these from the proof bytes and the fixed schedule; exporting them is what
        // lets the Solidity test compare step by step instead of only at the end.
        "ood_points": replay.ood_points.iter().map(ext_json).collect::<Vec<_>>(),
        "round_batching": replay.round_batching.iter().map(ext_json).collect::<Vec<_>>(),
        "query_indices": replay.query_indices.iter()
            .map(|v| v.iter().map(|&i| i as u64).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "round_randomness": replay.round_randomness.iter()
            .map(|v| v.iter().map(ext_json).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "final_randomness": replay.final_randomness.as_ref()
            .map(|v| v.iter().map(ext_json).collect::<Vec<_>>()),
        "fixed_absorb": blobs,
        "num_fixed_observations": fixed.iter().filter(|v| v.is_some()).count(),
        "num_varying_observations": varying.len(),
        "negatives": negatives,
        "accept": true,
    });

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    let json_path = dir.join("whir_proof_vectors.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&doc)?.into_bytes())?;
    let blob = replay_blob(&base.program, &fixed)?;
    let blob_path = dir.join("whir_proof_vectors.bin");
    std::fs::write(&blob_path, &blob)?;
    println!(
        "wrote {} and {} ({} bytes)",
        json_path.display(),
        blob_path.display(),
        blob.len()
    );
    Ok(())
}

/// Asserts the exported fixed blobs tile the blob's constant payload EXACTLY: every
/// byte the contract hard-codes appears in exactly one run, in order, and nothing
/// else does.
///
/// An earlier version of `fixed_runs` merged proof-varying commitment digests into
/// the runs, which this check catches: a digest byte is never part of the constant
/// payload, so any run containing one desynchronises the tiling. Without it the
/// contract would absorb a stale commitment out of a hard-coded blob - a soundness
/// bug that every downstream transcript value would then paper over.
fn check_fixed_runs_tile(
    blob: &[u8],
    const_start: usize,
    const_len: usize,
    doc: &serde_json::Value,
) {
    let mut at = const_start;
    let runs = doc["fixed_absorb"].as_array().expect("fixed_absorb runs");
    for run in runs {
        let hex_str = run.as_str().expect("fixed_absorb run is a hex string");
        assert!(hex_str.len() % 2 == 0, "odd-length hex run");
        let bytes = hex_str.len() / 2;
        assert!(
            at + bytes <= const_start + const_len,
            "fixed run overruns the payload"
        );
        for k in 0..bytes {
            let want = u8::from_str_radix(&hex_str[k * 2..k * 2 + 2], 16).expect("hex digit");
            assert_eq!(blob[at + k], want, "fixed run byte differs from the blob");
        }
        at += bytes;
    }
    assert_eq!(
        at - const_start,
        const_len,
        "the fixed runs do not cover the whole constant payload"
    );
}

/// Every negative control in the artifact must have been REJECTED by the native
/// verifier. A contract cannot be sounder than the reference it replays, so if a
/// tampered field slipped through here the field carries data nothing checks and the
/// port would inherit the hole.
fn check_negatives_rejected(doc: &serde_json::Value) {
    for n in doc["negatives"].as_array().into_iter().flatten() {
        assert_eq!(
            n["rejected"].as_bool(),
            Some(true),
            "the native verifier accepted a tampered proof: {:?}",
            n["label"].as_str().unwrap_or_default()
        );
    }
}

/// The operation an event stands for: its kind and its argument.
const fn op_of(e: &SemEvent) -> (&'static str, usize) {
    match e {
        SemEvent::ObserveBase { .. } => ("observe_base", 1),
        SemEvent::ObserveBytes { bytes } => ("observe_bytes", bytes.len()),
        SemEvent::SampleBase { values } => ("sample_base", values.len()),
        SemEvent::SampleBits { bits, .. } => ("sample_bits", *bits),
        SemEvent::Grind { bits, .. } => ("grind", *bits),
        SemEvent::CheckWitness { bits, .. } => ("check_witness", *bits),
        SemEvent::SampleUniformBits { bits, .. } => ("uniform_bits", *bits),
    }
}

/// The artifacts' shape, pinned so a stale file fails here rather than in a
/// confusing place in a Solidity test.
///
/// The generator is `#[ignore]`d because re-proving is nondeterministic, which
/// means nothing normally re-checks the files on disk. This does. It asserts the
/// SHAPE the Solidity side is written against - never the values, which move with
/// every mask draw.
#[test]
fn whir_proof_vectors_artifact_has_the_pinned_shape() -> Result<(), Box<dyn Error>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    let json_path = dir.join("whir_proof_vectors.json");
    if !json_path.exists() {
        println!("whir_proof_vectors.json not generated yet; skipping");
        return Ok(());
    }
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(
        doc["accept"].as_bool(),
        Some(true),
        "the recorded proof must be an accepting one"
    );
    assert_eq!(
        doc["shape"]["stacked_num_variables"].as_u64(),
        Some(11),
        "stacked arity"
    );
    assert_eq!(
        doc["shape"]["n_rounds"].as_u64(),
        Some(1),
        "WHIR round count"
    );
    assert_eq!(
        doc["shape"]["final_sumcheck_rounds"].as_u64(),
        Some(3),
        "the closing sumcheck must fold the variables the rounds left over"
    );
    // One intermediate round means one round commitment and one round of query
    // indices, plus the terminal query set: the loop body AND the tail are both
    // present in the artifact the Solidity test walks.
    assert_eq!(
        doc["round_commitments"].as_array().map_or(0, Vec::len),
        1,
        "one intermediate round must carry one commitment"
    );
    assert_eq!(
        doc["query_indices"].as_array().map_or(0, Vec::len),
        2,
        "one round of queries plus the terminal query set"
    );
    assert_eq!(
        doc["shape"]["num_zetas"].as_u64(),
        Some(2),
        "opening points"
    );
    assert_eq!(
        doc["negatives"].as_array().map_or(0, Vec::len),
        5,
        "every negative control must be present"
    );
    check_negatives_rejected(&doc);
    // The blob is what the contract actually walks, so pin its header the same way
    // the semantic-program test pins its own: a stale blob would lead the Solidity
    // side through a schedule that no longer matches the recorded program.
    let blob_path = dir.join("whir_proof_vectors.bin");
    let blob =
        std::fs::read(&blob_path).map_err(|e| format!("missing {}: {e}", blob_path.display()))?;
    assert!(blob.len() > 28, "blob is shorter than its header");
    assert_eq!(&blob[..4], b"WSPR", "blob magic");
    assert_eq!(u16::from_be_bytes([blob[4], blob[5]]), 1, "blob version");
    let schedule_len = usize::from(u16::from_be_bytes([blob[6], blob[7]]));
    let be32 = |k: usize| {
        usize::try_from(u32::from_be_bytes([
            blob[8 + k * 4],
            blob[9 + k * 4],
            blob[10 + k * 4],
            blob[11 + k * 4],
        ]))
        .expect("a payload length fits a usize")
    };
    let lens = [be32(0), be32(1), be32(2), be32(3), be32(4)];
    assert_eq!(
        blob.len(),
        28 + schedule_len * 4 + lens.iter().sum::<usize>(),
        "blob payload lengths do not cover the file"
    );
    // With grinding off there are no witness checks, so the witness pool is empty
    // and every observation is either a config constant or proof data.
    assert_eq!(
        lens[4], 0,
        "grinding is off, so no proof-of-work witness may appear"
    );
    let num_fixed = usize::try_from(doc["num_fixed_observations"].as_u64().unwrap_or(0))
        .expect("a count of observations fits a usize");
    assert_eq!(
        lens[0],
        num_fixed * 4,
        "the blob constant table disagrees with the fixed-value classification"
    );
    check_fixed_runs_tile(&blob, 28 + schedule_len * 4, lens[0], &doc);
    println!(
        "proof vectors pinned: {schedule_len} schedule entries, {lens:?} payloads, {num_fixed} fixed observations"
    );
    Ok(())
}
