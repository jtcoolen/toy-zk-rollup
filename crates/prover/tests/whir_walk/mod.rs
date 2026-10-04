//! The WHIR verifier-transcript walk, shared by every test that drives a WHIR
//! opening argument: the small-shape proof vectors, and the composed settlement-shape
//! vectors where the SAME walk replaces the native PCS inside the batch delegate.
//!
//! The rule this module exists to enforce: the walk is the specification the Solidity
//! core is written from, and it is exercised by the pinned small-shape test. When the
//! settlement-shape test drives this exact code inside the batch transcript and the
//! recorded program still equals the native verifier's, the composition is proven -
//! not a re-derivation of the protocol, but the same code at a different shape.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Dimensions;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::constraints::statement::eq::EqStatement;
use p3_sumcheck::constraints::statement::select::SelectStatement;
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::layout::{Layout as _, PrefixProver, Verifier};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::OpeningProtocol;
use p3_whir::domain::{WhirDomain, WhirQueryPoint};
use p3_whir::parameters::WhirConfig;
use p3_whir::pcs::proof::{QueryOpenings, WhirProof};
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};
use prover::config::mmcs;
use prover::semantic_trace::SemChallenger;
use prover::whir::{Challenge, Dft};
use prover::F;
use std::error::Error;

/// The verifier-side WHIR transcript over the traced challenger.
pub type SemVerifierTranscript<'a> = WhirVerifierTranscript<'a, SemChallenger, F, Challenge>;

/// Hex for the Solidity side, which reads `hex"..."` literals.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(&mut s, "{b:02x}");
            s
        })
}

/// The batching challenge `gamma` that weights the constraint's statements.
///
/// `challenge_powers(shift)` yields `gamma^shift, gamma^(shift+1), ...`, so the
/// first element at `shift = 1` is `gamma` itself.
pub fn challenge_of(constraint: &Constraint<F, Challenge>) -> Challenge {
    constraint
        .challenge_powers(1)
        .next()
        .expect("challenge_powers is an infinite sequence")
}

/// The output of the intermediate-round phase of a transcript walk.
pub(crate) struct RoundWalk {
    /// The combined claim after each round's `combine_evals`, i.e. the sum that
    /// round's sumcheck must open with. Pins the round constraint's batching:
    /// ood answers at gamma^1.., then the folded query evaluations.
    pub(crate) claimed_evals: Vec<Challenge>,
    pub(crate) folded_claims: Vec<Challenge>,
    /// Each round's folded query evaluations, in query order: the opened row
    /// folded at the previous round's randomness. The contract computes these
    /// from the Merkle openings; pinning them here separates a fold bug from a
    /// batching bug.
    pub(crate) folds: Vec<Vec<Challenge>>,
    /// Out-of-domain points, in the order drawn.
    pub(crate) ood_points: Vec<Challenge>,
    /// Per-round query domain points (univariate base scalars), in query
    /// order: the STIR selection points this round's constraint batches.
    pub(crate) domain_points: Vec<Vec<u32>>,
    /// Per-round batching challenges for the STIR selection statements.
    pub(crate) round_batching: Vec<Challenge>,
    /// Query indices per WHIR round.
    pub(crate) query_indices: Vec<Vec<usize>>,
    /// The point each round's sumcheck reduces to.
    pub(crate) round_randomness: Vec<Vec<Challenge>>,
    /// Per-round OOD answers, in draw order (proof data, not transcript state).
    pub(crate) ood_answers: Vec<Vec<Challenge>>,
    /// Per-round `PoW` witnesses (base field).
    pub(crate) pow_witnesses: Vec<F>,
    /// Per-round sumcheck {0,1}-pair evaluations, split like the initial one.
    pub(crate) sumcheck_ca: Vec<Vec<Challenge>>,
    pub(crate) sumcheck_cinf: Vec<Vec<Challenge>>,
    /// Per-round sumcheck proof-of-work witnesses (canonical base u32s; empty
    /// at zero difficulty). The contract's SumcheckCore checks each grind.
    pub(crate) sumcheck_pow_witnesses: Vec<Vec<u32>>,
    /// Per-round opened rows, flattened base-field limbs for round 0 and packed
    /// extension elements for later rounds. The contract authenticates these
    /// against the previous commitment and folds them; exporting them lets the
    /// test check the fold separately from the Merkle path.
    pub(crate) rows_base: Vec<Vec<u32>>,
    pub(crate) rows_ext: Vec<Vec<Challenge>>,
    /// Per-round round parameters the contract needs: `num_variables`,
    /// `log_folded_domain_size`, `ood_samples`, `folding_pow_bits`.
    pub(crate) params: Vec<[u32; 4]>,
    /// Each round's Merkle commitment root: the contract binds it and later
    /// rounds open against the previous one.
    pub(crate) commitments: Vec<[u8; 32]>,
    /// Per-round, per-query Merkle paths (leaf-to-root sibling digests, hex),
    /// rebuilt from each round's pruned multiproof with the verifier's own
    /// restore walk. Round 0 opens base rows, later rounds extension rows.
    pub(crate) paths: Vec<Vec<Vec<String>>>,
}

/// Walk the intermediate WHIR rounds of the verifier transcript.
///
/// One round is: bind the round commitment, draw and answer the out-of-domain
/// points, check the query proof-of-work, draw the query indices, draw the round
/// batching challenge, then fold with the round sumcheck. The contract performs the
/// identical sequence per round, so this is the shape its loop must match.
#[allow(clippy::too_many_lines)]
pub(crate) fn replay_rounds(
    vt: &mut SemVerifierTranscript<'_>,
    whir: &WhirProof<F, Challenge, prover::config::Mmcs>,
    config: &WhirConfig<Challenge, F, SemChallenger>,
    dft: &Dft,
    initial_claimed: Challenge,
    initial_randomness: &Point<Challenge>,
    cap_height: usize,
) -> Result<RoundWalk, Box<dyn Error>> {
    let mut walk = RoundWalk {
        folded_claims: Vec::new(),
        claimed_evals: Vec::new(),
        folds: Vec::new(),
        ood_points: Vec::new(),
        domain_points: Vec::new(),
        round_batching: Vec::new(),
        query_indices: Vec::new(),
        round_randomness: Vec::new(),
        ood_answers: Vec::new(),
        pow_witnesses: Vec::new(),
        sumcheck_ca: Vec::new(),
        sumcheck_cinf: Vec::new(),
        sumcheck_pow_witnesses: Vec::new(),
        rows_base: Vec::new(),
        rows_ext: Vec::new(),
        params: Vec::new(),
        commitments: Vec::new(),
        paths: Vec::new(),
    };
    // The claim the round sumchecks fold, threaded from the initial phase
    // exactly as the native verifier threads it: each round's constraint adds
    // its batched expectations onto the carried claim before folding it.
    let mut claimed_eval = initial_claimed;
    // Round 0 folds each opened row at the INITIAL sumcheck's reduction point:
    // the WHIR fold chain starts before any intermediate round exists.
    let mut prev_randomness: Option<Point<Challenge>> = Some(initial_randomness.clone());
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
        // The round's equality group: OOD points drawn from the transcript,
        // answers from the proof - the same pairs `ParsedCommitment::parse_with_round`
        // builds inside the native verifier.
        let mut ood_statement = EqStatement::initialize(rp.num_variables);
        for &answer in &rproof.ood_answers {
            // The transcript draws a univariate scalar; the constraint expands it
            // to `rp.num_variables` coordinates, exactly as parse_with_round does.
            let zeta = vt.ood_point();
            walk.ood_points.push(zeta);
            vt.ood_answer(answer);
            let point = Point::expand_from_univariate(zeta, rp.num_variables);
            ood_statement.add_evaluated_constraint(point, answer);
        }
        walk.ood_answers.push(rproof.ood_answers.clone());
        walk.pow_witnesses.push(rproof.pow_witness);
        walk.params.push([
            // Protocol parameters, each far below u32::MAX by construction
            // (arities <= 32, bit counts <= 32); the export is u32 because the
            // contract reads u32 words.
            u32::try_from(rp.num_variables).expect("num_variables fits u32"),
            u32::try_from(rp.log_folded_domain_size).expect("log_folded_domain_size fits u32"),
            u32::try_from(rp.ood_samples).expect("ood_samples fits u32"),
            u32::try_from(rp.folding_pow_bits).expect("folding_pow_bits fits u32"),
        ]);
        walk.commitments.push(
            <[u8; 32]>::try_from(
                rproof
                    .commitment
                    .as_ref()
                    .expect("every intermediate round commits")
                    .roots()[0]
                    .as_ref(),
            )
            .expect("32-byte root"),
        );
        vt.query_pow(round_index, rproof.pow_witness)
            .map_err(|e| format!("round {round_index} query pow: {e:?}"))?;
        let indices = vt.query_indices(round_index);
        walk.query_indices.push(indices.clone());

        // The selection group: each opened row folded at the PREVIOUS round's
        // randomness (Prefix order, so the point is used as-is), then placed at
        // the query's domain point. This is `verify_stir_challenges`'s fold, and
        // the contract computes the identical fold from its Merkle openings -
        // pinning the folds separately separates a fold bug from a batching bug.
        let randomness = prev_randomness
            .clone()
            .ok_or_else(|| "no prev randomness".to_string())?;
        let (rows, base_limbs): (Vec<Vec<Challenge>>, Vec<Vec<u32>>) = match &rproof.openings {
            QueryOpenings::Base(o) => (
                o.rows
                    .iter()
                    .map(|r| r.iter().map(|&x| x.into()).collect())
                    .collect(),
                o.rows
                    .iter()
                    .map(|r| r.iter().map(F::as_canonical_u32).collect())
                    .collect(),
            ),
            QueryOpenings::Extension(o) => (o.rows.clone(), Vec::new()),
        };
        if base_limbs.is_empty() {
            walk.rows_ext.extend(rows.clone());
        } else {
            walk.rows_base.extend(base_limbs);
        }
        // Per-round query paths, rebuilt from the pruned multiproof with the
        // verifier's own restore walk: round 0 opens base rows (width 1 <<
        // folding), later rounds extension rows (the ext tree is the base tree
        // with four times the row width). The contract verifies one
        // self-sufficient path per query, so the artifact carries the expanded form.
        {
            let (dims, row_limbs): (Vec<Dimensions>, Vec<Vec<Vec<F>>>) = match &rproof.openings {
                QueryOpenings::Base(o) => (
                    vec![Dimensions {
                        height: rp.domain_size >> rp.folding_factor,
                        width: 1 << rp.folding_factor,
                    }],
                    o.rows.iter().map(|row| vec![row.clone()]).collect(),
                ),
                QueryOpenings::Extension(o) => (
                    vec![Dimensions {
                        height: rp.domain_size >> rp.folding_factor,
                        width: (1 << rp.folding_factor) * 4,
                    }],
                    o.rows
                        .iter()
                        .map(|row| {
                            vec![row
                                .iter()
                                .flat_map(|x| x.as_basis_coefficients_slice().to_vec())
                                .collect::<Vec<_>>()]
                        })
                        .collect(),
                ),
            };
            let proof = match &rproof.openings {
                QueryOpenings::Base(o) => &o.proof,
                QueryOpenings::Extension(o) => &o.proof,
            };
            let paths = prover::config::mmcs(cap_height)
                .restore_and_recompute_paths(&dims, &indices, &row_limbs, proof)
                .map_err(|e| format!("round {round_index} restore paths: {e:?}"))?;
            walk.paths.push(
                paths
                    .iter()
                    .map(|p| p.siblings.iter().map(|d| hex(d)).collect())
                    .collect(),
            );
        }
        if rows.len() != indices.len() {
            return Err(format!(
                "round {round_index}: {} rows for {} queries",
                rows.len(),
                indices.len()
            )
            .into());
        }
        let mut select_statement = SelectStatement::initialize(rp.num_variables);
        let mut round_folds = Vec::with_capacity(indices.len());
        let mut round_domain_points: Vec<u32> = Vec::with_capacity(indices.len());
        for (&index, row) in indices.iter().zip(&rows) {
            let fold = Poly::new(row.clone()).eval_ext::<F>(&randomness);
            round_folds.push(fold);
            match <Dft as WhirDomain<F, Challenge>>::query_point(
                dft,
                rp.log_folded_domain_size,
                rp.num_variables,
                index,
            ) {
                WhirQueryPoint::Univariate(var) => {
                    select_statement.add_constraint(var, fold);
                    round_domain_points.push(F::as_canonical_u32(&var));
                }
                WhirQueryPoint::Multilinear(point) => {
                    select_statement.add_point_constraint(point, fold);
                }
            }
        }
        walk.folds.push(round_folds);
        walk.domain_points.push(round_domain_points);

        let gamma = vt.round_batching();
        walk.round_batching.push(gamma);
        // The native verifier batches with `Constraint::new_with_existing_claim`:
        // the carried claim keeps gamma^0, the OOD group takes gamma^1.., the
        // selection group follows.
        let constraint = Constraint::new_with_existing_claim(
            gamma,
            rp.num_variables,
            vec![
                Statements::Eq(ood_statement),
                Statements::Select(select_statement),
            ],
        );
        constraint.combine_evals(&mut claimed_eval);
        walk.claimed_evals.push(claimed_eval);

        walk.sumcheck_ca.push(
            rproof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .map(|pair| pair[0])
                .collect(),
        );
        walk.sumcheck_cinf.push(
            rproof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .map(|pair| pair[1])
                .collect(),
        );
        walk.sumcheck_pow_witnesses.push(
            rproof
                .sumcheck
                .pow_witnesses
                .iter()
                .map(F::as_canonical_u32)
                .collect(),
        );
        let r = vt
            .delegate_round_fold(|challenger| {
                rproof.sumcheck.verify_rounds(
                    challenger,
                    &mut claimed_eval,
                    config.round_folding_factor(round_index + 1),
                    rp.folding_pow_bits,
                    Basis::Evaluation,
                )
            })
            .map_err(|e| format!("round {round_index} sumcheck: {e:?}"))?;
        walk.round_randomness.push(r.as_slice().to_vec());
        walk.folded_claims.push(claimed_eval);
        prev_randomness = Some(r);
    }
    Ok(walk)
}

/// The output of the terminal phase.
pub(crate) struct TerminalWalk {
    /// Terminal query indices.
    pub(crate) query_indices: Vec<usize>,
    /// The point the closing sumcheck reduces to, when there is one.
    pub(crate) final_randomness: Option<Vec<Challenge>>,
    /// The final polynomial, sent in the clear: `2^num_variables` coefficients.
    pub(crate) final_poly: Vec<Challenge>,
    /// The terminal proof-of-work witness as a canonical base u32.
    pub(crate) final_pow_witness: u32,
    /// Terminal opened rows as canonical limbs (four per extension element).
    pub(crate) final_rows_ext: Vec<Vec<Challenge>>,
    /// Per-query Merkle paths for the terminal openings (against the last
    /// round's root), rebuilt with the same walk the verifier runs.
    pub(crate) final_paths: Vec<Vec<String>>,
    /// Each terminal query's folded row at the last round's randomness.
    pub(crate) final_folds: Vec<Challenge>,
    /// The terminal queries' domain points (univariate base scalars).
    pub(crate) final_domain_points: Vec<u32>,
    /// Closing sumcheck round values: h(0) and h(infinity) per round.
    pub(crate) final_sumcheck_ca: Vec<Challenge>,
    pub(crate) final_sumcheck_cinf: Vec<Challenge>,
    /// Closing sumcheck `PoW` witnesses (canonical base u32s; empty at zero
    /// difficulty, one per round otherwise).
    pub(crate) final_sumcheck_pow_witnesses: Vec<u32>,
    /// The claim entering and leaving the closing sumcheck.
    pub(crate) claimed_before_final: Challenge,
    pub(crate) claimed_after_final: Challenge,
}

/// Walk the terminal phase: bind the final polynomial, check the terminal query
/// proof-of-work, draw the terminal query indices, then run the closing sumcheck.
pub(crate) fn replay_terminal(
    vt: &mut SemVerifierTranscript<'_>,
    whir: &WhirProof<F, Challenge, prover::config::Mmcs>,
    config: &WhirConfig<Challenge, F, SemChallenger>,
    dft: &Dft,
    claimed_eval: Challenge,
    last_randomness: &Point<Challenge>,
    last_root: &[u8; 32],
    cap_height: usize,
) -> Result<TerminalWalk, Box<dyn Error>> {
    let n_rounds = whir.rounds.len();
    let final_poly = whir.final_poly.as_ref().ok_or("missing final polynomial")?;
    vt.final_poly(final_poly.as_slice())
        .map_err(|e| format!("final poly: {e:?}"))?;
    vt.query_pow(n_rounds, whir.final_pow_witness)
        .map_err(|e| format!("terminal query pow: {e:?}"))?;
    let query_indices = vt.query_indices(n_rounds);

    // The terminal openings: extension rows against the LAST round's root,
    // folded at the last round's randomness - the same shape as an intermediate
    // round, except the fold is then checked against the public polynomial
    // rather than batched into the claim.
    let fr = config.final_round_config();
    let opening = match &whir.final_openings {
        QueryOpenings::Extension(o) => o,
        QueryOpenings::Base(_) => return Err("terminal openings must be extension".into()),
    };
    // The extension tree IS the base tree with four times the row width: an
    // extension leaf hashes as its four basis limbs in order, so path
    // reconstruction runs on the base mmcs with width 4 * (1 << folding) and
    // rows flattened to base limbs.
    let dims = [Dimensions {
        height: fr.domain_size >> fr.folding_factor,
        width: (1 << fr.folding_factor) * 4,
    }];
    let paths = mmcs(cap_height)
        .restore_and_recompute_paths(
            &dims,
            &query_indices,
            &opening
                .rows
                .iter()
                .map(|row| {
                    vec![row
                        .iter()
                        .flat_map(|x| x.as_basis_coefficients_slice().to_vec())
                        .collect::<Vec<_>>()]
                })
                .collect::<Vec<_>>(),
            &opening.proof,
        )
        .map_err(|e| format!("restore terminal paths: {e:?}"))?;
    let final_paths: Vec<Vec<String>> = paths
        .iter()
        .map(|p| p.siblings.iter().map(|d| hex(d)).collect())
        .collect();
    let final_folds: Vec<Challenge> = opening
        .rows
        .iter()
        .map(|row| Poly::new(row.clone()).eval_ext::<F>(last_randomness))
        .collect();
    let mut final_domain_points: Vec<u32> = Vec::with_capacity(query_indices.len());
    for &i in &query_indices {
        match <Dft as WhirDomain<F, Challenge>>::query_point(
            dft,
            fr.log_folded_domain_size,
            fr.num_variables,
            i,
        ) {
            WhirQueryPoint::Univariate(var) => final_domain_points.push(F::as_canonical_u32(&var)),
            WhirQueryPoint::Multilinear(_) => {
                return Err("two-adic domain yields univariate query points".into());
            }
        }
    }
    let _ = last_root;

    let claimed_before_final = claimed_eval;
    let mut claimed = claimed_eval;
    let final_randomness = vt
        .delegate_final_fold(|challenger| {
            p3_sumcheck::verify_final_sumcheck_rounds(
                whir.final_sumcheck.as_ref(),
                challenger,
                &mut claimed,
                config.final_sumcheck_rounds(),
                config.final_folding_pow_bits(),
                Basis::Evaluation,
            )
        })
        .transpose()
        .map_err(|e| format!("final sumcheck: {e:?}"))?
        .map(|p| p.as_slice().to_vec());
    let claimed_after_final = claimed;

    let (final_sumcheck_ca, final_sumcheck_cinf, final_sumcheck_pow_witnesses) =
        whir.final_sumcheck.as_ref().map_or_else(
            || (Vec::new(), Vec::new(), Vec::new()),
            |sc| {
                (
                    sc.polynomial_evaluations.iter().map(|p| p[0]).collect(),
                    sc.polynomial_evaluations.iter().map(|p| p[1]).collect(),
                    sc.pow_witnesses.iter().map(F::as_canonical_u32).collect(),
                )
            },
        );
    Ok(TerminalWalk {
        query_indices,
        final_randomness,
        final_poly: final_poly.as_slice().to_vec(),
        final_pow_witness: F::as_canonical_u32(&whir.final_pow_witness),
        final_rows_ext: opening.rows.clone(),
        final_paths,
        final_folds,
        final_domain_points,
        final_sumcheck_ca,
        final_sumcheck_cinf,
        final_sumcheck_pow_witnesses,
        claimed_before_final,
        claimed_after_final,
    })
}

/// The claimed evaluations and WHIR argument of one opening-argument proof.
///
/// `PcsProof` bundles both; the driver takes the bundle so the eval list can never
/// be zipped against a different proof than the transcript walk consumes.
pub(crate) type PcsProof = p3_whir::pcs::proof::PcsProof<F, Challenge, prover::config::Mmcs>;

/// Everything one full WHIR run (initial fold, intermediate rounds, terminal phase)
/// produces, as the walk sees it.
pub(crate) struct WhirRoundWalk {
    /// Layout batching challenge `alpha`.
    pub(crate) alpha: Challenge,
    /// Batching challenge `gamma` of the initial constraint.
    pub(crate) gamma: Challenge,
    /// The combined claim before the initial sumcheck folds it.
    pub(crate) initial_claimed_eval: Challenge,
    /// The claim after the initial sumcheck folds it - what round 0 carries.
    pub(crate) claimed_eval: Challenge,
    /// The point the initial sumcheck reduces to.
    pub(crate) randomness: Vec<Challenge>,
    /// Equality points of the initial constraint, in batching-power order.
    pub(crate) eq_points: Vec<Point<Challenge>>,
    /// The claimed evaluation paired with each equality point.
    pub(crate) eq_evals: Vec<Challenge>,
    /// Number of constraints in each equality statement group.
    pub(crate) eq_group_lens: Vec<usize>,
    /// Arity the initial constraint lives in.
    pub(crate) num_variables: usize,
    /// Program offsets (into the shared sink) of the phase boundaries of this
    /// round's walk: [claims_start, claim_end_0, ..., claim_end_n,
    /// initial_fold_end, terminal_start, terminal_end]. Trusted-setup
    /// schedule data: the contract's walk plan is derived from these, not
    /// re-derived from shapes (the per-claim framing constant count varies
    /// with claim width and stacked arity).
    pub(crate) phase_offsets: Vec<usize>,
    /// The virtual out-of-domain answers the initial phase binds, in order.
    pub(crate) initial_ood_answers: Vec<Challenge>,
    /// The initial sumcheck's {0,1}-pair evaluations, split like the rounds'.
    pub(crate) initial_sumcheck_ca: Vec<Challenge>,
    pub(crate) initial_sumcheck_cinf: Vec<Challenge>,
    /// Initial sumcheck proof-of-work witnesses (canonical base u32s; empty at
    /// zero difficulty).
    pub(crate) initial_sumcheck_pow_witnesses: Vec<u32>,
    /// The root the terminal queries open against: the last round's commitment,
    /// or the batch commitment when there were no rounds.
    pub(crate) last_root: [u8; 32],
    /// The claimed evaluations the schedule opens, one batch per opening, matrix-major
    /// order matching `points`. These are the UNSCALED bounds the contract's initial
    /// phase absorbs; the rescale check multiplies them by the eq-scales.
    pub(crate) bound_evals: Vec<Vec<Challenge>>,
    /// Number of evaluations per opening batch.
    pub(crate) claim_widths: Vec<usize>,
    /// The intermediate-round walk.
    pub(crate) rounds: RoundWalk,
    /// Per-query Merkle paths for the round-0 openings, expanded one path per query.
    pub(crate) round0_paths: Vec<Vec<String>>,
    /// The terminal-phase walk.
    pub(crate) terminal: TerminalWalk,
    /// Per-round query indices, terminal set last.
    pub(crate) query_indices: Vec<Vec<usize>>,
}

/// Drive one complete WHIR opening-argument verification through the traced
/// transcript: layout claims, the initial fold, the intermediate rounds, the
/// terminal phase, and `finish()`.
///
/// This is the call sequence `WhirVerifier::replay` performs, bracketed exactly as
/// `WhirUniPcs::verify_rounds` brackets it - the same sequence the small-shape
/// pinned test drives. The caller owns the challenger: in the small-shape test the
/// commitment is observed before this call; inside the batch delegate the batch
/// transcript already bound every commitment, so nothing is observed here.
///
/// # Errors
///
/// Any transcript, sumcheck or shape error the native walk surfaces, with the phase.
#[allow(clippy::too_many_lines)] // one linear replay of WhirVerifier::replay; splitting scatters the spec
pub(crate) fn verify_whir_round(
    ch: &mut SemChallenger,
    pcs_proof: &PcsProof,
    config: &WhirConfig<Challenge, F, SemChallenger>,
    protocol: &OpeningProtocol,
    points: &[Point<Challenge>],
    dft: &Dft,
    cap_height: usize,
    initial_root: &[u8; 32],
) -> Result<WhirRoundWalk, Box<dyn Error>> {
    let whir = &pcs_proof.whir;
    assert_eq!(
        protocol.num_openings(),
        pcs_proof.evals.len(),
        "the schedule must name one batch per claimed-eval group"
    );

    let mut layout = Verifier::<F, Challenge>::new(
        &protocol.table_shapes(),
        PrefixProver::<F, Challenge>::strategy(),
    );
    let sink = ch.sink();
    let mut phase_offsets: Vec<usize> = Vec::new();
    for &eval in &whir.initial_ood_answers {
        layout.add_virtual_eval(eval, ch);
    }
    phase_offsets.push(sink.len());
    for (((table_idx, batch), evals), point) in
        protocol.iter_openings().zip(&pcs_proof.evals).zip(points)
    {
        layout
            .add_claim_at(table_idx, batch, point, evals, ch)
            .map_err(|e| format!("add_claim_at: {e:?}"))?;
        phase_offsets.push(sink.len());
    }

    let shape = WhirShape::new(config, protocol.num_openings());
    let mut vt = SemVerifierTranscript::new(ch, shape);
    let mut initial_claimed: Option<Challenge> = None;
    let (constraint, alpha, claimed_eval, randomness) = vt.delegate_initial_fold(|challenger| {
        let alpha = layout.batching_challenge(challenger);
        let constraint = layout.constraint(alpha);
        let mut claimed = Challenge::ZERO;
        constraint.combine_evals(&mut claimed);
        initial_claimed = Some(claimed);
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
    phase_offsets.push(sink.len());
    assert_eq!(
        initial_randomness.num_variables(),
        config.round_folding_factor(0),
        "the initial sumcheck must fold exactly the first round's arity"
    );

    let initial_sumcheck_ca: Vec<Challenge> = whir
        .initial_sumcheck
        .polynomial_evaluations
        .iter()
        .map(|p| p[0])
        .collect();
    let initial_sumcheck_cinf: Vec<Challenge> = whir
        .initial_sumcheck
        .polynomial_evaluations
        .iter()
        .map(|p| p[1])
        .collect();
    let initial_sumcheck_pow_witnesses: Vec<u32> = whir
        .initial_sumcheck
        .pow_witnesses
        .iter()
        .map(F::as_canonical_u32)
        .collect();

    let rounds = replay_rounds(
        &mut vt,
        whir,
        config,
        dft,
        // Native carries the FOLDED claim into the round loop: verify_rounds
        // mutates claimed_eval in place, and the round constraint folds onto the
        // folded value, not the pre-fold sum. Passing the pre-fold claim here
        // silently shifts every round checkpoint by (folded - prefold); the
        // round sumcheck cannot catch it because verify_rounds folds the claim
        // forward without validating the sum - only the terminal identity does.
        claimed_eval,
        &initial_randomness,
        cap_height,
    )?;

    // Per-query Merkle authentication paths for the round-0 openings, rebuilt
    // from the pruned multiproof with the SAME walk the native verifier runs.
    // The contract verifies one self-sufficient path per query, so the artifact
    // carries the expanded form.
    let round0_paths: Vec<Vec<String>> = {
        let rp0 = &config.round_parameters()[0];
        let opening = match &whir.rounds[0].openings {
            QueryOpenings::Base(o) => o,
            QueryOpenings::Extension(_) => return Err("round 0 openings must be base field".into()),
        };
        let dims = [Dimensions {
            height: rp0.domain_size >> rp0.folding_factor,
            width: 1 << rp0.folding_factor,
        }];
        let paths = mmcs(cap_height)
            .restore_and_recompute_paths(
                &dims,
                &rounds.query_indices[0],
                &opening
                    .rows
                    .iter()
                    .map(|row| vec![row.clone()])
                    .collect::<Vec<_>>(),
                &opening.proof,
            )
            .map_err(|e| format!("restore round-0 paths: {e:?}"))?;
        paths
            .iter()
            .map(|p| p.siblings.iter().map(|d| hex(d)).collect())
            .collect()
    };

    // The terminal phase folds at the LAST round's randomness and opens against
    // the LAST round's root; with no intermediate rounds those are the initial
    // sumcheck's point and the batch commitment (`initial_root`).
    let last_randomness_vec = rounds
        .round_randomness
        .last()
        .cloned()
        .unwrap_or_else(|| initial_randomness.as_slice().to_vec());
    let last_randomness = Point::new(last_randomness_vec);
    let last_root: [u8; 32] = if whir.rounds.is_empty() {
        *initial_root
    } else {
        <[u8; 32]>::try_from(
            whir.rounds
                .last()
                .and_then(|r| r.commitment.as_ref())
                .expect("round commitment")
                .roots()[0]
                .as_ref(),
        )
        .expect("32-byte root")
    };
    let claimed_after_rounds = rounds.folded_claims.last().copied().unwrap_or(claimed_eval);
    phase_offsets.push(sink.len());
    let terminal = replay_terminal(
        &mut vt,
        whir,
        config,
        dft,
        claimed_after_rounds,
        &last_randomness,
        &last_root,
        cap_height,
    )?;
    vt.finish();
    phase_offsets.push(sink.len());

    // The initial constraint holds only equality statements - the selection group
    // is added per WHIR round - which is what makes the flattened point list line
    // up with the gamma powers. A Next or Select group would consume powers this
    // flattening cannot see, so it is an error rather than a silent misalignment.
    let mut eq_points: Vec<Point<Challenge>> = Vec::new();
    let mut eq_evals: Vec<Challenge> = Vec::new();
    let mut eq_group_lens: Vec<usize> = Vec::new();
    for statement in constraint.statements() {
        let Statements::Eq(eq) = statement else {
            return Err("the initial constraint must hold only equality statements".into());
        };
        let eq: &EqStatement<Challenge> = eq;
        eq_group_lens.push(eq.len());
        eq_points.extend(eq.iter().map(|(p, _)| p.clone()));
        eq_evals.extend(eq.iter().map(|(_, e)| *e));
    }

    let mut query_indices = rounds.query_indices.clone();
    query_indices.push(terminal.query_indices.clone());
    Ok(WhirRoundWalk {
        alpha,
        gamma: challenge_of(&constraint),
        initial_claimed_eval: initial_claimed.expect("the closure sets the pre-fold claim"),
        claimed_eval,
        randomness: initial_randomness.as_slice().to_vec(),
        eq_points,
        eq_evals,
        eq_group_lens,
        num_variables: constraint.num_variables(),
        phase_offsets,
        initial_ood_answers: whir.initial_ood_answers.clone(),
        initial_sumcheck_ca,
        initial_sumcheck_cinf,
        initial_sumcheck_pow_witnesses,
        last_root,
        bound_evals: pcs_proof
            .evals
            .iter()
            .map(|b| b.current().to_vec())
            .collect(),
        claim_widths: pcs_proof.evals.iter().map(|b| b.current().len()).collect(),
        rounds,
        round0_paths,
        terminal,
        query_indices,
    })
}
