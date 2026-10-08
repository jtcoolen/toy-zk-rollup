//! The rollup node binary: HTTP API, sequencer actor, block driver, L1
//! settlement sender.
//!
//! # Shape
//!
//! One actor task owns the [`node::sequencer::Sequencer`] outright - no lock
//! around proving, so a block proof cannot stall a state read and there is no
//! lock ordering to get wrong. HTTP handlers hold a command channel and a
//! cheap read-only [`Snapshot`]; the actor refreshes the snapshot after every
//! state change, so `/health` and `/v1/state` never queue behind a proof.
//!
//! ```text
//!   HTTP (axum)                    actor task                  L1
//!   -----------                    ----------                  --
//!   POST /v1/demo/transfer -cmd->  prove + submit
//!   POST /v1/block/produce ----->  produce_block + bundle --> eth_sendTransaction
//!   GET  /v1/state  <-snapshot--   (refreshed after each step)
//! ```
//!
//! # Security posture (D-082)
//!
//! * Every route is behind the [`node::Acl`]; a path not in the policy is a
//!   404, never a default-open pass. `/health` and `/metrics` require a
//!   `ReadOnly` token - they leak height and timing.
//! * The token signing key comes from `NODE_TOKEN_KEY_FILE` (0600 enforced on
//!   read) or `NODE_TOKEN_KEY` (hex), held in `Zeroizing` and wiped as soon
//!   as the signer is built.
//! * Bodies are capped at 1 MiB; requests are rate-limited per role and
//!   endpoint so a submit flood cannot starve reads.
//! * The node holds **no L1 keys**: settlement is `eth_sendTransaction` from
//!   a configured unlocked sender (D-080). A failed settlement keeps its
//!   artifact and is never blind-resent.
//! * No secret material is logged: keys, tokens, and note randomness appear
//!   in no tracing span.
//!
//! # The demo proving seam (D-079)
//!
//! The inner `CircuitVerifier` is not wire-serializable, so the demo proves
//! transfers in-process against the fixture genesis notes. The node holds
//! those fixture spend keys - which is exactly why `/v1/demo/transfer` is
//! Admin-only: it is an operator script stand-in for the wallet, not a
//! public endpoint. `/v1/transfer` validates the wallet's SPHINCS+ envelope
//! end to end and then answers 501: admitting a *remote* proof needs the
//! production verifier-rebuild path, recorded as deferred in D-079.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use governor::{Quota, RateLimiter};
use nonzero_ext::nonzero;
use p3_field::PrimeField32;
use pq_hash::{Poseidon2Commitment, Poseidon2Shielded};
use prover::client::{prove_client_transfer, ClientSpec};
use prover::fixtures::{funded_note, seed};
use rand::rngs::SysRng;
use rand::TryRng;
use shielded::keys::derive_spend_pk;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use node::metrics::names;
use node::sequencer::{ClientTransferProof, Sequencer};
use node::settlement::{Manifest, SettlementSender};
use node::wire::{SpendKey, SubmitOk, TransferWire};
use node::{Acl, Role, TokenSigner};

/// Inner WHIR sizing: the same budget the prover's transfer tests use. The
/// block circuit's `BLOCK_LOG_MAX_LDE` is separate and larger.
const LOG_MAX_LDE: usize = prover::transfer::LOG_MAX_LDE;

/// One input, one output - every demo transfer's shape.
const ONE_IN_ONE_OUT: prover::block::TransferShape = prover::block::TransferShape {
    num_nullifiers: 1,
    num_outputs: 1,
};

/// Fixture genesis notes - the same seeds the sequencer integration tests
/// use, so the e2e script and the tests exercise identical notes.
const GENESIS: [(u8, u64); 2] = [(11, 1_000), (22, 2_000)];

/// Body cap for every request: a transfer wire DTO is a few KB (the SPHINCS+
/// signature dominates at ~8 KB); 1 MiB is orders of magnitude of headroom
/// while bounding allocator pressure from junk.
const MAX_BODY_BYTES: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Runtime configuration, read from the environment once at startup.
///
/// Nothing secret lives here: the token key is loaded separately into
/// `Zeroizing` and never stored in this struct (which derives `Debug`).
#[derive(Debug, Clone)]
struct Config {
    addr: String,
    cors_origins: Vec<String>,
    block_interval: Duration,
    settle: bool,
    rpc_url: String,
    manifest_path: String,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let interval_ms: u64 = env_or("NODE_BLOCK_INTERVAL_MS", "10000")
            .parse()
            .map_err(|e| format!("NODE_BLOCK_INTERVAL_MS: {e}"))?;
        Ok(Self {
            addr: env_or("NODE_ADDR", "127.0.0.1:3000"),
            cors_origins: env_or("NODE_CORS_ORIGINS", "")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            block_interval: Duration::from_millis(interval_ms),
            settle: env_or("NODE_SETTLE", "0") == "1",
            rpc_url: env_or("NODE_RPC_URL", "http://127.0.0.1:8545"),
            manifest_path: env_or("NODE_MANIFEST", "contracts/deployments/local.json"),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Load the token signing key, preferring the file (0600-enforced) over the
/// environment variable. The env path exists for container setups where a
/// secret arrives as an env var; both paths wipe the key on drop.
fn load_token_key() -> Result<Zeroizing<Vec<u8>>, String> {
    if let Ok(path) = std::env::var("NODE_TOKEN_KEY_FILE") {
        let bytes = node::keystore::read_private(std::path::Path::new(&path))
            .map_err(|e| format!("NODE_TOKEN_KEY_FILE: {e}"))?;
        if bytes.is_empty() {
            return Err("token key file is empty".into());
        }
        return Ok(bytes);
    }
    if let Ok(hex_key) = std::env::var("NODE_TOKEN_KEY") {
        let key = Zeroizing::new(
            hex::decode(hex_key.trim()).map_err(|e| format!("NODE_TOKEN_KEY: {e}"))?,
        );
        if key.len() < 16 {
            return Err("NODE_TOKEN_KEY must carry at least 16 bytes of entropy".into());
        }
        return Ok(key);
    }
    Err("no token key: set NODE_TOKEN_KEY_FILE (0600) or NODE_TOKEN_KEY (hex)".into())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Fresh 32 bytes from the OS CSPRNG, for output note randomness.
fn random_bytes() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| format!("CSPRNG: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Snapshot: the lock-free read side
// ---------------------------------------------------------------------------

/// A small, cheaply-clonable view of the node, refreshed by the actor after
/// every state change. Readers never touch the sequencer and never block
/// behind a proof.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    block_number: u64,
    note_count: usize,
    spent_count: usize,
    root_hex: String,
    nullifier_root_hex: String,
    pending: usize,
}

impl Snapshot {
    fn of(seq: &Sequencer) -> Self {
        let s = seq.state();
        Self {
            block_number: s.block_number(),
            note_count: s.note_count(),
            spent_count: s.spent_count(),
            root_hex: s.root().to_hex(),
            nullifier_root_hex: s.nullifier_root().to_hex(),
            pending: seq.pending(),
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "block_number": self.block_number,
            "note_count": self.note_count,
            "spent_count": self.spent_count,
            "root": self.root_hex,
            "nullifier_root": self.nullifier_root_hex,
            "pending": self.pending,
        })
    }
}

// ---------------------------------------------------------------------------
// The actor
// ---------------------------------------------------------------------------

/// Commands to the sequencer actor. Every command replies on its oneshot; a
/// dropped receiver just means the client hung up.
enum Cmd {
    DemoTransfer {
        input_index: usize,
        out_value: u64,
        fee: u64,
        reply: oneshot::Sender<Result<SubmitOk, String>>,
    },
    /// State pre-check for a proofless wallet envelope (D-090): double-spend
    /// and stale roots against the committed state - the same roots
    /// `/v1/roots` reports. The full admission (pending projections, child
    /// proof) still happens at proof time; this only answers what a signed
    /// envelope can already be judged on.
    CheckAdmit {
        public: shielded::TransferPublic,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Produce {
        reply: oneshot::Sender<Result<serde_json::Value, String>>,
    },
    Settle {
        reply: oneshot::Sender<Result<String, String>>,
    },
}

/// The demo client's view of one genesis note: the note, its opening key,
/// and the SPHINCS+ key that signs its statements. All fixture-derived and
/// therefore public knowledge - see D-079.
struct DemoNote {
    note: shielded::Note,
    sk_d: [u8; 32],
    index: usize,
    spend_key: SpendKey,
}

/// The sequencer actor: sole owner of the node's mutable state.
struct Actor {
    seq: Sequencer,
    demo: Vec<DemoNote>,
    /// Recipient demo outputs go to (fixture seed, like the tests).
    recipient: shielded::SpendPublicKey,
    sender: Option<SettlementSender>,
    /// The last produced block awaiting settlement, as (statement limbs, WBND
    /// bundle). D-080: a failed settlement keeps its artifact; a successful
    /// one clears it, so a double-settle cannot be issued blindly. The bundle
    /// is encoded at produce time so `settle` is only an RPC send.
    pending_settlement: Option<(Vec<u64>, Vec<u8>)>,
    snapshot: Arc<std::sync::RwLock<Snapshot>>,
}

impl Actor {
    fn new(config: &Config, snapshot: Arc<std::sync::RwLock<Snapshot>>) -> Result<Self, String> {
        let notes: Vec<(shielded::Note, [u8; 32])> =
            GENESIS.iter().map(|(b, v)| funded_note(*b, *v)).collect();
        let hashes: Vec<_> = notes
            .iter()
            .map(|(n, _)| n.commit(&Poseidon2Commitment::default()))
            .collect();
        let seq = Sequencer::funded(LOG_MAX_LDE, hashes).map_err(|e| format!("sequencer: {e}"))?;
        let demo = notes
            .into_iter()
            .enumerate()
            .map(|(index, (note, sk_d))| DemoNote {
                note,
                sk_d,
                index,
                spend_key: SpendKey::demo(0xA0 + index as u64),
            })
            .collect();
        let sender = if config.settle {
            let manifest =
                Manifest::load(&config.manifest_path).map_err(|e| format!("manifest: {e}"))?;
            Some(SettlementSender::new(config.rpc_url.clone(), manifest))
        } else {
            None
        };
        Ok(Self {
            seq,
            demo,
            recipient: derive_spend_pk(&Poseidon2Shielded, &seed(9)),
            sender,
            pending_settlement: None,
            snapshot,
        })
    }

    fn refresh(&self) {
        let snap = Snapshot::of(&self.seq);
        // Gauges are f64; heights and queue depths are far below 2^53, so the
        // conversion is exact in every realistic run.
        #[allow(clippy::cast_precision_loss)]
        {
            ::metrics::gauge!(names::BLOCK_HEIGHT).set(snap.block_number as f64);
            ::metrics::gauge!(names::MEMPOOL_SIZE).set(snap.pending as f64);
        }
        // Poison-tolerant on purpose: the snapshot is a derived status cache
        // and the assignment below is a whole-value move, so a lock held during
        // an unrelated panic still contains a valid (old or new) snapshot.
        // Panicking here would take the node down over a stale metrics gauge.
        *self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snap;
    }

    /// Prove one demo transfer end to end and admit it.
    ///
    /// Runs inline on the actor task: proving takes tens of seconds and the
    /// actor is single-command-at-a-time anyway; HTTP reads are unaffected
    /// because they answer from the snapshot, not from here.
    fn prove_and_submit(
        &mut self,
        input_index: usize,
        out_value: u64,
        fee: u64,
    ) -> Result<SubmitOk, String> {
        let t0 = std::time::Instant::now();
        let r = self.prove_and_submit_inner(input_index, out_value, fee);
        let secs = t0.elapsed().as_secs_f64();
        let label = if r.is_ok() { "accepted" } else { "rejected" };
        ::metrics::counter!(names::SUBMITS, "outcome" => label).increment(1);
        ::metrics::histogram!(names::SUBMIT_LATENCY, "outcome" => label).record(secs);
        if r.is_ok() {
            self.refresh();
        }
        r
    }

    fn prove_and_submit_inner(
        &mut self,
        input_index: usize,
        out_value: u64,
        fee: u64,
    ) -> Result<SubmitOk, String> {
        let d = self
            .demo
            .iter()
            .find(|d| d.index == input_index)
            .ok_or_else(|| format!("no demo note at index {input_index}"))?;
        if out_value.saturating_add(fee) > d.note.value() {
            return Err(format!(
                "output {out_value} + fee {fee} exceeds input value {}",
                d.note.value()
            ));
        }
        // Fresh note randomness from the OS CSPRNG. In production this is the
        // wallet's job; deriving an output's randomness from the spent note
        // would make the two notes linkable, so it must never be reused.
        let output =
            shielded::Note::new(out_value, random_bytes()?, random_bytes()?, self.recipient);
        // Prove against the *pending* projections: committed state plus every
        // queued nullifier and output. Since D-088 the commitment root chains
        // within a batch too - each transfer attests the root its own appends
        // produce - so membership and root both come from the projected tree.
        // `submit`'s admission check demands exactly these roots.
        let tree = self.seq.client_tree();
        let path = tree
            .path(d.index)
            .ok_or_else(|| format!("no membership path for note {}", d.index))?;
        let mut map = self.seq.client_map();
        let spec = ClientSpec {
            note: &d.note,
            sk_d: &d.sk_d,
            path: &path.siblings,
            index: d.index,
            output: &output,
            fee,
        };
        let inner = self.seq.inner().clone();
        let artifacts = prove_client_transfer(&inner, &spec, &tree, &mut map)
            .map_err(|e| format!("prove: {e}"))?;
        let envelope = d
            .spend_key
            .sign_public(&artifacts.public)
            .map_err(|e| format!("sign: {e}"))?;
        let first_nf = artifacts
            .public
            .nullifiers
            .first()
            .ok_or_else(|| "proof has no nullifiers".to_string())?
            .to_hex();
        self.seq
            .submit(ClientTransferProof {
                verifier: artifacts.verifier,
                proof: artifacts.proof,
                statement: artifacts.statement,
                shape: ONE_IN_ONE_OUT,
                public: artifacts.public,
                envelope,
            })
            .map_err(|e| format!("submit: {e}"))?;
        Ok(SubmitOk {
            nullifier: first_nf,
            pending: self.seq.pending(),
        })
    }

    /// Drain the mempool into one block; when settlement is enabled, encode
    /// the WBND bundle immediately so `/v1/block/settle` is only an RPC send.
    fn produce(&mut self) -> Result<serde_json::Value, String> {
        let t0 = std::time::Instant::now();
        let artifact = self
            .seq
            .produce_block()
            .map_err(|e| format!("produce: {e}"))?;
        let secs = t0.elapsed().as_secs_f64();
        ::metrics::counter!(names::BLOCKS_PRODUCED).increment(1);
        ::metrics::histogram!(names::BLOCK_PROVE_SECONDS).record(secs);
        let height = self.seq.state().block_number();
        tracing::info!(
            height,
            transfers = artifact.num_transfers,
            secs,
            "block produced"
        );
        let summary = serde_json::json!({
            "block_number": height,
            "num_transfers": artifact.num_transfers,
            "total_fee": artifact.total_fee,
            "prove_seconds": secs,
            "root": self.seq.state().root().to_hex(),
        });
        self.pending_settlement = if self.sender.is_some() {
            let limbs: Vec<u64> = artifact
                .statement
                .iter()
                .map(|f| u64::from(f.as_canonical_u32()))
                .collect();
            // Bundle encoding re-runs the composed walk twice: heavy, but it
            // belongs here so a settlement failure never re-proves.
            let (bundle, _jj) =
                prover::composed_export::settlement_bundle(&artifact.rc, &artifact.statement)
                    .map_err(|e| format!("bundle: {e}"))?;
            tracing::info!(bytes = bundle.len(), "settlement bundle encoded");
            Some((limbs, bundle))
        } else {
            None
        };
        self.refresh();
        Ok(summary)
    }

    async fn settle(&mut self) -> Result<String, String> {
        let Some((limbs, bundle)) = self.pending_settlement.clone() else {
            return Err("no block awaiting settlement".into());
        };
        let Some(sender) = self.sender.clone() else {
            return Err("settlement disabled (NODE_SETTLE=1 to enable)".into());
        };
        let hash = sender
            .settle(&limbs, &bundle)
            .await
            .map_err(|e| format!("settlement: {e}"))?;
        self.pending_settlement = None;
        Ok(hash)
    }

    async fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::DemoTransfer {
                input_index,
                out_value,
                fee,
                reply,
            } => {
                let r = self.prove_and_submit(input_index, out_value, fee);
                let _ = reply.send(r);
            }
            Cmd::CheckAdmit { public, reply } => {
                // Committed-state check only: the wallet witnessed the roots
                // /v1/roots reported, which are the committed ones. A queued
                // transfer that later makes this stale is caught again at
                // proof-time admission; this answers the wallet's question
                // without touching the proving machinery.
                let r = self
                    .seq
                    .state()
                    .check_admit(&public)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            Cmd::Produce { reply } => {
                let r = self.produce();
                let _ = reply.send(r);
            }
            Cmd::Settle { reply } => {
                let r = self.settle().await;
                let _ = reply.send(r);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// The keyed rate limiter: per role+endpoint, so a submit flood cannot
/// starve reads. `governor` 0.10 ships no axum layer, so the check is a
/// hand-rolled call in the guard middleware below.
type Limiter = RateLimiter<
    String,
    governor::state::keyed::DefaultKeyedStateStore<String>,
    governor::clock::DefaultClock,
>;

/// Shared state for every handler: cheap handles, no sequencer.
#[derive(Clone)]
struct AppState {
    tx: mpsc::UnboundedSender<Cmd>,
    acl: Arc<Acl>,
    signer: Arc<TokenSigner>,
    snapshot: Arc<std::sync::RwLock<Snapshot>>,
    limiter: Arc<Limiter>,
    metrics: Arc<metrics_exporter_prometheus::PrometheusHandle>,
}

/// Auth + rate-limit middleware. The ACL is the source of truth: a path not
/// in the policy is a 404 (we do not confirm it exists), and a token below
/// the required role is a 403. Failures are counted by reason so the
/// dashboard can tell a flood of junk from an expired operator token.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let Some(required) = st.acl.required_role(&path) else {
        return (StatusCode::NOT_FOUND, "no such endpoint").into_response();
    };
    let authed = (|| -> Result<Role, (StatusCode, &'static str)> {
        let header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "missing"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "missing"))?;
        st.signer
            .verify_for(token, now_unix(), required)
            .map_err(|e| {
                let (status, reason) = match e {
                    node::AuthError::Expired(_) => (StatusCode::UNAUTHORIZED, "expired"),
                    node::AuthError::Insufficient { .. } => (StatusCode::FORBIDDEN, "insufficient"),
                    _ => (StatusCode::UNAUTHORIZED, "bad"),
                };
                (status, reason)
            })
    })();
    let role = match authed {
        Ok(r) => r,
        Err((status, reason)) => {
            ::metrics::counter!(names::AUTH_FAILURES, "reason" => reason).increment(1);
            return (status, "token rejected").into_response();
        }
    };
    let key = format!("{role:?} {path}");
    if st.limiter.check_key(&key).is_err() {
        ::metrics::counter!(names::RATE_LIMITED, "endpoint" => path).increment(1);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    next.run(req).await
}

async fn health(State(st): State<AppState>) -> Json<serde_json::Value> {
    let guard = st
        .snapshot
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Json(guard.json())
}

async fn roots(State(st): State<AppState>) -> Json<serde_json::Value> {
    let (root, nullifier_root) = {
        let s = st
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (s.root_hex.clone(), s.nullifier_root_hex.clone())
    };
    Json(serde_json::json!({ "root": root, "nullifier_root": nullifier_root }))
}

async fn metrics_route(State(st): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.metrics.render(),
    )
        .into_response()
}

/// The wallet-facing endpoint: validates the SPHINCS+ envelope end to end
/// (parse at exact scheme sizes, verify over the statement encoding), then
/// asks the actor whether the statement is admissible against the committed
/// state - a spent nullifier or a stale root is a 422, not a shrug (D-090).
/// A valid, state-plausible envelope still answers 501: admitting a remote
/// proof needs the production verifier-rebuild path deferred in D-079.
/// Validation runs here (one hash-based signature check is milliseconds);
/// the state check goes through the actor so it reads the same state the
/// block driver mutates - no torn reads, no lock inversion.
async fn submit(State(st): State<AppState>, Json(wire): Json<TransferWire>) -> Response {
    let envelope = match wire.to_envelope() {
        Ok(e) => e,
        Err(e) => {
            ::metrics::counter!(names::TX_REJECTIONS, "reason" => "envelope").increment(1);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("envelope rejected: {e}"),
            )
                .into_response();
        }
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if st
        .tx
        .send(Cmd::CheckAdmit {
            public: envelope.public.clone(),
            reply: reply_tx,
        })
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "actor gone").into_response();
    }
    match reply_rx.await {
        Ok(Ok(())) => (
            StatusCode::NOT_IMPLEMENTED,
            "envelope valid; remote proof admission is deferred (D-079) - \
             the demo prover is /v1/demo/transfer",
        )
            .into_response(),
        Ok(Err(reason)) => {
            ::metrics::counter!(names::TX_REJECTIONS, "reason" => "state").increment(1);
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("state rejected: {reason}"),
            )
                .into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "actor dropped").into_response(),
    }
}

#[derive(serde::Deserialize)]
struct DemoReq {
    input_index: usize,
    out_value: u64,
    #[serde(default)]
    fee: u64,
}

async fn demo_transfer(
    State(st): State<AppState>,
    Json(req): Json<DemoReq>,
) -> Result<Json<SubmitOk>, (StatusCode, String)> {
    let (reply_tx, reply_rx) = oneshot::channel();
    st.tx
        .send(Cmd::DemoTransfer {
            input_index: req.input_index,
            out_value: req.out_value,
            fee: req.fee,
            reply: reply_tx,
        })
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor gone".into()))?;
    reply_rx
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor dropped".into()))?
        .map(Json)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))
}

async fn produce(
    State(st): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (reply_tx, reply_rx) = oneshot::channel();
    st.tx
        .send(Cmd::Produce { reply: reply_tx })
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor gone".into()))?;
    reply_rx
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor dropped".into()))?
        .map(Json)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))
}

async fn settle(
    State(st): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (reply_tx, reply_rx) = oneshot::channel();
    st.tx
        .send(Cmd::Settle { reply: reply_tx })
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor gone".into()))?;
    reply_rx
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "actor dropped".into()))?
        .map(|hash| Json(serde_json::json!({ "tx_hash": hash })))
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))
}

fn build_router(st: AppState, cors_origins: &[String]) -> Router {
    let origins: Vec<HeaderValue> = cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_route))
        .route("/v1/state", get(health))
        .route("/v1/roots", get(roots))
        .route("/v1/transfer", post(submit))
        .route("/v1/demo/transfer", post(demo_transfer))
        .route("/v1/block/produce", post(produce))
        .route("/v1/block/settle", post(settle))
        .route_layer(middleware::from_fn_with_state(st.clone(), guard))
        .layer(cors)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_BODY_BYTES,
        ))
        .with_state(st)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    node::metrics::init_tracing();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("token") => return issue_token_cli(&args),
        Some("genesis") => return write_genesis_cli(&args),
        _ => {}
    }
    let config = Config::from_env()?;
    let key = load_token_key()?;
    let signer = Arc::new(TokenSigner::new(&key).map_err(|e| format!("token signer: {e}"))?);
    drop(key); // Zeroizing wipes it; the signer keeps only the keyed MAC state.
    let metrics_handle = Arc::new(node::metrics::install_recorder()?);
    let snapshot = Arc::new(std::sync::RwLock::new(Snapshot::default()));
    let mut actor = Actor::new(&config, snapshot.clone())?;
    actor.refresh();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let limiter = Arc::new(RateLimiter::keyed(
        Quota::per_second(nonzero!(20u32)).allow_burst(nonzero!(40u32)),
    ));
    let st = AppState {
        tx: cmd_tx,
        acl: Arc::new(Acl::default_policy()),
        signer,
        snapshot: snapshot.clone(),
        limiter,
        metrics: metrics_handle,
    };
    let app = build_router(st.clone(), &config.cors_origins);

    // The actor: sole owner of the sequencer.
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            actor.handle(cmd).await;
        }
    });

    // The block driver: produce (and settle) whenever the mempool has work.
    let driver_tx = st.tx.clone();
    let interval = config.block_interval;
    let settle_enabled = config.settle;
    let driver_snap = snapshot.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let pending = driver_snap
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending;
            if pending == 0 {
                continue;
            }
            let (rtx, rrx) = oneshot::channel();
            if driver_tx.send(Cmd::Produce { reply: rtx }).is_err() {
                return;
            }
            match rrx.await {
                Ok(Ok(v)) => tracing::info!(summary = %v, "auto-produced"),
                Ok(Err(e)) => tracing::warn!(err = %e, "auto-produce failed"),
                Err(_) => return,
            }
            if settle_enabled {
                let (stx, srx) = oneshot::channel();
                if driver_tx.send(Cmd::Settle { reply: stx }).is_err() {
                    return;
                }
                match srx.await {
                    Ok(Ok(h)) => tracing::info!(hash = %h, "auto-settled"),
                    Ok(Err(e)) => tracing::warn!(err = %e, "auto-settle failed"),
                    Err(_) => return,
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&config.addr).await?;
    tracing::info!(addr = %config.addr, settle = config.settle, "node listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// `node token --role admin --ttl 86400`: issue a token for operators and
/// the e2e script. Prints only the token, so scripts can capture stdout.
fn issue_token_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let role = arg_after(args, "--role").unwrap_or_else(|| "admin".into());
    let ttl: u64 = arg_after(args, "--ttl")
        .unwrap_or_else(|| "86400".into())
        .parse()
        .map_err(|e| format!("--ttl: {e}"))?;
    let role = match role.as_str() {
        "readonly" => Role::ReadOnly,
        "submitter" => Role::Submitter,
        "admin" => Role::Admin,
        other => return Err(format!("unknown role {other}").into()),
    };
    let key = load_token_key()?;
    let signer = TokenSigner::new(&key).map_err(|e| format!("token signer: {e}"))?;
    println!("{}", signer.issue(role, now_unix() + ttl));
    Ok(())
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// `node genesis [--out PATH]`: emit the genesis leaves the node's demo
/// notes commit to, plus the Poseidon2 root of the tree holding them, in the
/// shape `Deploy.s.sol` reads (D-088: the pool is seeded with the ROOT, not
/// the leaves - roots are attested, not re-derived). The deployed pool must
/// start at exactly the tree the node witnessed against - the pool enforces
/// `rootBefore == currentRoot`, so any other genesis reverts.
fn write_genesis_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let out =
        arg_after(args, "--out").unwrap_or_else(|| "contracts/deployments/genesis.json".into());
    let hasher = Poseidon2Commitment::default();
    let mut tree = shielded::tree::CommitmentTree::new(hasher.clone());
    let mut leaves: Vec<String> = Vec::new();
    for (b, v) in GENESIS {
        let leaf = funded_note(b, v).0.commit(&hasher);
        tree.append(&leaf);
        leaves.push(leaf.to_hex());
    }
    let doc = serde_json::json!({
        "genesis_leaves": leaves,
        "genesis_root_hex": tree.root().to_hex(),
    });
    std::fs::write(&out, serde_json::to_string_pretty(&doc)?)?;
    eprintln!("wrote {out} ({} leaves)", leaves.len());
    Ok(())
}
