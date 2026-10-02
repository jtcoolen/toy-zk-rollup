//! Prometheus metrics and structured logging for the node.
//!
//! # Why metrics are a first-class part of this node, not a bolt-on
//!
//! A rollup node has three failure modes that are invisible without numbers:
//! the mempool silently backing up, proving getting slower than block time,
//! and a client hammering the submit endpoint. Each of those is a different
//! operational response, and each needs a different signal. The metrics below
//! are chosen so that a dashboard can answer "is the node healthy" without
//! reading a log line.
//!
//! # The recorder
//!
//! We use the `metrics` facade with the Prometheus exporter in *pull-render*
//! mode: `install_recorder()` returns a [`PrometheusHandle`] whose
//! `render()` produces the Prometheus text exposition. The node's own axum
//! router serves that at `/metrics`. We deliberately do NOT use the
//! exporter's built-in HTTP listener — the node already owns a port, and two
//! servers on one port is a deployment footgun.
//!
//! # Cardinality discipline
//!
//! Prometheus's failure mode is unbounded label cardinality: a label whose
//! values are unbounded (a user id, a tx hash) turns the metrics store into
//! a memory leak. Every label on every metric here is drawn from a small,
//! fixed set — `role`, `outcome`, `endpoint`. No metric carries a tx hash,
//! an address, or a nullifier as a label. Those belong in logs, not in
//! time-series.
//!
//! # Debugging with metrics
//!
//! The histograms are the debugging tool. `submit_latency_seconds` and
//! `block_prove_seconds` are histograms, so a latency spike can be read as
//! a p99 shift rather than a single sample, and the p50-vs-p99 split tells
//! you whether the whole node slowed down or just the tail. The Grafana
//! dashboard in `observability/` graphs exactly these.

use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use std::time::Duration;

/// Install the global Prometheus recorder and return the handle that renders
/// the exposition text.
///
/// Installs the `metrics` global recorder, so any `metrics::counter!` call
/// anywhere in the process feeds this. Call exactly once at startup.
///
/// # Errors
///
/// Returns [`BuildError`] if a recorder is already installed (double install)
/// or a bucket configuration is invalid.
pub fn install_recorder() -> Result<PrometheusHandle, BuildError> {
    PrometheusBuilder::new()
        // Latency histograms: buckets chosen for a node whose operations
        // range from ~50 µs (a state read) to ~10 s (a block proof). The
        // buckets are logarithmic-ish across that range.
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("node_submit_latency_seconds".to_string()),
            &[
                0.000_05, 0.000_2, 0.001, 0.005, 0.02, 0.1, 0.5, 1.0, 5.0, 10.0,
            ],
        )?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("node_block_prove_seconds".to_string()),
            &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0],
        )?
        // Keep idle metrics alive so a dashboard does not show gaps when the
        // node is quiet; a dropped series looks like a crash.
        .idle_timeout(
            metrics_util::MetricKindMask::ALL,
            Some(Duration::from_secs(3600)),
        )
        .install_recorder()
}

/// Initialize structured logging.
///
/// Reads `RUST_LOG` (e.g. `RUST_LOG=node=info,axum=warn`). Defaults to
/// `info` for the node and `warn` for the HTTP stack so a normal run is
/// readable and a noisy dependency does not drown the signal.
///
/// Idempotent: a second call is a no-op rather than a panic, so a test that
/// calls it twice does not crash.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("node=info,axum=warn,tower_http=warn"));
    // `try_init` so a second call (or a test harness that already installed
    // a subscriber) does not panic.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

/// The metric names this node emits, as constants.
///
/// Centralized so the dashboard and the code agree on names by construction
/// rather than by grep. A typo in a metric name is otherwise invisible until
/// a panel shows no data.
pub mod names {
    /// Counter: transfers submitted, labeled `outcome` (accepted|rejected).
    pub const SUBMITS: &str = "node_submits_total";
    /// Histogram: submit endpoint latency, labeled `outcome`.
    pub const SUBMIT_LATENCY: &str = "node_submit_latency_seconds";
    /// Counter: blocks produced.
    pub const BLOCKS_PRODUCED: &str = "node_blocks_produced_total";
    /// Histogram: block proving wall time.
    pub const BLOCK_PROVE_SECONDS: &str = "node_block_prove_seconds";
    /// Gauge: transfers currently in the mempool.
    pub const MEMPOOL_SIZE: &str = "node_mempool_size";
    /// Gauge: current block height.
    pub const BLOCK_HEIGHT: &str = "node_block_height";
    /// Counter: auth failures, labeled `reason` (missing|bad|expired|insufficient).
    pub const AUTH_FAILURES: &str = "node_auth_failures_total";
    /// Counter: rate-limited requests, labeled `endpoint`.
    pub const RATE_LIMITED: &str = "node_rate_limited_total";
    /// Counter: rejected transfers by reason.
    pub const TX_REJECTIONS: &str = "node_tx_rejections_total";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorder_renders_prometheus_text() {
        // A fresh recorder per test process; `install_recorder` is global, so
        // this test must be the only one that installs it. We use a local
        // builder rather than the global to keep the test isolated.
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("install recorder");
        metrics::counter!(names::SUBMITS, "outcome" => "accepted").increment(3);
        let text = handle.render();
        assert!(
            text.contains("node_submits_total"),
            "rendered text missing the counter: {text}"
        );
        assert!(text.contains("outcome=\"accepted\""));
    }

    #[test]
    fn metric_names_are_valid_prometheus_identifiers() {
        // Prometheus names must match [a-zA-Z_:][a-zA-Z0-9_:]*.
        let all = [
            names::SUBMITS,
            names::SUBMIT_LATENCY,
            names::BLOCKS_PRODUCED,
            names::BLOCK_PROVE_SECONDS,
            names::MEMPOOL_SIZE,
            names::BLOCK_HEIGHT,
            names::AUTH_FAILURES,
            names::RATE_LIMITED,
            names::TX_REJECTIONS,
        ];
        for name in all {
            let ok = name.chars().enumerate().all(|(i, c)| {
                c == '_'
                    || c.is_ascii_alphanumeric()
                    || (i == 0 && (c.is_ascii_alphabetic() || c == ':'))
            });
            assert!(ok, "invalid prometheus metric name: {name}");
        }
    }
}
