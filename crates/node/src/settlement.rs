//! L1 settlement: encode `applyBlock` and send it over JSON-RPC.
//!
//! A faithful port of `contracts/scripts/settle_block.mjs`, kept small and
//! hand-rolled on purpose: the ABI surface is one function of two arguments,
//! and a hand-written encoder is auditable against the Solidity signature in
//! a way a generated one is not. The selector is pinned by
//! `contracts/test/SelectorPins.t.sol` against the native `keccak256` the
//! contract dispatches on, so this constant cannot drift silently.
//!
//! # Key custody
//!
//! The node holds **no signing keys**. The transaction is submitted with
//! `eth_sendTransaction` from a *sender account configured by address* — on
//! a dev chain (anvil) that account is unlocked and its address is public
//! knowledge; in production the RPC endpoint belongs to a signing relayer
//! (unlocking a geth node or a signer bridge), and this code never sees a
//! private key. That is a deliberate trust boundary, not an oversight.

use std::time::Duration;

use serde_json::json;
use thiserror::Error;

/// `applyBlock(uint256[],bytes)` — first four bytes of the EVM-native
/// keccak256 of the signature, pinned by `SelectorPins.t.sol`.
const SELECTOR: [u8; 4] = [0x0c, 0xb0, 0x00, 0xb5];

/// Gas ceiling for one settlement: matches the 20 B the dev-chain runs use
/// (the WHIR verifier's cost is data-dependent and still well above what a
/// static estimate would give).
const GAS_LIMIT: u64 = 20_000_000_000;

/// Errors from the settlement sender. Nothing here retries blindly: a
/// failed or reverted settlement keeps its artifact for operator review.
#[derive(Debug, Error)]
pub enum SettlementError {
    /// Transport-level failure talking to the execution-layer RPC.
    #[error("rpc transport: {0}")]
    Transport(String),
    /// The RPC answered with a JSON-RPC error object.
    #[error("rpc error for {method}: {detail}")]
    Rpc {
        /// The JSON-RPC method that failed.
        method: &'static str,
        /// The error object, serialized.
        detail: String,
    },
    /// The transaction landed but reverted.
    #[error("settlement tx {hash} reverted (receipt status {status})")]
    Reverted {
        /// The transaction hash.
        hash: String,
        /// The receipt's `status` field, verbatim.
        status: String,
    },
    /// No receipt within the deadline.
    #[error("no receipt for {hash} within {secs}s")]
    Timeout {
        /// The transaction hash.
        hash: String,
        /// The deadline that elapsed.
        secs: u64,
    },
    /// The deployment manifest is missing or malformed.
    #[error("manifest: {0}")]
    Manifest(String),
}

/// The deployment manifest: the addresses a settlement transaction needs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest {
    /// The `ShieldedPool` proxy address.
    pub pool: String,
    /// The account the settlement tx is sent from (unlocked on the RPC
    /// endpoint; the node holds no keys).
    pub deployer: String,
}

impl Manifest {
    /// Load the manifest from a JSON file (the shape written by
    /// `contracts/scripts/deploy_local.mjs`).
    ///
    /// # Errors
    ///
    /// [`SettlementError::Manifest`] if the file is unreadable or malformed.
    pub fn load(path: &str) -> Result<Self, SettlementError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| SettlementError::Manifest(format!("{path}: {e}")))?;
        serde_json::from_str(&text).map_err(|e| SettlementError::Manifest(format!("{path}: {e}")))
    }
}

/// 32-byte big-endian word for a `uint256`.
fn enc_uint(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// `uint256[]` tail: length word, then one word per element.
fn enc_dyn_array(words: &[u64]) -> Vec<u8> {
    let mut out = enc_uint(words.len() as u64).to_vec();
    for w in words {
        out.extend_from_slice(&enc_uint(*w));
    }
    out
}

/// `bytes` tail: length word, then the payload zero-padded to a word.
fn enc_bytes(buf: &[u8]) -> Vec<u8> {
    let mut out = enc_uint(buf.len() as u64).to_vec();
    out.extend_from_slice(buf);
    let pad = (32 - buf.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Encode the full `applyBlock(uint256[],bytes)` calldata.
///
/// `statement` is the block statement as canonical field elements (the same
/// limbs the proof was verified against); `proof` is the WBND bundle.
#[must_use]
pub fn encode_apply_block(statement: &[u64], proof: &[u8]) -> Vec<u8> {
    let stmt_tail = enc_dyn_array(statement);
    let proof_tail = enc_bytes(proof);
    let mut calldata = SELECTOR.to_vec();
    // Dynamic-argument head: offsets to each tail, from the head's end.
    calldata.extend_from_slice(&enc_uint(0x40));
    calldata.extend_from_slice(&enc_uint(0x40 + stmt_tail.len() as u64));
    calldata.extend_from_slice(&stmt_tail);
    calldata.extend_from_slice(&proof_tail);
    calldata
}

/// The settlement sender: an RPC URL, a manifest, and nothing secret.
#[derive(Clone, Debug)]
pub struct SettlementSender {
    rpc: reqwest::Client,
    url: String,
    manifest: Manifest,
    poll: Duration,
    deadline: Duration,
}

impl SettlementSender {
    /// Build a sender for `url` (e.g. `http://127.0.0.1:8545`).
    #[must_use]
    pub fn new(url: impl Into<String>, manifest: Manifest) -> Self {
        Self {
            rpc: reqwest::Client::new(),
            url: url.into(),
            manifest,
            poll: Duration::from_secs(2),
            deadline: Duration::from_secs(600),
        }
    }

    /// One JSON-RPC call. Returns the `result` value, or an error carrying
    /// the RPC's error object verbatim.
    async fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, SettlementError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .rpc
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SettlementError::Transport(e.to_string()))?;
        let mut value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SettlementError::Transport(e.to_string()))?;
        if let Some(err) = value.get("error") {
            return Err(SettlementError::Rpc {
                method,
                detail: err.to_string(),
            });
        }
        Ok(value
            .get_mut("result")
            .map_or_else(serde_json::Value::default, std::mem::take))
    }

    /// Settle one block: encode, send, and wait for a successful receipt.
    ///
    /// Returns the transaction hash. A revert or timeout is an error — the
    /// caller keeps its artifact and does not resend blindly (a resent
    /// settlement of the same block would double-apply nullifiers if the
    /// first attempt actually landed).
    ///
    /// # Errors
    ///
    /// [`SettlementError`] on transport failure, revert, or timeout.
    pub async fn settle(&self, statement: &[u64], proof: &[u8]) -> Result<String, SettlementError> {
        let calldata = encode_apply_block(statement, proof);
        let tx = json!({
            "from": self.manifest.deployer,
            "to": self.manifest.pool,
            "data": format!("0x{}", hex::encode(&calldata)),
            "gas": format!("{GAS_LIMIT:#x}"),
        });
        tracing::info!(
            limbs = statement.len(),
            proof_bytes = proof.len(),
            "sending applyBlock"
        );
        let hash = self
            .call("eth_sendTransaction", json!([tx]))
            .await?
            .as_str()
            .ok_or_else(|| SettlementError::Transport("sendTransaction: non-string result".into()))?
            .to_string();

        let t0 = std::time::Instant::now();
        loop {
            let rc = self
                .call("eth_getTransactionReceipt", json!([hash.clone()]))
                .await?;
            if !rc.is_null() {
                let status = rc.get("status").and_then(|s| s.as_str()).unwrap_or("0x0");
                let gas = rc
                    .get("gasUsed")
                    .and_then(|s| s.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
                if status != "0x1" {
                    return Err(SettlementError::Reverted {
                        hash,
                        status: status.to_string(),
                    });
                }
                tracing::info!(
                    %hash,
                    gas = gas.unwrap_or(0),
                    secs = t0.elapsed().as_secs_f64(),
                    "settlement confirmed"
                );
                return Ok(hash);
            }
            if t0.elapsed() > self.deadline {
                return Err(SettlementError::Timeout {
                    hash,
                    secs: self.deadline.as_secs(),
                });
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_block_head_offsets_match_the_js_encoder() {
        // Two limbs, a small proof: the offsets and layout are fully
        // predictable by hand and must match settle_block.mjs exactly.
        let stmt = vec![7u64, 8];
        let proof = vec![0xAAu8; 33]; // forces one padding byte
        let cd = encode_apply_block(&stmt, &proof);
        assert_eq!(&cd[0..4], &SELECTOR);
        assert_eq!(cd.len(), 4 + 32 * 2 + (32 + 2 * 32) + (32 + 64));
        // head[0] = 0x40
        assert_eq!(cd[35], 0x40);
        // head[1] = 0x40 + stmt tail length (len word + 2 elements = 96 = 0x60)
        assert_eq!(cd[66], 0x00);
        assert_eq!(cd[67], 0xa0); // 0x40 + 0x60
                                  // stmt tail: length 2, then 7, then 8
        assert_eq!(cd[68 + 31], 2);
        assert_eq!(cd[68 + 63], 7);
        assert_eq!(cd[68 + 95], 8);
        // proof tail: length 33, payload, one pad byte
        assert_eq!(cd[68 + 96 + 31], 33);
        assert_eq!(cd[68 + 96 + 32], 0xAA);
        assert_eq!(cd[cd.len() - 1], 0x00);
    }

    #[test]
    fn empty_proof_pads_to_nothing() {
        let cd = encode_apply_block(&[1], &[]);
        assert_eq!(cd.len(), 4 + 64 + 32 + 32 + 32);
    }

    #[test]
    fn manifest_parses_the_deploy_script_shape() {
        let m: Manifest = serde_json::from_str(
            r#"{"verifier":"0xaaa0","pool":"0xbbb0","deployer":"0xccc0","chainId":31337}"#,
        )
        .expect("manifest");
        assert_eq!(m.pool, "0xbbb0");
        assert_eq!(m.deployer, "0xccc0");
    }
}
