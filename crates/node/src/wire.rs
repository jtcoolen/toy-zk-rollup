//! The HTTP wire format for transfers.
//!
//! The wire carries what a wallet can actually produce: the public statement
//! and its SPHINCS+ envelope. Hex strings are lowercase, unspaced; byte
//! arrays are length-checked against the scheme's real sizes, so a truncated
//! or oversized field is a 400, never a panic or a silent pad.
//!
//! The client *proof* is deliberately not on this wire: the inner verifier is
//! not wire-serializable (D-079), and the demo's proving path runs in-process
//! inside the node binary. When the verifier-rebuild path lands, the proof
//! field joins this DTO and [`TransferWire::to_envelope`] stays the unchanged
//! trust boundary - the envelope is what authorizes the spend.

use pq_hash::{Digest32, MerkleRoot, NoteHash, Nullifier};
use pq_sign::{Sha2_128f, SigningKey, SpendAuth, SphincsPlusAuth, VerifyingKey};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use shielded::TransferPublic;

use crate::tx::{ShieldedTransfer, TxError};

/// A 32-byte digest, hex-encoded on the wire.
type Hex32 = String;

/// The transfer as it arrives over HTTP.
#[derive(Clone, Debug, Deserialize)]
pub struct TransferWire {
    /// Nullifiers being spent, one per input.
    pub nullifiers: Vec<Hex32>,
    /// Output commitments being appended, one per output.
    pub outputs: Vec<Hex32>,
    /// The commitment-tree root the inputs were proven against.
    pub root: Hex32,
    /// The nullifier-map root before this transfer.
    pub nullifier_root_before: Hex32,
    /// The nullifier-map root after this transfer.
    pub nullifier_root_after: Hex32,
    /// The fee, in base units.
    pub fee: u64,
    /// The SPHINCS+ verifying key (64 bytes: `pk_seed || pk_root`).
    pub verifying_key: String,
    /// The SPHINCS+ signature over the statement encoding.
    pub signature: String,
}

/// Parse lowercase hex of exactly `n` bytes.
fn hex_fixed(s: &str, n: usize) -> Result<Vec<u8>, String> {
    if s.len() != n * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected {n}-byte hex, got {} chars", s.len()));
    }
    hex::decode(s).map_err(|e| e.to_string())
}

fn digest32(s: &str) -> Result<Digest32, String> {
    let b = hex_fixed(s, 32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(Digest32::new(a))
}

impl TransferWire {
    /// Rebuild the public statement, rejecting malformed shapes before any
    /// crypto is attempted.
    ///
    /// # Errors
    ///
    /// `Err(message)` describing the first malformed field, for a 400 body.
    pub fn to_public(&self) -> Result<TransferPublic, String> {
        if self.nullifiers.is_empty() || self.outputs.is_empty() {
            return Err("a transfer must spend and create at least one note".into());
        }
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|h| digest32(h).map(Nullifier::from_digest))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(|h| digest32(h).map(NoteHash::from_digest))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TransferPublic {
            nullifiers,
            outputs,
            root: MerkleRoot::from_digest(digest32(&self.root)?),
            nullifier_roots: shielded::NullifierRoots {
                before: MerkleRoot::from_digest(digest32(&self.nullifier_root_before)?),
                after: MerkleRoot::from_digest(digest32(&self.nullifier_root_after)?),
            },
            fee: self.fee,
        })
    }

    /// Rebuild the signed envelope: parse key and signature at their exact
    /// scheme sizes, then verify the signature over the statement encoding.
    ///
    /// # Errors
    ///
    /// `Err(TxError)` for a malformed field or an envelope that does not
    /// authorize the statement.
    pub fn to_envelope(&self) -> Result<ShieldedTransfer, TxError> {
        let public = self.to_public().map_err(|_| TxError::TooLarge)?;
        let vk = <SphincsPlusAuth as SpendAuth>::public_key_from_bytes(
            &hex::decode(&self.verifying_key).map_err(|_| TxError::TooLarge)?,
        )
        .map_err(|_| TxError::BadSignature)?;
        let signature = <SphincsPlusAuth as SpendAuth>::signature_from_bytes(
            &hex::decode(&self.signature).map_err(|_| TxError::TooLarge)?,
        )
        .map_err(|_| TxError::BadSignature)?;
        let envelope = ShieldedTransfer {
            public,
            verifying_key: vk,
            signature,
        };
        envelope.verify_signature()?;
        Ok(envelope)
    }
}

/// A SPHINCS+ keypair for the demo's in-process client (D-079).
///
/// Real deployments load spend keys from the password-protected keystore;
/// this type exists so the one place that holds them is explicit and never
/// `Debug`-printed. The demo seeds are public fixture knowledge, so
/// deterministic derivation is a feature here, not a shortcut.
pub struct SpendKey {
    sk: SigningKey<Sha2_128f>,
    vk: VerifyingKey<Sha2_128f>,
}

impl SpendKey {
    /// Deterministic demo keypair from a seed value (same pattern as the
    /// sequencer integration tests' `sign_statement`).
    #[must_use]
    pub fn demo(seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let (sk, vk) = SphincsPlusAuth::generate_keypair(&mut rng);
        Self { sk, vk }
    }

    /// Sign `envelope`'s statement encoding, returning the completed
    /// envelope with this key's verifying key and a fresh signature.
    ///
    /// # Errors
    ///
    /// `TxError` if the statement cannot be encoded (count overflow).
    pub fn sign(&self, envelope: &ShieldedTransfer) -> Result<ShieldedTransfer, TxError> {
        let message = envelope.signing_message()?;
        Ok(ShieldedTransfer {
            public: envelope.public.clone(),
            verifying_key: self.vk.clone(),
            signature: SphincsPlusAuth::sign(&self.sk, &message),
        })
    }

    /// Sign a public statement directly, producing a complete envelope.
    ///
    /// The placeholder-signature dance is not sloppiness: `signing_message`
    /// is a method on the envelope, so an envelope must exist before the
    /// real message does. The placeholder is never verified.
    ///
    /// # Errors
    ///
    /// `TxError` if the statement cannot be encoded (count overflow).
    pub fn sign_public(
        &self,
        public: &shielded::TransferPublic,
    ) -> Result<ShieldedTransfer, TxError> {
        let unsigned = ShieldedTransfer {
            public: public.clone(),
            verifying_key: self.vk.clone(),
            signature: SphincsPlusAuth::sign(&self.sk, b"placeholder"),
        };
        let message = unsigned.signing_message()?;
        Ok(ShieldedTransfer {
            public: unsigned.public,
            verifying_key: self.vk.clone(),
            signature: SphincsPlusAuth::sign(&self.sk, &message),
        })
    }

    /// The matching verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey<Sha2_128f> {
        self.vk.clone()
    }
}

impl core::fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.debug_struct("SpendKey").finish_non_exhaustive()
    }
}

/// Serialize a verifying key for the wire.
#[must_use]
pub fn vk_hex(vk: &VerifyingKey<Sha2_128f>) -> String {
    hex::encode(<SphincsPlusAuth as SpendAuth>::public_key_to_bytes(vk))
}

/// Serialize a signature for the wire.
#[must_use]
pub fn sig_hex(sig: &<SphincsPlusAuth as SpendAuth>::Signature) -> String {
    hex::encode(<SphincsPlusAuth as SpendAuth>::signature_to_bytes(sig))
}

/// The response to an accepted transfer.
#[derive(Serialize, Debug)]
pub struct SubmitOk {
    /// The first nullifier, as the transfer's handle.
    pub nullifier: String,
    /// Mempool depth after admission.
    pub pending: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::{Digest32, Keccak256Commitment, Sha3_256Shielded};
    use shielded::keys::derive_spend_pk;

    fn sample_wire() -> TransferWire {
        let sk_d = [3u8; 32];
        let pk_d = derive_spend_pk(&Sha3_256Shielded, &sk_d);
        let note = shielded::Note::new(900, [1u8; 32], [2u8; 32], pk_d);
        let nf = note.nullifier(&Sha3_256Shielded, &sk_d);
        let out = note.commit(&Keccak256Commitment);
        let public = TransferPublic {
            nullifiers: vec![nf],
            outputs: vec![out],
            root: MerkleRoot::from_digest(Digest32::new([7u8; 32])),
            nullifier_roots: shielded::NullifierRoots {
                before: MerkleRoot::from_digest(Digest32::new([8u8; 32])),
                after: MerkleRoot::from_digest(Digest32::new([9u8; 32])),
            },
            fee: 100,
        };
        let key = SpendKey::demo(0x42);
        let unsigned = ShieldedTransfer {
            public,
            verifying_key: key.verifying_key(),
            signature: SphincsPlusAuth::sign(&key.sk, b"unused placeholder"),
        };
        let signed = key.sign(&unsigned).expect("signs");
        TransferWire {
            nullifiers: vec![nf.to_hex()],
            outputs: vec![out.to_hex()],
            root: "07".repeat(32),
            nullifier_root_before: "08".repeat(32),
            nullifier_root_after: "09".repeat(32),
            fee: 100,
            verifying_key: vk_hex(&signed.verifying_key),
            signature: sig_hex(&signed.signature),
        }
    }

    #[test]
    fn wire_roundtrips_to_a_verifying_envelope() {
        let w = sample_wire();
        let env = w.to_envelope().expect("envelope verifies");
        assert_eq!(env.public.fee, 100);
        assert_eq!(env.public.nullifiers.len(), 1);
    }

    #[test]
    fn tampered_fee_fails_the_signature() {
        let mut w = sample_wire();
        w.fee = 101;
        assert_eq!(w.to_envelope().err(), Some(TxError::BadSignature));
    }

    #[test]
    fn malformed_hex_is_rejected_not_panicked() {
        let mut w = sample_wire();
        w.root = "0abc".into();
        assert!(w.to_public().is_err());
        let mut w2 = sample_wire();
        w2.signature = "zz".repeat(4);
        assert!(w2.to_envelope().is_err());
    }

    #[test]
    fn empty_sets_are_rejected() {
        let mut w = sample_wire();
        w.nullifiers.clear();
        assert!(w.to_public().is_err());
    }
}
