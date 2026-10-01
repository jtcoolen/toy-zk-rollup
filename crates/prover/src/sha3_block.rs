//! SHA3-256 for a single rate-block message, on the Keccak-f[1600] table.
//!
//! ## Why this exists
//!
//! The shielded layer hashes nullifiers and spend-key derivations with **SHA3-256**
//! (FIPS-202), not Keccak-256. The two differ in exactly one byte: the domain
//! separator that starts the padding. Keccak pads with `0x01`, SHA3 pads with
//! `0x06`. Same permutation, same rate, different pad.
//!
//! The off-the-shelf circuit helper [`CircuitBuilder::keccak256_limbs`] hardcodes
//! the Keccak `0x01` pad, so it cannot produce a SHA3 digest. This module adds the
//! `0x06` variant. It is deliberately narrow:
//!
//! * **Single block only.** Every SHA3 preimage in this protocol is ≤ 136 bytes
//!   (the nullifier's is 110, the spend-key derivation's is 68), so the sponge
//!   never loops. That removes the multi-block XOR-absorb path entirely — and with
//!   it the need for the private `xor_limb16` gadget.
//! * **Even byte length.** Limbs pack two bytes, so the message must be an even
//!   number of bytes. The domain tags are chosen even for exactly this reason.
//!
//! ## The block layout
//!
//! SHA3-256 absorbs a 136-byte block: the message, then `0x06`, then zeros, with
//! the top bit of the block's final byte set. The state is 100 limbs; the rate is
//! 68 limbs, so the 32 capacity limbs stay zero, exactly as the native sponge
//! initializes them.
//!
//! ```text
//!   limbs:  [ message limbs ][ 0x06 ‖ 0x00 … 0x80 ][ capacity = 0 ]
//!             n limbs         68 − n limbs            32 limbs
//! ```

use p3_circuit::ops::{
    bytes_to_limbs, KECCAK256_DIGEST_LIMBS, KECCAK256_RATE_BYTES, KECCAK_STATE_LIMBS,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

/// The SHA3 (FIPS-202) pad byte. Keccak-256 uses `0x01`; SHA3-256 uses `0x06`.
const SHA3_PAD: u8 = 0x06;

/// 16-bit limbs in one SHA3-256 rate block.
const RATE_LIMBS: usize = KECCAK256_RATE_BYTES / 2;

/// SHA3-256 of a single-block message given as little-endian 16-bit limbs.
///
/// `message` must be at most `RATE_LIMBS - 1` limbs, so the pad byte and the
/// final `0x80` still land inside the first block.
///
/// Returns the 32-byte digest as [`KECCAK256_DIGEST_LIMBS`] little-endian limbs,
/// from exactly one Keccak-f[1600] call.
///
/// # Errors
///
/// * [`CircuitBuilderError::NonPrimitiveOpArity`] if the message leaves no room
///   for the pad in the first block.
/// * Propagates [`CircuitBuilderError`] from the Keccak-f op.
pub fn sha3_256_single_block<F, BF>(
    builder: &mut CircuitBuilder<F>,
    message: &[ExprId],
) -> Result<Vec<ExprId>, CircuitBuilderError>
where
    F: Field + ExtensionField<BF>,
    BF: PrimeField64,
{
    // The pad needs at least the block's final byte, so the message must stop
    // short of the rate boundary.
    if message.len() >= RATE_LIMBS {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "Sha3_256SingleBlock",
            expected: format!("at most {} limbs", RATE_LIMBS - 1),
            got: message.len(),
        });
    }

    // The padded tail: `0x06` right after the message, `0x80` in the last byte
    // of the block, zeros between. Mirrors `keccak256_limbs`' tail with SHA3's
    // pad byte.
    let message_bytes = 2 * message.len();
    let mut tail = vec![0u8; KECCAK256_RATE_BYTES - message_bytes];
    tail[0] = SHA3_PAD;
    // Non-empty because `message.len() < RATE_LIMBS` keeps the message below the
    // block size.
    if let Some(last) = tail.last_mut() {
        *last |= 0x80;
    }

    // The state: message limbs, then the constant tail limbs, then zero capacity.
    // Block 0 fills the all-zero initial state directly, so nothing is XORed.
    let mut state: Vec<ExprId> = message.to_vec();
    state.extend(
        bytes_to_limbs(&tail)
            .into_iter()
            .map(|limb| builder.define_const(F::from_u16(limb))),
    );
    state.resize(KECCAK_STATE_LIMBS, builder.define_const(F::ZERO));

    let permuted = builder.add_keccak_f1600(&state)?;
    // The digest is the first 32 bytes of the permuted state.
    Ok(permuted.into_iter().take(KECCAK256_DIGEST_LIMBS).collect())
}
