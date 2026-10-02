//! The STARK configuration: `KoalaBear` + quintic challenge field + Keccak transcript.
//!
//! ## Why this exact shape
//!
//! The on-chain verifier replays the Fiat-Shamir transcript to derive its own
//! challenges. With a Keccak-256 transcript it does so with the native
//! `keccak256` opcode (`0x20`, ~30 gas) and never implements a hash itself.
//! FIPS SHA3-256 has no precompile at all, so a SHA3 transcript would cost the
//! verifier thousands of gas per hash in Solidity.
//!
//! The Poseidon2 exception (ticket 05) is still required, but only *inside* the
//! recursion engine: the in-circuit Merkle gadget that verifies a lower layer's
//! openings is Poseidon2-shaped. The split is therefore
//!
//! ```text
//!   Shielded layer   SHA3-256     note/nullifier derivation, off-chain and
//!                                in-circuit as Keccak-f[1600] rows carrying
//!                                the 0x06 domain byte
//!   Layers 0..N-1    Poseidon2    Merkle + transcript, verified in-circuit
//!                                by the recursion engine
//!   Layer N (final)  Keccak-256   Merkle + transcript, replayed by Solidity
//! ```
//!
//! One audited permutation covers both hash needs: `p3-keccak-air` constrains
//! only the permutation, so the SHA3-vs-Keccak difference is a witness choice,
//! not a constraint change.
//!
//! Field: `KoalaBear` (31-bit `Monty`, `TwoAdic`). Challenge field: the D=5 trinomial
//! extension, giving ~128-bit conjecturable security against the union of
//! classical and quantum adversaries.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

/// The base field: `KoalaBear`, a 31-bit `Monty` prime with a large two-adic subgroup.
pub type F = KoalaBear;

/// The challenge field: degree-5 trinomial extension of `KoalaBear`.
///
/// 5 × 31 = 155 bits of field, which under the union bound with a quantum
/// attacker's Grover-amplified hash queries lands at ~128-bit conjecturable
/// security. See ticket 03.
pub type Challenge = QuinticTrinomialExtensionField<F>;

/// Byte-native Keccak-256 leaf hash.
///
/// A row serializes to bytes (`into_byte_stream` = canonical little-endian
/// for `KoalaBear`) and hashes with FIPS-padded Keccak-256 — the *same* function
/// the EVM's `keccak256` opcode computes. This is the property the settlement
/// boundary needs: Solidity walks the tree with the native opcode (~250 gas per
/// node) and never implements a permutation.
///
/// The previous shape (`PaddingFreeSponge<KeccakF, 25, 17, 4>` over u64 lanes)
/// shares the Keccak-f[1600] permutation but is not Keccak-256: no FIPS
/// padding, u64 lane order, 4-lane squeeze. Replaying it in Solidity means a
/// hand-rolled permutation at ~30-50k gas per call, which is over the block
/// gas limit at settlement query counts. See D-050.
type FieldHash = SerializingHasher<Keccak256Hash>;

/// Two-to-one compression: `keccak256(left || right)`, the native opcode,
/// matching `contracts/src/MerkleProof.sol` exactly.
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;

/// The Keccak-256 Merkle tree over base-field rows.
///
/// Digests are 32 raw bytes (`DIGEST_ELEMS = 32`), absorbed into the
/// transcript as bytes by `SerializingChallenger32`'s
/// `CanObserve<MerkleCap<F, [u8; N]>>` impl — so the cap the Solidity side
/// pins is the cap the transcript bound, byte for byte.
pub type Mmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;

/// The same tree viewed over the extension field, for FRI's commit phase.
pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, Mmcs>;

/// The PCS: two-adic FRI over the Keccak Merkle tree.
pub type Pcs = TwoAdicFriPcs<F, Radix2DitParallel<F>, Mmcs, ChallengeMmcs>;

/// The Fiat-Shamir transcript: Keccak-256 over serialized field elements.
///
/// `SerializingChallenger32` absorbs each base-field element as its little-endian
/// u32, which the Solidity verifier reproduces byte-for-byte.
pub type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

/// The full STARK configuration.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Build the Keccak-256 Merkle MMCS.
#[must_use]
pub const fn mmcs(cap_height: usize) -> Mmcs {
    let field_hash = SerializingHasher::new(Keccak256Hash {});
    let compress = CompressionFunctionFromHasher::new(Keccak256Hash {});
    MerkleTreeMmcs::new(field_hash, compress, cap_height)
}

/// A fresh Keccak-256 transcript, empty initial state.
#[must_use]
pub const fn challenger() -> Challenger {
    SerializingChallenger32::from_hasher(Vec::new(), Keccak256Hash {})
}

/// Assemble the proving/verification configuration.
#[must_use]
pub fn config(fri_params: FriParameters<ChallengeMmcs>) -> Config {
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::default(), mmcs(3), fri_params);
    StarkConfig::new(pcs, challenger())
}
