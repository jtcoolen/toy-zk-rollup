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
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;

/// The base field: `KoalaBear`, a 31-bit `Monty` prime with a large two-adic subgroup.
pub type F = KoalaBear;

/// The challenge field: degree-5 trinomial extension of `KoalaBear`.
///
/// 5 × 31 = 155 bits of field, which under the union bound with a quantum
/// attacker's Grover-amplified hash queries lands at ~128-bit conjecturable
/// security. See ticket 03.
pub type Challenge = QuinticTrinomialExtensionField<F>;

/// Keccak sponge over the 1600-bit state: 4 u64 output limbs.
type KeccakSponge = PaddingFreeSponge<KeccakF, 25, 17, 4>;

/// Maps field-element vectors into the sponge via their u64 serialization.
type FieldHash = SerializingHasher<KeccakSponge>;

/// Two-to-one compression for Merkle internal nodes.
type Compress = CompressionFunctionFromHasher<KeccakSponge, 2, 4>;

/// The Keccak Merkle tree over base-field vectors.
///
/// `VECTOR_LEN` is how many field elements are hashed per leaf; the digest is 4
/// u64 limbs = 32 bytes, which is exactly a Keccak-256 digest, so the Solidity
/// side walks the same tree with `keccak256`.
pub type Mmcs = MerkleTreeMmcs<
    [F; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    2,
    4,
>;

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

/// Build the Keccak Merkle MMCS.
#[must_use]
pub const fn mmcs(cap_height: usize) -> Mmcs {
    let sponge = PaddingFreeSponge::<KeccakF, 25, 17, 4>::new(KeccakF {});
    let field_hash = SerializingHasher::new(sponge);
    let compress = CompressionFunctionFromHasher::new(sponge);
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
