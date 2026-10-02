//! Golden vectors for the `KoalaBear` quartic extension field.
//!
//! The settlement challenge field is `BinomialExtensionField<KoalaBear, 4>`.
//! The on-chain side represents an extension element as four 31-bit limbs
//! packed into one `uint256` and does arithmetic with SWAR-style wide
//! arithmetic. That representation is an optimization, and an optimization
//! that computes the wrong field is worse than no optimization at all.
//!
//! These vectors pin it: every operation here is computed by p3's Rust
//! implementation, which is the reference, and the Solidity library must
//! reproduce all of them.
//!
//! Regenerate with:
//!     cargo test -p prover --test `ext4_vectors` -- --ignored --nocapture

use std::error::Error;
use std::path::{Path, PathBuf};

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, PrimeField64};
use prover::whir::{Challenge as EF, F};

/// Where checked-in vectors live, relative to the workspace root.
fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(
            || PathBuf::from("contracts/test/vectors"),
            |root| root.join("contracts/test/vectors"),
        )
}

/// Canonical limbs of an extension element, as decimal strings.
/// Canonical limbs of an extension element, index 0 is the constant term.
///
/// Explicitly converted to canonical: p3 serializes `MontyField31` in
/// Montgomery form because it is faster, so a `serde` dump of a field
/// element would carry Montgomery limbs. The Solidity library works in
/// canonical limbs, so the vectors must too, and the conversion has to be
/// visible here rather than assumed.
fn limbs(v: &EF) -> Vec<u64> {
    // Fully qualified: `EF` has a `BasedVectorSpace` impl over several
    // algebras, so the method is ambiguous without naming the base field.
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

fn f(b: u32) -> F {
    F::from_u32(b)
}

fn ef(a: u32, b: u32, c: u32, d: u32) -> EF {
    EF::new([f(a), f(b), f(c), f(d)])
}

#[test]
#[ignore = "regenerates vectors; run explicitly"]
fn emit_ext4_vectors() -> Result<(), Box<dyn Error>> {
    // The binomial nonresidue w: EF = F[x] / (x^4 - w). The Solidity
    // library hard-codes it, so it is pinned explicitly rather than
    // assumed.
    let x = EF::new([F::ZERO, F::ONE, F::ZERO, F::ZERO]);
    let w = x * x * x * x;
    let w_canonical = limbs(&w)[0];

    // A spread of operands: small, large, zero-containing, and ones that
    // exercise carries across limb boundaries in the packed representation.
    let operands: Vec<(u32, u32, u32, u32)> = vec![
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (0, 1, 0, 0),
        (7, 11, 13, 17),
        (19, 23, 29, 31),
        (2_130_706_432, 0, 0, 0), // p - 1
        (0, 2_130_706_432, 2_130_706_432, 2_130_706_432),
        (0x7fff_ffff, 0x4000_0000, 1, 0x1ff_ffff),
        (1_234_567_890, 987_654_321, 429_496_729, 777),
        (
            0x0f0f_0f0f,
            0x0f0f_0f0f,
            0x00ff_00ff,
            0xff00_ff00 % 2_130_706_433,
        ),
    ];

    let mut cases: Vec<serde_json::Value> = Vec::new();
    for &(a0, a1, a2, a3) in &operands {
        for &(b0, b1, b2, b3) in &operands {
            let a = ef(a0, a1, a2, a3);
            let b = ef(b0, b1, b2, b3);
            let mut case = serde_json::json!({
                "a": limbs(&a),
                "b": limbs(&b),
                "add": limbs(&(a + b)),
                "sub": limbs(&(a - b)),
                "mul": limbs(&(a * b)),
                "square": limbs(&(a * a)),
            });
            // Inverse only where it exists; zero has none.
            if let Some(inv) = a.try_inverse() {
                case.as_object_mut()
                    .expect("object")
                    .insert("inv".to_string(), serde_json::json!(limbs(&inv)));
            }
            cases.push(case);
        }
    }

    // Base-scalar multiplication and the w-multiply, both used by the
    // folding path.
    let mut base_cases: Vec<serde_json::Value> = Vec::new();
    for &(a0, a1, a2, a3) in &operands {
        let a = ef(a0, a1, a2, a3);
        for s in [0u32, 1, 2, 3, 2_130_706_432] {
            base_cases.push(serde_json::json!({
                "a": limbs(&a),
                "s": s,
                "out": limbs(&(a * EF::from(f(s)))),
            }));
        }
        base_cases.push(serde_json::json!({
            "a": limbs(&a),
            "s": "w",
            "out": limbs(&(a * w)),
        }));
    }

    let out = serde_json::json!({
        "note": "KoalaBear quartic extension vectors from p3; limbs are canonical decimal, index 0 is the constant term",
        "modulus": F::ORDER_U32.to_string(),
        "nonresidue_w": w_canonical,
        "degree": 4,
        "num_cases": cases.len(),
        "num_base_scalar_cases": base_cases.len(),
        "cases": cases,
        "base_scalar_cases": base_cases,
    });

    let dir = vectors_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("ext4_vectors.json");
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&out)?))?;
    println!("wrote {} ({} cases)", path.display(), cases.len());
    Ok(())
}
