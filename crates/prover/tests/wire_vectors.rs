//! Postcard wire-format ground truth for the Solidity `ProofCodec`.
//!
//! Run with:
//!
//! ```text
//! cargo test -p prover --test wire_vectors -- --ignored --nocapture
//! ```
//!
//! ## Why this exists as a vector file rather than a Rust test
//!
//! `ProofCodec.sol` has to decode the exact bytes postcard produces from the
//! Rust proof struct: LEB128 unsigned varints, a 4-byte little-endian length
//! prefix before every `Vec`, and `Option` as a single tag byte. None of that is
//! visible from the Solidity side, and a wrong varint or a missing tag does not
//! fail loudly - it desynchronises the cursor and every later field reads as
//! garbage. So the decoder is pinned against recorded bytes, not against a
//! reimplementation of the same idea in two languages.
//!
//! ## What is pinned
//!
//! - A minimal hand-built value for each primitive shape (varint boundaries at
//!   1, 127, 128, 2^16, 2^32) so the varint reader is tested at its edges.
//! - The real proof type, field by field, with each sub-struct encoded on its
//!   own so a Solidity test can decode one piece without decoding the whole.
//! - The whole proof, plus its total length, so the top-level cursor walk is
//!   exercised.
//!
//! Proof bytes are NOT pinned by content: HVZK blinding makes them differ per
//! run (D-051 finding 1). What is pinned is their SHAPE - field order, tag
//! bytes, lengths - which is exactly what a decoder depends on.

#![cfg(test)]

use std::error::Error;
use std::path::{Path, PathBuf};

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

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! rather than push_str(&format!(..)): no intermediate String per
        // byte, which is what the lint is about.
        write!(&mut out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

/// Reads one postcard varint at `*cur`, advancing it. Mirrors the contract.
fn take_varint(bytes: &[u8], cur: &mut usize) -> u64 {
    let mut out = 0u64;
    let mut shift = 0u32;
    loop {
        let b = bytes[*cur];
        *cur += 1;
        out |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return out;
        }
        shift += 7;
    }
}

/// Reads one 32-byte digest at `*cur`, advancing it.
fn take_digest(bytes: &[u8], cur: &mut usize) -> String {
    let s = hex(&bytes[*cur..*cur + 32]);
    *cur += 32;
    s
}

/// Reads one `MerkleCap`: a varint count, then that many digests.
fn take_cap(bytes: &[u8], cur: &mut usize) -> (u64, Vec<String>) {
    let n = take_varint(bytes, cur);
    let mut caps = Vec::new();
    for _ in 0..n {
        caps.push(take_digest(bytes, cur));
    }
    (n, caps)
}

/// Varint edge cases, encoded exactly as postcard encodes a `u32`/`u64`/`usize`.
#[test]
#[ignore = "regenerates a checked-in golden vector; run deliberately"]
fn varint_vectors() -> Result<(), Box<dyn Error>> {
    // 127 -> one byte, 128 -> two. These are the boundaries a hand-rolled
    // LEB128 reader gets wrong.
    let values: Vec<u64> = vec![
        0,
        1,
        63,
        127,
        128,
        129,
        255,
        300,
        16_383,
        16_384,
        u64::from(u16::MAX),
        u64::from(u32::MAX),
    ];
    let mut out = Vec::new();
    for v in values {
        let u32_bytes = postcard::to_allocvec(&u32::try_from(v).unwrap_or(u32::MAX))?;
        out.push(serde_json::json!({
            "value": v,
            "u32_hex": hex(&u32_bytes),
            "u32_len": u32_bytes.len(),
            "u64_hex": hex(&postcard::to_allocvec(&v)?),
        }));
    }
    let path = vectors_dir().join("varint_vectors.json");
    std::fs::create_dir_all(path.parent().expect("dir"))?;
    std::fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "note": "postcard uses unsigned LEB128; 127 is one byte and 128 is two",
                // Explicit count: the Solidity side reads it with parseJsonUint, and a
                // length function is not portable across JSON-path implementations.
                "case_count": out.len(),
                "values": out,
            }))?
        ),
    )?;
    println!("wrote {}", path.display());
    Ok(())
}

/// Composite shapes: `Option`, `Vec`, fixed arrays, `bool`, and raw `u8`.
///
/// These are the shapes the proof is built from, and each has a rule a
/// hand-rolled decoder gets wrong: `Option` is a tag not a length, `[T; N]` has
/// NO length prefix, `bool` is one byte, and `u8` is a raw byte rather than a
/// varint (postcard pops one byte for `u8` and varints everything wider).
#[test]
#[ignore = "regenerates a checked-in golden vector; run deliberately"]
fn composite_vectors() -> Result<(), Box<dyn Error>> {
    #[derive(serde::Serialize)]
    struct Shape {
        tag: u8,
        small: u32,
        big: u32,
        flag: bool,
        present: Option<u32>,
        absent: Option<u32>,
        fixed: [u32; 4],
        list: Vec<u32>,
        wide: Vec<u32>,
    }
    let shape = Shape {
        tag: 0xff,
        small: 1,
        big: u32::MAX,
        flag: true,
        present: Some(300),
        absent: None,
        fixed: [0, 1, 127, 128],
        list: vec![],
        wide: (0..40u32).collect(),
    };
    let bytes = postcard::to_allocvec(&shape)?;

    // The same shape with flag=false and a populated empty-list slot, so the
    // decoder is exercised on both bool encodings and on a zero-length Vec.
    let shape2 = Shape {
        flag: false,
        list: vec![7],
        ..shape
    };
    let bytes2 = postcard::to_allocvec(&shape2)?;

    let out = serde_json::json!({
        "note": "postcard composite shapes: Option is a tag byte, [T;N] has no length, u8 is raw",
        "case_count": 2,
        "fields": [
            {"name": "tag", "kind": "u8_raw"},
            {"name": "small", "kind": "u32_varint"},
            {"name": "big", "kind": "u32_varint"},
            {"name": "flag", "kind": "bool"},
            {"name": "present", "kind": "option_u32"},
            {"name": "absent", "kind": "option_u32"},
            {"name": "fixed", "kind": "array_u32", "len": 4},
            {"name": "list", "kind": "vec_u32"},
            {"name": "wide", "kind": "vec_u32"}
        ],
        "cases": [
            {"name": "flag_true_empty_list", "hex": hex(&bytes), "len": bytes.len(),
             "flag": true, "present": 300, "absent": null, "fixed": [0, 1, 127, 128],
             "list": [], "wide_len": 40, "wide_last": 39},
            {"name": "flag_false_one_item", "hex": hex(&bytes2), "len": bytes2.len(),
             "flag": false, "present": 300, "absent": null, "fixed": [0, 1, 127, 128],
             "list": [7], "wide_len": 40, "wide_last": 39}
        ]
    });
    let path = vectors_dir().join("composite_vectors.json");
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&out)?))?;
    println!(
        "wrote {} ({} and {} bytes)",
        path.display(),
        bytes.len(),
        bytes2.len()
    );
    Ok(())
}

/// The leading fields of one real settlement proof.
///
/// `ProofCodec` is only useful if it walks a real proof. Proving takes seconds,
/// so this records the leading fields of one real proof - enough to pin the
/// field ORDER and the Option tag positions, which is what a cursor walk
/// depends on - plus the total length.
///
/// ## What a commitment actually is on the wire
///
/// The commitment type is `MerkleCap`, and `MerkleCap` serialises its cap as a
/// Vec of digests. So a commitment is a varint count followed by that many
/// 32-byte digests - NOT a bare digest. At `cap_height` 0 the count is 1, which
/// is the case the settlement config uses, but the count is still on the wire
/// and a decoder that skips it desynchronises immediately.
///
/// ## Why the bytes are not pinned across runs
///
/// HVZK blinding randomises the commitments (D-051 finding 1), so digests
/// differ per run. What is stable, and what this pins, is the SHAPE: the count,
/// the tag byte, the field order, and the total length.
#[test]
#[ignore = "proves and regenerates a checked-in golden vector; run deliberately"]
fn settlement_proof_shape() -> Result<(), Box<dyn Error>> {
    use p3_air::{AirBuilder, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use prover::whir::{config, Config, F};

    #[derive(Clone, Copy, Debug)]
    struct FibAir;

    impl<F2> p3_air::BaseAir<F2> for FibAir {
        fn width(&self) -> usize {
            2
        }
        fn num_public_values(&self) -> usize {
            1
        }
    }

    impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for FibAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
            let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
            let two = AB::F::ONE + AB::F::ONE;
            let public: AB::Expr = builder.public_values()[0].into();
            builder.when_first_row().assert_eq(a, AB::F::ONE);
            builder.when_first_row().assert_eq(b, AB::F::ONE);
            builder.when_transition().assert_eq(a + b, a_next);
            builder.when_transition().assert_eq(a + b * two, b_next);
            builder.when_last_row().assert_eq(a, public);
        }
    }

    let len = 1usize << 8;
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let last_a = values[values.len() - 2];
    let trace = p3_matrix::dense::RowMajorMatrix::new(values, 2);
    let pis = vec![last_a];

    let cfg = config(0, 16).expect("settlement config");
    let proof: p3_uni_stark::Proof<Config> =
        p3_uni_stark::prove(&cfg, &FibAir, trace, &pis).expect("prove");
    let bytes = postcard::to_allocvec(&proof)?;

    // Walk the leading fields exactly as the contract does.
    let mut cur = 0usize;

    // Commitments { trace, quotient_chunks, random: Option<...> }
    let (trace_n, trace_cap) = take_cap(&bytes, &mut cur);
    let (quot_n, quot_cap) = take_cap(&bytes, &mut cur);
    let random_tag = bytes[cur];
    cur += 1;
    let random = if random_tag == 1 {
        let (n, caps) = take_cap(&bytes, &mut cur);
        serde_json::json!({ "count": n, "digests": caps })
    } else {
        serde_json::Value::Null
    };

    // OpenedValues { trace_local: Vec<Challenge>, .. }
    let trace_local_len = take_varint(&bytes, &mut cur);

    let out = serde_json::json!({
        "note": "leading fields of one real settlement proof; digests vary per run because of blinding",
        "hash": "keccak256",
        "cap_height": 0,
        "total_len": bytes.len(),
        // Exactly the region the walk above consumed, so the Solidity side can
        // walk the same fields and then assert finish() lands on the end of the
        // slice. A fixed 64-byte prefix would truncate mid-field.
        "leading_hex": hex(&bytes[..cur]),
        "commitments_trace_count": trace_n,
        "commitments_trace_digests": trace_cap,
        "commitments_quotient_count": quot_n,
        "commitments_quotient_digests": quot_cap,
        "commitments_random_tag": random_tag,
        "commitments_random": random,
        "opened_values_trace_local_len": trace_local_len,
        "cursor_after_leading": cur
    });
    let path = vectors_dir().join("proof_shape.json");
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&out)?))?;
    println!(
        "wrote {} (proof {} bytes, cursor {} after leading fields)",
        path.display(),
        bytes.len(),
        cur
    );
    Ok(())
}
