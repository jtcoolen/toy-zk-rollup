//! The WBND encoder must be byte-identical to the JS generators that produced
//! the committed artifacts: same flat sidecar (modulo the description string)
//! and byte-equal bundle. If this test fails, the Rust encoder and the Solidity
//! decoder's producer have drifted - fix the encoder, never the vectors.

use prover::wbnd;
use serde_json::Value;

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors")
}

fn read_vec(name: &str) -> Vec<u8> {
    std::fs::read(vectors_dir().join(name)).expect("committed vector")
}

fn check_shape(src: &str, flat: &str, bundle: &str) {
    let jj: Value = serde_json::from_slice(&read_vec(src)).expect("composed vectors json");
    let bin = read_vec(&src.replace(".json", ".bin"));
    let committed_flat: Value = serde_json::from_slice(&read_vec(flat)).expect("committed flat");
    let committed_bundle = read_vec(bundle);

    let mine_flat = wbnd::flat_from_vectors(&jj);
    // Semantic equality on everything the bundle consumes; the description
    // string is allowed to differ. Compare key-by-key so a mismatch names the
    // key instead of dumping a megabyte of numbers.
    for key in ["round_starts", "num_rounds"] {
        assert_eq!(mine_flat[key], committed_flat[key], "{src}: {key}");
    }
    let mine_rounds = mine_flat["rounds"].as_array().unwrap();
    let comm_rounds = committed_flat["rounds"].as_array().unwrap();
    assert_eq!(mine_rounds.len(), comm_rounds.len(), "{src}: round count");
    for (r, (mr, cr)) in mine_rounds.iter().zip(comm_rounds.iter()).enumerate() {
        let mk = mr.as_object().unwrap();
        let ck = cr.as_object().unwrap();
        assert_eq!(mk.len(), ck.len(), "round {r}: key count");
        for (k, mv) in mk {
            let cv = ck
                .get(k)
                .unwrap_or_else(|| panic!("{src}: round {r} missing key {k}"));
            if mv != cv {
                let brief = |v: &Value| {
                    let s = v.to_string();
                    if s.len() > 160 {
                        format!("{}...", &s[..160])
                    } else {
                        s
                    }
                };
                panic!(
                    "{src}: round {r} key {k}\n  mine: {}\n  comm: {}",
                    brief(mv),
                    brief(cv)
                );
            }
        }
    }

    let mine_bundle = wbnd::encode_bundle(&mine_flat, &jj, &bin);
    assert_eq!(
        mine_bundle.len(),
        committed_bundle.len(),
        "{src}: bundle length (mine {})",
        mine_bundle.len()
    );
    if mine_bundle != committed_bundle {
        let at = mine_bundle
            .iter()
            .zip(committed_bundle.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "{src}: bundle bytes differ at {at:#x}: mine {:?}, committed {:?}",
            &mine_bundle[at..at + 8],
            &committed_bundle[at..at + 8]
        );
    }
}

#[test]
fn wbnd_encoder_matches_js_fib_artifact() {
    check_shape(
        "composed_vectors.json",
        "composed_flat.json",
        "composed_bundle.bin",
    );
}

#[test]
fn wbnd_encoder_matches_js_block_artifact() {
    check_shape(
        "block_composed_vectors.json",
        "block_composed_flat.json",
        "block_composed_bundle.bin",
    );
}
