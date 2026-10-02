#[test]
fn probe_sample_and_monty() {
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::{PrimeCharacteristicRing, PrimeField32, PrimeField64};
    use prover::whir::F;
    use prover::transcript_trace::TracedTranscript;

    for v in [0xdeadbeefu32, 1, 2, 0xffff] {
        let x = F::from_u32(v);
        let u = x.to_unique_u32();
        let le = u.to_le_bytes();
        println!(
            "OBS {v:#x} canon {:#x} monty {:#010x} LE {:02x}{:02x}{:02x}{:02x}",
            x.as_canonical_u64(),
            u,
            le[0],
            le[1],
            le[2],
            le[3]
        );
    }

    let mut t = TracedTranscript::<F>::new();
    t.challenger.observe(F::from_u32(0xdead_beef));
    let alpha: F = t.challenger.sample();
    println!("ALPHA canon {:#x} ({}) monty {:#010x}",
        alpha.as_canonical_u64(), alpha.as_canonical_u64(), alpha.to_unique_u32());
    let raw: [u8; 4] = [0x22, 0x63, 0x54, 0x73];
    let word = u32::from_le_bytes(raw);
    println!("raw trace word {word:#010x} masked {:#010x}", word & 0x7fff_ffff);
    let _ = t.trace();
}
