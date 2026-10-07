p = "crates/prover/src/wbnd.rs"
s = open(p).read()

# 1. Sink: pruned blob variant (bit 31 of count = pruned flag).
old = """    /// Packed ext elements (each a 64-hex-char string): byte count + raw bytes."""
new = """    /// v8 pruned sibling stream: like \`blob\`, but bit 31 of the byte count
    /// is the pruned flag. The contract restores per-query paths from this
    /// stream with the vendor frontier walk (one sibling per level per
    /// unique query index), so the count must equal unique_indices * depth
    /// * 32 - the decoder validates it in-band.
    fn blob_pruned(&mut self, bytes: &[u8]) {
        self.word(bytes.len() as u32 | 0x8000_0000);
        let mut i = 0;
        while i < bytes.len() {
            let mut buf = [0u8; 4];
            let n = 4usize.min(bytes.len() - i);
            buf[..n].copy_from_slice(&bytes[i..i + n]);
            self.word(u32::from_le_bytes(buf));
            i += 4;
        }
    }
    /// Packed ext elements (each a 64-hex-char string): byte count + raw bytes."""
assert s.count(old) == 1
s = s.replace(old, new)

# 2. impl signature: compact bool -> (compact, pruned).
old = """pub fn encode_bundle(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    encode_bundle_impl(j, jj, bin, false)
}"""
new = """pub fn encode_bundle(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    encode_bundle_impl(j, jj, bin, false, false)
}"""
assert s.count(old) == 1
s = s.replace(old, new)

old = """pub fn encode_bundle_v7(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    encode_bundle_impl(j, jj, bin, true)
}

fn encode_bundle_impl(j: &Value, jj: &Value, bin: &[u8], compact: bool) -> Vec<u8> {"""
new = """pub fn encode_bundle_v7(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    encode_bundle_impl(j, jj, bin, true, false)
}

/// v8: v7 plus PRUNED per-round Merkle paths. The round paths blob carries
/// the vendor frontier stream (shared siblings stored once) with bit 31 of
/// its byte count set; the contract restores one full path per query with
/// the same walk the prover ran (batch 42). The final-round blob stays
/// expanded - 7 KB, no sharing to exploit. CONFIG/STATEMENT unchanged.
#[must_use]
pub fn encode_bundle_v8(j: &Value, jj: &Value, bin: &[u8]) -> Vec<u8> {
    encode_bundle_impl(j, jj, bin, true, true)
}

fn encode_bundle_impl(
    j: &Value,
    jj: &Value,
    bin: &[u8],
    compact: bool,
    pruned: bool,
) -> Vec<u8> {"""
assert s.count(old) == 1
s = s.replace(old, new)

# 3. per-round paths blob site -> pruned when v8.
old = """            m.blob(&hex_to_bytes(rd["paths_hex"].as_str().unwrap()));"""
new = """            if pruned {
                m.blob_pruned(&hex_to_bytes(rd["pruned_hex"].as_str().unwrap()));
            } else {
                m.blob(&hex_to_bytes(rd["paths_hex"].as_str().unwrap()));
            }"""
assert s.count(old) == 1
s = s.replace(old, new)

# 4. header stamp.
old = """    out[4] = if compact { 7 } else { 5 };"""
new = """    out[4] = if pruned { 8 } else if compact { 7 } else { 5 };"""
assert s.count(old) == 1
s = s.replace(old, new)

# 5. v8 split (clone of v7 split).
old = """/// The WBND header: (magic ok, version, cfg words, prf words)."""
new = """/// The WBND v8 bundle with CONFIG excised: header ver=8, cfgWords=0, then
/// the compact PROOF (pruned round paths) + STATEMENT. Same split contract
/// as v6/v7: the caller ships the returned CONFIG to the chunk satellites
/// and pins its digest (identical CONFIG to v6/v7).
#[must_use]
pub fn encode_bundle_v8_split(j: &Value, jj: &Value, bin: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let full = encode_bundle_v8(j, jj, bin);
    let (_magic, _ver, cfgw, prfw) = crate::wbnd::header(&full);
    let cfg_bytes = full[16..16 + cfgw * 4].to_vec();
    let mut out = vec![0u8; 16];
    out[..4].copy_from_slice(b"WBND");
    out[4] = 8;
    out[8..12].copy_from_slice(&0u32.to_le_bytes());
    out[12..16].copy_from_slice(&(prfw as u32).to_le_bytes());
    out.extend_from_slice(&full[16 + cfgw * 4..]);
    (out, cfg_bytes)
}

/// The WBND header: (magic ok, version, cfg words, prf words)."""
assert s.count(old) == 1
s = s.replace(old, new)

open(p, "w").write(s)
print("v8 encoder patched")
