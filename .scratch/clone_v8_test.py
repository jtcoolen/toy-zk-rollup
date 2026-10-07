p = "crates/prover/tests/recursion_chain.rs"
s = open(p).read()
i = s.index("fn export_chain_bundle_v7()")
j = s.rindex("/// D-092 v7 export", 0, i)
k = s.index(chr(10) + "}" + chr(10), i) + 3
body = s[j:k]
v8 = body.replace("export_chain_bundle_v7", "export_chain_bundle_v8")
v8 = v8.replace("encode_bundle_v7_split", "encode_bundle_v8_split")
v8 = v8.replace("bundle_v7", "bundle_v8").replace("config_v7", "config_v8").replace("chunk_v7", "chunk_v8").replace("sidecar_v7", "sidecar_v8")
v8 = v8.replace('"v7 bundle', '"v8 bundle')
v8 = v8.replace('write v7', 'write v8').replace('write sidecar v7', 'write sidecar v8')
v8 = v8.replace("D-092 v7 export: same chain, compact PROOF ext limbs (16 B/element,", "D-092 v8 export: same chain, compact ext limbs + PRUNED round paths,")
v8 = v8.replace("/// batch 41). Writes its OWN", "/// (batch 42). Writes its OWN")
s = s[:k] + chr(10) + v8 + s[k:]
open(p, "w").write(s)
print("cloned")
