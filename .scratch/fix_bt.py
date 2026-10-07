p='crates/prover/src/wbnd.rs'
s=open(p).read()
s=s.replace('like \\`blob\\`','like `blob`')
open(p,'w').write(s)
print('ok')
