# 13 - Wallet: MV3 extension, PQ custody, good UX

Type: prototype
Status: open
Blocked by: 06

## Question

What does the wallet look like, and where do post-quantum secrets live in a browser
extension that has no trusted execution environment?

## UX requirements

- MetaMask-shaped: install → create/restore → address → receive → send → activity.
- **8KB PQ signatures must not be visible pain.** They are a background detail, not a
  user-facing artifact.
- Key restore from a mnemonic must work for SPHINCS+ (seed → deterministic key tree).
- Show balance, shielded vs transparent, and a clear "why is this slow" affordance
  during proving.

## The custody problem (the real decision)

MV3 has no secure enclave. A SPHINCS+ signing key in a browser is exposed to XSS and
to the extension host. Options:

1. **WebCrypto + PBKDF2/Argon2-wrapped key in `storage.local`.** Simple, standard,
   but SPHINCS+ is not a WebCrypto algorithm — needs WASM.
2. **WASM module (`slh-dsa` compiled to wasm32) + WebCrypto-wrapped key material.**
   The PQ math runs in WASM; the wrapping/derivation uses WebCrypto. Standard
   primitives, no custom crypto.
3. **Hardware-backed (WebAuthn / secure enclave).** Best security, worst compatibility.

**Leaning: option 2.** WASM for the PQ primitive, WebCrypto for wrapping. Keeps all
actual cryptography in vetted libraries and confines our own code to plumbing.

## State of this ticket

Prototype the UI flow and the custody boundary. The proving client (does the wallet
prove locally or delegate to a node?) is fog until the proving cost is known.
