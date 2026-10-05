# PQ Shielded Wallet - MV3 browser extension

The wallet half of the post-quantum shielded-pool rollup demo. All crypto
runs in a Rust-compiled WebAssembly module (`wallet_wasm.wasm`, built from
`crates/wallet-wasm`) that shares the node's own crates - one implementation
of the vault format, the canonical signing message, and the SPHINCS+
envelope, so wallet and node cannot drift.

## What is inside

| file | role |
|---|---|
| `manifest.json` | MV3 manifest; CSP locked to `'self'`, host permissions localhost-only |
| `wallet_wasm.wasm` | the crypto core (build: `scripts/build_extension.sh`) |
| `wallet.js` | the wasm ABI shim (buffer arena, out buffer, error codes) |
| `node-client.js` | HTTP client for the rollup node API |
| `popup.html` / `popup.js` | the UI: Vault / Send / Demo / Settings tabs |
| `smoke.mjs` | Node-driven test of the real wasm artifact (`node extension/smoke.mjs`) |

## Setup (once)

1. **Build the wasm** (only if you changed the Rust):
   ```sh
   ./scripts/build_extension.sh   # builds + smoke-tests + copies here
   ```
   The committed artifact is current; skip this unless you edited
   `crates/wallet-wasm`.
2. **Start the node** (see `README.md` at the repo root, "Run the demo"):
   the node listens on `http://127.0.0.1:3000` by default.
3. **Issue a token** for the extension:
   ```sh
   cargo run -p node -- token --role submitter --ttl 86400
   ```
   (The Demo tab needs `--role admin` instead.)
4. **Load the extension**: chrome://extensions → Developer mode →
   "Load unpacked" → select this folder.
5. Open the popup → **Settings** → paste the node URL and token → Save.

## Using it

- **Vault tab** - create a vault (Argon2id + AES-256-GCM sealed; the password
  never leaves this device and is never stored), or unlock an exported
  `pq-vault.json`. Export gives you the sealed blob; it is useless without
  the password.
- **Send tab** - re-enter the password, set an output value plus fresh
  `rho`/`psi` (32 random bytes each - the "why" is in the shielded design:
  they are what makes the note unlinkable), Fetch roots, then Sign + submit.
  The node verifies your SPHINCS+ signature over the canonical message and
  answers **501**: envelope valid, remote proof admission deferred (D-083).
  A 501 here is a *success* signal for the wallet.
- **Demo tab** - the working end-to-end path today: the node proves a real
  shielded transfer with its fixture keys and settles it on L1 (Admin
  token). This is what `scripts/e2e_local.sh` automates.

## Security posture

- Password ≥ 8 chars; vault re-sealed with fresh salt/nonce on re-key; wrong
  password is cryptographically indistinguishable from corruption (AES-GCM
  auth tag), reported as `wrong password`.
- Secrets (`sk_d`, SPHINCS+ secret key) exist only inside a wasm call and
  are zeroized on return; input buffers zeroize on free.
- The popup persists only: the sealed vault, the node URL, and the token -
  all in `chrome.storage.local`, all useless to a file-theft attacker without
  the password / useless off the node origin.
- No network calls except the configured node origin; no remote code, no
  inline scripts (CSP enforced), no eval anywhere.
