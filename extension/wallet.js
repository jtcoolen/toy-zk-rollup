// wallet.js - the JavaScript side of the wallet-wasm ABI.
//
// The Rust core (crates/wallet-wasm) exports a flat C ABI: inputs are
// written into linear memory via buf_alloc()/memory.buffer, results are read
// from a single out buffer. (Names carry a buf_ prefix on purpose: a bare
// `free` export collides with dlmalloc's C symbol in the linked module.) This shim hides all of that and hands the popup
// a promise-based API whose methods mirror the Rust exports one-for-one.
//
// Security notes:
// * No crypto happens here. This file moves bytes; every decision (KDF,
//   cipher, signature, canonical encoding) is made inside the audited Rust
//   module. That is deliberate: hand-rolled JS crypto has already failed
//   this project three times.
// * Entropy comes from crypto.getRandomValues (the browser CSPRNG) and is
//   fed to the wasm per call; the module holds no ambient randomness.
// * memory.buffer can be detached when the wasm heap grows, so it is read
//   fresh on every access - never cached.
// * Vault bytes are kept as hex strings; the popup stores them via
//   chrome.storage.local. The vault itself is Argon2id + AES-256-GCM sealed,
//   so storage at rest is ciphertext.

'use strict';

/** Error codes mirrored from crates/wallet-wasm/src/lib.rs. */
export const ERR = Object.freeze({
  WRONG_PASSWORD: 1,
  BAD_INPUT: 2,
  ENTROPY: 3,
  SIGNATURE: 4,
  TOO_LARGE: 5,
  ENTROPY_FAILED: 6,
  INTERNAL: 7,
});

/** A wasm call failed: code is the ERR_* value, message came from the module. */
export class WasmError extends Error {
  constructor(code, message) {
    super(message || `wasm call failed (code ${code})`);
    this.name = 'WasmError';
    this.code = code;
  }
}

const hexRe = /^[0-9a-fA-F]*$/;

/** Lowercase hex -> Uint8Array, rejecting anything else. */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !hexRe.test(hex)) {
    throw new TypeError('expected lowercase hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Uint8Array -> lowercase hex. */
export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Instantiate the module and return the wallet API.
 *
 * @param {ArrayBuffer|Response|WebAssembly.Module} source wasm bytes, a
 *   fetch Response, or a pre-compiled module. The extension passes bytes it
 *   fetched from its own chrome-extension:// URL - never a remote download.
 */
export async function loadWallet(source) {
  const module =
    source instanceof WebAssembly.Module
      ? source
      : (await WebAssembly.instantiate(await asBytes(source))).instance.exports;
  return makeApi(module);
}

async function asBytes(source) {
  if (source instanceof ArrayBuffer) return source;
  if (typeof Response !== 'undefined' && source instanceof Response) {
    return source.arrayBuffer();
  }
  throw new TypeError('loadWallet: expected ArrayBuffer, Response, or Module');
}

/**
 * Build the API over an instantiated export object. Split out from
 * loadWallet so tests can drive it with any WebAssembly exports object.
 */
export function makeApi(exports) {
  const { memory } = exports;

  const view = () => new Uint8Array(memory.buffer);

  /** Copy bytes in, call fn with (ptr,len) pairs, copy the out buffer back,
   * free everything. Always frees, even when fn throws. */
  function call(fn, ...inputs) {
    const ptrs = [];
    try {
      const args = [];
      for (const input of inputs) {
        const [ptr, len] = put(input);
        ptrs.push(ptr);
        args.push(ptr, len);
      }
      const code = fn(...args);
      const outLen = exports.out_len();
      const out = view().slice(exports.out_ptr(), exports.out_ptr() + outLen);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(out);
      if (code !== 0) {
        throw new WasmError(code, text);
      }
      return { bytes: out, text };
    } finally {
      for (const ptr of ptrs) exports.buf_free(ptr);
      exports.free_out();
    }
  }

  /** Write bytes into linear memory, returning [ptr, len]; caller frees. */
  function put(input) {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    const ptr = exports.buf_alloc(bytes.length);
    view().set(bytes, ptr);
    return [ptr, bytes.length];
  }

  /** 32 bytes of browser CSPRNG entropy, as the module requires. */
  function entropy() {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    return b;
  }

return {
    /** Create a fresh vault; returns the sealed vault bytes as hex. */
    vaultCreate(password) {
      return bytesToHex(call(exports.vault_create, password, entropy()).bytes);
    },

    /** Re-key a vault under a new password; returns the new vault hex. */
    vaultChange(oldPassword, newPassword, vaultHex) {
      return bytesToHex(
        call(exports.vault_change, oldPassword, newPassword, entropy(), hexToBytes(vaultHex)).bytes,
      );
    },

    /** The vault's public identity: {pk_d, verifying_key} (hex fields). */
    pubkey(password, vaultHex) {
      return JSON.parse(call(exports.wallet_pubkey, password, hexToBytes(vaultHex)).text);
    },

    /**
     * Sign a transfer statement. `statement` is the plain object the node's
     * TransferWire expects minus the envelope: {nullifiers, outputs, root,
     * nullifier_root_before, nullifier_root_after, fee}. Returns the full
     * POST body as an object (statement fields + verifying_key + signature).
     */
    signTransfer(password, vaultHex, statement) {
      const json = JSON.stringify(statement);
      return JSON.parse(call(exports.sign_transfer, password, hexToBytes(vaultHex), json).text);
    },

    /** Verify an envelope locally before trusting it: throws WasmError on a
     * bad signature (code 4). Returns true on success. */
    verifyTransfer(statement, verifyingKeyHex, signatureHex) {
      call(
        exports.verify_transfer,
        JSON.stringify(statement),
        verifyingKeyHex,
        signatureHex,
      );
      return true;
    },

    /** Note commitment under the Keccak hasher: {value, rho, psi, pkD} hex.
     * `value` is a JS number (u64 on the wasm side); the rest are hex strings. */
    noteCommit({ value, rho, psi, pkD }) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError('note value must be a non-negative safe integer');
      }
      const rp = put(rho);
      const pp = put(psi);
      const kp = put(pkD);
      try {
        const code = exports.note_commit(BigInt(value), rp[0], rp[1], pp[0], pp[1], kp[0], kp[1]);
        const outLen = exports.out_len();
        const out = view().slice(exports.out_ptr(), exports.out_ptr() + outLen);
        const text = new TextDecoder().decode(out);
        if (code !== 0) throw new WasmError(code, text);
        return text;
      } finally {
        exports.buf_free(rp[0]);
        exports.buf_free(pp[0]);
        exports.buf_free(kp[0]);
        exports.free_out();
      }
    },

    /** Nullifier for a note owned by this vault, under SHA3-256. */
    noteNullifier(password, vaultHex, rhoHex) {
      return call(exports.note_nullifier, password, hexToBytes(vaultHex), rhoHex).text;
    },
  };
}
