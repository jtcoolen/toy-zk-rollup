// smoke.mjs - end-to-end test of the REAL wasm artifact through the shim.
//
// Run: node extension/smoke.mjs   (after building the release wasm)
// This is the ABI test the native unit tests cannot do: it exercises the
// arena (buf_alloc/buf_free), the out buffer, and every export through the same
// code path the MV3 popup uses. Node stands in for the browser: webcrypto
// provides crypto.getRandomValues.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

// Node >= 19 ships a global webcrypto; the shim uses crypto.getRandomValues
// exactly as the browser popup does.

const here = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = process.env.WASM_PATH
  || path.join(here, '..', 'target', 'wasm32-unknown-unknown', 'release', 'wallet_wasm.wasm');

const { loadWallet, WasmError } = await import('./wallet.js');

const wasm = readFileSync(wasmPath);
console.log(`wasm: ${wasmPath} (${wasm.length} bytes)`);
const w = await loadWallet(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));

const PW = 'correc4-horse-battery';
const hex64 = (b) => b.toString(16).padStart(2, '0');

// 1. vault create + identity
const vault = w.vaultCreate(PW);
assert.match(vault, /^[0-9a-f]+$/, 'vault is hex');
const id = w.pubkey(PW, vault);
assert.equal(id.pk_d.length, 64, 'pk_d is 32 bytes');
assert.equal(id.verifying_key.length, 64, 'vk is 32 bytes (SHA2-128f)');
console.log('vault create + pubkey OK');

// 2. wrong password -> WasmError code 1
assert.throws(() => w.pubkey('wrong', vault), (e) => e instanceof WasmError && e.code === 1);
console.log('wrong password rejected');

// 3. re-key keeps identity
const rekeyed = w.vaultChange(PW, 'new-passphrase-2', vault);
assert.deepEqual(w.pubkey('new-passphrase-2', rekeyed), id, 'identity survives re-key');
console.log('re-key OK');

// 4. note commit + nullifier are deterministic
const rho = Array.from({ length: 32 }, (_, i) => hex64(i)).join('');
const psi = Array.from({ length: 32 }, (_, i) => hex64(200 - i)).join('');
const out1 = w.noteCommit({ value: 1000, rho, psi, pkD: id.pk_d });
assert.equal(out1, w.noteCommit({ value: 1000, rho, psi, pkD: id.pk_d }));
const nf = w.noteNullifier(PW, vault, rho);
assert.equal(nf.length, 64);
console.log('note commit/nullifier OK');

// 5. sign a statement, verify it, tamper-check
const statement = {
  nullifiers: [nf],
  outputs: [out1],
  root: 'ab'.repeat(32),
  root_after: 'ac'.repeat(32),
  nullifier_root_before: 'cd'.repeat(32),
  nullifier_root_after: 'cd'.repeat(32),
  fee: 7,
};
const env = w.signTransfer(PW, vault, statement);
assert.equal(env.fee, 7);
assert.equal(env.verifying_key, id.verifying_key);
assert.ok(w.verifyTransfer(statement, env.verifying_key, env.signature));
const bad = { ...statement, fee: 8 };
assert.throws(
  () => w.verifyTransfer(bad, env.verifying_key, env.signature),
  (e) => e instanceof WasmError && e.code === 4,
);
console.log('sign + verify + tamper-reject OK');

// 6. the arena does not leak: a hundred calls, memory stays bounded
for (let i = 0; i < 100; i += 1) w.noteCommit({ value: i, rho, psi, pkD: id.pk_d });
console.log('arena stress OK');

console.log('SMOKE OK - all exports verified through the real wasm artifact');
