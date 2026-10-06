// e2e_wallet.mjs - the wallet's full loop against a live node, headless.
//
// This is the extension's own code - extension/wallet.js (the real wasm, the
// same arena path the MV3 popup uses) and extension/node-client.js (the same
// fetch client the popup uses) - driven without a browser. The popup adds
// chrome.storage and DOM around exactly these calls; everything that decides
// whether a transfer is accepted lives in this path.
//
// Failure paths covered (D-090):
//   * bad-sig      - fee tampered after signing -> 422 envelope rejected
//   * stale-root   - envelope witnessed against a root the node does not have
//                    -> 422 state rejected (twice: bogus, then superseded)
//   * double-spend - envelope re-spends a nullifier a block already settled
//                    (the nullifier arrives from the node's own demo-transfer
//                    response, so it is a genuinely spent nullifier) -> 422
//   * happy        - signed envelope against current roots -> 501 (verified;
//                    proof admission deferred per D-079)
//
// Env: NODE_URL, ADMIN_TOKEN, SUBMIT_TOKEN, READ_TOKEN.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

import { loadWallet } from '../extension/wallet.js';
import { makeNodeClient, NodeError } from '../extension/node-client.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const NODE_URL = (process.env.NODE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const wasmPath = process.env.WASM_PATH
  || path.join(here, '..', 'extension', 'wallet_wasm.wasm');

const log = (...a) => console.log('[wallet-e2e]', ...a);

async function expectRevert(p, status, needle) {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof NodeError, `expected NodeError, got: ${e}`);
    assert.equal(e.status, status, `status: ${e.body}`);
    assert.ok(e.body.includes(needle), `body ${JSON.stringify(e.body)} lacks ${JSON.stringify(needle)}`);
    return e.body;
  }
  assert.fail(`expected rejection ${status} containing ${JSON.stringify(needle)}`);
}

const wasm = readFileSync(wasmPath);
log(`wasm: ${wasm.length} bytes`);
const wallet = await loadWallet(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
log('wasm loaded through the popup code path');

const submit = makeNodeClient(() => ({ baseUrl: NODE_URL, token: process.env.SUBMIT_TOKEN }));
const admin = makeNodeClient(() => ({ baseUrl: NODE_URL, token: process.env.ADMIN_TOKEN }));

// The admin client has no produce verb (the popup never produces); the block
// driver endpoint is a plain authenticated POST, so call it directly.
async function produceBlock() {
  const res = await fetch(NODE_URL + '/v1/block/produce', {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.ADMIN_TOKEN}` },
  });
  const text = await res.text();
  if (!res.ok) throw new NodeError(res.status, text);
  return JSON.parse(text);
}

// --- vault: the wallet's identity, password never leaves this scope ---------
const PW = 'correct-horse-battery-staple';
const vault = wallet.vaultCreate(PW);
const id = wallet.pubkey(PW, vault);
assert.equal(id.pk_d.length, 64);
log('vault created, identity:', id.pk_d.slice(0, 16) + '...');

const hex64 = () =>
  Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');

/** Build + sign a wallet envelope against the given roots. The nullifier is
 * our own vault's over fresh randomness unless one is supplied (the
 * double-spend case re-sends a nullifier the node has already settled). */
function signEnvelope(roots, { fee = 10, nullifier } = {}) {
  const rho = hex64();
  const psi = hex64();
  const out = wallet.noteCommit({ value: 900, rho, psi, pkD: id.pk_d });
  const nf = nullifier ?? wallet.noteNullifier(PW, vault, rho);
  const statement = {
    nullifiers: [nf],
    outputs: [out],
    root: roots.root,
    root_after: roots.root,
    nullifier_root_before: roots.nullifier_root,
    nullifier_root_after: roots.nullifier_root,
    fee,
  };
  return wallet.signTransfer(PW, vault, statement);
}

/** The statement part of an envelope, for local verification. */
const statementOf = (e) => ({
  nullifiers: e.nullifiers, outputs: e.outputs, root: e.root,
  root_after: e.root_after, nullifier_root_before: e.nullifier_root_before,
  nullifier_root_after: e.nullifier_root_after, fee: e.fee,
});

// --- 1. happy path: a signed, state-plausible envelope reaches 501 ----------
const roots = await submit.roots();
log('roots:', roots.root.slice(0, 16) + '...');
const env = signEnvelope(roots);
// The wallet checks its own signature before ever trusting it outbound.
assert.ok(wallet.verifyTransfer(statementOf(env), env.verifying_key, env.signature));
const res = await submit.submit(env);
assert.equal(res.verified, true, '501 = envelope verified on the node');
log('happy path: envelope verified by the node (501)');

// --- 2. bad-sig: tamper with the fee after signing --------------------------
const tampered = { ...env, fee: env.fee + 1 };
const badBody = await expectRevert(submit.submit(tampered), 422, 'envelope rejected');
assert.ok(badBody.includes('signature'), `tamper reason: ${badBody}`);
log('bad-sig: tampered fee rejected with 422');

// --- 3. stale-root: a witnessed root the node does not have -----------------
const bogus = signEnvelope({ root: '00'.repeat(32), nullifier_root: roots.nullifier_root });
const staleBody = await expectRevert(submit.submit(bogus), 422, 'state rejected');
assert.ok(staleBody.includes('witnessed against root'), `stale reason: ${staleBody}`);
log('stale-root: bogus root rejected with 422');

// --- 4. real spend: demo transfer + block -> a genuinely spent nullifier ----
log('demo transfer (proves a child transfer - a minute or two)...');
const demo = await admin.demoTransfer(0, 900, 100);
const spentNf = demo.nullifier;
log('demo transfer admitted, nullifier', spentNf.slice(0, 16) + '...');
log('producing a block (proves the block circuit - a few minutes)...');
const block = await produceBlock();
log('block', block.block_number, 'with', block.num_transfers, 'transfer(s)');
const roots1 = await submit.roots();
assert.notEqual(roots1.root, roots.root, 'committed root advanced after the block');

// --- 5. double-spend: re-spend the nullifier the block just settled ---------
const replay = signEnvelope(roots1, { nullifier: spentNf });
const dsBody = await expectRevert(submit.submit(replay), 422, 'state rejected');
assert.ok(dsBody.includes('already spent'), `double-spend reason: ${dsBody}`);
log('double-spend: settled nullifier re-spend rejected with 422');

// --- 6. stale-root for real: the pre-block roots are now superseded ---------
const old = signEnvelope(roots);
const stale2 = await expectRevert(submit.submit(old), 422, 'state rejected');
assert.ok(stale2.includes('witnessed against root'), `stale-after-block: ${stale2}`);
log('stale-root: pre-block roots now rejected with 422');

// --- 7. happy path again on the new state ------------------------------------
const env2 = signEnvelope(roots1);
const res2 = await submit.submit(env2);
assert.equal(res2.verified, true);
log('happy path on new state: verified (501)');

// --- 8. the rejection counters moved -----------------------------------------
const metrics = await (await fetch(NODE_URL + '/metrics', {
  headers: { authorization: `Bearer ${process.env.READ_TOKEN}` },
})).text();
assert.match(metrics, /node_tx_rejections_total\{reason="envelope"\} [1-9]/);
assert.match(metrics, /node_tx_rejections_total\{reason="state"\} [2-9][0-9]*\b/);
log('metrics: envelope + state rejections counted');

log('WALLET E2E GREEN: happy, bad-sig, stale-root (x2), double-spend all behaved');
