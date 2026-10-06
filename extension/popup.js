// popup.js - MV3 popup controller. Wires the DOM to wallet.js (wasm shim)
// and node-client.js. No crypto here; state machine only.
//
// State that must survive popup close: the sealed vault hex and node config
// (chrome.storage.local). The *password* and unlocked key material never
// persist - the popup is a short-lived document, and everything secret dies
// with it. Re-open = re-unlock. That is a feature, not an inconvenience.

'use strict';

import { loadWallet, WasmError, hexToBytes } from './wallet.js';
import { makeNodeClient } from './node-client.js';

const $ = (id) => document.getElementById(id);
const store = chrome.storage.local;

/** Live config for the node client (re-read per call). */
const state = { cfg: { baseUrl: '', token: '' }, vaultHex: null, identity: null, wallet: null };

const node = makeNodeClient(() => state.cfg);

function rand32() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function show(view) {
  for (const v of ['Vault', 'Send', 'Demo', 'Settings']) {
    $('view' + v).classList.toggle('hidden', v !== view);
    $('tab' + v).classList.toggle('active', v === view);
  }
}

function setMsg(el, text, ok = false) {
  el.textContent = text || '';
  el.classList.toggle('err', !ok);
  el.classList.toggle('out', ok);
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

async function boot() {
  const saved = await store.get(['vaultHex', 'cfg']);
  state.vaultHex = saved.vaultHex || null;
  state.cfg = saved.cfg || { baseUrl: 'http://127.0.0.1:3000', token: '' };
  $('setUrl').value = state.cfg.baseUrl;
  $('setTok').value = state.cfg.token;
  state.wallet = await loadWallet(await (await fetch(chrome.runtime.getURL('wallet_wasm.wasm'))).arrayBuffer());
  renderVault();
  try {
    const r = await node.roots();
    $('netBadge').textContent = '· node up';
    state.roots = r;
  } catch {
    $('netBadge').textContent = '· node down';
  }
}

function renderVault() {
  const open = state.identity !== null;
  $('vaultLocked').classList.toggle('hidden', open);
  $('vaultOpen').classList.toggle('hidden', !open);
  if (open) {
    $('pkd').textContent = state.identity.pk_d;
    $('vk').textContent = state.identity.verifying_key;
  }
}

// ---------------------------------------------------------------------------
// vault tab
// ---------------------------------------------------------------------------

async function createVault() {
  const p1 = $('pw1').value;
  if (p1.length < 8) return setMsg($('vaultMsg'), 'password: 8+ characters');
  if (p1 !== $('pw2').value) return setMsg($('vaultMsg'), 'passwords do not match');
  try {
    const hex = state.wallet.vaultCreate(p1);
    await store.set({ vaultHex: hex });
    state.vaultHex = hex;
    state.identity = state.wallet.pubkey(p1, hex);
    $('pw1').value = ''; $('pw2').value = '';
    setMsg($('vaultMsg'), '', true);
    renderVault();
  } catch (e) {
    setMsg($('vaultMsg'), String(e && e.message ? e.message : e));
  }
}

async function unlockExisting() {
  const file = $('unlockFile').files[0];
  if (!file) return setMsg($('vaultMsg'), 'choose a vault file first');
  const text = (await file.text()).trim();
  const hex = text.startsWith('{') ? JSON.parse(text).vault : text;
  try {
    hexToBytes(hex);
    state.identity = state.wallet.pubkey($('pw1').value, hex);
    state.vaultHex = hex;
    await store.set({ vaultHex: hex });
    $('pw1').value = '';
    setMsg($('vaultMsg'), '', true);
    renderVault();
  } catch (e) {
    state.identity = null;
    setMsg($('vaultMsg'), e instanceof WasmError && e.code === 1 ? 'wrong password' : String(e.message || e));
  }
}

function lock() {
  state.identity = null;
  renderVault();
}

function exportVault() {
  const blob = new Blob([JSON.stringify({ v: 1, vault: state.vaultHex }, null, 2)], {
    type: 'application/json',
  });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pq-vault.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------------------
// send tab
// ---------------------------------------------------------------------------

async function signAndSubmit() {
  if (!state.identity) return setMsg($('sendMsg'), 'unlock the vault first');
  const rho = $('sRho').value.trim();
  const psi = $('sPsi').value.trim();
  if (!/^[0-9a-f]{64}$/.test(rho) || !/^[0-9a-f]{64}$/.test(psi)) {
    return setMsg($('sendMsg'), 'rho and psi must be 64 hex chars (fresh random per note)');
  }
  if (!state.roots) return setMsg($('sendMsg'), 'fetch roots first');
  try {
    const out = state.wallet.noteCommit({
      value: Number($('sValue').value),
      rho,
      psi,
      pkD: state.identity.pk_d,
    });
    // The password is re-typed per signing session (pwSend): the popup never
    // persists or caches it, so "unlocked" identity display and the ability
    // to sign are deliberately separate states.
    const nf = state.wallet.noteNullifier($('pwSend').value, state.vaultHex, rho);
    const statement = {
      nullifiers: [nf],
      outputs: [out],
      root: state.roots.root,
      // root_after (D-088) is what the tree looks like after `out` is
      // appended. The manual send path is envelope-only - the node answers 501
      // (D-079) - so the true root_after is computed by the prover on the demo
      // path (/v1/demo/transfer), which proves against the sequencer's
      // pending tree. The field is present so the signature covers the full
      // canonical statement the node re-encodes.
      root_after: state.roots.root,
      nullifier_root_before: state.roots.nullifier_root,
      nullifier_root_after: state.roots.nullifier_root,
      fee: Number($('sFee').value),
    };
    const envelope = state.wallet.signTransfer($('pwSend').value, state.vaultHex, statement);
    const res = await node.submit(envelope);
    setMsg($('sendMsg'), res.admitted
      ? 'submitted and admitted'
      : 'envelope VERIFIED on the node (501 = admission deferred, D-083)', true);
    $('sendOut').textContent = JSON.stringify(envelope, null, 2);
  } catch (e) {
    setMsg($('sendMsg'), String(e.message || e));
  }
}

// ---------------------------------------------------------------------------
// demo + settings
// ---------------------------------------------------------------------------

async function runDemo() {
  try {
    const r = await node.demoTransfer(Number($('dIn').value), Number($('dVal').value), Number($('dFee').value));
    $('demoOut').textContent = JSON.stringify(r, null, 2);
    setMsg($('demoMsg'), 'demo transfer admitted', true);
  } catch (e) {
    setMsg($('demoMsg'), String(e.message || e));
  }
}

async function saveSettings() {
  state.cfg = { baseUrl: $('setUrl').value.trim(), token: $('setTok').value.trim() };
  await store.set({ cfg: state.cfg });
  setMsg($('setMsg'), 'saved', true);
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

$('tabVault').onclick = () => show('Vault');
$('tabSend').onclick = () => show('Send');
$('tabDemo').onclick = () => show('Demo');
$('tabSettings').onclick = () => show('Settings');
$('btnCreate').onclick = createVault;
$('btnUnlock').onclick = () => $('unlockFile').click();
$('unlockFile').onchange = unlockExisting;
$('btnLock').onclick = lock;
$('btnExport').onclick = exportVault;
$('btnFillRoots').onclick = async () => {
  try {
    state.roots = await node.roots();
    setMsg($('sendMsg'), 'roots: ' + state.roots.root.slice(0, 16) + '…', true);
  } catch (e) {
    setMsg($('sendMsg'), String(e.message || e));
  }
};
$('btnSignSend').onclick = signAndSubmit;
$('btnDemo').onclick = runDemo;
$('btnSave').onclick = saveSettings;

boot().catch((e) => setMsg($('vaultMsg'), 'boot failed: ' + String(e.message || e)));
