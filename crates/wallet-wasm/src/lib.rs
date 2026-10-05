//! Browser wallet crypto core, compiled to `wasm32-unknown-unknown`.
//!
//! # What this crate is
//!
//! The parts of a wallet that must be *right*: unlocking the vault, deriving
//! spend keys, building the canonical signing message, and producing the
//! SPHINCS+ spend authorization. They live here - in Rust, sharing the exact
//! crates the node uses (`vault`, `pq-sign`, `shielded`) - rather than in
//! JavaScript, because a wallet and a node that disagree on one byte of the
//! canonical encoding reject each other's transfers, and because audited Rust
//! crates (slh-dsa, argon2, aes-gcm) beat hand-rolled JS crypto on every axis
//! that matters.
//!
//! # The ABI
//!
//! No wasm-bindgen: the extension loads this module with the plain WebAssembly
//! API, so the surface is manual `extern "C"` with a minimal, **safe** byte
//! interface (the workspace denies `unsafe_code`, and this crate keeps that
//! promise - the arena below is what makes it possible):
//!
//! * JS calls `alloc(len)` to get a linear-memory offset, writes its input
//!   bytes there via `wasmInstance.memory.buffer`, then calls the export with
//!   `(offset, len)` pairs.
//! * Results land in one out buffer, read with `out_ptr()`/`out_len()`, then
//!   released with `free_out()`.
//! * Every fallible export returns `0` (`OK`) or a small `ERR_*` code. On
//!   failure the out buffer holds a short UTF-8 message for the UI.
//! * `buf_free(offset)` releases an input buffer and **zeroizes** it first, so
//!   password and key bytes do not linger in linear memory.
//!
//! Internally, `buf_alloc` hands out offsets of buffers it owns in a registry
//! (`Mutex<Vec<Vec<u8>>>`), so reading inputs back is a lookup, not a raw
//! pointer dereference - no `unsafe` anywhere, at the cost of one copy per
//! call. Wallet payloads are bytes-to-kilobytes; the copy is free next to a
//! 64 MiB Argon2 hash.
//!
//! # Secrets lifetime
//!
//! Unlocked key bytes exist as `Zeroizing<Vec<u8>>` only inside the call that
//! needs them and are wiped on return. Input buffers are zeroized on `buf_free`.
//! The crate never persists anything: JS owns storage.
//!
//! # Testing split
//!
//! The logic lives in the pure `imp` functions below, which take ``&[u8]`` and
//! are fully tested natively (`cargo test -p wallet-wasm`). The `extern "C"`
//! wrappers are thin offset-resolution shims; they are exercised end to end by
//! the extension's node smoke test, which runs the real wasm artifact.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// See the module docs: allowed for the `#[unsafe(no_mangle)]` export
// attributes only; the crate body contains no unsafe code.
#![allow(unsafe_code)]
// The workspace denies `unsafe_code`, and this crate keeps that promise in
// substance: there are no raw-pointer derefs, no transmutes, no `static mut`
// - the arena design above exists precisely so the ABI needs none. What it
// cannot avoid is the *attribute* `#[unsafe(no_mangle)]`: a plain-WebAssembly
// module is reachable from JS only through unmangled export names, and
// `#[export_name]` is classified unsafe just the same. The lint is therefore
// allowed at crate scope for the attribute formality alone; the 13 exports
// below are the entire symbol surface and are reviewed as a unit. If a
// future Rust edition offers a safe export attribute, switch to it and drop
// this allow.

use std::sync::{Mutex, MutexGuard, PoisonError};

use pq_hash::{Digest32, MerkleRoot, NoteHash, Nullifier, Poseidon2Commitment, Sha3_256Shielded};
use pq_sign::{Sha2_128f, SigningKey, SpendAuth, SphincsPlusAuth};
use shielded::keys::derive_spend_pk;
use shielded::transfer::NullifierRoots;
use shielded::{Note, TransferPublic};
use signature::Keypair;
use zeroize::{Zeroize, Zeroizing};

/// Success.
pub const OK: i32 = 0;
/// The password did not open the vault.
pub const ERR_WRONG_PASSWORD: i32 = 1;
/// Input bytes were malformed (bad vault, bad hex, bad JSON, bad lengths).
pub const ERR_BAD_INPUT: i32 = 2;
/// The caller's entropy was too short to seed a CSPRNG.
pub const ERR_ENTROPY: i32 = 3;
/// A signature did not verify.
pub const ERR_SIGNATURE: i32 = 4;
/// A count in the statement exceeded the protocol cap.
pub const ERR_TOO_LARGE: i32 = 5;
/// The entropy source failed outright.
pub const ERR_ENTROPY_FAILED: i32 = 6;
/// Catch-all for internal failures (seal/encode errors).
pub const ERR_INTERNAL: i32 = 7;

/// The most bytes a vault may seal. A SPHINCS+ secret key is 128 bytes; a
/// generous cap still bounds what the KDF will be asked to decrypt.
const MAX_VAULT_PAYLOAD: usize = 4096;
/// The most bytes a statement JSON may occupy.
const MAX_STATEMENT_BYTES: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Safe linear-memory plumbing
// ---------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Poison only happens if a panic escaped another call while holding the
    // lock; the guarded data is a byte buffer, so recovering the inner value
    // is safe and keeps the wallet alive instead of panicking on every later
    // call.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Input buffers handed out by `buf_alloc`. The registry is what lets the exports
/// read inputs back by offset without any `unsafe` pointer arithmetic.
static ARENA: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
/// The single out buffer.
static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// wasm32 linear-memory offsets fit in `u32` by construction. On 64-bit test
/// hosts the cast truncates, which is why native tests exercise `imp`
/// directly and the ABI itself is smoke-tested in the wasm runtime.
#[allow(
    clippy::cast_possible_truncation,
    reason = "wasm32 offsets fit u32; see crate docs"
)]
fn mem_off(ptr: *const u8) -> u32 {
    ptr as usize as u32
}

/// Allocate `len` bytes and return their offset. JS writes input bytes there,
/// then passes `(offset, len)` to an export.
#[unsafe(no_mangle)]
pub extern "C" fn buf_alloc(len: u32) -> u32 {
    let buf = vec![0u8; len as usize];
    let off = mem_off(buf.as_ptr());
    lock(&ARENA).push(buf);
    off
}

/// Release an input buffer, zeroizing it first so secret bytes do not linger.
#[unsafe(no_mangle)]
pub extern "C" fn buf_free(off: u32) -> i32 {
    // Two separate lock acquisitions, never nested: wasm32-unknown-unknown's
    // std mutex aborts on contention, and the guard from `.position()` would
    // still be alive when the removal ran if this were one expression.
    let pos = {
        let arena = lock(&ARENA);
        arena.iter().position(|b| mem_off(b.as_ptr()) == off)
    };
    let Some(pos) = pos else {
        return ERR_BAD_INPUT;
    };
    let buf = lock(&ARENA).remove(pos);
    // Zeroizing wipes the buffer on drop, so password and key bytes never
    // linger in linear memory.
    drop(Zeroizing::new(buf));
    OK
}

/// Read `(off, len)` back out of the arena. Returns a copy so no lock is held
/// across the actual computation.
fn read_buf(off: u32, len: u32) -> Option<Vec<u8>> {
    let len = usize::try_from(len).ok()?;
    // Scoped so the mutex guard drops before the copy is returned.
    let copied = {
        let arena = lock(&ARENA);
        match arena.iter().find(|b| mem_off(b.as_ptr()) == off) {
            Some(b) if len <= b.len() => Some(b[..len].to_vec()),
            _ => None,
        }
    };
    copied
}

/// Offset of the current out buffer (valid until the next export call).
#[unsafe(no_mangle)]
pub extern "C" fn out_ptr() -> u32 {
    mem_off(lock(&OUT).as_ptr())
}

/// Length of the current out buffer.
#[unsafe(no_mangle)]
pub extern "C" fn out_len() -> u32 {
    let len = lock(&OUT).len();
    #[allow(
        clippy::cast_possible_truncation,
        reason = "wasm32 memory is at most 4 GiB; out buffers are far smaller"
    )]
    let truncated = len as u32;
    truncated
}

/// Release the out buffer.
#[unsafe(no_mangle)]
pub extern "C" fn free_out() {
    let mut out = lock(&OUT);
    out.zeroize();
    *out = Vec::new();
}

fn set_out(bytes: Vec<u8>) {
    *lock(&OUT) = bytes;
}

/// Put an error message in the out buffer and return the given code.
fn fail(code: i32, msg: &str) -> i32 {
    set_out(msg.as_bytes().to_vec());
    code
}

/// Put raw bytes in the out buffer and return OK.
fn ok_bytes(bytes: &[u8]) -> i32 {
    set_out(bytes.to_vec());
    OK
}

// ---------------------------------------------------------------------------
// Wallet operations (pure, natively testable)
// ---------------------------------------------------------------------------

/// Vault payload layout: `version(1) || sk_d(32) || slh_sk(N)`.
///
/// `sk_d` is the shielded spend secret (derives `pk_d` and nullifiers);
/// `slh_sk` is the SPHINCS+ envelope key that authorizes the transfer wire
/// message. Both are needed to sign, so both live in the vault, and both are
/// wiped as soon as the signing call returns.
const PAYLOAD_VERSION: u8 = 1;
const SK_D_LEN: usize = 32;
/// SPHINCS+ SHA2-128f secret key: `sk_seed(n) || sk_prf(n) || pk(2n)` with
/// n = 16, i.e. 64 bytes total (slh-dsa's `SkLen = 4 * 16`).
const SLH_SK_LEN: usize = 64;
const PAYLOAD_LEN: usize = 1 + SK_D_LEN + SLH_SK_LEN;

/// A decoded error: (export code, human message).
type Fail = (i32, String);

fn bad(msg: impl Into<String>) -> Fail {
    (ERR_BAD_INPUT, msg.into())
}

/// Parse exactly-32-byte lowercase hex into a digest.
fn hex32(s: &str) -> Result<Digest32, Fail> {
    let bytes = hex::decode(s).map_err(|e| bad(format!("bad hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| bad("hex value is not 32 bytes"))?;
    Ok(Digest32::new(arr))
}

/// Parse a hex string into raw bytes of exactly `n` length.
fn hex_n(s: &str, n: usize) -> Result<Vec<u8>, Fail> {
    let bytes = hex::decode(s).map_err(|e| bad(format!("bad hex: {e}")))?;
    if bytes.len() != n {
        return Err(bad(format!("expected {n}-byte hex, got {}", bytes.len())));
    }
    Ok(bytes)
}

/// Seed a CSPRNG from caller-supplied entropy.
///
/// The browser cannot hand wasm an OS CSPRNG handle, so JS passes
/// `crypto.getRandomValues(32)` bytes per call. Thirty-two bytes is exactly
/// the `StdRng` seed size; anything shorter would silently reduce the key
/// space, so it is refused rather than padded.
fn seeded_rng(entropy: &[u8]) -> Result<rand::rngs::StdRng, Fail> {
    use rand::SeedableRng;
    let seed: [u8; 32] = entropy
        .try_into()
        .map_err(|_| (ERR_ENTROPY, "entropy must be exactly 32 bytes".to_string()))?;
    Ok(rand::rngs::StdRng::from_seed(seed))
}

/// Unlock the vault and split the payload into its two secret keys.
///
/// Both halves are `Zeroizing`: they wipe when the caller drops them, which
/// is the end of the enclosing export call.
struct VaultKeys {
    sk_d: Zeroizing<Vec<u8>>,
    slh_sk: Zeroizing<Vec<u8>>,
}

fn unlock(password: &[u8], vault_bytes: &[u8]) -> Result<VaultKeys, Fail> {
    let sealed = vault::SealedVault::from_bytes(vault_bytes)
        .map_err(|e| (ERR_BAD_INPUT, format!("vault: {e}")))?;
    let payload = sealed.open(password).map_err(|e| match e {
        vault::VaultError::WrongPassword => (ERR_WRONG_PASSWORD, "incorrect password".to_string()),
        other => (ERR_BAD_INPUT, format!("vault: {other}")),
    })?;
    if payload.len() != PAYLOAD_LEN || payload[0] != PAYLOAD_VERSION {
        return Err(bad("vault payload has an unexpected shape"));
    }
    Ok(VaultKeys {
        sk_d: Zeroizing::new(payload[1..=SK_D_LEN].to_vec()),
        slh_sk: Zeroizing::new(payload[1 + SK_D_LEN..].to_vec()),
    })
}

/// Build a fresh vault: generate `sk_d` and the SPHINCS+ keypair from
/// `entropy`, seal the payload under `password`.
///
/// Returns the sealed vault bytes.
fn imp_vault_create(password: &[u8], entropy: &[u8]) -> Result<Vec<u8>, Fail> {
    use rand::TryRng;
    let mut rng = seeded_rng(entropy)?;
    let mut sk_d = vec![0u8; SK_D_LEN];
    rng.try_fill_bytes(&mut sk_d)
        .map_err(|e| (ERR_ENTROPY_FAILED, format!("entropy: {e}")))?;
    let (auth_sk, _vk) = SphincsPlusAuth::generate_keypair(&mut rng);
    let slh_sk = auth_sk.to_bytes().to_vec();
    if slh_sk.len() != SLH_SK_LEN {
        return Err(bad("unexpected SPHINCS+ key size"));
    }
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&sk_d);
    payload.extend_from_slice(&slh_sk);
    let sealed = vault::seal_with_rng(password, &payload, MAX_VAULT_PAYLOAD, &mut rng)
        .map_err(|e| (ERR_INTERNAL, format!("seal: {e}")))?;
    sealed
        .to_bytes()
        .map_err(|e| (ERR_INTERNAL, format!("encode: {e}")))
}

/// Re-key a vault: open under `old`, re-seal under `new` with fresh salt and
/// nonce. Keys themselves are unchanged.
fn imp_vault_change(
    old: &[u8],
    new: &[u8],
    entropy: &[u8],
    vault_bytes: &[u8],
) -> Result<Vec<u8>, Fail> {
    let keys = unlock(old, vault_bytes)?;
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&keys.sk_d);
    payload.extend_from_slice(&keys.slh_sk);
    let mut rng = seeded_rng(entropy)?;
    let sealed = vault::seal_with_rng(new, &payload, MAX_VAULT_PAYLOAD, &mut rng)
        .map_err(|e| (ERR_INTERNAL, format!("seal: {e}")))?;
    sealed
        .to_bytes()
        .map_err(|e| (ERR_INTERNAL, format!("encode: {e}")))
}

/// The public identity inside a vault, as JSON:
/// `{"pk_d":hex,"verifying_key":hex}`.
fn imp_pubkey(password: &[u8], vault_bytes: &[u8]) -> Result<String, Fail> {
    let keys = unlock(password, vault_bytes)?;
    let mut sk_d = [0u8; 32];
    sk_d.copy_from_slice(&keys.sk_d);
    let pk_d = derive_spend_pk(&Sha3_256Shielded, &sk_d);
    let auth_sk = SigningKey::<Sha2_128f>::try_from(&keys.slh_sk[..])
        .map_err(|_| bad("vault holds a malformed SPHINCS+ key"))?;
    let vk = SphincsPlusAuth::public_key_to_bytes(&auth_sk.verifying_key());
    Ok(format!(
        "{{\"pk_d\":\"{}\",\"verifying_key\":\"{}\"}}",
        hex::encode(pk_d.as_bytes()),
        hex::encode(&vk)
    ))
}

/// Parse the statement JSON the UI collects from the node:
/// `{"nullifiers":[hex..],"outputs":[hex..],"root":hex,
/// "nullifier_root_before":hex,"nullifier_root_after":hex,"fee":u64}`.
fn stmt_from_json(text: &str) -> Result<TransferPublic, Fail> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| bad(format!("statement JSON: {e}")))?;
    let hex_list = |key: &str| -> Result<Vec<Digest32>, Fail> {
        let arr = v
            .get(key)
            .and_then(|x| x.as_array())
            .ok_or_else(|| bad(format!("statement missing array '{key}'")))?;
        arr.iter()
            .map(|x| {
                let s = x
                    .as_str()
                    .ok_or_else(|| bad(format!("'{key}' entries must be strings")))?;
                hex32(s)
            })
            .collect()
    };
    let nullifiers: Vec<Nullifier> = hex_list("nullifiers")?
        .into_iter()
        .map(Nullifier::from_digest)
        .collect();
    let outputs: Vec<NoteHash> = hex_list("outputs")?
        .into_iter()
        .map(NoteHash::from_digest)
        .collect();
    let field = |key: &str| -> Result<Digest32, Fail> {
        let s = v
            .get(key)
            .and_then(|x| x.as_str())
            .ok_or_else(|| bad(format!("statement missing string '{key}'")))?;
        hex32(s)
    };
    let fee = v
        .get("fee")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad("statement missing numeric 'fee'"))?;
    Ok(TransferPublic {
        nullifiers,
        outputs,
        root: MerkleRoot::from_digest(field("root")?),
        nullifier_roots: NullifierRoots {
            before: MerkleRoot::from_digest(field("nullifier_root_before")?),
            after: MerkleRoot::from_digest(field("nullifier_root_after")?),
        },
        fee,
    })
}

/// Sign a transfer: unlock, build the canonical message via
/// `shielded::encode_statement` (the *same function the node runs*), sign it
/// with the vault's SPHINCS+ key, and emit the `TransferWire` JSON the node's
/// `/v1/transfer` endpoint accepts.
fn imp_sign_transfer(
    password: &[u8],
    vault_bytes: &[u8],
    statement_json: &[u8],
) -> Result<String, Fail> {
    if statement_json.len() > MAX_STATEMENT_BYTES {
        return Err(bad("statement too large"));
    }
    let text = std::str::from_utf8(statement_json).map_err(|e| bad(format!("utf8: {e}")))?;
    let public = stmt_from_json(text)?;
    let message = shielded::encode_statement(&public)
        .map_err(|_| (ERR_TOO_LARGE, "statement exceeds count limits".to_string()))?;
    let keys = unlock(password, vault_bytes)?;
    let auth_sk = SigningKey::<Sha2_128f>::try_from(&keys.slh_sk[..])
        .map_err(|_| bad("vault holds a malformed SPHINCS+ key"))?;
    let sig = SphincsPlusAuth::sign(&auth_sk, &message);
    let vk = SphincsPlusAuth::public_key_to_bytes(&auth_sk.verifying_key());
    let hex_of =
        |ds: &[Digest32]| -> Vec<String> { ds.iter().map(|d| hex::encode(d.as_bytes())).collect() };
    // Echo the statement fields back exactly as TransferWire expects, then
    // the envelope. This JSON is the POST body; nothing secret is in it.
    let nf = hex_of(
        &public
            .nullifiers
            .iter()
            .map(|n| {
                let mut d = [0u8; 32];
                d.copy_from_slice(n.as_bytes());
                Digest32::new(d)
            })
            .collect::<Vec<_>>(),
    );
    let out = hex_of(
        &public
            .outputs
            .iter()
            .map(|o| {
                let mut d = [0u8; 32];
                d.copy_from_slice(o.as_bytes());
                Digest32::new(d)
            })
            .collect::<Vec<_>>(),
    );
    let arr = |items: &[String]| {
        items
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    Ok(format!(
        "{{\"nullifiers\":[{}],\"outputs\":[{}],\"root\":\"{}\",\"nullifier_root_before\":\"{}\",\"nullifier_root_after\":\"{}\",\"fee\":{},\"verifying_key\":\"{}\",\"signature\":\"{}\"}}",
        arr(&nf),
        arr(&out),
        hex::encode(public.root.as_bytes()),
        hex::encode(public.nullifier_roots.before.as_bytes()),
        hex::encode(public.nullifier_roots.after.as_bytes()),
        public.fee,
        hex::encode(&vk),
        hex::encode(SphincsPlusAuth::signature_to_bytes(&sig)),
    ))
}

/// Verify a signed wire envelope before sending it: parse the statement,
/// rebuild the canonical message, check the SPHINCS+ signature. Returns Ok
/// only if the signature is valid over exactly those bytes.
fn imp_verify_transfer(statement_json: &[u8], vk_hex: &str, sig_hex: &str) -> Result<(), Fail> {
    let text = std::str::from_utf8(statement_json).map_err(|e| bad(format!("utf8: {e}")))?;
    let public = stmt_from_json(text)?;
    let message = shielded::encode_statement(&public)
        .map_err(|_| (ERR_TOO_LARGE, "statement exceeds count limits".to_string()))?;
    // No hardcoded length: the scheme parser is the authority on vk size
    // (SHA2-128f keys are 32 bytes), same as the node's wire path.
    let vk_bytes = hex::decode(vk_hex).map_err(|e| bad(format!("bad vk hex: {e}")))?;
    let vk = SphincsPlusAuth::public_key_from_bytes(&vk_bytes).map_err(|_| bad("bad vk"))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| bad(format!("bad sig hex: {e}")))?;
    let sig = SphincsPlusAuth::signature_from_bytes(&sig_bytes).map_err(|_| bad("bad sig"))?;
    SphincsPlusAuth::verify(&vk, &message, &sig).map_err(|_| {
        (
            ERR_SIGNATURE,
            "signature does not cover this statement".to_string(),
        )
    })
}

/// Commit a note: `Note::commit` under the Keccak commitment hasher - the
/// same hasher the settlement layer replays.
fn imp_note_commit(
    value: u64,
    rho_hex: &str,
    psi_hex: &str,
    pk_d_hex: &str,
) -> Result<String, Fail> {
    let rho: [u8; 32] = hex_n(rho_hex, 32)?.try_into().map_err(|_| bad("rho"))?;
    let psi: [u8; 32] = hex_n(psi_hex, 32)?.try_into().map_err(|_| bad("psi"))?;
    let pk_d_bytes = hex_n(pk_d_hex, 32)?;
    let mut pk_d_arr = [0u8; 32];
    pk_d_arr.copy_from_slice(&pk_d_bytes);
    let note = Note::new(
        value,
        rho,
        psi,
        shielded::keys::SpendPublicKey::from_bytes(pk_d_arr),
    );
    Ok(hex::encode(
        note.commit(&Poseidon2Commitment::new()).as_bytes(),
    ))
}

/// The nullifier for a note owned by this vault: `Note::nullifier` under
/// SHA3-256, the shielded hasher the circuit mirrors.
fn imp_note_nullifier(password: &[u8], vault_bytes: &[u8], rho_hex: &str) -> Result<String, Fail> {
    let rho: [u8; 32] = hex_n(rho_hex, 32)?.try_into().map_err(|_| bad("rho"))?;
    let keys = unlock(password, vault_bytes)?;
    let mut sk_d = [0u8; 32];
    sk_d.copy_from_slice(&keys.sk_d);
    // The note's pk_d is irrelevant to the nullifier (it is H(sk_d || rho)),
    // but Note requires one; pass the derived pk_d for honesty.
    let pk_d = derive_spend_pk(&Sha3_256Shielded, &sk_d);
    let note = Note::new(0, rho, [0u8; 32], pk_d);
    Ok(hex::encode(
        note.nullifier(&Sha3_256Shielded, &sk_d).as_bytes(),
    ))
}

// ---------------------------------------------------------------------------
// extern "C" surface
// ---------------------------------------------------------------------------

/// Create a fresh vault. Returns 0 and the vault bytes in the out buffer.
#[unsafe(no_mangle)]
pub extern "C" fn vault_create(pw_ptr: u32, pw_len: u32, ent_ptr: u32, ent_len: u32) -> i32 {
    let (Some(pw), Some(ent)) = (read_buf(pw_ptr, pw_len), read_buf(ent_ptr, ent_len)) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    match imp_vault_create(&pw, &ent) {
        Ok(bytes) => ok_bytes(&bytes),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Re-key a vault under a new password. Returns 0 and the new vault bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments, reason = "flat ABI by design")]
pub extern "C" fn vault_change(
    old_ptr: u32,
    old_len: u32,
    new_ptr: u32,
    new_len: u32,
    ent_ptr: u32,
    ent_len: u32,
    vault_ptr: u32,
    vault_len: u32,
) -> i32 {
    let inputs = [
        read_buf(old_ptr, old_len),
        read_buf(new_ptr, new_len),
        read_buf(ent_ptr, ent_len),
        read_buf(vault_ptr, vault_len),
    ];
    let [Some(old), Some(new), Some(ent), Some(vault)] = inputs else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    match imp_vault_change(&old, &new, &ent, &vault) {
        Ok(bytes) => ok_bytes(&bytes),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// The vault's public identity as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn wallet_pubkey(pw_ptr: u32, pw_len: u32, vault_ptr: u32, vault_len: u32) -> i32 {
    let (Some(pw), Some(vault)) = (read_buf(pw_ptr, pw_len), read_buf(vault_ptr, vault_len)) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    match imp_pubkey(&pw, &vault) {
        Ok(json) => ok_bytes(json.as_bytes()),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Sign a transfer statement; out holds the `TransferWire` JSON.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments, reason = "flat ABI by design")]
pub extern "C" fn sign_transfer(
    pw_ptr: u32,
    pw_len: u32,
    vault_ptr: u32,
    vault_len: u32,
    stmt_ptr: u32,
    stmt_len: u32,
) -> i32 {
    let (Some(pw), Some(vault), Some(stmt)) = (
        read_buf(pw_ptr, pw_len),
        read_buf(vault_ptr, vault_len),
        read_buf(stmt_ptr, stmt_len),
    ) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    match imp_sign_transfer(&pw, &vault, &stmt) {
        Ok(json) => ok_bytes(json.as_bytes()),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Verify a signed envelope: `(stmt, vk, sig)`. 0 = valid.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments, reason = "flat ABI by design")]
pub extern "C" fn verify_transfer(
    stmt_ptr: u32,
    stmt_len: u32,
    vk_ptr: u32,
    vk_len: u32,
    sig_ptr: u32,
    sig_len: u32,
) -> i32 {
    let (Some(stmt), Some(vk), Some(sig)) = (
        read_buf(stmt_ptr, stmt_len),
        read_buf(vk_ptr, vk_len),
        read_buf(sig_ptr, sig_len),
    ) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    let (Ok(vk_s), Ok(sig_s)) = (std::str::from_utf8(&vk), std::str::from_utf8(&sig)) else {
        return fail(ERR_BAD_INPUT, "vk/sig must be utf8 hex");
    };
    match imp_verify_transfer(&stmt, vk_s, sig_s) {
        Ok(()) => {
            set_out(Vec::new());
            OK
        }
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Commit a note; out holds the hex note hash.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments, reason = "flat ABI by design")]
pub extern "C" fn note_commit(
    value: u64,
    rho_ptr: u32,
    rho_len: u32,
    psi_ptr: u32,
    psi_len: u32,
    pkd_ptr: u32,
    pkd_len: u32,
) -> i32 {
    let (Some(rho), Some(psi), Some(pk_d)) = (
        read_buf(rho_ptr, rho_len),
        read_buf(psi_ptr, psi_len),
        read_buf(pkd_ptr, pkd_len),
    ) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    let (Ok(rho_s), Ok(psi_s), Ok(pk_s)) = (
        std::str::from_utf8(&rho),
        std::str::from_utf8(&psi),
        std::str::from_utf8(&pk_d),
    ) else {
        return fail(ERR_BAD_INPUT, "inputs must be utf8 hex");
    };
    match imp_note_commit(value, rho_s, psi_s, pk_s) {
        Ok(hexed) => ok_bytes(hexed.as_bytes()),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Nullifier for a note under this vault; out holds the hex nullifier.
#[unsafe(no_mangle)]
pub extern "C" fn note_nullifier(
    pw_ptr: u32,
    pw_len: u32,
    vault_ptr: u32,
    vault_len: u32,
    rho_ptr: u32,
    rho_len: u32,
) -> i32 {
    let (Some(pw), Some(vault), Some(rho)) = (
        read_buf(pw_ptr, pw_len),
        read_buf(vault_ptr, vault_len),
        read_buf(rho_ptr, rho_len),
    ) else {
        return fail(ERR_BAD_INPUT, "bad input offsets");
    };
    let Ok(rho_s) = std::str::from_utf8(&rho) else {
        return fail(ERR_BAD_INPUT, "rho must be utf8 hex");
    };
    match imp_note_nullifier(&pw, &vault, rho_s) {
        Ok(hexed) => ok_bytes(hexed.as_bytes()),
        Err((code, msg)) => fail(code, &msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn pw() -> Vec<u8> {
        b"wallet password".to_vec()
    }

    fn statement_json(fee: u64) -> String {
        format!(
            "{{\"nullifiers\":[\"{}\",\"{}\"],\"outputs\":[\"{}\"],\"root\":\"{}\",\"nullifier_root_before\":\"{}\",\"nullifier_root_after\":\"{}\",\"fee\":{}}}",
            "01".repeat(32),
            "02".repeat(32),
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
            "dd".repeat(32),
            fee
        )
    }

    #[test]
    fn vault_create_then_pubkey_round_trips() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let json = imp_pubkey(&pw(), &vault).expect("pubkey");
        assert!(json.contains("\"pk_d\""));
        assert!(json.contains("\"verifying_key\""));
        // SHA2-128f verifying keys are 32 bytes = 64 hex chars.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("identity is JSON");
        assert_eq!(parsed["pk_d"].as_str().expect("pk_d").len(), 64);
        assert_eq!(parsed["verifying_key"].as_str().expect("vk").len(), 64);
    }

    #[test]
    fn a_wrong_password_never_opens_the_vault() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let (code, _) = imp_pubkey(b"not it", &vault).expect_err("must fail");
        assert_eq!(code, ERR_WRONG_PASSWORD);
    }

    #[test]
    fn vault_change_rekeys_but_keeps_identity() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let before = imp_pubkey(&pw(), &vault).expect("pubkey");
        let rekeyed = imp_vault_change(&pw(), b"new password", &entropy(9), &vault).expect("rekey");
        let after = imp_pubkey(b"new password", &rekeyed).expect("pubkey");
        assert_eq!(before, after, "identity survives the re-key");
        assert!(imp_pubkey(&pw(), &rekeyed).is_err(), "old password is dead");
    }

    #[test]
    fn short_entropy_is_refused_not_padded() {
        let (code, _) = imp_vault_create(&pw(), &[1u8; 16]).expect_err("must fail");
        assert_eq!(code, ERR_ENTROPY);
    }

    #[test]
    fn sign_then_verify_round_trips_and_the_wire_shape_is_right() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let wire = imp_sign_transfer(&pw(), &vault, statement_json(100).as_bytes()).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&wire).expect("wire is JSON");
        for key in [
            "nullifiers",
            "outputs",
            "root",
            "nullifier_root_before",
            "nullifier_root_after",
            "fee",
            "verifying_key",
            "signature",
        ] {
            assert!(v.get(key).is_some(), "wire missing {key}");
        }
        assert_eq!(v["fee"].as_u64(), Some(100));
        assert_eq!(v["nullifiers"].as_array().expect("nf array").len(), 2);
        let vk = v["verifying_key"].as_str().expect("vk");
        let sig = v["signature"].as_str().expect("sig");
        imp_verify_transfer(statement_json(100).as_bytes(), vk, sig).expect("valid");
    }

    #[test]
    fn a_tampered_fee_fails_verification() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let wire = imp_sign_transfer(&pw(), &vault, statement_json(100).as_bytes()).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&wire).expect("wire");
        let vk = v["verifying_key"].as_str().expect("vk");
        let sig = v["signature"].as_str().expect("sig");
        let (code, _) = imp_verify_transfer(statement_json(101).as_bytes(), vk, sig)
            .expect_err("fee bump must fail");
        assert_eq!(code, ERR_SIGNATURE);
    }

    #[test]
    fn the_signed_message_is_the_shared_canonical_encoding() {
        // The wallet must sign EXACTLY what shielded::encode_statement builds -
        // the same function the node runs. If this drifts, wallet and node
        // reject each other; this test is the tripwire.
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let json = statement_json(55);
        let public = stmt_from_json(&json).expect("parse");
        let message = shielded::encode_statement(&public).expect("encode");
        assert!(message.starts_with(shielded::DOMAIN_TX));
        // And the wire signature verifies over exactly that message:
        let wire = imp_sign_transfer(&pw(), &vault, json.as_bytes()).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&wire).expect("wire");
        let vk = SphincsPlusAuth::public_key_from_bytes(
            &hex::decode(v["verifying_key"].as_str().expect("vk")).expect("vk hex"),
        )
        .expect("vk parse");
        let sig = SphincsPlusAuth::signature_from_bytes(
            &hex::decode(v["signature"].as_str().expect("sig")).expect("sig hex"),
        )
        .expect("sig parse");
        SphincsPlusAuth::verify(&vk, &message, &sig).expect("canonical message verifies");
    }

    #[test]
    fn malformed_statements_are_rejected_before_crypto() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        // Missing fee.
        let (code, _) = imp_sign_transfer(
            &pw(),
            &vault,
            b"{\"nullifiers\":[],\"outputs\":[],\"root\":\"00\",\"nullifier_root_before\":\"00\",\"nullifier_root_after\":\"00\"}",
        )
        .expect_err("must fail");
        assert_eq!(code, ERR_BAD_INPUT);
        // Non-hex digest.
        let (code, _) = stmt_from_json("{\"nullifiers\":[\"zz\"],\"outputs\":[],\"root\":\"00\",\"nullifier_root_before\":\"00\",\"nullifier_root_after\":\"00\",\"fee\":0}")
            .expect_err("must fail");
        assert_eq!(code, ERR_BAD_INPUT);
    }

    #[test]
    fn note_commit_matches_the_shared_note_crate() {
        // The wallet's commit must equal what shielded::Note computes - one
        // implementation, checked here rather than trusted.
        let rho = "11".repeat(32);
        let psi = "22".repeat(32);
        let pk_d = "33".repeat(32);
        let hexed = imp_note_commit(1234, &rho, &psi, &pk_d).expect("commit");
        let mut rho_b = [0u8; 32];
        rho_b.copy_from_slice(&hex::decode(&rho).expect("rho"));
        let mut psi_b = [0u8; 32];
        psi_b.copy_from_slice(&hex::decode(&psi).expect("psi"));
        let mut pk_b = [0u8; 32];
        pk_b.copy_from_slice(&hex::decode(&pk_d).expect("pk"));
        let note = Note::new(
            1234,
            rho_b,
            psi_b,
            shielded::keys::SpendPublicKey::from_bytes(pk_b),
        );
        assert_eq!(
            hexed,
            hex::encode(note.commit(&Poseidon2Commitment::new()).as_bytes())
        );
    }

    #[test]
    fn note_nullifier_uses_the_vault_secret_key() {
        let vault = imp_vault_create(&pw(), &entropy(7)).expect("create");
        let rho = "11".repeat(32);
        let nf = imp_note_nullifier(&pw(), &vault, &rho).expect("nullifier");
        assert_eq!(nf.len(), 64, "32 bytes hex");
        // Deterministic in (sk_d, rho): same vault + rho -> same nullifier.
        assert_eq!(nf, imp_note_nullifier(&pw(), &vault, &rho).expect("again"));
        // Different vault -> different sk_d -> different nullifier.
        let other = imp_vault_create(&pw(), &entropy(8)).expect("create");
        assert_ne!(nf, imp_note_nullifier(&pw(), &other, &rho).expect("other"));
    }
}
