// Stukken opvragen: the office's vault key.
//
// Every request has its own key pair, and its private half is locked under one
// vault key (AES-256-GCM) before it leaves this browser. That vault key lives
//
//   1. in this browser's IndexedDB, as a CryptoKey that cannot be exported, so
//      opening a download here needs no extra step; and
//   2. when the account has a passkey that can do PRF, also on the server,
//      locked under a key derived from that passkey (WebAuthn PRF, then HKDF,
//      the same construction the signing vault uses in vendor/vault.js). Another
//      computer with the same passkey opens it with one tap. The server holds
//      the locked copy and never the PRF output, so it cannot open it.
//
// Without such a passkey the key exists only here. The page says so in plain
// words: the files can then be opened on this computer only.

import { b64u, fromB64u, rand } from '/js/opvragen-kern.js?v=1';

const DB = 'paramant-opvragen';
const STORE = 'kluis';
const KEK_INFO = 'paramant/opvragen/kek/v1';
const te = new TextEncoder();

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains(STORE)) r.result.createObjectStore(STORE, { keyPath: 'id' }); };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error || new Error('IndexedDB'));
  });
}
async function idbGet(id) {
  try {
    const db = await idb();
    return await new Promise((resolve) => {
      const q = db.transaction(STORE, 'readonly').objectStore(STORE).get(id);
      q.onsuccess = () => { db.close(); resolve(q.result ? q.result.key : null); };
      q.onerror = () => { db.close(); resolve(null); };
    });
  } catch { return null; }
}
async function idbPut(id, key) {
  const db = await idb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put({ id, key });
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
  db.close();
}

function importVault(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function kekFrom(prf) {
  const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(KEK_INFO) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function webauthnOk() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

// One passkey tap that returns the PRF output for the credential that answered.
// Chromium wants evalByCredential when more than one credential is allowed;
// with one, plain eval works everywhere (parasign-signer.js learnt this first).
async function prfTap(creds) {
  const allow = creds.map((c) => ({ type: 'public-key', id: fromB64u(c.cred) }));
  const prf = creds.length === 1 ? { eval: { first: fromB64u(creds[0].salt) } }
    : { evalByCredential: Object.fromEntries(creds.map((c) => [c.cred, { first: fromB64u(c.salt) }])) };
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rand(32), rpId: location.hostname, userVerification: 'required', timeout: 60000,
    allowCredentials: allow, extensions: { prf } } });
  const first = a && a.getClientExtensionResults && a.getClientExtensionResults().prf
    && a.getClientExtensionResults().prf.results && a.getClientExtensionResults().prf.results.first;
  if (!first) { const e = new Error('prf_unsupported'); e.code = 'prf_unsupported'; throw e; }
  return { cred: b64u(new Uint8Array(a.rawId)), prf: new Uint8Array(first) };
}

async function wrapWithPasskey(kluisId, raw, passkeys) {
  const salt = rand(32);
  const { cred, prf } = await prfTap(passkeys.map((p) => ({ cred: p.credId, salt: b64u(salt) })));
  const kek = await kekFrom(prf); prf.fill(0);
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(kluisId) }, kek, raw));
  return { cred, salt: b64u(salt), iv: b64u(iv), ct: b64u(ct) };
}

async function unwrapWithPasskey(k) {
  const { cred, prf } = await prfTap(k.wraps.map((w) => ({ cred: w.cred, salt: w.salt })));
  const w = k.wraps.find((x) => x.cred === cred);
  if (!w) { prf.fill(0); throw new Error('unknown passkey'); }
  const kek = await kekFrom(prf); prf.fill(0);
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(w.iv), additionalData: te.encode(k.kluis_id) },
    kek, fromB64u(w.ct)));
  const key = await importVault(raw); raw.fill(0);
  try { await idbPut(k.kluis_id, key); } catch { /* storage off: it still works for this visit */ }
  return key;
}

// The vault key for a request that names this kluis_id. Throws an Error with
// code 'not_here' when this browser has no copy and no passkey can open one.
export async function openVault(kluisId, kluizen) {
  const here = await idbGet(kluisId);
  if (here) return here;
  const k = (kluizen || []).find((x) => x.kluis_id === kluisId);
  if (k && k.wraps && k.wraps.length && webauthnOk()) return unwrapWithPasskey(k);
  const e = new Error('not_here'); e.code = 'not_here'; throw e;
}

// The vault key to lock a NEW request under. A copy in this browser first;
// then one a passkey can open; else a new vault, carried by a passkey if the
// account has one. `post(kluis)` writes the server record.
export async function vaultForNew({ kluizen, passkeys, post, onStatus }) {
  for (const k of kluizen || []) {
    const key = await idbGet(k.kluis_id);
    if (key) return { kluisId: k.kluis_id, key, carried: !!(k.wraps && k.wraps.length) };
  }
  const withWraps = (kluizen || []).filter((k) => k.wraps && k.wraps.length);
  if (withWraps.length && webauthnOk()) {
    try {
      if (onStatus) onStatus('unlock');
      const key = await unwrapWithPasskey(withWraps[0]);
      return { kluisId: withWraps[0].kluis_id, key, carried: true };
    } catch { /* cancelled or not this passkey: a new vault below */ }
  }
  const kluisId = b64u(rand(16));
  const raw = rand(32);
  let wrap = null;
  if (passkeys && passkeys.length && webauthnOk()) {
    try { if (onStatus) onStatus('passkey'); wrap = await wrapWithPasskey(kluisId, raw, passkeys); }
    catch { wrap = null; }
  }
  const key = await importVault(raw); raw.fill(0);
  await post({ kluis_id: kluisId, wrap });
  try { await idbPut(kluisId, key); }
  catch (e) {
    // No storage (a private window) and no passkey: a request made now could
    // never be opened again once this tab closes. Refuse instead.
    if (!wrap) { const err = new Error('no_storage'); err.code = 'no_storage'; throw err; }
  }
  return { kluisId, key, carried: !!wrap };
}
