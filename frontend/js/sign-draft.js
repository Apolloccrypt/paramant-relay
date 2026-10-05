// The work on /sign survives a sign-in (retest 2026-10-04, T5-6).
//
// A session that ran out halfway sent the customer to /auth/login, and back on
// /sign everything was gone: the document, the spot for the signature, the
// people who had to sign. Here that work is kept as a draft in THIS browser
// while the customer signs in, and put back afterwards.
//
// What is kept: the document, its name and hash, the placement, the setup
// (alone / together / invite), the recipients and the invitation text. ALL of
// it is encrypted (AES-GCM) under a key that belongs to the ACCOUNT: the relay
// derives it per account (GET /api/user/sign-draft-key) and this page holds it
// in memory only, never next to the draft. Only the save time and the expiry
// stay readable. Another account in this browser gets another key, cannot open
// the draft, and the draft is wiped (security review r2 (a)). It is also wiped
// when the request is sent or the document signed, when the customer starts
// over, on sign-out (nav-auth.js), and after two hours on any page.
const DB = 'paramant-sign-draft';
const STORE = 'kv';
const KEY = 'current';
export const DRAFT_TTL_MS = 2 * 60 * 60 * 1000;

function open() {
  return new Promise((resolve, reject) => {
    let req;
    try { req = indexedDB.open(DB, 1); } catch (e) { reject(e); return; }
    req.onupgradeneeded = () => { try { req.result.createObjectStore(STORE); } catch { /* exists */ } };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('indexeddb'));
  });
}

async function tx(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const store = t.objectStore(STORE);
      let out;
      const r = fn(store);
      if (r) r.onsuccess = () => { out = r.result; };
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error || new Error('indexeddb'));
      t.onabort = () => reject(t.error || new Error('indexeddb'));
    });
  } finally {
    try { db.close(); } catch { /* closed */ }
  }
}

// The account key, as a non-extractable AES-GCM CryptoKey, or null when there
// is no session. Fetched while the session is still valid, kept in memory.
let accountKey = null;
export async function loadAccountKey(fetcher = fetch) {
  try {
    const r = await fetcher('/api/user/sign-draft-key', { credentials: 'include', cache: 'no-store' });
    if (!r.ok) return (accountKey = null);
    const { key } = await r.json();
    const raw = Uint8Array.from(atob(String(key).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    if (raw.length !== 32) return (accountKey = null);
    accountKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    raw.fill(0);
    return accountKey;
  } catch { return (accountKey = null); }
}
export function hasAccountKey() { return !!accountKey; }

const enc = new TextEncoder();
const dec = new TextDecoder();
async function seal(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv, ct: new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes)) };
}
async function open1(key, box) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: box.iv }, key, box.ct));
}

// meta: plain JSON (hash, name, placement, recipients, ...). bytes: Uint8Array.
// Without an account key nothing is stored (returns false).
export async function saveDraft(meta, bytes, key = accountKey) {
  if (!key) return false;
  const now = Date.now();
  const m = await seal(key, enc.encode(JSON.stringify(meta || {})));
  const b = bytes && bytes.length ? await seal(key, bytes) : null;
  const rec = { v: 2, savedAt: now, expiresAt: now + DRAFT_TTL_MS, m, b };
  await tx('readwrite', (s) => s.put(rec, KEY));
  return true;
}

// The draft, or null (none, too old, another account, or unreadable: those
// are wiped).
export async function loadDraft(now = Date.now(), key = accountKey) {
  let rec;
  try { rec = await tx('readonly', (s) => s.get(KEY)); } catch { return null; }
  if (!rec) return null;
  if (rec.v !== 2 || !(now < rec.expiresAt) || !(now - rec.savedAt < DRAFT_TTL_MS)) { await clearDraft(); return null; }
  if (!key) return null;
  let meta, bytes = null;
  try {
    meta = JSON.parse(dec.decode(await open1(key, rec.m)));
    if (rec.b) bytes = await open1(key, rec.b);
  } catch { await clearDraft(); return null; }
  return { meta: meta || {}, bytes, savedAt: rec.savedAt };
}

export async function hasDraft(now = Date.now()) {
  try {
    const rec = await tx('readonly', (s) => s.get(KEY));
    return !!(rec && rec.v === 2 && now < rec.expiresAt);
  } catch { return false; }
}

export async function clearDraft() {
  try { await tx('readwrite', (s) => s.delete(KEY)); } catch { /* nothing to wipe */ }
}
