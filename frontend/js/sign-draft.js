// The work on /sign survives a sign-in (retest 2026-10-04, T5-6).
//
// A session that ran out halfway sent the customer to /auth/login, and back on
// /sign everything was gone: the document, the spot for the signature, the
// people who had to sign. Here that work is kept as a draft in THIS browser
// while the customer signs in, and put back afterwards.
//
// What is kept: the document's SHA3 hash and name, the placement, the setup
// (alone / together / invite), the recipients and the invitation text. The
// document bytes are kept too, so nobody has to find the file again, but never
// in the clear: they are encrypted with AES-GCM under a key WebCrypto made
// non-extractable (no script can read the raw key out), stored next to them in
// IndexedDB. Nothing leaves the browser. The draft is wiped as soon as the
// request is sent or the document signed, when the customer chooses to start
// over, and on its own after two hours.
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

// meta: plain JSON (hash, name, placement, recipients, ...). bytes: Uint8Array.
export async function saveDraft(meta, bytes) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = bytes && bytes.length ? new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes)) : null;
  const rec = { v: 1, savedAt: Date.now(), meta: JSON.parse(JSON.stringify(meta || {})), iv, ct, key };
  await tx('readwrite', (s) => s.put(rec, KEY));
  return true;
}

// The draft, or null (none, too old, or unreadable: those are wiped).
export async function loadDraft(now = Date.now()) {
  let rec;
  try { rec = await tx('readonly', (s) => s.get(KEY)); } catch { return null; }
  if (!rec || rec.v !== 1) return null;
  if (!(now - rec.savedAt < DRAFT_TTL_MS)) { await clearDraft(); return null; }
  let bytes = null;
  if (rec.ct) {
    try { bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.key, rec.ct)); }
    catch { await clearDraft(); return null; }
  }
  return { meta: rec.meta || {}, bytes, savedAt: rec.savedAt };
}

export async function hasDraft(now = Date.now()) {
  try {
    const rec = await tx('readonly', (s) => s.get(KEY));
    return !!(rec && rec.v === 1 && now - rec.savedAt < DRAFT_TTL_MS);
  } catch { return false; }
}

export async function clearDraft() {
  try { await tx('readwrite', (s) => s.delete(KEY)); } catch { /* nothing to wipe */ }
}
