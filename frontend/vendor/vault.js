// ParaSign signing-key vault.
//
// Persists ML-DSA-65 private keys in IndexedDB, encrypted with a passphrase-
// derived KEK (PBKDF2-SHA256 600000 iter -> AES-256-GCM). All WebCrypto-
// native, zero dependencies, same-origin only (loads under script-src 'self').
//
// Envelope layout (forward-compatible with WebAuthn-PRF in PR 2):
//   {
//     id:          <pk_hash_sha3, used as IDB primary key>,
//     alg:         'ML-DSA-65',
//     label:       <string|null>,
//     pk_b64:      <public key, base64, plain (public)>,
//     pk_hash:     <SHA3-256 hex of the raw public key>,
//     enrolled_at: <ISO timestamp>,
//     wraps: [
//       { kekSource: 'passphrase', kdf: 'PBKDF2-SHA256', iter, salt, iv, ciphertext }
//       // PR 2 appends   { kekSource: 'webauthn-prf', credentialId, iv, ciphertext }
//     ]
//   }
//
// The wraps array is what lets a second KEK source (Face ID / Touch ID via
// WebAuthn-PRF) be added later without re-encrypting or migrating data.

const DB_NAME    = 'paramant';
const STORE_NAME = 'signing-keys';
const DB_VERSION = 1;
const PBKDF2_ITER = 600000;
const PBKDF2_HASH = 'SHA-256';
const KEK_NAME    = 'AES-GCM';
const KEK_BITS    = 256;
const SALT_BYTES  = 16;
const IV_BYTES    = 12;

// --- Base64 helpers (Uint8Array <-> base64 string). Same idiom the relay uses.
function b64Encode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64Decode(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// --- IDB open (idempotent). Creates store on first call.
function vaultOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error || new Error('IDB open failed'));
    req.onblocked = () => reject(new Error('IDB blocked (another tab is upgrading)'));
  });
}

function _tx(db, mode) {
  return db.transaction(STORE_NAME, mode).objectStore(STORE_NAME);
}
function _toPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

// --- Metadata-only listing. Never returns plaintext secret material.
//     Returns array of { id, alg, label, pk_b64, pk_hash, enrolled_at, kekSources, lastUsedAt }.
export async function vaultList() {
  const db = await vaultOpen();
  const all = await _toPromise(_tx(db, 'readonly').getAll());
  db.close();
  return all.map(e => ({
    id:          e.id,
    alg:         e.alg,
    label:       e.label || null,
    pk_b64:      e.pk_b64,
    pk_hash:     e.pk_hash,
    enrolled_at: e.enrolled_at,
    last_used_at: e.last_used_at || null,
    kekSources:  (e.wraps || []).map(w => w.kekSource),
  }));
}

// --- Passphrase -> KEK via PBKDF2-SHA256 (600k iter -> AES-GCM 256).
async function _deriveKekFromPassphrase(passphrase, salt) {
  const passBytes = new TextEncoder().encode(String(passphrase));
  const baseKey = await crypto.subtle.importKey(
    'raw', passBytes, { name: 'PBKDF2' }, false, ['deriveKey'],
  );
  const kek = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: PBKDF2_HASH },
    baseKey,
    { name: KEK_NAME, length: KEK_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
  // Wipe the passphrase bytes from our copy. (V8 will GC the TextEncoder
  // result; we cannot reach into the WebCrypto-internal copy. This is a
  // best-effort hygiene step.)
  passBytes.fill(0);
  return kek;
}

// --- Store an entry. If id already exists, the new passphrase-wrap REPLACES
//     the existing passphrase-wrap on that entry (so the user can change
//     passphrases). Other wraps (e.g. PR 2's prf wrap) are left intact.
export async function vaultStore({ alg, label, pk_b64, pk_hash, secretKeyBytes, passphrase }) {
  if (!alg || !pk_b64 || !pk_hash) throw new Error('vaultStore: alg, pk_b64, pk_hash required');
  if (!(secretKeyBytes instanceof Uint8Array) || secretKeyBytes.length === 0) {
    throw new Error('vaultStore: secretKeyBytes (Uint8Array) required');
  }
  if (!passphrase || String(passphrase).length < 8) {
    throw new Error('vaultStore: passphrase of at least 8 chars required');
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const kek  = await _deriveKekFromPassphrase(passphrase, salt);
  const ct   = new Uint8Array(
    await crypto.subtle.encrypt({ name: KEK_NAME, iv }, kek, secretKeyBytes),
  );

  const wrap = {
    kekSource:  'passphrase',
    kdf:        'PBKDF2-SHA256',
    iter:       PBKDF2_ITER,
    salt:       b64Encode(salt),
    iv:         b64Encode(iv),
    ciphertext: b64Encode(ct),
  };

  const db = await vaultOpen();
  const store = _tx(db, 'readwrite');
  const existing = await _toPromise(store.get(pk_hash));

  const entry = existing ? { ...existing } : {
    id:          pk_hash,
    alg,
    label:       label || null,
    pk_b64,
    pk_hash,
    enrolled_at: new Date().toISOString(),
    wraps:       [],
    last_used_at: null,
  };
  // Update label if provided (idempotent re-store)
  if (label) entry.label = label;
  // Replace existing passphrase wrap if there is one, else append
  entry.wraps = (entry.wraps || []).filter(w => w.kekSource !== 'passphrase');
  entry.wraps.push(wrap);

  await _toPromise(store.put(entry));
  db.close();

  return {
    id: entry.id,
    alg: entry.alg,
    label: entry.label,
    pk_hash: entry.pk_hash,
    enrolled_at: entry.enrolled_at,
    kekSources: entry.wraps.map(w => w.kekSource),
  };
}

// --- Unlock with passphrase. Returns the raw secretKeyBytes (Uint8Array) so
//     the caller can hand it to ml_dsa65.sign(). Throws 'wrong passphrase' on
//     auth-tag mismatch, 'no such key' if the id is unknown, 'no passphrase
//     wrap' if the entry has no passphrase KEK source.
export async function vaultUnlock(id, passphrase) {
  if (!id) throw new Error('vaultUnlock: id required');
  if (!passphrase) throw new Error('vaultUnlock: passphrase required');

  const db = await vaultOpen();
  const entry = await _toPromise(_tx(db, 'readonly').get(id));
  if (!entry) { db.close(); throw new Error('no such key'); }
  const wrap = (entry.wraps || []).find(w => w.kekSource === 'passphrase');
  if (!wrap) { db.close(); throw new Error('no passphrase wrap'); }

  const salt = b64Decode(wrap.salt);
  const iv   = b64Decode(wrap.iv);
  const ct   = b64Decode(wrap.ciphertext);
  const kek  = await _deriveKekFromPassphrase(passphrase, salt);

  let plain;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: KEK_NAME, iv }, kek, ct),
    );
  } catch (e) {
    db.close();
    // GCM auth-tag failure = wrong passphrase (or tampered ciphertext)
    throw new Error('wrong passphrase');
  }

  // Touch last_used_at so the account UI can show 'recently used'
  try {
    const rw = _tx(db, 'readwrite');
    const fresh = await _toPromise(rw.get(id));
    if (fresh) {
      fresh.last_used_at = new Date().toISOString();
      await _toPromise(rw.put(fresh));
    }
  } catch {}
  db.close();

  return {
    secretKeyBytes: plain,
    pk_b64:         entry.pk_b64,
    pk_hash:        entry.pk_hash,
    label:          entry.label,
  };
}

// --- Delete an entry. Used when the user revokes locally (server-side
//     revocation is a separate DELETE /api/user/account/signing-key call).
export async function vaultDelete(id) {
  if (!id) throw new Error('vaultDelete: id required');
  const db = await vaultOpen();
  await _toPromise(_tx(db, 'readwrite').delete(id));
  db.close();
}

// --- Feature-probe. Pages can call this on load to decide whether to show
//     the vault UI. (IDB + WebCrypto are both standard in modern browsers,
//     but private-mode/Safari quirks can disable IDB.)
export async function vaultAvailable() {
  try {
    if (typeof indexedDB === 'undefined') return false;
    if (!crypto || !crypto.subtle) return false;
    const db = await vaultOpen();
    db.close();
    return true;
  } catch {
    return false;
  }
}
