// ParaSign signing-key vault.
//
// Persists ML-DSA-65 private keys in IndexedDB, encrypted with a WebAuthn-PRF-
// derived KEK (passkey -> HKDF-SHA256 -> AES-256-GCM). All WebCrypto-native, zero
// dependencies, same-origin only (loads under script-src 'self'). R018 v4: the
// passkey PRF is the only persisted unlock source; the passphrase wrap (PBKDF2)
// was removed (the non-PRF fallback is a TOTP-gated ephemeral key, never stored).
//
// Envelope layout:
//   {
//     id:          <pk_hash_sha3, used as IDB primary key>,
//     alg:         'ML-DSA-65',
//     label:       <string|null>,
//     pk_b64:      <public key, base64, plain (public)>,
//     pk_hash:     <SHA3-256 hex of the raw public key>,
//     enrolled_at: <ISO timestamp>,
//     wraps: [
//       { kekSource: 'webauthn-prf', credentialId, hkdf, info, prfSalt, iv, ciphertext }
//     ]
//   }
//
// The wraps array still allows multiple PRF KEK sources (e.g. several passkeys)
// to unwrap the same key without re-encrypting or migrating data.

const DB_NAME    = 'paramant';
const STORE_NAME = 'signing-keys';
const DB_VERSION = 1;
const KEK_NAME    = 'AES-GCM';
const KEK_BITS    = 256;
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

// Passphrase wraps were removed in R018 v4: the signing key is unlocked only by
// the passkey's WebAuthn-PRF (one tap), and the non-PRF fallback is a TOTP-gated
// ephemeral key that is never persisted here. assertStrongPassphrase / vaultStore
// / vaultUnlock (and the PBKDF2 KEK) are therefore gone — only PRF wraps remain.

// --- WebAuthn-PRF wrap (R018 / "PR 2"). The passkey's PRF output derives a KEK
//     (HKDF-SHA256, domain-separated, per-wrap random salt) that unwraps the
//     same ML-DSA secret key. ADDITIVE: the passphrase wrap is never touched, so
//     it remains the recovery floor (lockout invariant). PRF is never the sole
//     wrap. Per-wrap salt (not a fixed per-RP salt) so KEKs are independent.
async function _deriveKekFromPrf(prfOutput, hkdfSalt) {
  const ikm = await crypto.subtle.importKey('raw', prfOutput, { name: 'HKDF' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: new TextEncoder().encode('paramant/parasign/vault-kek/v1') },
    ikm,
    { name: KEK_NAME, length: KEK_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Return the prf wrap's { credentialId, prfSalt(b64) } so the caller can run the
// WebAuthn PRF eval with the SAME salt that was used at enrol (the PRF output is
// only reproducible for an identical (credential, salt)). Null if no prf wrap.
export async function vaultGetPrfWrapInfo(id, credentialId) {
  if (!id) throw new Error('vaultGetPrfWrapInfo: id required');
  const db = await vaultOpen();
  const entry = await _toPromise(_tx(db, 'readonly').get(id));
  db.close();
  if (!entry) return null;
  const matches = (entry.wraps || []).filter(w => w.kekSource === 'webauthn-prf' && (!credentialId || w.credentialId === credentialId));
  if (!matches.length) return null;
  const w = matches[matches.length - 1];
  return { credentialId: w.credentialId, prfSalt: w.prfSalt };
}

// Add (or replace, per credential) a webauthn-prf wrap. Requires the unlocked
// secretKeyBytes (caller obtained it during enrol or via a passphrase unlock)
// AND the SAME prfSalt the caller fed to the WebAuthn PRF eval to obtain
// prfOutput (the salt is stored so unlock can reproduce the PRF output).
export async function vaultAddPrfWrap({ pk_hash, secretKeyBytes, credentialId, prfSalt, prfOutput }) {
  if (!pk_hash || !(secretKeyBytes instanceof Uint8Array) || secretKeyBytes.length === 0) throw new Error('vaultAddPrfWrap: pk_hash + secretKeyBytes required');
  if (!credentialId || !(prfOutput instanceof Uint8Array) || prfOutput.length < 16) throw new Error('vaultAddPrfWrap: credentialId + prfOutput required');
  if (!(prfSalt instanceof Uint8Array) || prfSalt.length < 16) throw new Error('vaultAddPrfWrap: prfSalt (>=16 bytes, the WebAuthn PRF eval salt) required');
  const iv      = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const kek     = await _deriveKekFromPrf(prfOutput, prfSalt);
  const ct      = new Uint8Array(await crypto.subtle.encrypt({ name: KEK_NAME, iv }, kek, secretKeyBytes));
  const wrap = {
    kekSource: 'webauthn-prf', credentialId, hkdf: 'HKDF-SHA256',
    info: 'paramant/parasign/vault-kek/v1',
    prfSalt: b64Encode(prfSalt), iv: b64Encode(iv), ciphertext: b64Encode(ct),
  };
  const db = await vaultOpen();
  const store = _tx(db, 'readwrite');
  const entry = await _toPromise(store.get(pk_hash));
  if (!entry) { db.close(); throw new Error('no such key'); }
  entry.wraps = (entry.wraps || []).filter(w => !(w.kekSource === 'webauthn-prf' && w.credentialId === credentialId));
  entry.wraps.push(wrap);   // other PRF wraps left intact
  await _toPromise(store.put(entry));
  db.close();
  return { id: pk_hash, kekSources: entry.wraps.map(w => w.kekSource) };
}

// --- Create a NEW entry wrapped by a passkey PRF. This is the "your sign-in
//     passkey IS your signing key" path (ADR R018): the ML-DSA-65 key is generated
//     in the browser and the ONLY thing that can unwrap it is the account's passkey
//     PRF — there is no separate signing passphrase to choose, lose, or be phished
//     for. Recovery is the synced passkey itself (iCloud Keychain / Google Password
//     Manager) plus the ability to enrol a fresh key on a new device (the relay
//     keeps a multi-key, GitHub-SSH-style list, so old signatures stay verifiable).
export async function vaultCreatePrfOnly({ alg, label, pk_b64, pk_hash, secretKeyBytes, credentialId, prfSalt, prfOutput }) {
  if (!alg || !pk_b64 || !pk_hash) throw new Error('vaultCreatePrfOnly: alg, pk_b64, pk_hash required');
  if (!(secretKeyBytes instanceof Uint8Array) || secretKeyBytes.length === 0) throw new Error('vaultCreatePrfOnly: secretKeyBytes required');
  if (!credentialId || !(prfOutput instanceof Uint8Array) || prfOutput.length < 16) throw new Error('vaultCreatePrfOnly: credentialId + prfOutput required');
  if (!(prfSalt instanceof Uint8Array) || prfSalt.length < 16) throw new Error('vaultCreatePrfOnly: prfSalt (>=16 bytes, the WebAuthn PRF eval salt) required');

  const iv  = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const kek = await _deriveKekFromPrf(prfOutput, prfSalt);
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: KEK_NAME, iv }, kek, secretKeyBytes));
  const wrap = {
    kekSource: 'webauthn-prf', credentialId, hkdf: 'HKDF-SHA256',
    info: 'paramant/parasign/vault-kek/v1',
    prfSalt: b64Encode(prfSalt), iv: b64Encode(iv), ciphertext: b64Encode(ct),
  };

  const db = await vaultOpen();
  const store = _tx(db, 'readwrite');
  const existing = await _toPromise(store.get(pk_hash));
  const entry = existing ? { ...existing } : {
    id: pk_hash, alg, label: label || null, pk_b64, pk_hash,
    enrolled_at: new Date().toISOString(), wraps: [], last_used_at: null,
  };
  if (label) entry.label = label;
  // Replace any existing prf wrap for THIS credential; keep other PRF wraps intact.
  entry.wraps = (entry.wraps || []).filter(w => !(w.kekSource === 'webauthn-prf' && w.credentialId === credentialId));
  entry.wraps.push(wrap);
  await _toPromise(store.put(entry));
  db.close();
  return { id: entry.id, alg: entry.alg, label: entry.label, pk_hash: entry.pk_hash, enrolled_at: entry.enrolled_at, kekSources: entry.wraps.map(w => w.kekSource) };
}

// Unlock via the webauthn-prf wrap. Returns raw secretKeyBytes. The caller must
// zeroize them after signing (see parasign-signer.js dispose()).
export async function vaultUnlockPrf(id, { prfOutput, credentialId } = {}) {
  if (!id) throw new Error('vaultUnlockPrf: id required');
  if (!(prfOutput instanceof Uint8Array)) throw new Error('vaultUnlockPrf: prfOutput required');
  const db = await vaultOpen();
  const entry = await _toPromise(_tx(db, 'readonly').get(id));
  if (!entry) { db.close(); throw new Error('no such key'); }
  const matches = (entry.wraps || []).filter(w => w.kekSource === 'webauthn-prf' && (!credentialId || w.credentialId === credentialId));
  if (!matches.length) { db.close(); throw new Error('no prf wrap'); }
  const wrap = matches[matches.length - 1];
  const kek = await _deriveKekFromPrf(prfOutput, b64Decode(wrap.prfSalt));
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: KEK_NAME, iv: b64Decode(wrap.iv) }, kek, b64Decode(wrap.ciphertext)));
  } catch (e) { db.close(); throw new Error('prf unwrap failed'); }
  try { const rw = _tx(db, 'readwrite'); const fresh = await _toPromise(rw.get(id)); if (fresh) { fresh.last_used_at = new Date().toISOString(); await _toPromise(rw.put(fresh)); } } catch {}
  db.close();
  return { secretKeyBytes: plain, pk_b64: entry.pk_b64, pk_hash: entry.pk_hash, label: entry.label };
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
