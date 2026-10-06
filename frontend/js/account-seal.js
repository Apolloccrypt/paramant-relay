// Small secrets kept in THIS browser, sealed under a key of the ACCOUNT.
//
// Three things are kept in localStorage so a link can be sent again later:
// the signer's half of the document key (cosign-share-memory.js), the
// sender's signing links with half A of the key (sign-flow.js
// rememberSignerLinks) and the recipients' links of a send by name
// (parashare.page.js rememberSendLinks). None of them may sit there readable
// (review #573, M4): a shared computer with an open browser profile would hand
// them to whoever looks.
//
// So they are sealed with AES-GCM under the same account key as the /sign
// draft (GET /api/user/sign-draft-key, sign-draft.js): derived per account by
// the server, held in memory only, never next to what it seals. Another
// account in this browser gets another key and opens nothing; nav-auth.js
// wipes the records then, on sign-out, and when they expire (at most eight
// days, checked on every page load). The purpose and the storage name are
// bound in as additional data, so a record cannot be moved to another slot.
//
// Only the expiry stays readable, for that sweep.

export const SEAL_MAX_MS = 8 * 864e5;

let keyPromise = null;
async function accountKey(fetcher = fetch) {
  if (!keyPromise) {
    keyPromise = (async () => {
      try {
        const r = await fetcher('/api/user/sign-draft-key', { credentials: 'include', cache: 'no-store' });
        if (!r.ok) return null;
        const { key } = await r.json();
        const raw = Uint8Array.from(atob(String(key).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
        if (raw.length !== 32) return null;
        const k = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        raw.fill(0);
        return k;
      } catch { return null; }
    })();
  }
  const k = await keyPromise;
  if (!k) keyPromise = null; // no session yet: ask again next time
  return k;
}

// For tests: start over with another fetcher.
export function resetAccountKey() { keyPromise = null; }

function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function unb64(s) { return Uint8Array.from(atob(String(s || '')), (c) => c.charCodeAt(0)); }
const enc = new TextEncoder();
const dec = new TextDecoder();

// Seal `value` (any JSON) under `name` until `exp` (ms). False when there is no
// account key (not signed in) or storage is off: then nothing is kept at all.
export async function sealPut(name, value, exp, { now = Date.now(), fetcher } = {}) {
  const until = Math.min(Number(exp) || 0, now + SEAL_MAX_MS);
  if (!(until > now)) return false;
  const key = await accountKey(fetcher);
  if (!key) return false;
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode('paramant-seal-v2:' + name + ':' + until) },
      key, enc.encode(JSON.stringify(value))));
    localStorage.setItem(name, JSON.stringify({ v: 2, exp: until, iv: b64(iv), ct: b64(ct) }));
    return true;
  } catch { return false; }
}

// The value, or null (none, expired, older than eight days, readable old
// form, another account, tampered). Everything but "no key yet" is wiped.
export async function sealGet(name, { now = Date.now(), fetcher } = {}) {
  let rec = null;
  try { rec = JSON.parse(localStorage.getItem(name) || 'null'); } catch { rec = undefined; }
  if (rec === null) return null;
  const wipe = () => { try { localStorage.removeItem(name); } catch { /* storage off */ } return null; };
  if (!rec || rec.v !== 2 || !(now < Number(rec.exp)) || Number(rec.exp) > now + SEAL_MAX_MS) return wipe();
  const key = await accountKey(fetcher);
  if (!key) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(rec.iv), additionalData: enc.encode('paramant-seal-v2:' + name + ':' + Number(rec.exp)) },
      key, unb64(rec.ct));
    return JSON.parse(dec.decode(new Uint8Array(pt)));
  } catch { return wipe(); }
}

export function sealDel(name) { try { localStorage.removeItem(name); } catch { /* storage off */ } }
