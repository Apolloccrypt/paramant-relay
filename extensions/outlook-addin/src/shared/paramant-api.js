// paramant-api.js — auth + real encrypt/upload for the Outlook add-in taskpane.
//
// The taskpane is a hosted page on a paramant.app origin, so it can POST to the relay
// directly (CORS allows *.paramant.app) and runs the shared core itself: the whole
// attachment is available in memory from Office.js, so encryptAndUpload() chunks, encrypts
// (AES-256-GCM, key in the URL fragment), uploads, and returns a burn-on-read link that the
// paramant.app/get receiver already understands.

import { discoverRelay, checkKey, encryptAndUpload, DEFAULT_RELAY, RATE_LIMITED_MESSAGE } from '../../../shared/paramant-core.js';
import { setAuth, getAuth, clearAuth } from './state.js';
import { getAttachmentContent } from './office-helpers.js';

const SESSION_HOURS = 8;
const ADMIN_BASE = 'https://paramant.app/api/user';

// ── Capabilities ──────────────────────────────────────────────────────────────────
export async function getCapabilities() {
  try {
    const res = await fetch(`${DEFAULT_RELAY}/v2/auth/capabilities`);
    if (!res.ok) return { api_key: true, user_totp: false };
    return await res.json();
  } catch {
    return { api_key: true, user_totp: false };
  }
}

// ── API key auth ────────────────────────────────────────────────────────────────────
export async function loginWithApiKey(apikey) {
  const key = (apikey || '').trim();
  if (!key) return { success: false, message: 'Enter your API key.' };
  try {
    const relay = await discoverRelay(key);
    const { valid, plan, rateLimited } = await checkKey(relay, key);
    if (rateLimited) return { success: false, message: RATE_LIMITED_MESSAGE };
    if (!valid) return { success: false, message: 'Invalid API key.' };

    const until = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
    setAuth({ mode: 'apikey', apikey: key, plan: plan || null, relay, until });
    return { success: true, mode: 'apikey', plan: plan || null, relay, expires_at: new Date(until).toISOString() };
  } catch (err) {
    if (err?.code === 'rate_limited') return { success: false, message: RATE_LIMITED_MESSAGE };
    return { success: false, message: 'Network error. Check your connection.' };
  }
}

// ── E-mail + authenticator code ─────────────────────────────────────────────────────
// The pane runs on addin.paramant.app. The account server answers that origin,
// with credentials, on exactly the routes used here: /user/login,
// /user/session/verify, /user/parasend/token and /user/logout (admin/server.js
// ADDIN_CORS_PATHS). Until that existed the sign-in ended in "Network error"
// (fase 1, EXT-20-A). The session itself is the paramant.app cookie; the pane
// keeps only the e-mail address and the end time.
//
// A session holds no API key and must not. Uploads ask the account for the same
// fifteen-minute ParaSend session token /parashare uses and send it as a Bearer
// to the relay of the account's sector (mintSessionToken says which).
export async function loginWithTotp(email, totp) {
  const e = String(email || '').trim();
  const code = String(totp || '').replace(/\s+/g, '');
  if (!e || !/^\d{6}$/.test(code)) return { success: false, message: 'Enter your e-mail address and the 6-digit code.' };
  let res;
  try {
    res = await fetch(`${ADMIN_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: e, totp: code }),
      credentials: 'include',
    });
  } catch {
    return { success: false, message: 'Network error. Check your connection.' };
  }
  const data = await res.json().catch(() => ({}));
  if (res.status === 429) return { success: false, message: RATE_LIMITED_MESSAGE };
  if (!res.ok) {
    if (data.error === 'pow_required') return { success: false, message: 'Too many attempts from this address. Sign in once on paramant.app, then try again here.' };
    return { success: false, message: data.message || 'Invalid e-mail or code.' };
  }
  const until = data.session_expires_at ? new Date(data.session_expires_at).getTime() : Date.now() + 3600e3;
  setAuth({ mode: 'totp', email: data.email || e, until });
  return { success: true, mode: 'totp', email: data.email || e, expires_at: new Date(until).toISOString() };
}

const SECTOR_RELAYS = {
  health: 'https://health.paramant.app', legal: 'https://legal.paramant.app',
  finance: 'https://finance.paramant.app', iot: 'https://iot.paramant.app',
  main: 'https://relay.paramant.app', relay: 'https://relay.paramant.app',
};
export function relayForSector(sector) {
  return SECTOR_RELAYS[String(sector || '').toLowerCase()] || 'https://health.paramant.app';
}
let cachedToken = null; // { token, relay, exp } in memory only

// A fresh ParaSend session token for the signed-in account, or null when the
// session is gone. Throws with a readable message on anything else.
export async function sessionToken() {
  if (cachedToken && Date.now() < cachedToken.exp - 60_000) return cachedToken;
  let res;
  try {
    res = await fetch(`${ADMIN_BASE}/parasend/token`, { method: 'POST', credentials: 'include' });
  } catch {
    throw new Error('Network error. Check your connection.');
  }
  if (res.status === 401) { cachedToken = null; clearAuth(); return null; }
  if (!res.ok) throw new Error(res.status === 429 ? RATE_LIMITED_MESSAGE : 'Upload failed. Please try again.');
  const d = await res.json().catch(() => ({}));
  if (!d.token) throw new Error('Upload failed. Please try again.');
  cachedToken = { token: d.token, relay: relayForSector(d.sector), exp: Date.now() + (Number(d.expires_in_s) || 900) * 1000 };
  return cachedToken;
}

// ── Session ──────────────────────────────────────────────────────────────────────────
export async function verifySession() {
  const auth = getAuth();
  if (!auth) return { authenticated: false };
  if (auth.until && Date.now() > auth.until) { clearAuth(); return { authenticated: false }; }

  if (auth.mode === 'apikey') {
    return { authenticated: true, mode: 'apikey', plan: auth.plan || null, expires_at: new Date(auth.until).toISOString() };
  }
  if (auth.mode === 'totp') {
    try {
      const res = await fetch(`${ADMIN_BASE}/session/verify`, { credentials: 'include' });
      if (!res.ok) { clearAuth(); return { authenticated: false }; }
      const d = await res.json().catch(() => ({}));
      return { authenticated: true, mode: 'totp', email: d.email || auth.email, expires_at: new Date(auth.until).toISOString() };
    } catch {
      return { authenticated: false };
    }
  }
  clearAuth();
  return { authenticated: false };
}

export async function logout() {
  const auth = getAuth();
  cachedToken = null;
  if (auth?.mode === 'totp') {
    try { await fetch(`${ADMIN_BASE}/logout`, { method: 'POST', credentials: 'include' }); } catch {}
  }
  clearAuth();
}

// ── Upload one attachment ──────────────────────────────────────────────────────────
// opts: { ttlMs, deviceId?, onProgress? }
export async function uploadAttachment(att, opts) {
  const auth = getAuth();
  let creds;
  if (auth?.mode === 'apikey' && auth.apikey) {
    creds = { apiKey: auth.apikey, relay: auth.relay || DEFAULT_RELAY };
  } else if (auth?.mode === 'totp') {
    try {
      const tok = await sessionToken();
      if (!tok) return { success: false, message: 'not_authenticated' };
      creds = { relay: tok.relay, getBearer: async () => (await sessionToken())?.token };
    } catch (err) {
      return { success: false, message: String(err?.message || err) };
    }
  } else {
    return { success: false, message: 'not_authenticated' };
  }

  let bytes;
  try {
    bytes = base64ToBytes(await getAttachmentContent(att.id));
  } catch {
    return { success: false, message: 'Could not read the attachment.' };
  }

  try {
    const result = await encryptAndUpload({
      bytes, fileName: att.name, fileSize: bytes.length,
      ...creds,
      ttlMs: opts.ttlMs, deviceId: opts.deviceId || 'paramant-outlook',
      onProgress: opts.onProgress,
    });
    return { success: true, shareUrl: result.shareUrl, expiresAt: result.expiresAt, totalChunks: result.totalChunks };
  } catch (err) {
    // Monthly transfer quota (HTTP 402): carry the structured fields through so the
    // taskpane renders a real upgrade notice instead of a bare failure string.
    if (err?.code === 'quota_reached') {
      return {
        success: false, code: 'quota_reached', message: String(err.message || ''),
        plan: err.plan ?? null, limit: err.limit ?? null,
        upgradeUrl: err.upgradeUrl || 'https://paramant.app/pricing',
      };
    }
    return { success: false, message: String(err?.message || err) };
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
