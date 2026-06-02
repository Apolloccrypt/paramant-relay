// paramant-api.js — auth + real encrypt/upload for the Outlook add-in taskpane.
//
// The taskpane is a hosted page on a paramant.app origin, so it can POST to the relay
// directly (CORS allows *.paramant.app) and runs the shared core itself: the whole
// attachment is available in memory from Office.js, so encryptAndUpload() chunks, encrypts
// (AES-256-GCM, key in the URL fragment), uploads, and returns a burn-on-read link that the
// paramant.app/parashare receiver already understands.

import { discoverRelay, checkKey, encryptAndUpload, DEFAULT_RELAY } from '../../../shared/paramant-core.js';
import { setAuth, getAuth, clearAuth } from './state.js';
import { getAttachmentContent } from './office-helpers.js';

const ADMIN_BASE = 'https://paramant.app/api/user';
const SESSION_HOURS = 8;

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
    const { valid, plan } = await checkKey(relay, key);
    if (!valid) return { success: false, message: 'Invalid API key.' };

    const until = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
    setAuth({ mode: 'apikey', apikey: key, plan: plan || null, relay, until });
    return { success: true, mode: 'apikey', plan: plan || null, relay, expires_at: new Date(until).toISOString() };
  } catch {
    return { success: false, message: 'Network error. Check your connection.' };
  }
}

// ── TOTP auth (dormant until the relay enables it) ──────────────────────────────────
export async function loginWithTotp(email, totp) {
  let res;
  try {
    res = await fetch(`${ADMIN_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, totp }),
      credentials: 'include',
    });
  } catch {
    return { success: false, message: 'Network error. Check your connection.' };
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return { success: false, message: err.message || 'Invalid email or code.' };
  }
  const data = await res.json();
  setAuth({ mode: 'totp', email: data.email, until: new Date(data.session_expires_at).getTime() });
  return { success: true, mode: 'totp', email: data.email };
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
      return await res.json();
    } catch { return { authenticated: false }; }
  }
  return { authenticated: false };
}

export async function logout() {
  const auth = getAuth();
  if (auth?.mode === 'totp') {
    try { await fetch(`${ADMIN_BASE}/logout`, { method: 'POST', credentials: 'include' }); } catch {}
  }
  clearAuth();
}

// ── Upload one attachment ──────────────────────────────────────────────────────────
// opts: { ttlMs, deviceId?, onProgress? }
export async function uploadAttachment(att, opts) {
  const auth = getAuth();
  if (auth?.mode !== 'apikey' || !auth.apikey) return { success: false, message: 'not_authenticated' };

  let bytes;
  try {
    bytes = base64ToBytes(await getAttachmentContent(att.id));
  } catch {
    return { success: false, message: 'Could not read the attachment.' };
  }

  try {
    const result = await encryptAndUpload({
      bytes, fileName: att.name, fileSize: bytes.length,
      apiKey: auth.apikey, relay: auth.relay || DEFAULT_RELAY,
      ttlMs: opts.ttlMs, deviceId: opts.deviceId || 'paramant-outlook',
      onProgress: opts.onProgress,
    });
    return { success: true, shareUrl: result.shareUrl, expiresAt: result.expiresAt, totalChunks: result.totalChunks };
  } catch (err) {
    return { success: false, message: String(err?.message || err) };
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
