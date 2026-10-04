// auth-client.js — authentication + session for the service worker.
//
// Live path: API key. The key is validated against the relay sector it belongs to
// (discoverRelay races /v2/check-key across the sectored relays) and the resolved relay is
// cached on the session so uploads don't repeat the fan-out. /v2/check-key returns
// { valid, plan } — there is no email field, so we surface the plan instead.
//
// TOTP (email + authenticator) sits behind the server capability flag; the UI only shows
// it when the relay advertises it. Uploads on a TOTP session use a ParaSend session token,
// see getUploadCredentials.

import { discoverRelay, checkKey, DEFAULT_RELAY, RATE_LIMITED_MESSAGE } from '../../../shared/paramant-core.js';
import { getSettings } from '../shared/settings.js';

const ADMIN_BASE   = 'https://paramant.app/api/user';
const SESSION_HOURS = 8;

// ── Capabilities (public) ───────────────────────────────────────────────────────

export async function getCapabilities() {
  try {
    const res = await fetch(`${DEFAULT_RELAY}/v2/auth/capabilities`);
    if (!res.ok) return { api_key: true, user_totp: false };
    return await res.json();
  } catch {
    return { api_key: true, user_totp: false };
  }
}

// ── API key auth ──────────────────────────────────────────────────────────────────

export async function loginWithApiKey(apikey) {
  const key = (apikey || '').trim();
  if (!key) return { success: false, message: 'Enter your API key.' };

  let relay;
  try {
    const { relay_override } = await getSettings();
    relay = await discoverRelay(key, relay_override || undefined);
    const { valid, plan, rateLimited } = await checkKey(relay, key);
    if (rateLimited) return { success: false, message: RATE_LIMITED_MESSAGE };
    if (!valid) return { success: false, message: 'Invalid API key.' };

    const until = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
    await chrome.storage.local.set({
      auth_mode: 'apikey', auth_apikey: key, auth_plan: plan || null,
      auth_relay: relay, auth_until: until, auth_email: null,
    });
    return { success: true, mode: 'apikey', plan: plan || null, relay, expires_at: new Date(until).toISOString() };
  } catch (err) {
    if (err?.code === 'rate_limited') return { success: false, message: RATE_LIMITED_MESSAGE };
    return { success: false, message: 'Network error. Check your connection.' };
  }
}

// ── TOTP auth (shown when the relay advertises user_totp) ───────────────────────────

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
  await chrome.storage.local.set({
    auth_mode: 'totp', auth_email: data.email, auth_until: new Date(data.session_expires_at).getTime(),
  });
  return { success: true, mode: 'totp', email: data.email, expires_at: data.session_expires_at };
}

// ── Session ────────────────────────────────────────────────────────────────────────

export async function verifySession() {
  const s = await chrome.storage.local.get([
    'auth_mode', 'auth_apikey', 'auth_plan', 'auth_relay', 'auth_email', 'auth_until',
  ]);
  if (!s.auth_mode) return { authenticated: false };
  if (s.auth_until && Date.now() > s.auth_until) {
    await clearAuth();
    return { authenticated: false };
  }

  if (s.auth_mode === 'apikey') {
    // Must mirror getUploadCredentials' definition of "signed in": without the stored key,
    // the popup would show "signed in" while every upload fails with not_authenticated. If a
    // stale session is missing the key, clear it so the popup prompts a fresh sign-in.
    if (!s.auth_apikey) { await clearAuth(); return { authenticated: false }; }
    return {
      authenticated: true, mode: 'apikey', plan: s.auth_plan || null, relay: s.auth_relay,
      expires_at: new Date(s.auth_until).toISOString(),
    };
  }

  if (s.auth_mode === 'totp') {
    try {
      const res = await fetch(`${ADMIN_BASE}/session/verify`, { credentials: 'include' });
      if (!res.ok) { await clearAuth(); return { authenticated: false }; }
      return await res.json();
    } catch {
      return { authenticated: false };
    }
  }
  return { authenticated: false };
}

// Returns the credentials uploads need, or null when not signed in.
//
// Two shapes: { apikey, relay } for a key session, { bearer, relay } for an
// e-mail + code session. The second one used to be null, so a TOTP sign-in said
// "Signed in" in the popup while every upload answered "Sign in to Paramant"
// (fase 1, EXT-03-A). A TOTP session holds no API key, and must not: it asks
// the account for the same short-lived ParaSend session token /parashare uses
// (POST /api/user/parasend/token, fifteen minutes, five transfer routes), and
// uploads with that as a Bearer. The token is minted on the health relay, so
// that is where it is used.
export const SESSION_TOKEN_URL = `${ADMIN_BASE}/parasend/token`;
export const SESSION_TOKEN_RELAY = 'https://health.paramant.app';
const TOKEN_MARGIN_MS = 60_000;
let cachedToken = null; // { token, exp } in memory only; an evicted worker mints anew

export async function getUploadCredentials() {
  const s = await chrome.storage.local.get(['auth_mode', 'auth_apikey', 'auth_relay', 'auth_until']);
  if (s.auth_until && Date.now() > s.auth_until) { await clearAuth(); return null; }
  if (s.auth_mode === 'apikey') {
    if (!s.auth_apikey) return null;
    return { apikey: s.auth_apikey, relay: s.auth_relay || DEFAULT_RELAY };
  }
  if (s.auth_mode === 'totp') {
    if (cachedToken && Date.now() < cachedToken.exp - TOKEN_MARGIN_MS) {
      return { bearer: cachedToken.token, relay: SESSION_TOKEN_RELAY };
    }
    let res;
    try {
      res = await fetch(SESSION_TOKEN_URL, { method: 'POST', credentials: 'include' });
    } catch {
      throw new Error('network');
    }
    if (res.status === 401) { await clearAuth(); return null; }
    if (!res.ok) throw new Error(res.status === 429 ? 'Too many attempts. Wait a minute and try again.' : 'Upload failed. Please try again.');
    const d = await res.json().catch(() => ({}));
    if (!d.token) throw new Error('Upload failed. Please try again.');
    cachedToken = { token: d.token, exp: Date.now() + (Number(d.expires_in_s) || 900) * 1000 };
    return { bearer: d.token, relay: SESSION_TOKEN_RELAY };
  }
  return null;
}

// ── Logout ──────────────────────────────────────────────────────────────────────────

export async function logout() {
  const { auth_mode } = await chrome.storage.local.get('auth_mode');
  if (auth_mode === 'totp') {
    try { await fetch(`${ADMIN_BASE}/logout`, { method: 'POST', credentials: 'include' }); } catch {}
  }
  await clearAuth();
  return { success: true };
}

async function clearAuth() {
  cachedToken = null;
  await chrome.storage.local.remove([
    'auth_mode', 'auth_apikey', 'auth_plan', 'auth_relay', 'auth_email', 'auth_until',
  ]);
}
