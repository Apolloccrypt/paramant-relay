import { setAuth, getAuth, clearAuth } from './state.js';
import { getAttachmentContent } from './office-helpers.js';

const RELAY_BASE = 'https://relay.paramant.app';
const ADMIN_BASE = 'https://paramant.app/api/user';

// ── Capabilities ──────────────────────────────────────────────────────────────

export async function getCapabilities() {
  try {
    const res = await fetch(`${RELAY_BASE}/v2/auth/capabilities`);
    if (!res.ok) return { api_key: true, user_totp: false };
    return await res.json();
  } catch {
    return { api_key: true, user_totp: false };
  }
}

// ── API key auth ──────────────────────────────────────────────────────────────

export async function loginWithApiKey(apikey) {
  let res;
  try {
    res = await fetch(`${RELAY_BASE}/v2/check-key`, {
      method: 'POST',
      headers: { 'X-Api-Key': apikey, 'Content-Type': 'application/json' },
    });
  } catch {
    return { success: false, message: 'Network error. Check your connection.' };
  }

  if (!res.ok) return { success: false, message: 'Invalid API key' };

  const data = await res.json();
  if (!data.valid) return { success: false, message: 'Invalid API key' };

  const until = Date.now() + 8 * 60 * 60 * 1000;
  setAuth({ mode: 'apikey', apikey, email: data.email || null, until });

  return {
    success: true,
    mode: 'apikey',
    email: data.email || null,
    expires_at: new Date(until).toISOString(),
  };
}

// ── TOTP auth ─────────────────────────────────────────────────────────────────

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
  setAuth({
    mode: 'totp',
    email: data.email,
    until: new Date(data.session_expires_at).getTime(),
  });

  return { success: true, mode: 'totp', email: data.email };
}

// ── Session ───────────────────────────────────────────────────────────────────

export async function verifySession() {
  const auth = getAuth();
  if (!auth) return { authenticated: false };

  if (auth.until && Date.now() > auth.until) {
    clearAuth();
    return { authenticated: false };
  }

  if (auth.mode === 'apikey') {
    return { authenticated: true, mode: 'apikey', email: auth.email };
  }

  if (auth.mode === 'totp') {
    try {
      const res = await fetch(`${ADMIN_BASE}/session/verify`, { credentials: 'include' });
      if (!res.ok) { clearAuth(); return { authenticated: false }; }
      return await res.json();
    } catch {
      return { authenticated: false };
    }
  }

  return { authenticated: false };
}

// ── Logout ────────────────────────────────────────────────────────────────────

export async function logout() {
  const auth = getAuth();
  if (auth?.mode === 'totp') {
    try {
      await fetch(`${ADMIN_BASE}/logout`, { method: 'POST', credentials: 'include' });
    } catch {}
  }
  clearAuth();
}

// ── Upload ────────────────────────────────────────────────────────────────────

export async function uploadAttachment(att, opts) {
  const auth = getAuth();
  if (!auth) return { success: false, message: 'not_authenticated' };

  const content = await getAttachmentContent(att.id); // base64

  const body = JSON.stringify({
    payload: content,
    metadata: {
      filename: att.name,
      content_type: att.contentType,
      size: att.size,
    },
    ttl_ms: opts.ttl_seconds * 1000,
  });

  let res;
  if (auth.mode === 'apikey') {
    res = await fetch(`${RELAY_BASE}/v2/inbound`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': auth.apikey },
      body,
    });
  } else {
    res = await fetch('https://paramant.app/api/relay/v2/inbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body,
    });
  }

  if (!res.ok) return { success: false };
  const data = await res.json();
  return { success: true, share_url: data.share_url, expires_at: data.expires_at };
}
