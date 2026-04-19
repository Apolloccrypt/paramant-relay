// auth-client.js — wraps paramant.app /api/user/* endpoints
// MOCK MODE: set USE_MOCK = false when Track A PR 5 is live
// At that point, remove everything inside the `if (USE_MOCK)` blocks.

const USE_MOCK = true;

const API_BASE   = 'https://paramant.app/api/user';
const RELAY_BASE = 'https://paramant.app';

// ── Mock helpers ─────────────────────────────────────────────────────────────

function mockSession(email) {
  return {
    authenticated: true,
    email,
    expires_at: new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
  };
}

// ── Auth functions ────────────────────────────────────────────────────────────

export async function loginWithTotp(email, totp) {
  if (USE_MOCK) {
    // Accept any 6-digit code; reject anything else so the error path is testable
    if (/^\d{6}$/.test(totp)) {
      await chrome.storage.local.set({ mockEmail: email });
      return { success: true, ...mockSession(email) };
    }
    return { success: false, error: 'invalid_totp', message: 'Invalid code (mock: use any 6 digits).' };
  }

  const res = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, totp }),
    credentials: 'include',
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return { success: false, error: err.error, message: err.message ?? 'Login failed.' };
  }

  const data = await res.json();
  return { success: true, email: data.email, expires_at: data.session_expires_at };
}

export async function verifySession() {
  if (USE_MOCK) {
    const { mockEmail } = await chrome.storage.local.get('mockEmail');
    if (!mockEmail) return { authenticated: false };
    return mockSession(mockEmail);
  }

  try {
    const res = await fetch(`${API_BASE}/session/verify`, { credentials: 'include' });
    if (!res.ok) return { authenticated: false };
    return await res.json();
  } catch {
    return { authenticated: false };
  }
}

export async function logout() {
  if (USE_MOCK) {
    await chrome.storage.local.remove('mockEmail');
    return { success: true };
  }

  await fetch(`${API_BASE}/logout`, { method: 'POST', credentials: 'include' });
  return { success: true };
}

export async function uploadFile(fileData, metadata) {
  if (USE_MOCK) {
    // Simulate a 600 ms upload delay, return a fake share URL
    await new Promise(r => setTimeout(r, 600));
    const id = Math.random().toString(36).slice(2, 10);
    return {
      success: true,
      share_url: `https://paramant.app/get/${id}#mockkey`,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  const res = await fetch(`${RELAY_BASE}/v2/inbound`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payload: arrayBufferToBase64(fileData),
      metadata,
      ttl_ms: 24 * 60 * 60 * 1000,
    }),
  });

  if (!res.ok) return { success: false, error: 'upload_failed' };

  const data = await res.json();
  return { success: true, share_url: data.share_url, expires_at: data.expires_at };
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
