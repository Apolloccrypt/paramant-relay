const RELAY_BASE  = 'https://relay.paramant.app';
const ADMIN_BASE  = 'https://paramant.app/api/user';
const STORAGE_KEY = 'paramant_api_key';

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

  const until = Date.now() + 8 * 60 * 60 * 1000; // 8h UX session
  await chrome.storage.local.set({
    [STORAGE_KEY]: apikey,
    auth_mode: 'apikey',
    auth_email: data.email || null,
    auth_until: until,
  });

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
  await chrome.storage.local.set({
    auth_mode: 'totp',
    auth_email: data.email,
    auth_until: new Date(data.session_expires_at).getTime(),
  });

  return {
    success: true,
    mode: 'totp',
    email: data.email,
    expires_at: data.session_expires_at,
  };
}

// ── Session ───────────────────────────────────────────────────────────────────

export async function verifySession() {
  const stored = await chrome.storage.local.get([
    'auth_mode', 'auth_email', 'auth_until', STORAGE_KEY,
  ]);

  if (!stored.auth_mode) return { authenticated: false };

  if (stored.auth_until && Date.now() > stored.auth_until) {
    await chrome.storage.local.clear();
    return { authenticated: false };
  }

  if (stored.auth_mode === 'apikey') {
    return {
      authenticated: true,
      mode: 'apikey',
      email: stored.auth_email,
      expires_at: new Date(stored.auth_until).toISOString(),
    };
  }

  if (stored.auth_mode === 'totp') {
    try {
      const res = await fetch(`${ADMIN_BASE}/session/verify`, { credentials: 'include' });
      if (!res.ok) {
        await chrome.storage.local.clear();
        return { authenticated: false };
      }
      return await res.json();
    } catch {
      return { authenticated: false };
    }
  }

  return { authenticated: false };
}

// ── Logout ────────────────────────────────────────────────────────────────────

export async function logout() {
  const { auth_mode } = await chrome.storage.local.get('auth_mode');

  if (auth_mode === 'totp') {
    try {
      await fetch(`${ADMIN_BASE}/logout`, { method: 'POST', credentials: 'include' });
    } catch {}
  }

  await chrome.storage.local.clear();
  return { success: true };
}

// ── Upload ────────────────────────────────────────────────────────────────────

export async function uploadFile(fileData, metadata) {
  const stored = await chrome.storage.local.get(['auth_mode', STORAGE_KEY]);

  if (!stored.auth_mode) return { success: false, message: 'not_authenticated' };

  const body = JSON.stringify({
    payload: arrayBufferToBase64(fileData),
    metadata,
    ttl_ms: 24 * 60 * 60 * 1000,
  });

  let res;
  if (stored.auth_mode === 'apikey') {
    res = await fetch(`${RELAY_BASE}/v2/inbound`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': stored[STORAGE_KEY] },
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

  if (!res.ok) return { success: false, message: 'upload_failed' };

  const data = await res.json();
  return { success: true, share_url: data.share_url, expires_at: data.expires_at };
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
