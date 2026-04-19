import { getAttachmentContent } from './office-helpers.js';

const API_BASE = 'https://paramant.app/api/user';
const RELAY_BASE = 'https://paramant.app/api/relay/v2';

export async function login(email, totp) {
  const res = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, totp }),
    credentials: 'include',
  });

  if (res.ok) {
    const data = await res.json();
    return { success: true, email: data.email };
  }
  const err = await res.json();
  return { success: false, error: err.error, message: err.message };
}

export async function verifySession() {
  try {
    const res = await fetch(`${API_BASE}/session/verify`, { credentials: 'include' });
    if (!res.ok) return { authenticated: false };
    return await res.json();
  } catch {
    return { authenticated: false };
  }
}

export async function logout() {
  await fetch(`${API_BASE}/logout`, { method: 'POST', credentials: 'include' });
}

export async function uploadAttachment(att, opts) {
  const content = await getAttachmentContent(att.id); // base64

  const res = await fetch(`${RELAY_BASE}/inbound`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payload: content,
      metadata: {
        filename: att.name,
        content_type: att.contentType,
        size: att.size,
      },
      ttl_ms: opts.ttl_seconds * 1000,
    }),
  });

  if (!res.ok) return { success: false };
  const data = await res.json();
  return { success: true, share_url: data.share_url, expires_at: data.expires_at };
}
