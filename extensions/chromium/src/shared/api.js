// api.js — fetch wrapper with session awareness
// Used by service worker; not imported from content scripts.

export async function apiFetch(path, options = {}) {
  const url = `https://paramant.app${path}`;
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw Object.assign(new Error(body.message ?? res.statusText), { status: res.status, body });
  }

  return res.json();
}
