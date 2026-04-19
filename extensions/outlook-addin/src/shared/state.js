const AUTH_KEY = 'paramant_auth';

export function setAuth(data) {
  try {
    localStorage.setItem(AUTH_KEY, JSON.stringify(data));
  } catch {}
}

export function getAuth() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function clearAuth() {
  try {
    localStorage.removeItem(AUTH_KEY);
  } catch {}
}
