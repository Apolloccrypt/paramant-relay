const KEY = 'paramant_session';

export function saveSession(email) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ email }));
  } catch {
    // sessionStorage not available in some Office contexts
  }
}

export function loadSession() {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function clearSession() {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // ignore
  }
}
