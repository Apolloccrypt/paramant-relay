// The way back after making an account, for any page on this site (test with
// a stranger, 13-10-2026). A visitor who pressed "Kies Firm" or "Inloggen om
// te versturen" and had no account yet went to /signup, and /signup forgot
// where he came from: after two mails and the setup he stood on a welcome
// screen with no road back to the plan or the document he had chosen.
//
// Signing up takes two mails, and a link from a mail opens in a new tab, so
// sessionStorage is gone by then. This browser keeps, in localStorage, the
// path to go back to and nothing else, for 24 hours (as long as the
// confirmation link works). It is read on the setup page's welcome screen and
// on a later sign-in, and it goes once it is used.
//
// Only a path on this site is kept: it starts with exactly one slash, has no
// backslash, no scheme, no control characters, and resolves to this origin.
// /signup?next=//evil.example or /signup?next=https://evil.example is
// ignored, so this can never become an open redirect.
export const NEXT_KEY = 'paramant:signup-next';
export const NEXT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_LEN = 512;

export function safeLocalPath(p) {
  if (typeof p !== 'string' || !p || p.length > MAX_LEN) return null;
  if (!/^\/(?![/\\])/.test(p)) return null;
  if (/[\\\u0000-\u001f\u007f\s]/.test(p)) return null;
  try {
    const base = 'https://paramant.invalid';
    const u = new URL(p, base);
    if (u.origin !== base) return null;
    return u.pathname + u.search;
  } catch { return null; }
}

function read(storage, now) {
  let rec = null;
  try { rec = JSON.parse(storage.getItem(NEXT_KEY) || 'null'); } catch { rec = null; }
  const path = rec && typeof rec === 'object' ? safeLocalPath(rec.path) : null;
  const ok = path && path === rec.path && Number(rec.exp) > now && Number(rec.exp) <= now + NEXT_MAX_AGE_MS;
  if (!ok) {
    try { if (rec !== null) storage.removeItem(NEXT_KEY); } catch { /* storage off */ }
    return null;
  }
  return path;
}

// Keeps `next` when it is a path on this site. Returns the path kept, or null.
export function stashSignupNext(storage, next, now = Date.now()) {
  const path = safeLocalPath(next);
  if (!path) return null;
  try {
    storage.setItem(NEXT_KEY, JSON.stringify({ path, exp: now + NEXT_MAX_AGE_MS }));
    return read(storage, now);
  } catch { return null; }
}

// The path to go back to, or null. Reads only.
export function signupNextPath(storage, now = Date.now()) {
  return read(storage, now);
}

// The path, once: the record goes as it is read.
export function takeSignupNext(storage, now = Date.now()) {
  const path = read(storage, now);
  try { storage.removeItem(NEXT_KEY); } catch { /* storage off */ }
  return path;
}

// A buyer who came from the price page reads that he pays after the account
// exists; anyone else reads that he goes back to where he was.
export function isPricingPath(path) {
  return /^\/(en\/)?pricing(\?|$)/.test(String(path || ''));
}
