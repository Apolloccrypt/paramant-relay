// The way back after signing in, without a secret in a query.
//
// The invite link carries the invite token in ?t= and (half of) the document
// key in the #fragment. Putting both into /auth/login?return=... turned the
// fragment into a query: it reached the server and its access log, which the
// fragment never does. So the full address stays in this tab's sessionStorage,
// the login page only gets `<path>?resume=1`, and the page puts the address
// back (history.replaceState, nothing is sent) when it loads again.
const KEY = 'paramant:login-return';
const MAX_AGE_MS = 60 * 60 * 1000;

// Returns the path for ?return=. With no usable storage the reader still gets
// back to the page, without the token or key; the page then says the link is
// incomplete, and the invite mail has the whole link. Nothing secret leaks.
export function stashReturn(storage, loc, now = Date.now()) {
  const path = loc.pathname;
  try {
    storage.setItem(KEY, JSON.stringify({ path, url: loc.pathname + loc.search + loc.hash, at: now }));
  } catch { return path; }
  return path + '?resume=1';
}

// Puts the stashed address back when this page was reached through ?resume=1.
// Only on the same path, only once, only within the hour. Returns true when
// the address was restored.
export function resumeReturn(storage, loc, hist, now = Date.now(), key = KEY, maxAge = MAX_AGE_MS) {
  if (new URLSearchParams(loc.search).get('resume') !== '1') return false;
  let rec = null;
  try { rec = JSON.parse(storage.getItem(key) || 'null'); if (rec) storage.removeItem(key); } catch { rec = null; }
  if (!rec || rec.path !== loc.pathname || typeof rec.url !== 'string') return false;
  if (!(now - Number(rec.at) < maxAge)) return false;
  if (!rec.url.startsWith(loc.pathname)) return false;
  hist.replaceState(hist.state, '', rec.url);
  return true;
}

// The way back after making an account (acceptance r5, A). Signing up takes
// two mails (confirm, then the setup link), and a link from a mail opens in a
// new tab, where this tab's sessionStorage is gone. So this one address waits
// in localStorage, for as long as the confirmation link works (24 hours), and
// only until it is used: the setup page reads the path, the co-sign page puts
// the address back and removes it. Like the key half this browser already
// keeps per request (cosign-share-memory.js) it is never sent to us; it is
// stored only when the reader clicks "Maak er gratis een".
export const SIGNUP_KEY = 'paramant:signup-return';
export const SIGNUP_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export function stashSignupReturn(storage, loc, now = Date.now()) {
  try {
    storage.setItem(SIGNUP_KEY, JSON.stringify({ path: loc.pathname, url: loc.pathname + loc.search + loc.hash, at: now }));
    return true;
  } catch { return false; }
}

// The local path to go back to after the account is ready ('/co-sign?resume=1'),
// or null. Reads only; the co-sign page removes the record when it restores it.
export function signupReturnPath(storage, now = Date.now()) {
  let rec = null;
  try { rec = JSON.parse(storage.getItem(SIGNUP_KEY) || 'null'); } catch { rec = null; }
  if (!rec || typeof rec.path !== 'string' || typeof rec.url !== 'string') return null;
  if (!(now - Number(rec.at) < SIGNUP_MAX_AGE_MS)) {
    try { storage.removeItem(SIGNUP_KEY); } catch { /* storage off */ }
    return null;
  }
  if (!/^\/(en\/)?co-sign$/.test(rec.path) || !rec.url.startsWith(rec.path)) return null;
  return rec.path + '?resume=1';
}
