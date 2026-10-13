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
// new tab, where this tab's sessionStorage is gone. So this browser keeps, in
// localStorage, which request and which party the reader came from: the path,
// the envelope id and the party index. Never the invite token and never the
// key half (review #566): those stay in the invitation link. The record
// carries its expiry (24 hours, as long as the confirmation link works), is
// checked when it is written and on every page (nav-auth.js sweeps it), goes
// on sign-out and once it is used. It is stored only when the reader clicks
// "Maak er gratis een".
export const SIGNUP_KEY = 'paramant:signup-return';
export const SIGNUP_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const COSIGN_PATH = /^\/(en\/)?co-sign$/;
const ENV_ID = /^[A-Za-z0-9_-]{20,64}$/;

function requestOf(loc) {
  const q = new URLSearchParams(loc.search || '');
  const env = (q.get('env') || '').trim();
  const p = parseInt(q.get('p') || '', 10);
  if (!COSIGN_PATH.test(loc.pathname) || !ENV_ID.test(env) || !Number.isInteger(p) || p < 0) return null;
  return { path: loc.pathname, env, p };
}

// A record is usable when it has exactly the fields above and has not expired.
function readSignupReturn(storage, now) {
  let rec = null;
  try { rec = JSON.parse(storage.getItem(SIGNUP_KEY) || 'null'); } catch { rec = null; }
  const ok = rec && typeof rec === 'object' && COSIGN_PATH.test(rec.path) && ENV_ID.test(rec.env)
    && Number.isInteger(rec.p) && rec.p >= 0 && Number(rec.exp) > now && Number(rec.exp) <= now + SIGNUP_MAX_AGE_MS
    && rec.url === undefined;
  if (!ok) {
    try { if (rec !== null) storage.removeItem(SIGNUP_KEY); } catch { /* storage off */ }
    return null;
  }
  return rec;
}

export function stashSignupReturn(storage, loc, now = Date.now()) {
  const req = requestOf(loc);
  if (!req) return false;
  try {
    storage.setItem(SIGNUP_KEY, JSON.stringify({ ...req, exp: now + SIGNUP_MAX_AGE_MS }));
    return readSignupReturn(storage, now) !== null;
  } catch { return false; }
}

// The local path to go back to after the account is ready
// ('/co-sign?env=..&p=..&resume=1'), or null. Reads only.
export function signupReturnPath(storage, now = Date.now()) {
  const rec = readSignupReturn(storage, now);
  if (!rec) return null;
  return `${rec.path}?env=${encodeURIComponent(rec.env)}&p=${rec.p}&resume=1`;
}

// On the co-sign page reached through that path: true when this browser
// stored the way back for exactly this request and party. The record goes.
export function takeSignupReturn(storage, loc, now = Date.now()) {
  if (new URLSearchParams(loc.search || '').get('resume') !== '1') return false;
  const rec = readSignupReturn(storage, now);
  const req = requestOf(loc);
  if (!rec || !req) return false;
  try { storage.removeItem(SIGNUP_KEY); } catch { /* storage off */ }
  return rec.path === req.path && rec.env === req.env && rec.p === req.p;
}
