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
export function resumeReturn(storage, loc, hist, now = Date.now()) {
  if (new URLSearchParams(loc.search).get('resume') !== '1') return false;
  let rec = null;
  try { rec = JSON.parse(storage.getItem(KEY) || 'null'); storage.removeItem(KEY); } catch { rec = null; }
  if (!rec || rec.path !== loc.pathname || typeof rec.url !== 'string') return false;
  if (!(now - Number(rec.at) < MAX_AGE_MS)) return false;
  if (!rec.url.startsWith(loc.pathname)) return false;
  hist.replaceState(hist.state, '', rec.url);
  return true;
}
