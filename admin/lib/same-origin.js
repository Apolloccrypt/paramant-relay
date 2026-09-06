'use strict';
// Is this state-changing request coming from our own page, or from somebody
// else's?
//
// WHY THIS FILE EXISTS. Finding 19 of the 2026-09-05 hostile review: the user
// side of the admin server has no CSRF defence at all beyond the cookie's own
// SameSite=Lax. No token, no Origin check, no Referer check, no Sec-Fetch-Site.
//
// Lax was a deliberate choice (ADR R018): the co-sign flow lands a recipient
// through a top-level navigation from an emailed link, and Strict would bounce
// an already-logged-in signer to re-authenticate on exactly the flow the product
// is built for. That choice is not what is being revisited. What is being closed
// is the gap the choice does not cover: SameSite works on the REGISTRABLE
// DOMAIN, and health.paramant.app, legal.paramant.app, finance.paramant.app,
// iot.paramant.app and relay.paramant.app are all same-site with paramant.app.
// One HTML injection on one sector host yields a page whose POSTs carry the
// user's session cookie, and twelve state-changing routes need no request body
// at all -- resetting TOTP, destroying backup codes, revoking sessions,
// cancelling the subscription, minting a live ParaSign API key.
//
// THE RULE, and the order matters:
//   1. A safe method (GET/HEAD/OPTIONS) is never checked.
//   2. A request with no session cookie is never checked: it is authenticating
//      by something the attacker's page cannot borrow.
//   3. An allow-listed Origin passes. This comes FIRST, because the browser
//      extensions are legitimate callers whose Sec-Fetch-Site is cross-site by
//      construction.
//   4. Sec-Fetch-Site decides when the browser sent it: same-origin, or none
//      (typed in the address bar), and nothing else.
//   5. An Origin that is present and not allow-listed is refused.
//   6. Neither header: allowed. Every browser sends Origin on a POST, so this
//      case is a non-browser client, and a non-browser client is not doing CSRF
//      -- it either holds the cookie already or gains nothing by omitting a
//      header. Refusing here would only break the repo's own node http tests
//      and every curl a support engineer runs, without closing anything.
//
// Deliberately NOT same-site: a sector subdomain is exactly the origin this
// exists to refuse, so the allow list names the site itself and nothing under it.
// relay/relay.js isAllowedOrigin does accept `.paramant.app`, and that is
// correct there (CORS for the API) and wrong here.

// Origins allowed to drive a cookie-authenticated write.
//   siteUrl:   the product's own origin, from SITE_URL.
//   extra:     comma-separated extras from env, for a taskpane host.
// Browser extensions are matched by scheme: their id changes per install and per
// browser, and an unpacked build has a different one again, so an id list would
// be a list that is always slightly wrong. The scheme is the meaningful part:
// only code the user installed can hold such an origin.
function buildAllowList(siteUrl, extra) {
  const out = new Set();
  try { out.add(new URL(siteUrl).origin); } catch (_) { /* no usable SITE_URL */ }
  for (const raw of String(extra || '').split(',')) {
    const o = raw.trim();
    if (!o) continue;
    try { out.add(new URL(o).origin); } catch (_) { /* ignore an unparseable entry */ }
  }
  return out;
}

const EXTENSION_SCHEME = /^(chrome-extension|moz-extension|safari-web-extension):\/\//;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Pure, so the whole decision table is testable without a server.
// Returns { ok: true } or { ok: false, reason }.
function verdict({ method, hasCookie, origin, secFetchSite, allow, allowLocalhost = false }) {
  if (SAFE_METHODS.has(String(method || '').toUpperCase())) return { ok: true, reason: 'safe_method' };
  if (!hasCookie) return { ok: true, reason: 'no_session_cookie' };

  const o = String(origin || '').trim();
  if (o) {
    if (allow.has(o)) return { ok: true, reason: 'allowed_origin' };
    if (EXTENSION_SCHEME.test(o)) return { ok: true, reason: 'extension_origin' };
    if (allowLocalhost && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o)) return { ok: true, reason: 'dev_origin' };
    return { ok: false, reason: `cross_origin:${o}` };
  }

  const sfs = String(secFetchSite || '').trim().toLowerCase();
  if (sfs) {
    if (sfs === 'same-origin' || sfs === 'none') return { ok: true, reason: `sec_fetch_site:${sfs}` };
    return { ok: false, reason: `sec_fetch_site:${sfs}` };
  }

  return { ok: true, reason: 'no_browser_headers' };
}

module.exports = { buildAllowList, verdict, EXTENSION_SCHEME, SAFE_METHODS };
