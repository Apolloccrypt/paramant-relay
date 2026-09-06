'use strict';
// THE CSRF ORIGIN GATE. A write that authenticates with the session cookie must
// come from our own page.
//
// WHY THIS EXISTS. Finding 19 of the 2026-09-05 hostile review. The user side of
// the admin server had no CSRF defence beyond the cookie's own SameSite=Lax: no
// token, no Origin check, no Referer check, no Sec-Fetch-Site. Grepped on
// 2026-09-06, the word "Origin" appeared in that file only inside WebAuthn
// configuration and inside the comment explaining SameSite.
//
// Lax is not the bug and is not being revisited: it is a written-down trade-off
// for the co-sign flow, which lands a recipient through a top-level navigation
// from an emailed link. The bug is that Lax is scoped to the REGISTRABLE DOMAIN.
// health / legal / finance / iot / relay .paramant.app are all same-site with
// paramant.app, so a single HTML injection on any one of them produces a page
// whose POSTs carry the session cookie. Twelve state-changing routes need no
// request body at all, which means a plain form submit reaches them without ever
// being preflighted: reset the TOTP, destroy the backup codes, revoke the
// sessions, cancel the subscription, mint a live ParaSign API key.
//
// The review marked the exploitation route "probable" rather than confirmed, and
// that was right: no live injection point was found. What is confirmed is that
// there is no second layer if one appears.
//
// WHAT IT REQUIRES
//   O1  the check is mounted in FRONT of the whole /api router, not per route.
//       A per-route list is a list that the next route is not on.
//   O2  the allow list does not accept a sector subdomain. That origin is the
//       one this exists to refuse, and relay.js isAllowedOrigin does accept it
//       (correctly, for CORS on the API, and wrongly for this).
//   O3  the decision table behaves, case by case.
//
// The static half runs anywhere (pure functions plus fs). The behavioural half
// at the bottom boots a real admin against redis and is skipped by name through
// ADMIN_TEST_SKIP, like every other suite here that needs one.

const { test, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const sameOrigin = require('../lib/same-origin');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');
const SRC = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

const SITE = 'https://paramant.app';
const allow = sameOrigin.buildAllowList(SITE, '');

const ask = (over = {}) => sameOrigin.verdict({
  method: 'POST', path: '/user/account/totp/reset', hasCookie: true, origin: '', secFetchSite: '', allow, ...over,
});

test('the check is mounted in front of the whole router, before the routes', () => {
  const mount = SRC.indexOf('app.use(`${BASE_PATH}/api`, requireSameOrigin);');
  const router = SRC.indexOf('app.use(`${BASE_PATH}/api`, api);');
  assert.ok(mount > 0, 'the same-origin check is not mounted');
  assert.ok(router > 0, 'the api router mount moved');
  assert.ok(mount < router, 'the check is mounted after the router, so it never runs first');
  // And it is not a per-route decoration, which is the shape that goes stale.
  const perRoute = (SRC.match(/requireSameOrigin\s*,/g) || []).length;
  assert.strictEqual(perRoute, 0, 'the check is being applied route by route as well; one mount is the point');
});

test('a sector subdomain is refused, which is the whole finding', () => {
  for (const host of ['health', 'legal', 'finance', 'iot', 'relay']) {
    const o = `https://${host}.paramant.app`;
    const v = ask({ origin: o });
    assert.strictEqual(v.ok, false, `${o} was accepted; it is same-site, which is exactly the attack`);
    assert.match(v.reason, /^cross_origin:/);
  }
  // A lookalike that merely ends in the same string, too.
  assert.strictEqual(ask({ origin: 'https://paramant.app.example.test' }).ok, false);
  assert.strictEqual(ask({ origin: 'https://notparamant.app' }).ok, false);
});

test('our own page passes, by Origin and by Sec-Fetch-Site', () => {
  assert.strictEqual(ask({ origin: SITE }).ok, true);
  assert.strictEqual(ask({ secFetchSite: 'same-origin' }).ok, true);
  // Typed in the address bar, or a bookmark: the browser says none.
  assert.strictEqual(ask({ secFetchSite: 'none' }).ok, true);
  assert.strictEqual(ask({ secFetchSite: 'same-site' }).ok, false, 'same-site is the sector subdomain again');
  assert.strictEqual(ask({ secFetchSite: 'cross-site' }).ok, false);
});

test('Origin decides before Sec-Fetch-Site, because the extensions are cross-site by construction', () => {
  // The browser extension and the Outlook taskpane are real callers that hold a
  // cookie and always look cross-site. If Sec-Fetch-Site were consulted first
  // they would be refused, and the fix for that would be to weaken the rule for
  // everyone.
  const ext = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
  assert.strictEqual(ask({ origin: ext, secFetchSite: 'cross-site' }).ok, true);
  assert.strictEqual(ask({ origin: 'moz-extension://11111111-2222-3333-4444-555555555555', secFetchSite: 'cross-site' }).ok, true);
  // And a page merely CLAIMING to be an extension over https is not one.
  assert.strictEqual(ask({ origin: 'https://chrome-extension.example.test' }).ok, false);
});

test('what is never checked, is never checked for a reason', () => {
  // A read cannot change anything, and a request with no session cookie is
  // authenticating by something an attacker's page cannot borrow.
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    assert.strictEqual(ask({ method, origin: 'https://evil.example.test' }).ok, true, `${method} was refused`);
  }
  assert.strictEqual(ask({ hasCookie: false, origin: 'https://evil.example.test' }).ok, true, 'a keyed caller was refused');
  // Neither header at all: a non-browser client. Every browser sends Origin on
  // a POST, so refusing here would close nothing and break every curl and every
  // node http test in this repo.
  const bare = ask({});
  assert.strictEqual(bare.ok, true);
  assert.strictEqual(bare.reason, 'no_browser_headers');
});

test('localhost passes in development and not in production', () => {
  const dev = sameOrigin.verdict({ method: 'POST', hasCookie: true, origin: 'http://localhost:8080', secFetchSite: '', allow, allowLocalhost: true });
  const prod = sameOrigin.verdict({ method: 'POST', hasCookie: true, origin: 'http://localhost:8080', secFetchSite: '', allow, allowLocalhost: false });
  assert.strictEqual(dev.ok, true);
  assert.strictEqual(prod.ok, false, 'a production deploy accepts http://localhost as an origin');
  assert.match(SRC, /CSRF_ALLOW_LOCALHOST = process\.env\.NODE_ENV !== 'production'/, 'the dev exception is not tied to NODE_ENV');
});

test('the allow list is built from SITE_URL, not from a hardcoded host', () => {
  const other = sameOrigin.buildAllowList('https://staging.example.test', '');
  assert.ok(other.has('https://staging.example.test'));
  assert.ok(!other.has(SITE), 'the production origin is baked in regardless of SITE_URL');
  // Extras, for a taskpane host that is not ours.
  const withExtra = sameOrigin.buildAllowList(SITE, 'https://outlook.office.com, https://outlook.office365.com');
  assert.ok(withExtra.has('https://outlook.office.com'));
  assert.ok(withExtra.has('https://outlook.office365.com'));
  // Junk in the env does not become an allowed origin.
  assert.ok(!sameOrigin.buildAllowList(SITE, 'not a url, , ///').has('not a url'));
  assert.match(SRC, /CSRF_EXTRA_ORIGINS/, 'there is no way to add an origin without editing code');
});

test('exactly one write is exempt, and it is the one that only destroys the caller own session', () => {
  // The Outlook task pane runs on addin.paramant.app and its logout is a simple
  // cross-origin POST: no preflight, cookie attached, response hidden by CORS.
  // It works today, the add-in ignores the answer, and an origin check would
  // silently stop it revoking anything. Signing somebody out is the one write
  // where refusing costs a shipped client more than it buys.
  assert.deepStrictEqual([...sameOrigin.EXEMPT_PATHS], ['/user/logout'],
    'the exempt set has changed. A write that GRANTS anything does not belong in it.');
  assert.strictEqual(ask({ path: '/user/logout', origin: 'https://addin.paramant.app' }).ok, true);
  assert.strictEqual(ask({ path: '/user/logout', origin: 'https://evil.example.test' }).reason, 'exempt_path');
  // And the exemption is a PATH, not a prefix: nothing else under it rides along.
  assert.strictEqual(ask({ path: '/user/logout/all', origin: 'https://legal.paramant.app' }).ok, false);
  assert.strictEqual(ask({ path: '/user/account/key', origin: 'https://addin.paramant.app' }).ok, false);
});

test('self-test: the refusal reason names the origin, so a broken client is diagnosable', () => {
  const v = ask({ origin: 'https://legal.paramant.app' });
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'cross_origin:https://legal.paramant.app');
  assert.match(SRC, /console\.warn\('\[csrf\] refused'/, 'a refusal is not logged, so nobody can tell why a client broke');
  assert.match(SRC, /error: 'csrf_origin'/, 'the refusal has no stable error code for a client to read');
});

// ── the behavioural half, on a really booted admin ───────────────────────────
// The static half above drives the decision table. This one proves the table is
// actually consulted, by a process, in front of the routes -- which is the half
// that a refactor breaks silently.

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const ACCOUNT_KEY = `pgp_csrf_${SUFFIX}`;
const SITE_ORIGIN = 'https://paramant.app';
let rc = null;
let srv = null;
let relay = null;

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error('unmet precondition "redis": the redis module is not installed. Run npm ci in admin/, or declare it: ADMIN_TEST_SKIP=redis');
  }
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); }
  catch (e) {
    try { await c.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
  relay = await stubRelay(defaultRelayState([]));
  srv = await boot({ redisUrl: url, relay, env: { SITE_URL: SITE_ORIGIN, NODE_ENV: 'production' } });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* already gone */ } }
});

async function cookie() {
  const token = crypto.randomBytes(24).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: ACCOUNT_KEY, email: `owner-${SUFFIX}@example.test`,
    created_at: Date.now(), primary_api_key: ACCOUNT_KEY, legacy_revealable: true,
  }), { EX: 3600 });
  return `paramant_user_session=${token}`;
}

test('over HTTP: the add-in can still sign a user out from its own host', async () => {
  if (!srv) return;
  const Cookie = await cookie();
  const r = await fetch(`${srv.base}/api/user/logout`, {
    method: 'POST', headers: { Cookie, Origin: 'https://addin.paramant.app' },
  });
  assert.notStrictEqual(r.status, 403, 'the Outlook task pane can no longer log anybody out');
  assert.strictEqual(await rc.get(`paramant:user:session:${Cookie.split('=')[1]}`), null,
    'the logout was allowed through but revoked nothing');
});

test('over HTTP: a same-site sector origin cannot drive a cookie write', async () => {
  if (!srv) return;
  const Cookie = await cookie();
  // The sharpest of the twelve bodyless writes: it tears down the second factor.
  const path_ = '/api/user/account/totp/reset';

  const evil = await fetch(`${srv.base}${path_}`, {
    method: 'POST', headers: { Cookie, Origin: 'https://legal.paramant.app' },
  });
  assert.strictEqual(evil.status, 403, `a sector subdomain drove the reset: ${evil.status}`);
  assert.strictEqual((await evil.json()).error, 'csrf_origin');

  // And the account is untouched: the refusal happened before the handler.
  assert.ok(await rc.get(`paramant:user:session:${Cookie.split('=')[1]}`), 'the session was revoked by a refused request');
});

test('over HTTP: our own page is not refused, and neither is a header-less client', async () => {
  if (!srv) return;
  const ours = await fetch(`${srv.base}/api/user/account/totp/reset`, {
    method: 'POST', headers: { Cookie: await cookie(), Origin: SITE_ORIGIN },
  });
  assert.notStrictEqual(ours.status, 403, 'our own origin was refused');

  const bare = await fetch(`${srv.base}/api/user/account/totp/reset`, {
    method: 'POST', headers: { Cookie: await cookie() },
  });
  assert.notStrictEqual(bare.status, 403, 'a client sending no browser headers was refused');
});

test('over HTTP: a read is never refused, whatever origin it claims', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/user/account`, {
    method: 'GET', headers: { Cookie: await cookie(), Origin: 'https://evil.example.test' },
  });
  assert.notStrictEqual(r.status, 403, 'a GET was refused on its origin');
});

test('over HTTP: the check covers every route, including one added after it', async () => {
  if (!srv) return;
  // Mounted in front of the router, so it applies to paths that do not exist
  // either. That is the property: a new route is covered on the day it is
  // written, without anybody remembering to decorate it.
  const r = await fetch(`${srv.base}/api/user/some-route-added-next-month`, {
    method: 'POST', headers: { Cookie: await cookie(), Origin: 'https://iot.paramant.app' },
  });
  assert.strictEqual(r.status, 403, 'the check is per route after all');
});
