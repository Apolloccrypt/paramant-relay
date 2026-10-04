// One load of /account answered 429. Why, and the lock that keeps it fixed.
//
// deploy/nginx-paramant-live.conf put the whole of /api/user/ in relay_auth:
// 10 requests a minute per IP, burst 5. That is a login brake. But /account
// fires about nine /api/user/ calls on load (session check, me, keys,
// passkeys, signing keys ...), so on prod the sixth to ninth came back 429 and
// the page printed "HTTP 429" (tester 5, 2026-10-04: 65 s idle, one load, six
// 200/401 then three 429). Dashboard and /sign added their own.
//
// The fix splits the location: the doors where a password, a TOTP code or a new
// account is tried keep relay_auth; every other /api/user/ call is a signed-in
// read and goes to user_session. This suite reads the confs as nginx would
// resolve them and holds three things:
//   1. every /api/user/ request the app pages make lands in user_session, and
//      the burst there swallows the requests of the three pages loaded at once;
//   2. every login, signup, setup and TOTP door still lands in relay_auth;
//   3. the zone is defined in the tracked snippet, per IP, and the self-host
//      conf makes the same split for its /admin/ surface.
// Static on purpose: no nginx binary in CI. The resolver below is nginx's own
// rule for these blocks (exact match, then regex, then longest prefix).

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// Every location block of a conf with the limit_req zone and burst it sets.
function locations(conf) {
  const out = [];
  const re = /^\s*location\s+(=|~\*?|\^~)?\s*(\S+)\s*\{/gm;
  let m;
  while ((m = re.exec(conf))) {
    let depth = 1; let i = re.lastIndex;
    while (depth && i < conf.length) { if (conf[i] === '{') depth++; else if (conf[i] === '}') depth--; i++; }
    const body = conf.slice(re.lastIndex, i - 1);
    const lr = /limit_req\s+zone=([A-Za-z0-9_]+)(?:\s+burst=(\d+))?/.exec(body);
    out.push({ mod: m[1] || '', path: m[2], zone: lr ? lr[1] : null, burst: lr && lr[2] ? Number(lr[2]) : 0, body });
  }
  return out;
}

function resolve(locs, uri) {
  const exact = locs.find((l) => l.mod === '=' && l.path === uri);
  if (exact) return exact;
  const prefixes = locs.filter((l) => (l.mod === '' || l.mod === '^~') && uri.startsWith(l.path))
    .sort((a, b) => b.path.length - a.path.length);
  if (prefixes[0] && prefixes[0].mod === '^~') return prefixes[0];
  const rx = locs.find((l) => l.mod.startsWith('~') && new RegExp(l.path, l.mod === '~*' ? 'i' : '').test(uri));
  return rx || prefixes[0] || null;
}

// The rates in the tracked snippet, per zone, in requests a minute.
function zoneRates(text) {
  const out = {};
  for (const m of text.matchAll(/^\s*limit_req_zone\s+(\S+)\s+zone=([A-Za-z0-9_]+):\S+\s+rate=(\d+)r\/m;/gm)) out[m[2]] = { key: m[1], perMin: Number(m[3]) };
  return out;
}

const LIVE = locations(read('deploy/nginx-paramant-live.conf'));
const SNIPPET = zoneRates(read('deploy/nginx/snippets/paramant-limit-req.conf'));

// The /api/user/ paths the three signed-in pages ask for, read out of the
// scripts those pages load. A path built from a template stops at the first ${.
function apiCallsOf(page) {
  const html = read(`frontend/${page}.html`);
  const scripts = [...html.matchAll(/src="(\/[^"?]+\.js)/g)].map((m) => m[1]);
  const calls = new Set();
  for (const src of scripts) {
    const file = path.join(ROOT, 'frontend', src);
    if (!fs.existsSync(file)) continue;
    for (const m of fs.readFileSync(file, 'utf8').matchAll(/['"`](\/api\/user\/[A-Za-z0-9/_-]*)/g)) calls.add(m[1]);
  }
  return [...calls];
}

const LOGIN_DOORS = [
  '/api/user/login', '/api/user/login-with-backup', '/api/user/signup',
  '/api/user/signup/verify/abc', '/api/user/setup/tok', '/api/user/setup/tok/confirm',
  '/api/user/auth/webauthn/login/options', '/api/user/auth/webauthn/login/verify',
  '/api/user/auth/request-totp-reset', '/api/user/auth/reset-confirm',
  '/api/user/account/totp/reset', '/api/user/account/backup-codes/regenerate',
];

test('every login, signup, setup and TOTP door keeps the brute-force zone', () => {
  for (const uri of LOGIN_DOORS) {
    const loc = resolve(LIVE, uri);
    assert.ok(loc, `${uri} reaches no location`);
    assert.equal(loc.zone, 'relay_auth', `${uri} lands in ${loc.path} (zone ${loc.zone}); a login door must stay in relay_auth`);
    assert.ok(loc.burst <= 5, `${uri}: burst ${loc.burst} is not a brake`);
  }
  assert.equal(SNIPPET.relay_auth.perMin, 10, 'relay_auth is the 10-a-minute login brake');
});

test('an ordinary signed-in page load stays under the /api/user/ limit', () => {
  const pages = ['account', 'dashboard', 'sign'];
  const seen = [];
  for (const page of pages) {
    const calls = apiCallsOf(page);
    assert.ok(calls.length >= 3, `${page}: found only ${calls.length} /api/user/ calls; this check is looking at nothing`);
    for (const uri of calls) {
      const loc = resolve(LIVE, uri);
      assert.ok(loc && loc.zone, `${uri} (from /${page}) reaches no rate-limited location`);
      // The internal auth_request probes have no zone of their own; they are
      // not reachable from a browser.
      if (/(^|\n)\s*internal;/.test(loc.body)) continue;
      // A door the page opens on a click (enrolling a passkey, a TOTP reset)
      // is a credential action and keeps the brake on purpose.
      if (uri.startsWith('/api/user/auth/') || LOGIN_DOORS.some((d) => uri === d || uri.startsWith(d))) continue;
      assert.equal(loc.zone, 'user_session', `${uri} (from /${page}) lands in ${loc.path}, zone ${loc.zone}`);
      seen.push(uri);
    }
  }
  const gen = resolve(LIVE, '/api/user/account');
  assert.equal(gen.zone, 'user_session');
  // Leaky bucket with nodelay: burst + 1 requests may arrive in the same
  // instant. All three pages at once, twice over (an office of two behind one
  // address), must fit, and the old 9-request /account load with ample room.
  assert.ok(gen.burst + 1 >= 2 * seen.length, `burst ${gen.burst} is too small for ${seen.length} distinct calls x2`);
  assert.ok(SNIPPET.user_session && SNIPPET.user_session.perMin >= 120, 'user_session refills at 120 a minute or more');
  // Per signed-in session since sweep-chaos 6 (an office behind one NAT
  // address ran out at ~17 people); the address is the fallback without a cookie.
  assert.equal(SNIPPET.user_session.key, '$user_session_key', 'user_session is keyed per session');
  const snippetText = read('deploy/nginx/snippets/paramant-limit-req.conf');
  assert.match(snippetText, /map \$cookie_paramant_user_session \$user_session_key \{[^}]*""\s+\$binary_remote_addr;[^}]*default\s+\$cookie_paramant_user_session;/, 'the session key falls back to the address');
});

test('every /api/user/ block strips the internal headers and sets the client address', () => {
  for (const loc of LIVE.filter((l) => l.path.startsWith('/api/user/'))) {
    for (const h of ['X-Internal-Auth ""', 'X-Verified-Email-Hash ""', 'X-Real-IP $remote_addr']) {
      assert.ok(loc.body.includes(`proxy_set_header ${h}`), `${loc.path}: missing proxy_set_header ${h}`);
    }
    if (!/(^|\n)\s*internal;/.test(loc.body)) {
      assert.ok(loc.body.includes('proxy_set_header X-Paramant-Client-IP ""'), `${loc.path}: a browser could send X-Paramant-Client-IP through`);
    }
  }
});

test('the self-host conf splits /admin/ the same way', () => {
  const conf = read('deploy/nginx-selfhost.conf');
  const locs = locations(conf);
  const zones = zoneRates(conf);
  assert.ok(zones.session && zones.session.perMin >= 120, 'the self-host conf defines a session zone');
  assert.equal(resolve(locs, '/admin/api/user/account').zone, 'session');
  assert.equal(resolve(locs, '/admin/app.js').zone, 'session');
  for (const uri of ['/admin/api/auth/login', ...LOGIN_DOORS.map((d) => d.replace('/api/user/', '/admin/api/user/'))]) {
    assert.equal(resolve(locs, uri).zone, 'auth', `${uri} must stay in the self-host auth zone`);
  }
});

// sweep-chaos 6: the :8081 health block set X-Real-IP $remote_addr without
// set_real_ip_from, so behind Caddy every visitor was 127.0.0.1 and the
// relay's per-IP limits were one bucket for everybody.
test('every local server block that forwards X-Real-IP first takes the real address from Caddy', () => {
  const live = read('deploy/nginx-paramant-live.conf');
  const blocks = live.split(/\nserver \{/).slice(1);
  const wrong = [];
  for (const b of blocks) {
    const listen = (/listen\s+(\S+);/.exec(b) || [])[1] || '?';
    if (!/proxy_set_header X-Real-IP \$remote_addr;/.test(b)) continue;
    if (!/set_real_ip_from 127\.0\.0\.1;/.test(b) || !/real_ip_header X-Forwarded-For;/.test(b)) wrong.push(listen);
  }
  assert.deepEqual(wrong, [], `these blocks forward 127.0.0.1 as the client: ${wrong.join(', ')}`);
});
