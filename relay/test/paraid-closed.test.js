'use strict';
// ParaID is out of the shop window (fb3cdd3, 2026-07-19) and is not a product in
// lib/billing-catalog.js, so nobody can buy it. It was still fully on offer:
// listed in sitemap.xml (re-added by the bulk SEO commit e0e82a1 six days after
// the removal decision) and, worse, POST /v1/paraid/issue-document signed
// identity claims for anyone on the internet behind nothing but an IP rate-limit.
//
// This test locks the two halves of that shut:
//   A) sitemap.xml carries no /paraid* route, and the three pages say noindex,
//      so what Google already has drops out.
//   B) POST /v1/paraid/issue-document refuses an unauthenticated caller. Proved
//      by RUNNING the real relay request handler, not by reading relay.js: the
//      redis module is stubbed and http.createServer is intercepted so relay.js
//      can be required without binding a socket, then the handler is called.
//
// Fails on the old code: the sitemap has three <loc>/paraid entries, the pages
// carry no robots meta, and the endpoint answers 503/429/200 (never 401) to a
// request with no Authorization header.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Readable } = require('stream');
const Module = require('module');

const FRONTEND = path.join(__dirname, '..', '..', 'frontend');
let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// -- A1. sitemap.xml ---------------------------------------------------------
const sitemap = fs.readFileSync(path.join(FRONTEND, 'sitemap.xml'), 'utf8');
const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim());
// Guard against passing on an empty or truncated sitemap: the other routes must
// still be there, otherwise "no paraid" would be true for the wrong reason.
assert.ok(locs.length > 20, `sitemap looks truncated: only ${locs.length} <loc> entries`);
const paraidLocs = locs.filter((u) => {
  const p = new URL(u).pathname.replace(/\/+$/, '');
  return p === '/paraid' || p.startsWith('/paraid-');
});
assert.deepStrictEqual(paraidLocs, [], `sitemap still offers ParaID routes: ${paraidLocs.join(', ')}`);
ok(`sitemap.xml lists ${locs.length} routes and none of them is a /paraid route`);

// -- A2. noindex on the three pages ------------------------------------------
for (const f of ['paraid.html', 'paraid-app.html', 'paraid-document.html']) {
  const html = fs.readFileSync(path.join(FRONTEND, f), 'utf8');
  const m = /<meta\s+name=["']robots["']\s+content=["']([^"']+)["']\s*\/?>/i.exec(html);
  assert.ok(m, `${f} has no <meta name="robots">`);
  assert.ok(/noindex/i.test(m[1]), `${f} robots meta is "${m[1]}", expected noindex`);
  ok(`${f} is noindex ("${m[1]}")`);
}

// -- B1. the auth decision itself --------------------------------------------
// authenticateBearer is the one definition of "known /v1 caller", shared by the
// ParaSign open-API router and the relay's own ParaID route.
const openApi = require('../lib/parasign-open-api');
const KEY = 'psk_live_paraidtest0000000000000000';
const REVOKED = 'psk_live_revoked00000000000000000';
const keys = new Map([
  [KEY, { plan: 'pro', active: true, account_id: 'acct_demo', scope: 'parasign' }],
  [REVOKED, { plan: 'pro', active: false, account_id: 'acct_demo' }],
]);
for (const [label, header] of [
  ['no Authorization header', ''],
  ['a non-Bearer header', 'Basic hunter2'],
  ['a Bearer token that is not a psk_ key', 'Bearer abc123'],
  ['an unknown psk_ key', 'Bearer psk_live_neverissued0000000'],
  ['a revoked psk_ key', `Bearer ${REVOKED}`],
]) {
  const r = openApi.authenticateBearer(header, keys);
  assert.strictEqual(r.ok, false, `${label} was accepted`);
  assert.strictEqual(r.code, 401);
  ok(`authenticateBearer rejects ${label} with 401`);
}
const good = openApi.authenticateBearer(`Bearer ${KEY}`, keys);
assert.strictEqual(good.ok, true);
assert.strictEqual(good.token, KEY);
assert.strictEqual(good.mode, 'live');
ok('authenticateBearer accepts an active psk_live_ key');

// -- B2. the live route ------------------------------------------------------
// Boot relay.js far enough to get its request handler. Two kinds of narrow stub:
// the npm packages relay.js requires at load time (this suite runs without
// node_modules, like every other test here), and http.createServer, so nothing
// binds a port. None of the stubbed packages is on the path under test; if one
// is ever called the throw shows up as a failure rather than a silent pass.
// Every property is a function that throws, so a stub that is actually used
// fails the test instead of quietly returning undefined. The crypto impls only
// destructure at load time, which this satisfies without running any crypto.
const stub = (name) => new Proxy({}, {
  get(_t, prop) {
    if (typeof prop === 'symbol' || prop === 'then') return undefined;
    return () => { throw new Error(`${name} is stubbed in this test (${String(prop)})`); };
  },
});
const STUB_NAMES = ['redis', 'argon2', 'ws', 'nats', '@paramant/core'];
const origLoad = Module._load;
Module._load = function (request, ...rest) {
  if (STUB_NAMES.includes(request) || request.startsWith('@noble/')) return stub(request);
  return origLoad.call(this, request, ...rest);
};
const http = require('http');
const origCreateServer = http.createServer;
let handler = null;
http.createServer = function (h) {
  handler = h;
  return { listen() { return this; }, on() { return this; }, close() { return this; } };
};

// Every on-disk path relay.js writes to defaults to /data. Point them all at a
// throwaway dir so a test run cannot touch a real deployment's state, not even
// when it happens to run as a user that may write there.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'paraid-closed-'));
process.env.RELAY_MODE = 'full';
process.env.REDIS_URL = '';                 // leaves the stubbed createClient unused
process.env.SERVE_FRONTEND = 'false';
process.env.CT_FILE = path.join(TMP, 'ct.log');
process.env.STH_FILE = path.join(TMP, 'sth.json');
process.env.PEER_STH_DIR = path.join(TMP, 'peer-sths');
process.env.RELAY_IDENTITY_FILE = path.join(TMP, 'identity.json');
process.env.TRIAL_KEYS_FILE = path.join(TMP, 'trial-keys.json');
process.env.CODE_MANIFEST_FILE = path.join(TMP, 'code-manifest.json');
process.env.DPA_FILE = path.join(TMP, 'dpa.json');
process.env.PARAID_REGISTRY_FILE = path.join(TMP, 'paraid-issuers.json');
process.env.PARAID_ISSUER_KEY_FILE = path.join(TMP, 'paraid-issuer-key.json');
process.env.USERS_JSON = JSON.stringify({ api_keys: [
  { key: KEY, plan: 'pro', label: 'acct_demo', email: 'demo@example.com', active: true, account_id: 'acct_demo', scope: 'parasign' },
] });

require('../relay.js');
Module._load = origLoad;
http.createServer = origCreateServer;
assert.ok(typeof handler === 'function', 'did not capture the relay request handler');

function mkReq(headers, body) {
  const req = Readable.from([Buffer.from(body || '')]);
  req.url = '/v1/paraid/issue-document';
  req.method = 'POST';
  req.headers = Object.assign({ 'content-type': 'application/json' }, headers);
  req.socket = { remoteAddress: '127.0.0.1' };
  return req;
}
function mkRes() {
  return { code: 0, headers: {}, body: '',
    setHeader() {}, getHeader() { return undefined; },
    writeHead(c, h) { this.code = c; this.headers = h || {}; return this; },
    end(b) { this.body = b == null ? '' : String(b); return this; } };
}

const CLAIM = JSON.stringify({ holder_binding: 'AAAA', mrz_line1: 'x', mrz_line2: 'y' });

(async () => {
  for (const [label, headers] of [
    ['no Authorization header', {}],
    ['a Bearer token that is not a psk_ key', { authorization: 'Bearer abc123' }],
    ['an unknown psk_ key', { authorization: 'Bearer psk_live_neverissued0000000' }],
    ['an X-Api-Key instead of a Bearer token', { 'x-api-key': KEY }],
  ]) {
    const res = mkRes();
    await handler(mkReq(headers, CLAIM), res);
    // 401 specifically: a 503 (no issuer key) or 429 (rate limit) would mean the
    // request got past the gate and only stopped on an operational accident.
    assert.strictEqual(res.code, 401,
      `POST /v1/paraid/issue-document with ${label} answered ${res.code}, expected 401`);
    assert.strictEqual(JSON.parse(res.body).error, 'unauthorized');
    ok(`POST /v1/paraid/issue-document refuses ${label} with 401`);
  }

  // And the gate is a gate, not a blanket refusal: an authenticated key gets
  // past it. No issuer key exists in a test run, so the honest next answer is
  // 503 "issuer not configured". Anything except 401 proves the gate opened.
  const res = mkRes();
  await handler(mkReq({ authorization: `Bearer ${KEY}` }, CLAIM), res);
  assert.notStrictEqual(res.code, 401,
    'an authenticated psk_live_ key was still rejected as unauthorized');
  ok(`an authenticated psk_live_ key passes the gate (got ${res.code}, not 401)`);

  console.log(`\n${passed} checks passed`);
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
