'use strict';
// The security headers a sector relay puts on every answer, measured on a
// really booted relay.js.
//
// WHY THIS SUITE EXISTS. setHeaders (relay.js:2318) is the only place the five
// sector relays get security headers: nginx-paramant-public.conf adds nothing
// but HSTS to relay/health/legal/finance/iot, so whatever this function omits
// is simply absent from https://relay.paramant.app and its four siblings. It
// had no test. An external scan on 2026-09-03 found two things wrong with it
// that had been true for as long as the function existed:
//
//   * no X-Frame-Options at all, on all five, while paramant.app sent DENY;
//   * Permissions-Policy: interest-cohort=(). FLoC was withdrawn in 2022 and
//     interest-cohort was never added to the feature registry, so that policy
//     parses to an empty policy. The header was present, passed every scanner
//     that only checks presence, and restricted nothing.
//
// The second is the interesting one and it is why this suite asserts values and
// not names. A header that is present but says nothing is the same failure as a
// test that runs but asserts nothing: it reads as a pass from the outside. So
// every assertion below is on the content.
//
// Boots without redis, so the routes behind the gate answer 503. That is fine:
// these headers are set on every response regardless of what the route decides,
// which is exactly the property worth pinning.
// Runs in the relay-crypto-tests job: the route-*.test.js glob there boots a
// real relay.js with the deps installed and a redis service, which this suite
// needs to start relay.js at all.
// Run: node --test relay/test/route-security-headers.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

let srv;
let checks = 0;
const did = () => { checks++; };

before(async () => { srv = await boot({ tag: 'security-headers' }); });
after(async () => { await killAll(); summary('route-security-headers', checks); });

// Headers must not depend on the route being happy, so both a route that
// answers and one that refuses are measured.
async function bothWays() {
  const ok = await srv.get('/health');
  const refused = await srv.get('/v2/envelopes/does-not-exist');
  return [ok, refused];
}

test('every answer carries X-Frame-Options: DENY', async () => {
  for (const r of await bothWays()) {
    assert.strictEqual(r.headers['x-frame-options'], 'DENY',
      'a relay answers json to script and is never framed; the CSP says so to a current browser and this says it to the rest');
  }
  did();
});

test('Permissions-Policy restricts a registered feature, not a withdrawn one', async () => {
  const [r] = await bothWays();
  const value = r.headers['permissions-policy'];
  assert.ok(value, 'Permissions-Policy is absent');
  assert.ok(!/interest-cohort/.test(value),
    'interest-cohort was never a registered feature; a policy naming only it parses to an empty policy and restricts nothing');
  assert.match(value, /(geolocation|microphone|camera|payment|usb)=\(\)/,
    'at least one registered feature must actually be denied, or the header is decoration');
  did();
});

test('X-Content-Type-Options is nosniff', async () => {
  for (const r of await bothWays()) {
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
  }
  did();
});

test('Referrer-Policy does not leak the path off-origin', async () => {
  const [r] = await bothWays();
  assert.ok(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
    .includes(r.headers['referrer-policy']), `leaky Referrer-Policy: ${r.headers['referrer-policy']}`);
  did();
});

test('the CSP denies framing and allows no eval beyond WebAssembly', async () => {
  const [r] = await bothWays();
  const csp = r.headers['content-security-policy'];
  assert.ok(csp, 'Content-Security-Policy is absent');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  // 'wasm-unsafe-eval' is deliberate and is not 'unsafe-eval': it permits
  // WebAssembly compilation and nothing else, which ML-KEM and ML-DSA need.
  assert.ok(!/(^|[^-])'unsafe-eval'/.test(csp.replace(/'wasm-unsafe-eval'/g, '')),
    `the CSP allows unsafe-eval: ${csp}`);
  did();
});

// HSTS is the TLS edge's header, not the relay's (CT-DEDUP, second round).
// Measured 2026-10-06 on production: /health on all six hosts carried
// Strict-Transport-Security twice, once from the edge and once from here,
// because a header added by nginx or Caddy does not replace the one the
// upstream already sent. The relay speaks plain HTTP, where a browser ignores
// HSTS anyway, so the only effect of sending it was the duplicate.
test('the relay leaves HSTS to the TLS edge, so the header appears once', async () => {
  for (const r of await bothWays()) {
    assert.strictEqual(r.headers['strict-transport-security'], undefined,
      'the relay sent Strict-Transport-Security itself; behind the edge that doubles the header');
  }
  // The edge still sets it, exactly once, for every relay host.
  const fs = require('fs');
  const path = require('path');
  const caddy = fs.readFileSync(path.join(__dirname, '../../deploy/caddy/Caddyfile'), 'utf8');
  const lines = caddy.split('\n').filter((l) => /^\s*header\s+Strict-Transport-Security\b/.test(l));
  assert.strictEqual(lines.length, 1, 'the Caddy edge sets HSTS once');
  const maxAge = Number((/max-age=(\d+)/.exec(lines[0]) || [])[1]);
  assert.ok(maxAge >= 31536000, `edge max-age ${maxAge} is under a year`);
  assert.match(lines[0], /includeSubDomains/i);
  did();
});

test('RELAY_SEND_HSTS=1 brings it back for a relay exposed without an edge', async () => {
  const own = await boot({ tag: 'security-headers-hsts', env: { RELAY_SEND_HSTS: '1' } });
  const r = await own.get('/health');
  const hsts = r.headers['strict-transport-security'];
  assert.ok(hsts, 'Strict-Transport-Security is absent with RELAY_SEND_HSTS=1');
  const maxAge = Number((/max-age=(\d+)/.exec(hsts) || [])[1]);
  assert.ok(maxAge >= 31536000, `max-age ${maxAge} is under a year`);
  assert.match(hsts, /includeSubDomains/i);
  did();
});
