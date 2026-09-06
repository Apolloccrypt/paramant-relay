'use strict';
// THE TRUSTED EDGE GATE. An address the relay limits people by may only come
// from a place the relay put there itself.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review, finding 7. Every per-IP limit
// in relay.js keyed on one line:
//
//     return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
//
// with a comment under it explaining that nginx sets X-Real-IP authoritatively.
// nginx did that on the apex and on relay.paramant.app. It did not on the four
// sector hostnames, and it did not in the /rp/<sector>/ blocks on the main site,
// and nginx forwards unknown client headers by default. On those hosts the
// header came from the caller, so the caller chose their own address, and the
// view limiter, the sign limiter, the signer lookup, the claim and status
// limiters, the MFA limiter, the anonymous upload window and the STH ingest
// window were all decorative at once. One header.
//
// The other direction needs no attacker at all: where NOBODY sets the header,
// every request on that hostname lands in one bucket keyed on the proxy, and one
// noisy visitor locks out everyone else on that host.
//
// WHAT MAKES THIS A CLASS AND NOT A CASE. The bug was not in any limiter. It was
// an assumption the code made about a config file, written in a comment in the
// code, where no config file could contradict it. Fixing getClientIp alone would
// leave the next assumption free to be written the same way, and fixing the four
// nginx blocks alone would leave the fifth to be added next month. So this gate
// asserts BOTH SIDES of the contract and refuses to let either drift:
//
//   THE EDGE     every proxy block that reaches a relay or the admin panel sets
//                X-Real-IP from the connection, and clears the headers that
//                would otherwise let a caller assert trust it does not have.
//   THE LOCK     the relay believes that header only from a trusted peer, and
//                only when it is really an address. A block someone forgets to
//                fix is then a lost address, not a bypass.
//   THE DEFAULT  the trusted set covers the peer the relay ACTUALLY sees in
//                production. Getting this wrong is silent and total: a default
//                of loopback only passes every test here and wipes out every
//                real client address in the container, putting the whole world
//                in one bucket. So it is asserted explicitly.
//
// HOW TO ANSWER A RED
//   From the edge half: add `proxy_set_header X-Real-IP $remote_addr;` (and the
//   two clears) to the block it names. Copy any neighbouring block. Do not add
//   the block to an exception list; the exception list is for locations that do
//   not reach a relay at all, and this gate decides that from the proxy_pass.
//   From the lock half: getClientIp must keep refusing a header from a peer it
//   does not trust. If a deployment genuinely fronts the relay from somewhere
//   else, that is TRUSTED_PROXY_CIDRS, not a change here.
//
// Runs anywhere: plain fs and a pure function. No redis, no engine, no server.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const clientIp = require('../lib/client-ip');

const ROOT = path.join(__dirname, '..', '..');

// The upstreams that are the relay fleet and the admin panel. 8080 is the static
// site and 8090 is the imaging viewer: neither reads X-Real-IP and neither has a
// limiter keyed on it, so a block that only reaches those is not this contract.
const RELAY_UPSTREAM = /proxy_pass\s+http:\/\/127\.0\.0\.1:(300[0-5]|4200)\b/;

// What a block that reaches a relay owes. X-Real-IP is the address itself. The
// other two are headers the relay treats as proof: X-Internal-Auth opens the
// internal surface and X-Verified-Email-Hash asserts which recipient you are.
// Both are checked against a secret, so neither is a hole today, but neither is
// ever legitimately sent by a browser either. Clearing them at the edge turns
// "an unguessable secret" into "not reachable", which is a better sentence.
const REQUIRED = [
  ['X-Real-IP', /proxy_set_header\s+X-Real-IP\s+\$remote_addr\s*;/i],
  ['X-Internal-Auth', /proxy_set_header\s+X-Internal-Auth\s+""\s*;/i],
  ['X-Verified-Email-Hash', /proxy_set_header\s+X-Verified-Email-Hash\s+""\s*;/i],
];

const CONFS = ['deploy/nginx-paramant-public.conf', 'deploy/nginx-paramant-live.conf'];

// Split a conf into location blocks by brace depth. Crude on purpose: it has to
// be obvious what it counts, because a parser nobody can read is a parser nobody
// trusts when it goes red.
function locationBlocks(src) {
  const lines = src.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*location\b/.test(lines[i]) || !lines[i].includes('{')) continue;
    let depth = lines[i].split('{').length - lines[i].split('}').length;
    const body = [lines[i]];
    let j = i;
    while (depth > 0 && j + 1 < lines.length) {
      j++;
      body.push(lines[j]);
      depth += lines[j].split('{').length - lines[j].split('}').length;
    }
    out.push({ line: i + 1, header: lines[i].trim().slice(0, 80), body: body.join('\n') });
  }
  return out;
}

test('every edge block that reaches a relay sets the client address and clears the trust headers', () => {
  const missing = [];
  let checked = 0;
  for (const rel of CONFS) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    for (const b of locationBlocks(src)) {
      if (!RELAY_UPSTREAM.test(b.body)) continue;
      checked++;
      for (const [name, re] of REQUIRED) {
        if (!re.test(b.body)) missing.push(`  ${rel}:${b.line}  ${b.header}\n      missing: proxy_set_header ${name}`);
      }
    }
  }

  // A gate that checks nothing passes. Four sector hosts, four /rp/ blocks, the
  // apex /v2/ and /admin/, the relay host and the internal listeners: the real
  // number is well over ten, and if it ever collapses to a handful the parser
  // above has stopped finding blocks rather than the config having shrunk.
  assert.ok(checked >= 10,
    `only ${checked} relay-facing blocks were found across ${CONFS.join(' and ')}. ` +
    'That is too few to be true, so locationBlocks() or RELAY_UPSTREAM has stopped matching ' +
    'and this gate is passing over nothing.');

  assert.deepStrictEqual(missing, [],
    'An edge block reaches a relay without settling who the caller is:\n' + missing.join('\n') +
    '\n\nThe relay limits people per IP and reads X-Real-IP to know who they are. A block that ' +
    'does not set it either forwards whatever the caller sent (every limiter becomes optional) ' +
    'or sends nothing (everyone on that hostname shares one bucket). Copy the three lines from ' +
    'the block next to it.');
});

test('the relay believes a forwarded address only from a peer it put there itself', () => {
  const ip = clientIp.makeClientIp({});
  const req = (peer, header) => ({
    socket: { remoteAddress: peer },
    headers: header === undefined ? {} : { 'x-real-ip': header },
  });

  // The bug, as a property: a stranger's own header is not their address.
  assert.strictEqual(ip(req('203.0.113.9', '8.8.8.8')), '203.0.113.9',
    'a caller connecting straight to the relay must not be able to name their own address');

  // The edge, as a property: what nginx says is believed.
  assert.strictEqual(ip(req('127.0.0.1', '8.8.8.8')), '8.8.8.8', 'loopback is the local nginx');
  assert.strictEqual(ip(req('172.17.0.1', '8.8.8.8')), '8.8.8.8', 'the docker bridge is the published port');
  assert.strictEqual(ip(req('::ffff:127.0.0.1', '8.8.8.8')), '8.8.8.8', 'a v4 peer on a dual-stack socket is the same peer');

  // A trusted proxy sending nonsense is a broken proxy, not an escape hatch.
  assert.strictEqual(ip(req('127.0.0.1', 'not-an-address')), '127.0.0.1');
  assert.strictEqual(ip(req('127.0.0.1', '')), '127.0.0.1');
  assert.strictEqual(ip(req('127.0.0.1', '99.99.99.99.99')), '127.0.0.1');
  // A very long header value was previously used verbatim as a Map key.
  assert.strictEqual(ip(req('127.0.0.1', 'x'.repeat(40000))), '127.0.0.1');
  // Only the nearest hop can have been written by our own edge.
  assert.strictEqual(ip(req('127.0.0.1', '8.8.8.8, 1.1.1.1')), '8.8.8.8');

  // No header at all is the shared-bucket case, and it must still be the peer
  // rather than a constant: 'unknown' for everyone is one bucket for everyone.
  assert.strictEqual(ip(req('127.0.0.1')), '127.0.0.1');
});

// ── The default that cannot be tested by testing ─────────────────────────────
// This one is here because getting it right and getting it wrong look identical
// from every other test in the repo. The suites all drive the relay over
// 127.0.0.1, so a trusted set of loopback alone is green everywhere. Production
// publishes the relay as 127.0.0.1:3001->3000 in docker, and the peer address
// the process inside the container sees is the bridge gateway in 172.16.0.0/12.
// Ship loopback-only and every real client collapses into one bucket, quietly,
// and the tests keep passing. So the ranges are asserted by name.
test('the trusted set covers the peer the relay actually sees in production', () => {
  const ip = clientIp.makeClientIp({});
  for (const peer of ['127.0.0.1', '::1', '172.17.0.1', '172.18.0.1', '10.1.2.3', '192.168.1.1']) {
    assert.strictEqual(ip({ socket: { remoteAddress: peer }, headers: { 'x-real-ip': '8.8.8.8' } }), '8.8.8.8',
      `${peer} must be trusted: it is a place nginx or the docker bridge can be, and if it is not ` +
      'trusted then every client behind it shares one rate-limit bucket');
  }
  for (const peer of ['203.0.113.9', '8.8.8.8', '2001:db8::1']) {
    assert.strictEqual(ip({ socket: { remoteAddress: peer }, headers: { 'x-real-ip': '9.9.9.9' } }), peer,
      `${peer} is a public address and must never be trusted to name someone else`);
  }
});

test('an operator can move the trust boundary, and moving it actually moves it', () => {
  const narrow = clientIp.makeClientIp({ trusted: '127.0.0.1/32' });
  assert.strictEqual(narrow({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-real-ip': '8.8.8.8' } }), '8.8.8.8');
  assert.strictEqual(narrow({ socket: { remoteAddress: '172.17.0.1' }, headers: { 'x-real-ip': '8.8.8.8' } }), '172.17.0.1',
    'a narrowed TRUSTED_PROXY_CIDRS must really narrow, or the setting is decoration');
});

// ── The gate must be able to go red ──────────────────────────────────────────
// Both halves, against synthetic inputs, so a reader can see what a failure
// looks like without breaking anything.
test('the gate itself fires on the shapes it is meant to catch', () => {
  // The edge half: a block that proxies to a relay and settles nothing.
  const broken = `
server {
    location / { proxy_pass http://127.0.0.1:3001; proxy_set_header Host $host; }
}`;
  const blocks = locationBlocks(broken).filter((b) => RELAY_UPSTREAM.test(b.body));
  assert.strictEqual(blocks.length, 1, 'the parser must find the block');
  assert.ok(!REQUIRED[0][1].test(blocks[0].body), 'and must see that X-Real-IP is absent');

  const fixed = `
server {
    location / { proxy_pass http://127.0.0.1:3001; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Internal-Auth ""; proxy_set_header X-Verified-Email-Hash ""; }
}`;
  const okBlocks = locationBlocks(fixed).filter((b) => RELAY_UPSTREAM.test(b.body));
  for (const [name, re] of REQUIRED) assert.ok(re.test(okBlocks[0].body), `${name} is seen when present`);

  // And a block that reaches nothing relay-shaped is not this contract.
  const staticOnly = `
server {
    location / { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }
}`;
  assert.strictEqual(locationBlocks(staticOnly).filter((b) => RELAY_UPSTREAM.test(b.body)).length, 0,
    'the static site is not behind a per-IP limiter and must not be dragged in');

  // The lock half: the pre-fix implementation, written out, must fail the
  // property the fixed one passes.
  const oldGetClientIp = (req) => req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  assert.strictEqual(oldGetClientIp({ socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-real-ip': '8.8.8.8' } }), '8.8.8.8',
    'this is the bug, reproduced: the old line let a stranger pick their address');
  const now = clientIp.makeClientIp({});
  assert.notStrictEqual(now({ socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-real-ip': '8.8.8.8' } }), '8.8.8.8',
    'and the current one must not');
});
