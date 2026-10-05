'use strict';
// no-full-ip-in-logs: /privacy says an IP is processed transiently for security
// and abuse prevention and is never logged for analytics or profiling, and
// /security says nginx access logging is off. Three admin paths wrote the full
// client IP to stdout anyway, and one of them wrote the full e-mail address
// next to it. A container log is not transient.
//
// This suite has two halves and they fail for different reasons:
//   1. the helper: masking is correct and reversible by nobody.
//   2. the call sites: the three real statements in admin/server.js are lifted
//      out of the source, executed against a captured console, and the output
//      is asserted. Reverting one of them to a raw console.log turns this red
//      even though the helper is still perfect.
//
// Run: node admin/test/log-redact.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { maskIpForLog, maskEmailForLog, redact, logRedacted } = require('../lib/log-redact');

const SERVER_PATH = path.join(__dirname, '..', 'server.js');

// Written independently of the implementation on purpose: if these mirrored the
// library's own patterns they would agree with a broken library.
const FULL_IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
const FULL_IPV6 = /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})+/;
// A local part of two or more characters in front of a domain. The masked form
// is `d***@example.com`, whose last character before the @ is a `*` and so not
// in the class; a plaintext address of any realistic length is.
const PLAINTEXT_EMAIL = /[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

// Sample PII. RFC 5737 / RFC 3849 documentation ranges, never a real subject.
const SAMPLE_IPV4 = '203.0.113.42';
const SAMPLE_IPV6 = '2001:db8:85a3:1319:8a2e:370:7348:1';
const SAMPLE_EMAIL = 'demo@example.com';

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// Assert one finished log line carries nothing identifying.
function assertClean(line, what) {
  assert.ok(!FULL_IPV4.test(line), `${what}: full IPv4 in output: ${line}`);
  assert.ok(!FULL_IPV6.test(line), `${what}: full IPv6 in output: ${line}`);
  assert.ok(!PLAINTEXT_EMAIL.test(line), `${what}: plaintext e-mail in output: ${line}`);
  assert.ok(!line.includes(SAMPLE_IPV4), `${what}: sample IPv4 verbatim: ${line}`);
  assert.ok(!line.includes(SAMPLE_IPV6), `${what}: sample IPv6 verbatim: ${line}`);
  assert.ok(!line.includes(SAMPLE_EMAIL), `${what}: sample address verbatim: ${line}`);
}

// Swap console.log/warn/error/info for a collector, run fn, always restore.
function captureConsole(fn) {
  const levels = ['log', 'warn', 'error', 'info'];
  const saved = {};
  const lines = [];
  for (const l of levels) {
    saved[l] = console[l];
    console[l] = (...args) => lines.push(args.map(a => (typeof a === 'string' ? a : String(a))).join(' '));
  }
  try { fn(); } finally { for (const l of levels) console[l] = saved[l]; }
  return lines;
}

function testMaskIp() {
  const table = [
    [SAMPLE_IPV4, '203.0.113.x'],
    ['198.51.100.7', '198.51.100.x'],
    [SAMPLE_IPV6, '2001:db8:85a3::x'],
    ['2001:db8:85a3::8a2e:370:7334', '2001:db8:85a3::x'],
    ['::ffff:203.0.113.42', '203.0.113.x'],
    ['fe80::1%eth0', 'fe80:0:0::x'],
    ['unknown', 'unknown'],
    ['', ''],
    [null, ''],
    ['not-an-address', '***'],
  ];
  for (const [input, want] of table) {
    assert.strictEqual(maskIpForLog(input), want, `maskIpForLog(${JSON.stringify(input)})`);
    assertClean(String(maskIpForLog(input)), 'maskIpForLog');
  }
  // /24 and /48: the fourth octet and the last five hextets are gone, and two
  // addresses that differ only inside the prefix stay distinguishable.
  assert.notStrictEqual(maskIpForLog('203.0.113.42'), maskIpForLog('203.0.114.42'), '/24 keeps the third octet');
  assert.strictEqual(maskIpForLog('203.0.113.42'), maskIpForLog('203.0.113.99'), 'host part is gone');
  assert.strictEqual(maskIpForLog('2001:db8:85a3::1'), maskIpForLog('2001:db8:85a3:ffff::2'), 'past the /48 is gone');
  ok('maskIpForLog truncates to /24 and /48 and leaves no full address');
}

function testMaskEmail() {
  assert.strictEqual(maskEmailForLog(SAMPLE_EMAIL), 'd***@example.com');
  assert.strictEqual(maskEmailForLog('a@example.org'), 'a***@example.org');
  assert.strictEqual(maskEmailForLog('@example.org'), '***', 'no local part is still not passed through');
  assert.strictEqual(maskEmailForLog(''), '');
  assert.strictEqual(maskEmailForLog(null), '');
  // The domain survives on purpose: without it these lines cannot answer which
  // provider is flooding signup, which is the only reason they exist.
  assert.ok(maskEmailForLog(SAMPLE_EMAIL).endsWith('@example.com'), 'domain kept');
  assertClean(maskEmailForLog(SAMPLE_EMAIL), 'maskEmailForLog');
  ok('maskEmailForLog drops the local part and keeps the domain');
}

function testRedactScrubber() {
  const dirty = `[signup] ${SAMPLE_EMAIL} from ${SAMPLE_IPV4} and ${SAMPLE_IPV6} and ::ffff:203.0.113.9`;
  assertClean(redact(dirty), 'redact');
  // The separator in front of the address. An earlier lookbehind excluded ":",
  // so every one of these key:value shapes went through the scrubber intact.
  // They are the ordinary way a log line is written, so they are the cases the
  // scrubber has to get right, not the exotic ones.
  const separators = [
    `ip:${SAMPLE_IPV4}`,
    `ipv6:${SAMPLE_IPV6}`,
    `ip=${SAMPLE_IPV4} ua=curl`,
    `addr:2001:db8:85a3::8a2e:370:7334`,
    `client:::ffff:203.0.113.42`,
    `peer=::ffff:203.0.113.42`,
    `[2001:db8::1]:443`,
    `v6:::1`,
    `x=fe80::1%eth0`,
    `ip:${SAMPLE_EMAIL} from ${SAMPLE_IPV4}`,
  ];
  for (const line of separators) assertClean(redact(line), `redact after a separator: ${line}`);
  // And it leaves alone the things a log line legitimately carries. The C++
  // scope operator is the reason the lookbehind still blocks a word character:
  // std::vector must survive, and an address is never written glued to a word.
  const untouched = [
    'timestamp 12:34:56 duration 1200ms',
    'at 2026-09-03T01:02:03Z',
    'build 3.1.0 node v22.11.0',
    'emailHash=8f14e45fceea167a5a36dedd4bea2543',
    'std::vector<int> and foo::bar and ns::method',
    'key::value',
    'ip=unknown',
  ];
  for (const line of untouched) {
    assert.strictEqual(redact(line), line, `redact must not touch: ${line}`);
  }
  // Non-strings pass through untouched so an object argument is not stringified.
  const obj = { ip: SAMPLE_IPV4 };
  assert.strictEqual(redact(obj), obj);
  // Known and accepted: a four-part version number reads as an address and is
  // masked. Over-scrubbing costs a digit in a log line, under-scrubbing costs
  // an IP. Pinned so the trade-off is a decision and not a surprise.
  assert.strictEqual(redact('schema 1.2.3.4'), 'schema 1.2.3.x', 'four-part versions are over-scrubbed on purpose');
  ok('redact scrubs addresses and leaves ordinary log text alone');
}

function testLogRedacted() {
  const lines = captureConsole(() => {
    logRedacted('log', `[t] ${SAMPLE_EMAIL} from ${SAMPLE_IPV4}`);
    logRedacted('warn', `[t] v6 ${SAMPLE_IPV6}`);
    logRedacted('nosuchlevel', `[t] falls back to log: ${SAMPLE_IPV4}`);
  });
  assert.strictEqual(lines.length, 3, 'every call reached a console level');
  for (const line of lines) assertClean(line, 'logRedacted');
  ok('logRedacted masks whatever a call site forgot');
}

// ── The call sites themselves ────────────────────────────────────────────────
// Lift the three statements out of admin/server.js and run them for real, so
// the assertion is about the shipped line and not about a copy of it.
function readCallSites() {
  const src = fs.readFileSync(SERVER_PATH, 'utf8');
  const tags = [
    '[signup] duplicate signup attempt',
    '[signup] pending signup for',
    '[totp-reset-req] rate limited',
  ];
  const found = [];
  for (const tag of tags) {
    const hits = src.split('\n').filter(l => l.includes(tag) && /(console|logRedacted)\s*\(/.test(l));
    assert.strictEqual(hits.length, 1, `expected exactly one log statement for "${tag}", got ${hits.length}`);
    found.push({ tag, stmt: hits[0].trim() });
  }
  return { src, found };
}

function testCallSitesAreRedacted() {
  const { found } = readCallSites();
  for (const { tag, stmt } of found) {
    // The masking must be at the call site, not left to the scrubber alone.
    assert.ok(stmt.startsWith('logRedacted('), `"${tag}" must log through logRedacted, got: ${stmt}`);
    const lines = captureConsole(() => {
      const run = new Function(
        'ip', 'norm', 'email', 'emailHash', 'logRedacted', 'maskIpForLog', 'maskEmail', 'console',
        stmt
      );
      const fake = { log: (...a) => console.log(...a), warn: (...a) => console.warn(...a), error: (...a) => console.error(...a) };
      run(SAMPLE_IPV4, SAMPLE_EMAIL, SAMPLE_EMAIL,
          '8f14e45fceea167a5a36dedd4bea2543', logRedacted, maskIpForLog, maskEmailForLog, fake);
      run(SAMPLE_IPV6, SAMPLE_EMAIL, SAMPLE_EMAIL,
          '8f14e45fceea167a5a36dedd4bea2543', logRedacted, maskIpForLog, maskEmailForLog, fake);
    });
    assert.strictEqual(lines.length, 2, `"${tag}" produced ${lines.length} lines, expected 2`);
    for (const line of lines) assertClean(line, tag);
  }
  ok('the three admin log statements emit no full IP and no plaintext address');
}

// Nothing else in the file may interpolate a raw IP or address into a log line,
// so a fourth path cannot reintroduce this by copying an old one.
function testNoOtherRawInterpolation() {
  const src = fs.readFileSync(SERVER_PATH, 'utf8');
  const offenders = [];
  src.split('\n').forEach((line, i) => {
    if (!/(console\.(log|warn|error|info)|logRedacted)\s*\(/.test(line)) return;
    if (/\$\{\s*(ip|norm|email|clientIp|remoteAddress)\s*\}/.test(line)) offenders.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepStrictEqual(offenders, [], `log statements interpolate a raw IP or address:\n  ${offenders.join('\n  ')}`);
  ok('no log statement in admin/server.js interpolates a raw IP or address');
}

function main() {
  testMaskIp();
  testMaskEmail();
  testRedactScrubber();
  testLogRedacted();
  testCallSitesAreRedacted();
  testNoOtherRawInterpolation();
  console.log(`\nlog-redact: ${passed} checks passed`);
}

main();
