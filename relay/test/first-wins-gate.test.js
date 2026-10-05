'use strict';
// THE FIRST-WINS GATE. A slot addressed by a value the requester can compute
// from public information may not be refilled by somebody else.
//
// WHY THIS EXISTS. Two of the 2026-09-05 findings are the same sentence written
// about two registries:
//
//   3    POST /v2/pubkey, the invite branch: `pubkeys.set(device_id, ...)`
//        unconditional, so whoever saw the ?s= token in a share link could
//        overwrite both key slots of a ParaShare session and read along. Fixed
//        the same evening with a 409.
//   22b  POST /v2/did/register: `didRegistry.set(did, ...)` unconditional, and
//        a DID is sha3-256(device_id + ecdh_pub), both of which GET /v2/did/:did
//        hands back to anyone. The existence test that was there,
//        `const _didIsNew = !didRegistry.has(did)`, fed a COUNTER and not a
//        refusal, which is what made it read as careful code.
//
// That last shape is the tell, and it is why this gate scans rather than naming
// two routes: an existence check whose answer decides how much to increment is
// indistinguishable, at a glance, from one that decides whether to say no.
//
// WHAT IT REQUIRES
//   F1  every write to an identity registry (didRegistry, pubkeys) sits in a
//       block that can answer 409. Not "checks existence" -- refuses.
//   F2  the refusal compares the OWNER, not merely the presence of an entry. A
//       slot that refuses its own owner cannot be refreshed, and a device that
//       cannot refresh loses itself when its key expires.
//   F3  a counter fed by an existence test is never the only use of that test.
//
// The behavioural halves live in route-omission-gate.test.js, DOOR 3 (pubkeys)
// and DOOR 4 (didRegistry), on a really booted relay.
//
// Runs anywhere: no redis, no engine, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
const LINES = SRC.split('\n');

// The registries whose key is a slot identity rather than an internal handle.
const REGISTRIES = /^\s*(didRegistry|pubkeys)\.set\(/;

// Starts one line ABOVE the write. A multi-line `pubkeys.set(slot, {` opens a
// brace on its own line, so walking back from the write itself finds that brace
// and returns the object literal as the "block". The gate then reported the
// route as unguarded while the 409 sat four lines above it.
function blockAround(idx) {
  let depth = 0; let start = Math.max(0, idx - 1);
  for (let i = idx - 1; i >= 0; i--) {
    const l = LINES[i];
    depth += (l.match(/\}/g) || []).length - (l.match(/\{/g) || []).length;
    if (depth < 0) { start = i; break; }
  }
  let d = 0; let end = LINES.length - 1;
  for (let i = start; i < LINES.length; i++) {
    const l = LINES[i];
    d += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length;
    if (i > start && d <= 0) { end = i; break; }
  }
  return { text: LINES.slice(start, end + 1).join('\n'), from: start + 1, to: end + 1 };
}

function writes() {
  const out = [];
  LINES.forEach((l, i) => { if (REGISTRIES.test(l)) out.push({ n: i + 1, text: l.trim(), block: blockAround(i) }); });
  return out;
}

test('every identity-slot write sits behind a refusal, not just an existence test', () => {
  const found = writes();
  assert.ok(found.length >= 4, `only ${found.length} identity-registry writes found; the scanner has drifted`);
  const offenders = [];
  for (const w of found) {
    if (!/writeHead\(409/.test(w.block.text)) offenders.push(`relay.js:${w.n} (block ${w.block.from}-${w.block.to}) can overwrite a slot without ever answering 409`);
  }
  assert.deepStrictEqual(offenders, [], `an identity slot that anyone can refill:\n  ${offenders.join('\n  ')}`);
});

test('the refusal is about the owner, so the owner can still refresh', () => {
  // A bare presence check turns every honest refresh into a 409. The pubkey
  // slots refuse on a LIVE entry and let an expired one through; the DID
  // registry refuses on a DIFFERENT owner and lets the same one re-register.
  // Both are "not you", spelled for their own lifetime model.
  const offenders = [];
  for (const w of writes()) {
    const b = w.block.text;
    const ownerAware = /\.key !== ownerKey/.test(b)          // didRegistry
      || /expires \|\| Date\.now\(\) </.test(b)              // a live-slot check
      || /ecdh_pub !== d\.ecdh_pub/.test(b);                 // an identical refresh
    if (!ownerAware) offenders.push(`relay.js:${w.n} refuses on presence alone; an honest refresh gets a 409`);
  }
  assert.deepStrictEqual(offenders, [], `a slot nobody can refresh:\n  ${offenders.join('\n  ')}`);
});

test('an existence test never only feeds a counter', () => {
  // The exact idiom finding 22b hid behind. `has()` whose result is used for
  // arithmetic and nothing else looks like a guard and is not one.
  const offenders = [];
  LINES.forEach((l, i) => {
    const m = /const\s+(\w+)\s*=\s*!?\s*(didRegistry|pubkeys|apiKeys)\.has\(/.exec(l);
    if (!m) return;
    const name = m[1];
    const block = blockAround(i).text;
    const uses = block.split('\n').filter((x) => new RegExp(`\\b${name}\\b`).test(x) && !x.includes(`const ${name}`));
    const refuses = uses.some((x) => /writeHead\(|return .*(409|403|401|conflict)/i.test(x));
    const counts = uses.some((x) => /\+ 1|\+\+|set\(.*\+/.test(x));
    if (counts && !refuses) offenders.push(`relay.js:${i + 1} \`${name}\` decides a counter and nothing else`);
  });
  assert.deepStrictEqual(offenders, [], `an existence test that only counts:\n  ${offenders.join('\n  ')}`);
});

test('the DID pubkey slot is not a shared namespace', () => {
  // Under DID-auth apiKey is '' and acctOf('') returns '', so the old
  // `${device_id}:${acctOf(apiKey)}` collapsed to `${device_id}:` for every
  // DID-authenticated caller at once, readable through GET /v2/pubkey/:device.
  // The slot expression itself is unchanged; what closed it is that the write
  // now refuses a live slot holding a different key.
  const start = SRC.indexOf("if (path === '/v2/did/register'");
  assert.ok(start > 0, 'the DID register route was not found');
  const route = SRC.slice(start, SRC.indexOf("\n  // ── GET /v2/did ", start));
  assert.match(route, /_heldPk && \(!_heldPk\.expires \|\| Date\.now\(\) < _heldPk\.expires\)/, 'the DID route writes a pubkey slot without checking whether it is live');
  assert.match(route, /writeHead\(409/, 'the DID route cannot refuse anything');
});

test('self-test: the scanner catches the pre-repair shape and clears the repaired one', () => {
  const broken = [
    "  if (path === '/v2/x' && req.method === 'POST') {",
    '    const isNew = !didRegistry.has(id);',
    '    didRegistry.set(id, { key: ownerKey });',
    '    if (isNew && ownerKey) counts.set(ownerKey, (counts.get(ownerKey) || 0) + 1);',
    '    res.writeHead(200); return res.end();',
    '  }',
  ].join('\n');
  const fixed = [
    "  if (path === '/v2/x' && req.method === 'POST') {",
    '    const held = didRegistry.get(id);',
    "    if (held && held.key !== ownerKey) { res.writeHead(409); return res.end(); }",
    '    didRegistry.set(id, { key: ownerKey });',
    '    res.writeHead(200); return res.end();',
    '  }',
  ].join('\n');

  const scanFor409 = (src) => src.split('\n').some((l) => REGISTRIES.test(l)) && /writeHead\(409/.test(src);
  assert.strictEqual(scanFor409(broken), false, 'the gate would pass the pre-repair shape');
  assert.strictEqual(scanFor409(fixed), true, 'the gate would fail the repaired shape');
});
