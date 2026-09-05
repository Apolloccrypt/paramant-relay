// The keyless surface, checked in both directions.
//
// frontend/docs.html publishes an API table with an Auth column, and a row that
// says "n/a" is a public invitation: it tells the world this route answers
// without a key. Nothing checked that column against the relay, in either
// direction. A route documented as public but actually gated is a support
// ticket; a route that is public but not documented as such is the thing you
// only find out about from someone else.
//
// POST /v2/anon-inbound is the case that started this: keyless, outside the
// entitlement and quota gates, advertised with Auth "n/a", and open since 20
// July 2026 when feat/close-anon-inbound proposed closing it. It stays open on
// purpose, and relay/lib/public-routes.js records why. What this suite closes is
// the drift around it.
//
// Three checks:
//   1. every docs row marked "n/a" is a declared public route
//   2. every declared public route is in the docs, marked "n/a"
//   3. every declared route dispatches ABOVE the API-key gate in relay.js, and
//      the set of exemptions inside that gate is the declared set
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require_ = createRequire(import.meta.url);
const { PUBLIC_ROUTES, KEY_GATE_EXEMPTIONS } = require_(path.join(ROOT, 'relay/lib/public-routes.js'));

const docsHtml = fs.readFileSync(path.join(ROOT, 'frontend/docs.html'), 'utf8');
const relaySrc = fs.readFileSync(path.join(ROOT, 'relay/relay.js'), 'utf8');

// The API route table in docs.html: rows that open with a method pill. Four
// cells, of which the first is the method, the second the path and the last the
// Auth column; the description in between may carry its own markup.
function docRows() {
  const rows = [];
  for (const m of docsHtml.matchAll(/<tr><td><span class="method [^"]*">([A-Z]+)<\/span><\/td>([\s\S]*?)<\/tr>/g)) {
    const cells = [...m[2].matchAll(/<td>([\s\S]*?)<\/td>/g)]
      .map((c) => c[1].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim());
    if (cells.length < 3) continue;
    rows.push({ method: m[1], path: cells[0], auth: cells[cells.length - 1] });
  }
  return rows;
}

const rows = docRows();
const declared = new Map(PUBLIC_ROUTES.map((r) => [`${r.method} ${r.docs}`, r]));

test('the docs route table parses at all', () => {
  assert.ok(rows.length >= 15, `parsed ${rows.length} rows out of docs.html; the table shape changed`);
  assert.ok(rows.some((r) => r.path === '/health'), 'no /health row, so the parse is picking up the wrong table');
});

test('every route the docs advertise as keyless is a declared public route', () => {
  const undeclared = rows
    .filter((r) => /^n\/a$/i.test(r.auth))
    .filter((r) => !declared.has(`${r.method} ${r.path}`))
    .map((r) => `${r.method} ${r.path}`);
  assert.deepEqual(undeclared, [],
    'docs.html tells the world these need no key, and nothing in the relay says\n' +
    'they are meant to be public:\n  ' + undeclared.join('\n  ') + '\n' +
    'Either give it an entry in relay/lib/public-routes.js with the reason it is\n' +
    'safe, or correct the Auth column.');
});

test('every declared public route is documented, and documented as keyless', () => {
  const missing = [];
  const mislabelled = [];
  for (const [id, r] of declared) {
    const row = rows.find((x) => x.method === r.method && x.path === r.docs);
    if (!row) missing.push(id);
    else if (!/^n\/a$/i.test(row.auth)) mislabelled.push(`${id} is documented as Auth "${row.auth}"`);
  }
  assert.deepEqual(missing, [],
    'these answer an anonymous caller and the API docs do not list them:\n  ' + missing.join('\n  '));
  assert.deepEqual(mislabelled, [],
    'the docs claim a credential is needed where none is:\n  ' + mislabelled.join('\n  '));
});

// The line in relay.js that turns "no valid key" into 401. Everything dispatched
// before it answers without ever being asked for one.
function keyGateAt() {
  // The one and only gate, not the per-route re-checks: it is the branch that
  // pairs the key test with the exemptions.
  const at = relaySrc.indexOf('} else if (!keyData?.active');
  assert.notEqual(at, -1,
    'the API-key gate in relay.js is no longer the `} else if (!keyData?.active ...` branch');
  return at;
}

test('every declared public route dispatches above the API-key gate', () => {
  const gate = keyGateAt();
  const wrong = [];
  for (const r of PUBLIC_ROUTES) {
    const at = relaySrc.indexOf(r.src);
    if (at === -1) wrong.push(`${r.method} ${r.docs}: no handler matching ${r.src}`);
    else if (at > gate) wrong.push(`${r.method} ${r.docs}: handler sits BELOW the key gate, so it is not public`);
  }
  assert.deepEqual(wrong, [], wrong.join('\n  '));
});

test('the API-key gate has exactly the exemptions that are declared', () => {
  // The gate reads `if (isAdminPath) {...} else if (!keyData?.active && !isX && !isY)`.
  // Anything named there is a way past the key check. Pinning the set is what
  // makes a new one a decision somebody has to write down.
  const gate = keyGateAt();
  const stmt = relaySrc.slice(relaySrc.lastIndexOf('if (isAdminPath)', gate), relaySrc.indexOf('{', gate));
  const found = [...new Set([...stmt.matchAll(/\bis[A-Z]\w*/g)].map((m) => m[0]))].sort();
  assert.deepEqual(found, [...KEY_GATE_EXEMPTIONS].sort(),
    'the ways past the API-key gate have changed.\n' +
    `  in relay.js:  ${found.join(', ')}\n` +
    `  declared:     ${[...KEY_GATE_EXEMPTIONS].sort().join(', ')}\n` +
    'A new exemption is a new hole in the gate. Add it to KEY_GATE_EXEMPTIONS in\n' +
    'relay/lib/public-routes.js with the reason, or take it out of relay.js.');
});

test('the deprecated anonymous upload still carries its Sunset headers', () => {
  // It is not closed, so the retirement signal is the only honest thing a caller
  // has to go on. Losing it would turn a deprecation into a surprise.
  const anon = relaySrc.indexOf("path === '/v2/anon-inbound'");
  assert.notEqual(anon, -1, 'the anonymous upload route is gone; update public-routes.js');
  const handler = relaySrc.slice(anon, anon + 4000);
  assert.match(handler, /res\.setHeader\('Deprecation', 'true'\)/, 'the Deprecation header is gone');
  assert.match(handler, /res\.setHeader\('Sunset',/, 'the Sunset header is gone');
  assert.ok(declared.get('POST /v2/anon-inbound')?.deprecated,
    'the declaration no longer marks the anonymous upload deprecated');
});
