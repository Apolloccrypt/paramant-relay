// A paraaf on every page, for every signer.
//
// The complaint that started this (2026-09-27, a paying customer): "Ik moest net
// een document door totaal 2 personen laten ondertekenen met op elke blad ook
// nog een paraaf. Ik zie die functie niet." The requester could already repeat
// their seal on every page from /sign. A co-signer could not: the relay accepted
// a manifest of at most 8 seal/date fields, which cannot spell out an initial on
// every sheet of a 20-page contract.
//
// Manifest v2 adds one flag, all_pages, meaning "this mark, at these normalised
// coordinates, on every page". A flag and not a page list, because the relay
// never learns the page count.
//
// The load-bearing property is byte compatibility. The manifest is hashed into
// the signature (recipe 5), so if normalisation of a pre-v2 manifest changes by
// a single byte, every .psign proof ever issued stops verifying. These tests
// pin that, and pin that the three implementations of the normaliser agree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const envelope = require(join(ROOT, 'relay/envelope.js'));

// The relay exports what it exports; reach the normaliser the way the signing
// path does, through the canonical hash, so this test cannot pass against a
// function nothing calls.
const canonical = envelope.canonicalAppearance
  || envelope.__test__?.canonicalAppearance;
const normalise = envelope.normaliseAppearance
  || envelope.__test__?.normaliseAppearance;

const seal = (extra = {}) => ({ type: 'seal', page_index: 0, x: 0.1, y: 0.8, w: 0.36, h: 0.105, ...extra });

test('a pre-v2 manifest normalises to exactly the old bytes', { skip: !canonical }, () => {
  const out = canonical({ version: 1, fields: [seal()] });
  assert.equal(out, '{"version":1,"fields":[{"type":"seal","page_index":0,"x":0.1,"y":0.8,"w":0.36,"h":0.105}]}',
    'every signature and .psign proof made before all_pages existed hashes these bytes');
});

test('an all_pages field raises the version and appends the flag', { skip: !normalise }, () => {
  const out = normalise({ version: 2, fields: [seal({ all_pages: true })] });
  assert.equal(out.version, 2);
  assert.equal(out.fields[0].all_pages, true);
  assert.equal(Object.keys(out.fields[0]).join(','), 'type,page_index,x,y,w,h,all_pages',
    'the flag goes last: any other key order changes the hashed bytes');
});

test('all_pages:false is not emitted at all', { skip: !normalise }, () => {
  const out = normalise({ version: 1, fields: [seal({ all_pages: false })] });
  assert.equal(out.version, 1, 'an explicit false is still a v1 manifest');
  assert.equal('all_pages' in out.fields[0], false,
    'emitting false would change the bytes of manifests that mean exactly what v1 meant');
});

test('a repeated field must anchor on the first page', { skip: !normalise }, () => {
  assert.throws(() => normalise({ version: 2, fields: [seal({ page_index: 3, all_pages: true })] }),
    /all_pages page/, 'repeating "from page 4" is a caller bug, not a reinterpretation');
});

test('all_pages requires the version that describes it', { skip: !normalise }, () => {
  assert.throws(() => normalise({ version: 1, fields: [seal({ all_pages: true })] }),
    /version 2/, 'a v1 manifest cannot carry a v2 field');
});

test('a non-boolean flag is rejected', { skip: !normalise }, () => {
  assert.throws(() => normalise({ version: 2, fields: [seal({ all_pages: 'yes' })] }),
    /all_pages/);
});

test('version 3 is still unsupported', { skip: !normalise }, () => {
  assert.throws(() => normalise({ version: 3, fields: [] }), /unsupported appearance version/);
});

// The three normalisers that must agree byte for byte: the relay (authority),
// the signer (produces the bytes) and the verifier (reproduces them from a
// .psign file). Compared as source, because the browser modules do not load
// under node --test without a DOM.
const SIGNER = readFileSync(join(ROOT, 'frontend/js/parasign-signer.js'), 'utf8');
const VERIFY = readFileSync(join(ROOT, 'frontend/parasign-verify.js'), 'utf8');

test('the signer knows all_pages and keeps the flag last', () => {
  assert.match(SIGNER, /clean\.all_pages = true/);
  assert.match(SIGNER, /version: anyAllPages \? 2 : 1/);
});

test('the verifier reproduces the same bytes', () => {
  assert.match(VERIFY, /field\.all_pages === true.*clean\.all_pages = true/s,
    'the verifier must emit the flag only when true, exactly as the relay does');
  assert.match(VERIFY, /version: anyAllPages \? 2 : 1/);
});

// The co-signer is the whole point: this is what the customer could not find.
const COSIGN_JS = readFileSync(join(ROOT, 'frontend/co-sign.js'), 'utf8');
for (const page of ['frontend/co-sign.html', 'frontend/en/co-sign.html']) {
  test(`${page}: a co-signer can ask for every page`, () => {
    const html = readFileSync(join(ROOT, page), 'utf8');
    assert.match(html, /id="appearance-allpages"/,
      'the co-signer needs the same choice the requester has on /sign');
  });
}

test('co-sign draws and stamps the repeat on every page', () => {
  assert.match(COSIGN_JS, /field\.all_pages\s*\n?\s*\? pages/,
    'the preview must show every repeat, or the signer approves marks they never saw');
  assert.match(COSIGN_JS, /const targets = field\.all_pages/,
    'the stamped PDF must repeat the field too');
});
