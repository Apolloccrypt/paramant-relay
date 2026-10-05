// Eindmatrix COSIGN-46-A: "Stuur mij de link opnieuw" mailed a link without
// the key half (#ks=), because no server has that half. It opened the request
// and not the document. The signer's browser now keeps the half from the full
// invitation once it has opened the document, and a link without one, for
// the same request and party, opens the document in that browser.
// Run: node --test tests/cosign-link-opnieuw-opent.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};
const { rememberShare, recallShare, SHARE_MAX_MS } = await import(path.join(ROOT, 'frontend/js/cosign-share-memory.js'));
const KS = 'v1.' + 'A'.repeat(43);

test('the half is remembered per request and party, and recalled', () => {
  mem.clear();
  const now = Date.parse('2026-10-05T10:00:00Z');
  assert.equal(rememberShare('env_demo', 2, KS, '2026-10-09T10:00:00Z', now), true);
  assert.equal(recallShare('env_demo', 2, now + 1000), KS);
  assert.equal(recallShare('env_demo', 1, now + 1000), null, 'another party gets nothing');
  assert.equal(recallShare('env_other', 2, now + 1000), null, 'another request gets nothing');
});

test('it lives until the signing period ends, at most eight days, then it is gone', () => {
  mem.clear();
  const now = Date.parse('2026-10-05T10:00:00Z');
  rememberShare('env_demo', 0, KS, '2026-10-06T10:00:00Z', now);
  assert.equal(recallShare('env_demo', 0, Date.parse('2026-10-06T09:59:00Z')), KS);
  assert.equal(recallShare('env_demo', 0, Date.parse('2026-10-06T10:00:01Z')), null);
  assert.equal(mem.size, 0, 'an expired half is removed');
  rememberShare('env_demo', 0, KS, '2027-01-01T00:00:00Z', now);
  assert.equal(JSON.parse([...mem.values()][0]).exp, now + SHARE_MAX_MS);
  assert.equal(SHARE_MAX_MS, 8 * 864e5);
  assert.equal(rememberShare('env_demo', 0, KS, '2026-10-01T00:00:00Z', now), false, 'a period that already ended keeps nothing');
});

test('only a well-formed half is kept', () => {
  mem.clear();
  assert.equal(rememberShare('env_demo', 0, 'v1.short', null), false);
  assert.equal(rememberShare('env_demo', 0, 'x'.repeat(46), null), false);
  mem.set('paramant.cosign.share.v1:env_demo:0', JSON.stringify({ s: 'garbage', exp: Date.now() + 1e6 }));
  assert.equal(recallShare('env_demo', 0), null);
});

test('co-sign opens a link without the half with the remembered one, and remembers only after it opened', () => {
  const src = read('frontend/co-sign.js');
  const fn = src.slice(src.indexOf('async function fetchAndOpenCapsule'), src.indexOf('async function loadDeliveredDocument'));
  assert.match(fn, /recallShare\(envId, partyIndex\)/);
  const decrypt = fn.indexOf('await decryptDocumentCapsule(');
  const remember = fn.indexOf('rememberShare(envId, partyIndex,');
  assert.ok(decrypt > 0 && remember > decrypt, 'the half is kept only after it proved to open the document');
  assert.match(src, /fetchAndOpenCapsule\(url, envId, partyIndex\)/);
  assert.match(src, /de sleutel die deze browser bewaarde van uw eerste uitnodiging, en klopt met dit verzoek/);
});

test('sign-out and another account wipe the halves, like the sender links', () => {
  const nav = read('frontend/js/nav-auth.js');
  assert.match(nav, /var COSIGN_SHARE = 'paramant\.cosign\.share\.v1:';/);
  const wipe = nav.slice(nav.indexOf('function wipeLocal()'), nav.indexOf('window.paramantWipeLocal'));
  assert.match(wipe, /cosignShares\(\)\.forEach/);
  assert.match(nav, /cosignLinks\(\)\.concat\(cosignShares\(\)\)/, 'expired halves are swept');
});

test('the dashboard says where the resent link opens the document', () => {
  const dash = read('frontend/js/dashboard.js');
  assert.match(dash, /if \(heldShare\(id\)\) note\.textContent/);
  assert.match(dash, /In deze browser opent de nieuwe link het document: hij bewaarde de sleutel van uw eerste uitnodiging\. Op een ander apparaat opent hij alleen het verzoek/);
});
