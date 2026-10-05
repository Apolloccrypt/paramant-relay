// Herreview #560, N2. co-sign.js sent the invitee to
// /auth/login?return=<path + ?t=<invite token> + #ks=<key half>>. A fragment
// never leaves the browser, but inside a query it reaches the server and its
// access log. Now the full address waits in sessionStorage and the login page
// only gets the path plus ?resume=1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const JS = readFileSync(join(ROOT, 'frontend/co-sign.js'), 'utf8');
const { stashReturn, resumeReturn } = await import(pathToFileURL(join(ROOT, 'frontend/js/login-return.js')).href);

function fakeStorage() {
  const m = new Map();
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}
const LINK = { pathname: '/co-sign', search: '?env=ENVabcdefghijklmnopqrst&p=1&t=SECRETinvitetoken1234567890', hash: '#ks=SECRETkeyhalf' };

test('the login return path carries neither the invite token nor the key fragment', () => {
  const st = fakeStorage();
  const ret = stashReturn(st, LINK, 1000);
  assert.equal(ret, '/co-sign?resume=1');
  assert.doesNotMatch(ret, /SECRET/);
});

test('after login the full address comes back once, on the same path only', () => {
  const st = fakeStorage();
  stashReturn(st, LINK, 1000);
  const calls = [];
  const hist = { state: null, replaceState: (_s, _t, url) => calls.push(url) };
  assert.equal(resumeReturn(st, { pathname: '/elders', search: '?resume=1', hash: '' }, hist, 2000), false);
  stashReturn(st, LINK, 1000);
  assert.equal(resumeReturn(st, { pathname: '/co-sign', search: '?resume=1', hash: '' }, hist, 2000), true);
  assert.deepEqual(calls, ['/co-sign' + LINK.search + LINK.hash]);
  assert.equal(resumeReturn(st, { pathname: '/co-sign', search: '?resume=1', hash: '' }, hist, 2000), false, 'only once');
});

test('a stash older than an hour is not restored, and without ?resume=1 nothing happens', () => {
  const st = fakeStorage();
  const hist = { state: null, replaceState: () => assert.fail('must not restore') };
  stashReturn(st, LINK, 0);
  assert.equal(resumeReturn(st, { pathname: '/co-sign', search: '', hash: '' }, hist, 10), false);
  assert.equal(resumeReturn(st, { pathname: '/co-sign', search: '?resume=1', hash: '' }, hist, 3_600_001), false);
});

test('co-sign.js no longer builds the login return from location.search or location.hash', () => {
  const fn = JS.slice(JS.indexOf('function loginCtaHtml'), JS.indexOf('function showClosed'));
  assert.ok(fn.length > 0);
  assert.doesNotMatch(fn, /location\.(search|hash)/, 'the token and the key fragment must stay out of ?return=');
  assert.match(fn, /stashReturn\(/);
  assert.match(JS, /resumeReturn\(window\.sessionStorage, location, history\)/);
});
