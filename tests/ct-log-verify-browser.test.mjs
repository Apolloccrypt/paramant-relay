// /ct-log may only say "Geverifieerd" / "Verified" after the browser itself has
// checked the pinned key, the signed tree head and the inclusion proof, and it
// must refuse when any of them is wrong. Driven in a real browser against a
// stubbed health relay built from relay/lib/ct-tree.js (the relay's own tree)
// and signed with a throwaway ML-DSA-65 key that the test pins in place of the
// real health key.
//
// WHY. Until 2026-10-06 the box said "✓ Geverifieerd: gevonden op index N" as
// soon as a prefix of the typed hash matched a row in the list the relay sent:
// a text search in the relay's own answer (RAPPORT.md section 4). The sabotage
// cases below are the point: a forged proof, a head signed by another key and a
// tree that rewrote its past must all fail to go green.
//
// Runs in Chromium; ~/bin/pw-webkit.sh runs the same file in WebKit.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const require = createRequire(import.meta.url);
const { CtMerkle } = require('../relay/lib/ct-tree.js');
const pqc = await import(path.join(ROOT, 'vendor', 'paramant-pqc.js'));

const RELAY = 'https://health.paramant.app';
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json', '.ico': 'image/x-icon' };
const aliases = { '/ct-log': '/ct-log.html', '/en/ct-log': '/en/ct-log.html' };

function canonicalJSON(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalJSON(v[k])).join(',') + '}';
}

const pinned = pqc.ml_dsa65.keygen(new Uint8Array(32).fill(11));
const stranger = pqc.ml_dsa65.keygen(new Uint8Array(32).fill(12));
const b64 = (u8) => Buffer.from(u8).toString('base64');
const fingerprint = Buffer.from(pqc.sha3_256(pinned.publicKey)).toString('hex');

// The real anchors file, with health's key and fingerprint swapped for ours.
const anchorsSrc = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'js', 'relay-trust-anchors.js'), 'utf8');
  const i = src.indexOf("host: 'health.paramant.app'");
  const fpAt = src.indexOf("fingerprint: '", i);
  const fpEnd = src.indexOf("'", fpAt + 14);
  const keyAt = src.indexOf("key: '", fpEnd);
  const keyEnd = src.indexOf("'", keyAt + 6);
  return src.slice(0, fpAt) + `fingerprint: '${fingerprint}'` + src.slice(fpEnd + 1, keyAt)
    + `key: '${b64(pinned.publicKey)}'` + src.slice(keyEnd + 1);
})();

const leaf = (tag, i) => crypto.createHash('sha3-256').update(`${tag}-${i}`).digest('hex');
function makeTree(n, tag = 'genuine') {
  const t = new CtMerkle();
  for (let i = 0; i < n; i++) t.append(leaf(tag, i));
  return t;
}
function sthFor(tree, keys = pinned) {
  const payload = { relay_id: RELAY, sha3_root: tree.root(), timestamp: Date.parse('2026-10-06T10:00:00Z'), tree_size: tree.size, version: 1 };
  return { ...payload, signature: b64(pqc.ml_dsa65.sign(keys.secretKey, Buffer.from(canonicalJSON(payload), 'utf8'))) };
}

// A stub relay whose behaviour each test sets: which tree, which signer, and
// optional sabotage of the proof.
function relayStub(state) {
  return async (route) => {
    const u = new URL(route.request().url());
    const json = (status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body),
      headers: { 'access-control-allow-origin': '*' } });
    const t = state.tree;
    if (u.pathname === '/health') return json(200, { ok: true, version: '3.1.1' });
    if (u.pathname === '/v2/ct/log') {
      const from = parseInt(u.searchParams.get('from') || '0', 10);
      const limit = parseInt(u.searchParams.get('limit') || '100', 10);
      const entries = [];
      for (let i = from; i < Math.min(t.size, from + limit); i++) {
        entries.push({ index: i, type: 'transfer', leaf_hash: t.leaf(i), tree_hash: t.root(i + 1), ts: Date.parse('2026-10-06T09:00:00Z') });
      }
      return json(200, { ok: true, size: t.size, root: t.root(), entries });
    }
    if (u.pathname === '/v2/sth') {
      if (state.sthDown) return json(503, { error: 'down' });
      return json(200, { ok: true, sth: sthFor(t, state.signer || pinned) });
    }
    const pm = u.pathname.match(/^\/v2\/ct\/proof\/(\d+)$/);
    if (pm) {
      const i = parseInt(pm[1], 10);
      // state.oldRelay: a relay from before 3.1.2 ignores ?tree_size and
      // sends no tree_size field.
      const n = state.oldRelay ? i + 1 : parseInt(u.searchParams.get('tree_size') || String(i + 1), 10);
      let proof = t.inclusionProof(i, n);
      if (state.forgeProof && proof.length) {
        proof = proof.map((s, k) => (k === 0 ? { ...s, hash: s.hash.slice(0, -1) + (s.hash.endsWith('0') ? '1' : '0') } : s));
      }
      if (state.oldRelay) return json(200, { ok: true, index: i, leaf_hash: t.leaf(i), tree_hash: t.root(n), proof, ts: null });
      return json(200, { ok: true, index: i, leaf_hash: t.leaf(i), tree_size: n, tree_hash: t.root(n), proof, ts: null });
    }
    if (u.pathname === '/v2/sth/consistency') {
      const from = parseInt(u.searchParams.get('from'), 10);
      const to = parseInt(u.searchParams.get('to'), 10);
      return json(200, { ok: true, from, to, proof: t.consistencyProof(from, to) });
    }
    return json(404, { error: 'not stubbed' });
  };
}

function startServer() {
  const server = http.createServer((req, res) => {
    let name = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    name = aliases[name] || name;
    const file = path.join(ROOT, name);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, body) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

const server = await startServer();
const ORIGIN = 'http://127.0.0.1:' + server.address().port;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

async function openPage(state, route = '/ct-log', context = null) {
  const ctx = context || await browser.newContext({ viewport: { width: 1100, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.route('**/js/relay-trust-anchors.js*', (r) => r.fulfill({ status: 200, contentType: 'text/javascript', body: anchorsSrc }));
  await page.route(RELAY + '/**', relayStub(state));
  await page.goto(ORIGIN + route, { waitUntil: 'load' });
  await page.waitForFunction(() => document.getElementById('stat-total').textContent !== 'n/a');
  return { ctx, page, errors };
}

async function check(page, hash) {
  await page.fill('#verify-input', hash);
  await page.click('.verify-bar button');
  await page.waitForFunction(() => document.getElementById('verify-result').hasAttribute('data-verdict'));
  return {
    verdict: await page.getAttribute('#verify-result', 'data-verdict'),
    text: await page.textContent('#verify-result'),
    steps: await page.$$eval('#verify-result li', (els) => els.map((e) => e.dataset.step + ':' + e.dataset.ok)),
  };
}

test('a genuine entry goes green only after key, head and inclusion all held; growth is checked on the next visit', async () => {
  const state = { tree: makeTree(8) };
  const { ctx, page, errors } = await openPage(state);
  const r1 = await check(page, state.tree.leaf(3));
  assert.equal(r1.verdict, 'verified', r1.text);
  assert.match(r1.text, /✓ Geverifieerd: index 3 staat in de door deze relay ondertekende boom/);
  assert.deepEqual(r1.steps, ['key:t', 'sth:t', 'inclusion:t', 'consistency:n']);
  assert.match(r1.text, /Geen eerdere boomstand in deze browser/);
  assert.match(r1.text, /dat anderen dezelfde boom zien/);
  await page.close();

  // Same browser, the log has grown honestly: the consistency proof is checked.
  state.tree = makeTree(13);
  const again = await openPage(state, '/ct-log', ctx);
  const r2 = await check(again.page, state.tree.leaf(11));
  assert.equal(r2.verdict, 'verified', r2.text);
  assert.deepEqual(r2.steps, ['key:t', 'sth:t', 'inclusion:t', 'consistency:t']);
  assert.deepEqual(errors.concat(again.errors), []);
  await ctx.close();
});

test('a forged inclusion proof does not go green', async () => {
  const state = { tree: makeTree(9), forgeProof: true };
  const { ctx, page } = await openPage(state);
  const r = await check(page, state.tree.leaf(4));
  assert.equal(r.verdict, 'failed', r.text);
  assert.doesNotMatch(r.text, /Geverifieerd/);
  assert.ok(r.steps.includes('inclusion:f'), r.steps.join(','));
  await ctx.close();
});

test('a relay from before 3.1.2 (no ?tree_size) is "not checked", not accused', async () => {
  const state = { tree: makeTree(9), oldRelay: true };
  const { ctx, page } = await openPage(state);
  const r = await check(page, state.tree.leaf(3));
  assert.equal(r.verdict, 'unchecked', r.text);
  assert.ok(r.steps.includes('inclusion:n'), r.steps.join(','));
  assert.doesNotMatch(r.text, /Geverifieerd/);
  await ctx.close();
});

test('a tree head signed by a key that is not the pinned one does not go green', async () => {
  const state = { tree: makeTree(9), signer: stranger };
  const { ctx, page } = await openPage(state);
  const r = await check(page, state.tree.leaf(2));
  assert.equal(r.verdict, 'failed', r.text);
  assert.doesNotMatch(r.text, /Geverifieerd/);
  assert.ok(r.steps.includes('sth:f'), r.steps.join(','));
  await ctx.close();
});

test('a log that rewrote its past is caught on the next visit of the same browser', async () => {
  const state = { tree: makeTree(8) };
  const { ctx, page } = await openPage(state);
  assert.equal((await check(page, state.tree.leaf(1))).verdict, 'verified');
  await page.close();
  // A fresh tree of 12 whose first 8 leaves differ: validly signed, but not an
  // extension of the head this browser kept.
  state.tree = makeTree(12, 'rewritten');
  const again = await openPage(state, '/ct-log', ctx);
  const r = await check(again.page, state.tree.leaf(10));
  assert.equal(r.verdict, 'failed', r.text);
  assert.ok(r.steps.includes('consistency:f'), r.steps.join(','));
  assert.doesNotMatch(r.text, /Geverifieerd/);
  await ctx.close();
});

test('when the signed head cannot be fetched the page says "not cryptographically confirmed", never verified', async () => {
  const state = { tree: makeTree(6), sthDown: true };
  const { ctx, page } = await openPage(state);
  const r = await check(page, state.tree.leaf(5));
  assert.equal(r.verdict, 'unchecked', r.text);
  assert.match(r.text, /niet cryptografisch bevestigd/);
  assert.doesNotMatch(r.text, /Geverifieerd/);
  await ctx.close();
});

test('a tree-hash match is listed, not verified', async () => {
  const state = { tree: makeTree(6) };
  const { ctx, page } = await openPage(state);
  const r = await check(page, state.tree.root(3));
  assert.equal(r.verdict, 'unchecked', r.text);
  assert.match(r.text, /niet cryptografisch bevestigd/);
  await ctx.close();
});

test('the English page says the same in English', async () => {
  const state = { tree: makeTree(7) };
  const { ctx, page, errors } = await openPage(state, '/en/ct-log');
  const ok = await check(page, state.tree.leaf(6));
  assert.equal(ok.verdict, 'verified', ok.text);
  assert.match(ok.text, /✓ Verified: index 6 is in the tree this relay signed/);
  assert.match(ok.text, /that others see the same tree/);
  state.forgeProof = true;
  const bad = await check(page, state.tree.leaf(2));
  assert.equal(bad.verdict, 'failed', bad.text);
  assert.doesNotMatch(bad.text, /Verified/);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test.after(async () => { await browser.close(); server.close(); });
