'use strict';
// /v2/ct/proof computes every path from the full tree, never from the pair
// stored with the entry, and can prove inclusion against any tree size.
//
// WHY THIS SUITE EXISTS. Measured on health.paramant.app on 2026-10-06
// (paramant-bewijs/ct-onderzoek-2026-10-06, raw/voor-3.1.0/health/proof-45.json):
// 39 old entries (positions 1-34 and 42-46, April 2026) are in the right place
// in the tree, but /v2/ct/proof handed out the tree_hash and audit path stored
// at append time. For 42-46 that pair belongs to an earlier, restarted tree:
// the path for 45 folds as leaf 7 of an 8-leaf tree that starts at position
// 38. No customer could check such a proof against the published log.
//
// The fixture below is that defect: a correct log whose entries 42..46 carry
// tree_hash and proof from a second tree that began at 38.
// Run: node --test relay/test/route-ct-proof-from-tree.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');
const { ctTreeHash, ctInclusionProof, ctNodeHash } = require('../lib/ct-hash');

const N = 50;
let srv;
let truth;
let checks = 0;
const did = () => { checks++; };

const fold = (leaf, steps) => (steps || []).reduce(
  (r, s) => (s.position === 'right' ? ctNodeHash(r, s.hash) : ctNodeHash(s.hash, r)), leaf);

before(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-ctproof-'));
  const file = path.join(dir, 'ct-log.jsonl');
  const entries = [];
  for (let i = 0; i < N; i++) {
    const leaf_hash = crypto.createHash('sha3-256').update('ct-proof-leaf-' + i).digest('hex');
    const soFar = [...entries, { leaf_hash }];
    entries.push({ index: i, type: 'transfer', leaf_hash, tree_hash: ctTreeHash(soFar),
      ts: new Date(Date.UTC(2026, 3, 14, 19, 0, 0) + i * 1000).toISOString(),
      proof: ctInclusionProof(soFar, soFar.length - 1) });
  }
  truth = entries.map((e) => ({ leaf_hash: e.leaf_hash }));
  // The restarted April tree: positions 38.. as if they were leaves 0..
  const restarted = entries.slice(38).map((e) => ({ leaf_hash: e.leaf_hash }));
  for (let p = 42; p <= 46; p++) {
    const sub = restarted.slice(0, p - 38 + 1);
    entries[p].tree_hash = ctTreeHash(sub);
    entries[p].proof = ctInclusionProof(sub, sub.length - 1);
  }
  fs.writeFileSync(file, entries.map((e) => JSON.stringify(e) + '\n').join(''));
  srv = await boot({ tag: 'ctproof', dir, env: { CT_FILE: file } });
});

after(async () => { summary('route-ct-proof-from-tree', checks); await killAll(); });

test('the proof for an entry with a stale stored path folds to the real tree', async () => {
  for (const i of [0, 41, 42, 45, 46, 49]) {
    const r = await srv.get(`/v2/ct/proof/${i}`);
    assert.strictEqual(r.status, 200);
    const expectRoot = ctTreeHash(truth.slice(0, i + 1));
    assert.strictEqual(r.json.tree_hash, expectRoot, `tree_hash at ${i} is not the root of the published tree at ${i + 1}`);
    assert.strictEqual(fold(r.json.leaf_hash, r.json.proof), expectRoot, `audit path at ${i} does not fold to the published tree`);
  }
  did();
});

test('?tree_size=N proves inclusion straight against the current head', async () => {
  const log = await srv.get('/v2/ct/log?from=0&limit=1');
  const sth = await srv.get('/v2/sth');
  const size = sth.status === 200 ? sth.json.sth.tree_size : log.json.size;
  const root = sth.status === 200 ? sth.json.sth.sha3_root : log.json.root;
  for (const i of [3, 45, size - 1]) {
    const r = await srv.get(`/v2/ct/proof/${i}?tree_size=${size}`);
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.tree_size, size);
    assert.strictEqual(r.json.tree_hash, root);
    assert.strictEqual(fold(r.json.leaf_hash, r.json.proof), root, `leaf ${i} does not fold to the head at ${size}`);
  }
  for (const bad of ['0', String(size + 1), 'abc', '45']) {
    const r = await srv.get(`/v2/ct/proof/45?tree_size=${bad}`);
    assert.strictEqual(r.status, 400, `tree_size=${bad} answered ${r.status}`);
  }
  assert.strictEqual((await srv.get(`/v2/ct/proof/${size}`)).status, 404);
  did();
});
