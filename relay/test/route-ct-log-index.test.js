'use strict';
// The public CT log listing must number its entries by POSITION, and the relay
// must repair a persisted log whose stored index field says otherwise.
//
// WHY THIS SUITE EXISTS. On 2026-09-04 the live log at /v2/ct/log served 4720
// entries whose Merkle root, inclusion proofs and signed tree head all verified
// against relay/lib/ct-hash.js, while the listing reported the indices 4..8
// twice and 42..46 not at all: five entries kept an index field from before an
// April rebuild moved them. Nothing about the tree was wrong, because the tree
// is addressed by position. Only the projection that read the stored field was.
// So the listing lied about where an entry sat while /v2/ct/proof?index=42
// happily returned the entry at position 42, which is the worst possible split
// for a transparency log: two endpoints of the same server disagreeing about
// what "index" means.
//
// Two things are asserted here, on a really booted relay.js reading a really
// poisoned CT_FILE:
//   1. the listing and the feed number rows from the position regardless of
//      what the stored field says;
//   2. the startup recount rewrites that field back to the position, is a
//      no-op on the next boot, and leaves the Merkle root byte-identical -
//      recomputed here from the file's own leaf hashes, not taken on trust.
// Run: node --test relay/test/route-ct-log-index.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { ctTreeHash, ctInclusionProof, ctNodeHash } = require('../lib/ct-hash');

const N = 60;              // entries in the fixture log
const BAD_FROM = 42;       // the five poisoned positions, as seen in production
const BAD_TO = 46;
const BAD_SHIFT = 38;      // position 42 stored 4, 43 stored 5, and so on

let dir;
let checks = 0;
const did = () => { checks++; };

// A CT log the relay will accept on load: oldest first, one JSON object per
// line, each with the leaf_hash and tree_hash a real append would have written.
// The index field of positions 42..46 is then poisoned exactly the way the
// production log was, and nothing else is touched.
function writeFixture(file) {
  const entries = [];
  for (let i = 0; i < N; i++) {
    const leaf_hash = crypto.createHash('sha3-256').update('ct-fixture-leaf-' + i).digest('hex');
    const soFar = [...entries, { leaf_hash }];
    entries.push({
      index: i,
      type: 'key_reg',
      leaf_hash,
      tree_hash: ctTreeHash(soFar),
      ts: new Date(Date.UTC(2026, 3, 14, 19, 0, 0) + i * 1000).toISOString(),
      proof: ctInclusionProof(soFar, soFar.length - 1),
    });
  }
  for (let p = BAD_FROM; p <= BAD_TO; p++) entries[p].index = p - BAD_SHIFT;
  fs.writeFileSync(file, entries.map((e) => JSON.stringify(e) + '\n').join(''));
  return entries;
}

const readLog = (file) =>
  fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));

const rootFromProof = (leaf, pathSteps) =>
  (pathSteps || []).reduce(
    (r, step) => (step.position === 'right' ? ctNodeHash(r, step.hash) : ctNodeHash(step.hash, r)),
    leaf);

before(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-ctindex-')); });
after(async () => {
  await killAll();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* gone */ }
  assert.ok(checks >= 4, `expected at least 4 checks, ran ${checks}`);
});

test('a poisoned CT log is served, repaired and re-served by position', async (t) => {
  const file = path.join(dir, 'ct-log.jsonl');
  const written = writeFixture(file);
  const truthLeaves = written.map((e) => e.leaf_hash);
  const truthRoot = ctTreeHash(written);

  // The fixture really is broken before the relay ever sees it.
  assert.deepStrictEqual(
    written.slice(BAD_FROM, BAD_TO + 1).map((e) => e.index), [4, 5, 6, 7, 8],
    'fixture reproduces the production defect');

  const srv = await boot({ tag: 'ctindex', dir, env: { CT_FILE: file } });

  await t.test('the listing numbers entries by position, not by the stored field', async () => {
    const r = await srv.get('/v2/ct/log?from=0&limit=1000');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.size, N, 'the whole fixture was loaded');
    const idxs = r.json.entries.map((e) => e.index);
    assert.deepStrictEqual(idxs, written.map((_, i) => i),
      'indices 0..59 exactly once each, no duplicate 4..8, no missing 42..46');
    assert.strictEqual(new Set(idxs).size, N, 'no duplicates at all');
    assert.deepStrictEqual(r.json.entries.map((e) => e.leaf_hash), truthLeaves,
      'the row labelled n still carries the leaf that was appended n-th');
    did();
  });

  await t.test('a page not starting at zero is numbered from where it starts', async () => {
    const r = await srv.get('/v2/ct/log?from=40&limit=8');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.entries.map((e) => e.index), [40, 41, 42, 43, 44, 45, 46, 47]);
    assert.strictEqual(r.json.entries[2].leaf_hash, truthLeaves[42],
      'row 42 is the entry at position 42, which is what /v2/ct/proof already returned');
    // The feed is the same projection over the tail.
    const feed = await srv.get('/ct/feed');
    assert.strictEqual(feed.status, 200);
    const feedIdx = feed.json.entries.map((e) => e.i);
    assert.deepStrictEqual(feedIdx, feedIdx.map((_, i) => N - feedIdx.length + i),
      'the feed numbers its tail from position too');
    did();
  });

  await t.test('listing and proof agree, and the proof still verifies', async () => {
    for (const i of [0, 41, 42, 44, 46, 59]) {
      const p = await srv.get('/v2/ct/proof?index=' + i);
      assert.strictEqual(p.status, 200, `proof for index ${i}`);
      assert.strictEqual(p.json.index, i);
      assert.strictEqual(p.json.leaf_hash, truthLeaves[i],
        `proof at ${i} resolves the same entry the listing labels ${i}`);
      assert.strictEqual(rootFromProof(p.json.leaf_hash, p.json.proof), p.json.tree_hash,
        `audit path at ${i} recomputes its own tree root`);
    }
    // The indices the poisoned field claimed must NOT resolve to those entries.
    const stale = await srv.get('/v2/ct/proof?index=4');
    assert.strictEqual(stale.json.leaf_hash, truthLeaves[4],
      'index 4 is the fourth entry, not the one that wrongly stored a 4');
    did();
  });

  await t.test('the recount rewrote the stored field and left the root alone', async () => {
    const after1 = readLog(file);
    assert.strictEqual(after1.length, N, 'no line was added or dropped');
    assert.deepStrictEqual(after1.map((e) => e.index), written.map((_, i) => i),
      'the persisted index field now equals the position everywhere');
    assert.deepStrictEqual(after1.map((e) => e.leaf_hash), truthLeaves,
      'not one leaf hash moved or changed');
    assert.strictEqual(ctTreeHash(after1), truthRoot,
      'the Merkle root over the repaired log is byte-identical');
    assert.deepStrictEqual(after1.map((e) => e.tree_hash), written.map((e) => e.tree_hash),
      'the per-entry tree_hash column is untouched');
    assert.deepStrictEqual(after1.map((e) => e.proof), written.map((e) => e.proof),
      'the stored audit paths are untouched');
    assert.match(srv.log(), /"msg":"ct_log_reindexed"[^\n]*"fixed":5/,
      'one line per log, naming how many entries were wrong');
    did();
  });

  await t.test('a second boot on the repaired log is a no-op', async () => {
    const before2 = readLog(file);
    const srv2 = await srv.restart();
    const r = await srv2.get('/v2/ct/log?from=0&limit=1000');
    assert.deepStrictEqual(r.json.entries.map((e) => e.index), written.map((_, i) => i));
    assert.deepStrictEqual(readLog(file), before2, 'the file was not rewritten again');
    assert.ok(!/"msg":"ct_log_reindexed"/.test(srv2.log()),
      'idempotent: the second boot finds nothing to correct and says nothing');
    assert.strictEqual(ctTreeHash(readLog(file)), truthRoot, 'root still identical');
    await srv2.stop();
    did();
  });
});

test('a clean CT log boots without being rewritten', async () => {
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-ctclean-'));
  try {
    const file = path.join(dir2, 'ct-log.jsonl');
    const entries = [];
    for (let i = 0; i < 12; i++) {
      const leaf_hash = crypto.createHash('sha3-256').update('clean-' + i).digest('hex');
      const soFar = [...entries, { leaf_hash }];
      entries.push({ index: i, type: 'key_reg', leaf_hash, tree_hash: ctTreeHash(soFar), ts: '2026-04-14T19:00:00.000Z' });
    }
    fs.writeFileSync(file, entries.map((e) => JSON.stringify(e) + '\n').join(''));
    const raw = fs.readFileSync(file, 'utf8');

    const srv = await boot({ tag: 'ctclean', dir: dir2, env: { CT_FILE: file } });
    const r = await srv.get('/v2/ct/log?from=0&limit=100');
    assert.deepStrictEqual(r.json.entries.map((e) => e.index), entries.map((_, i) => i));
    assert.ok(!/"msg":"ct_log_reindexed"/.test(srv.log()), 'nothing to repair, nothing logged');
    assert.strictEqual(fs.readFileSync(file, 'utf8'), raw, 'the file was left byte-for-byte alone');
    assert.ok(!fs.existsSync(file + '.reindex.tmp'), 'no temp file left behind');
    await srv.stop();
    did();
  } finally {
    try { fs.rmSync(dir2, { recursive: true, force: true }); } catch (_) { /* gone */ }
  }
});
