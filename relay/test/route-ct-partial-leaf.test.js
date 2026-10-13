'use strict';
// Review #555, M1: a crash or a full disk in the middle of a 32-byte leaf
// write left a partial last leaf in ct-log.json.leaves. The relay logged it
// and then appended the recovered leaves BEHIND the partial bytes, so the
// next boot read every leaf after it shifted: a different root, a forked log.
// Now the partial tail is cut off before anything is appended.
// Run: node --test relay/test/route-ct-partial-leaf.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');
const { CtMerkle } = require('../lib/ct-tree');

let checks = 0;
const dirs = [];
after(async () => {
  summary('route-ct-partial-leaf', checks);
  await killAll();
  for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* gone */ } }
});

test('a partial last leaf is cut off at boot; the root survives two boots unchanged', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctpartial-')); dirs.push(dir);
  const N = 300;
  const t = new CtMerkle();
  const lines = [];
  for (let i = 0; i < N; i++) {
    const leaf_hash = crypto.randomBytes(32).toString('hex');
    t.append(leaf_hash);
    lines.push(JSON.stringify({ index: i, type: 'transfer', leaf_hash, tree_hash: t.root(), blob_hash: crypto.randomBytes(32).toString('hex'), sector: 'relay', ts: new Date(Date.now() - (N - i) * 1000).toISOString(), proof: [] }));
  }
  const rootBefore = t.root();
  const ctFile = path.join(dir, 'ct-log.json');
  fs.writeFileSync(ctFile, lines.join('\n') + '\n');
  // The leaf file holds the first 200 leaves, then 13 bytes of a leaf whose
  // write was cut off.
  const t200 = new CtMerkle();
  for (let i = 0; i < 200; i++) t200.append(JSON.parse(lines[i]).leaf_hash);
  fs.writeFileSync(ctFile + '.leaves', Buffer.concat([t200.leafBytes(), crypto.randomBytes(13)]));

  const env = { CT_FILE: ctFile, STH_FILE: path.join(dir, 'sth-log.jsonl') };
  let srv = await boot({ tag: 'ctpartial', dir, captureLog: true, env });
  let sth = (await srv.get('/v2/sth')).json.sth;
  assert.strictEqual(sth.tree_size, N);
  assert.strictEqual(sth.sha3_root, rootBefore, 'first boot: the root of the whole log');
  assert.strictEqual(fs.statSync(ctFile + '.leaves').size, N * 32, 'the leaf file is whole leaves only');
  await srv.stop();

  srv = await boot({ tag: 'ctpartial2', dir, captureLog: true, env });
  sth = (await srv.get('/v2/sth')).json.sth;
  assert.strictEqual(sth.tree_size, N);
  assert.strictEqual(sth.sha3_root, rootBefore, 'second boot: still the same root');
  assert.doesNotMatch(srv.log(), /ct_tree_root_mismatch/);
  await srv.stop();
  checks++;
});
