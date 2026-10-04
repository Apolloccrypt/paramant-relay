'use strict';
// The CT log past 10 000 entries, and after a rotation plus a restart, on a
// really booted relay.
//
// WHY. The signed tree head took the in-memory WINDOW length as tree_size.
// Measured (sweep-chaos, ct-cap.mjs): a relay with 10 000 entries signed 10 001
// once, then froze there while /v2/ct/log went on to 10 002, 10 003, and every
// next head was refused as a fork (sth_refused_would_fork). After a rotation
// plus a restart (ct-rotate.mjs) the relay came back with only the newest part
// of the log, /v2/ct/proof answered "Index not found" for older receipts, and
// again every next head was refused. Production health was at 4854 entries on
// 2026-10-04, so this was weeks away, not theoretical.
// Run: node --test relay/test/route-ct-full-tree.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');
const { CtMerkle, verifyConsistency } = require('../lib/ct-tree');
const { ctNodeHash } = require('../lib/ct-hash');

const KEY = 'pgp_ct_full_tree_suite_key_01';
const users = { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'sender@example.test', account_id: 'acct_ct_full' }] };
let checks = 0;
const did = () => { checks++; };
const dirs = [];
function scratch(tag) { const d = fs.mkdtempSync(path.join(os.tmpdir(), `ctfull-${tag}-`)); dirs.push(d); return d; }

async function upload(srv, i) {
  const payload = Buffer.from(`ct-full-${i}-${crypto.randomBytes(8).toString('hex')}`);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const r = await srv.post('/v2/inbound', { headers: { 'X-Api-Key': KEY, 'X-Real-IP': `198.51.100.${(i % 200) + 1}` }, body: { hash, payload: payload.toString('base64') } });
  assert.strictEqual(r.status, 200, `upload ${i}: ${JSON.stringify(r.json)}`);
  return r;
}
const sthSize = async (srv) => (await srv.get('/v2/sth')).json?.sth?.tree_size;
const sthHistory = async (srv) => (await srv.get('/v2/sth/history')).json;
function fold(leafHash, proof) {
  let h = leafHash;
  for (const s of proof) h = s.position === 'left' ? ctNodeHash(s.hash, h) : ctNodeHash(h, s.hash);
  return h;
}
function rootAt(hist, size) {
  const list = Array.isArray(hist) ? hist : (hist.sths || hist.history || []);
  const s = list.find((x) => x.tree_size === size);
  return s ? s.sha3_root : null;
}

after(async () => {
  summary('route-ct-full-tree', checks);
  await killAll();
  for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* gone */ } }
});

test('past 10 000 entries the head keeps growing, no fork, old proofs still resolve', async () => {
  const dir = scratch('cap');
  // A real log of 10 000 entries: correct leaf hashes and correct roots, as a
  // relay that ran for weeks would have written it.
  const t = new CtMerkle();
  const lines = [];
  for (let i = 0; i < 10000; i++) {
    const leaf_hash = crypto.randomBytes(32).toString('hex');
    t.append(leaf_hash);
    lines.push(JSON.stringify({ index: i, type: 'transfer', leaf_hash, tree_hash: t.root(), blob_hash: crypto.randomBytes(32).toString('hex'), sector: 'relay', ts: new Date(Date.now() - (10000 - i) * 1000).toISOString(), proof: [] }));
  }
  const ctFile = path.join(dir, 'ct-log.json');
  fs.writeFileSync(ctFile, lines.join('\n') + '\n');
  const root10000 = t.root();
  let srv = await boot({ tag: 'ctcap', dir, usersFile: true, users, captureLog: true, env: { CT_FILE: ctFile } });
  assert.strictEqual(await sthSize(srv), 10000, 'startup head is the full log');
  assert.strictEqual((await srv.get('/v2/sth')).json.sth.sha3_root, root10000);
  for (let i = 0; i < 5; i++) {
    await upload(srv, i);
    assert.strictEqual(await sthSize(srv), 10001 + i, `head after upload ${i + 1}`);
    assert.strictEqual((await srv.get('/v2/ct/log?limit=1')).json.size, 10001 + i);
  }
  assert.doesNotMatch(srv.log(), /sth_refused_would_fork/, 'no head refused');
  assert.doesNotMatch(srv.log(), /ct_tree_root_mismatch/);

  // Entry 0..4 have left the 10 000-entry window; their proofs still resolve.
  const p0 = await srv.get('/v2/ct/proof/2');
  assert.strictEqual(p0.status, 200, 'pruned entry still has a proof');
  assert.strictEqual(p0.json.pruned, true);
  assert.strictEqual(fold(p0.json.leaf_hash, p0.json.proof), p0.json.tree_hash);
  // The newest receipt folds to the signed root.
  const pn = await srv.get('/v2/ct/proof/10004');
  const hist = await sthHistory(srv);
  assert.strictEqual(fold(pn.json.leaf_hash, pn.json.proof), rootAt(hist, 10005));

  // Consistency 10 000 -> 10 005 verifies against two signed heads.
  const c = await srv.get('/v2/sth/consistency?from=10000&to=10005');
  assert.strictEqual(c.status, 200, JSON.stringify(c.json));
  assert.ok(verifyConsistency(10000, 10005, root10000, rootAt(hist, 10005), c.json.proof), 'RFC 9162 consistency');
  // And across the window boundary from a small size.
  const c2 = await srv.get('/v2/sth/consistency?from=3&to=10005');
  assert.ok(verifyConsistency(3, 10005, t.root(3), rootAt(hist, 10005), c2.json.proof));

  // Restart: the leaf file carries the tree back.
  srv = await srv.restart();
  assert.ok(fs.existsSync(ctFile + '.leaves'), 'leaf file written');
  assert.strictEqual(fs.statSync(ctFile + '.leaves').size, 10005 * 32);
  await upload(srv, 99);
  assert.strictEqual(await sthSize(srv), 10006);
  assert.doesNotMatch(srv.log(), /sth_refused_would_fork/);
  await srv.stop();
  did();
});

test('rotation plus restart: the tree is whole, numbered parts are never overwritten', async () => {
  const dir = scratch('rot');
  const ctFile = path.join(dir, 'ct-log.json');
  const env = { CT_FILE: ctFile, CT_MAX_SIZE: '3000' };
  let srv = await boot({ tag: 'ctrot', dir, usersFile: true, users, captureLog: true, env });
  const roots = [];
  for (let i = 0; i < 14; i++) {
    await upload(srv, i);
    roots.push((await srv.get('/v2/sth')).json.sth.sha3_root);
    await new Promise((r) => setTimeout(r, 60)); // let the async drain + rotate run
  }
  await srv.stop();
  const parts = fs.readdirSync(dir).filter((n) => /^ct-log\.json\.\d+$/.test(n));
  assert.ok(parts.length >= 2, `expected at least two rotated parts, saw ${parts.join(',')}`);

  srv = await boot({ tag: 'ctrot2', dir, usersFile: true, captureLog: true, env });
  assert.strictEqual(await sthSize(srv), 14, 'head size survives rotation + restart');
  assert.strictEqual((await srv.get('/v2/ct/log?limit=1')).json.size, 14);
  const p = await srv.get('/v2/ct/proof/2');
  assert.strictEqual(p.status, 200, 'an entry from the first rotated part still resolves');
  assert.strictEqual(fold(p.json.leaf_hash, p.json.proof), roots[2]);
  await upload(srv, 50);
  assert.strictEqual(await sthSize(srv), 15);
  const hist = await sthHistory(srv);
  const c = await srv.get('/v2/sth/consistency?from=5&to=15');
  assert.ok(verifyConsistency(5, 15, roots[4], rootAt(hist, 15), c.json.proof));
  assert.doesNotMatch(srv.log(), /sth_refused_would_fork|ct_tree_incomplete/);
  await srv.stop();

  // An upgrade from the window code has no leaf file at all: the rotated parts
  // plus CT_FILE give it back.
  fs.rmSync(ctFile + '.leaves');
  srv = await boot({ tag: 'ctrot3', dir, usersFile: true, captureLog: true, env });
  assert.strictEqual(await sthSize(srv), 15);
  assert.match(srv.log(), /ct_leaves_recovered/);
  await upload(srv, 51);
  assert.strictEqual(await sthSize(srv), 16);
  assert.doesNotMatch(srv.log(), /sth_refused_would_fork|ct_tree_incomplete/);
  await srv.stop();
  did();
});
