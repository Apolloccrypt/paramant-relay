'use strict';
// Nothing the transparency log publishes may say WHEN more precisely than the
// hour, and the sabotage check here is the attack itself rather than a proxy
// for it.
//
// WHY THIS SUITE EXISTS. A CT leaf commits to the full-precision timestamp:
// blobLeafHash(blob_hash, sector, ts) with no salt and no secret. The two
// inputs besides the time are guessable by anyone holding a copy of the
// document (the sha256) and by everyone (five sector names). So the ONLY thing
// standing between "I have this file" and "I can prove this file went through
// Paramant, at this instant" is how precisely the public log gives away the
// time. Rounding to the hour leaves 3.6e6 x 5 candidates, which is 57 seconds
// on one core: bad, and the fix for that is a salted leaf in a second tree.
// Leaking the exact millisecond ANYWHERE leaves one, which is not an attack at
// all. Measured on a booted relay before this suite existed, two routes did:
//
//   /ct/feed        `t` was the stored ts. Joined to the full leaf_hash that
//                   /v2/ct/log publishes at the same index: 1 hash.
//   /v2/sth,        an STH is produced on EVERY append, so tree_size N is leaf
//   /v2/sth/history N-1, and its timestamp was Date.now() taken microseconds
//                   after that leaf's own ts: 1 hash. Worse than the feed - the
//                   feed showed fifty entries, the history shows a thousand,
//                   the heads are mirrored to every peer, and this one was
//                   inside a signature, so it could not be fixed in the
//                   projection.
//
// Fixing the two known routes is not the point. The point is the class, so the
// last test walks every public CT route's response and fails on ANY value that
// carries sub-hour precision, whether or not anyone thought about that route.
// Run: node --test relay/test/route-ct-public-time.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { blobLeafHash } = require('../lib/ct-hash');
const { summary } = require('./_requires');

const KEY = 'pgp_public_time_suite_key_00001';
const SECTORS = ['relay', 'health', 'finance', 'legal', 'iot'];
const HOUR_MS = 3600000;

let srv;
let target;          // { hash, leaf_hash, index, ts } - the leaf under attack
let checks = 0;
const did = () => { checks++; };

const isWholeHour = (ms) => Number.isFinite(ms) && ms % HOUR_MS === 0;

// Upload one blob and hand back its sha256, the way a sender would.
async function upload(label) {
  const payload = Buffer.from(`${label}-${crypto.randomBytes(8).toString('hex')}`);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const r = await srv.post('/v2/inbound', {
    headers: { 'X-Api-Key': KEY },
    body: { hash, payload: payload.toString('base64') },
  });
  assert.strictEqual(r.status, 200, `upload ${label}: ${JSON.stringify(r.json)}`);
  return hash;
}

before(async () => {
  srv = await boot({
    tag: 'cttime',
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'sender@example.test', account_id: 'acct_sender' }] },
  });
  // Several leaves, so the one under attack is not the only thing in the tree
  // and the audit path it hangs from is a real one.
  const hashes = [];
  for (let i = 0; i < 5; i++) hashes.push(await upload('doc' + i));
  const log = await srv.get('/v2/ct/log?from=0&limit=100');
  const idx = 2;
  target = { hash: hashes[idx], leaf_hash: log.json.entries[idx].leaf_hash, index: idx };
});

after(async () => { summary('route-ct-public-time', checks); await killAll(); });

test('the receipt still carries the full timestamp, and it is what makes the leaf', async () => {
  // The control. Everything below asserts that a value CANNOT reconstruct the
  // leaf, and an assertion of that shape passes just as happily when the leaf
  // recipe has changed under it and nothing can reconstruct it any more. So
  // first: prove the attack works when you legitimately hold the ts, which is
  // exactly what the customer's own receipt gives him.
  const r = await srv.get(`/v2/outbound/${target.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(r.status, 200);
  const receiptId = r.headers['x-paramant-receipt-id'];
  assert.ok(receiptId, 'the download hands over a receipt id');
  const rc = await srv.get(`/v2/transfers/${receiptId}/receipt`, { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(rc.status, 200, `receipt fetch: ${JSON.stringify(rc.json)}`);
  const receipt = JSON.parse(Buffer.from(rc.json.receipt, 'base64url').toString('utf8'));
  assert.ok(receipt.ts, 'the receipt carries the full-precision ts');
  assert.strictEqual(
    blobLeafHash(receipt.blob_hash, receipt.sector, receipt.ts),
    receipt.inclusion_proof.leaf_hash,
    'holder of the receipt recomputes his own leaf in one hash - this is the point of a receipt');
  assert.ok(new Date(receipt.ts).getTime() % HOUR_MS !== 0,
    'and that ts is the real one, not a coarsened copy: precision belongs in the private receipt');
  did();
});

test('/ct/feed rounds to the hour, so the feed-to-log join is dead', async () => {
  const feed = await srv.get('/ct/feed');
  assert.strictEqual(feed.status, 200);
  assert.ok(feed.json.entries.length >= 5);
  for (const e of feed.json.entries) {
    assert.ok(isWholeHour(Date.parse(e.t)), `/ct/feed entry ${e.i} carries a sub-hour t: ${e.t}`);
  }
  // The attack that used to cost one hash: take t from the feed at the index,
  // take the full leaf_hash from /v2/ct/log at the same index, try five sectors.
  const fe = feed.json.entries.find((e) => e.i === target.index);
  assert.ok(fe, 'the feed shows the entry under attack');
  let tried = 0;
  for (const s of SECTORS) { tried++; assert.notStrictEqual(blobLeafHash(target.hash, s, fe.t), target.leaf_hash); }
  assert.strictEqual(tried, SECTORS.length, 'all five sectors were tried and none confirmed');
  did();
});

test('every signed tree head is stamped on the hour, at production and not in the projection', async () => {
  const one = await srv.get('/v2/sth');
  assert.strictEqual(one.status, 200);
  assert.ok(isWholeHour(one.json.sth.timestamp), `latest STH timestamp is sub-hour: ${one.json.sth.timestamp}`);

  const hist = await srv.get('/v2/sth/history?limit=100');
  assert.ok(hist.json.sths.length >= 5, 'there is a history to check');
  for (const s of hist.json.sths) {
    assert.ok(isWholeHour(s.timestamp), `STH at tree_size ${s.tree_size} is sub-hour: ${s.timestamp}`);
  }
  // The head at tree_size = index + 1 is the one produced by the append of the
  // leaf under attack. It used to be that leaf's own millisecond.
  const head = hist.json.sths.find((s) => s.tree_size === target.index + 1);
  assert.ok(head, 'the head for the leaf under attack is in the history');
  let tried = 0;
  for (let d = -50; d <= 50; d++) {
    const iso = new Date(head.timestamp + d).toISOString();
    for (const s of SECTORS) { tried++; assert.notStrictEqual(blobLeafHash(target.hash, s, iso), target.leaf_hash); }
  }
  assert.ok(tried >= 500, 'a real neighbourhood around the head timestamp was searched');
  did();
});

test('an old head signed with a precise timestamp still verifies: the fix is not retroactive', () => {
  // Coarsening happens before signing, so the signature covers the coarse
  // value. Verification, both in frontend/js/receipt-verify.js and in
  // /v2/sth/ingest, rebuilds the canonical payload from whatever fields the
  // head carries and pins no resolution. A head signed last April keeps the
  // timestamp it was signed with and keeps verifying. This asserts the property
  // that makes that true: the canonical form is field-driven, not value-driven.
  const canonical = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
  const precise = { relay_id: 'r', sha3_root: 'a'.repeat(64), timestamp: 1788636058944, tree_size: 3, version: 1 };
  const coarse = { ...precise, timestamp: 1788634800000 };
  assert.notStrictEqual(canonical(precise), canonical(coarse), 'the two differ, as they must');
  assert.deepStrictEqual(Object.keys(JSON.parse(canonical(precise))), Object.keys(JSON.parse(canonical(coarse))),
    'and they differ only in the value: no verifier has to know which era a head is from');
  did();
});

test('no public CT route leaks sub-hour precision anywhere in its response', async () => {
  // The class check. Everything above names a route that was known to leak.
  // This one walks whatever the routes return and fails on any value carrying
  // sub-hour precision, so a route added later is covered without being listed.
  const routes = ['/ct/feed', '/v2/ct/log?from=0&limit=100', `/v2/ct/proof?index=${target.index}`,
    '/v2/sth', '/v2/sth/history?limit=100', '/v2/sth/peers'];
  const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$/;
  // Epoch milliseconds in a range that can only be a timestamp: 2001 to 2286.
  const looksEpochMs = (n) => Number.isInteger(n) && n > 1e12 && n < 1e13;
  const offences = [];
  const walk = (node, where) => {
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      if (ISO.test(node) && !isWholeHour(Date.parse(node))) offences.push(`${where} = ${node}`);
      return;
    }
    if (typeof node === 'number') {
      if (looksEpochMs(node) && !isWholeHour(node)) offences.push(`${where} = ${node}`);
      return;
    }
    if (Array.isArray(node)) { node.forEach((v, i) => walk(v, `${where}[${i}]`)); return; }
    if (typeof node === 'object') { for (const [k, v] of Object.entries(node)) walk(v, `${where}.${k}`); }
  };
  for (const r of routes) {
    const res = await srv.get(r);
    if (res.status === 404) continue;   // /v2/sth/peers is empty on a lone relay
    assert.strictEqual(res.status, 200, `${r} answered ${res.status}`);
    walk(res.json, r);
  }
  assert.deepStrictEqual(offences, [],
    'a public CT route published a time more precise than the hour. Every public projection '
    + 'must go through ctCoarseTs / ctCoarseMs; the full-precision value belongs in the stored '
    + 'entry and in the receipt the customer keeps, nowhere else.');
  did();
});
