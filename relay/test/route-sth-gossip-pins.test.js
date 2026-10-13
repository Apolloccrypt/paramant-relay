'use strict';
// The public STH mirror only holds heads from relays whose key is pinned to
// the name they use, and it says when a head arrived to the hour, no finer.
//
// WHY THIS SUITE EXISTS. Measured on production on 2026-10-06
// (paramant-bewijs/ct-onderzoek-2026-10-06): relay.paramant.app mirrored 20
// "peers" in /v2/sth/peers, 15 of them fresh keys calling themselves
// https://health.paramant.app with trees of 1 to 35 leaves, plus
// relay.telling.test and relay.p10-test.nl from local acceptance stacks.
// POST /v2/sth/ingest checked the signature under the key that came WITH the
// head and nothing else, so any key could speak for any name. The mirror is
// the one place a split view would show, and it was full of noise; our own
// monitor (scripts/paramant-verify-peers) raised a false alarm on it.
//
// The same mirror published received_at to the millisecond. A head is
// gossiped the instant it is signed and signed on every append, so that
// millisecond is the leaf's own time: 115 of 116 mirrored health heads gave it
// away, undoing the hour rounding of the log (relay.js ctCoarseTs) for every
// leaf on health.
//
// Each test below fails on origin/main 4a0ee9dd.
// Run: node --test relay/test/route-sth-gossip-pins.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary, requireEngine } = require('./_requires');

const HOUR_MS = 3600000;
const PIN_HOST = 'peer.pinned.test';
const SIG = requireEngine();

let checks = 0;
const did = () => { checks++; };

function keypair() {
  const kp = SIG.generateKeyPair();
  const pk = Buffer.from(kp.publicKey);
  return { pk, sk: Buffer.from(kp.secretKey), hash: crypto.createHash('sha3-256').update(pk).digest('hex') };
}

// A head exactly as relay.js broadcastSTH sends it.
function head(kp, relayId, treeSize, root) {
  const payload = { relay_id: relayId, sha3_root: root || crypto.randomBytes(32).toString('hex'),
    timestamp: Math.floor(Date.now() / HOUR_MS) * HOUR_MS, tree_size: treeSize, version: 1 };
  const canonical = JSON.stringify(Object.fromEntries(Object.keys(payload).sort().map((k) => [k, payload[k]])));
  const signature = Buffer.from(SIG.sign(Buffer.from(canonical, 'utf8'), kp.sk)).toString('base64');
  return { ...payload, signature, public_key: kp.pk.toString('base64'), relay_pk_hash: kp.hash };
}

// What a polluted production mirror looks like on disk: one .jsonl per key.
function seed(dir, kp, records) {
  const d = path.join(dir, 'peer-sths');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, kp.hash + '.jsonl'),
    records.map((r) => JSON.stringify({ ...r, received_at: '2026-10-03T11:26:33.411Z' })).join('\n') + '\n');
}

const pinned = keypair();      // the relay we pin as PIN_HOST
const stranger = keypair();    // a key nobody pinned
const impostor = keypair();    // a key that claims to be health.paramant.app
const tester = keypair();      // a local acceptance stack
const rotated = keypair();     // the old key of RET_HOST, retired after a rotation
const RET_HOST = 'peer.rotated.test';
const rotatedNew = keypair();  // its new key
let srv;
let dir;

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-gossip-pins-'));
  // The pollution, exactly the three shapes found on production.
  seed(dir, impostor, [head(impostor, 'https://health.paramant.app', 27), head(impostor, 'https://health.paramant.app', 28)]);
  seed(dir, tester, [head(tester, 'https://relay.telling.test', 3)]);
  // A pinned key with one honest head and one head under a name it may not use.
  seed(dir, pinned, [head(pinned, `https://${PIN_HOST}`, 5), head(pinned, 'https://relay.p10-test.nl', 6)]);
  // A relay that rotated: its old mirror, written under the old key, plus one
  // exact duplicate as the open route used to let in.
  const old1 = head(rotated, `https://${RET_HOST}`, 11);
  seed(dir, rotated, [old1, head(rotated, `https://${RET_HOST}`, 12), old1]);
  // A file that is not a mirror at all: left alone, not moved.
  fs.writeFileSync(path.join(dir, 'peer-sths', 'sth-log.jsonl'), '{"not":"a mirror"}\n');
  srv = await boot({ tag: 'gossip-pins', dir, env: {
    PEER_STH_PINS: `${PIN_HOST}=${pinned.hash},${RET_HOST}=${rotatedNew.hash}`,
    PEER_STH_RETIRED_PINS: `${RET_HOST}=${rotated.hash}`,
    PEER_STH_FILE_MAX: '6', PEER_STH_FILE_KEEP: '3' } });
});

after(async () => { summary('route-sth-gossip-pins', checks); await killAll(); });

test('startup purges mirrored heads whose key is not pinned to their relay_id, and logs it', async () => {
  const peers = await srv.get('/v2/sth/peers');
  assert.strictEqual(peers.status, 200);
  const ids = peers.json.peers.map((p) => p.relay_pk_hash).sort();
  assert.deepStrictEqual(ids, [pinned.hash, rotated.hash].sort(), `only pinned (and retired) relays may stay in the public mirror, got ${JSON.stringify(peers.json.peers)}`);
  const hist = await srv.get(`/v2/sth/peers/${pinned.hash}`);
  assert.deepStrictEqual(hist.json.sths.map((s) => s.relay_id), [`https://${PIN_HOST}`],
    'the head the pinned key sent under someone else\'s name is gone too');
  for (const k of [impostor, tester]) {
    assert.strictEqual((await srv.get(`/v2/sth/peers/${k.hash}`)).status, 404);
  }
  const log = srv.log();
  assert.match(log, /"msg":"peer_sth_purged"[^\n]*"relay_id":"https:\/\/health\.paramant\.app"/);
  assert.match(log, /"msg":"peer_sth_purged"[^\n]*"relay_id":"https:\/\/relay\.telling\.test"/);
  assert.match(log, /"msg":"peer_sth_purged"[^\n]*"relay_id":"https:\/\/relay\.p10-test\.nl"/);
  // Moved aside as evidence, not served.
  assert.ok(fs.readdirSync(path.join(dir, 'peer-sths', 'purged')).length >= 3, 'the purged files are kept under purged/');
  did();
});

test('a pinned relay name is only accepted with its pinned key', async () => {
  const r = await srv.post('/v2/sth/ingest', { body: head(impostor, 'https://health.paramant.app', 40) });
  assert.strictEqual(r.status, 403, `a foreign key speaking for health.paramant.app was accepted: ${r.text}`);
  assert.strictEqual(r.json.reason, 'relay_id_pinned_to_other_key');
  const r2 = await srv.post('/v2/sth/ingest', { body: head(stranger, `https://${PIN_HOST}`, 9) });
  assert.strictEqual(r2.status, 403);
  did();
});

test('a pinned key cannot speak for another name, and an unpinned paramant.app name is refused', async () => {
  const r = await srv.post('/v2/sth/ingest', { body: head(pinned, 'https://elsewhere.example', 7) });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.json.reason, 'pinned_key_other_relay_id');
  const r2 = await srv.post('/v2/sth/ingest', { body: head(stranger, 'https://www.paramant.app', 1) });
  assert.strictEqual(r2.status, 403);
  assert.strictEqual(r2.json.reason, 'unpinned_paramant_host');
  did();
});

test('an unpinned peer is not refused but never reaches the public mirror', async () => {
  const r = await srv.post('/v2/sth/ingest', { body: head(tester, 'https://relay.telling.test', 4) });
  assert.strictEqual(r.status, 202, r.text);
  assert.strictEqual(r.json.mirrored, false);
  const peers = await srv.get('/v2/sth/peers');
  assert.ok(!peers.json.peers.some((p) => p.relay_pk_hash === tester.hash), 'the unpinned peer is listed publicly');
  assert.strictEqual((await srv.get(`/v2/sth/peers/${tester.hash}`)).status, 404);
  did();
});

test('the pinned relay is mirrored, and received_at says the hour and nothing finer', async () => {
  const r = await srv.post('/v2/sth/ingest', { body: head(pinned, `https://${PIN_HOST}`, 8) });
  assert.strictEqual(r.status, 200, r.text);
  const hist = await srv.get(`/v2/sth/peers/${pinned.hash}`);
  assert.strictEqual(hist.json.sths.length, 2);
  for (const s of hist.json.sths) {
    const ms = Date.parse(s.received_at);
    assert.ok(Number.isFinite(ms) && ms % HOUR_MS === 0,
      `received_at ${s.received_at} is more precise than the hour; it gives away the leaf's moment`);
  }
  // Includes the head stored before this fix with a millisecond received_at.
  assert.ok(hist.json.sths.some((s) => s.tree_size === 5 && s.received_at === '2026-10-03T11:00:00.000Z'));
  const peers = await srv.get('/v2/sth/peers');
  const me = peers.json.peers.find((p) => p.relay_pk_hash === pinned.hash);
  assert.ok(me && Date.parse(me.latest_ts) % HOUR_MS === 0, `latest_ts ${me && me.latest_ts} is sub-hour`);
  did();
});

test('a retired key keeps its old heads in the mirror, but a new head under it is refused', async () => {
  const hist = await srv.get(`/v2/sth/peers/${rotated.hash}`);
  assert.strictEqual(hist.status, 200, 'the old mirror of a rotated relay was purged');
  assert.deepStrictEqual(hist.json.sths.map((s) => s.tree_size), [11, 12], 'old heads kept, the duplicate dropped');
  assert.ok(fs.existsSync(path.join(dir, 'peer-sths', rotated.hash + '.jsonl')), 'the old mirror file stays in place');
  const peers = await srv.get('/v2/sth/peers');
  const me = peers.json.peers.find((p) => p.relay_pk_hash === rotated.hash);
  assert.strictEqual(me.retired, true);
  const r = await srv.post('/v2/sth/ingest', { body: head(rotated, `https://${RET_HOST}`, 13) });
  assert.strictEqual(r.status, 403, r.text);
  assert.strictEqual(r.json.reason, 'retired_key');
  // The new key carries on under the same name.
  const r2 = await srv.post('/v2/sth/ingest', { body: head(rotatedNew, `https://${RET_HOST}`, 13) });
  assert.strictEqual(r2.status, 200, r2.text);
  // And a file in the directory that is no mirror was not touched.
  assert.ok(fs.existsSync(path.join(dir, 'peer-sths', 'sth-log.jsonl')), 'a non-mirror .jsonl was moved');
  did();
});

test('a relay_id with a dot at the end is refused, not filed as an unknown peer', async () => {
  for (const rid of ['https://health.paramant.app.', 'https://health.paramant.app%2e', `https://${PIN_HOST}.`, 'https://relay.example.org.']) {
    const r = await srv.post('/v2/sth/ingest', { body: head(stranger, rid, 3) });
    assert.strictEqual(r.status, 403, `${rid} answered ${r.status}: ${r.text}`);
    assert.strictEqual(r.json.reason, 'relay_id_trailing_dot');
  }
  did();
});

test('a head the mirror already holds is not stored again, and the file stays bounded', async () => {
  const file = path.join(dir, 'peer-sths', pinned.hash + '.jsonl');
  const lines = () => fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).length;
  const h = head(pinned, `https://${PIN_HOST}`, 20);
  const r1 = await srv.post('/v2/sth/ingest', { body: h });
  assert.strictEqual(r1.status, 200, r1.text);
  const before = (await srv.get(`/v2/sth/peers/${pinned.hash}`)).json.total;
  for (let i = 0; i < 5; i++) {
    const r = await srv.post('/v2/sth/ingest', { body: h });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.duplicate, true);
    assert.strictEqual(r.json.stored, false);
  }
  assert.strictEqual((await srv.get(`/v2/sth/peers/${pinned.hash}`)).json.total, before, 'a replay was stored');
  // A fork (same size, other root) is evidence and IS stored.
  const fork = await srv.post('/v2/sth/ingest', { body: head(pinned, `https://${PIN_HOST}`, 20) });
  assert.strictEqual(fork.status, 200);
  assert.notStrictEqual(fork.json.duplicate, true);
  // Past PEER_STH_FILE_MAX (6 here) the file is compacted to the newest 3.
  for (let n = 21; n < 30; n++) {
    assert.strictEqual((await srv.post('/v2/sth/ingest', { body: head(pinned, `https://${PIN_HOST}`, n) })).status, 200);
  }
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(lines() <= 6, `mirror file has ${lines()} lines, more than PEER_STH_FILE_MAX`);
  assert.match(srv.log(), /"msg":"peer_sth_compacted"/);
  did();
});
