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
let srv;
let dir;

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-gossip-pins-'));
  // The pollution, exactly the three shapes found on production.
  seed(dir, impostor, [head(impostor, 'https://health.paramant.app', 27), head(impostor, 'https://health.paramant.app', 28)]);
  seed(dir, tester, [head(tester, 'https://relay.telling.test', 3)]);
  // A pinned key with one honest head and one head under a name it may not use.
  seed(dir, pinned, [head(pinned, `https://${PIN_HOST}`, 5), head(pinned, 'https://relay.p10-test.nl', 6)]);
  srv = await boot({ tag: 'gossip-pins', dir, env: { PEER_STH_PINS: `${PIN_HOST}=${pinned.hash}` } });
});

after(async () => { summary('route-sth-gossip-pins', checks); await killAll(); });

test('startup purges mirrored heads whose key is not pinned to their relay_id, and logs it', async () => {
  const peers = await srv.get('/v2/sth/peers');
  assert.strictEqual(peers.status, 200);
  const ids = peers.json.peers.map((p) => p.relay_pk_hash);
  assert.deepStrictEqual(ids, [pinned.hash], `only the pinned relay may stay in the public mirror, got ${JSON.stringify(peers.json.peers)}`);
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
