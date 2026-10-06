'use strict';
// scripts/paramant-verify-peers runs clean against a local fleet, ignores
// pollution, and goes red on a real split view.
//
// WHY THIS SUITE EXISTS. On 2026-10-06 the monitor, run read-only against
// production, exited 1 with "INCONSISTENCY DETECTED" over 15 impostor keys
// calling themselves health.paramant.app (paramant-bewijs/ct-onderzoek-
// 2026-10-06/raw/na-3.1.1/eigen-tool-verify-peers.txt). It trusted the key that
// came with each head, and it would have passed a real fork signed by the real
// key, because it only checked the latest head's signature and a rollback
// sorted by an hour-rounded timestamp. A monitor that cries wolf and misses the
// wolf is worse than none.
//
// The fleet here is two booted relays. Loopback gossip is blocked on purpose
// (the SSRF guard), so the heads health would broadcast are delivered to the
// mirror by hand, byte for byte as broadcastSTH sends them.
// Run: node --test relay/test/route-verify-peers-fleet.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { boot, killAll } = require('./_relay-server');
const { summary, requireEngine } = require('./_requires');

const SIG = requireEngine();
const KEY = 'pgp_fleet_suite_key_0000000000001';
const NAME = 'health.local.test';
const MONITOR = path.join(__dirname, '..', '..', 'scripts', 'paramant-verify-peers');

let health;
let mirror;
let fp;
let checks = 0;
const did = () => { checks++; };

const canonical = (p) => JSON.stringify(Object.fromEntries(Object.keys(p).sort().map((k) => [k, p[k]])));

function monitor() {
  const r = spawnSync(process.execPath, [MONITOR, '--relay', mirror.base, '--pins', `${NAME}=${fp}`,
    '--resolve', `${NAME}=${health.base}`, '--verbose'], { encoding: 'utf8', timeout: 60000 });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

before(async () => {
  health = await boot({
    tag: 'vp-health',
    env: { RELAY_SELF_URL: `https://${NAME}` },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'sender@example.test', account_id: 'acct_vp' }] },
  });
  for (let i = 0; i < 6; i++) {
    const payload = Buffer.from('vp-' + i + '-' + crypto.randomBytes(6).toString('hex'));
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const r = await health.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash, payload: payload.toString('base64') } });
    assert.strictEqual(r.status, 200, `upload ${i}: ${r.text}`);
  }
  const pub = await health.get('/v2/pubkey');
  fp = pub.json.pk_hash;
  mirror = await boot({ tag: 'vp-mirror', env: { PEER_STH_PINS: `${NAME}=${fp}` } });
  // Gossip, delivered by hand.
  const hist = await health.get('/v2/sth/history?limit=100');
  assert.ok(hist.json.sths.length >= 6, 'health signed a head per append');
  for (const h of hist.json.sths) {
    const r = await mirror.post('/v2/sth/ingest', { body: { ...h, public_key: pub.json.public_key, relay_pk_hash: fp } });
    assert.strictEqual(r.status, 200, r.text);
  }
});

after(async () => { summary('route-verify-peers-fleet', checks); await killAll(); });

test('the monitor runs clean against a consistent local fleet', () => {
  const r = monitor();
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /0 inconsistency/);
  assert.match(r.out, new RegExp(`https://${NAME.replace(/\./g, '\\.')} \\d+ -> \\d+: consistent`), 'consistency proofs were really checked');
  did();
});

test('impostors cannot get into the mirror, so they cannot raise a false alarm', async () => {
  const kp = SIG.generateKeyPair();
  const pk = Buffer.from(kp.publicKey);
  const p = { relay_id: `https://${NAME}`, sha3_root: 'ab'.repeat(32), timestamp: 1788634800000, tree_size: 2, version: 1 };
  const signature = Buffer.from(SIG.sign(Buffer.from(canonical(p), 'utf8'), Buffer.from(kp.secretKey))).toString('base64');
  const r = await mirror.post('/v2/sth/ingest', { body: { ...p, signature, public_key: pk.toString('base64') } });
  assert.strictEqual(r.status, 403);
  const again = monitor();
  assert.strictEqual(again.code, 0, again.out);
  did();
});

test('a split view signed by the real key turns the monitor red', async () => {
  // The real health key signs a second root for a size it already signed.
  const id = JSON.parse(fs.readFileSync(path.join(health.dir, 'relay-identity.json'), 'utf8'));
  const sth = (await health.get('/v2/sth/history?limit=100')).json.sths[2];
  const forged = { relay_id: sth.relay_id, sha3_root: crypto.randomBytes(32).toString('hex'),
    timestamp: sth.timestamp, tree_size: sth.tree_size, version: 1 };
  const signature = Buffer.from(SIG.sign(Buffer.from(canonical(forged), 'utf8'), Buffer.from(id.sk, 'base64'))).toString('base64');
  const r = await mirror.post('/v2/sth/ingest', { body: { ...forged, signature, public_key: id.pk, relay_pk_hash: fp } });
  assert.strictEqual(r.status, 200, 'a validly signed head from the pinned key is mirrored');
  const res = monitor();
  assert.strictEqual(res.code, 1, res.out);
  assert.match(res.out, /two roots for tree_size/);
  did();
});
