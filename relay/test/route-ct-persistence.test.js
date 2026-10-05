'use strict';
// A transparency log that evaporates on restart is not evidence, and a relay
// that survives its own log is worse than one that does not.
//
// WHY THIS SUITE EXISTS. CT_FILE used to default to null: persistence was
// opt-in, docker-compose.yml opted in, and so production was fine and nobody
// looked again. Every other relay - a self-host, a community node, a plain
// `node relay.js` - kept its whole log in RAM. Measured on a booted relay
// before this suite existed: four entries, restart, and
//
//   * /v2/ct/log comes back at size 0;
//   * /v2/ct/proof?index=3 answers 404, so every receipt issued before the
//     restart stops resolving;
//   * RELAY_IDENTITY_FILE brings back the SAME ML-DSA-65 key and STH_FILE
//     brings back the old signed heads, so the relay signs tree_size 1 a second
//     time over a different root, and /v2/sth/history ends up holding two
//     contradictory heads for one tree size under one key.
//
// That last one is the reason this is not a nice-to-have. An empty log is a
// loss. A forked log is a published, signed contradiction that no verifier can
// tell apart from tampering, produced without a warning by a relay that thought
// it was starting clean.
//
// So two things are asserted here, both on really booted relays:
//   1. persistence is the DEFAULT. Nothing has to be set for the log to survive
//      a restart with the same root and resolvable old proofs.
//   2. when it is switched off on purpose (CT_FILE=""), the fork is refused
//      rather than signed. The relay stops issuing heads, says why in the log,
//      and says so on the public /v2/sth, because an outside monitor cannot
//      otherwise tell a frozen log from a quiet week.
// Run: node --test relay/test/route-ct-persistence.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');
const ctFields = require('../lib/ct-fields');

const KEY = 'pgp_ct_persistence_suite_key_01';
const users = { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'sender@example.test', account_id: 'acct_sender' }] };

let checks = 0;
const did = () => { checks++; };
const dirs = [];

function scratch(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `ctpersist-${tag}-`));
  dirs.push(d);
  return d;
}

async function upload(srv, label) {
  const payload = Buffer.from(`${label}-${crypto.randomBytes(8).toString('hex')}`);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const r = await srv.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash, payload: payload.toString('base64') } });
  assert.strictEqual(r.status, 200, `upload ${label}: ${JSON.stringify(r.json)}`);
  return hash;
}

// tree_size -> the set of distinct roots this relay has signed for it. More
// than one root at a size IS the fork; there is no benign reading of it.
function rootsPerSize(sths) {
  const m = new Map();
  for (const s of sths) {
    if (!m.has(s.tree_size)) m.set(s.tree_size, new Set());
    m.get(s.tree_size).add(s.sha3_root);
  }
  return [...m.entries()].filter(([, r]) => r.size > 1).map(([size, r]) => `tree_size ${size}: ${r.size} roots`);
}

after(async () => {
  summary('route-ct-persistence', checks);
  await killAll();
  for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* gone */ } }
});

test('with nothing configured, the log survives a restart and old proofs still resolve', async () => {
  const dir = scratch('default');
  // No CT_FILE anywhere. _relay-server only sets the paths that already had a
  // /data default, so this is the bare-checkout case the old default broke.
  let srv = await boot({ tag: 'ctp1', dir, usersFile: true, users });
  assert.ok(!process.env.CT_FILE, 'the environment is not quietly setting CT_FILE for us');
  for (let i = 0; i < 4; i++) await upload(srv, 'doc' + i);
  const before = await srv.get('/v2/ct/log?from=0&limit=10');
  assert.strictEqual(before.json.size, 4);
  const rootBefore = before.json.root;
  const leavesBefore = before.json.entries.map((e) => e.leaf_hash);
  const idBefore = (await srv.get('/ct/feed')).json.relay_id;
  await srv.stop();

  srv = await boot({ tag: 'ctp2', dir, usersFile: true });
  const after2 = await srv.get('/v2/ct/log?from=0&limit=10');
  assert.strictEqual(after2.json.size, 4, 'the log came back, all four entries');
  assert.strictEqual(after2.json.root, rootBefore, 'and with a byte-identical Merkle root');
  assert.deepStrictEqual(after2.json.entries.map((e) => e.leaf_hash), leavesBefore, 'leaf for leaf');
  assert.strictEqual((await srv.get('/ct/feed')).json.relay_id, idBefore, 'same relay identity, as before');

  const p = await srv.get('/v2/ct/proof?index=3');
  assert.strictEqual(p.status, 200, 'a receipt issued before the restart still resolves');
  assert.strictEqual(p.json.leaf_hash, leavesBefore[3]);

  // And it keeps growing from where it was, rather than from zero.
  await upload(srv, 'after-restart');
  assert.strictEqual((await srv.get('/v2/ct/log?from=0&limit=10')).json.size, 5);
  await srv.stop();
  did();
});

test('the log file lands next to the signed heads it attests to', async () => {
  // The head and the tree it commits to belong on the same volume: a deployment
  // that pointed STH_FILE at a writable path has already said where that is.
  const dir = scratch('samedir');
  const srv = await boot({ tag: 'ctp3', dir, usersFile: true, users });
  await upload(srv, 'one');
  await srv.stop();          // stop, so the queued write is flushed
  assert.ok(fs.existsSync(path.join(dir, 'ct-log.json')), 'ct-log.json sits beside sth-log.jsonl');
  assert.ok(fs.existsSync(path.join(dir, 'sth-log.jsonl')));
  did();
});

test('what really lands on disk carries only fields the gate declares', async () => {
  // The round trip for relay/lib/ct-fields.js. ct-fields.test.js holds the list
  // against a hand-written copy and against the call sites; this reads the file
  // the relay actually wrote. A gate that is imported but not reached would
  // pass both of those and fail here.
  const dir = scratch('fields');
  const srv = await boot({ tag: 'ctp8', dir, usersFile: true, users, captureLog: true });
  for (let i = 0; i < 3; i++) await upload(srv, 'gated' + i);
  await srv.stop();
  const lines = fs.readFileSync(path.join(dir, 'ct-log.json'), 'utf8').split('\n').filter((l) => l.trim());
  assert.strictEqual(lines.length, 3, 'three appends, three lines');
  const allowed = new Set(ctFields.allowedFields('transfer'));
  for (const line of lines) {
    const e = JSON.parse(line);
    const undeclared = Object.keys(e).filter((k) => !allowed.has(k));
    assert.deepStrictEqual(undeclared, [], `a transfer entry on disk carries ${undeclared.join(', ')}`);
    assert.strictEqual(e.type, 'transfer');
    assert.ok(e.leaf_hash && e.ts && e.blob_hash, 'and the declared fields are all there');
  }
  // The gate STRIPS, so a smuggled field never reaches the file and the check
  // above stays green whatever anyone adds. This is the half that goes red:
  // the relay says at error level that it dropped something, and a normal run
  // must have nothing to say.
  assert.ok(!/"msg":"ct_entry_field_rejected"/.test(srv.log()),
    'the relay dropped a field on its way into the log. Something reached a CT entry without '
    + 'being declared in relay/lib/ct-fields.js. The log line names it.');
  assert.ok(!/"msg":"ct_payload_field_rejected"/.test(srv.log()),
    'the relay dropped a payload key on its way into a leaf preimage.');
  did();
});

test('an explicitly empty CT_FILE still means RAM-only, for the caller who means it', async () => {
  const dir = scratch('optout');
  const srv = await boot({ tag: 'ctp4', dir, usersFile: true, users, env: { CT_FILE: '' } });
  await upload(srv, 'ephemeral');
  await srv.stop();
  assert.ok(!fs.existsSync(path.join(dir, 'ct-log.json')), 'nothing was written');
  did();
});

test('a relay that lost its tree refuses to sign a head contradicting one it already signed', async () => {
  const dir = scratch('fork');
  let srv = await boot({ tag: 'ctp5', dir, usersFile: true, users, env: { CT_FILE: '' }, captureLog: true });
  for (let i = 0; i < 4; i++) await upload(srv, 'doc' + i);
  const headBefore = (await srv.get('/v2/sth')).json.sth;
  assert.strictEqual(headBefore.tree_size, 4);
  await srv.stop();

  // Same scratch dir: the identity key and the STH history come back, the tree
  // does not. This is exactly the state that used to produce a forked log.
  srv = await boot({ tag: 'ctp6', dir, usersFile: true, env: { CT_FILE: '' }, captureLog: true });
  assert.strictEqual((await srv.get('/v2/ct/log?from=0&limit=10')).json.size, 0, 'the tree is gone, as asked');
  await upload(srv, 'after-the-loss');

  const hist = await srv.get('/v2/sth/history?limit=1000');
  assert.deepStrictEqual(rootsPerSize(hist.json.sths), [],
    'the relay signed a second, different root for a tree size it had already signed. '
    + 'That is a fork: a published contradiction under one key, indistinguishable from tampering.');

  const sth = await srv.get('/v2/sth');
  assert.strictEqual(sth.json.sth.tree_size, 4, 'the last head is still the last HONEST head');
  assert.ok(sth.json.forked, '/v2/sth says the log is frozen, so a monitor can tell this from a quiet week');
  assert.strictEqual(sth.json.forked.reason, 'root_differs_at_same_size');
  assert.strictEqual(sth.json.forked.max_signed_size, 4);

  assert.match(srv.log(), /"msg":"sth_refused_would_fork"/,
    'and it says so in the log, at error level, with the reason and the way back');
  await srv.stop();
  did();
});

test('the guard is not a blanket refusal: a healthy log keeps producing heads', async () => {
  // A guard that fires on everything is a guard nobody keeps. Re-signing the
  // SAME root at the same size is idempotent, not a contradiction, and a tree
  // that only grows must never trip.
  const dir = scratch('healthy');
  const srv = await boot({ tag: 'ctp7', dir, usersFile: true, users, captureLog: true });
  for (let i = 0; i < 6; i++) await upload(srv, 'grow' + i);
  const hist = await srv.get('/v2/sth/history?limit=1000');
  assert.strictEqual(hist.json.sths.length, 6, 'one head per append, all six signed');
  assert.deepStrictEqual(hist.json.sths.map((s) => s.tree_size), [1, 2, 3, 4, 5, 6], 'strictly growing');
  assert.deepStrictEqual(rootsPerSize(hist.json.sths), []);
  assert.ok(!(await srv.get('/v2/sth')).json.forked, 'nothing frozen');
  assert.ok(!/"msg":"sth_refused_would_fork"/.test(srv.log()), 'and the guard never fired');
  await srv.stop();
  did();
});
