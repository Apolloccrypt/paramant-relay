'use strict';
// The per-user session index, against a real Redis.
//
// The behavioural half of finding 14. keyspace-scan-gate.test.js proves nothing
// scans the keyspace any more; this proves the thing that replaced it actually
// answers the same questions, including the two that a naive index gets wrong:
//
//   - a session whose blob expired must not keep appearing in its owner's list
//     (the set outlives the blob by design, so every read prunes);
//   - a user minted BEFORE this deploy has no index at all, and must still be
//     able to see and revoke his sessions. That is the `scan` fallback, and it
//     adopts what it finds so it is paid once per user rather than per request.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/user-sessions.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');

const userSessions = require('../lib/user-sessions');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
let rc = null;
let checks = 0;
const did = () => { checks++; };
const RUN = Math.random().toString(36).slice(2, 8);
const USER = `pgp_us_${RUN}`;
const OTHER = `pgp_other_${RUN}`;

// The scan the admin server hands in for a user with no index yet.
const scan = async function* (client, match) {
  for await (const k of client.scanIterator({ MATCH: match, COUNT: 100 })) {
    if (Array.isArray(k)) { for (const one of k) yield one; } else yield k;
  }
};

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error('unmet precondition "redis": the redis module is not installed. Run npm ci in admin/, or declare it: ADMIN_TEST_SKIP=redis');
  }
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); }
  catch (e) {
    try { await c.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
});

after(async () => {
  if (rc) {
    const keys = [];
    for await (const k of scan(rc, `paramant:user:session*${''}`)) keys.push(k);
    for (const k of keys) { if (k.includes(RUN)) await rc.del(k).catch(() => {}); }
    await rc.del(userSessions.indexKey(USER)).catch(() => {});
    await rc.del(userSessions.indexKey(OTHER)).catch(() => {});
    try { await rc.disconnect(); } catch (_) { /* already gone */ }
  }
  console.log(`# user-sessions: ${checks} checks ${checks ? 'passed' : 'ran'}`);
});

const rec = (user) => ({ user_id: user, email: `${user}@example.test`, created_at: Date.now(), ip: '10.0.0.1', ua: 'probe' });

test('a remembered session is listed for its owner and for nobody else', async () => {
  if (!rc) return;
  const a = `tok_a_${RUN}`;
  const b = `tok_b_${RUN}`;
  const foreign = `tok_f_${RUN}`;
  await userSessions.remember(rc, USER, a, rec(USER), 60);
  await userSessions.remember(rc, USER, b, rec(USER), 60);
  await userSessions.remember(rc, OTHER, foreign, rec(OTHER), 60);

  const mine = await userSessions.list(rc, USER);
  assert.strictEqual(mine.indexed, true, 'the index was not used');
  assert.deepStrictEqual(mine.sessions.map((s) => s.token).sort(), [a, b].sort());

  const theirs = await userSessions.list(rc, OTHER);
  assert.deepStrictEqual(theirs.sessions.map((s) => s.token), [foreign]);
  did();
});

test('an expired blob does not linger in the list, and is pruned from the set', async () => {
  if (!rc) return;
  const gone = `tok_gone_${RUN}`;
  await userSessions.remember(rc, USER, gone, rec(USER), 60);
  // What an expiry looks like: the blob goes, the set entry stays behind.
  await rc.del(userSessions.sessionKey(gone));

  const { sessions } = await userSessions.list(rc, USER);
  assert.ok(!sessions.some((s) => s.token === gone), 'a dead session is still listed');
  const members = await rc.sMembers(userSessions.indexKey(USER));
  assert.ok(!members.includes(gone), 'the dead token was not pruned from the index');
  did();
});

test('a session record belonging to somebody else is never returned, even from the set', async () => {
  if (!rc) return;
  // Defence in depth: if a token ever lands in the wrong set, the record itself
  // still decides. This is the property the old scan got right by accident and
  // an index could lose.
  const wrong = `tok_wrong_${RUN}`;
  await rc.set(userSessions.sessionKey(wrong), JSON.stringify(rec(OTHER)), { EX: 60 });
  await rc.sAdd(userSessions.indexKey(USER), wrong);

  const { sessions } = await userSessions.list(rc, USER);
  assert.ok(!sessions.some((s) => s.token === wrong), 'an index entry overrode the record');
  await rc.del(userSessions.sessionKey(wrong));
  did();
});

test('forget removes the blob and the index entry together', async () => {
  if (!rc) return;
  const t = `tok_out_${RUN}`;
  await userSessions.remember(rc, USER, t, rec(USER), 60);
  await userSessions.forget(rc, USER, t);
  assert.strictEqual(await rc.get(userSessions.sessionKey(t)), null);
  assert.ok(!(await rc.sMembers(userSessions.indexKey(USER))).includes(t), 'logout left a token in the index');
  did();
});

test('revokeAll clears every session, and can keep the one asking', async () => {
  if (!rc) return;
  await rc.del(userSessions.indexKey(USER));
  const keep = `tok_keep_${RUN}`;
  const drop1 = `tok_d1_${RUN}`;
  const drop2 = `tok_d2_${RUN}`;
  for (const t of [keep, drop1, drop2]) await userSessions.remember(rc, USER, t, rec(USER), 60);

  const revoked = await userSessions.revokeAll(rc, USER, { except: keep });
  assert.strictEqual(revoked, 2);
  assert.ok(await rc.get(userSessions.sessionKey(keep)), 'the current session was revoked too');
  assert.strictEqual(await rc.get(userSessions.sessionKey(drop1)), null);
  assert.deepStrictEqual(await rc.sMembers(userSessions.indexKey(USER)), [keep]);

  const all = await userSessions.revokeAll(rc, USER);
  assert.strictEqual(all, 1);
  assert.strictEqual(await rc.get(userSessions.sessionKey(keep)), null);
  assert.deepStrictEqual(await rc.sMembers(userSessions.indexKey(USER)), []);
  did();
});

test('a session from before the index still shows up, and is adopted once', async () => {
  if (!rc) return;
  // Its own user, because the fallback SCANS: any session another test in this
  // file left behind for USER would be found too and the count would drift.
  const LEGACY_USER = `pgp_legacy_${RUN}`;
  const legacy = `tok_legacy_${RUN}`;
  // Exactly what the old code wrote: a blob, and no index entry.
  await rc.set(userSessions.sessionKey(legacy), JSON.stringify(rec(LEGACY_USER)), { EX: 60 });

  const first = await userSessions.list(rc, LEGACY_USER, scan);
  assert.strictEqual(first.indexed, false, 'the fallback did not report itself as a fallback');
  assert.deepStrictEqual(first.sessions.map((s) => s.token), [legacy]);

  // Adopted, so the scan is paid once and not per request.
  const second = await userSessions.list(rc, LEGACY_USER, scan);
  assert.strictEqual(second.indexed, true, 'the fallback answer was not adopted into the index');
  assert.deepStrictEqual(second.sessions.map((s) => s.token), [legacy]);

  // And revocation reaches it either way.
  assert.strictEqual(await userSessions.revokeAll(rc, LEGACY_USER, { scan }), 1);
  assert.strictEqual(await rc.get(userSessions.sessionKey(legacy)), null);
  await rc.del(userSessions.indexKey(LEGACY_USER)).catch(() => {});
  did();
});

test('a user with nothing gets an empty answer, not a scan', async () => {
  if (!rc) return;
  const nobody = `pgp_nobody_${RUN}`;
  const { sessions, indexed } = await userSessions.list(rc, nobody);
  assert.deepStrictEqual(sessions, []);
  assert.strictEqual(indexed, true);
  assert.strictEqual(await userSessions.revokeAll(rc, nobody), 0);
  did();
});
