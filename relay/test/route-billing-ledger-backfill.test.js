'use strict';
// Review #555, M3: the durable billing ledger started empty. Payments settled
// before it existed lived in redis markers with a 60-day TTL and in
// paid_by_<product> (the last payment only), so once a marker expired an old
// tr_ id was grantable again through the public webhook. At boot the relay
// now writes every settled id it knows into the ledger, once.
// Needs a redis. Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-billing-ledger-backfill.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
const sfx = crypto.randomBytes(5).toString('hex');
const OLD_MARKER = `tr_bfmark${sfx}`;
const OLD_REVOKED = `tr_bfrev${sfx}`;
const POINTER = `tr_bfptr${sfx}`;
after(async () => {
  await killAll();
  if (rc) {
    try { await rc.del([`paramant:billing:done:${OLD_MARKER}`, `paramant:billing:done:${OLD_REVOKED}`]); } catch (_) { /* gone */ }
    try { await rc.disconnect(); } catch (_) { /* gone */ }
  }
  summary('route-billing-ledger-backfill', checks);
});

function ledgerLines(file) {
  try { return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
}
async function waitFor(fn, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (fn()) return true; await new Promise((r) => setTimeout(r, 100)); }
  return false;
}

test('settled ids from redis markers and paid_by pointers land in the ledger at boot, once', async (t) => {
  rc = await requireRedis('redis://127.0.0.1:6399');
  if (!rc) return t.skip('no redis');
  await rc.set(`paramant:billing:done:${OLD_MARKER}`, 'granted', { EX: 3600 });
  await rc.set(`paramant:billing:done:${OLD_REVOKED}`, 'revoked', { EX: 3600 });
  const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
  const env = { REDIS_URL: rc.options.url, MAIL_PROVIDER: 'dryrun', BILLING_LEDGER_BACKFILL_DELAY_MS: '300' };
  let srv = await boot({ tag: 'ledgerbf', usersFile: true, captureLog: true, env,
    users: { api_keys: [{ key: KEY, plan: 'pro', plan_parasign: 'pro', active: true, email: 'bf@example.test', account_id: 'acct_bf_' + sfx, paid_by_parasign: POINTER }] } });
  const ledgerFile = path.join(path.dirname(srv.env.USERS_FILE), 'billing-processed.jsonl');
  const ok = await waitFor(() => {
    const ids = new Set(ledgerLines(ledgerFile).map((r) => r.id));
    return ids.has(OLD_MARKER) && ids.has(OLD_REVOKED) && ids.has(POINTER);
  });
  assert.ok(ok, 'ledger after boot: ' + JSON.stringify(ledgerLines(ledgerFile)));
  const byId = new Map(ledgerLines(ledgerFile).map((r) => [r.id, r.val]));
  assert.strictEqual(byId.get(OLD_MARKER), 'granted');
  assert.strictEqual(byId.get(OLD_REVOKED), 'revoked');
  assert.strictEqual(byId.get(POINTER), 'granted');
  srv = await srv.restart();
  await new Promise((r) => setTimeout(r, 1500));
  // Other suites share this redis and may add their own markers between the
  // two boots, so the check is on OUR ids: each one is in the ledger once.
  const mine = ledgerLines(ledgerFile).filter((r) => [OLD_MARKER, OLD_REVOKED, POINTER].includes(r.id));
  assert.strictEqual(mine.length, 3, 'a second boot writes none of them again: ' + JSON.stringify(mine));
  await srv.stop();
  checks++;
});
