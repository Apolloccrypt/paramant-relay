'use strict';
// The paid-term reminder: does it warn the right account, once, and only once.
//
// WHAT THIS SUITE IS FOR. Two failures would each be worse than sending
// nothing. Mailing a customer twice about the same date makes the relay look
// broken at the moment it is asking for money, and five containers against one
// redis is five copies by default. And a reminder that a restart resets would
// mail the whole book again after every deploy, which is exactly the shape of
// the bug the 2026-09-01 finding recorded (a paid_until fix that lived in
// process memory and did not survive the restart it was written to prevent).
//
// So the checks are about state, not about copy: three accounts at 10 days, 5
// days and expired yesterday; a second sweep; a sweep from a freshly required
// module (a "restart" against the same store); and two sweeps at once.
//
// The store is a fake, deliberately. It implements only the seven commands the
// planner uses, and it implements SET NX as a check-and-write with no await in
// the middle, which is what redis guarantees and what the lock rests on. Every
// method is async, so two concurrent sweeps really do interleave at their await
// points rather than running to completion one after the other.

const test = require('node:test');
const assert = require('node:assert/strict');

const MODULE = require.resolve('../lib/plan-expiry');
const planExpiry = require(MODULE);

// A "restart": a brand-new module instance, as a new process would get, against
// the store that is already there. Anything the planner remembered in module
// scope would show up here as a second mail.
function freshModule() {
  delete require.cache[MODULE];
  return require(MODULE);
}

// ── the fake store ───────────────────────────────────────────────────────────
function fakeRedis() {
  const strings = new Map();   // key -> { value, opts }
  const zsets = new Map();     // key -> Map(member -> score)
  const hashes = new Map();    // key -> Map(field -> value)
  const zset = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };
  const hash = (k) => { if (!hashes.has(k)) hashes.set(k, new Map()); return hashes.get(k); };
  return {
    isReady: true,
    strings, zsets, hashes,
    async set(k, v, opts) {
      // Atomic check-and-write, as redis SET NX is. No await between the read
      // and the write: that is the whole reason the lock works.
      if (opts && opts.NX && strings.has(k)) return null;
      strings.set(k, { value: String(v), opts: opts || {} });
      return 'OK';
    },
    async get(k) { const e = strings.get(k); return e ? e.value : null; },
    async del(k) { return strings.delete(k) ? 1 : 0; },
    async zAdd(k, { score, value }) { const z = zset(k); const had = z.has(value); z.set(value, score); return had ? 0 : 1; },
    async zRem(k, member) { return zset(k).delete(member) ? 1 : 0; },
    async zRangeByScore(k, min, max) {
      return [...zset(k).entries()]
        .filter(([, s]) => s >= min && s <= max)
        .sort((a, b) => a[1] - b[1])
        .map(([m]) => m);
    },
    async hSet(k, f, v) { hash(k).set(f, String(v)); return 1; },
    async hGet(k, f) { const v = hash(k).get(f); return v === undefined ? null : v; },
    async hDel(k, f) { return hash(k).delete(f) ? 1 : 0; },
  };
}

function mailbox() {
  const sent = [];
  const fn = async (msg) => { sent.push(msg); return true; };
  fn.sent = sent;
  return fn;
}

const DAY = 86400000;
const NOW = Date.parse('2026-09-26T09:00:00.000Z');
const SITE = 'https://paramant.app';

// Three accounts, the three cases that matter. The dates are exact so the copy
// assertions below can name the day.
const ACCOUNTS = [
  { accountId: 'acct_ten', product: 'parasign', tier: 'pro', email: 'ten@example.com', paidUntil: new Date(NOW + 10 * DAY).toISOString() },
  { accountId: 'acct_five', product: 'parasign', tier: 'pro', email: 'five@example.com', paidUntil: new Date(NOW + 5 * DAY).toISOString() },
  { accountId: 'acct_gone', product: 'parasend', tier: 'pro', email: 'gone@example.com', paidUntil: new Date(NOW - 1 * DAY).toISOString() },
];

async function seeded(mod) {
  const redis = fakeRedis();
  for (const a of ACCOUNTS) await mod.upsertExpiry(redis, a);
  return redis;
}

test('one sweep warns the account inside the window, tells the lapsed one, and leaves the far one alone', async () => {
  const redis = await seeded(planExpiry);
  const send = mailbox();
  const r = await planExpiry.runSweep({ redis, now: NOW, sendEmail: send, siteUrl: SITE });

  assert.equal(r.ran, true, 'the sweep took the lock');
  assert.equal(r.warned, 1, 'exactly one warning');
  assert.equal(r.ended, 1, 'exactly one end notice');
  assert.equal(send.sent.length, 2);

  const to = send.sent.map((m) => m.to).sort();
  assert.deepEqual(to, ['five@example.com', 'gone@example.com'],
    'ten days out is not warned; five days out and expired yesterday are');

  const warn = send.sent.find((m) => m.to === 'five@example.com');
  assert.equal(warn.subject, 'Your ParaSign Pro ends on 1 October 2026');
  assert.match(warn.text, /Your ParaSign Pro ends on 1 October 2026\./);
  assert.match(warn.text, /Renew for another month or year, or let it fall back to Community; nothing is charged automatically\./);
  assert.match(warn.text, /https:\/\/paramant\.app\/pricing/);

  const ended = send.sent.find((m) => m.to === 'gone@example.com');
  assert.equal(ended.subject, 'Your ParaSend Pro has ended');
  assert.match(ended.text, /ended on 25 September 2026, and your account is now on Community\./);
  assert.match(ended.text, /Nothing was charged\./);

  // No em-dash anywhere in what a customer reads.
  const EM_DASH = '\u2014';
  for (const m of send.sent) assert.equal(m.text.includes(EM_DASH), false, 'no em-dash in the mail');
});

test('a second sweep at the same clock sends nothing', async () => {
  const redis = await seeded(planExpiry);
  const first = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: first, siteUrl: SITE });
  assert.equal(first.sent.length, 2);

  const second = mailbox();
  const r = await planExpiry.runSweep({ redis, now: NOW, sendEmail: second, siteUrl: SITE });
  assert.equal(r.ran, true, 'the lock was given back, so the second sweep runs');
  assert.equal(second.sent.length, 0, 'and it has nothing left to say');
});

test('a sweep six hours later, and one a day later, still send nothing', async () => {
  const redis = await seeded(planExpiry);
  const first = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: first, siteUrl: SITE });

  const later = mailbox();
  await planExpiry.runSweep({ redis, now: NOW + 6 * 3600000, sendEmail: later, siteUrl: SITE });
  await planExpiry.runSweep({ redis, now: NOW + DAY, sendEmail: later, siteUrl: SITE });
  assert.equal(later.sent.length, 0);
});

test('a restart is a new process against the same store, and it sends nothing', async () => {
  const redis = await seeded(planExpiry);
  const first = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: first, siteUrl: SITE });
  assert.equal(first.sent.length, 2);

  // Nothing about "already warned him" may live in module scope.
  const restarted = freshModule();
  const after = mailbox();
  const r = await restarted.runSweep({ redis, now: NOW + 3600000, sendEmail: after, siteUrl: SITE });
  assert.equal(r.ran, true);
  assert.equal(after.sent.length, 0, 'the markers are in redis, not in the process');
});

test('two containers sweeping at the same time: one does the work, the other stands down', async () => {
  const redis = await seeded(planExpiry);
  const a = mailbox();
  const b = mailbox();
  const [ra, rb] = await Promise.all([
    planExpiry.runSweep({ redis, now: NOW, sendEmail: a, siteUrl: SITE }),
    planExpiry.runSweep({ redis, now: NOW, sendEmail: b, siteUrl: SITE }),
  ]);
  const ran = [ra, rb].filter((r) => r.ran);
  const stood = [ra, rb].filter((r) => !r.ran);
  assert.equal(ran.length, 1, 'exactly one sweep held the lock');
  assert.equal(stood.length, 1);
  assert.equal(stood[0].reason, 'locked');
  assert.equal(a.sent.length + b.sent.length, 2, 'and the mail went out once, not twice');
});

test('a renewal moves the date, and the new period gets its own warning', async () => {
  const redis = await seeded(planExpiry);
  const first = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: first, siteUrl: SITE });
  assert.equal(first.sent.length, 2);

  // The five-day account pays for another month. paid_until moves, so the old
  // marker no longer names the current period and the next warning is due.
  const renewed = new Date(NOW + 35 * DAY).toISOString();
  await planExpiry.upsertExpiry(redis, {
    accountId: 'acct_five', product: 'parasign', tier: 'pro',
    email: 'five@example.com', paidUntil: renewed,
  });

  const quiet = mailbox();
  await planExpiry.runSweep({ redis, now: NOW + 6 * DAY, sendEmail: quiet, siteUrl: SITE });
  assert.equal(quiet.sent.some((m) => m.to === 'five@example.com'), false,
    'the renewed account is 29 days out, so there is nothing to say to it yet');

  const due = mailbox();
  await planExpiry.runSweep({ redis, now: NOW + 30 * DAY, sendEmail: due, siteUrl: SITE });
  assert.equal(due.sent.length, 1);
  assert.equal(due.sent[0].to, 'five@example.com');
  assert.equal(due.sent[0].subject, 'Your ParaSign Pro ends on 31 October 2026');
});

test('without a mailer nothing is marked as sent, so the next sweep tries again', async () => {
  const redis = await seeded(planExpiry);
  const lines = [];
  const log = (level, event, fields) => lines.push({ level, event, fields });
  // What relay.js's sendResendEmail returns when RESEND_API_KEY is unset.
  const dead = async () => false;

  const r = await planExpiry.runSweep({ redis, now: NOW, sendEmail: dead, siteUrl: SITE, log });
  assert.equal(r.warned, 0);
  assert.equal(r.ended, 0);
  const skipped = lines.filter((l) => l.event === 'plan_expiry_mail_skipped');
  assert.equal(skipped.length, 2, 'one line per missed mail');

  // No marker was left behind, so a configured relay still sends them later.
  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW + 3600000, sendEmail: send, siteUrl: SITE });
  assert.equal(send.sent.length, 2, 'the mail that could not go out is not lost');
});

test('a mailer that throws is treated as a mail that did not go out', async () => {
  const redis = await seeded(planExpiry);
  const boom = async () => { throw new Error('resend down'); };
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: boom, siteUrl: SITE });

  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW + 60000, sendEmail: send, siteUrl: SITE });
  assert.equal(send.sent.length, 2);
});

test('the marker outlives the longest term that is sold', async () => {
  const redis = await seeded(planExpiry);
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: mailbox(), siteUrl: SITE });
  const keys = [...redis.strings.keys()].filter((k) => k.startsWith(planExpiry.NOTICE_PREFIX));
  assert.equal(keys.length, 2);
  for (const k of keys) {
    assert.equal(redis.strings.get(k).opts.EX, planExpiry.NOTICE_TTL_S);
    assert.ok(planExpiry.NOTICE_TTL_S > 366 * 86400, 'a yearly term must not outlive its marker');
    assert.match(k, /2026-1?0?-?/);
  }
  // The paid_until is IN the name. That is what makes a renewal a new mail and
  // a restart a no-op, with nothing to clean up either way.
  assert.ok(keys.some((k) => k.includes('acct_five') && k.includes(ACCOUNTS[1].paidUntil)));
});

test('a lapsed period is only news for a week, and is dropped from the index after a month', async () => {
  const redis = await seeded(planExpiry);
  const late = mailbox();
  // Eight days after it ended: past the grace, so no mail. Silence is right
  // here; the account has been on Community long enough that a note saying so
  // would be news about nothing.
  await planExpiry.runSweep({ redis, now: NOW + 8 * DAY, sendEmail: late, siteUrl: SITE });
  assert.equal(late.sent.some((m) => m.to === 'gone@example.com'), false,
    'nine days past the end is past the grace, and silence is the honest answer');

  const pruned = await planExpiry.runSweep({ redis, now: NOW + 40 * DAY, sendEmail: mailbox(), siteUrl: SITE });
  assert.equal(pruned.pruned, 2, 'both finished periods left the index');
  assert.equal(await redis.hGet(planExpiry.META_HASH, 'acct_gone|parasend'), null);
});

test('landing on the floor tier takes the account out of the index', async () => {
  const redis = await seeded(planExpiry);
  // The chargeback path: setProductPlan(account, product, floor, null).
  await planExpiry.upsertExpiry(redis, { accountId: 'acct_five', product: 'parasign', tier: 'free', paidUntil: null });
  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: send, siteUrl: SITE });
  assert.equal(send.sent.some((m) => m.to === 'five@example.com'), false,
    'a revoked plan is not warned about');
});

test('an erased account is forgotten, address and all', async () => {
  const redis = await seeded(planExpiry);
  await planExpiry.forgetAccount(redis, 'acct_five');
  assert.equal(await redis.hGet(planExpiry.META_HASH, 'acct_five|parasign'), null);
  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: send, siteUrl: SITE });
  assert.equal(send.sent.some((m) => m.to === 'five@example.com'), false);
});

test('the boot seed fills the index from what a container has on file, and repeats harmlessly', async () => {
  const redis = fakeRedis();
  const records = [
    { accountId: 'acct_a', record: { plan_parasign: 'pro', paid_until_parasign: new Date(NOW + 3 * DAY).toISOString(), email: 'a@example.com' } },
    { accountId: 'acct_b', record: { plan_parasend: 'community', email: 'b@example.com' } },
    { accountId: 'acct_c', record: { plan_parasend: 'pro', paid_until_parasend: new Date(NOW + 200 * DAY).toISOString(), email: 'c@example.com' } },
  ];
  const first = await planExpiry.seedIndex(redis, records);
  assert.equal(first.seen, 3);
  assert.equal(first.indexed, 2, 'the account with no paid period is not indexed');
  const again = await planExpiry.seedIndex(redis, records);
  assert.equal(again.indexed, 2, 'seeding twice is an upsert, not a duplicate');

  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: send, siteUrl: SITE });
  assert.deepEqual(send.sent.map((m) => m.to), ['a@example.com'],
    'only the account whose term is close');
});

test('an account with no address is logged, not mailed, and not marked', async () => {
  const redis = fakeRedis();
  await planExpiry.upsertExpiry(redis, {
    accountId: 'acct_quiet', product: 'parasign', tier: 'pro',
    paidUntil: new Date(NOW + 2 * DAY).toISOString(), email: '',
  });
  const lines = [];
  const send = mailbox();
  await planExpiry.runSweep({ redis, now: NOW, sendEmail: send, siteUrl: SITE, log: (l, e, f) => lines.push([l, e, f]) });
  assert.equal(send.sent.length, 0);
  assert.equal(lines.filter(([, e]) => e === 'plan_expiry_no_address').length, 1);
  assert.equal([...redis.strings.keys()].filter((k) => k.startsWith(planExpiry.NOTICE_PREFIX)).length, 0);
});

test('no redis is a sweep that does not run, not a sweep that crashes', async () => {
  const r = await planExpiry.runSweep({ redis: null, now: NOW, sendEmail: mailbox() });
  assert.equal(r.ran, false);
  assert.equal(r.reason, 'no_redis');
});

test('the date in the mail is the same date in every container', () => {
  // Hand-built and UTC on purpose: toLocaleDateString needs Intl data a slim
  // container image is not guaranteed to carry, and a mail that says a
  // different day depending on which relay sent it is worse than no mail.
  assert.equal(planExpiry.formatDate('2026-10-03T00:00:00.000Z'), '3 October 2026');
  assert.equal(planExpiry.formatDate('2026-01-01T23:59:59.000Z'), '1 January 2026');
  assert.equal(planExpiry.formatDate('not a date'), null);
});

test('the member encoding survives an account id that looks like a key', () => {
  const m = planExpiry.memberOf('pgp_live_abc123', 'parasign');
  assert.deepEqual(planExpiry.parseMember(m), { accountId: 'pgp_live_abc123', product: 'parasign' });
  assert.equal(planExpiry.parseMember('nonsense'), null);
  assert.equal(planExpiry.parseMember('acct|banana'), null);
});
