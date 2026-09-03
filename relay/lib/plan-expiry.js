'use strict';
// Telling a paying customer that his term is about to run out, before it does.
//
// WHY THIS FILE EXISTS. Every checkout is a ONE-OFF payment for one term
// (BILLING_MODE empty, so Mollie is never asked for a mandate or a
// subscription). `paid_until_<product>` is the end of that term, and
// entitlements.effectiveProductTier floors the tier the moment it passes. That
// is correct and it is silent: the customer's account drops to Community with
// no warning, no mail, and nothing on the site that ever said a date was
// coming. He finds out when a signature is refused.
//
// There is no cron on the server and no scheduler container, so the reminder
// has to live inside the relay process. That brings two problems this module
// exists to solve, and they are the two that a naive setInterval gets wrong.
//
//   1. FIVE CONTAINERS. relay-main, relay-health, relay-finance, relay-legal
//      and relay-iot all run this same code against ONE redis. Without a lock
//      a customer gets the same mail five times. The lock is redis SET NX PX,
//      taken per sweep, so exactly one container does the work per window.
//
//   2. RESTARTS. The relay is restarted for every deploy, and a restart is
//      exactly what killed the previous paid_until fix (see the 2026-09-01
//      finding: the period was written to memory and not to disk, so every
//      restart handed paying accounts an unbounded grant again). NOTHING here
//      lives in process memory. The "already told him" marker is a redis key
//      whose NAME carries the paid_until it belongs to, with a TTL longer than
//      the longest term sold. A new process against the same redis therefore
//      sends zero mails, and a renewal (which moves paid_until) gets a fresh
//      marker on its own, without anybody having to delete the old one.
//
// THE INDEX. Accounts do not live in redis; they live in users.json, per
// container, loaded into memory at boot. So a sweep that reads only its own
// container would mail about the accounts that container happens to know. The
// index below is the fix: the same write path that sets paid_until also writes
// {account, product} into a redis ZSET scored by the period end, plus the
// address to write to. Every container seeds it from what it knows at boot
// (idempotent, a ZADD with the same score is a no-op), so the union of all
// five is complete, and any one of them can then do the whole sweep from redis
// alone. Reading the due set is one ZRANGEBYSCORE over a window, not a scan of
// every account.
//
// The mailer is injected (relay.js passes sendResendEmail), on the pattern of
// lib/transfer-notify.js, so the tests drive a spy and never touch the network.

const entitlements = require('./entitlements');

// ── Redis layout ─────────────────────────────────────────────────────────────
// Member is "<accountId>|<product>". A pipe cannot occur in either half: an
// account id is a key or a uuid, and a product is one of two literals.
const INDEX_ZSET = 'paramant:billing:expiry';        // score = paid_until epoch ms
const META_HASH = 'paramant:billing:expiry_meta';    // member -> JSON {email, tier, paid_until}
const LOCK_KEY = 'paramant:billing:expiry_lock';
const NOTICE_PREFIX = 'paramant:billing:expiry_notice';

const DAY_MS = 86400000;

// How far ahead the warning goes out. Seven days is long enough to act on and
// short enough that the date in the mail is still the date the customer cares
// about.
const WARN_DAYS = 7;
const WARN_WINDOW_MS = WARN_DAYS * DAY_MS;

// How long after a period ended the "it has ended" mail may still go out. The
// sweep runs every six hours, so the normal case is the same day; this is the
// tail for a relay that was down. Past it the account has been on Community
// long enough that a mail saying so is news about nothing.
const ENDED_GRACE_MS = 7 * DAY_MS;

// When a finished period is dropped from the index. Well past ENDED_GRACE_MS,
// so a pruned entry is never one that still had a mail owing.
const PRUNE_AFTER_MS = 30 * DAY_MS;

// Longer than the longest term sold (one year), so a marker can NEVER expire
// while the paid_until it names is still the current one. This is the whole
// idempotency guarantee and the number is deliberately generous: a marker that
// outlives its period costs nothing, one that dies inside it sends a second
// mail to someone who already had one.
const NOTICE_TTL_S = 400 * 86400;

// Every six hours, plus once at boot. Six hours means a term that ends at
// 02:00 still gets its "ended" mail that morning, and it survives a container
// that is restarted twice a day without ever sending twice (the markers do
// that, not the interval).
const SWEEP_INTERVAL_MS = 6 * 3600000;

// Held only for the length of one sweep. Long enough that a slow redis or a
// large index cannot let a second container in halfway; far shorter than the
// interval, so a container that is killed mid-sweep does not block the next
// window.
const LOCK_TTL_MS = 10 * 60000;

const DEFAULT_SITE_URL = 'https://paramant.app';

// ── Naming ───────────────────────────────────────────────────────────────────
const PRODUCT_NAME = Object.freeze({ parasign: 'ParaSign', parasend: 'ParaSend' });
const TIER_NAME = Object.freeze({ pro: 'Pro', business: 'Business', enterprise: 'Enterprise' });

// The name the site gives the free plan, for both products. entitlements calls
// the floors 'free' (ParaSign) and 'community' (ParaSend); /pricing, /account
// and /dashboard all say Community, and the mail has to match what the reader
// sees when he arrives.
const FLOOR_NAME = 'Community';

const MONTHS = Object.freeze(['January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December']);

// "3 October 2026". UTC and hand-built rather than toLocaleDateString: the
// same date has to read the same in a mail from any container, and Intl data is
// not something a slim container image is guaranteed to carry.
//
// The year is part of it. It read "3 October" until 2026-09-03, which is
// unambiguous only while the reader assumes the current year, and a term that
// ended last December reads exactly like one that ends this December. The
// browser side writes the same string from frontend/js/format-date.js, so the
// date in this mail and the date on /account are one date.
function formatDate(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function memberOf(accountId, product) {
  return `${accountId}|${product}`;
}

function parseMember(member) {
  const i = String(member).lastIndexOf('|');
  if (i <= 0) return null;
  const accountId = String(member).slice(0, i);
  const product = String(member).slice(i + 1);
  if (product !== 'parasign' && product !== 'parasend') return null;
  return { accountId, product };
}

// The marker that says this exact mail already went out. paid_until is IN the
// name, so a renewal is a different key and gets its own mail, and a restart
// finds the old one still standing.
function noticeKey(kind, accountId, product, paidUntilIso) {
  return `${NOTICE_PREFIX}:${kind}:${accountId}:${product}:${paidUntilIso}`;
}

function floorTierOf(product) {
  return product === 'parasign' ? 'free' : 'community';
}

function planLabel(product, tier) {
  const p = PRODUCT_NAME[product] || product;
  const t = TIER_NAME[tier] || tier;
  return `${p} ${t}`;
}

// ── The two mails ────────────────────────────────────────────────────────────
// Plain sentences, no urgency, no offer. The customer bought a term; he is
// being told when it stops and that nothing happens to his card unless he says
// so. That last half is the point: on a one-off payment "your plan ends" reads
// as a threat of a charge unless it says otherwise.
function expiryMail({ product, tier, paidUntil, kind, siteUrl }) {
  const date = formatDate(paidUntil);
  if (!date) return null;
  const plan = planLabel(product, tier);
  const pricing = `${String(siteUrl || DEFAULT_SITE_URL).replace(/\/+$/, '')}/pricing`;
  if (kind === 'ended') {
    const subject = `Your ${plan} has ended`;
    const text = [
      `Your ${plan} ended on ${date}, and your account is now on ${FLOOR_NAME}.`,
      '',
      'Nothing was charged. Every plan here is a one-off payment for the term you buy, so nothing renews by itself and nothing is collected without you.',
      '',
      `You can buy another month or another year at any time: ${pricing}`,
      '',
      'Paramant',
    ].join('\n');
    return { subject, text, html: htmlBody(subject, text, pricing) };
  }
  const subject = `Your ${plan} ends on ${date}`;
  const text = [
    `Your ${plan} ends on ${date}.`,
    '',
    `Renew for another month or year, or let it fall back to ${FLOOR_NAME}; nothing is charged automatically.`,
    '',
    `Your plans and prices are here: ${pricing}`,
    '',
    'Paramant',
  ].join('\n');
  return { subject, text, html: htmlBody(subject, text, pricing) };
}

const escHtml = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function htmlBody(subject, text, pricing) {
  const paragraphs = text.split('\n\n')
    .filter((p) => p && p !== 'Paramant')
    .map((p) => `<p style="margin:0 0 16px;line-height:1.6">${escHtml(p)}</p>`)
    .join('\n');
  return [
    '<div style="font-family:system-ui,-apple-system,\'Segoe UI\',sans-serif;color:#0B3A6A;max-width:520px">',
    `<h1 style="font-size:18px;margin:0 0 16px">${escHtml(subject)}</h1>`,
    paragraphs,
    `<p style="margin:0"><a href="${escHtml(pricing)}" style="color:#0B3A6A">${escHtml(pricing)}</a></p>`,
    '</div>',
  ].join('\n');
}

// ── Index maintenance ────────────────────────────────────────────────────────
// Called from the same place that writes paid_until, and once per container at
// boot for what is already on file. Both are upserts, so running them twice
// costs two round trips and changes nothing.
//
// A record on the floor tier, or without a period, is REMOVED rather than
// skipped: that is the chargeback path (setProductPlan(..., floor, null)) and
// an entry left behind would mail a customer about a plan he no longer has.
async function upsertExpiry(redis, { accountId, product, tier, paidUntil, email }) {
  if (!redis || !accountId || (product !== 'parasign' && product !== 'parasend')) {
    return { indexed: false, reason: 'bad_args' };
  }
  const member = memberOf(accountId, product);
  const norm = product === 'parasign'
    ? entitlements.normaliseParasignTier(tier)
    : entitlements.normaliseParasendTier(tier);
  const at = paidUntil ? Date.parse(paidUntil) : NaN;
  if (norm === floorTierOf(product) || Number.isNaN(at)) {
    await redis.zRem(INDEX_ZSET, member);
    await redis.hDel(META_HASH, member);
    return { indexed: false, reason: 'not_paid' };
  }
  await redis.zAdd(INDEX_ZSET, { score: at, value: member });
  await redis.hSet(META_HASH, member, JSON.stringify({
    email: email || '',
    tier: norm,
    paid_until: new Date(at).toISOString(),
  }));
  return { indexed: true, member, score: at };
}

// Drop an account from the index entirely (both products). Used when a key is
// erased or deactivated.
async function forgetAccount(redis, accountId) {
  if (!redis || !accountId) return { removed: 0 };
  let removed = 0;
  for (const product of entitlements.PRODUCTS) {
    const member = memberOf(accountId, product);
    removed += await redis.zRem(INDEX_ZSET, member);
    await redis.hDel(META_HASH, member);
  }
  return { removed };
}

// One boot seed from whatever this container has on file. `records` is an
// iterable of { accountId, record } where record carries plan_<product> and
// paid_until_<product>. Never mails; only fills the index.
async function seedIndex(redis, records) {
  let indexed = 0;
  let seen = 0;
  for (const entry of records || []) {
    const rec = entry && entry.record;
    const accountId = entry && entry.accountId;
    if (!rec || !accountId) continue;
    seen++;
    for (const product of entitlements.PRODUCTS) {
      const tier = rec[entitlements.PRODUCT_PLAN_FIELD[product]];
      const paidUntil = rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]];
      if (!paidUntil) continue;
      const r = await upsertExpiry(redis, { accountId, product, tier, paidUntil, email: rec.email });
      if (r.indexed) indexed++;
    }
  }
  return { seen, indexed };
}

// ── The lock ─────────────────────────────────────────────────────────────────
// SET NX PX. The token is checked before the release so a sweep that overran
// its TTL cannot delete a lock a different container is now holding.
function lockToken() {
  return `${process.pid}:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
}

async function acquireLock(redis, ttlMs, token) {
  const ok = await redis.set(LOCK_KEY, token, { NX: true, PX: ttlMs || LOCK_TTL_MS });
  return ok === 'OK' || ok === true;
}

async function releaseLock(redis, token) {
  const held = await redis.get(LOCK_KEY);
  if (held !== token) return false;
  await redis.del(LOCK_KEY);
  return true;
}

// ── The sweep ────────────────────────────────────────────────────────────────
// deps:
//   redis      node-redis v4 client (required)
//   now        epoch ms, injectable so the tests can move the clock
//   sendEmail  ({to, subject, text, html}) -> truthy when the mail was
//              DISPATCHED. relay.js's sendResendEmail returns false when
//              RESEND_API_KEY is unset, which is exactly the case that must not
//              consume the marker.
//   log        (level, event, fields)
//   siteUrl    base for the /pricing link
//
// Returns { ran, warned, ended, skipped, missing, pruned, reason }.
async function runSweep(deps) {
  const d = deps || {};
  const redis = d.redis;
  const log = typeof d.log === 'function' ? d.log : () => {};
  const now = typeof d.now === 'number' ? d.now : Date.now();
  const sendEmail = d.sendEmail;
  const siteUrl = d.siteUrl || DEFAULT_SITE_URL;
  const out = { ran: false, warned: 0, ended: 0, skipped: 0, missing: 0, pruned: 0, reason: null };
  if (!redis || !redis.isReady) { out.reason = 'no_redis'; return out; }

  const token = lockToken();
  let got = false;
  try {
    got = await acquireLock(redis, d.lockTtlMs || LOCK_TTL_MS, token);
  } catch (e) {
    out.reason = 'lock_error';
    log('warn', 'plan_expiry_lock_failed', { err: e.message });
    return out;
  }
  // Not an error and not worth a log line above debug: on five containers this
  // is the expected answer four times out of five.
  if (!got) { out.reason = 'locked'; return out; }
  out.ran = true;

  try {
    // Everything that has already ended (back to the prune horizon) plus
    // everything ending inside the warning window. One range read; the index
    // holds only accounts with a paid period, and the window is a slice of it.
    const due = await redis.zRangeByScore(INDEX_ZSET, now - PRUNE_AFTER_MS, now + WARN_WINDOW_MS);
    // Anything older than the prune horizon is a finished period nobody owes a
    // mail for. Dropping it keeps the index the size of the paying customers,
    // not the size of everyone who ever paid.
    const stale = await redis.zRangeByScore(INDEX_ZSET, 0, now - PRUNE_AFTER_MS - 1);
    for (const member of stale) {
      await redis.zRem(INDEX_ZSET, member);
      await redis.hDel(META_HASH, member);
      out.pruned++;
    }

    for (const member of due) {
      const parsed = parseMember(member);
      if (!parsed) { out.missing++; continue; }
      const { accountId, product } = parsed;
      let meta = null;
      try { meta = JSON.parse(await redis.hGet(META_HASH, member) || 'null'); } catch { meta = null; }
      if (!meta || !meta.paid_until) {
        // Score without meta: the index and the hash drifted. Drop the entry
        // rather than guess an address.
        await redis.zRem(INDEX_ZSET, member);
        out.missing++;
        continue;
      }
      const at = Date.parse(meta.paid_until);
      if (Number.isNaN(at)) { await redis.zRem(INDEX_ZSET, member); await redis.hDel(META_HASH, member); out.missing++; continue; }
      const tier = meta.tier;
      if (!tier || tier === floorTierOf(product)) { out.skipped++; continue; }

      let kind = null;
      if (now >= at) {
        if (now - at <= ENDED_GRACE_MS) kind = 'ended';
      } else if (at - now <= WARN_WINDOW_MS) {
        kind = 'warn';
      }
      if (!kind) { out.skipped++; continue; }

      const to = meta.email;
      if (!to) {
        log('warn', 'plan_expiry_no_address', { account: String(accountId).slice(0, 12), product, kind });
        out.skipped++;
        continue;
      }

      // Reserve BEFORE sending. Under the lock this only guards against a
      // repeat inside one sweep, but it is also what makes a crash between the
      // send and the write impossible to turn into a second mail. The
      // reservation is given back below when the mail did not actually leave.
      const key = noticeKey(kind, accountId, product, meta.paid_until);
      const reserved = await redis.set(key, String(now), { NX: true, EX: NOTICE_TTL_S });
      if (!(reserved === 'OK' || reserved === true)) { out.skipped++; continue; }

      const msg = expiryMail({ product, tier, paidUntil: at, kind, siteUrl });
      let sent = false;
      try {
        sent = !!(typeof sendEmail === 'function' && await sendEmail({
          to, subject: msg.subject, text: msg.text, html: msg.html,
        }));
      } catch (e) {
        sent = false;
        log('warn', 'plan_expiry_mail_error', { account: String(accountId).slice(0, 12), product, kind, err: e.message });
      }
      if (!sent) {
        // No mail went out, so no marker may stand. One line per missed mail,
        // and the next sweep tries again: an unconfigured RESEND_API_KEY must
        // not silently consume the only warning a customer gets.
        await redis.del(key);
        log('warn', 'plan_expiry_mail_skipped', {
          account: String(accountId).slice(0, 12), product, kind,
          paid_until: meta.paid_until, reason: 'not_dispatched',
        });
        continue;
      }
      if (kind === 'ended') out.ended++; else out.warned++;
      log('info', 'plan_expiry_mail_sent', {
        account: String(accountId).slice(0, 12), product, tier, kind, paid_until: meta.paid_until,
      });
    }
  } catch (e) {
    out.reason = 'sweep_error';
    log('warn', 'plan_expiry_sweep_failed', { err: e.message });
  } finally {
    try { await releaseLock(redis, token); } catch { /* the PX expiry is the backstop */ }
  }
  return out;
}

// ── The planner ──────────────────────────────────────────────────────────────
// One sweep shortly after boot (delayed so the relay finishes starting and so
// five containers coming up together do not all reach the lock in the same
// millisecond), then one every six hours. The timers are unref'd: this must
// never be the reason a process refuses to exit.
function startPlanExpiryPlanner(deps) {
  const d = deps || {};
  const log = typeof d.log === 'function' ? d.log : () => {};
  const intervalMs = d.intervalMs || SWEEP_INTERVAL_MS;
  const bootDelayMs = typeof d.bootDelayMs === 'number'
    ? d.bootDelayMs
    : 30000 + Math.floor(Math.random() * 30000);
  let running = false;
  let seeded = false;
  const tick = async () => {
    // A sweep still running when the next tick arrives is a redis that is very
    // slow; a second one on top of it would only make that worse.
    if (running) return;
    running = true;
    try {
      // Once per process, and BEFORE the first sweep: whatever this container
      // has on file goes into the shared index, so an account that was paid
      // for before this code existed is still reachable. Idempotent, so the
      // other four containers doing the same thing costs round trips and
      // nothing else.
      if (!seeded && typeof d.seed === 'function') {
        seeded = true;
        try {
          const s = await d.seed();
          if (s && s.indexed) log('info', 'plan_expiry_index_seeded', s);
        } catch (e) {
          seeded = false;
          log('warn', 'plan_expiry_seed_failed', { err: e.message });
        }
      }
      const r = await runSweep({ ...d, now: Date.now() });
      if (r.ran && (r.warned || r.ended || r.pruned || r.missing)) {
        log('info', 'plan_expiry_sweep', r);
      }
    } catch (e) {
      log('warn', 'plan_expiry_sweep_failed', { err: e.message });
    } finally {
      running = false;
    }
  };
  const boot = setTimeout(tick, bootDelayMs);
  const timer = setInterval(tick, intervalMs);
  if (boot.unref) boot.unref();
  if (timer.unref) timer.unref();
  return { tick, stop() { clearTimeout(boot); clearInterval(timer); } };
}

module.exports = {
  INDEX_ZSET, META_HASH, LOCK_KEY, NOTICE_PREFIX,
  WARN_DAYS, WARN_WINDOW_MS, ENDED_GRACE_MS, PRUNE_AFTER_MS,
  NOTICE_TTL_S, SWEEP_INTERVAL_MS, LOCK_TTL_MS, DEFAULT_SITE_URL,
  formatDate, memberOf, parseMember, noticeKey, planLabel, expiryMail,
  upsertExpiry, forgetAccount, seedIndex,
  acquireLock, releaseLock, runSweep, startPlanExpiryPlanner,
};
