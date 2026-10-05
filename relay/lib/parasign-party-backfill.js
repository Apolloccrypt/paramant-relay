'use strict';
// Filling the party worklist index for the envelopes that predate it.
//
// WHY THIS FILE EXISTS. relay/envelope.js writes 'parasign:party:<hash>:envelopes'
// in create(), so every envelope made from now on indexes itself. Every envelope
// made BEFORE that line existed does not, and those are precisely the ones a
// recipient is waiting on today. Without a backfill the new worklist would be
// truthful and empty for a fortnight, which reads to the person waiting exactly
// like the bug it was built to fix.
//
// It is a migration, not a sweep: it runs once, it is finished, and then it
// never runs again. Three properties make that safe on this estate.
//
//   1. FIVE CONTAINERS, ONE STORE. relay-main, relay-health, relay-finance,
//      relay-legal and relay-iot all run this code against one redis. A SCAN of
//      every envelope hash times five, at boot, is five times the work for one
//      result. The lock is redis SET NX PX, the same idiom lib/plan-expiry.js
//      takes per sweep, with the token checked before the release so a run that
//      overran its TTL cannot delete a lock another container now holds.
//
//   2. RESTARTS. The relay restarts on every deploy. A marker in process memory
//      would therefore mean "once per deploy", forever. The marker is a redis
//      key with no TTL, written only after a run that finished, so the second
//      container up finds the work done and the tenth deploy scans nothing.
//
//   3. IT IS IDEMPOTENT ANYWAY. Both of the above are optimisations, not
//      correctness: EnvelopeStore.backfillPartyIndex() adds only slots that are
//      still waiting, and a zAdd of a member already present only rewrites its
//      score with the same created_at. Running it twice, or concurrently, gives
//      the same set. That is deliberate: a migration whose safety rests on a
//      lock is a migration that breaks the day the lock is lost.
//
// The relay never learns an address here. The index is keyed on the same
// namespaced party-email hash the envelope record already stores.

const LOCK_KEY = 'paramant:parasign:party_index:lock';
const DONE_KEY = 'paramant:parasign:party_index:backfilled';
// Long enough for a SCAN over an estate-sized keyspace, short enough that a
// container killed mid-run does not block the next boot for an afternoon.
const LOCK_TTL_MS = 10 * 60000;
// Boot delay with jitter, so five containers coming up together do not all
// reach the lock in the same millisecond and four of them do a pointless GET.
const BOOT_DELAY_MS = 15000;
const BOOT_JITTER_MS = 20000;

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

// Run the backfill unless it has already been done.
//
// deps:
//   redis     node-redis v4 client (required)
//   store     an EnvelopeStore (required)
//   log       (level, event, fields)
//   force     ignore the done marker; for the operator script, never at boot
//   lockTtlMs override for the tests
//
// Returns { ran, reason, scanned, indexed, skipped }. `ran: false` with reason
// 'done' or 'locked' is the ordinary answer on four containers out of five and
// on every boot after the first; it is not a failure and gets no log line.
async function runPartyIndexBackfill(deps) {
  const d = deps || {};
  const redis = d.redis;
  const store = d.store;
  const log = typeof d.log === 'function' ? d.log : () => {};
  const out = { ran: false, reason: null, scanned: 0, indexed: 0, skipped: 0 };
  if (!redis || !redis.isReady) { out.reason = 'no_redis'; return out; }
  if (!store || !store.available()) { out.reason = 'no_store'; return out; }

  if (!d.force) {
    try {
      if (await redis.get(DONE_KEY)) { out.reason = 'done'; return out; }
    } catch (e) {
      out.reason = 'marker_error';
      log('warn', 'party_index_marker_failed', { err: e.message });
      return out;
    }
  }

  const token = lockToken();
  let got = false;
  try {
    got = await acquireLock(redis, d.lockTtlMs || LOCK_TTL_MS, token);
  } catch (e) {
    out.reason = 'lock_error';
    log('warn', 'party_index_lock_failed', { err: e.message });
    return out;
  }
  if (!got) { out.reason = 'locked'; return out; }

  try {
    // Re-read the marker under the lock. Without this, two containers that both
    // passed the check above would both scan the whole keyspace: harmless, but
    // it is the one race the lock is here to remove.
    if (!d.force && await redis.get(DONE_KEY)) { out.reason = 'done'; return out; }
    const res = await store.backfillPartyIndex({ log });
    out.ran = true;
    out.scanned = res.scanned;
    out.indexed = res.indexed;
    out.skipped = res.skipped;
    // The marker carries the result, not just a flag, so an operator reading the
    // keyspace can see what the migration actually did and when.
    await redis.set(DONE_KEY, JSON.stringify({ at: new Date().toISOString(), ...res }));
    // The one line this migration is allowed to print. It names the count,
    // because "how many were waiting and invisible" is the number anybody
    // reviewing this feature will ask for first.
    log('info', 'parasign_party_index_backfilled', res);
  } catch (e) {
    out.reason = 'failed';
    // Deliberately no marker on a failure: the next boot tries again. A partial
    // run leaves a partly filled index, which is correct-but-incomplete, and the
    // retry completes it because zAdd is idempotent.
    log('warn', 'parasign_party_index_backfill_failed', { err: e.message });
  } finally {
    try { await releaseLock(redis, token); } catch { /* the TTL is the backstop */ }
  }
  return out;
}

// Schedule the one run, after a jittered boot delay. Returns { stop } so a test
// can cancel it. The timer is unref'd: this must never be the reason a process
// stays alive.
function startPartyIndexBackfill(deps) {
  const d = deps || {};
  const delay = Number.isFinite(d.bootDelayMs)
    ? d.bootDelayMs
    : BOOT_DELAY_MS + Math.floor(Math.random() * BOOT_JITTER_MS);
  const timer = setTimeout(() => {
    runPartyIndexBackfill(d).catch((e) => {
      const log = typeof d.log === 'function' ? d.log : () => {};
      log('warn', 'parasign_party_index_backfill_failed', { err: e.message });
    });
  }, delay);
  if (timer.unref) timer.unref();
  return { stop() { clearTimeout(timer); } };
}

module.exports = {
  LOCK_KEY, DONE_KEY, LOCK_TTL_MS,
  runPartyIndexBackfill, startPartyIndexBackfill,
  acquireLock, releaseLock,
};
