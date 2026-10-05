'use strict';
// The sessions of ONE user, addressable without reading everybody else's.
//
// WHY THIS FILE EXISTS. Finding 14 of the 2026-09-05 hostile review. Eight
// places in admin/server.js answered the question "which sessions belong to
// this user?" the same way: SCAN the whole Redis keyspace for
// paramant:user:session:*, GET every key that comes back, parse it, and throw
// away the ones belonging to somebody else. GET /api/user/account did it on
// every page load of the account screen, with no rate limit and no cache, and
// the Redis behind it is shared by all five relay sectors and the admin plane.
// One free account plus a loop is a fleet-wide load generator.
//
// The cost is not only the scan. It is a serial GET per key, so the work grows
// with the number of sessions in the entire product, and the user-agent column
// of one person's account page is paid for by everybody's Redis.
//
// It is also a privacy shape nobody chose: to show you your own sessions, the
// process reads every other customer's session blob, complete with their IP and
// their user agent, and filters afterwards.
//
// So each session is written into a per-user SET as well, and the eight readers
// ask that set. A session is two keys now, and the invariant is that the SET may
// hold a token whose blob is already gone (an expired session, a crash between
// the two writes) but never the other way round: the blob is written first and
// removed last. Every reader prunes what it finds dead, so the set converges
// without a sweeper.
//
// TTL. The set outlives the longest session it can hold, and every write pushes
// it out again. A user who never comes back loses the set by expiry, which is
// correct: there is nothing left to index.
//
// The fallback is deliberate. `list` and `revokeAll` take a `scan` function and
// use it ONLY when the index is missing for a user who demonstrably has
// sessions -- the deploy window, where sessions minted by the old code carry no
// index entry. It is not a permanent second path: `indexed` in the result says
// which way the answer came, so a caller (and a test) can see the difference.

const SESSION_PREFIX = 'paramant:user:session:';
const INDEX_PREFIX = 'paramant:user:sessions:';

// Comfortably past the sliding one-hour session TTL and the absolute cap, so a
// live session is never orphaned by its own index expiring first.
const INDEX_TTL_S = 8 * 24 * 3600;

const sessionKey = (token) => `${SESSION_PREFIX}${token}`;
const indexKey = (userId) => `${INDEX_PREFIX}${userId}`;
const tokenOf = (key) => String(key).slice(SESSION_PREFIX.length);

// Write the session and index it. The blob first: a token in the set with no
// blob is a harmless miss that the next read prunes, while a blob with no index
// entry is a session its owner cannot see or revoke.
async function remember(redis, userId, token, record, ttlS) {
  await redis.set(sessionKey(token), JSON.stringify(record), { EX: ttlS });
  if (!userId) return;
  try {
    await redis.sAdd(indexKey(userId), token);
    await redis.expire(indexKey(userId), INDEX_TTL_S);
  } catch (_) { /* the session still works; the next read falls back to a scan */ }
}

// Drop one session. Blob last, for the same reason.
async function forget(redis, userId, token) {
  if (userId) { try { await redis.sRem(indexKey(userId), token); } catch (_) { /* pruned on the next read */ } }
  await redis.del(sessionKey(token));
}

async function readIndexed(redis, userId) {
  let tokens = [];
  try { tokens = await redis.sMembers(indexKey(userId)); } catch (_) { return null; }
  if (!tokens || !tokens.length) return null;
  const out = [];
  const dead = [];
  // One round trip for the blobs instead of one per token. mGet on an empty
  // list is not universally safe across clients, hence the guard above.
  let raws;
  try { raws = await redis.mGet(tokens.map(sessionKey)); }
  catch (_) { raws = []; for (const t of tokens) raws.push(await redis.get(sessionKey(t)).catch(() => null)); }
  tokens.forEach((t, i) => {
    const raw = raws[i];
    if (!raw) { dead.push(t); return; }
    let s;
    // One corrupt blob must not take out the whole answer. It can only be this
    // user's now, which is itself part of the repair.
    try { s = JSON.parse(raw); } catch { dead.push(t); return; }
    if (!s || s.user_id !== userId) { dead.push(t); return; }
    out.push({ token: t, session: s });
  });
  if (dead.length) { try { await redis.sRem(indexKey(userId), dead); } catch (_) { /* next read */ } }
  return out;
}

// Every live session of one user, as { token, session }.
//   scan: optional `(redis, match) => AsyncIterable<string>` used only when the
//         user has no index yet. Pass it during the deploy window; leave it out
//         and a missing index simply means no sessions.
async function list(redis, userId, scan) {
  if (!userId) return { sessions: [], indexed: true };
  const indexed = await readIndexed(redis, userId);
  if (indexed) return { sessions: indexed, indexed: true };
  if (typeof scan !== 'function') return { sessions: [], indexed: true };
  const out = [];
  for await (const key of scan(redis, `${SESSION_PREFIX}*`)) {
    const raw = await redis.get(key).catch(() => null);
    if (!raw) continue;
    let s;
    try { s = JSON.parse(raw); } catch { continue; }
    if (!s || s.user_id !== userId) continue;
    out.push({ token: tokenOf(key), session: s });
  }
  // Adopt what the scan found, so the fallback is paid for once per user and
  // not once per request.
  if (out.length) {
    try {
      await redis.sAdd(indexKey(userId), out.map((e) => e.token));
      await redis.expire(indexKey(userId), INDEX_TTL_S);
    } catch (_) { /* the answer is already correct; indexing is the optimisation */ }
  }
  return { sessions: out, indexed: false };
}

// Revoke every session of a user, optionally keeping the one making the request.
// Returns how many were removed.
async function revokeAll(redis, userId, opts = {}) {
  const { except = null, scan = null } = opts;
  const { sessions } = await list(redis, userId, scan);
  let revoked = 0;
  for (const { token } of sessions) {
    if (except && token === except) continue;
    await redis.del(sessionKey(token)).catch(() => {});
    revoked++;
  }
  try {
    if (except) { const keep = sessions.some((e) => e.token === except); await redis.del(indexKey(userId)); if (keep) { await redis.sAdd(indexKey(userId), except); await redis.expire(indexKey(userId), INDEX_TTL_S); } }
    else await redis.del(indexKey(userId));
  } catch (_) { /* the blobs are gone, which is what revocation means */ }
  return revoked;
}

module.exports = { SESSION_PREFIX, INDEX_PREFIX, INDEX_TTL_S, sessionKey, indexKey, remember, forget, list, revokeAll };
