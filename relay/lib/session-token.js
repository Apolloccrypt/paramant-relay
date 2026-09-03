'use strict';
// ParaSend session tokens (pst_): a narrow, short-lived stand-in for an account
// api-key, so /parashare never has to hold a pgp_ key in the browser.
//
// WHAT PROBLEM THIS SOLVES. Until now the ParaSend page fetched the account's
// real api-key from GET /api/user/account/key and kept it in a variable for the
// life of the tab. That is a full data-plane credential with no expiry: any
// script that got to run on the page could read it, and then keep it. The
// security review of #397 said as much, and this is the answer it named. The
// page now asks the admin for a pst_ token, the token lives fifteen minutes,
// and it opens only the five routes a transfer actually walks. The XSS ceiling
// drops from "a key, forever" to "these five routes, for fifteen minutes".
//
// WHY REDIS AND NOT A MAP. The five sector relays are separate processes behind
// one shared redis (docker-compose.yml). A Map would mint on health and be
// unknown on legal, and the page discovers its sector at run time, so the token
// has to live where all five can see it.
//
// This module is the decision layer, with the redis client injected, so every
// rule below is unit-testable without a relay: relay/test/session-token.test.js
// covers it against a fake store, relay/test/route-session-token.test.js drives
// the real thing over HTTP.

const crypto = require('crypto');

// Fifteen minutes. Long enough for a sender to pick a file, compare a
// fingerprint and upload it; short enough that a stolen token is a window and
// not a key. Not configurable on purpose: an operator who could set this to a
// week would silently rebuild the credential this module exists to remove.
const TTL_S = 900;

const PREFIX = 'pst_';
// 32 bytes of CSPRNG, hex. The shape is pinned here rather than guessed at the
// call sites, so a malformed Authorization header is refused before it ever
// reaches the store.
const TOKEN_RE = /^pst_[0-9a-f]{64}$/;

// token -> owner record.
const tokenKey = (token) => `paramant:pst:${token}`;
// owner key -> the set of tokens minted for it, so a revocation can sweep them.
// The owner key is hashed: redis keyspace listings, SCAN output and slowlog
// entries all show key NAMES, and an api-key in a key name is an api-key in
// every one of those places.
const ownerKey = (key) =>
  `paramant:pst:owner:${crypto.createHash('sha256').update(String(key)).digest('hex')}`;

function isSessionToken(value) {
  return typeof value === 'string' && TOKEN_RE.test(value);
}

// The token out of an Authorization header, or ''. Only the Bearer form is
// unwrapped, and only when it is the whole header: `Bearer a b` is not a token.
function bearerToken(header) {
  if (typeof header !== 'string') return '';
  const m = /^Bearer[ \t]+([^\s]+)$/i.exec(header.trim());
  return m ? m[1] : '';
}

// ── Scope ────────────────────────────────────────────────────────────────────
// An ALLOWLIST, deliberately, and the whole point of the feature. A pst_ token
// is not a small api-key, it is a different credential that happens to
// authenticate as the same account: it opens the five routes /parashare walks
// and nothing else. Anything not named here is refused, including routes that
// do not exist yet, which is what keeps this list honest as relay.js grows.
//
// What is NOT here, and why each absence matters:
//   /v2/user/*      the account's own session surface (TOTP, signing keys,
//                   document worklist). A token minted for a file transfer must
//                   never be able to enrol a signing key.
//   /v2/keys        anything that hands out or lists credentials.
//   /v2/outbound    downloading is the receiver's half of the flow and needs no
//                   account credential; letting a token do it would make a
//                   stolen token a way to drain the account's blobs.
//   /v2/audit       the account's history.
//   /v2/admin/*     never, under any credential but ADMIN_TOKEN.
//   /v2/session-token itself: a token may not mint another one, so the fifteen
//                   minutes cannot be rolled forward from inside the browser.
const SCOPE = [
  // Sector discovery. The page races four sectors to find the one that accepts
  // the account; the answer is valid/plan and nothing else.
  { method: null, path: '/v2/check-key' },
  // The one-time ticket for the signalling socket.
  { method: 'POST', path: '/v2/ws-ticket' },
  // Publishing the sender's half of the handshake, and reading the receiver's.
  { method: 'POST', path: '/v2/pubkey' },
  { method: 'GET', re: /^\/v2\/pubkey\/[^/]+$/ },
  // The upload itself.
  { method: 'POST', path: '/v2/inbound' },
];

function scopeAllows(method, path) {
  const m = String(method || '').toUpperCase();
  // A preflight carries no Authorization header, so it never gets here with a
  // token; if one ever does, it is answered by the CORS handler, not by us.
  if (m === 'OPTIONS') return true;
  return SCOPE.some((rule) => {
    if (rule.method && rule.method !== m) return false;
    return rule.re ? rule.re.test(path) : rule.path === path;
  });
}

// ── Store ────────────────────────────────────────────────────────────────────

// Mint a token for `owner` (an api-key). Returns { token, expires_ms,
// expires_in_s }. Throws when there is no store: a token that cannot be written
// must not be handed out, because the holder would then carry a credential no
// relay can check.
async function mint(redisClient, owner, now = Date.now()) {
  if (!redisClient) throw new Error('session-token: no redis client');
  if (!owner || typeof owner !== 'string') throw new Error('session-token: no owner key');
  const token = PREFIX + crypto.randomBytes(32).toString('hex');
  const expires_ms = now + TTL_S * 1000;
  // exp is stored INSIDE the record as well as being the redis TTL. Redis is
  // what expires it; the field is what catches a record that outlived its TTL
  // through a restore, a replica lag or a hand-written key.
  await redisClient.set(tokenKey(token), JSON.stringify({ key: owner, exp: expires_ms }), { EX: TTL_S });
  // The sweep index. Its own TTL is the token's plus a minute, refreshed on
  // every mint, so the set never outlives the last token it points at by more
  // than that. Entries for tokens that already expired are harmless: the
  // revocation deletes names, and deleting a name that is gone is a no-op.
  await redisClient.sAdd(ownerKey(owner), token);
  await redisClient.expire(ownerKey(owner), TTL_S + 60);
  return { token, expires_ms, expires_in_s: TTL_S };
}

// The owner key a token stands for, or null. Null covers every refusal there
// is: a malformed token, one that expired, one that was revoked, and one whose
// record is not the shape this module writes. The caller cannot tell them
// apart, and must not: that separation would be an oracle for guessing tokens.
//
// A redis failure is NOT null. It throws, and the route turns that into a 503,
// because answering 401 on an outage would tell a legitimate holder their token
// is bad and send them to re-authenticate over a store that is merely down.
async function resolve(redisClient, token, now = Date.now()) {
  if (!isSessionToken(token)) return null;
  if (!redisClient) throw new Error('session-token: no redis client');
  const raw = await redisClient.get(tokenKey(token));
  if (!raw) return null;
  let rec;
  try { rec = JSON.parse(raw); } catch (_) { return null; }
  if (!rec || typeof rec.key !== 'string' || !rec.key) return null;
  if (typeof rec.exp === 'number' && now > rec.exp) return null;
  return { key: rec.key, expires_ms: typeof rec.exp === 'number' ? rec.exp : null };
}

// Every live token for one api-key, gone. Called when the key is revoked.
//
// This is belt AND braces, and both halves are load-bearing. The braces are
// here: the tokens are deleted, so they stop resolving on every sector at once.
// The belt is in relay.js: a resolved token is looked up in apiKeys like any
// other credential, so a token whose owner is no longer an active key yields no
// principal even if this sweep never ran (a sector that was restarting, a redis
// that was briefly unreachable). Neither alone is enough; a revocation that
// depends on a best-effort write is not a revocation.
async function revokeForKey(redisClient, owner) {
  if (!redisClient || !owner) return 0;
  const idx = ownerKey(owner);
  const tokens = await redisClient.sMembers(idx);
  if (tokens && tokens.length) await redisClient.del(tokens.map(tokenKey));
  await redisClient.del(idx);
  return (tokens || []).length;
}

module.exports = {
  TTL_S, PREFIX, SCOPE,
  isSessionToken, bearerToken, scopeAllows,
  mint, resolve, revokeForKey,
  tokenKey, ownerKey,
};
