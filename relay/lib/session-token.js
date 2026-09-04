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
// At most this many live tokens per account. A ceiling, not a rate limit: the
// page mints one per load and one per refresh, so twenty is far above any
// honest use, and it stops a signed-in session (or a script inside one) from
// turning the mint route into an unbounded credential factory. The index is
// pruned before the cap is believed, so nobody is refused because of tokens
// redis has already expired.
const MAX_LIVE_PER_ACCOUNT = 20;
// 32 bytes of CSPRNG, hex. The shape is pinned here rather than guessed at the
// call sites, so a malformed Authorization header is refused before it ever
// reaches the store.
const TOKEN_RE = /^pst_[0-9a-f]{64}$/;

// SHA-256 of an api-key, hex. The ONE way an owner is named anywhere in this
// module: in the redis key names AND in the record body.
//
// WHY THE BODY TOO. The key names were hashed from the start, because SCAN
// output, keyspace listings and the slowlog all show names. The VALUE was the
// api-key in the clear, which meant an RDB snapshot, a replica, a backup on
// someone's laptop or a MONITOR session carried live pgp_ credentials for every
// account that had sent a file in the last fifteen minutes. A read-only leak of
// the store is now a leak of hashes: to use one you would have to already hold
// the key it is a hash of.
//
// Preimage resistance is not what does the work here, and it should not have
// to: an api-key is 32 random bytes, so the hash is not guessable, but the real
// property is that the relay resolves a hash by looking it up in the api-key
// table it already has in memory. Nothing derives a key from a hash. Anyone
// without that table has a hash and nothing else.
const keyHash = (key) => crypto.createHash('sha256').update(String(key)).digest('hex');
const HASH_RE = /^[0-9a-f]{64}$/;

// token -> owner record.
const tokenKey = (token) => `paramant:pst:${token}`;
// owner key -> the set of tokens minted for it, so a revocation can sweep them.
const ownerKey = (key) => `paramant:pst:owner:${keyHash(key)}`;

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

// ── The second purpose: the signed-in app pages ──────────────────────────────
// A token is minted FOR A PURPOSE, and the purpose picks which allowlist it is
// judged against. The two lists are DISJOINT and neither is a superset of the
// other: a token minted on /parashare cannot start a checkout, and a token
// minted on /pricing cannot upload a file. That is the only reason this feature
// could grow past the transfer path at all. Merging both into one flat SCOPE
// would have widened the ParaSend token by three routes to give three other
// pages a credential they needed, which is how a narrow credential quietly
// becomes an api-key again.
//
// Why each route is here, and nothing else is:
//
//   POST /v2/billing/checkout        /pricing. Pressing a price button creates
//     a Mollie payment whose metadata names the account, and that call is
//     authenticated to the relay. Until now pricing-billing.js fetched the
//     account's pgp_ key to make it, so every visit to /pricing that ended in a
//     click put a permanent data-plane credential in the tab. The route creates
//     a payment; it moves no money and reveals nothing about the account.
//
//   GET  /v2/user/history            /dashboard, "Your history". A read-only
//     projection over the account's own audit chain: identifiers, status and
//     timing, never a payload, download token or key. This one path out of
//     /v2/user/* is named ON ITS OWN, never a prefix, precisely because the
//     rest of /v2/user/* is the signing-key and TOTP surface that the ParaSend
//     scope note below refuses by name. A read of your own history is not that.
//
//   GET  /v2/parasign/audit-export   /dashboard, the signing-audit export. Also
//     read-only over the same chain, tier-gated at Business+ by the route
//     itself. It is an export of what the account already did.
//
//   GET  /v2/parasign/inbox          the signed-in homepage and /dashboard,
//     "Waiting for your signature". The other three routes answer questions
//     about what the account DID; this one answers what is waiting ON it, off
//     the party index in relay/envelope.js.
//
//     The two pages that show it today reach it through the admin proxy, on the
//     session cookie, like every other fetch they make. It is on this list all
//     the same, and from the day the route is born rather than later: the proxy
//     forwards the ACCOUNT'S OWN API-KEY, which is the credential #401 and its
//     follow-up spent two changes taking out of these pages. A route that only
//     ever answers a key is a route that has to be re-authorised the day a page
//     moves off keys, and that is the moment somebody widens a list under time
//     pressure. Naming it here means the narrow credential is never the one
//     thing that cannot read it.
//
//     It is in scope because of what it CANNOT hand out, not because of who
//     asks for it. The route returns a document name, who sent it, when it went
//     out and when signing closes. It does not return the per-party invite
//     token, the document hash, the capsule, or the other parties' email
//     hashes. So a stolen token buys the knowledge that a document is waiting,
//     which the thief's victim already had, and not the capability to open or
//     sign it: that still lives only in the link in the mail. The resend action
//     next to it (POST /v2/parasign/inbox/<id>/resend) is deliberately NOT
//     here. It reads the stored invite token back to put it in a mail, so it
//     stays behind internal auth on the admin hop, where a browser cannot
//     reach it at all.
//
//     The address it answers for is derived by the relay from the resolved
//     api-key, never taken from the request. A header a browser can set would
//     have turned a fifteen-minute token into a way to read anybody's worklist.
//
// What stays out, under BOTH purposes: /v2/keys, the signing-key and TOTP
// routes, /v2/outbound, /v2/admin/*, and /v2/session-token itself. No token
// mints another one, whatever it was minted for.
const APP_SCOPE = [
  { method: 'POST', path: '/v2/billing/checkout' },
  { method: 'GET', path: '/v2/user/history' },
  { method: 'GET', path: '/v2/parasign/audit-export' },
  { method: 'GET', path: '/v2/parasign/inbox' },
];

const PURPOSE_PARASEND = 'parasend';
const PURPOSE_APP = 'app';
const SCOPES = { [PURPOSE_PARASEND]: SCOPE, [PURPOSE_APP]: APP_SCOPE };

// A stored record written before purposes existed has no `p` field, and it can
// only be a ParaSend token, so an ABSENT purpose means parasend. That is the
// only lenient case, and it is deliberately `undefined` alone: null, a number,
// an object and an unknown word all come back null, and null opens nothing.
//
// This asymmetry is the whole safety property. If null had folded onto parasend
// too, then a record carrying a purpose this build does not understand would be
// judged against the transfer allowlist instead of being refused, which is a
// credential doing something nobody minted it to do. So: unknown means no
// scope, and resolve() below turns that into no principal at all.
function normalisePurpose(purpose) {
  if (purpose === undefined || purpose === '') return PURPOSE_PARASEND;
  return Object.prototype.hasOwnProperty.call(SCOPES, purpose) ? purpose : null;
}

function scopeAllows(method, path, purpose = PURPOSE_PARASEND) {
  const m = String(method || '').toUpperCase();
  // A preflight carries no Authorization header, so it never gets here with a
  // token; if one ever does, it is answered by the CORS handler, not by us.
  if (m === 'OPTIONS') return true;
  const rules = SCOPES[normalisePurpose(purpose)];
  if (!rules) return false;
  return rules.some((rule) => {
    if (rule.method && rule.method !== m) return false;
    return rule.re ? rule.re.test(path) : rule.path === path;
  });
}

// ── Store ────────────────────────────────────────────────────────────────────

// Drop the names of tokens redis has already expired from an owner index, and
// return how many are really live. The index is a set of NAMES; redis expires
// the records those names point at, not the names, so the set drifts upward
// until something looks. Only the cap below looks, and only when it is about to
// refuse, so this costs nothing on the ordinary path.
async function pruneOwnerIndex(redisClient, idx) {
  const names = await redisClient.sMembers(idx);
  if (!names || !names.length) return 0;
  const alive = await Promise.all(names.map((n) => redisClient.exists(tokenKey(n))));
  const dead = names.filter((_, i) => !alive[i]);
  if (dead.length) await redisClient.sRem(idx, dead);
  return names.length - dead.length;
}

// Mint a token for `owner` (an api-key). Returns { token, expires_ms,
// expires_in_s }, or { capped: true, live, cap } when the account already holds
// the maximum number of live tokens. Throws when there is no store: a token
// that cannot be written must not be handed out, because the holder would then
// carry a credential no relay can check.
async function mint(redisClient, owner, now = Date.now(), purpose = PURPOSE_PARASEND) {
  if (!redisClient) throw new Error('session-token: no redis client');
  if (!owner || typeof owner !== 'string') throw new Error('session-token: no owner key');
  // A purpose this module does not know is refused HERE rather than written and
  // refused later: a token that opens nothing is a support ticket, and minting
  // one silently is how a typo in a caller becomes an hour of debugging.
  const p = normalisePurpose(purpose);
  if (!p) throw new Error('session-token: unknown purpose');
  const idx = ownerKey(owner);

  // The ceiling. sCard first because it is one round trip and almost always
  // under the cap; the prune runs only when the cheap count says we are about
  // to refuse, so a refusal is never made on the strength of dead names.
  let live = await redisClient.sCard(idx);
  if (live >= MAX_LIVE_PER_ACCOUNT) {
    live = await pruneOwnerIndex(redisClient, idx);
    if (live >= MAX_LIVE_PER_ACCOUNT) {
      return { capped: true, live, cap: MAX_LIVE_PER_ACCOUNT };
    }
  }

  const token = PREFIX + crypto.randomBytes(32).toString('hex');
  const expires_ms = now + TTL_S * 1000;
  // The owner is named by HASH, never in the clear: see keyHash above for why
  // the value matters as much as the key name. exp is stored inside the record
  // as well as being the redis TTL. Redis is what expires it; the field is what
  // catches a record that outlived its TTL through a restore, a replica lag or
  // a hand-written key.
  await redisClient.set(tokenKey(token), JSON.stringify({ kh: keyHash(owner), exp: expires_ms, p }), { EX: TTL_S });
  // The sweep index. Its own TTL is the token's plus a minute, refreshed on
  // every mint, so the set never outlives the last token it points at by more
  // than that.
  await redisClient.sAdd(idx, token);
  await redisClient.expire(idx, TTL_S + 60);
  return { token, expires_ms, expires_in_s: TTL_S, purpose: p };
}

// The owner key a token stands for, or null. Null covers every refusal there
// is: a malformed token, one that expired, one that was revoked, one whose
// record is not the shape this module writes, and one whose owner hash no
// longer resolves to a key. The caller cannot tell them apart, and must not:
// that separation would be an oracle for guessing tokens.
//
// `resolveOwner` turns the stored hash back into the api-key. It is injected,
// and in relay.js it is a lookup in the api-key table already in memory. That
// is the whole reason hashing the record is free: nothing derives a key from a
// hash, it is looked up in a table only the relay has.
//
// EXP IS REQUIRED. A record with no exp, or an exp that is not a number, is
// refused. It used to be optional, checked with a typeof, so a record that
// somehow lost the field fell back to whatever TTL redis had on it, and one
// written by hand with no field at all never expired on the wall clock at all.
// A credential whose lifetime is a property of the store alone has no lifetime
// when the store is wrong.
//
// A redis failure is NOT null. It throws, and the route turns that into a 503,
// because answering 401 on an outage would tell a legitimate holder their token
// is bad and send them to re-authenticate over a store that is merely down.
async function resolve(redisClient, token, resolveOwner, now = Date.now()) {
  if (!isSessionToken(token)) return null;
  if (!redisClient) throw new Error('session-token: no redis client');
  if (typeof resolveOwner !== 'function') throw new Error('session-token: no owner resolver');
  const raw = await redisClient.get(tokenKey(token));
  if (!raw) return null;
  let rec;
  try { rec = JSON.parse(raw); } catch (_) { return null; }
  if (!rec || typeof rec.kh !== 'string' || !HASH_RE.test(rec.kh)) return null;
  if (typeof rec.exp !== 'number' || !Number.isFinite(rec.exp)) return null;
  if (now > rec.exp) return null;
  const key = resolveOwner(rec.kh);
  if (!key || typeof key !== 'string') return null;
  // The purpose travels back with the principal, because the caller cannot
  // decide the scope without it. A record with no `p` predates purposes and is
  // a ParaSend token. A record with a `p` this build does not know is refused
  // OUTRIGHT, here, rather than handed back with an empty scope: a credential
  // whose authority this code cannot compute is not a principal, and leaving it
  // to the gate would make every future caller of resolve() responsible for a
  // rule that belongs in one place.
  const purpose = normalisePurpose(rec.p);
  if (!purpose) return null;
  return { key, expires_ms: rec.exp, purpose };
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
  TTL_S, PREFIX, SCOPE, APP_SCOPE, SCOPES, MAX_LIVE_PER_ACCOUNT,
  PURPOSE_PARASEND, PURPOSE_APP, normalisePurpose,
  isSessionToken, bearerToken, scopeAllows, keyHash,
  mint, resolve, revokeForKey, pruneOwnerIndex,
  tokenKey, ownerKey,
};
