'use strict';
// WebAuthn / passkey ceremony helpers for the admin server (ADR R018, PR-A).
// The admin server owns the session cookie and is same-origin with the site,
// so the ceremony (challenge issue + assertion/attestation verification, rpId/
// origin checks) lives here. Durable credential storage lives in the relay
// (relay/lib/user-webauthn.js), reached over X-Internal-Auth.
//
// SECURITY: rpId and expectedOrigin are deployment config, NEVER derived from
// the request (Host / X-Forwarded-* are attacker-influenceable behind the
// Caddy->nginx proxy chain). A Host-header attack must not be able to shift the
// RP. Override only via trusted env at deploy time.

const crypto = require('crypto');
const { incrInWindow } = require('./redis-counter');

const RP_ID           = process.env.WEBAUTHN_RP_ID || 'paramant.app';
const RP_NAME         = process.env.WEBAUTHN_RP_NAME || 'Paramant';
const EXPECTED_ORIGIN = process.env.WEBAUTHN_ORIGIN || process.env.SITE_URL || 'https://paramant.app';

// ── Signature-counter (cloned-authenticator) rule ───────────────────────────
// WebAuthn's signature counter is the only defence against a cloned
// authenticator. Many platform passkeys (notably iCloud Keychain) ALWAYS report
// 0 -> in that case the counter is allowed but not comparable. Otherwise the
// counter MUST strictly increase; a non-increasing non-zero counter means a
// possible clone and the assertion is refused (no session). Pure + testable.
function counterIsAcceptable(stored, next) {
  const s = stored | 0;
  const n = next | 0;
  if (s === 0 || n === 0) return true;   // 0 on either side: allowed, not compared
  return n > s;                          // both non-zero: must strictly increase
}

// ── Per-IP / per-account rate limiting (fixed window via Redis INCR) ─────────
// Exact limits are exported so callers (and reviewers) can see them; they are
// enforced on BOTH /login/options and /login/verify.
const LIMITS = {
  loginOptions:    { ip: 30, account: 15, windowSec: 900 },   // 15-min window
  loginVerify:     { ip: 10, account: 5,  windowSec: 900 },
  registerOptions: { ip: 20, account: 10, windowSec: 900 },
  registerVerify:  { ip: 10, account: 5,  windowSec: 900 },
};

// Returns true if this hit is within the limit. `bucket` already encodes scope
// (e.g. 'lv:ip:1.2.3.4' or 'lv:acct:<hash>').
async function rateHit(redisClient, bucket, limit, windowSec) {
  return (await rateHitCounted(redisClient, bucket, limit, windowSec)).allowed;
}

// The same hit, with the count. A caller that has to charge an escalating cost
// (rather than only refuse at the ceiling) needs to know how far into its
// budget this attempt is; `count` is the post-increment value, so the attempts
// BEFORE this one are count - 1.
async function rateHitCounted(redisClient, bucket, limit, windowSec) {
  const k = `paramant:webauthn:rl:${bucket}`;
  // A lost expiry here refuses this bucket for good; see lib/redis-counter.js.
  const n = await incrInWindow(redisClient, k, windowSec);
  return { allowed: n <= limit, count: n };
}

// Hash an account/email scope so the rate-limit key never stores PII.
function scopeHash(s) {
  return crypto.createHash('sha256').update(String(s || '')).digest('hex').slice(0, 32);
}

// ── The address a phone actually sends ───────────────────────────────────────
// /login/options is the only passkey route that depends on a typed field, and
// it answered 400 invalid_email to anything its shape check disliked. The
// browser turned that into "could_not_start (400)" and the customer was stuck,
// while the cross-device link right below it kept working because it sends no
// address at all. That asymmetry is the whole bug report of 2026-09-04.
//
// What arrives here is not always a bare address. A phone keyboard and an
// autofill entry both add things that are invisible on screen:
//
//   - a no-break space (U+00A0) or a zero-width space (U+200B) pasted along
//     with the address, in the MIDDLE of it, where .trim() cannot reach;
//   - a newline or tab from a paste out of a mail client;
//   - the display form "Mick <mick@example.com>", which is what a contact card
//     yields when it is dropped into a text field.
//
// None of those change which account is meant, so none of them are a reason to
// refuse to start the ceremony. Stripping them is safe here in a way it would
// not be elsewhere: this address only selects which credential ids to offer.
// Identity is established at /login/verify from the assertion itself, never
// from this field, so a normalisation that picked the wrong account would still
// hand out nothing a passkey holder could use.
//
// Deliberately NOT normalised: anything that changes which mailbox is named.
// No dots removed, no plus-tag stripped, no unicode confusables folded.
const INVISIBLE_G = /[\u0000-\u0020\u007f\u00a0\u1680\u2000-\u200f\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]/g;
const INVISIBLE_1 = new RegExp(INVISIBLE_G.source);
const ANGLED_RE   = /<([^<>]+)>[^<>]*$/;
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeLoginEmail(raw) {
  let s = String(raw == null ? '' : raw);
  const angled = s.match(ANGLED_RE);
  if (angled) s = angled[1];                 // "Name <a@b.com>" -> "a@b.com"
  s = s.replace(INVISIBLE_G, '');            // anywhere, not only at the ends
  return s.toLowerCase();
}

// Is this a usable sign-in address, after normalisation?
function isLoginEmail(s) { return typeof s === 'string' && s.length > 0 && EMAIL_SHAPE.test(s); }

// What the process log is allowed to say about an address it refused.
//
// Not the address, not a hash of it, not its domain: only the shape facts that
// tell the next reader WHICH check failed and why. A length and a handful of
// booleans identify nobody, and they are exactly what was missing when this
// came in from a phone we cannot attach a debugger to.
function loginEmailShape(raw) {
  const s = String(raw == null ? '' : raw);
  const n = normalizeLoginEmail(s);
  return {
    len: s.length,
    at_count: (s.match(/@/g) || []).length,
    dot_after_at: /@[^@]*\./.test(s),
    invisible: INVISIBLE_1.test(s),
    inner_space: /\S[ \t\u00a0]+\S/.test(s),
    angled: ANGLED_RE.test(s),
    non_ascii: /[^\x20-\x7e]/.test(s),
    normalised_ok: isLoginEmail(n),
    changed_by_normalise: n !== s.toLowerCase().trim(),
  };
}

// ── One-shot challenge / flow store ──────────────────────────────────────────
// The flow record holds the expected challenge plus the identity the options
// step bound it to. Consumed (deleted) at verify BEFORE any crypto, so a
// challenge can never be replayed. EX 300s.
function newFlowId() { return crypto.randomBytes(16).toString('hex'); }

async function putAuthFlow(redisClient, flowId, data) {
  await redisClient.set(`paramant:webauthn:auth:${flowId}`, JSON.stringify(data), { EX: 300 });
}

async function takeAuthFlow(redisClient, flowId) {
  if (typeof flowId !== 'string' || !/^[0-9a-f]{32}$/.test(flowId)) return null;
  const k = `paramant:webauthn:auth:${flowId}`;
  const raw = await redisClient.get(k);
  if (!raw) return null;
  await redisClient.del(k);                 // one-shot: consume before verifying
  try { return JSON.parse(raw); } catch { return null; }
}

// Registration flow store (separate namespace from auth). Same one-shot
// semantics: the record holds the expected challenge and the verified-email
// binding (user_id + email + the setup_token it was derived from).
async function putRegFlow(redisClient, flowId, data) {
  await redisClient.set(`paramant:webauthn:reg:${flowId}`, JSON.stringify(data), { EX: 300 });
}

async function takeRegFlow(redisClient, flowId) {
  if (typeof flowId !== 'string' || !/^[0-9a-f]{32}$/.test(flowId)) return null;
  const k = `paramant:webauthn:reg:${flowId}`;
  const raw = await redisClient.get(k);
  if (!raw) return null;
  await redisClient.del(k);                 // one-shot: consume before verifying
  try { return JSON.parse(raw); } catch { return null; }
}

module.exports = {
  RP_ID, RP_NAME, EXPECTED_ORIGIN,
  counterIsAcceptable,
  LIMITS, rateHit, rateHitCounted, scopeHash,
  normalizeLoginEmail, isLoginEmail, loginEmailShape,
  newFlowId, putAuthFlow, takeAuthFlow, putRegFlow, takeRegFlow,
};
