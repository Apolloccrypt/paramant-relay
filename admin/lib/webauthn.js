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
  const k = `paramant:webauthn:rl:${bucket}`;
  const n = await redisClient.incr(k);
  if (n === 1) await redisClient.expire(k, windowSec);
  return n <= limit;
}

// Hash an account/email scope so the rate-limit key never stores PII.
function scopeHash(s) {
  return crypto.createHash('sha256').update(String(s || '')).digest('hex').slice(0, 32);
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
  LIMITS, rateHit, scopeHash,
  newFlowId, putAuthFlow, takeAuthFlow, putRegFlow, takeRegFlow,
};
