'use strict';

// Named recipients for a send.
//
// The existing transfer is one blob behind one link: whoever opens it first
// gets the file and it burns. That is right for a hand-over between two people
// and wrong for a document that has to reach a group, because the sender never
// learns who actually collected it.
//
// A send with named recipients keeps one blob and gives every person their own
// pickup token. A token works exactly once. The blob is dropped when the last
// token has been used, or when the TTL runs out -- whichever comes first, so a
// send never outlives its window because one person never showed up.
//
// Two deliberate choices.
//
// Tokens are stored hashed, like passwords. A dump of the store therefore does
// not hand over the files. Re-inviting somebody mints a NEW token rather than
// resending the old one; the old one dies at that moment, which is also what a
// sender expects from "send it again".
//
// The email is stored as a namespaced hash, the same shape ParaSign uses for
// signing parties (see envelope.js partyEmailHash). The plain address is kept
// alongside it only so the sender's own dashboard can show who is on the list;
// matching is done on the hash.

const crypto = require('crypto');
const tiers = require('./tiers');

const TOKEN_BYTES = 32;

// Namespaced so a recipient hash can never be confused with, or replayed as, a
// ParaSign party hash over the same address.
// The key that turns this hash from a pseudonym into a real one.
//
// An unsalted hash over email addresses is reversible by guessing: the space is
// small and the answer confirms itself. Keyed, it only means something to this
// relay. RECIPIENT_HASH_KEY keeps the value stable across restarts; without it
// a per-process key is generated, which is safe but makes stored hashes
// unreadable after a restart -- acceptable only while the records live in
// memory too, and a reason to set it before this state moves to Redis.
const EMAIL_HASH_KEY = process.env.RECIPIENT_HASH_KEY || crypto.randomBytes(32).toString('hex');
const EMAIL_HASH_EPHEMERAL = !process.env.RECIPIENT_HASH_KEY;

// `salt` is per send and is stored with it. Without it the hash is a pseudonym
// anyone can undo: the space of email addresses is small, so a guess confirms
// itself. With it, a hash means something only inside its own send, and a dump
// of one send tells you nothing about another.
function recipientEmailHash(email, salt) {
  const norm = normaliseForHash(email);
  if (!norm) return '';
  return crypto.createHmac('sha3-256', EMAIL_HASH_KEY + '\x00' + (salt || ''))
    .update('paramant/send-recipient/v2\x00', 'utf8')
    .update(norm, 'utf8')
    .digest('hex');
}

function newSendSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// Lowercase first, then normalise AGAIN. Some capitals do not fold back in one
// pass: the Turkish dotted capital I lowercases to an i with a combining dot,
// which is a different string from a plain i. One mailbox appearing as two
// recipients means two live tokens, and revoking one revokes nothing.
function normaliseForHash(email) {
  if (email == null) return '';
  try {
    return String(email).normalize('NFC').trim().toLowerCase().normalize('NFC');
  } catch (_) {
    return '';
  }
}

function newPickupToken() {
  return crypto.randomBytes(TOKEN_BYTES).toString('base64url');
}

// What we keep instead of the token itself.
function tokenHash(token) {
  if (typeof token !== 'string' || !token) return '';
  return crypto.createHash('sha3-256')
    .update('paramant/pickup-token/v1\x00', 'utf8')
    .update(token, 'utf8')
    .digest('hex');
}

function safeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length === 0 || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

// Build the recipient table for a new send.
//
// Returns { ok, reason, limit, records, tokens } where `tokens` maps the plain
// email to its one-time token. The caller mails those out and then forgets
// them: they are not recoverable from `records`.
function buildRecipients(plan, list, now) {
  const checked = tiers.checkRecipients(plan, list);
  if (!checked.ok) {
    return { ok: false, reason: checked.reason, limit: checked.limit,
             asked: checked.count, records: [], tokens: {} };
  }
  const at = now || Date.now();
  const salt = newSendSalt();
  const records = [];
  // Object.create(null): a key like __proto__ must be an ordinary entry, not a
  // setter that swallows the token and leaves a recipient who can never collect.
  const tokens = Object.create(null);
  for (const email of checked.recipients) {
    const token = newPickupToken();
    tokens[email] = token;
    records.push({
      email,                              // for the sender's own overview
      email_hash: recipientEmailHash(email, salt),
      token_hash: tokenHash(token),
      invited_at: at,
      picked_up_at: null,
      revoked_at: null,
      reminders: 0,
    });
  }
  return { ok: true, reason: null, limit: checked.limit, asked: records.length,
           salt, records, tokens };
}

// A real token is 43 characters. Anything much longer is somebody making the
// relay hash megabytes on an unauthenticated route; refuse before the work.
const MAX_TOKEN_LEN = 128;

// Find the recipient a pickup token belongs to. Walks the whole table so a
// caller cannot learn which addresses exist by timing the miss. Rows that are
// missing or malformed are skipped rather than thrown over: this runs on a
// public route, where a broken row must be a 404 and never a 500.
function findByToken(records, token) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LEN) return null;
  const want = tokenHash(token);
  if (!want) return null;
  let found = null;
  for (const r of Array.isArray(records) ? records : []) {
    if (!r || typeof r !== 'object') continue;
    if (safeHexEqual(r.token_hash || '', want)) found = r;
  }
  return found;
}

// Find AND claim in one step, bound to the token that was presented.
//
// WHY THIS REPLACED find-then-mark. Looking up, checking and marking used to be
// three separate calls, which let two things through that an adversarial pass
// demonstrated on 22-09:
//
//   Two simultaneous requests with the same token both got the file, while the
//   overview kept saying one collection. An invisible second delivery is worse
//   than a visible one.
//
//   A request that had already fetched its record could still call markPickedUp
//   after a re-invite had replaced the token, so a link the sender had just
//   killed still worked.
//
// So the claim re-verifies the token against the record at the moment it flips
// the flag, and the flip is the same statement as the check. Node runs this
// without interleaving, so the pair is atomic here; the day this state moves to
// Redis it has to become one script there, and that is what the note is for.
//
// Look up and claim in ONE step. Returns the record, or null when the token
// cannot collect. This is what a route must call: anything that first looks up
// and then marks leaves a window in which two requests both pass the check.
function claimPickup(records, token, now) {
  const record = findByToken(records, token);
  if (pickupRefusal(record)) return null;
  return markPickedUp(record, now, token) ? record : null;
}

// Same claim, with the reason a route needs for its error message.
// Returns { ok, record, reason }. Only ok:true may serve the file.
function claim(records, token, now) {
  const record = findByToken(records, token);
  const refusal = pickupRefusal(record);
  if (refusal) return { ok: false, record: record || null, reason: refusal };
  // Re-verify against the presented token: the record may have been re-invited
  // between lookup and here in a future async version of this path.
  if (!safeHexEqual(record.token_hash || '', tokenHash(token))) {
    return { ok: false, record: null, reason: 'unknown_token' };
  }
  if (!markPickedUp(record, now, token)) {
    return { ok: false, record: null, reason: 'unknown_token' };
  }
  return { ok: true, record, reason: null };
}

// Why a token cannot be used right now, or null when it can.
function pickupRefusal(record) {
  if (!record) return 'unknown_token';
  if (record.revoked_at) return 'revoked';
  if (record.picked_up_at) return 'already_collected';
  return null;
}

// Mark one recipient as collected. The token is REQUIRED and is verified
// against the record here.
//
// It used to look only at the record, which meant a request that already held
// the record could still collect after a re-invite had replaced the token: a
// link the sender had just killed kept working. A record alone cannot tell you
// whether the link that reached you is still the current one; only the token
// can, so nothing may flip this flag without presenting it.
function markPickedUp(record, now, token) {
  if (!record || record.picked_up_at || record.revoked_at) return false;
  if (!safeHexEqual(record.token_hash || '', tokenHash(token))) return false;
  record.picked_up_at = now || Date.now();
  return true;
}

// Withdraw one person's access without touching the rest of the send.
function revoke(record, now) {
  if (!record || record.revoked_at || record.picked_up_at) return false;
  record.revoked_at = now || Date.now();
  return true;
}

// Give one person a new token; the old one stops working immediately.
//
// A re-invite does NOT undo a withdrawal. Clearing revoked_at used to bring a
// withdrawn person back with a working link and wipe the withdrawal out of the
// record, so the sender could no longer see that it ever happened. Reversing a
// withdrawal has to be its own decision, with its own trace.
//
// It is also refused once the send is finished, because the file is gone by
// then and a fresh token would point at nothing.
// `records` is optional and last, so existing callers keep working; pass it and
// the send-is-finished check comes along too.
function reinvite(record, now, records) {
  if (!record || typeof record !== 'object') return null;
  if (record.picked_up_at || record.revoked_at) return null;
  if (Array.isArray(records) && allSettled(records)) return null;
  const token = newPickupToken();
  record.token_hash = tokenHash(token);
  record.reminders = (record.reminders || 0) + 1;
  record.invited_at = now || Date.now();
  return token;
}

// The blob may go when nobody can still collect it: everyone has either picked
// it up or been revoked.
function allSettled(records) {
  const list = (Array.isArray(records) ? records : []).filter(r => r && typeof r === 'object');
  if (list.length === 0) return false;
  return list.every(r => r.picked_up_at || r.revoked_at);
}

// What the sender's dashboard shows. No hashes, no tokens.
function overview(records) {
  const list = (Array.isArray(records) ? records : []).filter(r => r && typeof r === 'object');
  const collected = list.filter(r => r.picked_up_at).length;
  return {
    total: list.length,
    collected,
    outstanding: list.filter(r => !r.picked_up_at && !r.revoked_at).length,
    revoked: list.filter(r => r.revoked_at && !r.picked_up_at).length,
    recipients: list.map(r => ({
      email: r.email,
      status: r.picked_up_at ? 'collected' : r.revoked_at ? 'revoked' : 'waiting',
      invited_at: r.invited_at || null,
      picked_up_at: r.picked_up_at || null,
      reminders: r.reminders || 0,
    })),
  };
}

module.exports = {
  TOKEN_BYTES,
  recipientEmailHash,
  normaliseForHash,
  EMAIL_HASH_EPHEMERAL,
  newPickupToken,
  tokenHash,
  buildRecipients,
  newSendSalt,
  findByToken,
  claimPickup,          // the one a route must use: look up and claim in one step
  claim,                // same, with a reason for the error message
  MAX_TOKEN_LEN,
  pickupRefusal,
  markPickedUp,
  revoke,
  reinvite,
  allSettled,
  overview,
};
