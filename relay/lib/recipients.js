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
// `sealed` is optional: a map of address -> { token, wrapped_key } prepared in
// the sender's browser.
//
// WHY THE BROWSER MAKES THOSE. The file is sealed with a key this relay never
// sees. In the ordinary one-link flow that key rides in the fragment of the URL,
// which a browser does not send to servers. A send to a group cannot do that,
// because we post the invitation and a fragment would travel through the mail
// regardless.
//
// So the browser wraps the file key under a key derived from each recipient's
// own token, and hands us only the wrapping. We keep the wrapping and the HASH
// of the token. The token itself passes through once, to be put in an email,
// and is never written down.
//
// The relay therefore holds a locked box and no key. The mail provider carries
// a key and has never seen the box. Neither half is enough on its own, and that
// is the whole point: it is why the token may not be stored here, not even for
// the length of a send.
//
// Returns { ok, reason, limit, records, tokens }. `tokens` maps the address to
// its one-time token, for the caller to mail and then forget: it cannot be
// recovered from `records`.
function buildRecipients(plan, list, now, sealed) {
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
  // No wrappings, no send. The fallback that used to sit here minted a relay
  // token with wrapped_key null, so every recipient got an invitation, spent
  // their one-time link, and read "this link cannot open it". Bytes nobody can
  // read are worse than no bytes at all, and an older frontend or a hand-rolled
  // API call is exactly how that happened.
  const meegeleverd = (sealed && typeof sealed === 'object') ? sealed : null;
  if (!meegeleverd) {
    return { ok: false, reason: 'missing_wrapped_key', limit: checked.limit,
             asked: checked.recipients.length, records: [], tokens: {} };
  }
  // One token may appear once. findByToken keeps the LAST match, so two
  // recipients on one token means the first is mailed a code that lands in the
  // second one's mailbox, is shown a stranger's masked address, and can never
  // collect -- while allSettled never turns true and the file sits out its TTL.
  const gezien = new Set();
  for (const email of checked.recipients) {
    let token, wrapped = null;
    {
      const paar = Object.prototype.hasOwnProperty.call(meegeleverd, email)
        ? meegeleverd[email] : null;
      // Every address must come with its own wrapping. One missing entry means
      // one person who can never open the file, and silently giving them a
      // relay-made token would hand them bytes they cannot read.
      // TOKEN_SHAPE is the alphabet the pickup route matches on. A token with a
      // dot or a percent passes a length check and then fails the route, so the
      // recipient meets "Invalid API key" on their own link and the sender sees
      // nothing wrong. The wrapping is base64url for the same reason: it rides
      // back as an HTTP header, and a stray CR there costs the recipient their
      // one collection with a 500.
      if (!paar || typeof paar.token !== 'string' || typeof paar.wrapped_key !== 'string'
          || !TOKEN_SHAPE.test(paar.token)
          || paar.token.length > MAX_TOKEN_LEN
          || !WRAP_SHAPE.test(paar.wrapped_key) || paar.wrapped_key.length > 4096) {
        return { ok: false, reason: 'missing_wrapped_key', limit: checked.limit,
                 asked: checked.recipients.length, records: [], tokens: {},
                 rejected: email };
      }
      if (gezien.has(paar.token)) {
        return { ok: false, reason: 'duplicate_token', limit: checked.limit,
                 asked: checked.recipients.length, records: [], tokens: {},
                 rejected: email };
      }
      gezien.add(paar.token);
      token = paar.token;
      wrapped = paar.wrapped_key;
    }
    tokens[email] = token;
    records.push({
      email,                              // for the sender's own overview
      email_hash: recipientEmailHash(email, salt),
      token_hash: tokenHash(token),
      // The file key, locked under this recipient's token. Useless here: we
      // keep only the hash of the token that opens it.
      wrapped_key: wrapped,
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
// The alphabet /v2/pickup/:token matches on, and the shape of a wrapping that
// can travel in a response header. Both are checked where the send is made, so
// a bad one is a refusal the sender reads rather than a dead link a recipient
// discovers.
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{32,128}$/;
// 60 tekens, niet 16. Een wikkeling is 12 bytes IV plus 44 bytes sleutel plus
// een 16-byte tag = 72 bytes, en base64url daarvan is 96 tekens. Zestien tekens
// is twaalf bytes: die haalt de ondergrens van unwrap niet eens, dus de
// ontvanger liep de hele reis, verbrandde zijn eenmalige link, en kreeg pas
// daarna te horen dat het niet ging. Weigeren hoort bij het aanmaken, waar de
// AFZENDER het nog kan oplossen.
const WRAP_SHAPE  = /^[A-Za-z0-9_-]{60,4096}$/;

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
// A REMINDER, and deliberately not a new link.
//
// This used to mint a fresh token, and that quietly destroyed the file for the
// person it was meant to help. The file key is wrapped under the recipient's
// OWN token (frontend/js/send-wrap.js); a new token cannot open the wrapping
// that is already in the store, and this relay has no way to make a new one,
// because it never holds the file key. So the recipient typed the right code,
// burned their one-time link, and read "this link cannot open it" -- with no
// way back, since the record then counted as collected.
//
// It cannot be fixed by keeping the token either: not writing the token down
// is the whole reason the relay cannot open what it stores. A relay that could
// re-send the link is a relay that could open the file.
//
// So a reminder points at the invitation the recipient already has. Their link
// is untouched and still works. If the mail is truly gone, the sender sends
// the file again, which is one action and keeps every promise intact.
function reinvite(record, now, records) {
  if (!record || typeof record !== 'object') return null;
  if (record.picked_up_at || record.revoked_at) return null;
  if (Array.isArray(records) && allSettled(records)) return null;
  record.reminders = (record.reminders || 0) + 1;
  record.reminded_at = now || Date.now();
  // invited_at stays: it is when the link they hold was sent, and the
  // dashboard uses it to say how long somebody has been waiting.
  return { ok: true, reminders: record.reminders, invited_at: record.invited_at };
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
