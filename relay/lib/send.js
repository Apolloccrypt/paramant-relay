'use strict';

// A send to named recipients, end to end.
//
// The ordinary transfer is one blob behind one link that burns on first read.
// That is right for a hand-over between two people and wrong for a document
// that has to reach a group: the sender never learns who actually collected it,
// and the first person to click takes it away from the rest.
//
// A send keeps ONE encrypted blob and hands every person their own pickup
// token. A token works exactly once. The blob is dropped when the last token is
// settled, or when the window closes, whichever comes first.
//
// WHY THIS IS A SEPARATE FILE. The existing transfer path keeps blobs in a Map
// in process memory, which is fine for five minutes and one reader. A send to
// thirty people can stand open for a week, so a restart would quietly destroy
// it. This layer writes through the durable store instead: encrypted at rest,
// with a TTL, in its own namespace.
//
// Everything here takes the store as an argument, so the whole flow is testable
// without starting a relay.

const crypto = require('crypto');
const recipients = require('./recipients');
const tiers = require('./tiers');

const ID_BYTES = 18;                    // 24 chars base64url
const MAX_TOKEN_LEN = recipients.MAX_TOKEN_LEN;

function newSendId() {
  return crypto.randomBytes(ID_BYTES).toString('base64url');
}

// ── proving the mailbox ──────────────────────────────────────────────────────
// A token proves that a link was used. It does not prove WHO used it, and that
// is the thing a sender is paying for: a forwarded mail or a mailbox somebody
// else reads looks exactly like the right person collecting.
//
// A full account would prove it, and would also mean twenty external partners
// registering before they can open one file. That is the friction that keeps
// people on the free consumer services, so it is not the answer either.
//
// The middle road, and the one the signing path already takes: a short code to
// the SAME address the invitation went to. No registration, one extra step of
// about ten seconds, and it turns "the link was used" into "somebody with
// access to that mailbox collected it".
//
// The code is stored hashed, expires quickly, and survives three wrong guesses.
const CODE_TTL_MS = 15 * 60 * 1000;
const CODE_TRIES = 3;
const CODE_DIGITS = 6;

function newCode() {
  // Uniform over the whole range: a modulo of a random byte would lean on the
  // low digits, and a six-digit space is small enough that it would show.
  let out = '';
  while (out.length < CODE_DIGITS) out += String(crypto.randomInt(0, 10));
  return out;
}

function codeHash(sendId, token, code) {
  return crypto.createHash('sha3-256')
    .update('paramant/pickup-code/v1\x00', 'utf8')
    .update(String(sendId), 'utf8').update('\x00', 'utf8')
    .update(recipients.tokenHash(token), 'utf8').update('\x00', 'utf8')
    .update(String(code || ''), 'utf8')
    .digest('hex');
}

function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

// anna@example.org -> a***a@example.org. Enough for the holder to recognise
// their own address, not enough to learn somebody else's from a stray link.
function maskEmail(email) {
  const s = String(email || '');
  const at = s.indexOf('@');
  if (at < 1) return '***';
  const local = s.slice(0, at);
  const domain = s.slice(at);
  if (local.length <= 2) return local[0] + '***' + domain;
  return local[0] + '***' + local[local.length - 1] + domain;
}

// The token index. A pickup arrives with a token and nothing else, so something
// has to map it to its send. Keyed on the HASH of the token: the index is as
// unreadable as the records are.
function tokenIndexId(token) {
  return 'tok-' + recipients.tokenHash(token);
}

// The account index. A sender's dashboard has to list what they sent, and a
// store that only answers by id cannot do that. Kept as a short list of ids per
// account, newest first, capped: a dashboard shows recent work, and an index
// that grows without end is a slow page and a memory leak in one.
const ACCOUNT_INDEX_MAX = 200;
// The index outlives the sends in it, so a sender can still see last week's
// delivery after the file and its recipient list are gone. Thirty days.
const ACCOUNT_INDEX_TTL_MS = 30 * 24 * 3600 * 1000;

function accountIndexId(accountId) {
  return 'acct-' + crypto.createHash('sha3-256')
    .update('paramant/send-account/v1\x00', 'utf8')
    .update(String(accountId || ''), 'utf8')
    .digest('hex');
}

function createSendStore({ store, log, now }) {
  if (!store) throw new Error('send: a store is required');
  const clock = typeof now === 'function' ? now : () => Date.now();

  async function readSend(id) {
    if (typeof id !== 'string' || !id) return null;
    const meta = await store.getMeta(id);
    return meta && Array.isArray(meta.records) ? meta : null;
  }

  async function writeSend(id, send, ttlMs) {
    await store.putMeta(id, send, ttlMs);
  }

  // How long this send may stand open: what the sender asked for, capped by the
  // plan. A group send that outlives its plan's window would be a quiet way to
  // buy a week of storage on a one-hour row.
  function windowFor(plan, wantedMs) {
    const ceiling = tiers.tierLimitNum(plan, 'view_ttl_ms');
    const asked = Number(wantedMs);
    const ms = Number.isFinite(asked) && asked > 0 ? asked : ceiling;
    return Math.max(1000, Math.min(ms, ceiling));
  }

  return {
    // Create a send. Returns { ok, id, tokens, expires_at, count } or a reason.
    //
    // `tokens` maps each address to its one-time token. The caller mails those
    // and then forgets them: they cannot be recovered from what is stored.
    async create({ plan, blob, addresses, ttlMs, filename, accountId }) {
      if (!Buffer.isBuffer(blob) || blob.length === 0) {
        return { ok: false, reason: 'no_blob' };
      }
      const built = recipients.buildRecipients(plan, addresses, clock());
      if (!built.ok) {
        return { ok: false, reason: built.reason, limit: built.limit,
                 asked: built.asked, rejected: built.rejected };
      }
      const id = newSendId();
      const ttl = windowFor(plan, ttlMs);
      const created = clock();
      const send = {
        id,
        account_id: accountId || null,
        plan: tiers.normalisePlan(plan),
        filename: String(filename || '').slice(0, 200),
        salt: built.salt,
        created_at: created,
        expires_at: created + ttl,
        size: blob.length,
        records: built.records,
      };

      // Blob first: an index entry pointing at a send whose file never landed
      // would be a link that 500s. If the blob write fails there is nothing to
      // clean up, because nothing else exists yet.
      await store.putBlob(id, blob, ttl);
      await writeSend(id, send, ttl);
      for (const token of Object.values(built.tokens)) {
        await store.putMeta(tokenIndexId(token), { send: id }, ttl);
      }
      // The account index outlives the send itself, so a sender can still see
      // last week's delivery after the file is gone. Ids only: everything that
      // could identify a recipient stays in the send, which expires on time.
      if (accountId) {
        const key = accountIndexId(accountId);
        const prev = (await store.getMeta(key)) || {};
        const ids = [id].concat(Array.isArray(prev.sends) ? prev.sends : [])
          .slice(0, ACCOUNT_INDEX_MAX);
        await store.putMeta(key, { sends: ids }, ACCOUNT_INDEX_TTL_MS);
      }
      if (log) log('info', 'send_created', { id, count: built.records.length, ttl_ms: ttl });
      return { ok: true, id, tokens: built.tokens, expires_at: send.expires_at,
               count: built.records.length };
    },

    // Step one of collecting: prove the mailbox.
    //
    // Deliberately does NOT claim the token. A code request must not burn a
    // link, or one stray click would cost somebody their only collection.
    //
    // Returns { ok, email, masked, code }. The code is for the caller to mail
    // and is never in an HTTP response: whoever asks for it must already be
    // able to read that mailbox.
    async requestPickup(token) {
      const found = await this._locate(token);
      if (!found.ok) return found;
      const { send, record } = found;

      const refusal = recipients.pickupRefusal(record);
      if (refusal) return { ok: false, reason: refusal };

      const code = newCode();
      record.code_hash = codeHash(send.id, token, code);
      record.code_expires_at = clock() + CODE_TTL_MS;
      record.code_tries = 0;
      await writeSend(send.id, send, Math.max(1000, send.expires_at - clock()));
      if (log) log('info', 'pickup_code_issued', { id: send.id });
      return { ok: true, email: record.email, masked: maskEmail(record.email),
               code, expires_in_s: Math.floor(CODE_TTL_MS / 1000) };
    },

    // Shared lookup for every token-bearing call.
    async _locate(token) {
      if (typeof token !== 'string' || !token || token.length > MAX_TOKEN_LEN) {
        return { ok: false, reason: 'unknown_token' };
      }
      const index = await store.getMeta(tokenIndexId(token));
      if (!index || !index.send) return { ok: false, reason: 'unknown_token' };
      const send = await readSend(index.send);
      if (!send) return { ok: false, reason: 'expired' };
      const record = recipients.findByToken(send.records, token);
      if (!record) return { ok: false, reason: 'unknown_token' };
      return { ok: true, send, record };
    },

    // Step two: the code, and then the file.
    //
    // Looking up and claiming stay one statement, because that is what keeps
    // two simultaneous clicks from both being served.
    //
    // Returns { ok, blob, filename, email, remaining } or { ok:false, reason }.
    async collect(token, code) {
      const found = await this._locate(token);
      if (!found.ok) return found;
      const { send, record } = found;

      const refusal = recipients.pickupRefusal(record);
      if (refusal) return { ok: false, reason: refusal };

      if (!record.code_hash) return { ok: false, reason: 'no_code_requested' };
      if (clock() > (record.code_expires_at || 0)) {
        return { ok: false, reason: 'code_expired' };
      }
      if ((record.code_tries || 0) >= CODE_TRIES) {
        return { ok: false, reason: 'too_many_tries' };
      }
      if (!sameHash(record.code_hash, codeHash(send.id, token, code))) {
        record.code_tries = (record.code_tries || 0) + 1;
        const left = CODE_TRIES - record.code_tries;
        await writeSend(send.id, send, Math.max(1000, send.expires_at - clock()));
        if (log) log('info', 'pickup_code_wrong', { id: send.id, tries_left: left });
        return { ok: false, reason: 'wrong_code', tries_left: Math.max(0, left) };
      }
      // The code is spent the moment it works, so a mailbox somebody else reads
      // later cannot replay it.
      record.code_hash = null;
      record.code_expires_at = null;

      const claimed = recipients.claimPickup(send.records, token, clock());
      if (!claimed) return { ok: false, reason: 'already_collected' };
      return this._serve(send, claimed);
    },

    // Hand over the bytes for a claim that has already been made. Only called
    // with a record that collect() just claimed, so there is nothing left to
    // decide here except whether the file is still there.
    async _serve(send, record) {
      const blob = await store.getBlob(send.id);
      if (!blob) {
        // The file is gone but the record says collected. Say so plainly rather
        // than pretend: the sender's overview must not show a collection that
        // never handed anything over.
        record.picked_up_at = null;
        await writeSend(send.id, send, Math.max(1000, send.expires_at - clock()));
        return { ok: false, reason: 'expired' };
      }

      const settled = recipients.allSettled(send.records);
      await writeSend(send.id, send, Math.max(1000, send.expires_at - clock()));
      if (settled) {
        // Everybody has been, so the file may go. The records stay until the
        // window closes, so the sender can still see who collected and when.
        await store.delBlob(send.id);
        if (log) log('info', 'send_drained', { id: send.id });
      }
      const view = recipients.overview(send.records);
      return { ok: true, blob, filename: send.filename, email: record.email,
               remaining: view.outstanding, settled };
    },

    // Everything this account sent, newest first, for the sender's dashboard.
    //
    // A send whose window has closed is gone from the store but still in the
    // index. It comes back as a row that says so rather than being dropped
    // silently: "I sent that last week and it expired" is information, and a
    // list that quietly shrinks looks like something went missing.
    async list(accountId, limit) {
      if (!accountId) return { ok: true, sends: [] };
      const index = await store.getMeta(accountIndexId(accountId));
      const ids = (index && Array.isArray(index.sends) ? index.sends : [])
        .slice(0, Math.max(1, Math.min(Number(limit) || 50, 200)));
      const sends = [];
      for (const id of ids) {
        const send = await readSend(id);
        if (!send) { sends.push({ id, status: 'expired' }); continue; }
        const view = recipients.overview(send.records);
        sends.push({
          id: send.id,
          filename: send.filename,
          created_at: send.created_at,
          expires_at: send.expires_at,
          size: send.size,
          status: view.outstanding === 0 ? 'done' : 'open',
          total: view.total,
          collected: view.collected,
          outstanding: view.outstanding,
          revoked: view.revoked,
        });
      }
      return { ok: true, sends };
    },

    // Does this send belong to this account?
    //
    // Kept out of overview() on purpose: the owner is not part of what a sender
    // looks at, and a field that travels to a browser is a field that can end up
    // somewhere else. Every route that touches a send by id asks this first, and
    // answers a stranger the same way it answers an id that never existed.
    async ownedBy(id, accountId) {
      if (!accountId) return false;
      const send = await readSend(id);
      return Boolean(send && send.account_id && send.account_id === accountId);
    },

    // What the sender sees. Never tokens, never hashes.
    async overview(id) {
      const send = await readSend(id);
      if (!send) return { ok: false, reason: 'unknown_send' };
      const view = recipients.overview(send.records);
      return { ok: true, id: send.id, filename: send.filename,
               created_at: send.created_at, expires_at: send.expires_at,
               size: send.size, ...view };
    },

    // Withdraw one person without touching the rest.
    async revoke(id, email) {
      const send = await readSend(id);
      if (!send) return { ok: false, reason: 'unknown_send' };
      const want = String(email || '').trim().toLowerCase();
      const record = send.records.find(r => r && r.email === want);
      if (!record) return { ok: false, reason: 'unknown_recipient' };
      if (!recipients.revoke(record, clock())) {
        return { ok: false, reason: record.picked_up_at ? 'already_collected' : 'revoked' };
      }
      const settled = recipients.allSettled(send.records);
      await writeSend(id, send, Math.max(1000, send.expires_at - clock()));
      if (settled) await store.delBlob(id);
      return { ok: true, settled };
    },

    // Send somebody a fresh link. The old one dies at that moment.
    async reinvite(id, email) {
      const send = await readSend(id);
      if (!send) return { ok: false, reason: 'unknown_send' };
      const want = String(email || '').trim().toLowerCase();
      const record = send.records.find(r => r && r.email === want);
      if (!record) return { ok: false, reason: 'unknown_recipient' };
      const token = recipients.reinvite(record, clock(), send.records);
      if (!token) {
        return { ok: false,
                 reason: record.picked_up_at ? 'already_collected'
                       : record.revoked_at ? 'revoked' : 'finished' };
      }
      const left = Math.max(1000, send.expires_at - clock());
      await writeSend(id, send, left);
      await store.putMeta(tokenIndexId(token), { send: id }, left);
      return { ok: true, token, email: record.email };
    },
  };
}

module.exports = { createSendStore, newSendId, tokenIndexId, accountIndexId,
                   maskEmail, CODE_TTL_MS, CODE_TRIES, CODE_DIGITS };
