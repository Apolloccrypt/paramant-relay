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

// The token index. A pickup arrives with a token and nothing else, so something
// has to map it to its send. Keyed on the HASH of the token: the index is as
// unreadable as the records are.
function tokenIndexId(token) {
  return 'tok-' + recipients.tokenHash(token);
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
      if (log) log('info', 'send_created', { id, count: built.records.length, ttl_ms: ttl });
      return { ok: true, id, tokens: built.tokens, expires_at: send.expires_at,
               count: built.records.length };
    },

    // Collect with a token. One call: looking up and claiming in two steps is
    // how two simultaneous clicks both got the file.
    //
    // Returns { ok, blob, filename, email, remaining } or { ok:false, reason }.
    async pickup(token) {
      if (typeof token !== 'string' || !token || token.length > MAX_TOKEN_LEN) {
        return { ok: false, reason: 'unknown_token' };
      }
      const index = await store.getMeta(tokenIndexId(token));
      if (!index || !index.send) return { ok: false, reason: 'unknown_token' };
      const send = await readSend(index.send);
      if (!send) return { ok: false, reason: 'expired' };

      const record = recipients.claimPickup(send.records, token, clock());
      if (!record) {
        const why = recipients.pickupRefusal(
          recipients.findByToken(send.records, token));
        return { ok: false, reason: why || 'unknown_token' };
      }

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

module.exports = { createSendStore, newSendId, tokenIndexId };
