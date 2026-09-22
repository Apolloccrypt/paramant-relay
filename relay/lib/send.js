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
// How often the sender may nudge one recipient. Each reminder is a mail to
// somebody who never signed up with us, so this is a courtesy ceiling as much
// as an abuse one.
const MAX_REMINDERS = 3;

// HOW BIG A SEND TO NAMED RECIPIENTS MAY BE, and this number is measured, not
// chosen for how it sounds.
//
// The ordinary flows never hold a whole file anywhere: a live hand-over streams
// through RAM three blocks at a time, and a one-link send is one sealed 5 MB
// block. That is why /pricing can honestly sell "500 MB handed over live, 5 MB
// over a link" while every tier stores transfers in RAM.
//
// A send to a group breaks that shape. Nobody is waiting at the other end, so
// the whole file sits in the durable store until the last recipient collects or
// the window closes -- up to seven days on Business. And parasign-store.js
// seals with `.toString('base64')`, so it occupies a THIRD more than its own
// size, in a Redis container limited to 256 MB that also carries sessions, rate
// limits and every ParaSign envelope.
//
//   256 MB  the container
//  - 56 MB  Redis itself, the AOF buffer, sessions, rate limits, ParaSign
//  = 200 MB for sends, AFTER base64
//  = 150 MB of real bytes, shared by every open send at once
//
// At 25 MB that is six sends open together. Bigger numbers are not generosity:
// one 150 MB send would fill the store and the next customer's signature would
// fail to write. Raise it only together with the Redis budget.
const SEND_MAX_MB = (() => {
  const n = parseInt(process.env.SEND_MAX_MB || '25', 10);
  return Number.isFinite(n) && n > 0 ? n : 25;
})();
const SEND_MAX_BYTES = SEND_MAX_MB * 1048576;

// The two ceilings that survive a new code.
//
// code_tries is per code and resets with every fresh one, which is right for
// the "2 tries left" line a recipient reads. On its own it was no lock at all:
// asking for a new code put it back to zero, so three guesses per round times
// as many rounds as you like. And every round mailed the recipient again, so
// one link was also an unmetered way to fill a stranger's mailbox from
// paramant.app.
//
// These two count over the life of the link and nothing resets them.
const MAX_CODE_REQUESTS = 5;
const MAX_WRONG_TOTAL = 9;
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

  // ── one send, one queue ────────────────────────────────────────────────────
  //
  // WHY THIS EXISTS. The durable store serialises: putMeta stringifies and
  // getMeta parses, so every read hands back a FRESH COPY. Every method here
  // reads, changes and writes the whole send back, with an await in between.
  //
  // That makes read-modify-write the shape of all of it, and an audit on 22-09
  // showed what that costs: two clicks on the same one-time link both got the
  // file, a wrong code guess rolled back a collection that had already
  // happened, and a withdrawal was quietly undone by a pickup that overlapped
  // it -- while the sender had been told the person was locked out.
  //
  // The comment on claimPickup said Node "runs this without interleaving". True
  // for an array in memory. Not true the moment the records travel through a
  // store, because the await between read and write is exactly where the other
  // request gets its turn.
  //
  // So every change to one send queues behind the previous change to that same
  // send. Different sends still run side by side. This is correct for one relay
  // process; across processes it needs a revision field and a compare-and-set
  // in the store, and that is written down in the deploy notes rather than
  // pretended away here.
  const ketens = new Map();
  function opVolgorde(id, werk) {
    const vorige = ketens.get(id) || Promise.resolve();
    const nu = vorige.then(werk, werk);
    // `stil` is the chain the NEXT caller waits on, and it can never reject:
    // one failed pickup must not break the send for everybody behind it.
    //
    // Everything that hangs off the queue hangs off `stil`, never off `nu`.
    // A `.finally()` on `nu` returns a DERIVED promise that inherits the
    // rejection and has no handler of its own, and this process turns an
    // unhandled rejection into emergencyZeroAndExit: one Redis hiccup during
    // one recipient's pickup would zero every other customer's blobs and stop
    // the relay. The caller catching its own error does not save it, because
    // the derived promise is a second, separate one.
    const stil = nu.then(() => {}, () => {});
    ketens.set(id, stil);
    // Drop the entry only while it is still the tail. The old rule looked at
    // the size of the whole map, so under the very load it was built for it
    // deleted a chain that had work queued behind it, and two changes to one
    // send ran side by side again.
    stil.then(() => { if (ketens.get(id) === stil) ketens.delete(id); });
    return nu;
  }

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
    async create({ plan, blob, addresses, ttlMs, filename, accountId, sealed, sender }) {
      if (!Buffer.isBuffer(blob) || blob.length === 0) {
        return { ok: false, reason: 'no_blob' };
      }
      const built = recipients.buildRecipients(plan, addresses, clock(), sealed);
      if (!built.ok) {
        return { ok: false, reason: built.reason, limit: built.limit,
                 asked: built.asked, rejected: built.rejected };
      }
      const id = newSendId();
      const ttl = windowFor(plan, ttlMs);
      const created = clock();
      // The ceiling belongs to the layer that writes the bytes down, not only
      // to the route that happens to call it today. A second caller, or a
      // route that grows an extra branch, would otherwise bring the unbounded
      // path straight back.
      const _plan = tiers.normalisePlan(plan);
      const _planMb = tiers.tierLimitNum(_plan, 'file_mb');
      // The strictest of the two wins. file_mb is what the plan sells;
      // SEND_MAX_MB is what the store can hold for days on end without taking
      // somebody else's signature down with it.
      const _mb = Math.min(Number.isFinite(_planMb) ? _planMb : Infinity, SEND_MAX_MB);
      if (Number.isFinite(_mb) && blob.length > _mb * 1048576) {
        return { ok: false, reason: 'too_large', limit: _mb, asked: blob.length,
                 dimension: _mb === SEND_MAX_MB ? 'send_max_mb' : 'file_mb' };
      }

      const send = {
        id,
        account_id: accountId || null,
        plan: _plan,
        filename: String(filename || '').slice(0, 200),
        // WHO IT IS FROM, and it has to live here rather than be looked up.
        // The code mail and the reminder go out on a route that carries no API
        // key: the recipient has a link and nothing else, so there is no key
        // record to read a name off. Without this the second mail arrives from
        // a faceless address while the first one had a name, which is exactly
        // the shape that gets a message quarantined.
        sender_name: String((sender && sender.naam) || '').slice(0, 60),
        sender_email: String((sender && sender.email) || '').slice(0, 254),
        salt: built.salt,
        created_at: created,
        expires_at: created + ttl,
        size: blob.length,
        records: built.records,
      };

      // The token index is ONE key space across every account, and the tokens
      // come out of the sender's browser. Without this check a second account
      // could put a token it had seen once -- a forwarded invitation, a line in
      // a proxy log -- into its own `sealed` and take over the row, so the
      // first sender's recipient is handed somebody else's send while the
      // dashboard still says "waiting".
      //
      // Claimed BEFORE the blob, because a refusal here must leave nothing
      // behind at all.
      const geclaimd = [];
      for (const token of Object.values(built.tokens)) {
        const sleutel = tokenIndexId(token);
        const bezet = await store.getMeta(sleutel);
        if (bezet && bezet.send && bezet.send !== id) {
          for (const k of geclaimd) { try { await store.delMeta(k); } catch (e) {} }
          if (log) log('warn', 'send_token_taken', { id });
          return { ok: false, reason: 'token_taken' };
        }
        await store.putMeta(sleutel, { send: id }, ttl);
        geclaimd.push(sleutel);
      }

      // From here on every failure has to undo what came before it. A half
      // written send used to leave the file in the store under an id nobody
      // knew, for as long as a week, and the sender got a 500 that said
      // nothing about it.
      try {
        await store.putBlob(id, blob, ttl);
        await writeSend(id, send, ttl);
      } catch (err) {
        try { await store.delBlob(id); } catch (e) {}
        for (const k of geclaimd) { try { await store.delMeta(k); } catch (e) {} }
        if (log) log('error', 'send_create_rolled_back', { id, err: err && err.message });
        throw err;
      }

      // The account index outlives the send itself, so a sender can still see
      // last week's delivery after the file is gone. Ids only: everything that
      // could identify a recipient stays in the send, which expires on time.
      //
      // Queued on the ACCOUNT, because this is read-modify-write on one key
      // shared by every send that account makes. Two sends started together
      // both read the old list and the second write dropped the first: that
      // send then existed, held its file and its tokens, and was invisible on
      // the dashboard and impossible to withdraw.
      if (accountId) {
        const key = accountIndexId(accountId);
        await opVolgorde('acct:' + accountId, async () => {
          const prev = (await store.getMeta(key)) || {};
          const ids = [id].concat(Array.isArray(prev.sends) ? prev.sends : [])
            .slice(0, ACCOUNT_INDEX_MAX);
          await store.putMeta(key, { sends: ids }, ACCOUNT_INDEX_TTL_MS);
        });
      }
      if (log) log('info', 'send_created', { id, count: built.records.length, ttl_ms: ttl });
      return { ok: true, id, tokens: built.tokens, expires_at: send.expires_at,
               count: built.records.length };
    },

    // The public entry points. Each one queues behind the previous change to
    // the same send, so a pickup cannot land between another request's read and
    // its write. See opVolgorde above for why that matters.
    async requestPickup(token) {
      const g = await this._zoekSend(token);
      if (!g.ok) return g;
      return opVolgorde(g.id, () => this._requestPickup(token));
    },

    async collect(token, code) {
      const g = await this._zoekSend(token);
      if (!g.ok) return g;
      return opVolgorde(g.id, () => this._collect(token, code));
    },

    async revoke(id, email) {
      return opVolgorde(String(id || ''), () => this._revoke(id, email));
    },

    async reinvite(id, email) {
      return opVolgorde(String(id || ''), () => this._reinvite(id, email));
    },

    // Which send a token belongs to, without touching it. Only used to pick the
    // right queue; every real decision happens inside it.
    async _zoekSend(token) {
      if (typeof token !== 'string' || !token || token.length > MAX_TOKEN_LEN) {
        return { ok: false, reason: 'unknown_token' };
      }
      const index = await store.getMeta(tokenIndexId(token));
      if (!index || !index.send) return { ok: false, reason: 'unknown_token' };
      return { ok: true, id: index.send };
    },

    // Step one of collecting: prove the mailbox.
    //
    // Deliberately does NOT claim the token. A code request must not burn a
    // link, or one stray click would cost somebody their only collection.
    //
    // Returns { ok, email, masked, code }. The code is for the caller to mail
    // and is never in an HTTP response: whoever asks for it must already be
    // able to read that mailbox.
    async _requestPickup(token) {
      const found = await this._locate(token);
      if (!found.ok) return found;
      const { send, record } = found;

      const refusal = recipients.pickupRefusal(record);
      if (refusal) return { ok: false, reason: refusal };

      // Counted before the code is minted, so the ceiling holds even when the
      // mail later fails. Both of these are what stops the reset-and-retry.
      if ((record.code_requests || 0) >= MAX_CODE_REQUESTS) {
        if (log) log('warn', 'pickup_code_capped', { id: send.id, dimension: 'requests' });
        return { ok: false, reason: 'too_many_codes', limit: MAX_CODE_REQUESTS };
      }
      if ((record.wrong_total || 0) >= MAX_WRONG_TOTAL) {
        if (log) log('warn', 'pickup_code_capped', { id: send.id, dimension: 'wrong' });
        return { ok: false, reason: 'too_many_tries' };
      }
      record.code_requests = (record.code_requests || 0) + 1;

      const code = newCode();
      record.code_hash = codeHash(send.id, token, code);
      record.code_expires_at = clock() + CODE_TTL_MS;
      record.code_tries = 0;
      await writeSend(send.id, send, Math.max(1000, send.expires_at - clock()));
      if (log) log('info', 'pickup_code_issued', { id: send.id });
      return { ok: true, email: record.email, masked: maskEmail(record.email),
               code, expires_in_s: Math.floor(CODE_TTL_MS / 1000),
               sender_name: send.sender_name || '', sender_email: send.sender_email || '',
               filename: send.filename || '' };
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
    async _collect(token, code) {
      const found = await this._locate(token);
      if (!found.ok) return found;
      const { send, record } = found;

      const refusal = recipients.pickupRefusal(record);
      if (refusal) return { ok: false, reason: refusal };

      if (!record.code_hash) return { ok: false, reason: 'no_code_requested' };
      if (clock() > (record.code_expires_at || 0)) {
        return { ok: false, reason: 'code_expired' };
      }
      if ((record.code_tries || 0) >= CODE_TRIES
          || (record.wrong_total || 0) >= MAX_WRONG_TOTAL) {
        return { ok: false, reason: 'too_many_tries' };
      }
      if (!sameHash(record.code_hash, codeHash(send.id, token, code))) {
        record.code_tries = (record.code_tries || 0) + 1;
        record.wrong_total = (record.wrong_total || 0) + 1;
        const left = Math.min(CODE_TRIES - record.code_tries,
                              MAX_WRONG_TOTAL - record.wrong_total);
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
               // The file key, locked under this recipient's own token. Useless
               // to us and to anyone who takes it from us; only the holder of
               // the token can open it, and that token was never written down.
               wrapped_key: record.wrapped_key || null,
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
    async _revoke(id, email) {
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
    async _reinvite(id, email) {
      const send = await readSend(id);
      if (!send) return { ok: false, reason: 'unknown_send' };
      const want = String(email || '').trim().toLowerCase();
      const record = send.records.find(r => r && r.email === want);
      if (!record) return { ok: false, reason: 'unknown_recipient' };
      const uit = recipients.reinvite(record, clock(), send.records);
      if (!uit) {
        return { ok: false,
                 reason: record.picked_up_at ? 'already_collected'
                       : record.revoked_at ? 'revoked' : 'finished' };
      }
      // A ceiling, because every reminder is a mail to somebody who is not our
      // customer. Without one, the dashboard button is an unmetered way to
      // mail a third party from paramant.app.
      if (uit.reminders > MAX_REMINDERS) {
        record.reminders = MAX_REMINDERS;
        return { ok: false, reason: 'reminder_limit', limit: MAX_REMINDERS };
      }
      // No new token, so no new index row either: their link is unchanged and
      // still the only one. That is what makes this a reminder instead of a
      // replacement -- see the note on recipients.reinvite.
      await writeSend(id, send, Math.max(1000, send.expires_at - clock()));
      return { ok: true, email: record.email, reminders: uit.reminders,
               invited_at: uit.invited_at, expires_at: send.expires_at,
               sender_name: send.sender_name || '', sender_email: send.sender_email || '',
               filename: send.filename || '' };
    },
  };
}

module.exports = { createSendStore, newSendId, tokenIndexId, accountIndexId,
                   maskEmail, CODE_TTL_MS, CODE_TRIES, CODE_DIGITS, MAX_REMINDERS, MAX_CODE_REQUESTS, MAX_WRONG_TOTAL,
                   SEND_MAX_MB, SEND_MAX_BYTES };
