'use strict';

// Stukken opvragen: an office asks a client for documents, and the client sends
// them from a phone without an account.
//
// WHAT THE RELAY HOLDS, AND WHAT IT CANNOT DO WITH IT.
//
// The office browser makes a fresh hybrid key pair for every request (ML-KEM-768
// and ECDH P-256, the same pair the live hand-over uses). The public half goes
// into the request. The private half is locked in that same browser under the
// office's own vault key (opvragen-kluis.js) and only that locked box comes
// here. The client's phone encrypts every file to the public half with the same
// encrypt_blob the rest of the product uses (crypto-wasm), so what arrives here
// is ciphertext for a key the relay never had.
//
//   relay          the request, the public key, a locked private key, and
//                  ciphertext; no key that opens any of it
//   mail provider  a reminder link at most; never a file, never a key
//
// THE PUBLIC KEY CANNOT BE SWAPPED UNSEEN. The office browser hashes the whole
// request as the client will see it (office name, greeting, the documents, the
// end date and both public keys) and puts that hash in the link's #fragment,
// which a browser never sends to a server. The client's page recomputes it from
// what this relay hands out and refuses on any difference. A relay that slipped
// in its own key would have to find a second request with the same SHA-256.
// That is why this file stores the descriptor exactly as the browser wrote it
// and refuses, rather than tidies, anything that is not already clean: a
// trimmed space would break the hash and leave a client with a link that
// refuses for no reason it can see.
//
// What the relay does see, and the privacy notes have to say so: the name and
// optional address of the client as the office typed them, the labels of the
// documents asked for, when each file arrived and how big it is (rounded up to
// 64 KiB by the phone). File names and contents travel inside the ciphertext.
//
// Everything here takes the store as an argument, like send.js, so the whole
// flow runs in a unit test without a relay.

const crypto = require('crypto');
const tiers = require('./tiers');

const ID_RE = /^[A-Za-z0-9_-]{24}$/;          // 18 random bytes, made by the office browser
const KLUIS_ID_RE = /^[A-Za-z0-9_-]{22}$/;    // 16 random bytes
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const KEM_PUB_BYTES = 1184;                    // ML-KEM-768 encapsulation key
const ECDH_PUB_BYTES = 65;                     // P-256, uncompressed

// One file is one wire packet of encrypt_blob, and that is padded to 5 MiB at
// most. The phone strips the random padding down to the next 64 KiB, so a
// passport photo of 1.2 MB costs 1.2 MB of the client's data plan instead of 5.
const FILE_MAX_BYTES = 5 * 1048576;
// The smallest packet encrypt_blob can make: magic, the ML-KEM ciphertext, the
// ephemeral ECDH key, nonce, length and tag around an empty file.
const FILE_MIN_BYTES = 1 + 4 + 1088 + 4 + 65 + 12 + 4 + 16;
const WIRE_MAGIC = 0x03;
// A passport has two sides, a payslip sometimes two pages. Three per document is
// what a person needs; more is what somebody filling the store needs.
const FILES_PER_ITEM = 3;

const LABEL_MAX = 60;
const NAME_MAX = 80;
const GREET_MAX = 40;
const OFFICE_MAX = 120;
const SK_WRAPPED_MAX = 8192;                   // base64url chars; the real box is about 3.3 KB

const TTL_MIN_MS = 3600_000;
// The office browser sets the end date, so its clock and ours differ a little.
const CLOCK_SLACK_MS = 10 * 60_000;

// A reminder is a mail to somebody who is not our customer. Three per request,
// and not two within the same hour: a double click is not a second reminder.
const MAX_REMINDERS = 3;
const REMINDER_GAP_MS = 3600_000;

// The vault records (opvragen-kluis.js). One per browser that made a request
// without a passkey to carry its key elsewhere, with a few passkey wraps each.
const KLUIS_MAX = 10;
const WRAPS_MAX = 10;
const KLUIS_TTL_MS = 400 * 86400_000;

const INDEX_MAX = 500;

function newId() { return crypto.randomBytes(18).toString('base64url'); }

function b64urlLen(s) {
  if (typeof s !== 'string' || !B64URL_RE.test(s) || s.length % 4 === 1) return -1;
  return Buffer.from(s, 'base64url').length;
}

// Clean text, or null. Clean means: already trimmed, already NFC, no control
// characters, within the length. We never repair it, see the header.
function cleanText(v, max, allowEmpty) {
  if (typeof v !== 'string') return null;
  if (!allowEmpty && v.length === 0) return null;
  if (v.length > max) return null;
  if (v !== v.trim()) return null;
  if (v.normalize('NFC') !== v) return null;
  if (/[\x00-\x1f\x7f\u2028\u2029<>]/.test(v)) return null;
  return v;
}

function accountIndexId(accountId) {
  return 'acct-' + crypto.createHash('sha3-256')
    .update('paramant/opvraag-account/v1\x00', 'utf8')
    .update(String(accountId || ''), 'utf8').digest('hex');
}
function kluisIndexId(accountId) {
  return 'kluis-' + crypto.createHash('sha3-256')
    .update('paramant/opvraag-kluis/v1\x00', 'utf8')
    .update(String(accountId || ''), 'utf8').digest('hex');
}
function reqKey(id) { return 'req-' + id; }
function blobKey(id, n) { return id + '.' + n; }
function budgetId(id, n) { return 'opvr:' + id + '.' + n; }

function limitsFor(plan) {
  const p = tiers.normalisePlan(plan);
  const mb = tiers.tierLimitNum(p, 'opvraag_mb');
  return {
    plan: p,
    open: tiers.tierLimitNum(p, 'opvraag_open'),
    items: tiers.tierLimitNum(p, 'opvraag_items'),
    bytes: Number.isFinite(mb) ? mb * 1048576 : Infinity,
    ttl_ms: tiers.tierLimitNum(p, 'opvraag_ttl_ms'),
    file_max_bytes: FILE_MAX_BYTES,
    files_per_item: FILES_PER_ITEM,
  };
}

// The request as the client sees it, and as the hash in the link covers it.
// Checked field by field; anything extra is refused, not ignored, so the
// browser and the relay can never disagree about what was hashed.
function checkDescriptor(d, { plan, office, now }) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return { ok: false, reason: 'bad_descriptor' };
  const keys = Object.keys(d).sort().join(',');
  if (keys !== 'ecdh_pub,expires_at,greet,id,items,kem_pub,office,v') return { ok: false, reason: 'bad_descriptor' };
  if (d.v !== 1) return { ok: false, reason: 'bad_version' };
  if (typeof d.id !== 'string' || !ID_RE.test(d.id)) return { ok: false, reason: 'bad_id' };
  if (cleanText(d.office, OFFICE_MAX, false) === null || d.office !== office) return { ok: false, reason: 'office_changed' };
  if (cleanText(d.greet, GREET_MAX, true) === null) return { ok: false, reason: 'bad_greet' };
  const lim = limitsFor(plan);
  if (!Array.isArray(d.items) || d.items.length < 1) return { ok: false, reason: 'no_items' };
  if (d.items.length > lim.items) return { ok: false, reason: 'too_many_items', limit: lim.items };
  const seen = new Set();
  for (const it of d.items) {
    if (cleanText(it, LABEL_MAX, false) === null) return { ok: false, reason: 'bad_item' };
    const k = it.toLowerCase();
    if (seen.has(k)) return { ok: false, reason: 'duplicate_item' };
    seen.add(k);
  }
  if (!Number.isSafeInteger(d.expires_at)) return { ok: false, reason: 'bad_expiry' };
  if (d.expires_at < now + TTL_MIN_MS - CLOCK_SLACK_MS) return { ok: false, reason: 'too_short' };
  if (d.expires_at > now + lim.ttl_ms + CLOCK_SLACK_MS) return { ok: false, reason: 'too_long', limit_ms: lim.ttl_ms };
  if (b64urlLen(d.kem_pub) !== KEM_PUB_BYTES) return { ok: false, reason: 'bad_kem_pub' };
  if (b64urlLen(d.ecdh_pub) !== ECDH_PUB_BYTES || Buffer.from(d.ecdh_pub, 'base64url')[0] !== 0x04) {
    return { ok: false, reason: 'bad_ecdh_pub' };
  }
  return { ok: true, descriptor: { v: 1, id: d.id, office: d.office, greet: d.greet, items: d.items.slice(),
    expires_at: d.expires_at, kem_pub: d.kem_pub, ecdh_pub: d.ecdh_pub } };
}

function normaliseEmail(raw) {
  if (raw == null || raw === '') return '';
  return tiers.normaliseAddress(raw);
}

function createOpvraagStore({ store, budget, log, now }) {
  if (!store) throw new Error('opvraag: a store is required');
  const clock = typeof now === 'function' ? now : () => Date.now();
  // Without a ledger (a unit test that does not care) every upload fits.
  const ledger = budget || { reserve: async () => ({ ok: true }), release: async () => {} };

  // One queue per request and per account, for the reason send.js spells out:
  // the store hands back copies, so every change is read, modify, write.
  const ketens = new Map();
  function opVolgorde(id, werk) {
    const vorige = ketens.get(id) || Promise.resolve();
    const nu = vorige.then(werk, werk);
    const stil = nu.then(() => {}, () => {});
    ketens.set(id, stil);
    stil.then(() => { if (ketens.get(id) === stil) ketens.delete(id); });
    return nu;
  }

  async function read(id) {
    if (typeof id !== 'string' || !ID_RE.test(id)) return null;
    const r = await store.getMeta(reqKey(id));
    if (!r || !r.descriptor) return null;
    if (clock() >= r.expires_at) return null;
    return r;
  }
  async function write(r) {
    await store.putMeta(reqKey(r.id), r, Math.max(1000, r.expires_at - clock()));
  }
  async function owned(id, accountId) {
    const r = await read(id);
    return r && accountId && r.account_id === accountId ? r : null;
  }

  async function indexIds(accountId) {
    const idx = await store.getMeta(accountIndexId(accountId));
    return idx && Array.isArray(idx.ids) ? idx.ids : [];
  }

  function itemView(r) {
    return r.descriptor.items.map((label, i) => {
      const files = r.files.filter((f) => f.item === i);
      return { label, count: files.length, last_at: files.length ? files[files.length - 1].at : null,
               size: files.reduce((s, f) => s + f.size, 0) };
    });
  }

  function summary(r) {
    const items = itemView(r);
    const received = items.filter((x) => x.count > 0).length;
    return {
      id: r.id, client_name: r.client_name, has_email: !!r.client_email,
      created_at: r.created_at, expires_at: r.expires_at, closed: !!r.closed_at,
      state: r.closed_at ? 'closed' : (received === items.length ? 'complete' : 'open'),
      items, received, total: items.length, files: r.files.length,
      reminders: r.reminders || 0, max_reminders: MAX_REMINDERS, kluis_id: r.kluis_id,
    };
  }

  async function kluisList(accountId) {
    const k = await store.getMeta(kluisIndexId(accountId));
    return k && Array.isArray(k.kluizen) ? k.kluizen : [];
  }

  async function openCount(accountId) {
    let n = 0;
    for (const id of await indexIds(accountId)) {
      const r = await read(id);
      if (r && !r.closed_at) n++;
    }
    return n;
  }

  return {
    limitsFor,

    async info(accountId, plan) {
      return { limits: limitsFor(plan), open: accountId ? await openCount(accountId) : 0 };
    },

    // Make a request. The office browser chose the id, made the keys and the
    // hash; we check its shape, the plan and that the id is free.
    async create({ accountId, plan, office, descriptor, clientName, clientEmail, lang, skWrapped, kluisId }) {
      if (!accountId) return { ok: false, reason: 'no_account' };
      const t = clock();
      const chk = checkDescriptor(descriptor, { plan, office, now: t });
      if (!chk.ok) return chk;
      const name = cleanText(clientName, NAME_MAX, false);
      if (name === null) return { ok: false, reason: 'bad_client_name' };
      const email = normaliseEmail(clientEmail);
      if (email === null) return { ok: false, reason: 'bad_client_email' };
      if (typeof skWrapped !== 'string' || !skWrapped || skWrapped.length > SK_WRAPPED_MAX || b64urlLen(skWrapped) < 64) {
        return { ok: false, reason: 'bad_sk_wrapped' };
      }
      if (typeof kluisId !== 'string' || !KLUIS_ID_RE.test(kluisId)) return { ok: false, reason: 'bad_kluis' };
      const lim = limitsFor(plan);
      const d = chk.descriptor;
      return opVolgorde('acct:' + accountId, async () => {
        if ((await openCount(accountId)) >= lim.open) return { ok: false, reason: 'too_many_open', limit: lim.open };
        // The id is one key space across every account. Taken, whoever holds it,
        // is a refusal: the browser makes a new one.
        const ttl = d.expires_at - t;
        const claimed = typeof store.claimMeta === 'function'
          ? await store.claimMeta(reqKey(d.id), { claim: 1 }, ttl)
          : !(await store.getMeta(reqKey(d.id)));
        if (!claimed) return { ok: false, reason: 'id_taken' };
        const r = {
          v: 1, id: d.id, account_id: accountId, plan: lim.plan, kluis_id: kluisId,
          created_at: t, expires_at: d.expires_at, closed_at: null,
          descriptor: d, client_name: name, client_email: email,
          lang: lang === 'en' ? 'en' : 'nl', sk_wrapped: skWrapped,
          files: [], next: 0, bytes: 0, reminders: 0, reminded_at: 0,
        };
        await write(r);
        const ids = [d.id].concat((await indexIds(accountId)).filter((x) => x !== d.id)).slice(0, INDEX_MAX);
        await store.putMeta(accountIndexId(accountId), { ids }, 31 * 86400_000);
        if (log) log('info', 'opvraag_created', { id: d.id.slice(0, 6), items: d.items.length, ttl_h: Math.round(ttl / 3600_000) });
        return { ok: true, id: d.id, expires_at: d.expires_at };
      });
    },

    // What the client's phone may read: the descriptor, and per document how
    // many files are already in, so a client who comes back sees what is done.
    async publicView(id) {
      const r = await read(id);
      if (!r) return { ok: false, reason: 'unknown' };
      if (r.closed_at) return { ok: false, reason: 'closed', office: r.descriptor.office };
      const lim = limitsFor(r.plan);
      return {
        ok: true, descriptor: r.descriptor,
        received: itemView(r).map((x) => x.count),
        file_max_bytes: FILE_MAX_BYTES, files_per_item: FILES_PER_ITEM,
        bytes_left: Math.max(0, lim.bytes - r.bytes),
      };
    },

    // One encrypted file for one document. The bytes are opaque; what we check
    // is that they could be a packet at all and that they fit.
    async upload(id, item, buf) {
      if (!Buffer.isBuffer(buf)) return { ok: false, reason: 'no_file' };
      return opVolgorde(id, async () => {
        const r = await read(id);
        if (!r) return { ok: false, reason: 'unknown' };
        if (r.closed_at) return { ok: false, reason: 'closed' };
        const i = Number(item);
        if (!Number.isInteger(i) || i < 0 || i >= r.descriptor.items.length) return { ok: false, reason: 'bad_item' };
        if (buf.length < FILE_MIN_BYTES || buf[0] !== WIRE_MAGIC) return { ok: false, reason: 'not_encrypted' };
        if (buf.length > FILE_MAX_BYTES) return { ok: false, reason: 'too_large', limit: FILE_MAX_BYTES };
        if (r.files.filter((f) => f.item === i).length >= FILES_PER_ITEM) {
          return { ok: false, reason: 'item_full', limit: FILES_PER_ITEM };
        }
        const lim = limitsFor(r.plan);
        if (r.bytes + buf.length > lim.bytes) return { ok: false, reason: 'request_full', limit: lim.bytes };
        const n = r.next;
        const room = await ledger.reserve(budgetId(id, n), buf.length, r.expires_at, r.account_id, r.plan === 'community');
        if (!room.ok) return { ok: false, reason: room.account ? 'account_store_full' : 'store_full' };
        try {
          await store.putBlob(blobKey(id, n), buf, Math.max(1000, r.expires_at - clock()));
          r.files.push({ n, item: i, size: buf.length, at: clock() });
          r.next = n + 1;
          r.bytes += buf.length;
          await write(r);
        } catch (err) {
          await ledger.release(budgetId(id, n));
          try { await store.delBlob(blobKey(id, n)); } catch (e) { /* al weg */ }
          throw err;
        }
        if (log) log('info', 'opvraag_file_in', { id: id.slice(0, 6), item: i, kb: Math.round(buf.length / 1024) });
        return { ok: true, n, item: i, count: r.files.filter((f) => f.item === i).length };
      });
    },

    async list(accountId) {
      if (!accountId) return { ok: true, requests: [] };
      const out = [];
      for (const id of await indexIds(accountId)) {
        const r = await read(id);
        if (r && r.account_id === accountId) out.push(summary(r));
      }
      return { ok: true, requests: out };
    },

    // The office's own view of one request, with what its browser needs to open
    // the files: the locked private key and the descriptor it hashed.
    async detail(id, accountId) {
      const r = await owned(id, accountId);
      if (!r) return { ok: false, reason: 'unknown' };
      return { ok: true, ...summary(r), descriptor: r.descriptor, sk_wrapped: r.sk_wrapped,
               file_list: r.files.map((f) => ({ n: f.n, item: f.item, size: f.size, at: f.at })) };
    },

    async getFile(id, accountId, n) {
      const r = await owned(id, accountId);
      if (!r) return { ok: false, reason: 'unknown' };
      const f = r.files.find((x) => x.n === Number(n));
      if (!f) return { ok: false, reason: 'unknown_file' };
      const buf = await store.getBlob(blobKey(id, f.n));
      if (!buf) return { ok: false, reason: 'unknown_file' };
      return { ok: true, bytes: buf, item: f.item };
    },

    // No more uploads. The files stay until the end date, for the download.
    async close(id, accountId) {
      return opVolgorde(id, async () => {
        const r = await owned(id, accountId);
        if (!r) return { ok: false, reason: 'unknown' };
        if (!r.closed_at) { r.closed_at = clock(); await write(r); }
        return { ok: true, closed_at: r.closed_at };
      });
    },

    // Everything gone now, before the end date.
    async remove(id, accountId) {
      return opVolgorde(id, async () => {
        const r = await owned(id, accountId);
        if (!r) return { ok: false, reason: 'unknown' };
        for (const f of r.files) {
          try { await store.delBlob(blobKey(id, f.n)); } catch (e) { /* verloopt toch */ }
          await ledger.release(budgetId(id, f.n));
        }
        await store.delMeta(reqKey(id));
        await opVolgorde('acct:' + accountId, async () => {
          const ids = (await indexIds(accountId)).filter((x) => x !== id);
          await store.putMeta(accountIndexId(accountId), { ids }, 31 * 86400_000);
        });
        if (log) log('info', 'opvraag_removed', { id: id.slice(0, 6), files: r.files.length });
        return { ok: true };
      });
    },

    // May a reminder go out now? Counts it when it may; undoReminder hands the
    // seat back when the mail then fails.
    async takeReminder(id, accountId) {
      return opVolgorde(id, async () => {
        const r = await owned(id, accountId);
        if (!r) return { ok: false, reason: 'unknown' };
        if (r.closed_at) return { ok: false, reason: 'closed' };
        if (!r.client_email) return { ok: false, reason: 'no_email' };
        const items = itemView(r);
        if (items.every((x) => x.count > 0)) return { ok: false, reason: 'complete' };
        if ((r.reminders || 0) >= MAX_REMINDERS) return { ok: false, reason: 'reminder_limit', limit: MAX_REMINDERS };
        if (r.reminded_at && clock() - r.reminded_at < REMINDER_GAP_MS) return { ok: false, reason: 'reminder_too_soon' };
        r.reminders = (r.reminders || 0) + 1;
        r.reminded_at = clock();
        await write(r);
        return { ok: true, email: r.client_email, client_name: r.client_name, lang: r.lang,
                 descriptor: r.descriptor, missing: items.filter((x) => x.count === 0).map((x) => x.label),
                 expires_at: r.expires_at, reminders: r.reminders };
      });
    },
    async undoReminder(id, accountId) {
      return opVolgorde(id, async () => {
        const r = await owned(id, accountId);
        if (!r || !r.reminders) return;
        r.reminders -= 1; r.reminded_at = 0;
        await write(r);
      });
    },

    // The office's vault records: which browsers hold a vault key, and the
    // passkey-locked copies of it. All opaque to us.
    kluisList,
    async kluisPut(accountId, input) {
      if (!accountId) return { ok: false, reason: 'no_account' };
      const kid = input && input.kluis_id;
      if (typeof kid !== 'string' || !KLUIS_ID_RE.test(kid)) return { ok: false, reason: 'bad_kluis' };
      let wrap = null;
      if (input.wrap != null) {
        const w = input.wrap;
        if (!w || typeof w !== 'object') return { ok: false, reason: 'bad_wrap' };
        if (typeof w.cred !== 'string' || !w.cred || w.cred.length > 512 || b64urlLen(w.cred) < 1) return { ok: false, reason: 'bad_wrap' };
        if (b64urlLen(w.salt) !== 32 || b64urlLen(w.iv) !== 12 || b64urlLen(w.ct) !== 48) return { ok: false, reason: 'bad_wrap' };
        wrap = { cred: w.cred, salt: w.salt, iv: w.iv, ct: w.ct, at: clock() };
      }
      return opVolgorde('kluis:' + accountId, async () => {
        const list = (await kluisList(accountId)).slice();
        let k = list.find((x) => x.kluis_id === kid);
        if (!k) {
          if (list.length >= KLUIS_MAX) return { ok: false, reason: 'too_many_vaults', limit: KLUIS_MAX };
          k = { kluis_id: kid, created_at: clock(), wraps: [] };
          list.push(k);
        }
        if (wrap) {
          k.wraps = k.wraps.filter((x) => x.cred !== wrap.cred);
          if (k.wraps.length >= WRAPS_MAX) return { ok: false, reason: 'too_many_wraps', limit: WRAPS_MAX };
          k.wraps.push(wrap);
        }
        await store.putMeta(kluisIndexId(accountId), { kluizen: list }, KLUIS_TTL_MS);
        return { ok: true, kluizen: list };
      });
    },
  };
}

module.exports = {
  createOpvraagStore, checkDescriptor, limitsFor, newId, cleanText,
  ID_RE, KLUIS_ID_RE, FILE_MAX_BYTES, FILE_MIN_BYTES, FILES_PER_ITEM, MAX_REMINDERS,
  REMINDER_GAP_MS, KEM_PUB_BYTES, ECDH_PUB_BYTES, accountIndexId,
};
