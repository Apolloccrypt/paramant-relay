'use strict';
// Every Mollie payment id this relay ever settled, on disk, forever.
//
// WHY. The idempotency marker lived in redis with a 60-day TTL, and the
// durable fallback on the account record held only the LAST payment per
// product (paid_by_<product>). After a second purchase plus 60 days (or one
// redis flush) a replay of the first payment's id -- printed on the invoice
// PDF, and the webhook is public -- passed both checks, and the relay
// re-fetched it from Mollie, found it 'paid', and granted another month for
// free (sweep-acct finding 1).
//
// Append-only JSONL next to users.json, one line per state change:
//   {"id":"tr_x","val":"granted","at":"...","grants":[{product,tier,from,until}]}
// The last line for an id wins. `grants` records the period the payment
// bought, which is what lets a chargeback take back exactly that period and
// not the months paid before it (sweep-acct finding 8).
const fs = require('fs');
const path = require('path');

class BillingLedger {
  constructor(file, log) {
    this.file = file;
    this.log = log || (() => {});
    this.map = new Map();
    this._queue = Promise.resolve();
  }

  load() {
    let raw = '';
    try { raw = fs.readFileSync(this.file, 'utf8'); }
    catch (e) { if (e.code !== 'ENOENT') this.log('error', 'billing_ledger_load_failed', { err: e.message, file: this.file }); return this; }
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line);
        if (r && typeof r.id === 'string') this.map.set(r.id, r);
      } catch { /* a torn last line from a crash; the rest stands */ }
    }
    return this;
  }

  get(id) { return this.map.get(id) || null; }
  status(id) { const r = this.map.get(id); return r ? r.val : null; }

  // Resolves once the line is on disk (fsync), rejects when it is not.
  record(id, val, extra) {
    const prev = this.map.get(id);
    const rec = { id, val, at: new Date().toISOString() };
    const grants = (extra && extra.grants) || (prev && prev.grants);
    if (grants) rec.grants = grants;
    this.map.set(id, rec);
    const line = JSON.stringify(rec) + '\n';
    const job = this._queue.then(async () => {
      await fs.promises.mkdir(path.dirname(path.resolve(this.file)), { recursive: true });
      const fh = await fs.promises.open(this.file, 'a', 0o600);
      try { await fh.write(line); await fh.sync(); } finally { await fh.close(); }
    });
    this._queue = job.catch((e) => this.log('error', 'billing_ledger_write_failed', { err: e.message, file: this.file, id }));
    return job;
  }
}

// Backfill (review #555, M3). The ledger started empty on the day it was
// deployed, while the payments settled before it lived only in redis markers
// (60-day TTL) and in paid_by_<product> on the account (the LAST payment
// only). Once a marker expired and paid_by had moved on, an old tr_ id was
// grantable again through the public webhook. So at boot every id the relay
// already knows as settled goes into the ledger: every paid_by_<product>
// pointer on an account record, and every paramant:billing:done:* marker in
// redis. Idempotent: an id the ledger has is never written again.
const DONE_PREFIX = 'paramant:billing:done:';
async function backfillLedger(ledger, { redis, records, products, log } = {}) {
  const say = log || (() => {});
  const add = [];
  const seen = new Set();
  const want = (id, val) => {
    if (typeof id !== 'string' || !/^tr_[A-Za-z0-9]+$/.test(id)) return;
    if (seen.has(id) || ledger.status(id)) return;
    seen.add(id);
    add.push([id, val]);
  };
  for (const rec of records || []) {
    if (!rec || typeof rec !== 'object') continue;
    for (const p of products || []) want(rec['paid_by_' + p], 'granted');
  }
  let scanned = 0;
  if (redis && redis.isReady) {
    try {
      for await (const batch of redis.scanIterator({ MATCH: DONE_PREFIX + '*', COUNT: 500 })) {
        const keys = Array.isArray(batch) ? batch : [batch];
        for (const k of keys) {
          scanned++;
          const id = String(k).slice(DONE_PREFIX.length);
          if (ledger.status(id) || seen.has(id)) continue;
          let v = null;
          try { v = await redis.get(k); } catch { v = null; }
          want(id, v === 'revoked' ? 'revoked' : 'granted');
        }
      }
    } catch (e) { say('warn', 'billing_ledger_backfill_scan_failed', { err: e.message }); }
  }
  for (const [id, val] of add) {
    try { await ledger.record(id, val); } catch { /* logged by the ledger */ }
  }
  say('info', 'billing_ledger_backfilled', { added: add.length, markers_scanned: scanned });
  return { added: add.length, scanned };
}

module.exports = { BillingLedger, backfillLedger, DONE_PREFIX };
