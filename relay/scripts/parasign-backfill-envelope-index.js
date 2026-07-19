#!/usr/bin/env node
'use strict';
// One-shot backfill for the ParaSign per-account envelope index
// (parasign:acct:<accountId>:envelopes). The index is only written at create()
// time, so envelopes created BEFORE it existed are absent from the audit-export.
// This SCANs every env:* hash and (re)builds the index.
//
// Account resolution per envelope:
//   1) the account_id field now written into each new envelope record, or
//   2) a SHA3(api_key) -> account_id reverse map built here from users.json,
//      matched against the record's creator_api_hash.
// An envelope whose creating key is no longer in users.json (and has no
// account_id field) cannot be resolved and is reported as `unresolved`. Without
// this backfill the index only works FORWARD (envelopes created from now on).
//
// Idempotent: re-running only refreshes each id's score. Safe to run live.
//
// Usage:
//   REDIS_URL=redis://127.0.0.1:6379 USERS_FILE=./users.json \
//     node scripts/parasign-backfill-envelope-index.js [--dry-run]

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createClient } = require('redis');
const { EnvelopeStore } = require('../envelope');
const keysTable = require('../lib/keys-table');

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const url = process.env.REDIS_URL || process.env.RELAY_REDIS_URL || 'redis://127.0.0.1:6379';
  const usersFile = process.env.USERS_FILE || path.join(__dirname, '..', 'users.json');

  // Reverse map SHA3(api_key) -> account_id from users.json (the best source a
  // standalone script has). New envelopes carry account_id and skip this; only
  // pre-index envelopes lean on it.
  const hashToAccount = new Map();
  try {
    const d = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    for (const k of (d.api_keys || [])) {
      if (!k || !k.key) continue;
      const acct = keysTable.parseAccountFields(k).account_id;
      hashToAccount.set(crypto.createHash('sha3-256').update(k.key).digest('hex'), acct);
    }
    console.error(`loaded ${hashToAccount.size} key->account mappings from ${usersFile}`);
  } catch (e) {
    console.error(`users.json load failed (${e.message}); only account_id-tagged envelopes will resolve`);
  }

  const redis = createClient({ url });
  redis.on('error', () => {});
  await redis.connect();
  const store = new EnvelopeStore(redis, {});

  const res = await store.backfillAccountIndex({
    resolveAccount: (h) => hashToAccount.get(h.creator_api_hash || '') || null,
    dryRun,
    log: (lvl, msg, meta) => console.error(lvl, msg, JSON.stringify(meta || {})),
  });

  console.log(JSON.stringify({ ok: true, dry_run: dryRun, ...res }));
  try { await redis.quit(); } catch { /* ignore */ }
}

main().catch((e) => { console.error(e); process.exit(1); });
