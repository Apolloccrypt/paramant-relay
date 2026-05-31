#!/usr/bin/env node
// Idempotent users.json v1 -> v2 migration (additive account-split schema).
//
//   node deploy/migrate-users-v2.mjs [path-to-users.json]
//
// Safe to run on a live file: it backs up first, writes atomically (tmp+rename),
// and is a no-op when the file is already schema_version >= 2. The relay also
// tolerates a v1 file at runtime (loadUsers defaults account_id = key), so this
// script is only needed when you want the on-disk file to carry the v2 shape.
//
// Rollback: restore the printed `.v1.bak.<stamp>` over users.json and reload.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require_ = createRequire(import.meta.url);
const { migrateUsersV2 } = require_('../relay/lib/keys-table.js');

const file = process.argv[2] || process.env.USERS_FILE || './users.json';

let raw;
try { raw = fs.readFileSync(file, 'utf8'); }
catch (e) { console.error(`[migrate] cannot read ${file}: ${e.message}`); process.exit(1); }

let data;
try { data = JSON.parse(raw); }
catch (e) { console.error(`[migrate] ${file} is not valid JSON: ${e.message}`); process.exit(1); }

if ((data.schema_version | 0) >= 2) {
  console.log(`[migrate] ${file} already schema_version >= 2 — no-op.`);
  process.exit(0);
}

let out;
try { out = migrateUsersV2(data); }
catch (e) { console.error(`[migrate] refused: ${e.message}`); process.exit(1); }

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const bak = `${file}.v1.bak.${stamp}`;
fs.copyFileSync(file, bak);

const tmp = `${file}.tmp.${process.pid}.${stamp}`;
fs.writeFileSync(tmp, JSON.stringify(out, null, 2));
fs.renameSync(tmp, file);

console.log(`[migrate] ${file}: v1 -> v2  (${out.api_keys.length} keys, ${Object.keys(out.accounts).length} accounts)`);
console.log(`[migrate] backup: ${bak}`);
