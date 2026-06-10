'use strict';
// Tamper-evident audit chain helpers (extracted for unit coverage, #19).
// chain_hash commits to EVERY field of an entry except chain_hash itself, using
// a canonical (sorted-key) encoding so object key order never matters.
const crypto = require('crypto');

// Recursive canonical JSON (sorted keys, no whitespace) — identical contract to
// the relay's canonicalJSON, kept local so this module is self-contained.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort()
    .map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function auditEntryHash(entry) {
  const rest = Object.assign({}, entry);
  delete rest.chain_hash; // exclude the field we are about to (re)compute
  return crypto.createHash('sha3-256').update(canonicalJSON(rest)).digest('hex');
}

// Verify a Merkle audit chain: recompute each entry's chain_hash over ALL its
// fields (tamper-evidence) AND verify the prev_hash linkage. Linkage is relative
// so a trimmed chain (oldest entries dropped past MAX_AUDIT) still verifies.
function verifyChain(entries) {
  for (let i = 0; i < entries.length; i++) {
    if (entries[i].chain_hash !== auditEntryHash(entries[i])) return false;
    if (i > 0 && entries[i].prev_hash !== entries[i - 1].chain_hash) return false;
  }
  return true;
}

module.exports = { canonicalJSON, auditEntryHash, verifyChain };
