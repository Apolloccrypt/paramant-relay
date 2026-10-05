'use strict';
// Pure CT-log hash primitives, extracted from relay.js so the transparency
// keten is unit-testable in isolation (the receipt/inclusion-proof roundtrip
// has no server dependencies). Domain separators: 0x00 pubkey leaf, 0x01 inner
// node, 0x02 blob/transfer leaf. SHA3-256 throughout.
const crypto = require('crypto');

function ctNodeHash(left, right) {
  return crypto.createHash('sha3-256')
    .update(Buffer.from([0x01]))
    .update(Buffer.from(left, 'hex'))
    .update(Buffer.from(right, 'hex'))
    .digest('hex');
}

function ctTreeHash(entries) {
  if (entries.length === 0) return '0'.repeat(64);
  let hashes = entries.map(e => e.leaf_hash);
  while (hashes.length > 1) {
    const next = [];
    for (let i = 0; i < hashes.length; i += 2) {
      next.push(i + 1 < hashes.length ? ctNodeHash(hashes[i], hashes[i + 1]) : hashes[i]);
    }
    hashes = next;
  }
  return hashes[0];
}

// Merkle audit path for `idx`. Each step is { hash, position:'left'|'right' }.
function ctInclusionProof(entries, idx) {
  if (entries.length <= 1) return [];
  let hashes = entries.map(e => e.leaf_hash);
  const path = [];
  let i = idx;
  while (hashes.length > 1) {
    const sibling = i % 2 === 0 ? i + 1 : i - 1;
    if (sibling < hashes.length) {
      path.push({ hash: hashes[sibling], position: i % 2 === 0 ? 'right' : 'left' });
    }
    const next = [];
    for (let j = 0; j < hashes.length; j += 2) {
      next.push(j + 1 < hashes.length ? ctNodeHash(hashes[j], hashes[j + 1]) : hashes[j]);
    }
    hashes = next;
    i = Math.floor(i / 2);
  }
  return path;
}

// Leaf hash for blob/transfer entries - domain separator 0x02. Commits to the
// transfer hash + sector + timestamp without exposing payload content. `ts` is
// REQUIRED: it is part of the committed leaf, so the receipt must carry it back
// for /v2/verify-receipt to recompute the same leaf.
function blobLeafHash(blobHash, sector, ts) {
  if (ts === undefined || ts === null) throw new TypeError('blobLeafHash: ts is required');
  const data = Buffer.concat([
    Buffer.from(blobHash, 'hex'),
    crypto.createHash('sha3-256').update(sector || 'relay').digest(),
    Buffer.from(String(ts), 'utf8'),
  ]);
  return crypto.createHash('sha3-256').update(Buffer.from([0x02])).update(data).digest('hex');
}

module.exports = { ctNodeHash, ctTreeHash, ctInclusionProof, blobLeafHash };
