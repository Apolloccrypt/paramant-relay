'use strict';
// Regression test for the delivery-receipt roundtrip (D1): the leaf recomputed
// at /v2/verify-receipt time must equal the leaf the relay committed at upload.
// Before the fix the receipt dropped `ts`, so blobLeafHash(...,undefined) threw
// and every verify returned 400. Run: node relay/test/ct-receipt.test.js
const assert = require('assert');
const crypto = require('crypto');
const { blobLeafHash, ctNodeHash, ctInclusionProof, ctTreeHash } = require('../lib/ct-hash');

let passed = 0;
const ok = n => { passed++; console.log('  ok -', n); };

// Recompute a Merkle root from a leaf + audit path exactly as /v2/verify-receipt does.
function rootFromProof(leaf, auditPath) {
  let root = leaf;
  for (const step of auditPath) {
    root = step.position === 'right' ? ctNodeHash(root, step.hash) : ctNodeHash(step.hash, root);
  }
  return root;
}

// ── ts is mandatory: the pre-fix bug was passing undefined ──────────────────
assert.throws(() => blobLeafHash('aa'.repeat(32), 'health', undefined), /ts is required/);
ok('blobLeafHash rejects a missing ts (the pre-fix 400 cause)');

// ── append/verify agree when ts is carried through ─────────────────────────
const blobHash = crypto.randomBytes(32).toString('hex');
const sector = 'health';
const ts = '2026-07-16T05:00:00.000Z';
const appendLeaf = blobLeafHash(blobHash, sector, ts);

// Simulate the receipt the outbound handler now emits (with ts) and the verify
// recompute from receipt.blob_hash + receipt.sector + receipt.ts.
const receipt = { blob_hash: blobHash, sector, ts };
const verifyLeaf = blobLeafHash(receipt.blob_hash, receipt.sector, receipt.ts);
assert.strictEqual(verifyLeaf, appendLeaf, 'verify leaf must equal append leaf');
ok('receipt roundtrip: recomputed leaf equals the committed leaf');

// ── a wrong ts must NOT verify (leaf binds the timestamp) ──────────────────
assert.notStrictEqual(blobLeafHash(blobHash, sector, '2026-07-16T06:00:00.000Z'), appendLeaf);
ok('a different ts yields a different leaf (timestamp is bound)');

// ── inclusion proof + root recompute holds for a small tree ────────────────
const entries = [];
for (let i = 0; i < 5; i++) {
  entries.push({ leaf_hash: blobLeafHash(crypto.randomBytes(32).toString('hex'), sector, ts) });
}
const idx = 3;
const proof = ctInclusionProof(entries, idx);
assert.strictEqual(rootFromProof(entries[idx].leaf_hash, proof), ctTreeHash(entries),
  'proof-recomputed root must equal the tree root');
ok('inclusion proof for a mid-tree leaf recomputes the tree root');

console.log(`\n${passed} passed`);
