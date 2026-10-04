'use strict';
// The full-log Merkle tree (lib/ct-tree.js) against the original window code.
//
// WHY. The relay signed tree_size = window length, so at 10 001 entries the
// head froze and every next head was refused as a fork; and its consistency
// proofs verified against no standard RFC 6962 / 9162 verifier (sibling order
// and the initial b flag were wrong). This suite holds:
//   1. roots and audit paths are byte-identical to lib/ct-hash.js for every
//      size the old code handled correctly, so no receipt already issued and
//      no head already signed changes value;
//   2. every consistency proof verifies with the RFC 9162 2.1.4.2 algorithm,
//      and a wrong old root does not;
//   3. past 10 000 leaves the root still matches a from-scratch MTH and an
//      append stays cheap.
// Run: node --test relay/test/ct-tree.test.js
const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { CtMerkle, verifyConsistency } = require('../lib/ct-tree');
const { ctTreeHash, ctInclusionProof, ctNodeHash } = require('../lib/ct-hash');

const leaf = (i) => crypto.createHash('sha3-256').update('leaf-' + i).digest('hex');

function fold(leafHash, proof) {
  let h = leafHash;
  for (const s of proof) h = s.position === 'left' ? ctNodeHash(s.hash, h) : ctNodeHash(h, s.hash);
  return h;
}

test('root and audit path equal the old window code for sizes 1..300', () => {
  const t = new CtMerkle();
  const entries = [];
  for (let n = 1; n <= 300; n++) {
    t.append(leaf(n - 1));
    entries.push({ leaf_hash: leaf(n - 1) });
    assert.strictEqual(t.root(), ctTreeHash(entries), `root at size ${n}`);
    assert.deepStrictEqual(t.inclusionProof(n - 1, n), ctInclusionProof(entries, n - 1), `newest-leaf path at size ${n}`);
  }
  for (const n of [1, 2, 3, 7, 64, 65, 129, 300]) {
    const sub = entries.slice(0, n);
    assert.strictEqual(t.root(n), ctTreeHash(sub), `historic root at ${n}`);
    for (let m = 0; m < n; m++) {
      const p = t.inclusionProof(m, n);
      assert.deepStrictEqual(p, ctInclusionProof(sub, m), `path ${m}/${n}`);
      assert.strictEqual(fold(leaf(m), p), ctTreeHash(sub));
    }
  }
});

test('every consistency proof verifies (RFC 9162 2.1.4.2) and a wrong root does not', () => {
  const t = new CtMerkle();
  for (let i = 0; i < 80; i++) t.append(leaf(i));
  let checked = 0;
  for (let to = 1; to <= 80; to++) {
    for (let from = 1; from <= to; from++) {
      const proof = t.consistencyProof(from, to);
      assert.ok(verifyConsistency(from, to, t.root(from), t.root(to), proof), `consistency ${from}->${to}`);
      if (from < to) {
        assert.ok(!verifyConsistency(from, to, leaf(999), t.root(to), proof), `forged old root ${from}->${to}`);
        assert.ok(!verifyConsistency(from, to, t.root(from), leaf(999), proof), `forged new root ${from}->${to}`);
      }
      checked++;
    }
  }
  assert.ok(checked > 3000);
});

test('the reported repro: consistency 3 -> 72 verifies', () => {
  const t = new CtMerkle();
  for (let i = 0; i < 72; i++) t.append(leaf(i));
  assert.ok(verifyConsistency(3, 72, t.root(3), t.root(72), t.consistencyProof(3, 72)));
});

test('past 10 000 leaves: size keeps growing, root equals full MTH, append stays cheap', () => {
  const t = new CtMerkle();
  const all = [];
  for (let i = 0; i < 10050; i++) { t.append(leaf(i)); all.push({ leaf_hash: leaf(i) }); }
  assert.strictEqual(t.size, 10050);
  assert.strictEqual(t.root(), ctTreeHash(all));
  assert.notStrictEqual(t.root(10001), t.root(10002));
  const p = t.inclusionProof(3, 10050);
  assert.strictEqual(fold(leaf(3), p), t.root());
  assert.ok(verifyConsistency(10000, 10050, t.root(10000), t.root(), t.consistencyProof(10000, 10050)));
  const t0 = process.hrtime.bigint();
  for (let i = 10050; i < 11050; i++) { t.append(leaf(i)); t.root(); t.inclusionProof(i, i + 1); }
  const perAppendMs = Number(process.hrtime.bigint() - t0) / 1e6 / 1000;
  assert.ok(perAppendMs < 5, `append+root+path took ${perAppendMs.toFixed(2)} ms each`);
});

test('leafBytes round-trips through a fresh tree', () => {
  const t = new CtMerkle();
  for (let i = 0; i < 37; i++) t.append(leaf(i));
  const b = t.leafBytes();
  const u = new CtMerkle();
  for (let i = 0; i < b.length; i += 32) u.append(b.toString('hex', i, i + 32));
  assert.strictEqual(u.root(), t.root());
});
