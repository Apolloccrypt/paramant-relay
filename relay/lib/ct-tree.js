'use strict';
// The whole CT Merkle tree, not a window of it.
//
// WHY. The relay used to keep the last 10 000 entries (CtWindow) and rebuild
// the Merkle tree over just that window on every append. Two things broke at
// entry 10 001:
//   * the signed tree head took the WINDOW length as tree_size, so it froze at
//     10 001 while the root kept changing, and produceSth refused every head
//     after that as a fork (root_differs_at_same_size): the log stopped
//     signing for good;
//   * every append hashed the full window twice (root + audit path), 130-240 ms
//     synchronously on the request thread, so the relay stood still under
//     load.
//
// This keeps every leaf hash (32 bytes each, in growing Buffers) plus every
// perfect subtree hash above it, so:
//   * append is O(log n);
//   * the root at ANY size m <= n is O(log n) lookups (RFC 6962 MTH);
//   * the audit path for any leaf against any size is O(log n);
//   * the RFC 6962 consistency proof between any two sizes is O(log n).
// Memory: about 2 * 32 bytes per leaf (64 MB per million entries).
//
// The tree shape is RFC 6962 (split at the largest power of two below n). The
// relay's original bottom-up pairing with odd-node promotion is the same tree,
// so every root and audit path this produces for a size up to 10 000 is
// byte-identical to what lib/ct-hash.js produced; relay/test/ct-tree.test.js
// holds that.
const { ctNodeHash } = require('./ct-hash');

const H = 32;

class Level {
  constructor() { this.buf = Buffer.alloc(H * 64); this.count = 0; }
  push(hashBuf) {
    if ((this.count + 1) * H > this.buf.length) {
      const next = Buffer.alloc(this.buf.length * 2);
      this.buf.copy(next, 0, 0, this.count * H);
      this.buf = next;
    }
    hashBuf.copy(this.buf, this.count * H);
    this.count++;
  }
  hex(i) { return this.buf.toString('hex', i * H, (i + 1) * H); }
  truncate(n) { if (n < this.count) this.count = n; }
}

function largestPow2Below(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function isPow2(n) { return n > 0 && (n & (n - 1)) === 0; }

class CtMerkle {
  constructor() { this.levels = [new Level()]; }

  get size() { return this.levels[0].count; }

  // Append one leaf hash (64 hex chars). Fills in every perfect subtree the
  // leaf completes.
  append(leafHex) {
    if (typeof leafHex !== 'string' || !/^[0-9a-f]{64}$/i.test(leafHex)) {
      throw new TypeError('CtMerkle.append: leaf must be 64 hex chars');
    }
    this.levels[0].push(Buffer.from(leafHex, 'hex'));
    let h = 0;
    let idx = this.levels[0].count - 1;
    while (idx % 2 === 1) {
      const lvl = this.levels[h];
      const parent = ctNodeHash(lvl.hex(idx - 1), lvl.hex(idx));
      if (!this.levels[h + 1]) this.levels.push(new Level());
      this.levels[h + 1].push(Buffer.from(parent, 'hex'));
      h++;
      idx = (idx - 1) / 2;
    }
    return this.size - 1;
  }

  leaf(i) { return (i >= 0 && i < this.size) ? this.levels[0].hex(i) : null; }

  // MTH(D[lo:hi]). The left part of every RFC 6962 split is a perfect subtree
  // aligned to its own size, so it is always a stored node.
  _mth(lo, hi) {
    const n = hi - lo;
    if (n <= 0) return '0'.repeat(64);
    if (isPow2(n) && lo % n === 0) {
      const h = Math.log2(n);
      return this.levels[h].hex(lo / n);
    }
    const k = largestPow2Below(n);
    return ctNodeHash(this._mth(lo, lo + k), this._mth(lo + k, hi));
  }

  // Root of the tree as it stood at `size` leaves (default: now).
  root(size = this.size) {
    if (!Number.isInteger(size) || size < 0 || size > this.size) return null;
    return this._mth(0, size);
  }

  // Audit path for leaf `m` in the tree of `size` leaves, deepest step first,
  // each step { hash, position: 'left'|'right' }: the format the relay has
  // always published and that receipt-verify.js folds.
  inclusionProof(m, size = this.size) {
    if (!Number.isInteger(m) || !Number.isInteger(size) || m < 0 || m >= size || size > this.size) return null;
    const out = [];
    const walk = (mm, lo, hi) => {
      const n = hi - lo;
      if (n <= 1) return;
      const k = largestPow2Below(n);
      if (mm < k) {
        walk(mm, lo, lo + k);
        out.push({ hash: this._mth(lo + k, hi), position: 'right' });
      } else {
        walk(mm - k, lo + k, hi);
        out.push({ hash: this._mth(lo, lo + k), position: 'left' });
      }
    };
    walk(m, 0, size);
    return out;
  }

  // RFC 6962 section 2.1.2: PROOF(m, D[n]) = SUBPROOF(m, D[n], true).
  //   SUBPROOF(m, D[lo:hi], b): m == n  -> [] if b, else [MTH(D[lo:hi])]
  //                             m <= k  -> SUBPROOF(m, D[lo:lo+k], b) : MTH(D[lo+k:hi])
  //                             m >  k  -> SUBPROOF(m-k, D[lo+k:hi], false) : MTH(D[lo:lo+k])
  // The sibling always goes AFTER the subproof. The old window code put
  // MTH(left) first in the third case and started with b=false, which is why
  // not one of its proofs verified against a standard verifier.
  consistencyProof(from, to = this.size) {
    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from || to > this.size) return null;
    if (from === 0 || from === to) return [];
    const sub = (m, lo, hi, b) => {
      const n = hi - lo;
      if (m === n) return b ? [] : [this._mth(lo, hi)];
      const k = largestPow2Below(n);
      if (m <= k) return sub(m, lo, lo + k, b).concat([this._mth(lo + k, hi)]);
      return sub(m - k, lo + k, hi, false).concat([this._mth(lo, lo + k)]);
    };
    return sub(from, 0, to, true);
  }

  // Raw leaf bytes from `from` on, for the leaves file.
  leafBytes(from = 0, to = this.size) { return Buffer.from(this.levels[0].buf.subarray(from * H, to * H)); }
}

// RFC 9162 section 2.1.4.2 verifier, used by the tests and by anyone holding
// two signed heads. Returns true when `proof` shows the tree of `to` leaves
// with root `newRoot` extends the tree of `from` leaves with root `oldRoot`.
function verifyConsistency(from, to, oldRoot, newRoot, proof) {
  if (from === to) return proof.length === 0 && oldRoot === newRoot;
  if (from === 0 || from > to) return false;
  let path = proof.slice();
  if (isPow2(from)) path = [oldRoot].concat(path);
  if (path.length === 0) return false;
  let fn = from - 1;
  let sn = to - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = ctNodeHash(c, fr);
      sr = ctNodeHash(c, sr);
      if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else {
      sr = ctNodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && fr === oldRoot && sr === newRoot;
}

module.exports = { CtMerkle, verifyConsistency };
