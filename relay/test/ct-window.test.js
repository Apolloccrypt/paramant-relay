'use strict';
// Regression test for the CT-log windowing (D2): monotonic indices past the cap,
// bounds-safe lookups, and window position mapping. Before the fix the index
// froze at CT_MAX (duplicates) and ctLog[idx] returned the wrong entry after the
// first shift. Run: node relay/test/ct-window.test.js
const assert = require('assert');
const crypto = require('crypto');
const { CtWindow } = require('../lib/ct-window');
const { ctTreeHash, ctInclusionProof, ctNodeHash } = require('../lib/ct-hash');

let passed = 0;
const ok = n => { passed++; console.log('  ok -', n); };

// Append n entries the way relay.js does: index = nextIndex() before build.
function fill(w, n) {
  for (let i = 0; i < n; i++) {
    const index = w.nextIndex();
    w.append({ index, leaf_hash: 'leaf' + index, type: 't' });
  }
}

// ── below the cap: index == position, everything retained ──────────────────
{
  const w = new CtWindow(100);
  fill(w, 10);
  assert.strictEqual(w.size, 10);
  assert.strictEqual(w.windowLength, 10);
  assert.strictEqual(w.nextIndex(), 10);
  assert.strictEqual(w.get(0).leaf_hash, 'leaf0');
  assert.strictEqual(w.get(9).leaf_hash, 'leaf9');
  assert.strictEqual(w.position(3), 3);
  ok('below the cap: indices and positions coincide, all retained');
}

// ── past the cap: indices stay monotonic, no duplicates, oldest pruned ──────
{
  const w = new CtWindow(4);
  fill(w, 10);                       // indices 0..9, window holds the last 4
  assert.strictEqual(w.size, 10, 'monotonic total keeps advancing');
  assert.strictEqual(w.windowLength, 4);
  assert.strictEqual(w.nextIndex(), 10, 'next index is 10, NOT frozen at max');
  // The retained window is indices 6,7,8,9 - each distinct.
  const idxs = w.entries.map(e => e.index);
  assert.deepStrictEqual(idxs, [6, 7, 8, 9]);
  assert.strictEqual(new Set(idxs).size, 4, 'no duplicate indices');
  ok('past the cap: index advances monotonically, oldest 4 pruned');
}

// ── lookups after pruning: correct entry or null, never the wrong one ───────
{
  const w = new CtWindow(4);
  fill(w, 10);
  assert.strictEqual(w.get(9).leaf_hash, 'leaf9', 'newest retained by its real index');
  assert.strictEqual(w.get(6).leaf_hash, 'leaf6', 'oldest retained by its real index');
  assert.strictEqual(w.get(5), null, 'pruned index returns null, not a wrong entry');
  assert.strictEqual(w.get(0), null, 'long-gone index returns null');
  assert.strictEqual(w.get(10), null, 'not-yet-appended index returns null');
  assert.strictEqual(w.position(7), 1, 'logical 7 sits at window position 1');
  assert.strictEqual(w.position(5), -1);
  ok('lookups after pruning resolve the right entry or null');
}

// ── the exact old-bug scenario: the wrong entry at the old positional index ─
{
  const w = new CtWindow(4);
  fill(w, 10);
  // The buggy code did ctLog[idx]; at idx=0 that would now be entry index 6.
  // get(0) must NOT return the entry currently sitting at array position 0.
  assert.notStrictEqual(w.get(0), w.entries[0]);
  assert.strictEqual(w.get(0), null);
  assert.strictEqual(w.entries[0].index, 6);
  ok('positional lookup bug is gone: get(0) != entries[0] after pruning');
}

// ── append enforces the monotonic contract ─────────────────────────────────
{
  const w = new CtWindow(4);
  assert.throws(() => w.append({ index: 5, leaf_hash: 'x' }), /nextIndex/);
  ok('append rejects a non-monotonic index');
}

// ── sliceByIndex + recent clamp to the window ───────────────────────────────
{
  const w = new CtWindow(4);
  fill(w, 10);
  assert.deepStrictEqual(w.sliceByIndex(7, 2).map(e => e.index), [7, 8]);
  assert.deepStrictEqual(w.sliceByIndex(0, 100).map(e => e.index), [6, 7, 8, 9], 'pruned start clamps to base');
  assert.deepStrictEqual(w.recent(2).map(e => e.index), [8, 9]);
  ok('sliceByIndex and recent clamp to the retained window');
}

// ── load rehydrates base from the persisted entries and trims to the cap ────
{
  const w = new CtWindow(3);
  w.load([{ index: 6, leaf_hash: 'a' }, { index: 7, leaf_hash: 'b' }, { index: 8, leaf_hash: 'c' }, { index: 9, leaf_hash: 'd' }]);
  assert.strictEqual(w.windowLength, 3, 'trimmed to cap keeping newest');
  assert.strictEqual(w.base, 7, 'base taken from the first retained entry');
  assert.strictEqual(w.get(9).leaf_hash, 'd');
  assert.strictEqual(w.get(6), null, 'the trimmed-away entry is gone');
  assert.strictEqual(w.nextIndex(), 10, 'append continues monotonically after load');
  ok('load rehydrates base and continues monotonically');
}

// ── integration: an entry's inclusion proof still validates past the cap ─────
// Replicates the relay's ctAppend* body (index=nextIndex, proof at the new leaf
// position, tree over the window) and checks the fresh entry's proof recomputes
// its own tree root - the guarantee that broke when the index froze at the cap.
{
  const w = new CtWindow(8);
  function rootFromProof(leaf, path) {
    let r = leaf;
    for (const step of path) r = step.position === 'right' ? ctNodeHash(r, step.hash) : ctNodeHash(step.hash, r);
    return r;
  }
  let last = null;
  for (let i = 0; i < 25; i++) {                       // well past the cap of 8
    const index = w.nextIndex();
    const leaf_hash = crypto.createHash('sha3-256').update('leaf' + index).digest('hex');
    const allEntries = [...w.entries, { leaf_hash }];
    const tree_hash = ctTreeHash(allEntries);
    const proof = ctInclusionProof(allEntries, allEntries.length - 1);
    const entry = { index, leaf_hash, tree_hash, proof };
    w.append(entry);
    last = entry;
  }
  assert.strictEqual(rootFromProof(last.leaf_hash, last.proof), last.tree_hash,
    'fresh entry proof must recompute its tree root past the cap');
  assert.strictEqual(last.index, 24, 'index kept advancing (24), not frozen at 8');
  assert.strictEqual(w.get(24).leaf_hash, last.leaf_hash);
  assert.strictEqual(w.get(10), null, 'a pruned index is gone, not misresolved');
  ok('integration: inclusion proof validates for a fresh entry past the cap');
}

console.log(`\n${passed} passed`);
