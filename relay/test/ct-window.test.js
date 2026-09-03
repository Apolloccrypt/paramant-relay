'use strict';
// Regression test for the CT-log windowing (D2): monotonic indices past the cap,
// bounds-safe lookups, and window position mapping. Before the fix the index
// froze at CT_MAX (duplicates) and ctLog[idx] returned the wrong entry after the
// first shift. Run: node relay/test/ct-window.test.js
const assert = require('assert');
const crypto = require('crypto');
const { CtWindow, reindexEntries } = require('../lib/ct-window');
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

// ── the stored index field is a cache, the position is the truth ────────────
// Reproduces the public-log defect of 2026-09: five entries whose persisted
// .index survived an April rebuild unchanged while their position had moved,
// so the listing showed indices 4..8 twice and 42..46 not at all.
function poisoned(n) {
  const list = [];
  for (let i = 0; i < n; i++) list.push({ index: i, leaf_hash: 'leaf' + i, type: 't' });
  for (let p = 42; p <= 46; p++) list[p].index = p - 38;   // 42..46 -> 4..8
  return list;
}

{
  const w = new CtWindow(1000);
  w.load(poisoned(60));
  // page() numbers rows from the position, so the poisoned field is bypassed.
  const pg = w.page(40, 8);
  assert.strictEqual(pg.start_index, 40);
  assert.deepStrictEqual(pg.entries.map((e, i) => pg.start_index + i), [40,41,42,43,44,45,46,47]);
  assert.deepStrictEqual(pg.entries.map(e => e.leaf_hash),
    ['leaf40','leaf41','leaf42','leaf43','leaf44','leaf45','leaf46','leaf47'],
    'position 42 still carries the leaf that was appended 43rd');
  // The stored field is still wrong at this point; that is the whole point.
  assert.strictEqual(pg.entries[2].index, 4, 'stored field is stale, and unused');
  ok('page() numbers entries from position, not from the stored index field');
}

{
  const w = new CtWindow(1000);
  w.load(poisoned(60));
  const feed = w.recentPage(10);
  assert.strictEqual(feed.start_index, 50);
  assert.deepStrictEqual(feed.entries.map((e, i) => feed.start_index + i),
    [50,51,52,53,54,55,56,57,58,59]);
  assert.strictEqual(w.logicalIndexAt(42), 42);
  ok('recentPage() and logicalIndexAt() are positional too');
}

// ── the repair: idempotent, and the Merkle root does not move ───────────────
{
  const w = new CtWindow(1000);
  w.load(poisoned(60));
  const rootBefore = ctTreeHash(w.entries);
  const leavesBefore = w.entries.map(e => e.leaf_hash);
  const proofBefore = ctInclusionProof(w.entries, 42);

  assert.strictEqual(w.reindex(), 5, 'exactly the five poisoned entries are corrected');
  assert.deepStrictEqual(w.entries.map(e => e.index), w.entries.map((_, p) => p),
    'every stored index now equals its position');
  assert.strictEqual(w.reindex(), 0, 'idempotent: a second pass finds nothing');

  assert.deepStrictEqual(w.entries.map(e => e.leaf_hash), leavesBefore, 'no leaf moved');
  assert.strictEqual(ctTreeHash(w.entries), rootBefore, 'root is byte-identical after the repair');
  assert.deepStrictEqual(ctInclusionProof(w.entries, 42), proofBefore, 'audit path is unchanged');
  // And lookups that were already positional keep answering the same entry.
  assert.strictEqual(w.get(42).leaf_hash, 'leaf42');
  ok('reindex() repairs the field, is idempotent, and leaves the root untouched');
}

// ── reindexEntries on the persisted list, including the rotated case ────────
{
  const list = poisoned(60);
  const rootBefore = ctTreeHash(list);
  assert.strictEqual(reindexEntries(list), 5);
  assert.strictEqual(reindexEntries(list), 0);
  assert.strictEqual(ctTreeHash(list), rootBefore, 'root unchanged over the persisted list');

  // A rotated file does not start at 0. The first entry is the anchor, so the
  // recount must continue from it rather than renumber the whole file from 0.
  const rotated = [{ index: 900, leaf_hash: 'a' }, { index: 7, leaf_hash: 'b' }, { index: 902, leaf_hash: 'c' }];
  assert.strictEqual(reindexEntries(rotated), 1);
  assert.deepStrictEqual(rotated.map(e => e.index), [900, 901, 902]);

  // No index field at all (a very old line) counts as wrong and gets one.
  const legacy = [{ leaf_hash: 'a' }, { leaf_hash: 'b' }];
  assert.strictEqual(reindexEntries(legacy), 2);
  assert.deepStrictEqual(legacy.map(e => e.index), [0, 1]);

  assert.strictEqual(reindexEntries([]), 0);
  assert.strictEqual(reindexEntries(null), 0);
  ok('reindexEntries anchors on the first entry, handles rotated and legacy lines');
}

// ── load() of a repaired list keeps appending monotonically ────────────────
{
  const list = poisoned(60);
  reindexEntries(list);
  const w = new CtWindow(1000);
  w.load(list);
  assert.strictEqual(w.base, 0);
  assert.strictEqual(w.nextIndex(), 60);
  const index = w.nextIndex();
  w.append({ index, leaf_hash: 'leaf60' });
  assert.strictEqual(w.get(60).leaf_hash, 'leaf60');
  ok('a repaired log rehydrates and keeps appending without a gap');
}

console.log(`\n${passed} passed`);
