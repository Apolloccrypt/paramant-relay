'use strict';
// The head guard, walked past the point where the Merkle window wraps.
//
// This is the failure the guard used to have, reproduced here so it cannot come
// back. The tree covers the CT_MAX most recent leaves and that window slides,
// so once it is full the leaf count stops growing while the root changes on
// every append. Keyed on tree_size alone the guard saw one size with many
// roots, called it a fork, refused the head, and kept refusing for ever while
// the log went on growing.
//
// On production the window holds ten thousand leaves and the log stood at 4814
// entries when this was found: a date, not a fault anyone had met yet.
const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { CtWindow } = require('../lib/ct-window');
const { ctTreeHash } = require('../lib/ct-hash');
const { sthKey, sthLogicalSize, sthRefusal } = require('../lib/sth-guard');

// A relay's head-signing loop, with everything that is not the guard removed:
// a sliding window, a real Merkle root over it, and the two pieces of state
// produceSth() keeps. `keyBy` selects the old behaviour or the new one so the
// bug and its repair are measured by the same harness.
function run({ windowSize, appends, keyBy }) {
  const w = new CtWindow(windowSize);
  const signedRoots = new Map();
  let maxSignedSize = -1;
  const signed = [];
  const refused = [];

  for (let i = 0; i < appends; i++) {
    const leaf_hash = crypto.createHash('sha3-256').update('leaf-' + i).digest('hex');
    const leaves = [...w.entries, { leaf_hash }];
    const sha3_root = ctTreeHash(leaves);
    w.append({ index: w.nextIndex(), leaf_hash, tree_hash: sha3_root });

    const tree_size = leaves.length;
    const window_base = w.size - tree_size;
    const head = { tree_size, window_base, sha3_root };

    // The old guard keyed on size alone and never knew about window_base.
    const asOld = keyBy === 'size';
    const refusal = sthRefusal({
      tree_size,
      window_base: asOld ? 0 : window_base,
      sha3_root,
      signedRoots,
      maxSignedSize,
    });
    if (refusal) { refused.push({ i, ...refusal }); continue; }

    const key = asOld ? `0:${tree_size}` : sthKey(head);
    signedRoots.set(key, sha3_root);
    const logical = asOld ? tree_size : sthLogicalSize(head);
    if (logical > maxSignedSize) maxSignedSize = logical;
    signed.push(head);
  }
  return { signed, refused, logSize: w.size };
}

test('keyed on tree_size alone, every head past the wrap is refused', () => {
  // The bug, stated as a measurement. Window of 4, twelve appends.
  const { signed, refused, logSize } = run({ windowSize: 4, appends: 12, keyBy: 'size' });
  assert.strictEqual(logSize, 12, 'the log grew to twelve either way');
  assert.strictEqual(signed.length, 5, 'only the heads up to and including the full window were signed');
  assert.strictEqual(refused.length, 7, 'every append after that was refused');
  assert.strictEqual(refused[0].reason, 'root_differs_at_same_size',
    'and refused for the reason that reads exactly like tampering');
});

test('keyed on the window it covers, the relay keeps signing', () => {
  const { signed, refused, logSize } = run({ windowSize: 4, appends: 12, keyBy: 'pair' });
  assert.strictEqual(refused.length, 0, `nothing was refused: ${JSON.stringify(refused)}`);
  assert.strictEqual(signed.length, 12, 'one head per append, all twelve');
  assert.strictEqual(logSize, 12);

  // Each head says which leaves it covers, and the last one describes the
  // window as it stands, not the log.
  const last = signed[signed.length - 1];
  assert.strictEqual(last.tree_size, 5, 'the tree is the window plus the new leaf');
  assert.strictEqual(last.window_base, 7, 'and it starts where the window starts');
  assert.strictEqual(sthLogicalSize(last), 12, 'base plus size is the size of the log');
});

test('the logical size never walks backwards, and no tree gets two roots', () => {
  const { signed } = run({ windowSize: 4, appends: 12, keyBy: 'pair' });
  const sizes = signed.map(sthLogicalSize);
  for (let i = 1; i < sizes.length; i++) {
    assert.ok(sizes[i] >= sizes[i - 1], `head ${i} went backwards: ${sizes[i - 1]} then ${sizes[i]}`);
  }
  const roots = new Map();
  for (const h of signed) {
    const k = sthKey(h);
    assert.ok(!roots.has(k) || roots.get(k) === h.sha3_root, `two roots for one tree at ${k}`);
    roots.set(k, h.sha3_root);
  }
  assert.strictEqual(roots.size, signed.length, 'every head describes a distinct tree');
});

test('a genuine contradiction is still refused', () => {
  // The guard must not have been loosened into uselessness. Same tree, other
  // root: that is the fork it exists to catch.
  const signedRoots = new Map([['0:5', 'a'.repeat(64)]]);
  const refusal = sthRefusal({
    tree_size: 5, window_base: 0, sha3_root: 'b'.repeat(64),
    signedRoots, maxSignedSize: 5,
  });
  assert.ok(refusal, 'a second, different root for one tree is refused');
  assert.strictEqual(refusal.reason, 'root_differs_at_same_size');

  // And re-signing the SAME root for the same tree stays allowed.
  assert.strictEqual(
    sthRefusal({ tree_size: 5, window_base: 0, sha3_root: 'a'.repeat(64), signedRoots, maxSignedSize: 5 }),
    null,
    'signing the same root again is idempotent, not a contradiction');
});

test('a log that shrank is still refused', () => {
  // The other half of the guard: the head window can prune the map, so this is
  // checked against a number that is never pruned. With the pair key that
  // number is the LOGICAL size, or a wrapped window would look like a shrink
  // on every append.
  const refusal = sthRefusal({
    tree_size: 3, window_base: 0, sha3_root: 'c'.repeat(64),
    signedRoots: new Map(), maxSignedSize: 900,
  });
  assert.ok(refusal, 'a tree smaller than one already signed is refused');
  assert.strictEqual(refusal.reason, 'tree_size_went_backwards');
});

test('heads signed before window_base existed are read as starting at leaf 0', () => {
  // Version 1 heads carry no window_base. They were signed while the window had
  // not wrapped, so leaf 0 is exactly where their tree started, and reading
  // them that way keeps their guarantee whole across the upgrade.
  assert.strictEqual(sthKey({ tree_size: 42 }), '0:42');
  assert.strictEqual(sthLogicalSize({ tree_size: 42 }), 42);
  assert.strictEqual(sthKey({ tree_size: 42, window_base: 7 }), '7:42');
  assert.strictEqual(sthLogicalSize({ tree_size: 42, window_base: 7 }), 49);
});
