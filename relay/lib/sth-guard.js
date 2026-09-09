'use strict';
// The rule that decides whether a signed tree head may be produced, pulled out
// of relay.js so it can be exercised without booting a relay. Same reason
// ct-window.js and ct-hash.js live here: the transparency chain is the part
// where a quiet mistake is worst, so its rules should be readable and testable
// on their own.
//
// WHAT IT GUARDS. A transparency log's whole claim is that a size, once
// signed, keeps its root for ever. Break that and the relay publishes two
// signed, contradictory heads under one key, which no verifier can tell apart
// from tampering.
//
// WHY THE KEY IS A PAIR. The Merkle tree here does not cover the whole log. It
// covers the CT_MAX most recent leaves, and that window slides. Once it is
// full the leaf count stops growing while the root changes on every append, so
// keyed on tree_size alone the guard sees the same size with a different root
// and calls it a fork. It is not one: it is a different tree.
//
// Reproduced with a window of 4, before this existed:
//
//   append 4  | log  5 | tree_size 5 | signed
//   append 5  | log  6 | tree_size 5 | REFUSED  root_differs_at_same_size
//   append 6  | log  7 | tree_size 5 | REFUSED
//   append 7+ | ...    | tree_size 5 | REFUSED, for ever
//
// The log kept growing, the relay signed nothing more, and it flagged itself
// as forked while doing it. On production the window holds ten thousand leaves
// and the log stood at 4814, so this was a date, not a fault anyone had met.
//
// So a tree is identified by (window_base, tree_size), and the thing that must
// only ever grow is their sum: the logical size of the log.

// The map key for one tree. Heads signed before window_base existed describe a
// tree that starts at leaf 0, which is what they were: the window had not
// wrapped yet. Reading a missing base as 0 keeps their guarantee intact.
function sthKey(head) {
  return `${head.window_base || 0}:${head.tree_size}`;
}

// The logical size of the log at the moment a head was signed.
function sthLogicalSize(head) {
  return (head.window_base || 0) + head.tree_size;
}

// May this head be signed? Returns null when it may, or the reason when it may
// not. `signedRoots` maps sthKey -> root for the heads still remembered;
// `maxSignedSize` is the largest logical size ever signed, which survives the
// pruning of that map and is what catches a log that walked backwards.
//
// Re-signing the SAME root for the SAME tree is allowed: that is idempotent,
// not a contradiction.
function sthRefusal({ tree_size, window_base, sha3_root, signedRoots, maxSignedSize }) {
  const base = Number.isFinite(window_base) ? window_base : 0;
  const logicalSize = base + tree_size;
  const priorRoot = signedRoots.get(`${base}:${tree_size}`);
  if (priorRoot !== undefined && priorRoot !== sha3_root) {
    return { reason: 'root_differs_at_same_size', priorRoot, logicalSize, base };
  }
  if (logicalSize < maxSignedSize) {
    return { reason: 'tree_size_went_backwards', priorRoot: priorRoot || null, logicalSize, base };
  }
  return null;
}

module.exports = { sthKey, sthLogicalSize, sthRefusal };
