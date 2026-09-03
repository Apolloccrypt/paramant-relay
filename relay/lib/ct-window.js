'use strict';
// Bounded, monotonically-indexed CT-log window (D2).
//
// The CT log keeps at most `max` recent entries in memory and rebuilds its
// Merkle tree over that window on every append. The old code used
// `index = ctLog.length` and `ctLog.shift()`, so once the window was full the
// index froze at `max` (duplicate indices, frozen STH tree_size) and the
// positional lookup `ctLog[idx]` returned the wrong entry after the first shift.
//
// CtWindow separates the two numbers that were conflated:
//   - logical index  : monotonic, never reused, = base + position. Public
//                       ct_log_index that clients (parasign notary) hold.
//   - window position : 0..windowLength-1, where the Merkle tree/proof live.
// An entry whose logical index has aged out of the window returns null on
// lookup (honestly "pruned") instead of a wrong or duplicate-indexed entry.
//
// POSITION IS THE AUTHORITY (2026-09). An entry also carries a stored .index
// field, written once at append time and persisted with the entry. That field
// is a cache, not a source of truth: a rebuild or migration of the persisted
// log can leave it stale while order and leaf_hashes are perfectly fine, which
// is exactly what happened on the public log (five entries at positions 42..46
// carried indices 4..8, so the listing showed duplicates while /v2/ct/proof,
// which resolves by position, kept answering correctly). Every read path that
// hands an index out therefore derives it from the position -- page(),
// recentPage() and logicalIndexAt() exist for that -- and reindex() /
// reindexEntries() repair the stored field so the two can no longer diverge.
class CtWindow {
  constructor(max) {
    this.max = max;
    this.entries = [];   // the retained window, oldest first
    this.base = 0;       // logical index of entries[0]
  }

  // Total number of entries ever appended (monotonic). This is what the STH
  // tree_size and the /ct feed size report as "how far the log has advanced".
  get size() { return this.base + this.entries.length; }

  // Number of leaves currently in the window (== the Merkle tree leaf count).
  get windowLength() { return this.entries.length; }

  // The logical index the next append() will receive.
  nextIndex() { return this.base + this.entries.length; }

  // Window position for a logical index, or -1 if it is outside the window.
  position(logicalIndex) {
    const p = logicalIndex - this.base;
    return (p >= 0 && p < this.entries.length) ? p : -1;
  }

  // The logical index of the entry at window position `p`. This, not the
  // stored .index field, is what a caller must publish for an entry.
  logicalIndexAt(position) { return this.base + position; }

  // Retrieve an entry by its logical index, or null if pruned/absent.
  get(logicalIndex) {
    const p = this.position(logicalIndex);
    return p === -1 ? null : this.entries[p];
  }

  last() { return this.entries.length ? this.entries[this.entries.length - 1] : null; }

  // Append a pre-built entry. Its .index MUST already equal nextIndex() (the
  // caller sets it before building leaf/tree/proof). Enforces the cap, advancing
  // base so logical indices stay monotonic.
  append(entry) {
    if (entry.index !== this.nextIndex()) {
      throw new Error(`CtWindow.append: entry.index ${entry.index} != nextIndex ${this.nextIndex()}`);
    }
    this.entries.push(entry);
    if (this.entries.length > this.max) { this.entries.shift(); this.base++; }
    return entry;
  }

  // Up to `count` entries starting at a logical index (for /v2/ct/log paging).
  // Clamps to the retained window; entries below base are pruned.
  sliceByIndex(fromLogical, count) {
    const start = Math.max(0, fromLogical - this.base);
    return this.entries.slice(start, start + count);
  }

  // sliceByIndex plus the logical index the first returned entry actually sits
  // at, so a listing can number its rows `start_index + i` instead of trusting
  // the stored .index field. `from` below base clamps to base, so start_index
  // is what the caller got, not what it asked for.
  page(fromLogical, count) {
    const start = Math.max(0, fromLogical - this.base);
    return { start_index: this.base + start, entries: this.entries.slice(start, start + count) };
  }

  // The most recent `n` entries (for the /ct feed).
  recent(n) { return this.entries.slice(-n); }

  // recent(n) with the logical index of its first entry, same reason as page().
  recentPage(n) {
    const start = Math.max(0, this.entries.length - n);
    return { start_index: this.base + start, entries: this.entries.slice(start) };
  }

  // One-shot repair of the retained window: force every stored .index back to
  // its position (base + p). Returns how many were wrong. Order, leaf_hash and
  // tree_hash are never touched, so the Merkle root over the window is
  // byte-identical before and after. Idempotent: a second call returns 0.
  reindex() { return reindexEntries(this.entries); }

  // Rehydrate from a persisted list (oldest first). Each entry carries its own
  // monotonic .index; base is taken from the first retained entry. Trims to the
  // cap, keeping the newest.
  load(list) {
    const arr = Array.isArray(list) ? list.filter(e => e && typeof e === 'object' && !Array.isArray(e)) : [];
    const trimmed = arr.length > this.max ? arr.slice(arr.length - this.max) : arr;
    this.entries = trimmed;
    this.base = trimmed.length && Number.isInteger(trimmed[0].index) ? trimmed[0].index : 0;
  }
}

// Recount a persisted, oldest-first entry list in place so every entry's stored
// .index equals its position relative to the first entry's index. The first
// entry is the anchor by definition: nothing else on disk says where a rotated
// or trimmed file starts, so its own index is taken at face value (0 when it
// has none). Returns the number of entries whose field was wrong. Only .index
// is written; order and leaf_hashes are left alone, which is what keeps the
// Merkle root identical. Idempotent.
function reindexEntries(list) {
  if (!Array.isArray(list) || list.length === 0) return 0;
  const first = list[0];
  const anchor = first && Number.isInteger(first.index) ? first.index : 0;
  let fixed = 0;
  for (let p = 0; p < list.length; p++) {
    const entry = list[p];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const want = anchor + p;
    if (entry.index !== want) { entry.index = want; fixed++; }
  }
  return fixed;
}

module.exports = { CtWindow, reindexEntries };
