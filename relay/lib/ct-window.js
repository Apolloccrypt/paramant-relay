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

  // The most recent `n` entries (for the /ct feed).
  recent(n) { return this.entries.slice(-n); }

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

module.exports = { CtWindow };
