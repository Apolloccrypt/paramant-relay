'use strict';

// The capacity ceiling that was written and never fired.
//
// relay.js refuses an upload when an account already holds more blobs than its
// plan allows. It reads that number off the entitlements object, and the field
// was never put there: undefined, Number.isFinite(undefined) is false, guard
// skipped on every request since the day it was written.
//
// Blobs live in RAM and only in RAM, so this is the single thing that stops one
// tenant from taking the pool. These tests hold the wiring in place, because
// the failure mode is silence: nothing logs, nothing errors, it simply never
// refuses.

const assert = require('node:assert/strict');
const test = require('node:test');

const tiers = require('../lib/tiers');
const entitlements = require('../lib/entitlements');

function limitsFor(plan) {
  const e = entitlements.getEntitlements({ plan });
  return e && e.parasend && e.parasend.limits;
}

test('every plan carries a usable concurrent_blobs ceiling', () => {
  for (const plan of ['community', 'pro', 'business', 'enterprise']) {
    const limits = limitsFor(plan);
    assert.ok(limits, plan + ' has no parasend limits at all');
    assert.ok('concurrent_blobs' in limits,
      plan + ' is missing concurrent_blobs, which is how the guard died');
    const value = limits.concurrent_blobs;
    assert.ok(Number.isFinite(value) || value === Infinity,
      plan + ' has a concurrent_blobs the guard cannot read: ' + String(value));
  }
});

test('the guard condition itself is true for a capped plan', () => {
  // This mirrors the exact test in relay.js. If this assertion fails, the
  // upload path is waving everybody through again.
  for (const plan of ['community', 'pro', 'business']) {
    const value = limitsFor(plan).concurrent_blobs;
    assert.equal(Number.isFinite(value), true,
      plan + ' would skip the ceiling check in relay.js');
  }
});

test('the ceiling never refuses a file the plan sells', () => {
  // NOT the raw table value, and that is the point. Waking the guard up with
  // the numbers as written broke paying customers: the table says 8 blocks on
  // community and 24 on pro, while file_mb says 500 MB on every row, and a
  // 500 MB file is a hundred blocks that all sit there at once when nobody is
  // collecting. Measured: pro failed at its 25th block, community at its 9th
  // transfer. So the ceiling is the plan's own number OR what file_mb already
  // promises, whichever is larger.
  for (const plan of ['community', 'pro', 'business', 'enterprise']) {
    const nu = limitsFor(plan).concurrent_blobs;
    const tabel = tiers.tierLimitNum(plan, 'concurrent_blobs');
    const mb = tiers.tierLimitNum(plan, 'file_mb');
    assert.ok(nu >= tabel, plan + ' fell below its own table value');
    if (Number.isFinite(mb)) {
      const nodig = Math.ceil((mb * 1048576) / (5 * 1048576));
      assert.ok(nu >= nodig,
        plan + ' would refuse a ' + mb + ' MB file it sells: ' + nu + ' blocks, needs ' + nodig);
    }
  }
});

test('enterprise is uncapped, and that is deliberate', () => {
  assert.equal(limitsFor('enterprise').concurrent_blobs, Infinity);
  // Infinity is not finite, so the guard skips it. That is the right outcome
  // for an uncapped row, and it is why the first test accepts either.
  assert.equal(Number.isFinite(limitsFor('enterprise').concurrent_blobs), false);
});

test('an unknown plan lands on community, never on unlimited', () => {
  for (const plan of [undefined, null, '', 'nonsense', 'gold']) {
    assert.equal(limitsFor(plan).concurrent_blobs,
                 limitsFor('community').concurrent_blobs,
                 'a plan nobody recognises must get the community ceiling');
    assert.equal(Number.isFinite(limitsFor(plan).concurrent_blobs), true,
                 'and never unlimited');
  }
});
