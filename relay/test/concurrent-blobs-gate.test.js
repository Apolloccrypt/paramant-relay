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

test('the numbers match the single source of truth', () => {
  for (const plan of ['community', 'pro', 'business', 'enterprise']) {
    assert.equal(limitsFor(plan).concurrent_blobs,
                 tiers.tierLimitNum(plan, 'concurrent_blobs'),
                 plan + ' drifted away from tiers.js');
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
                 tiers.tierLimitNum('community', 'concurrent_blobs'),
                 'a plan nobody recognises must get the smallest ceiling');
  }
});
