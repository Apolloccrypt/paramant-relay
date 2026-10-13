'use strict';

// How many people may sign one document. Two ceilings meet here: the plan says
// what an account bought, MAX_PARTIES says what one document can carry however
// much you pay. The lower one wins.
//
// The rule these tests exist for: raising a ceiling must never lower one. Every
// account could already put twenty names on a document, so twenty stays the
// floor on every row and thirty is what the paid rows add.

const assert = require('node:assert/strict');
const test = require('node:test');

const tiers = require('../lib/tiers');
const envelopeMod = require('../envelope');

test('twenty stays the floor for everyone, including the free row', () => {
  for (const plan of ['community', 'free', 'dev', undefined, null, 'nonsense']) {
    assert.equal(tiers.tierLimitNum(plan, 'max_parties'), 20,
      'a plan nobody recognises must not take twenty away from anyone');
  }
});

test('the paid rows go to thirty', () => {
  assert.equal(tiers.tierLimitNum('pro', 'max_parties'), 20, 'pro keeps twenty');
  assert.equal(tiers.tierLimitNum('business', 'max_parties'), 30);
  assert.equal(tiers.tierLimitNum('enterprise', 'max_parties'), 30);
  assert.equal(tiers.tierLimitNum('licensed', 'max_parties'), 30,
    'licensed self-host is enterprise');
});

test('thirty is the hard ceiling for one document', () => {
  assert.equal(envelopeMod.MAX_PARTIES, 30);
  for (const plan of Object.keys(tiers.TIER_LIMITS)) {
    assert.ok(tiers.tierLimitNum(plan, 'max_parties') <= envelopeMod.MAX_PARTIES,
      'no plan may promise more than a document can carry');
  }
});

test('the two ceilings are consistent with the send side', () => {
  // A document signed by thirty and a file sent to thirty are the same size of
  // group on purpose. If one moves, the other has to be considered too.
  for (const plan of ['business', 'enterprise']) {
    assert.equal(tiers.tierLimitNum(plan, 'max_parties'),
                 tiers.tierLimitNum(plan, 'max_recipients'),
                 'signing and sending describe the same room on paid rows');
  }
});

test('every plan carries the field, so nobody falls through to a default', () => {
  for (const [naam, limieten] of Object.entries(tiers.TIER_LIMITS)) {
    assert.equal(typeof limieten.max_parties, 'number', naam + ' has no max_parties');
    assert.ok(limieten.max_parties >= 20, naam + ' may not drop below the old twenty');
  }
});
