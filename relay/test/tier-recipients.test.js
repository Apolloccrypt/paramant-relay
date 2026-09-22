'use strict';

// Who may address more than one person is a plan decision, made server side.
// These tests pin that down: the browser can show the field to anybody, the
// answer comes from here.

const assert = require('node:assert/strict');
const test = require('node:test');

const tiers = require('../lib/tiers');

const twenty = Array.from({ length: 20 }, (_, i) => `person${i}@example.org`);

test('community is capped at one named recipient', () => {
  const one = tiers.checkRecipients('community', ['a@example.org']);
  assert.equal(one.ok, true);
  assert.equal(one.limit, 1);

  const many = tiers.checkRecipients('community', twenty);
  assert.equal(many.ok, false, 'a free account cannot address twenty people');
  assert.equal(many.reason, 'over_limit');
  // Counting stops one past the ceiling. Materialising all twenty before saying
  // no was work an outsider could ask for by the hundred thousand.
  assert.ok(many.count > many.limit && many.count <= many.limit + 1,
    'the refusal knows it is over, without walking the whole list');
  assert.deepEqual(many.recipients, [], 'and hands back no addresses');
});

test('the paid rows climb: pro ten, business and enterprise thirty', () => {
  assert.equal(tiers.tierLimitNum('pro', 'max_recipients'), 10);
  assert.equal(tiers.tierLimitNum('business', 'max_recipients'), 30);
  assert.equal(tiers.tierLimitNum('enterprise', 'max_recipients'), 30);

  assert.equal(tiers.checkRecipients('pro', twenty).ok, false, 'twenty is over pro');
  assert.equal(tiers.checkRecipients('business', twenty).ok, true, 'twenty fits business');
});

test('thirty is the ceiling everywhere, enterprise included', () => {
  const thirtyOne = Array.from({ length: 31 }, (_, i) => `p${i}@example.org`);
  assert.equal(tiers.checkRecipients('enterprise', thirtyOne).ok, false,
    'above thirty it is a distribution list, not a send');
});

test('a legacy or missing plan name falls back to community, never to a paid row', () => {
  for (const plan of ['free', 'dev', undefined, null, '', 'nonsense']) {
    const r = tiers.checkRecipients(plan, twenty);
    assert.equal(r.ok, false, `plan ${String(plan)} must not get a paid ceiling`);
    assert.equal(r.limit, 1);
  }
  assert.equal(tiers.tierLimitNum('licensed', 'max_recipients'), 30,
    'licensed self-host is enterprise');
});

test('addresses are normalised and de-duplicated before counting', () => {
  const r = tiers.checkRecipients('pro',
    ['  Anna@Example.org ', 'anna@example.org', 'ANNA@EXAMPLE.ORG', 'bob@example.org']);
  assert.equal(r.ok, true);
  assert.deepEqual(r.recipients, ['anna@example.org', 'bob@example.org']);
  assert.equal(r.count, 2, 'the same person three times is one recipient');
});

test('an empty list is refused, and never silently truncated', () => {
  const r = tiers.checkRecipients('business', ['', '   ', null]);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'empty');

  // The important half: over the limit we reject instead of dropping addresses.
  // Quietly sending to fewer people than asked is the worst failure here.
  const over = tiers.checkRecipients('pro', twenty);
  assert.equal(over.ok, false);
  assert.equal(over.reason, 'over_limit');
  assert.deepEqual(over.recipients, [],
    'nothing is handed back: the caller tells the sender to trim, not who was cut');
});
