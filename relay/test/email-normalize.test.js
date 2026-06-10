'use strict';
// Unit tests for the trial rate-limit e-mail normalizer (#13).
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeEmailForRateLimit } = require('../lib/email-normalize');

const N = normalizeEmailForRateLimit;

test('gmail dots and plus-tags collapse to one mailbox', () => {
  const canonical = 'jdoe@gmail.com';
  assert.equal(N('jdoe@gmail.com'), canonical);
  assert.equal(N('j.doe@gmail.com'), canonical);
  assert.equal(N('j.d.o.e@gmail.com'), canonical);
  assert.equal(N('jdoe+trial1@gmail.com'), canonical);
  assert.equal(N('J.Doe+anything@Gmail.com'), canonical);
  assert.equal(N('jdoe@googlemail.com'), canonical); // googlemail -> gmail
});

test('plus-tags are dropped for non-gmail providers too', () => {
  assert.equal(N('alice+promo@outlook.com'), 'alice@outlook.com');
  assert.equal(N('bob+x@fastmail.com'), 'bob@fastmail.com');
});

test('dots are preserved for non-gmail providers (distinct mailboxes)', () => {
  assert.notEqual(N('a.b@outlook.com'), N('ab@outlook.com'));
  assert.equal(N('a.b@outlook.com'), 'a.b@outlook.com');
});

test('distinct mailboxes stay distinct', () => {
  assert.notEqual(N('alice@gmail.com'), N('bob@gmail.com'));
  assert.notEqual(N('alice@gmail.com'), N('alice@outlook.com'));
});

test('case and whitespace normalized', () => {
  assert.equal(N('  Alice@Example.COM '), 'alice@example.com');
});

test('malformed / edge inputs do not throw and never collapse to bare domain', () => {
  assert.equal(N(''), '');
  assert.equal(N('notanemail'), 'notanemail');
  assert.equal(N(null), '');
  assert.equal(N('+tag@gmail.com'), '+tag@gmail.com'); // empty local -> left as-is, not "@gmail.com"
  assert.equal(N('a@'), 'a@');
});
