'use strict';

// A send with named recipients. One blob, one token per person, one pickup
// each. These tests pin the behaviour a sender relies on: nobody else can
// collect in your name, a second click gives nothing, and the sender can see
// who is still outstanding.

const assert = require('node:assert/strict');
const test = require('node:test');

const rec = require('../lib/recipients');

const three = ['anna@example.org', 'bob@example.org', 'carla@example.org'];

test('every recipient gets their own token, and tokens are not stored', () => {
  const built = rec.buildRecipients('business', three);
  assert.equal(built.ok, true);
  assert.equal(built.records.length, 3);

  const tokens = Object.values(built.tokens);
  assert.equal(new Set(tokens).size, 3, 'three different tokens');

  const raw = JSON.stringify(built.records);
  for (const t of tokens) {
    assert.ok(!raw.includes(t), 'the plain token is never part of what we store');
  }
  for (const r of built.records) {
    assert.match(r.token_hash, /^[a-f0-9]{64}$/);
    assert.match(r.email_hash, /^[a-f0-9]{64}$/);
    assert.equal(r.picked_up_at, null);
  }
});

test('a token collects once; the second attempt is refused', () => {
  const built = rec.buildRecipients('business', three);
  const token = built.tokens['bob@example.org'];

  // claimPickup is the only way in: looking up and claiming in one step is what
  // keeps two simultaneous requests from both passing the check.
  const found = rec.claimPickup(built.records, token, 1000);
  assert.equal(found.email, 'bob@example.org', 'the token points at one person');
  assert.equal(found.picked_up_at, 1000);

  assert.equal(rec.claimPickup(built.records, token, 2000), null,
    'a double click gets nothing');
  assert.equal(found.picked_up_at, 1000, 'and does not move the timestamp');
  assert.equal(rec.markPickedUp(found, 3000, token), false,
    'nor does the low-level call, even with the right token');
});

test('one person collecting does not touch anybody else', () => {
  const built = rec.buildRecipients('business', three);
  rec.claimPickup(built.records, built.tokens['anna@example.org'], 1000);

  const view = rec.overview(built.records);
  assert.equal(view.collected, 1);
  assert.equal(view.outstanding, 2);
  assert.equal(rec.allSettled(built.records), false, 'the file stays for the others');
});

test('an unknown or empty token finds nobody', () => {
  const built = rec.buildRecipients('pro', three);
  for (const bad of [rec.newPickupToken(), '', null, undefined, 'x']) {
    assert.equal(rec.findByToken(built.records, bad), null);
  }
  assert.equal(rec.pickupRefusal(null), 'unknown_token');
});

test('revoking one person leaves the rest working', () => {
  const built = rec.buildRecipients('business', three);
  const carla = rec.findByToken(built.records, built.tokens['carla@example.org']);
  assert.equal(rec.revoke(carla, 500), true);
  assert.equal(rec.pickupRefusal(carla), 'revoked');
  assert.equal(rec.revoke(carla, 900), false, 'revoking twice is not an event');

  const anna = rec.findByToken(built.records, built.tokens['anna@example.org']);
  assert.equal(rec.pickupRefusal(anna), null, 'anna is unaffected');

  const view = rec.overview(built.records);
  assert.equal(view.revoked, 1);
  assert.equal(view.outstanding, 2);
});

test('re-inviting mints a new token and kills the old one', () => {
  const built = rec.buildRecipients('business', three);
  const oud = built.tokens['bob@example.org'];
  const bob = rec.findByToken(built.records, oud);

  const nieuw = rec.reinvite(bob, 700);
  assert.ok(nieuw && nieuw !== oud);
  assert.equal(rec.findByToken(built.records, oud), null, 'the old link is dead');
  assert.equal(rec.findByToken(built.records, nieuw).email, 'bob@example.org');
  assert.equal(bob.reminders, 1);
  // The killed link must not work even for a request that still holds the
  // record: that was the hole, and it is why the token is now required here.
  assert.equal(rec.markPickedUp(bob, 800, oud), false, 'the dead token cannot collect');

  rec.claimPickup(built.records, nieuw, 900);
  assert.equal(rec.reinvite(bob, 1000), null, 'no re-invite after collection');
});

test('the blob may go once everyone has collected or been revoked', () => {
  const built = rec.buildRecipients('business', three);
  assert.equal(rec.allSettled([]), false, 'an empty table is not a finished send');

  rec.claimPickup(built.records, built.tokens['anna@example.org'], 100);
  rec.claimPickup(built.records, built.tokens['bob@example.org'], 200);
  assert.equal(rec.allSettled(built.records), false);

  rec.revoke(rec.findByToken(built.records, built.tokens['carla@example.org']));
  assert.equal(rec.allSettled(built.records), true,
    'collected plus revoked means nobody is still waiting');
});

test('the plan decides how many people a send may reach', () => {
  const twenty = Array.from({ length: 20 }, (_, i) => `p${i}@example.org`);
  const free = rec.buildRecipients('community', twenty);
  assert.equal(free.ok, false);
  assert.equal(free.reason, 'over_limit');
  assert.equal(free.limit, 1);
  assert.equal(free.records.length, 0, 'nothing is built for a refused send');
  // It also stops counting at the ceiling instead of normalising the whole
  // list first: a refused send must not be free work for whoever asked.
  assert.ok(free.asked <= free.limit + 1,
    'the refusal does not walk the entire list');

  assert.equal(rec.buildRecipients('business', twenty).ok, true);
});

test('the same address written three ways is one recipient', () => {
  const built = rec.buildRecipients('pro',
    [' Anna@Example.org', 'anna@example.org', 'ANNA@EXAMPLE.ORG ']);
  assert.equal(built.records.length, 1);
  assert.equal(built.records[0].email, 'anna@example.org');
  assert.equal(Object.keys(built.tokens).length, 1);
});

test('the overview shows people, never hashes or tokens', () => {
  const built = rec.buildRecipients('business', three);
  const view = rec.overview(built.records);
  const raw = JSON.stringify(view);
  assert.ok(!raw.includes('token_hash') && !raw.includes('email_hash'));
  assert.deepEqual(view.recipients.map(r => r.status), ['waiting', 'waiting', 'waiting']);
  assert.equal(view.total, 3);
});
