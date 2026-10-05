'use strict';

// A send with named recipients. One blob, one token per person, one pickup
// each. These tests pin the behaviour a sender relies on: nobody else can
// collect in your name, a second click gives nothing, and the sender can see
// who is still outstanding.

const assert = require('node:assert/strict');
const test = require('node:test');

const rec = require('../lib/recipients');
const { sealedVoor } = require('./_sealed');

const three = ['anna@example.org', 'bob@example.org', 'carla@example.org'];

test('every recipient gets their own token, and tokens are not stored', () => {
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
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
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
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
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
  rec.claimPickup(built.records, built.tokens['anna@example.org'], 1000);

  const view = rec.overview(built.records);
  assert.equal(view.collected, 1);
  assert.equal(view.outstanding, 2);
  assert.equal(rec.allSettled(built.records), false, 'the file stays for the others');
});

test('an unknown or empty token finds nobody', () => {
  const built = rec.buildRecipients('pro', three, undefined, sealedVoor(three));
  for (const bad of [rec.newPickupToken(), '', null, undefined, 'x']) {
    assert.equal(rec.findByToken(built.records, bad), null);
  }
  assert.equal(rec.pickupRefusal(null), 'unknown_token');
});

test('revoking one person leaves the rest working', () => {
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
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

test('a reminder leaves the link alone, because a new one could not be opened', () => {
  // This used to mint a fresh token, and that destroyed the file for the very
  // person it was meant to help: the file key is wrapped under the OLD token,
  // and the relay cannot re-wrap because it never holds the key. The recipient
  // typed the right code, spent their one-time link, and got bytes nothing
  // could open. So a reminder now points at the invitation they already have.
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
  const token = built.tokens['bob@example.org'];
  const bob = rec.findByToken(built.records, token);

  const uit = rec.reinvite(bob, 700);
  assert.ok(uit && uit.ok, 'a reminder is allowed while they are still waiting');
  assert.equal(bob.reminders, 1);
  assert.equal(bob.reminded_at, 700);

  // The one thing that matters: their link still works, and still opens.
  assert.equal(rec.findByToken(built.records, token).email, 'bob@example.org',
    'the link in their mailbox is the only one there is, and it is untouched');
  assert.equal(bob.wrapped_key, built.records.find(r => r.email === 'bob@example.org').wrapped_key,
    'the wrapping still belongs to the token they hold');
  assert.equal(rec.markPickedUp(bob, 800, token), true, 'and it can still collect');

  assert.equal(rec.reinvite(bob, 1000), null, 'no reminder after collection');
});

test('a token that was never theirs still cannot collect', () => {
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
  const bob = rec.findByToken(built.records, built.tokens['bob@example.org']);
  const anders = built.tokens['anna@example.org'];
  assert.equal(rec.markPickedUp(bob, 800, anders), false,
    'somebody else\'s token must never claim this record');
});

test('the blob may go once everyone has collected or been revoked', () => {
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
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
  const free = rec.buildRecipients('community', twenty, undefined, sealedVoor(twenty));
  assert.equal(free.ok, false);
  assert.equal(free.reason, 'over_limit');
  assert.equal(free.limit, 1);
  assert.equal(free.records.length, 0, 'nothing is built for a refused send');
  // And it names the number she actually listed. The old rule stopped at
  // limit+1, so the page told a sender who had pasted twenty names that she
  // had listed two.
  assert.equal(free.asked, twenty.length,
    'the refusal tells her how many she really listed');

  assert.equal(rec.buildRecipients('business', twenty, undefined, sealedVoor(twenty)).ok, true);
});

test('the same address written three ways is one recipient', () => {
  const drie = [' Anna@Example.org', 'anna@example.org', 'ANNA@EXAMPLE.ORG '];
  // One wrapping, because the sender's browser wraps per NORMALISED address.
  const built = rec.buildRecipients('pro', drie, undefined, sealedVoor(drie));
  assert.equal(built.records.length, 1);
  assert.equal(built.records[0].email, 'anna@example.org');
  assert.equal(Object.keys(built.tokens).length, 1);
});

test('the overview shows people, never hashes or tokens', () => {
  const built = rec.buildRecipients('business', three, undefined, sealedVoor(three));
  const view = rec.overview(built.records);
  const raw = JSON.stringify(view);
  assert.ok(!raw.includes('token_hash') && !raw.includes('email_hash'));
  assert.deepEqual(view.recipients.map(r => r.status), ['waiting', 'waiting', 'waiting']);
  assert.equal(view.total, 3);
});

// ── De onbevestigde ophaling ────────────────────────────────────────────────

test('een ophaling telt pas als de ontvanger bevestigt dat het bestand openging', () => {
  // Een server kan niet zien of bytes zijn aangekomen: een antwoord dat in de
  // socketbuffer past laat 'finish' vuren ook als de client al weg is. Gemeten
  // met 3 MB en een client die na 1 kB wegloopt: Node meldt exact hetzelfde
  // als bij een geslaagde download. Dus telt alleen wat de ontvanger zegt.
  const built = rec.buildRecipients('business', three, 1000, sealedVoor(three));
  const token = built.tokens['bob@example.org'];
  const bob = rec.findByToken(built.records, token);

  assert.ok(rec.claimPickup(built.records, token, 2000), 'de ophaling begint');
  assert.equal(rec.pickupRefusal(bob, 2000), 'already_collected',
    'zolang hij loopt is de link op, anders kon iedereen twee keer');

  // Vijf minuten later zonder bevestiging: de bytes zijn aantoonbaar nergens
  // aangekomen, dus hij krijgt zijn kans terug.
  const later = 2000 + rec.PICKUP_BEVESTIG_MS + 1;
  assert.equal(rec.pickupRefusal(bob, later), null,
    'een haperende verbinding mag niemand zijn enige ophaling kosten');
  assert.ok(rec.claimPickup(built.records, token, later), 'en hij kan opnieuw');
});

test('maar een bevestigde ophaling is voorgoed op', () => {
  const built = rec.buildRecipients('business', three, 1000, sealedVoor(three));
  const token = built.tokens['bob@example.org'];
  const bob = rec.findByToken(built.records, token);

  rec.claimPickup(built.records, token, 2000);
  assert.equal(rec.bevestigPickup(bob, 2100), true);

  const veelLater = 2000 + rec.PICKUP_BEVESTIG_MS * 10;
  assert.equal(rec.pickupRefusal(bob, veelLater), 'already_collected',
    'wie het bestand had, krijgt geen tweede beurt door te wachten');
  assert.equal(rec.claimPickup(built.records, token, veelLater), null);
});

test('bevestigen kan niet zonder ophalen', () => {
  const built = rec.buildRecipients('business', three, 1000, sealedVoor(three));
  const bob = rec.findByToken(built.records, built.tokens['bob@example.org']);
  assert.equal(rec.bevestigPickup(bob, 2000), false,
    'anders kon iemand een link doodverklaren die hij nooit gebruikte');
});
