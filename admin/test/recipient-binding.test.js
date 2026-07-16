'use strict';
// Unit test for admin/lib/recipient-binding.buildRecipientParties (audit 1.1).
// Proves envelope creation refuses co-signer rows that would produce an
// email-bound slot nobody can ever sign (empty or malformed email), instead of
// the old behaviour that silently dropped them into a dead-end invite.
// Run: node admin/test/recipient-binding.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { buildRecipientParties, RECIPIENT_EMAIL_RE } = require('../lib/recipient-binding');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// (a) DEAD-END GUARD: a named recipient with NO email is rejected (400 code),
//     never turned into a party. This is the core audit-1.1 fix.
{
  const r = buildRecipientParties([{ label: 'Alice', email: '' }]);
  assert.strictEqual(r.error, 'recipient_email_required', 'empty email rejected');
  assert.strictEqual(r.parties, undefined, 'no parties returned on rejection');
  ok('(a) recipient with empty email -> clean rejection, no dead-end slot');
}

// (a2) A malformed email (the classic typo the old "reference only" copy invited)
//      is likewise rejected up front, not minted into an unsignable slot.
for (const bad of ['not-an-email', 'a@b', 'alice@', '@example.com', 'a b@example.com']) {
  const r = buildRecipientParties([{ label: 'Bob', email: bad }]);
  assert.strictEqual(r.error, 'recipient_email_required', 'malformed rejected: ' + bad);
}
ok('(a2) malformed emails rejected before envelope creation');

// (b-create) A valid recipient is accepted and normalised (trim + length caps),
//            producing exactly the party slot the co-signer can later match.
{
  const r = buildRecipientParties([{ label: '  Carol  ', email: '  Carol@Example.COM  ' }]);
  assert.strictEqual(r.error, undefined, 'valid recipient accepted');
  assert.deepStrictEqual(r.parties, [{ label: 'Carol', email: 'Carol@Example.COM' }],
    'label + email trimmed, email preserved for downstream partyEmailHash');
  ok('(b) valid recipient accepted + trimmed');
}

// Multiple valid recipients preserve order; one bad row fails the whole batch
// (no partial dead-end envelope).
{
  const okAll = buildRecipientParties([
    { label: 'A', email: 'a@x.com' }, { label: 'B', email: 'b@x.com' },
  ]);
  assert.strictEqual(okAll.parties.length, 2, 'both valid recipients kept');
  const mixed = buildRecipientParties([
    { label: 'A', email: 'a@x.com' }, { label: 'B', email: '' },
  ]);
  assert.strictEqual(mixed.error, 'recipient_email_required', 'one bad row rejects the batch');
  ok('order preserved; one invalid row rejects the whole create');
}

// A fully-blank row (no label, no email) is ignored, matching the frontend
// which drops blank rows - this must NOT block a self-sign / valid batch.
{
  const r = buildRecipientParties([{ label: '', email: '' }, { label: 'D', email: 'd@x.com' }]);
  assert.strictEqual(r.error, undefined, 'blank row ignored, not an error');
  assert.strictEqual(r.parties.length, 1, 'only the real recipient becomes a party');
  ok('fully-blank rows ignored, real recipients still pass');
}

// Non-array / empty input -> no parties, no error (self-sign has zero recipients).
{
  assert.deepStrictEqual(buildRecipientParties(undefined), { parties: [] }, 'undefined -> empty');
  assert.deepStrictEqual(buildRecipientParties([]), { parties: [] }, 'empty array -> empty');
  ok('empty/undefined recipients -> empty party list (self-sign path intact)');
}

// The regex is the same shape admin/server.js already enforces on signup/login.
assert.ok(RECIPIENT_EMAIL_RE.test('x@y.zz') && !RECIPIENT_EMAIL_RE.test('x@y'), 'regex shape sane');
ok('email regex shape matches the signup/login validator');

console.log(`\nrecipient-binding: ${passed} checks passed`);
