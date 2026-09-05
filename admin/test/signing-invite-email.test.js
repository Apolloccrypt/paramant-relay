'use strict';

const assert = require('node:assert');
const { signingInviteEmail } = require('../lib/email-templates');

// The invitation mail is posted to a mail provider incorporated in the United
// States. Six sentences on paramant.app promise that no US party ever holds a
// key, and /dpa promises filenames are never handled in readable form. This
// file is the gate on both promises for the one message that leaves the EU.
//
// Every call below deliberately hands the template the very things it must not
// pass on: a complete link with the document key in the fragment, and a
// filename. If the template ever starts trusting its caller again, these fail.

const key = 'k'.repeat(43);
const token = 't'.repeat(43);
const base = `https://paramant.app/co-sign?env=env_demo_abcdefghijklmnop&p=0&t=${token}`;
const withKey = `${base}#doc=v1.${key}`;

const mail = signingInviteEmail({
  inviteUrl: withKey,
  recipientLabel: '<Signer Demo>',
  senderLabel: 'sender@example.com',
  documentName: 'opzegging-huurcontract.pdf',   // ignored by the template; proves it
  expiresAt: '2026-07-28T12:00:00.000Z',
  subject: 'Please sign the agreement',
  message: '<review before signing>',
  envelopeId: 'env_demo_abcdefghijklmnop',
  partyIndex: 0,
});

const everything = [mail.text, mail.html, mail.subject, JSON.stringify(mail.headers)].join('\n');

assert.equal(mail.subject, 'Please sign the agreement');
assert.ok(!everything.includes(key), 'no part of the mail carries the document key');
assert.ok(!everything.includes('#doc='), 'no part of the mail carries a key fragment');
assert.ok(!everything.includes('opzegging-huurcontract'), 'no part of the mail carries the filename');
assert.ok(mail.text.includes(base), 'plain text carries the link to the request itself');
assert.ok(mail.html.includes(base), 'HTML action carries the link to the request itself');
assert.ok(/It does not open the document/.test(mail.text), 'the mail says what the link cannot do');
assert.ok(mail.text.includes('Sign in with this invited email address'), 'identity requirement is explicit');
assert.ok(!mail.html.includes('<Signer Demo>'), 'recipient label is HTML escaped');
assert.ok(!mail.html.includes('<review before signing>'), 'message is HTML escaped');
assert.ok(!mail.headers['X-Entity-Ref-ID'].includes(token), 'mail header does not expose invite token');
assert.ok(!mail.headers['X-Entity-Ref-ID'].includes(key), 'mail header does not expose document key');

// The default subject is the other way a filename used to reach the provider:
// the sender's browser prefilled it with 'Please sign: <filename>'.
const noSubject = signingInviteEmail({
  inviteUrl: withKey, senderLabel: 'sender@example.com',
  documentName: 'opzegging-huurcontract.pdf',
  envelopeId: 'env_demo_abcdefghijklmnop', partyIndex: 0,
});
assert.equal(noSubject.subject, 'Signature requested', 'the default subject names no document');
assert.ok(!noSubject.text.includes(key) && !noSubject.html.includes(key), 'and still carries no key');

console.log('signing-invite-email: 14 checks passed');
