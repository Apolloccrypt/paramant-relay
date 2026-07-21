'use strict';

const assert = require('node:assert');
const { signingInviteEmail } = require('../lib/email-templates');

const key = 'k'.repeat(43);
const token = 't'.repeat(43);
const url = `https://paramant.app/co-sign?env=env_demo_abcdefghijklmnop&p=0&t=${token}#doc=v1.${key}`;
const mail = signingInviteEmail({
  inviteUrl: url,
  recipientLabel: '<Signer Demo>',
  senderLabel: 'sender@example.com',
  documentName: 'agreement-demo.pdf',
  expiresAt: '2026-07-28T12:00:00.000Z',
  subject: 'Please sign the agreement',
  message: '<review before signing>',
  envelopeId: 'env_demo_abcdefghijklmnop',
  partyIndex: 0,
});

assert.equal(mail.subject, 'Please sign the agreement');
assert.ok(mail.text.includes(url), 'plain text contains complete personal link');
assert.ok(mail.text.includes('Sign in with this invited email address'), 'identity requirement is explicit');
assert.ok(mail.html.includes(url), 'HTML action contains complete personal link');
assert.ok(!mail.html.includes('<Signer Demo>'), 'recipient label is HTML escaped');
assert.ok(!mail.html.includes('<review before signing>'), 'message is HTML escaped');
assert.ok(!mail.headers['X-Entity-Ref-ID'].includes(token), 'mail header does not expose invite token');
assert.ok(!mail.headers['X-Entity-Ref-ID'].includes(key), 'mail header does not expose document key');

console.log('signing-invite-email: 8 checks passed');
