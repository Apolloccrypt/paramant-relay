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
assert.equal(noSubject.subject, 'Verzoek om te ondertekenen / Signature requested', 'the default subject names no document, in both languages');
assert.ok(!noSubject.text.includes(key) && !noSubject.html.includes(key), 'and still carries no key');

// Dutch first, English underneath, unless the caller names one language.
assert.ok(mail.text.indexOf('Log in met het e-mailadres waarop u bent uitgenodigd') < mail.text.indexOf('Sign in with this invited email address'), 'Dutch comes before English');
assert.ok(/Hij opent het document niet/.test(mail.text), 'the Dutch text says what the link cannot do');
assert.ok(/<html lang="nl">/.test(mail.html), 'the bilingual mail is marked Dutch first');
const onlyEn = signingInviteEmail({ inviteUrl: withKey, envelopeId: 'env_demo_abcdefghijklmnop', partyIndex: 0, lang: 'en' });
assert.equal(onlyEn.subject, 'Signature requested', 'lang en keeps the English default subject');
assert.ok(!/Hij opent het document niet/.test(onlyEn.text) && /It does not open the document/.test(onlyEn.text), 'lang en is English only');
const onlyNl = signingInviteEmail({ inviteUrl: withKey, envelopeId: 'env_demo_abcdefghijklmnop', partyIndex: 0, lang: 'nl' });
assert.equal(onlyNl.subject, 'Verzoek om te ondertekenen', 'lang nl has the Dutch default subject');
assert.ok(!/It does not open the document/.test(onlyNl.text) && !onlyNl.text.includes(key) && !onlyNl.html.includes(key), 'lang nl is Dutch only and carries no key');

console.log('signing-invite-email: 22 checks passed');

// Since 2026-10-04: a link with HALF a split key ('#ks=') opens the document
// for the signed-in invitee. The share survives into the mail; a whole key
// next to it does not, and the text says the link opens the document.
{
  const share = 's'.repeat(43);
  const shareMail = signingInviteEmail({ inviteUrl: `${base}#ks=v1.${share}`, senderLabel: 'sender@example.com', envelopeId: 'env_demo_abcdefghijklmnop', partyIndex: 0 });
  assert.ok(shareMail.text.includes(`${base}#ks=v1.${share}`), 'the key share rides in the link');
  assert.ok(/opens the document in your browser once you have signed in/.test(shareMail.text), 'and the mail says the link opens the document');
  assert.ok(/opent het document in uw browser zodra u bent ingelogd/.test(shareMail.text), 'in Dutch too');
  const sneaky = signingInviteEmail({ inviteUrl: `${base}#ks=v1.${share}&doc=v1.${key}`, senderLabel: 'x', envelopeId: 'e', partyIndex: 0 });
  assert.ok(!(sneaky.text + sneaky.html).includes(key), 'a whole key smuggled next to a share is cut off');
  assert.ok(/It does not open the document/.test(sneaky.text), 'and that mail falls back to the notice');
}

// Retest 04-10: the mail promised "zet uw paraaf" also when the sender asked
// for no paraaf. It is only named when the request carries an all_pages field.
{
  const share = 's'.repeat(43);
  const url = `${base}#ks=v1.${share}`;
  const plain = signingInviteEmail({ inviteUrl: url, senderLabel: 'x', envelopeId: 'e', partyIndex: 0 });
  assert.ok(!/paraaf/i.test(plain.text + plain.html) && !/initials/i.test(plain.text + plain.html), 'no paraaf asked: the mail promises none');
  assert.ok(/zet uw handtekening en bent klaar/.test(plain.text) && /add your signature, and you are done/.test(plain.text), 'it names the signature only');
  const withParaaf = signingInviteEmail({ inviteUrl: url, senderLabel: 'x', envelopeId: 'e', partyIndex: 0, asksParaaf: true });
  assert.ok(/zet uw paraaf en handtekening/.test(withParaaf.text) && /add your initials and signature/.test(withParaaf.text), 'paraaf asked: the mail names it');
}
