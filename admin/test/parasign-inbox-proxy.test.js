'use strict';
// The two admin routes behind "Waiting for your signature", asserted against the
// source of both servers.
//
// What is being pinned is not that the routes work: that is the relay suite's
// job (relay/test/route-parasign-inbox.test.js). It is the three properties a
// working route can still get wrong, and each of them is a sentence somewhere
// else on the site:
//
//   1. the browser never names an account or an address. The inbox forwards the
//      session's own key and the relay derives the address from it; the resend
//      asserts the hash of the SESSION address and mails that same address;
//   2. the resend does not mint. It reuses the invitation template and the
//      invite token the relay stored, so the seven-day window is untouched and
//      the link already in the reader's mailbox keeps working;
//   3. it is capped at one per envelope per hour, on a bucket keyed to the
//      session account as well as the envelope, so an id a caller gets to name
//      can cost that caller a resend and never deny anybody else theirs.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const adminSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const relaySource = fs.readFileSync(path.join(__dirname, '..', '..', 'relay', 'relay.js'), 'utf8');
const templates = fs.readFileSync(path.join(__dirname, '..', 'lib', 'email-templates.js'), 'utf8');
const emailTemplates = require('../lib/email-templates');

const inboxRoute = adminSource.match(/api\.get\("\/user\/parasign\/inbox"[\s\S]*?\n\}\);/);
const resendRoute = adminSource.match(/api\.post\("\/user\/parasign\/inbox\/:id\/resend"[\s\S]*?\n\}\);/);

test('the inbox proxy is session-authenticated and lets the relay name the reader', () => {
  assert.ok(inboxRoute, 'the inbox proxy route exists');
  assert.match(inboxRoute[0], /authUser/);
  assert.match(inboxRoute[0], /"X-Api-Key": proxyApiKey\(req\.userSession\)/);
  // No address and no account id on the wire: the relay derives both from the
  // key. A route that accepted either would be a route that can be asked for
  // somebody else's worklist.
  assert.doesNotMatch(inboxRoute[0], /req\.(body|query|params)/);
  assert.doesNotMatch(inboxRoute[0], /X-Verified-Email-Hash/);
  assert.match(relaySource, /path === '\/v2\/parasign\/inbox' && req\.method === 'GET'/);
  assert.match(relaySource, /envelopeMod\.partyEmailHash\(selfEmail\)/);
});

test('the relay derives the reader from the key it authenticated, never from a header', () => {
  const route = relaySource.match(/if \(path === '\/v2\/parasign\/inbox' && req\.method === 'GET'\)[\s\S]*?\n  \}/);
  assert.ok(route, 'the relay inbox route exists');
  assert.doesNotMatch(route[0], /x-verified-email-hash/i,
    'the inbox must not read an email hash off the request: a browser can set a header');
  assert.match(route[0], /keyData && keyData\.email/);
});

test('the resend asserts the session address and can only mail that address', () => {
  assert.ok(resendRoute, 'the resend route exists');
  assert.match(resendRoute[0], /authUser/);
  assert.match(resendRoute[0], /const \{ user_id, email \} = req\.userSession/);
  assert.match(resendRoute[0], /"X-Verified-Email-Hash": partyEmailHashAdmin\(email\)/);
  assert.match(resendRoute[0], /sendEmail\(email,/,
    'the mail goes to the session address, which is the address the hash was asserted for');
  assert.doesNotMatch(resendRoute[0], /req\.body/,
    'nothing about a resend may come from the request body');
});

test('the resend reuses the invitation mail and mints no token', () => {
  assert.match(resendRoute[0], /emailTemplates\.signingInviteEmail\(/,
    'the resent mail is the invitation mail, not a second template that could drift from it');
  assert.doesNotMatch(resendRoute[0], /randomBytes|createHash\("sha3/,
    'a resend that generated anything would be minting a capability');
  // The relay hands back what it stored; nothing on either side writes a token.
  const relayRoute = relaySource.match(/if \(parasignResendMatch && req\.method === 'POST'\)[\s\S]*?\n  \}/);
  assert.ok(relayRoute, 'the relay resend route exists');
  assert.match(relayRoute[0], /if \(!_internalOk\(\)\) return _internalReject\(\)/);
  assert.match(relayRoute[0], /store\.getPartyInvite\(/);
  assert.doesNotMatch(relayRoute[0], /randomBytes/);
});

test('one resend per envelope per hour, on a bucket the caller cannot use against anybody else', () => {
  assert.match(resendRoute[0], /rateHit\(redis\(\), `resend:env:\$\{webauthn\.scopeHash\(user_id \+ ":" \+ id\)\}`, 1, 3600\)/,
    'the per-envelope cap must be one an hour and keyed on the session account as well as the envelope');
  assert.match(resendRoute[0], /rateHit\(redis\(\), `resend:ip:\$\{ip\}`, \d+, 3600\)/,
    'and a per-address ceiling above it');
  assert.match(resendRoute[0], /res\.status\(429\)\.json\(\{ error: "rate_limited" \}\)/);
});

test('neither invitation mail can carry the document key, and both say so', () => {
  // There used to be two kinds of invitation mail: the first one, built in the
  // sender's browser, put the document key in the link, and the resend could
  // not because no server ever held that key. The first kind is gone: the key
  // would have reached a mail provider outside the EU, which is the one thing
  // six pages on the site promise never happens. So there is one mail now, and
  // the flag that used to tell the two apart is gone with it.
  assert.doesNotMatch(resendRoute[0], /documentIncluded/,
    'the flag is gone: there is no invitation mail that carries a key');
  assert.doesNotMatch(templates, /documentIncluded/,
    'and the template no longer has a branch that promises one');
  assert.doesNotMatch(resendRoute[0], /documentName/,
    'a filename is content, and this mail leaves the EU');

  const KEY = 'k'.repeat(43);
  const both = ['https://paramant.app/co-sign?env=EnvelopeIdPlaceholder00&p=0&t=t',
                `https://paramant.app/co-sign?env=EnvelopeIdPlaceholder00&p=0&t=t#doc=v1.${KEY}`];
  const [resent, original] = both.map((inviteUrl) => emailTemplates.signingInviteEmail({
    inviteUrl, documentName: 'Engagement letter.pdf', senderLabel: 'demo@example.com',
    envelopeId: 'EnvelopeIdPlaceholder00', partyIndex: 0,
  }));
  for (const [label, mail] of [['resend', resent], ['first invitation', original]]) {
    const all = mail.text + mail.html + mail.subject;
    assert.ok(!all.includes(KEY), `${label} carries no document key`);
    assert.ok(!all.includes('Engagement letter'), `${label} carries no filename`);
    assert.match(mail.text, /It does not open the document/,
      `${label} says the link opens the request and not the document`);
  }
  assert.equal(resent.subject, original.subject, 'both are the same mail about the same request');
  assert.equal(resent.text, original.text,
    'and they are now byte-identical: the key was the only thing that differed');
});

test('the invitations endpoint refuses a link that still carries a key', () => {
  // The gate in front of the template. Trimming the fragment here instead of
  // refusing would let a modified client post the key to this process and rely
  // on us to drop it before Resend; refusing means nothing downstream has held
  // one. The browser strips it, this refuses it, the template cuts it again.
  const invitations = adminSource.match(/api\.post\("\/user\/envelopes\/:id\/invitations"[\s\S]*?\n\}\);/);
  assert.ok(invitations, 'the invitations route exists');
  assert.match(invitations[0], /if \(inviteUrl\.hash !== ""\) \{[\s\S]{0,120}?invite_url_carries_key/,
    'a fragment is a refusal, not something to clean up quietly');
  assert.doesNotMatch(invitations[0], /doc=v1/,
    'the route no longer requires the key it must never forward');
  assert.doesNotMatch(invitations[0], /documentName/,
    'and it no longer hands the filename to the mail provider');
});
