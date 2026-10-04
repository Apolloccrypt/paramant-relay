'use strict';
// The sender hears it when somebody else signs (lib/sign-notify.js).
//
// Real redis, the same store the admin uses: the record's TTL and its removal
// on completion are what this suite is about, and a Map would agree with
// whatever the code assumed. The mail itself is captured, not sent.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/sign-notify.test.js

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const signNotify = require('../lib/sign-notify');
const emailTemplates = require('../lib/email-templates');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(4).toString('hex');
const envId = (n) => crypto.randomBytes(24).toString('base64url').slice(0, 24) + RUN + n;
const SENDER = { user_id: `pgp_sender_${RUN}`, email: `Sender_${RUN}@Example.com` };
const COSIGNER = `pgp_cosigner_${RUN}`;

let rc = null;
before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error('unmet precondition "redis": run npm ci in admin/, or declare ADMIN_TEST_SKIP=redis');
  }
  rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    rc = null;
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
});
after(async () => { if (rc) await rc.quit().catch(() => {}); });

function capture() {
  const sent = [];
  return { sent, sendEmail: async (to, msg) => { sent.push({ to, msg }); } };
}
const run = (id, signer, relayBody, mail) => signNotify.afterSignature({
  client: rc, envelopeId: id, signerAccountId: signer, relayBody,
  sendEmail: mail.sendEmail, template: emailTemplates.signatureReceivedEmail,
});

test('the record holds a hash of the account and the address, and expires after the signing window', async (t) => {
  if (!rc) return t.skip('redis declared absent via ADMIN_TEST_SKIP');
  const id = envId('a');
  assert.equal(await signNotify.rememberSender(rc, id, SENDER), true);
  const raw = await rc.get(signNotify.KEY_PREFIX + id);
  assert.ok(raw);
  assert.ok(!raw.includes(SENDER.user_id), 'the account id is a credential; only its hash may be stored');
  assert.deepEqual(JSON.parse(raw), { uid: signNotify.idHash(SENDER.user_id), email: SENDER.email.toLowerCase() });
  const ttl = await rc.ttl(signNotify.KEY_PREFIX + id);
  assert.ok(ttl > 7 * 86400 && ttl <= 8 * 86400, `ttl ${ttl}s must outlive the 7-day invite and not much more`);
});

test('a co-signer signing mails the sender the count, and completion mails once and forgets', async (t) => {
  if (!rc) return t.skip('redis declared absent via ADMIN_TEST_SKIP');
  const id = envId('b');
  await signNotify.rememberSender(rc, id, SENDER);
  const mail = capture();

  assert.equal(await run(id, COSIGNER, { signed_count: 1, party_count: 3, status: 'pending' }, mail), 'sent');
  assert.equal(mail.sent.length, 1);
  assert.equal(mail.sent[0].to, SENDER.email.toLowerCase());
  assert.match(mail.sent[0].msg.subject, /Er is getekend \(1 van 3\)/);
  assert.match(mail.sent[0].msg.text, /1 van de 3 ondertekenaars heeft nu getekend/);
  assert.match(mail.sent[0].msg.text, /1 of 3 signers has now signed/);
  assert.ok(await rc.get(signNotify.KEY_PREFIX + id), 'not complete yet, so the record stays');

  assert.equal(await run(id, COSIGNER + '2', { signed_count: 3, party_count: 3, status: 'complete' }, mail), 'sent');
  assert.equal(mail.sent.length, 2);
  assert.match(mail.sent[1].msg.subject, /^Iedereen heeft getekend \/ Everyone has signed$/);
  assert.equal(await rc.get(signNotify.KEY_PREFIX + id), null, 'a complete envelope leaves nothing behind');
});

test('no mail on a retry, on the sender signing their own slot, or without a record', async (t) => {
  if (!rc) return t.skip('redis declared absent via ADMIN_TEST_SKIP');
  const id = envId('c');
  await signNotify.rememberSender(rc, id, SENDER);
  const mail = capture();
  assert.equal(await run(id, COSIGNER, { idempotent: true, signed_count: 1, party_count: 2, status: 'pending' }, mail), 'skipped');
  assert.equal(await run(id, SENDER.user_id, { signed_count: 1, party_count: 2, status: 'pending' }, mail), 'skipped');
  assert.equal(await run(envId('none'), COSIGNER, { signed_count: 1, party_count: 2, status: 'pending' }, mail), 'skipped');
  assert.equal(mail.sent.length, 0);

  // The sender completing the envelope themselves still clears the record.
  assert.equal(await run(id, SENDER.user_id, { signed_count: 2, party_count: 2, status: 'complete' }, mail), 'skipped');
  assert.equal(await rc.get(signNotify.KEY_PREFIX + id), null);
});

test('a failing mail provider never throws into the sign route', async (t) => {
  if (!rc) return t.skip('redis declared absent via ADMIN_TEST_SKIP');
  const id = envId('d');
  await signNotify.rememberSender(rc, id, SENDER);
  const out = await signNotify.afterSignature({
    client: rc, envelopeId: id, signerAccountId: COSIGNER,
    relayBody: { signed_count: 1, party_count: 2, status: 'pending' },
    sendEmail: async () => { throw new Error('provider down'); },
    template: emailTemplates.signatureReceivedEmail,
  });
  assert.equal(out, 'failed');
});

test('the mail carries a count and a link, never a file name, a party name or the envelope id', () => {
  const id = 'ENVELOPEIDSHOULDNOTLEAK0123456789';
  const msg = emailTemplates.signatureReceivedEmail({ signedCount: 2, partyCount: 2, complete: true, envelopeId: id });
  for (const part of [msg.subject, msg.text, msg.html]) assert.ok(!part.includes(id), 'envelope id must not be in the mail');
  assert.match(msg.text, /\/dashboard/);
  assert.match(msg.text, /Uw document is ondertekend door alle 2 ondertekenaars/);
  assert.match(msg.html, /lang="nl"/);
  const two = emailTemplates.signatureReceivedEmail({ signedCount: 2, partyCount: 3, complete: false, envelopeId: id });
  assert.match(two.text, /2 van de 3 ondertekenaars hebben nu getekend/);
  assert.match(two.text, /2 of 3 signers have now signed/);
});

test('server.js remembers the sender on create and tells them after a submit, without awaiting the mail', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const create = src.match(/api\.post\("\/user\/envelopes", authUser[\s\S]*?\n\}\);/);
  assert.ok(create);
  assert.match(create[0], /built\.parties\.length > 0[\s\S]*?signNotify\.rememberSender\(redis\(\), body\.envelope\.id, \{ user_id, email \}\)/);
  const submit = src.match(/api\.post\("\/user\/sign\/submit"[\s\S]*?\n\}\);/);
  assert.ok(submit);
  assert.match(submit[0], /\n    signNotify\.afterSignature\(\{[\s\S]*?signerAccountId: user_id, relayBody: body/);
  assert.doesNotMatch(submit[0], /await signNotify\.afterSignature/, 'the signer\'s 200 must not wait on a mail provider');
});

// Since 2026-10-04: "Iedereen heeft getekend" opens the finished document.
// The link carries an opaque reference, still never the envelope id, and
// only the sending account's session turns it back into the envelope.
test('completion links to the result through a reference only the sender can resolve', async (t) => {
  if (!rc) return t.skip('redis declared absent');
  const id = envId('res');
  await signNotify.rememberSender(rc, id, SENDER);
  const mail = capture();
  const out = await signNotify.afterSignature({
    client: rc, envelopeId: id, signerAccountId: COSIGNER,
    relayBody: { signed_count: 2, party_count: 2, status: 'complete' },
    sendEmail: mail.sendEmail, template: emailTemplates.signatureReceivedEmail, baseUrl: 'https://paramant.app',
  });
  assert.equal(out, 'sent');
  const msg = mail.sent[0].msg;
  const m = msg.text.match(/https:\/\/paramant\.app\/co-sign\?result=([A-Za-z0-9_-]{43})/);
  assert.ok(m, 'the button opens the result page');
  for (const part of [msg.subject, msg.text, msg.html]) assert.ok(!part.includes(id), 'still no envelope id in the mail');
  assert.equal(await signNotify.resolveResult(rc, m[1], SENDER.user_id), id, 'the sender resolves it');
  assert.equal(await signNotify.resolveResult(rc, m[1], COSIGNER), null, 'another account does not');
  assert.equal(await signNotify.resolveResult(rc, 'x'.repeat(43), SENDER.user_id), null, 'an unknown reference does not');
  const ttl = await rc.ttl(signNotify.RESULT_PREFIX + m[1]);
  assert.ok(ttl > 29 * 86400 && ttl <= 30 * 86400, 'it lives as long as the envelope record');
  await rc.del(signNotify.RESULT_PREFIX + m[1]);
});

test('a refusal mails the sender once, without names or the envelope id, and forgets', async (t) => {
  if (!rc) return t.skip('redis declared absent');
  const id = envId('dec');
  await signNotify.rememberSender(rc, id, SENDER);
  const mail = capture();
  assert.equal(await signNotify.afterDecline({ client: rc, envelopeId: id, sendEmail: mail.sendEmail, template: emailTemplates.signatureDeclinedEmail }), 'sent');
  assert.equal(mail.sent[0].to, SENDER.email.toLowerCase());
  assert.match(mail.sent[0].msg.subject, /^Verzoek geweigerd \/ Request declined$/);
  for (const part of [mail.sent[0].msg.text, mail.sent[0].msg.html]) assert.ok(!part.includes(id));
  assert.equal(await rc.get(signNotify.KEY_PREFIX + id), null, 'the record is gone');
  assert.equal(await signNotify.afterDecline({ client: rc, envelopeId: id, sendEmail: mail.sendEmail, template: emailTemplates.signatureDeclinedEmail }), 'skipped', 'and a second refusal mails nobody');
});
