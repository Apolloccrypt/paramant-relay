'use strict';
// ParaSend Pro upload/download notification gate (lib/transfer-notify.js).
// Proves the tier gate with a spy mailer (no Resend, no network): only a Pro+
// account with a contact e-mail triggers a send; community/free never does.

const { test } = require('node:test');
const assert = require('assert');
const tn = require('../lib/transfer-notify');

test('Pro+ with e-mail -> mailer called once, upload subject', () => {
  const calls = [];
  const r = tn.maybeNotify({ keyData: { plan: 'pro', email: 'owner@example.com' }, event: 'upload', hashPrefix: 'abcdef0123456789ff', bytes: 42, sendEmail: (o) => calls.push(o) });
  assert.strictEqual(r.sent, true);
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].to, 'owner@example.com');
  // Both languages unless the sender's page said which (SENDNAME-23-F).
  assert.strictEqual(calls[0].subject, `${tn.SUBJECTS_NL.upload} / ${tn.SUBJECTS.upload}`);
});

test('community/free -> mailer NEVER called (reason: tier)', () => {
  const calls = [];
  const r = tn.maybeNotify({ keyData: { plan: 'community', email: 'owner@example.com' }, event: 'upload', sendEmail: (o) => calls.push(o) });
  assert.strictEqual(r.sent, false);
  assert.strictEqual(r.reason, 'tier');
  assert.strictEqual(calls.length, 0);
});

test('Pro without a contact e-mail -> no send (reason: no_email)', () => {
  const calls = [];
  const r = tn.maybeNotify({ keyData: { plan: 'pro' }, event: 'upload', sendEmail: (o) => calls.push(o) });
  assert.strictEqual(r.sent, false);
  assert.strictEqual(r.reason, 'no_email');
  assert.strictEqual(calls.length, 0);
});

test('download event on a Pro account -> called with download subject', () => {
  const calls = [];
  const r = tn.maybeNotify({ keyData: { plan: 'enterprise', email: 'o@e.co' }, event: 'download', hashPrefix: 'ff', bytes: 1, sendEmail: (o) => calls.push(o) });
  assert.strictEqual(r.sent, true);
  assert.strictEqual(calls[0].subject, `${tn.SUBJECTS_NL.download} / ${tn.SUBJECTS.download}`);
});

test('null keyData -> no send, no throw', () => {
  const r = tn.maybeNotify({ keyData: null, event: 'upload', sendEmail: () => { throw new Error('should not be called'); } });
  assert.strictEqual(r.sent, false);
});

test('lang nl gives a Dutch mail, lang en an English one (SENDNAME-23-F)', () => {
  const calls = [];
  const kd = { plan: 'pro', plan_parasend: 'pro', email: 'a@example.test', active: true };
  tn.maybeNotify({ keyData: kd, event: 'upload', hashPrefix: 'abcdef', bytes: 3, sendEmail: (m) => calls.push(m), lang: 'nl' });
  tn.maybeNotify({ keyData: kd, event: 'download', hashPrefix: 'abcdef', bytes: 3, sendEmail: (m) => calls.push(m), lang: 'en' });
  assert.strictEqual(calls[0].subject, tn.SUBJECTS_NL.upload);
  assert.match(calls[0].text, /Kenmerk/);
  assert.strictEqual(calls[1].subject, tn.SUBJECTS.download);
  assert.doesNotMatch(calls[1].text, /Kenmerk/);
});
