'use strict';
// Acceptatie 3.1.1, taal 40: the API-key mail went out in English only to
// Dutch customers. It now carries Dutch first and English below, names the
// plan the way /pricing does, and still never carries the whole key.
const test = require('node:test');
const assert = require('node:assert/strict');
const { welcomeEmail } = require('../lib/email-templates');

const KEY = 'pgp_demo0123456789abcdefSECRET';

test('the API-key mail is Dutch first, English below, and masks the key', () => {
  const m = welcomeEmail({ apiKey: KEY, plan: 'pro', label: 'acct_demo', sectors: ['legal'] });
  assert.match(m.subject, /^Uw Paramant-API-sleutel staat klaar \/ Your Paramant API key is ready$/);
  const nl = m.text.indexOf('Een beheerder heeft een API-sleutel');
  const en = m.text.indexOf('An administrator has created an API key');
  assert.ok(nl >= 0 && en > nl, 'Dutch block first, English block after it');
  assert.match(m.text, /Plan: +Firm/);
  assert.doesNotMatch(m.text, /Plan: +pro\b/i);
  for (const body of [m.text, m.html]) {
    assert.ok(!body.includes(KEY), 'the full key never lands in the mail');
    assert.ok(!body.includes('SECRET'), 'the tail of the key past the last four is hidden');
  }
});
