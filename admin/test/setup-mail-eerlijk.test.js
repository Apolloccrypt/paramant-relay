'use strict';
// Acceptatie 3.1.1 ronde 2: the "Account afmaken" mail promised that nobody
// could type a code from your phone into a fake site. Real-time phishing does
// exactly that: the fake page asks for the six digits and passes them on. The
// mail now says what holds (no password list to leak, the code works briefly)
// and gives the one rule that does protect: type it only on paramant.app.
const { test } = require('node:test');
const assert = require('assert');
const { setupEmail } = require('../lib/email-templates');

for (const isReset of [false, true]) {
  test(`setup mail (${isReset ? 'reset' : 'new account'}): no promise about fake sites, NL and EN, text and html`, () => {
    const m = setupEmail({ token: 'tok_demo', requestedAt: Date.UTC(2026, 9, 5, 22, 46), isReset, validFor: '2 days' });
    for (const body of [m.text, m.html]) {
      assert.doesNotMatch(body, /nepsite|fake site/i, 'the mail still promises a code cannot be phished');
      assert.match(body, /Typ hem alleen op\s+paramant\.app\./);
      assert.match(body, /Type it only on paramant\.app\./);
    }
  });
}
