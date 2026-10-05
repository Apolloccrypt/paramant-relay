'use strict';
// sweep-acct finding 6: subject and message of a ParaSign invitation were free
// text from the sender, sent from hello@paramant.app with links intact and
// CR/LF in the subject passed to the mail provider.
const { test } = require('node:test');
const assert = require('assert');
const { safeSubject, safeMessage } = require('../lib/invite-text');

test('subject: one line, no links, no addresses', () => {
  const s = safeSubject('Contract\r\nBcc: victim@example.com\r\n\r\nconfirm at https://evil.example/login or www.evil.test');
  assert.doesNotMatch(s, /[\r\n]/);
  assert.doesNotMatch(s, /https?:|www\.|@/);
  assert.match(s, /\[link\]/);
  assert.strictEqual(safeSubject('Paramant support: verify at evil-example.com'), 'Paramant support: verify at [link]');
  assert.ok(safeSubject('x'.repeat(500)).length <= 140);
});

test('message: paragraphs stay, links and addresses do not', () => {
  const m = safeMessage('Hallo,\r\n\r\nTeken via http://phish.example/a?b=c\nof mail mij: boef@evil.nl\u0007');
  assert.match(m, /Hallo,\n\nTeken via \[link\]/);
  assert.doesNotMatch(m, /phish|evil\.nl|@|\u0007/);
  assert.strictEqual(safeMessage('Gewoon tekst, geen link.'), 'Gewoon tekst, geen link.');
});

// Review #555: the recipient label goes into "Beste <label>," of the same
// mail and was only cut to 80 characters.
test('the invitation label gets the same scrub as subject and message', () => {
  const fs = require('fs');
  const path = require('path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const route = src.match(/api\.post\("\/user\/envelopes\/:id\/invitations"[\s\S]*?\n\}\);/);
  assert.ok(route, 'the invitations route exists');
  assert.match(route[0], /const label = inviteText\.safeSubject\(item\?\.label, 80\);/);
  assert.strictEqual(safeSubject('Paramant support: verify at evil-example.com', 80), 'Paramant support: verify at [link]');
});
