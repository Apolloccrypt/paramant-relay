'use strict';

// The shape of the pickup route, checked against the source rather than a
// running relay, so this test costs nothing and still catches the two ways this
// route silently disappears: dropping out of a sector list, or a pattern that
// stops matching real tokens.

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('fs');
const path = require('path');

const recipients = require('../lib/recipients');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

// The pattern as it stands in relay.js, lifted so the test breaks when it moves.
// Read to the end of the line rather than to the first bracket: the pattern
// contains brackets of its own, and cutting at the first one produced an
// unterminated regex that failed for the wrong reason.
const PATTERN = (() => {
  const line = SOURCE.split('\n').find(l => l.includes('path.match(/^\\/v2\\/pickup'));
  assert.ok(line, 'the pickup route is gone from relay.js');
  const m = line.match(/path\.match\((.+)\);\s*$/);
  assert.ok(m, 'the pickup route no longer looks like a path match: ' + line.trim());
  // eslint-disable-next-line no-eval
  return eval(m[1]);
})();

test('a real token matches the route', () => {
  for (let i = 0; i < 25; i++) {
    const token = recipients.newPickupToken();
    assert.ok(PATTERN.test('/v2/pickup/' + token),
      'a freshly minted token must reach its own route: ' + token);
  }
});

test('the route refuses what is not a token', () => {
  const nee = [
    '/v2/pickup/',                      // nothing
    '/v2/pickup/short',                 // too short to be one
    '/v2/pickup/' + 'a'.repeat(200),    // longer than the layer will hash
    '/v2/pickup/../../etc/passwd',      // traversal
    '/v2/pickup/abc/def',               // a second segment
    '/v2/pickup/token?x=1',             // a query glued on
    '/v2/pickup/' + encodeURIComponent('a b'),
  ];
  for (const p of nee) assert.equal(PATTERN.test(p), false, 'must not match: ' + p);
});

test('the pattern cannot outgrow what the layer will hash', () => {
  const max = Number(String(PATTERN).match(/,(\d+)\}/)[1]);
  assert.ok(max <= recipients.MAX_TOKEN_LEN,
    'the route would accept a token longer than the layer refuses to hash, ' +
    'which is work an outsider can ask for');
});

test('every sector that carries transfers also carries pickup', () => {
  // Sector lists are plain arrays in the source. A send that cannot be
  // collected in a sector is worse than a send that cannot be made there.
  const lists = SOURCE.split('\n').filter(l => l.includes("'/v2/outbound'"));
  assert.ok(lists.length > 0, 'no sector list found; this test needs rewriting');
  for (const line of lists) {
    assert.ok(line.includes("'/v2/pickup'"),
      'a sector allows outbound but not pickup: ' + line.trim().slice(0, 70));
  }
});

test('vragen om een code is een POST, want een GET wordt door scanners afgevuurd', () => {
  // Dit was een GET, en dat is precies verkeerd voor een verzoek met een
  // bijwerking: een GET die MAIL VERSTUURT wordt afgevuurd door elke Safe
  // Links-, Proofpoint- of Barracuda-scanner die de uitnodiging opent. De
  // ontvanger kreeg dan een code voordat hij iets had aangeraakt, en nog een
  // toen hij klikte. Een scanner doet geen POST, en dat is de hele reparatie.
  //
  // De GET blijft bestaan voor links die vóór de overstap zijn verstuurd.
  const idx = SOURCE.indexOf('/v2\\/pickup');
  const blok = SOURCE.slice(idx, idx + 2400);
  assert.match(blok, /_body\.action === 'code'/,
    'om een code vragen hoort een POST met {action:"code"} te zijn');
  assert.match(blok, /req\.method === 'POST'/, 'en de route moet POST aannemen');
  assert.ok(!/apiKey/.test(blok.split('_sendStore()')[0]),
    'a recipient has no account, so the route must not reach for an api key');
});
