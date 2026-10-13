'use strict';
// Geen dode rate limiter, en geen limiter die doorlaat als het id ontbreekt.
//
// checkTeamRateLimit stond in relay.js met een eigen Map en een regel in de
// opruimsweep, en werd nergens aangeroepen. Hij gaf true terug zodra teamId
// ontbrak: een begrenzer die je passeert door een veld weg te laten. Hij is
// weggehaald (oorspronkelijk in b4ffe75f op fix/stille-breuken-usertest, PR
// #474). Deze toets houdt drie dingen vast:
//
//   1. checkTeamRateLimit en teamRateLimits komen niet terug.
//   2. Elke limiterfunctie in relay.js wordt ook ergens aangeroepen. Een
//      limiter die niemand aanroept beschermt niets en ziet er toch uit als
//      bescherming; dat is erger dan geen limiter.
//   3. Geen limiterfunctie opent met `if (!x) return true`: een ontbrekende
//      sleutel is een weigering, geen vrijbrief.
//
// Puur fs, geen redis, geen engine.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Regelcommentaar eruit: de plek waar checkTeamRateLimit stond, legt in een
// commentaar uit waarom hij weg is, en dat telt niet als terugkeer.
const SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8')
  .split('\n').filter((r) => !/^\s*\/\//.test(r)).join('\n');

// De namen zoals ze in relay.js staan: checkMfaRateLimit, claimRateOk,
// envSignRateOk, outboundRateOk, inviteRateOk, ...
const LIMITER = /^function\s+(\w*Rate(?:Limit|Ok)\w*)\s*\(([^)]*)\)\s*\{([\s\S]*?)^\}/gm;

function limiters() {
  return [...SRC.matchAll(LIMITER)].map((m) => ({ naam: m[1], params: m[2], body: m[3] }));
}

test('checkTeamRateLimit en zijn Map staan niet meer in relay.js', () => {
  assert.ok(!/\bcheckTeamRateLimit\s*\(/.test(SRC), 'checkTeamRateLimit is terug');
  assert.ok(!/\bteamRateLimits\b/.test(SRC), 'teamRateLimits is terug');
});

test('de toets vindt de limiters echt (anders is groen niets waard)', () => {
  const namen = limiters().map((l) => l.naam);
  for (const verwacht of ['checkMfaRateLimit', 'claimRateOk', 'envSignRateOk']) {
    assert.ok(namen.includes(verwacht), `${verwacht} niet gevonden; klopt de regex nog?`);
  }
});

test('elke limiter in relay.js wordt ook aangeroepen', () => {
  const dood = [];
  for (const { naam } of limiters()) {
    const aanroepen = SRC.match(new RegExp(`\\b${naam}\\s*\\(`, 'g')) || [];
    // Een van de treffers is de definitie zelf.
    if (aanroepen.length < 2) dood.push(naam);
  }
  assert.deepStrictEqual(dood, [], `limiter(s) zonder aanroep: ${dood.join(', ')}`);
});

test('geen limiter laat door als zijn sleutel ontbreekt', () => {
  const ruim = [];
  for (const { naam, params, body } of limiters()) {
    const eerste = (params.split(',')[0] || '').trim();
    if (!eerste) continue;
    const vorm = new RegExp(`if\\s*\\(\\s*!\\s*${eerste}\\s*\\)\\s*return\\s+true\\b`);
    if (vorm.test(body)) ruim.push(naam);
  }
  assert.deepStrictEqual(ruim, [], `limiter(s) die doorlaten zonder sleutel: ${ruim.join(', ')}`);
});
