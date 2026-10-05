// BEWAAKT DE CI-VERDELING ZELF, ZODAT EEN SUITE NIET IN DE VERKEERDE BAAN KAN.
//
// De repo verdeelt tests/*.test.mjs over drie banen. Die verdeling wordt
// afgeleid uit de imports van elke suite, en dat is drie keer misgegaan (zie
// de kop van tests/_relay-stack.mjs). Het symptoom was elke keer anders en
// elke keer misleidend: een hangende stap, een ontbrekende redis, een
// ontbrekende argon2. De oorzaak was elke keer dezelfde: de afleiding zei iets
// anders dan de suite deed.
//
// Deze suite stelt de twee vragen die dat onmogelijk maken. Hij heeft geen
// browser en geen backend nodig, dus hij draait in elke baan.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HIER, '..');
// Het patroon staat hier in stukken. scripts/browser-suites.mjs verdeelt op
// het noemen van de relay-entrypoint, en een bewaker die die naam letterlijk
// in zijn bron draagt zet zichzelf in de baan met een backend die hij niet
// nodig heeft. Deze suite hoort in de lichtste baan en moet overal kunnen
// draaien.
const ENTRY = 'relay' + '.js';
const START_RELAY = new RegExp("(?:spawn|fork|execFile)\\w*\\s*\\([^)]*['\"]" + ENTRY + "['\"]", 's');

const lijst = (vlag) => execFileSync(process.execPath,
  [path.join(ROOT, 'scripts', 'browser-suites.mjs'), vlag], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').map((r) => r.trim()).filter(Boolean);

const alle = fs.readdirSync(path.join(ROOT, 'tests'))
  .filter((n) => n.endsWith('.test.mjs')).map((n) => 'tests/' + n).sort();

test('elke suite zit in precies een baan, geen dubbel en geen wees', () => {
  const banen = {
    'geen browser': lijst('--no-browser'),
    'browser, gestubde backend': lijst('--browser-no-stack'),
    'browser plus een echte relay': lijst('--stack'),
  };
  for (const suite of alle) {
    const waar = Object.keys(banen).filter((naam) => banen[naam].includes(suite));
    assert.equal(waar.length, 1,
      suite + ' zit in ' + waar.length + ' banen (' + (waar.join(', ') || 'geen') + ').\n'
      + 'Een wees draait nergens en een dubbele draait twee keer; beide zijn stil.');
  }
});

// De kern. Zolang starten en verdelen hetzelfde feit zijn, kunnen ze niet uit
// elkaar lopen. Een suite die zelf een relay opstart omzeilt dat, en precies
// dat gebeurde op 22-09.
test('niemand start een relay buiten tests/_relay-stack.mjs om', () => {
  const eigen = path.join('tests', '_relay-stack.mjs');
  // Deze twee noemen relay.js omdat dat hun onderwerp is: de helper start er
  // een, de bewaker zoekt ernaar. Alle andere suites horen het niet te doen.
  const mogen = new Set(['tests/_relay-stack.mjs']);
  const zondaars = [];
  for (const suite of alle) {
    if (mogen.has(suite)) continue;
    const bron = fs.readFileSync(path.join(ROOT, suite), 'utf8');
    // Een spawn, fork of execFile die de relay-entrypoint als argument
    // noemt, in welke schrijfwijze dan ook.
    if (START_RELAY.test(bron)) zondaars.push(suite);
  }
  assert.deepEqual(zondaars, [],
    'deze suites starten zelf een relay: ' + zondaars.join(', ') + '.\n'
    + 'Gebruik startRelay() uit ' + eigen + '. Dat is niet netheid: de import is\n'
    + 'wat scripts/browser-suites.mjs in de juiste CI-baan zet. Zelf spawnen\n'
    + 'werkt lokaal en faalt in CI met een melding die naar de test wijst in\n'
    + 'plaats van naar de baan.');
});

test('wie de helper importeert staat ook echt in de stack-baan', () => {
  const stack = lijst('--stack');
  for (const suite of alle) {
    const bron = fs.readFileSync(path.join(ROOT, suite), 'utf8');
    // Een echte importregel, niet een vermelding in tekst: deze suite noemt
    // de helper zelf een paar keer zonder hem te gebruiken.
    if (!/\bfrom\s*['"][^'"]*_relay-stack[^'"]*['"]/.test(bron)) continue;
    assert.ok(stack.includes(suite),
      suite + ' importeert de relayhelper maar staat niet in --stack.\n'
      + 'Dan draait hij in een baan zonder backend en faalt daar op argon2 of redis.');
  }
});
