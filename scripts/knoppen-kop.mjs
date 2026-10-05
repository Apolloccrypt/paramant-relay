#!/usr/bin/env node
// De twee koppen die zichzelf niet konden tellen.
//
// deploy/knoppen.md opent met "N knoppen" en deploy/.env.example met
// "N variables". Allebei met de hand geschreven, allebei bewaakt door een
// poort die achteraf klaagt: K6 in tests/knoppen-compleet.test.mjs en E5 in
// tests/env-documented.test.mjs.
//
// Waarom dit bestand er is. Op 5 en 6 september liep het drie keer mis op
// dezelfde manier. Twee takken zetten allebei een getal in dezelfde kop, elk
// kloppend op de eigen boom. Waar git een conflict zag koos iemand er met de
// hand een, meestal door op te tellen, en dat is precies fout: het getal hoort
// uit de tabellen te komen, niet uit een som van twee takken. Waar git GEEN
// conflict zag, omdat beide kanten toevallig hetzelfde getal schreven, ging het
// stil door en stond het pas fout na de merge. Dat laatste is de dure variant,
// want er is dan niets rood tot de poort draait.
//
//   node scripts/knoppen-kop.mjs            wat er staat en wat er hoort te staan
//   node scripts/knoppen-kop.mjs --schrijf  zet beide koppen op het getelde getal
//
// Het telt met dezelfde uitdrukkingen als de twee poorten, zodat er geen derde
// waarheid ontstaat. Draai het na elke merge die een van beide bestanden raakt;
// het antwoord is dan geen afweging meer maar een uitkomst.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const KNOPPEN = 'deploy/knoppen.md';
const ENVEXAMPLE = 'deploy/.env.example';

// Dezelfde tabellezer als tests/knoppen-compleet.test.mjs. Een tabel begint bij
// zijn HTML-marker en loopt door tot de eerste regel die niet met | begint; de
// scheidingsregel en de kopregel tellen niet mee.
function rijen(tekst, marker) {
  const at = tekst.indexOf(`<!-- knoppen:${marker} -->`);
  if (at === -1) throw new Error(`${KNOPPEN} mist de marker <!-- knoppen:${marker} -->`);
  const rows = [];
  let begonnen = false;
  for (const line of tekst.slice(at).split('\n').slice(1)) {
    if (!line.startsWith('|')) {
      if (begonnen) break;
      continue;
    }
    begonnen = true;
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.every((c) => /^-*:?-*$/.test(c)) || cells[0] === '') continue;
    rows.push(cells);
  }
  return rows.slice(1);
}

const TABELLEN = ['env-buiten', 'shell', 'nginx', 'constanten'];

const knoppenTekst = readFileSync(join(ROOT, KNOPPEN), 'utf8');
const envTekst = readFileSync(join(ROOT, ENVEXAMPLE), 'utf8');

const perTabel = TABELLEN.map((m) => [m, rijen(knoppenTekst, m).length]);
const knoppen = perTabel.reduce((a, [, n]) => a + n, 0);

// Dezelfde verzameling als "documented" in tests/env-documented.test.mjs: een
// naam telt als hij als toewijzing staat, gezet of uitgecommentarieerd.
const variabelen = new Set(
  [...envTekst.matchAll(/^#?\s*([A-Z][A-Z0-9_]*)=/gm)].map((m) => m[1])
).size;

// De drie koppen. knoppen.md draagt er twee: zijn eigen aantal en dat van
// .env.example, en die laatste is degene die op 6 september uiteenliep met het
// bestand waar hij over gaat.
const KOPPEN = [
  { bestand: KNOPPEN, re: /^(-\s*\*\*)(\d+)(\s+knoppen\*\*)/m, hoort: knoppen, wat: 'knoppen' },
  { bestand: KNOPPEN, re: /^(-\s*\*\*)(\d+)(\s+omgevingsvariabelen\*\*)/m, hoort: variabelen, wat: 'omgevingsvariabelen' },
  { bestand: ENVEXAMPLE, re: /^(#\s*)(\d+)(\s+variables\b)/m, hoort: variabelen, wat: 'variables' },
];

const schrijven = process.argv.includes('--schrijf');
const inhoud = new Map([[KNOPPEN, knoppenTekst], [ENVEXAMPLE, envTekst]]);
let scheef = 0;

console.log(`geteld: ${perTabel.map(([m, n]) => `${m}=${n}`).join('  ')}  ->  ${knoppen} knoppen`);
console.log(`geteld: ${variabelen} namen in ${ENVEXAMPLE}`);
console.log('');

for (const kop of KOPPEN) {
  const tekst = inhoud.get(kop.bestand);
  const m = tekst.match(kop.re);
  if (!m) {
    console.log(`ONVINDBAAR  ${kop.bestand}: geen kopregel voor ${kop.wat}`);
    scheef += 1;
    continue;
  }
  const staat = Number(m[2]);
  if (staat === kop.hoort) {
    console.log(`OK          ${kop.bestand}: ${staat} ${kop.wat}`);
    continue;
  }
  scheef += 1;
  console.log(`SCHEEF      ${kop.bestand}: kop zegt ${staat} ${kop.wat}, geteld ${kop.hoort}`);
  if (schrijven) {
    inhoud.set(kop.bestand, tekst.replace(kop.re, `$1${kop.hoort}$3`));
  }
}

if (schrijven && scheef > 0) {
  for (const [bestand, tekst] of inhoud) {
    if (tekst !== readFileSync(join(ROOT, bestand), 'utf8')) {
      writeFileSync(join(ROOT, bestand), tekst);
      console.log(`geschreven: ${bestand}`);
    }
  }
  process.exit(0);
}

if (scheef > 0) {
  console.log('');
  console.log('Draai `node scripts/knoppen-kop.mjs --schrijf` om de koppen op het getelde getal te zetten.');
  process.exit(1);
}
