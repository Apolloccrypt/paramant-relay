// Geen tijdbom in een testfixture.
//
// Waarom dit bestand bestaat. Op 2026-10-11 verliep sign_expires_at in twee
// cosign-fixtures, vast gezet op die dag. Vanaf dat moment was elk verzoek in
// die suites verlopen en stonden acht tests in sign-e2e rood, ook op main,
// zonder dat er een regel code veranderd was (b7cfcfde). Een tweede stond klaar:
// date-format-visible gaf een document met expires_at 2026-11-30 terug, en het
// dashboard laat een verlopen document niet meer zien. Vanaf 30 november had die
// suite "no document row" gemeld.
//
// WAT HIER WORDT GETOETST. Een fixture die een verloopdatum (expires_at,
// sign_expires_at, session_expires_at, expiresAt) als vaste datum opgeeft, en
// die datum ligt tussen nu en zestig dagen vooruit. Dat is precies het venster
// waarin een vaste datum van "geldig" naar "verlopen" kantelt. Een datum in het
// verleden kantelt niet meer, en een datum ver vooruit is nog geen haast; hij
// valt hier vanzelf binnen als het zover is, met twee maanden marge.
//
// WAT HIER NIET WORDT GETOETST, met opzet. paid_until, ends, reset_date en
// gewone datums staan in veel fixtures als tekst die letterlijk terugkomt in
// een melding ("tot 5 november 2026"). Die kantelen niet: de pagina toont ze,
// ze vergelijkt ze niet met de klok. Ze meenemen zou vals alarm geven, en een
// poort die vals alarm geeft wordt uitgezet. Nagemeten op 2026-10-13: de hele
// root-suite en de relay-unitsuite met de klok zestig en 365 dagen vooruit
// (Date in Node en in elke Playwright-context verschoven). Alleen de fixtures
// met een verloopdatum vielen om.
//
// De oplossing is altijd dezelfde: schrijf de datum ten opzichte van nu,
//   expires_at: new Date(Date.now() + 29 * 864e5).toISOString()
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VENSTER_DAGEN = 60;
const SLEUTEL = /\b(?:sign_expires_at|session_expires_at|expires_at|expiresAt)\b["']?\s*:\s*["'](\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?)["']/g;

// Twee fixtures die op een andere tak al relatief zijn gemaakt (b7cfcfde op
// fix/campagne-vreemde-route). Ze hier wijzigen geeft een mergeconflict. Zodra
// die tak landt staat er geen vaste datum meer en doet deze uitzondering niets.
const WACHT_OP_ANDERE_TAK = new Set([
  'tests/cosign-r5-terugweg-en-token.test.mjs',
  'tests/cosign-randgevallen-eerlijk.test.mjs',
]);

function bestanden(dir) {
  const uit = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== 'node_modules') uit.push(...bestanden(p)); }
    else if (/\.(mjs|js|json)$/.test(e.name)) uit.push(p);
  }
  return uit;
}

export function tijdbommen(tekst, nu = Date.now()) {
  const uit = [];
  const grens = nu + VENSTER_DAGEN * 864e5;
  for (const m of tekst.matchAll(SLEUTEL)) {
    const t = Date.parse(m[1]);
    if (Number.isFinite(t) && t >= nu && t <= grens) {
      uit.push({ regel: tekst.slice(0, m.index).split('\n').length, datum: m[1] });
    }
  }
  return uit;
}

test('de toets herkent een vaste verloopdatum binnen het venster, en alleen die', () => {
  const nu = Date.parse('2026-10-13T00:00:00Z');
  assert.equal(tijdbommen(`sign_expires_at: '2026-10-20T12:00:00.000Z'`, nu).length, 1);
  assert.equal(tijdbommen(`{"expires_at":"2026-11-30T09:00:00.000Z"}`, nu).length, 1);
  assert.equal(tijdbommen(`expiresAt: '2026-12-11'`, nu).length, 1);
  assert.equal(tijdbommen(`expires_at: '2026-09-01T00:00:00Z'`, nu).length, 0, 'verleden kantelt niet meer');
  assert.equal(tijdbommen(`expires_at: '2027-06-01T00:00:00Z'`, nu).length, 0, 'ver vooruit is nog geen haast');
  assert.equal(tijdbommen(`paid_until: '2026-11-05T00:00:00Z'`, nu).length, 0, 'weergavedatum, geen verloopdatum');
  assert.equal(tijdbommen(`expires_at: new Date(Date.now() + 6 * 864e5).toISOString()`, nu).length, 0);
});

test(`geen testfixture heeft een vaste verloopdatum in de komende ${VENSTER_DAGEN} dagen`, () => {
  const zelf = path.relative(ROOT, fileURLToPath(import.meta.url));
  const fouten = [];
  for (const abs of bestanden(path.join(ROOT, 'tests'))) {
    const rel = path.relative(ROOT, abs).split(path.sep).join('/');
    if (rel === zelf || WACHT_OP_ANDERE_TAK.has(rel)) continue;
    for (const { regel, datum } of tijdbommen(fs.readFileSync(abs, 'utf8'))) {
      fouten.push(`${rel}:${regel}  ${datum}`);
    }
  }
  assert.deepEqual(fouten, [], 'vaste verloopdatum die binnenkort verloopt; schrijf hem ten opzichte van nu');
});
