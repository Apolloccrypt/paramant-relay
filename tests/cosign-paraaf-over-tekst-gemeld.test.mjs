// PDF-sweep B1 (2026-10-04): was er op geen enkele plek in de marge ruimte
// voor de parafen, dan zette js/cosign-layout.js ze stil op "de minst bedekte
// plek", over de tekst. Nu draagt de uitkomst covered: true en noemt
// requestsForParties de pagina's waar een paraaf over tekst staat, zodat /sign
// en /co-sign het hardop zeggen. Waar de marge wel vrij is, blijft het stil.
// Run: node --test tests/cosign-paraaf-over-tekst-gemeld.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { paraafSpotsForParties, paraafCoveredPages, pageListText, requestsForParties } from '../frontend/js/cosign-layout.js';

const A4 = { width: 595.28, height: 841.89 };
// Tekst van rand tot rand: geen enkele vrije marge.
const vol = [{ x: 0, y: 0, w: A4.width, h: A4.height }];
// Een gewone pagina: tekst in het midden, marges vrij.
const gewoon = [{ x: 72, y: 90, w: 450, h: 660 }];

test('volle pagina: de parafen dragen covered en de pagina wordt genoemd', () => {
  const pages = [A4, A4, A4];
  const tb = [gewoon, vol, gewoon];
  const spots = paraafSpotsForParties({ pages, textBoxesPerPage: tb, count: 3, avoid: [] });
  assert.equal(spots.covered, true, 'de terugval is niet stil');
  const reqs = requestsForParties({ anchor: null, signPage: 2, count: 3, withParaaf: true, pages, textBoxesPerPage: tb });
  assert.deepEqual(reqs.paraafCoveredPages, [1], 'alleen pagina 2 (index 1) staat vol');
});

test('vrije marges: geen covered, geen pagina', () => {
  const pages = [A4, A4, A4, A4];
  const tb = [gewoon, gewoon, gewoon, gewoon];
  const spots = paraafSpotsForParties({ pages, textBoxesPerPage: tb, count: 5, avoid: [] });
  assert.ok(!spots.covered);
  const reqs = requestsForParties({ anchor: null, signPage: 3, count: 5, withParaaf: true, pages, textBoxesPerPage: tb });
  assert.deepEqual(reqs.paraafCoveredPages, []);
  for (const s of spots) assert.deepEqual(paraafCoveredPages({ spot: s, pages, textBoxesPerPage: tb }), []);
});

test('een onleesbare pagina telt niet als bedekt (wij zeggen niets dat we niet weten)', () => {
  const spot = { x: 0.8, y: 0.9, w: 0.1, h: 0.03 };
  assert.deepEqual(paraafCoveredPages({ spot, pages: [A4, A4], textBoxesPerPage: [null, vol] }), [1]);
});

test('paginalijst in woorden, NL en EN', () => {
  assert.equal(pageListText([1], false), 'pagina 2');
  assert.equal(pageListText([0, 2, 4], false), "pagina's 1, 3 en 5");
  assert.equal(pageListText([0, 2], true), 'pages 1 and 3');
  assert.equal(pageListText([0, 1, 2, 3, 4, 5, 6, 7], false, 6), "pagina's 1, 2, 3, 4, 5, 6 en 2 andere");
});
