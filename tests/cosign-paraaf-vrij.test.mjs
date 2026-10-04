// Parafen van 2 tot 5 partijen staan vrij van tekst (hertest 2026-10-04, T2-A2).
//
// De hertest: bij twee partijen stonden de parafen vrij, bij drie en meer lag
// de paraaf van partij 3, 4 en 5 over de onderste tekstregel. De eerste paraaf
// kreeg een vrije hoek, de volgende schoven zonder tekstcontrole naar links
// (cosign-layout.js partyParaafSpot). Deze suite legt een volle pagina neer
// zoals de fixture van de hertest (smalle ondermarge van 40 pt, regels tot
// ruim over de helft van de breedte, en een variant met regels over de volle
// breedte) en eist voor elk aantal partijen: geen paraaf over tekst, geen
// paraaf op een andere paraaf, geen paraaf op een handtekening.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as layout from '../frontend/js/cosign-layout.js';
const { requestsForParties } = layout;
const paraafSpotsForParties = (o) => layout.paraafSpotsForParties(o);

const A4 = { width: 595.28, height: 841.89 };

// Regels zoals pdf.js ze geeft (punten, oorsprong linksonder), van de kop tot
// 40 pt boven de onderrand. lineW: de breedte van een regel in punten.
function fullPage(lineW, { bottom = 40, top = 800 } = {}) {
  const boxes = [{ x: 56, y: top, w: 300, h: 20 }];
  for (let base = top - 24; base >= bottom; base -= 14.2) boxes.push({ x: 56, y: base - 2.5, w: lineW, h: 12.5 });
  return boxes;
}
const frac = (b, pg) => ({ x: b.x / pg.width, y: 1 - (b.y + b.h) / pg.height, w: b.w / pg.width, h: b.h / pg.height });
const overlap = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

for (const [label, lineW] of [['regels tot 62% van de breedte', 0.62 * A4.width - 56], ['regels over de volle breedte', A4.width - 112]]) {
  test(`parafen van 2 tot 5 partijen liggen nooit over tekst (${label})`, () => {
    const pages = [A4, A4, A4, A4];
    const text = pages.map(() => fullPage(lineW));
    for (let n = 2; n <= 5; n++) {
      const reqs = requestsForParties({
        anchor: { x: 0.1, y: 0.56, w: 0.3, h: 0.085, page_index: 3 }, signPage: 3, count: n,
        withParaaf: true, pages, textBoxesPerPage: text,
      });
      const parafen = reqs.map((r) => r.fields.find((f) => f.all_pages));
      const sigs = reqs.map((r) => r.fields.find((f) => !f.all_pages));
      assert.equal(parafen.length, n);
      parafen.forEach((p, i) => {
        assert.ok(p, `partij ${i + 1} van ${n} heeft een paraaf`);
        assert.ok(p.x >= 0 && p.y >= 0 && p.x + p.w <= 1 && p.y + p.h <= 1, `op de pagina: ${JSON.stringify(p)}`);
        for (const t of text[0]) {
          assert.ok(!overlap(p, frac(t, A4)), `${n} partijen: paraaf van partij ${i + 1} ${JSON.stringify(p)} ligt over tekst ${JSON.stringify(t)}`);
        }
        for (const s of sigs) assert.ok(!overlap(p, s), `${n} partijen: paraaf ${i + 1} raakt een handtekening`);
        // Leesbaar blijven: nooit kleiner dan 55% van de standaardparaaf.
        assert.ok(p.w >= 0.12 * 0.55 - 1e-6 && p.h >= 0.038 * 0.55 - 1e-6, `paraaf te klein: ${JSON.stringify(p)}`);
      });
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
        assert.ok(!overlap(parafen[i], parafen[j]), `${n} partijen: parafen ${i + 1} en ${j + 1} liggen op elkaar`);
      }
    }
  });
}

test('zonder tekstlaag blijft de eerste paraaf rechtsonder, de rest ernaast in dezelfde rij', () => {
  const spots = paraafSpotsForParties({ pages: [A4], textBoxesPerPage: null, count: 3 });
  assert.equal(spots.length, 3);
  assert.ok(spots[0].x > 0.8 && spots[0].y > 0.9, JSON.stringify(spots[0]));
  assert.equal(new Set(spots.map((s) => s.y)).size, 1, 'een rij');
  assert.ok(spots[1].x < spots[0].x && spots[2].x < spots[1].x, 'naar links aangeschoven');
});

test('dezelfde invoer geeft voor afzender en ondertekenaar dezelfde plekken', () => {
  const pages = [A4, A4];
  const text = pages.map(() => fullPage(400));
  const a = paraafSpotsForParties({ pages, textBoxesPerPage: text, count: 4 });
  const b = paraafSpotsForParties({ pages, textBoxesPerPage: text.map((p) => p.map((x) => ({ ...x }))), count: 4 });
  assert.deepEqual(a, b);
});

// Acceptance test 2026-10-04, A and C: without a spot from the sender the
// signatures go under the last text when there is room, else onto a signature
// sheet after the last page; never over text, never over a paraaf.
test('zonder plek van de afzender: handtekeningen onder de tekst, of op een handtekeningblad', () => {
  const half = fullPage(400, { bottom: 430 }).map((b) => frac(b, A4));
  const full = fullPage(400).map((b) => frac(b, A4));
  for (let n = 1; n <= 5; n++) {
    const roomy = Array.from({ length: n }, (_, i) => layout.autoSignaturePlace({ index: i, count: n, pageCount: 4, textBoxes: half }));
    for (const p of roomy) {
      assert.equal(p.page_index, 3, `${n} partijen: op de laatste pagina als er plek is`);
      for (const t of half) assert.ok(!overlap(p.spot, t), `${n} partijen: handtekening over tekst ${JSON.stringify(p.spot)}`);
    }
    const crowded = Array.from({ length: n }, (_, i) => layout.autoSignaturePlace({ index: i, count: n, pageCount: 4, textBoxes: full }));
    for (const p of crowded) assert.equal(p.page_index, 4, `${n} partijen: een volle laatste pagina geeft een handtekeningblad`);
  }
  // The sender path with "paraaf verplicht" and no box: the parafen keep clear
  // of where the signatures will go.
  const pages = [A4, A4, A4, A4];
  const text = [fullPage(400), fullPage(400), fullPage(400), fullPage(400, { bottom: 430 })];
  const reqs = requestsForParties({ anchor: null, signPage: 0, count: 3, withParaaf: true, pages, textBoxesPerPage: text });
  const parafen = reqs.map((r) => r.fields.find((f) => f.all_pages));
  const sigs = [0, 1, 2].map((i) => layout.autoSignaturePlace({ index: i, count: 3, pageCount: 4, textBoxes: text[3].map((b) => frac(b, A4)) }).spot);
  for (const p of parafen) for (const s of sigs) assert.ok(!overlap(p, s), 'paraaf raakt een handtekening');
});

test('een scan zonder tekstlaag: donkere pixels tellen als tekst', async () => {
  const { inkBoxesFromImageData } = await import('../frontend/js/paraaf-place.js');
  const w = 100, h = 140, data = new Uint8ClampedArray(w * h * 4).fill(255);
  // "blad 1/3" bottom right: dark pixels at x 80..95, y 130..135.
  for (let y = 130; y < 136; y++) for (let x = 80; x < 96; x++) { const o = (y * w + x) * 4; data[o] = data[o + 1] = data[o + 2] = 20; }
  const boxes = inkBoxesFromImageData(data, w, h, 595.28, 841.89);
  assert.ok(boxes.length > 0);
  const spots = layout.paraafSpotsForParties({ pages: [A4], textBoxesPerPage: [boxes], count: 2 });
  for (const s of spots) for (const b of boxes) assert.ok(!overlap(s, frac(b, A4)), 'paraaf over het paginanummer van de scan');
});
