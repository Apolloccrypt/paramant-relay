// Fase-1-herrun PLAN-33-A: sinds "afzender betaalt" weigert de relay de derde
// solo-handtekening van een Community-klant al bij het aanmaken
// (sign_quota_insufficient, room 0). De admin gaf alleen {error} door en
// sign-flow.js ving het af met een kale zin, dus de koopkaart (prijs, knop,
// resetdatum) verdween. Nu: de admin geeft de getallen door, de kaart herkent
// de weigering, en /sign toont de kaart vóór de zin.
// Run: node --test tests/quota-afzender-betaalt-kaart.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

function loadCard(lang) {
  const window = {};
  const document = { documentElement: { lang }, addEventListener() {}, querySelectorAll: () => [] };
  vm.runInNewContext(read('frontend/js/quota-upgrade.js'), { window, document, navigator: { language: lang }, location: { pathname: lang === 'en' ? '/en/sign' : '/sign' }, console });
  return window.paQuotaUpgrade;
}

test('niets meer over op Community: de koopkaart, met resetdatum', () => {
  const q = loadCard('nl');
  const data = { error: 'sign_quota_insufficient', needed: 1, room: 0, used: 2, pending: 0, limit: 2, plan: 'free', reset_date: '2026-11-01' };
  assert.equal(q.isQuota402(402, data), true);
  const html = q.html(data);
  assert.match(html, /EUR 29/);
  assert.match(html, /href="\/pricing"/);
  assert.match(html, /2026-11-01/);
});

test('wel ruimte, maar te weinig voor dit verzoek: geen kaart (eigen zin in sign-flow.js)', () => {
  const q = loadCard('nl');
  assert.equal(q.isQuota402(402, { error: 'sign_quota_insufficient', needed: 3, room: 1, plan: 'free' }), false);
});

test('de admin geeft bij een 402 de getallen van de relay door', () => {
  const src = read('admin/server.js');
  const i = src.indexOf('if (rr.status === 402) {');
  assert.ok(i > 0);
  const block = src.slice(i, i + 500);
  for (const k of ['needed', 'room', 'plan', 'reset_date']) assert.match(block, new RegExp('"' + k + '"'));
});

test('/sign toont de kaart vóór de kale zin', () => {
  const src = read('frontend/sign-flow.js');
  const card = src.indexOf("window.paQuotaUpgrade.isQuota402(e.status, e.data)) {\n      $('ds-sign-status').innerHTML");
  const lim = src.indexOf("const lim = limitMessage(e);\n    if (lim) {\n      $('ds-sign-status')");
  assert.ok(card > 0 && lim > 0 && card < lim, 'kaart eerst');
});
