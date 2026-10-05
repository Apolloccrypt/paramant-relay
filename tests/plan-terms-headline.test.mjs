// The one sentence above the product lines on /account and /dashboard
// (frontend/js/plan-terms.js headline).
//
// Acceptatie 3.1.1, betalen punt 6: after a Firm customer bought a month of
// Business, /account said "HUIDIG PLAN Business, Betaald tot 6 december 2026"
// and directly under it "Ondertekenen: Business tot 5 november 2026, daarna
// Firm tot 6 december 2026". Two dates for Business. The headline now names the
// plan that runs, ITS end, and what follows, so it says what the lines say.
// Taal 31: auto_renews true said "nothing renews automatically".
//
// Plain node: the two browser scripts run in a vm with a minimal window.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'js');

function load(lang, nowIso) {
  const RealDate = Date;
  const fixed = RealDate.parse(nowIso);
  class FixedDate extends RealDate {
    constructor(...a) { if (a.length) super(...a); else super(fixed); }
    static now() { return fixed; }
  }
  const window = {};
  const ctx = { window, document: { documentElement: { lang }, createElement: () => ({ textContent: '' }) }, Date: FixedDate, Intl };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'format-date.js'), 'utf8'), ctx);
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'plan-terms.js'), 'utf8'), ctx);
  return window.paPlanTerms;
}

const upgraded = {
  current_plan: 'business',
  plan_parasign: 'business', plan_parasend: 'pro',
  paid_until_parasign: '2026-12-06T10:00:00.000Z', paid_until_parasend: '2026-12-06T10:00:00.000Z',
  terms_parasign: [{ tier: 'business', until: '2026-11-05T10:00:00.000Z', bundle: 'business' }, { tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }],
  terms_parasend: [{ tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }],
  auto_renews: false,
};

test('Firm to Business: the headline and the product lines give Business the same end', () => {
  const nl = load('nl', '2026-10-06T12:00:00.000Z');
  // Ronde 2: the "daarna Firm" part stands once, in the product line, not
  // also in the headline right above it.
  assert.equal(nl.headline(upgraded),
    'Business betaald tot 5 november 2026. Er wordt niets automatisch verlengd. Verlengen kan vanaf vandaag, u verliest geen dag.');
  assert.deepEqual([...nl.lines(upgraded)], [
    'Ondertekenen: Business tot 5 november 2026, daarna Firm tot 6 december 2026.',
    'Versturen: Firm tot 6 december 2026.',
  ]);
  const en = load('en', '2026-10-06T12:00:00.000Z');
  assert.equal(en.headline(upgraded),
    'Business paid until 5 November 2026. Nothing renews automatically. You can renew from today without losing a day.');
  // The sentence "Business tot ..., daarna Firm tot ..." appears exactly once
  // across the headline and the lines together.
  const all = [nl.headline(upgraded), ...nl.lines(upgraded)].join('\n');
  assert.equal((all.match(/Business tot 5 november 2026, daarna Firm tot 6 december 2026/g) || []).length, 1, all);
  assert.equal((all.match(/daarna Firm/g) || []).length, 1, all);
});

test('the headline never says "paid until" a date the plan it names does not run to', () => {
  const nl = load('nl', '2026-10-06T12:00:00.000Z');
  const h = nl.headline(upgraded);
  assert.doesNotMatch(h, /^Business betaald tot 6 december/);
});

test('auto_renews true says it renews; false says nothing renews', () => {
  const firm = { plan_parasign: 'pro', plan_parasend: 'pro', terms_parasign: [{ tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }], terms_parasend: [{ tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }] };
  const nl = load('nl', '2026-10-06T12:00:00.000Z');
  assert.equal(nl.headline({ ...firm, auto_renews: true }), 'Firm wordt op 6 december 2026 automatisch verlengd. Opzeggen kan tot die dag.');
  assert.match(nl.headline({ ...firm, auto_renews: false }), /^Firm betaald tot 6 december 2026\. Er wordt niets automatisch verlengd\./);
  const en = load('en', '2026-10-06T12:00:00.000Z');
  assert.equal(en.headline({ ...firm, auto_renews: true }), 'Firm renews automatically on 6 December 2026. You can cancel until that day.');
});

test('nothing paid, or only an ended term: no headline', () => {
  const nl = load('nl', '2026-10-06T12:00:00.000Z');
  assert.equal(nl.headline({ plan_parasign: 'free', plan_parasend: 'community' }), null);
  assert.equal(nl.headline({ terms_parasign: [{ tier: 'pro', until: '2026-09-01T00:00:00.000Z' }] }), null);
});

// Taal #25 (ronde 2): a Firm buyer read his plan three times on /dashboard:
// "Ondertekenen: Firm, zonder einddatum. / Versturen: Firm, zonder einddatum."
// above "FIRM-PLAN · ACTIEF", and "Facturen en verlengen" under a plan with no
// end. The product lines only show when they add something to the plan name.
test('product lines only when they say more than the plan once', () => {
  const nl = load('nl', '2026-10-06T12:00:00.000Z');
  const firmOpen = { plan_parasign: 'pro', plan_parasend: 'pro', paid_until_parasign: null, paid_until_parasend: null };
  assert.equal(nl.addsToPlan(firmOpen), false);
  assert.equal(nl.hasEnd(firmOpen), false);
  const firm = { terms_parasign: [{ tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }], terms_parasend: [{ tier: 'pro', until: '2026-12-06T10:00:00.000Z', bundle: 'firm' }] };
  assert.equal(nl.addsToPlan(firm), false);
  assert.equal(nl.hasEnd(firm), true);
  assert.equal(nl.addsToPlan(upgraded), true, 'Business then Firm: the lines carry what follows');
  const biz = { terms_parasign: [{ tier: 'business', until: '2026-11-05T10:00:00.000Z', bundle: 'business' }], terms_parasend: [{ tier: 'pro', until: '2026-11-05T10:00:00.000Z', bundle: 'business' }] };
  assert.equal(nl.addsToPlan(biz), true, 'Business names its ParaSend half differently');
  // The list element: hidden with onlyIfAdds for plain Firm, filled without it.
  const el = { firstChild: null, children: [], hidden: false, removeChild() { this.firstChild = null; }, appendChild(c) { this.children.push(c); } };
  nl.render(el, firm, { onlyIfAdds: true });
  assert.equal(el.hidden, true);
  nl.render(el, firm);
  assert.equal(el.hidden, false);
});
