'use strict';
// Waar een betaald plan vandaan komt (lib/beheer.js planSource).
//
// Het overzicht zei "12 op een betaald plan" naast "0 betalende klanten". Een
// plan is nog geen betaling: hier staat vast dat elk niet-gratis plan precies
// een bron krijgt, dat een teamsleutel niet als extra betaler telt, en dat
// niets gevonden "onbekend" is en nooit een gok.
const { test } = require('node:test');
const assert = require('assert');
const beheer = require('../lib/beheer');

const NOW = Date.parse('2026-10-25T12:00:00Z');
const later = new Date(NOW + 30 * 86400000).toISOString();
const eerder = new Date(NOW - 86400000).toISOString();

function acct(id, extra = {}) {
  return { _full: `pgp_${id}`, _account: `pgp_${id}`, active: true, plan_parasign: 'free', plan_parasend: 'community', ...extra };
}

test('alleen een niet-gratis plan heeft een bron', () => {
  assert.strictEqual(beheer.planSource(acct('demo1')), null);
  assert.strictEqual(beheer.planSource(acct('demo2', { plan_parasign: 'pro' })), 'onbekend');
  assert.strictEqual(beheer.planSource(acct('demo3', { plan_parasend: 'pro' })), 'onbekend');
});

test('elke bron uit de gegevens ernaast', () => {
  const ctx = {
    paying: new Set(['pgp_betaalt']),
    gifts: new Set(['pgp_cadeau']),
    manual: new Set(['pgp_beheer']),
  };
  assert.strictEqual(beheer.planSource(acct('betaalt', { plan_parasign: 'business' }), ctx), 'betaald');
  assert.strictEqual(beheer.planSource(acct('cadeau', { plan_parasign: 'pro' }), ctx), 'kortingscode');
  assert.strictEqual(beheer.planSource(acct('beheer', { plan_parasend: 'pro' }), ctx), 'handmatig');
  assert.strictEqual(beheer.planSource(acct('niets', { plan_parasign: 'pro' }), ctx), 'onbekend');
  const lid = { ...acct('lid', { plan_parasign: 'business' }), _account: 'pgp_betaalt' };
  assert.strictEqual(beheer.planSource(lid, ctx), 'team');
});

test('betaald wint van kortingscode en beheer', () => {
  const ctx = { paying: new Set(['pgp_demo']), gifts: new Set(['pgp_demo']), manual: new Set(['pgp_demo']) };
  assert.strictEqual(beheer.planSource(acct('demo', { plan_parasign: 'pro' }), ctx), 'betaald');
});

test('de uitsplitsing telt alleen actieve accounts en klopt op', () => {
  const ctx = { paying: new Set(['pgp_a']), gifts: new Set(['pgp_b', 'pgp_c']), manual: new Set() };
  const users = [
    acct('a', { plan_parasign: 'business' }),
    { ...acct('a2', { plan_parasign: 'business' }), _account: 'pgp_a' },
    { ...acct('a3', { plan_parasign: 'business' }), _account: 'pgp_a' },
    acct('b', { plan_parasign: 'pro' }),
    acct('c', { plan_parasend: 'pro' }),
    acct('d', { plan_parasign: 'pro' }),
    acct('e', { plan_parasign: 'pro', active: false }),
    acct('f'),
  ];
  const r = beheer.planSourceBreakdown(users, ctx);
  assert.strictEqual(r.on_paid_plan, 6);
  assert.deepStrictEqual(r.via, { betaald: 1, kortingscode: 2, team: 2, handmatig: 0, onbekend: 1 });
  assert.strictEqual(Object.values(r.via).reduce((x, y) => x + y, 0), r.on_paid_plan);
  assert.strictEqual(r.payments_read, true);
  assert.strictEqual(beheer.planSourceBreakdown(users, {}).payments_read, false);
});

test('een kortingscode telt alleen zolang het cadeau loopt', () => {
  const rec = (ends, tier = 'pro') => ({ code: 'DEMO-CODE', grants: [{ product: 'parasign', tier, days: 30, ends }] });
  assert.strictEqual(beheer.runningGift([rec(later)], NOW), true);
  assert.strictEqual(beheer.runningGift([rec(eerder)], NOW), false);
  assert.strictEqual(beheer.runningGift([rec(later, 'free')], NOW), false);
  assert.strictEqual(beheer.runningGift([null, { code: 'X' }, rec('geen datum')], NOW), false);
  assert.strictEqual(beheer.runningGift([], NOW), false);
});

test('beheer telt alleen bij een toekenning van een niet-gratis plan', () => {
  assert.strictEqual(beheer.manualGrant([{ event_type: 'admin_plan_changed', metadata: { from: 'community', to: 'pro' } }]), true);
  assert.strictEqual(beheer.manualGrant([{ event_type: 'admin_product_plan_changed', metadata: { product: 'parasign', tier: 'business' } }]), true);
  assert.strictEqual(beheer.manualGrant([{ event_type: 'admin_plan_changed', metadata: { to: 'community' } }]), false);
  assert.strictEqual(beheer.manualGrant([{ event_type: 'admin_product_plan_changed', metadata: { tier: 'free' } }]), false);
  assert.strictEqual(beheer.manualGrant([{ event_type: 'webauthn_login', metadata: {} }]), false);
  assert.strictEqual(beheer.manualGrant([]), false);
});

test('het scherm noemt onbekend "geen bron gevonden"', () => {
  assert.strictEqual(beheer.PLAN_SOURCE_NL.onbekend, 'geen bron gevonden');
  assert.deepStrictEqual(Object.keys(beheer.PLAN_SOURCE_NL), beheer.PLAN_SOURCES);
  const app = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const m = app.match(/const SOURCE_NL=(\{[^}]+\})/);
  assert.ok(m, 'app.js heeft SOURCE_NL');
  // eslint-disable-next-line no-new-func
  assert.deepStrictEqual(Function(`return ${m[1]}`)(), beheer.PLAN_SOURCE_NL, 'scherm en server noemen de bronnen gelijk');
});
