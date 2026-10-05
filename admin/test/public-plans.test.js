'use strict';
// GET /api/user/billing/plans says what /pricing and the checkout sell.
// PLAN-46-A: the list was a hand-kept array (Pro 9/89, 5 MB, no Firm) while
// /pricing sold Firm at 29/290 excl. VAT with 500 MB files.
const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { plans } = require('../lib/public-plans');
const catalog = require('../../relay/lib/billing-catalog');

test('Firm and ParaSign Business are listed at the catalog price', () => {
  const list = plans();
  const firm = list.find((p) => p.id === 'firm');
  assert.ok(firm, 'Firm is in the list');
  assert.strictEqual(firm.price_monthly_eur, 29);
  assert.strictEqual(firm.price_yearly_eur, 290);
  assert.strictEqual(String(firm.price_monthly_eur_incl_vat), String(Number(catalog.CATALOG.firm.firm.monthly)));
  assert.strictEqual(firm.limits.file_size_mb, 500);
  assert.deepStrictEqual(firm.includes.map((g) => `${g.product}:${g.tier}`).sort(), ['parasend:pro', 'parasign:pro']);
  const biz = list.find((p) => p.id === 'parasign_business');
  assert.ok(biz && biz.price_monthly_eur === 299);
  assert.ok(!list.some((p) => p.id === 'pro' && p.price_monthly_eur === 9), 'the old Pro 9/89 row is gone');
});

test('every plan on sale is in the list, and server.js keeps no list of its own', () => {
  const ids = plans().map((p) => `${p.product}:${p.plan}`);
  for (const o of catalog.ON_SALE) assert.ok(ids.includes(`${o.product}:${o.plan}`), `${o.product}/${o.plan} listed`);
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.doesNotMatch(src, /const PLANS = \[/);
});
