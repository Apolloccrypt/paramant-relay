// Een tweede aankoop, een cadeaucode en een herstart, over twee echte relays.
// Bevindingen R2, R3, R8 en R9 uit de betaaltest van 25-09-2026.
//
// WAAROM TWEE RELAYS. Het geld komt binnen op relay-main (nginx stuurt de
// publieke /v2 daarheen) en elk scherm leest relay-health. users.json is per
// container; alleen redis is gedeeld, en een relay neemt uit redis nooit een
// LAGER recht over (entitlements.mergeProductGrantInto). Dus wie op main een
// recht verlaagt, laat de vloot uit elkaar lopen: de /v2-API zegt Pro terwijl
// de schermen Business tonen. Dat is R3, en op een relay is het onzichtbaar.
//
// WAT HIER GEBEURT, per bevinding:
//   R8  de kassa verkoopt precies wat de site verkoopt (billing-catalog ON_SALE,
//       door relay/test/pricing-page.test.js aan de knoppen vastgepind), en
//       weigert een tweede plan over een lopend ander plan heen
//   R2  een Business-maand die toch binnenkomt bij een Firm-jaarklant (een
//       betaallink, een oud abonnement, een race) geeft een maand Business
//   R3  een Firm-betaling, een cadeaucode en een admin-toekenning laten een
//       lopende Business-termijn staan, op BEIDE relays
//   R9  een Firm-termijn geeft na een herstart één waarschuwingsmail, en die
//       noemt Firm
//
// Echt: twee relay.js, de admin, redis. Nagebouwd: Mollie en Resend, bereikt
// via de code die in productie draait (tests/helpers/mollie-intercept.cjs).
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test tests/rang-en-kassa.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const stack = require('./helpers/koper-stack.cjs');
const catalog = require('../relay/lib/billing-catalog.js');

const DAY = 86400000;
let S;
// Vijf accounts en niet meer: een relay zonder licentie houdt vijf actieve
// sleutels (relay.js COMMUNITY_KEY_LIMIT, BUSL). Elke test krijgt de zijne;
// R9 gebruikt het account van de kassatest opnieuw, dat nog niets kocht.
const A = {};

test.before(async () => {
  S = await stack.start();
  A.kassa = await account('kassa');
  A.firmJaar = await account('firm-jaar');
  A.businessFirm = await account('business-firm');
  A.businessCode = await account('business-code');
  A.businessAdmin = await account('business-admin');
});
test.after(async () => { if (S) await S.stop(); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function http(port, p, { method = 'GET', headers = {}, body } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(`http://127.0.0.1:${port}${p}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) { /* geen json */ }
  return { status: r.status, json, text };
}
const ADMIN = () => ({ 'X-Admin-Token': S.adminToken, 'X-Internal-Auth': S.internalToken });

// Een account zoals de admin er een aanmaakt: op beide relays.
async function account(label) {
  const key = 'pgp_' + crypto.randomBytes(32).toString('hex');
  const email = `${label}-${crypto.randomBytes(3).toString('hex')}@example.test`;
  for (const port of [S.relayPort, S.healthPort]) {
    const r = await http(port, '/v2/admin/keys', { method: 'POST', headers: { 'X-Admin-Token': S.adminToken },
      body: { key, email, label, plan: 'community', active: true } });
    assert.ok(r.status < 300, `account op ${port}: ${r.status} ${r.text}`);
  }
  return { key, email };
}

// Wat een relay het account geeft, en de einddatum die hij op schijf heeft.
async function recht(port, file, key) {
  const r = await http(port, `/v2/admin/entitlements/${key}`, { headers: ADMIN() });
  const e = (r.json && r.json.entitlements) || {};
  const u = (JSON.parse(fs.readFileSync(file, 'utf8')).api_keys || []).find((k) => k.key === key) || {};
  return {
    ondertekenen: e.parasign && e.parasign.tier, ondertekenenTot: (u.paid_until_parasign || '').slice(0, 10),
    versturen: e.parasend && e.parasend.tier, versturenTot: (u.paid_until_parasend || '').slice(0, 10),
  };
}
// Beide relays, na een korte pauze voor de gedeelde rij in redis.
async function beide(key) {
  await sleep(400);
  const main = await recht(S.relayPort, S.usersFile, key);
  const health = await recht(S.healthPort, S.healthUsersFile, key);
  assert.deepEqual(health, main, 'main en health zijn het oneens over wat dit account heeft');
  return main;
}

const kassa = (acc, product, plan, interval) => http(S.relayPort, '/v2/billing/checkout', {
  method: 'POST', headers: { 'X-Api-Key': acc.key }, body: { product, plan, interval } });

// De testkassa van de nagebouwde Mollie: betalen roept de webhook aan, zoals
// Mollie dat doet.
async function betaal(paymentId) {
  await fetch(`${S.mollieOrigin}/checkout/${paymentId}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'outcome=paid', redirect: 'manual' });
  await sleep(500);
}
async function koop(acc, product, plan, interval) {
  const c = await kassa(acc, product, plan, interval);
  assert.equal(c.status, 200, `kassa ${product}/${plan}/${interval}: ${c.status} ${c.text}`);
  await betaal(c.json.payment_id);
  return c.json.payment_id;
}
// Geld dat buiten onze kassa om binnenkomt, met dezelfde metadata: een
// betaallink uit het Mollie-dashboard, een abonnement van voor een wijziging,
// of twee tabbladen die tegelijk afrekenen. De webhook moet het dan nog steeds
// goed doen, want het geld is er al.
async function geldBuitenDeKassa(acc, product, plan, interval) {
  const order = catalog.resolveOrder({ product, plan, interval });
  const r = await fetch(`${S.mollieOrigin}/v2/payments`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: { currency: 'EUR', value: order.amount },
      description: catalog.orderLabel(order),
      metadata: { accountId: acc.key, product, plan, interval },
      webhookUrl: `http://127.0.0.1:${S.relayPort}/v2/billing/webhook`,
    }),
  });
  const p = await r.json();
  await betaal(p.id);
  return p.id;
}
const maandenVanaf = (iso) => Math.round((Date.parse(iso) - Date.now()) / (30.44 * DAY) * 10) / 10;

test('R8: de kassa verkoopt wat de site verkoopt, en niets anders', async () => {
  const acc = A.kassa;
  for (const { product, plan } of catalog.ON_SALE) {
    for (const interval of catalog.INTERVALS) {
      const c = await kassa(acc, product, plan, interval);
      assert.equal(c.status, 200, `${product}/${plan}/${interval} staat op de site: ${c.status} ${c.text}`);
    }
  }
  for (const [product, plan] of [['parasign', 'pro'], ['parasend', 'pro']]) {
    const voor = S.mollie.payments.size;
    const c = await kassa(acc, product, plan, 'monthly');
    assert.equal(c.status, 400, `${product}/${plan} staat op geen pagina en werd toch verkocht`);
    assert.equal(c.json && c.json.error, 'not_on_sale');
    assert.equal(S.mollie.payments.size, voor, 'er mag geen betaling zijn aangemaakt');
  }
});

test('R2: een Firm-jaar en daarna een Business-maand', async () => {
  const acc = A.firmJaar;
  await koop(acc, 'firm', 'firm', 'yearly');
  const jaar = await beide(acc.key);
  assert.equal(jaar.ondertekenen, 'pro');

  // Via de kassa: geweigerd, met een zin, en er gaat geen geld over.
  const voor = S.mollie.payments.size;
  const c = await kassa(acc, 'parasign', 'business', 'monthly');
  assert.equal(c.status, 409, `een Business-maand over een lopend Firm-jaar: ${c.status} ${c.text}`);
  assert.equal(c.json && c.json.error, 'other_plan_running');
  assert.match(String(c.json && c.json.message), /ParaSign Pro/);
  assert.equal(S.mollie.payments.size, voor);

  // Komt het geld toch binnen, dan geeft het een maand Business, geen dertien.
  await geldBuitenDeKassa(acc, 'parasign', 'business', 'monthly');
  const na = await beide(acc.key);
  assert.equal(na.ondertekenen, 'business');
  assert.ok(maandenVanaf(na.ondertekenenTot) <= 1.1,
    `een betaalde Business-maand liep tot ${na.ondertekenenTot}, ${maandenVanaf(na.ondertekenenTot)} maanden`);
  assert.equal(na.versturen, 'pro');
  assert.equal(na.versturenTot, jaar.versturenTot, 'Versturen uit het Firm-jaar blijft staan');
});

test('R3: een Business-klant die Firm koopt, houdt Business, op beide relays', async () => {
  const acc = A.businessFirm;
  await koop(acc, 'parasign', 'business', 'monthly');
  const biz = await beide(acc.key);
  assert.equal(biz.ondertekenen, 'business');

  const c = await kassa(acc, 'firm', 'firm', 'monthly');
  assert.equal(c.status, 409, `Firm over een lopende Business-termijn: ${c.status} ${c.text}`);
  assert.equal(c.json && c.json.error, 'other_plan_running');

  await geldBuitenDeKassa(acc, 'firm', 'firm', 'monthly');
  const na = await beide(acc.key);
  assert.equal(na.ondertekenen, 'business', 'de Firm-betaling zette Business terug');
  assert.equal(na.ondertekenenTot, biz.ondertekenenTot);
  assert.equal(na.versturen, 'pro', 'wat Firm erbij geeft, komt er wel bij');
});

test('R3: een cadeaucode verlaagt een lopende Business-termijn niet', async () => {
  const code = 'RANG' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const cp = await http(S.relayPort, '/v2/admin/coupons', { method: 'POST', headers: { 'X-Admin-Token': S.adminToken },
    body: { code, max_redemptions: 5 } });
  assert.ok(cp.status < 300, `code aanmaken: ${cp.status} ${cp.text}`);

  const acc = A.businessCode;
  await koop(acc, 'parasign', 'business', 'monthly');
  const biz = await beide(acc.key);

  const r = await http(S.relayPort, '/v2/billing/redeem', { method: 'POST', headers: { 'X-Api-Key': acc.key }, body: { code } });
  assert.equal(r.status, 200, `inwisselen: ${r.status} ${r.text}`);
  const na = await beide(acc.key);
  assert.equal(na.ondertekenen, 'business', 'de code zette Business terug naar Pro');
  assert.equal(na.ondertekenenTot, biz.ondertekenenTot);
  assert.equal(na.versturen, 'pro', 'de code geeft Versturen Pro erbij');
  assert.doesNotMatch(String(r.json && r.json.message), /ParaSign Pro/, 'het bericht belooft een plan dat hij niet krijgt');
  assert.match(String(r.json && r.json.message), /ParaSign Business/);

  // Een code die alleen iets geeft wat er al hoger loopt: niets verbruikt.
  const alleenPro = 'RANGPS' + crypto.randomBytes(3).toString('hex').toUpperCase();
  await http(S.relayPort, '/v2/admin/coupons', { method: 'POST', headers: { 'X-Admin-Token': S.adminToken },
    body: { code: alleenPro, max_redemptions: 5, grants: [{ product: 'parasign', tier: 'pro', days: 30 }] } });
  const r2 = await http(S.relayPort, '/v2/billing/redeem', { method: 'POST', headers: { 'X-Api-Key': acc.key }, body: { code: alleenPro } });
  assert.equal(r2.status, 409, `een code zonder iets toe te voegen: ${r2.status} ${r2.text}`);
  assert.equal(r2.json && r2.json.error, 'nothing_to_add');
  const doc = await http(S.relayPort, `/v2/admin/coupons/${alleenPro}`, { headers: { 'X-Admin-Token': S.adminToken } });
  assert.equal((doc.json && doc.json.coupon && doc.json.coupon.used) || 0, 0, 'de code is niet verbruikt');
  assert.deepEqual(await beide(acc.key), na);
});

test('R3: een admin-toekenning verlaagt een lopende Business-termijn niet, en intrekken kan nog', async () => {
  const acc = A.businessAdmin;
  await koop(acc, 'parasign', 'business', 'monthly');
  const biz = await beide(acc.key);
  // Zoals de admin het doet: dezelfde aanroep op elke relay.
  for (const port of [S.relayPort, S.healthPort]) {
    const r = await http(port, '/v2/admin/keys/set-product-plan', { method: 'POST', headers: ADMIN(),
      body: { key: acc.key, product: 'parasign', tier: 'pro' } });
    assert.equal(r.status, 409, `Pro over Business op ${port}: ${r.status} ${r.text}`);
    assert.equal(r.json && r.json.error, 'lower_than_running');
  }
  assert.deepEqual(await beide(acc.key), biz);
  // De vloer is geen toekenning maar intrekken, en dat blijft werken.
  for (const port of [S.relayPort, S.healthPort]) {
    const r = await http(port, '/v2/admin/keys/set-product-plan', { method: 'POST', headers: ADMIN(),
      body: { key: acc.key, product: 'parasign', tier: 'free' } });
    assert.equal(r.status, 200, `intrekken op ${port}: ${r.status} ${r.text}`);
  }
  assert.equal((await beide(acc.key)).ondertekenen, 'free');
});

// Als laatste: dit herstart beide relays.
test('R9: een Firm-termijn geeft na een herstart één waarschuwing, en die noemt Firm', async () => {
  const acc = A.kassa;
  await koop(acc, 'firm', 'firm', 'monthly');
  const over6 = new Date(Date.now() + 6 * DAY).toISOString();
  const zet = (j) => {
    for (const k of j.api_keys || []) {
      if (k.key !== acc.key) continue;
      k.paid_until_parasign = over6;
      k.paid_until_parasend = over6;
    }
  };
  S.resend.clear();
  await S.redis.del('paramant:billing:expiry');
  await S.redis.del('paramant:billing:expiry_meta');
  for (const welke of ['main', 'health']) await S.restartRelay(welke, zet, { PLAN_EXPIRY_BOOT_DELAY_MS: '1200' });
  await sleep(5000);
  const mails = S.resend.mails.filter((m) => [].concat(m.to).includes(acc.email));
  assert.equal(mails.length, 1, `één termijn, één waarschuwing; kwam: ${mails.map((m) => m.subject).join(' | ')}`);
  assert.match(String(mails[0].subject), /Firm/, 'de waarschuwing noemt het plan dat de klant kocht');
});
