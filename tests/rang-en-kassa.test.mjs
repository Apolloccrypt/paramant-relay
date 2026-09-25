// Een tweede aankoop, een cadeaucode en een herstart, over twee echte relays.
// Bevindingen R2, R3, R8 en R9 uit de betaaltest van 25-09-2026, en de review
// van #515.
//
// WAAROM TWEE RELAYS. Het geld komt binnen op relay-main (nginx stuurt de
// publieke /v2 daarheen) en elk scherm leest relay-health. users.json is per
// container; alleen redis is gedeeld, en een relay neemt uit redis nooit een
// LAGER recht over (entitlements.mergeProductGrantInto). Dus wie op main een
// recht verlaagt, laat de vloot uit elkaar lopen: de /v2-API zegt Pro terwijl
// de schermen Business tonen. Dat is R3, en op een relay is het onzichtbaar.
//
// WAT HIER GEBEURT:
//   R8  de kassa verkoopt precies wat de site verkoopt (billing-catalog ON_SALE,
//       door relay/test/pricing-page.test.js aan de knoppen vastgepind), en
//       weigert een ander plan naast een lopend plan; verlengen mag
//   R2  twee tabbladen, in beide volgordes: een Firm-jaar en een Business-maand
//       geven een maand Business en daarna Pro tot het einde van het jaar, op
//       beide relays, ook na een herstart. De eerste reparatie liet hier elf
//       betaalde maanden Pro verdwijnen (review #515)
//   R3  een Firm-betaling, een cadeaucode en de admin laten een lopende
//       Business-termijn staan; de admin kan hem alleen uitdrukkelijk verlagen,
//       en dan met zijn einddatum
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

// Wat een relay het account geeft, zoals elk scherm het leest: het recht uit
// /v2/admin/entitlements, en uit /v2/admin/keys de dag waarop het betaalde
// deel afloopt. Plus alle termijnen die de relay op schijf heeft, zodat een
// verschil tussen main en health ook zichtbaar is voordat het een ander recht
// oplevert.
const usersRec = (file, key) => (JSON.parse(fs.readFileSync(file, 'utf8')).api_keys || []).find((k) => k.key === key) || {};
async function recht(port, file, key) {
  const r = await http(port, `/v2/admin/entitlements/${key}`, { headers: ADMIN() });
  const e = (r.json && r.json.entitlements) || {};
  const l = await http(port, '/v2/admin/keys?reveal=1', { headers: ADMIN() });
  const k = ((l.json && l.json.keys) || []).find((x) => x.key === key) || {};
  const u = usersRec(file, key);
  const termijnen = (t) => (t ? Object.keys(t).sort().map((tier) => `${tier}:${String(t[tier].until || '').slice(0, 10)}`).join(',') : '');
  return {
    ondertekenen: e.parasign && e.parasign.tier, ondertekenenTot: (k.paid_until_parasign || '').slice(0, 10),
    versturen: e.parasend && e.parasend.tier, versturenTot: (k.paid_until_parasend || '').slice(0, 10),
    termijnen: termijnen(u.terms_parasign),
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

const dag = (ms) => new Date(ms).toISOString().slice(0, 10);
const plusMaanden = (n) => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() + n); return dag(d.getTime()); };

// Twee tabbladen: beide kassa-aanroepen gebeuren voordat er iets betaald is,
// dus beide geven 200. Daarna worden ze in de gegeven volgorde betaald.
async function tweeTabbladen(acc, volgorde) {
  const plannen = { firm: ['firm', 'firm', 'yearly'], business: ['parasign', 'business', 'monthly'] };
  const open = {};
  for (const wat of volgorde) {
    const c = await kassa(acc, ...plannen[wat]);
    assert.equal(c.status, 200, `tabblad ${wat}: ${c.status} ${c.text}`);
    open[wat] = c.json.payment_id;
  }
  for (const wat of volgorde) await betaal(open[wat]);
  return beide(acc.key);
}

// Wat beide volgordes moeten opleveren: een maand Business, en een jaar Pro
// dat eronder blijft liggen, op beide relays en in de gedeelde rij. De
// schermen noemen het einde van het betaalde deel: het einde van het jaar,
// niet van de maand, want daarna valt hij niet terug op Community.
async function geenTijdKwijt(acc, naam) {
  const na = await beide(acc.key);
  assert.equal(na.ondertekenen, 'business', naam);
  assert.equal(na.ondertekenenTot, plusMaanden(12), `${naam}: betaald tot het einde van het jaar`);
  assert.equal(na.versturen, 'pro', naam);
  assert.equal(na.versturenTot, plusMaanden(12), `${naam}: Versturen een jaar`);
  assert.equal(na.termijnen, `business:${plusMaanden(1)},pro:${plusMaanden(12)}`,
    `${naam}: het Firm-jaar moet onder de Business-maand blijven liggen`);
  const rij = await S.redis.hGetAll(`paramant:entitlements:grant:${acc.key}`);
  const inRij = JSON.parse(rij.terms_parasign || '{}');
  assert.deepEqual(Object.keys(inRij).sort(), ['business', 'pro'], `${naam}: de gedeelde rij draagt beide termijnen`);
  return na;
}

test('twee tabbladen: eerst een Firm-jaar, dan een Business-maand', async () => {
  await tweeTabbladen(A.firmJaar, ['firm', 'business']);
  await geenTijdKwijt(A.firmJaar, 'Firm-jaar dan Business-maand');
});

test('twee tabbladen: eerst een Business-maand, dan een Firm-jaar', async () => {
  await tweeTabbladen(A.businessFirm, ['business', 'firm']);
  await geenTijdKwijt(A.businessFirm, 'Business-maand dan Firm-jaar');
});

test('R3: een cadeaucode verlaagt een lopende Business-termijn niet', async () => {
  const code = 'RANG' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const cp = await http(S.relayPort, '/v2/admin/coupons', { method: 'POST', headers: { 'X-Admin-Token': S.adminToken },
    body: { code, max_redemptions: 5 } });
  assert.ok(cp.status < 300, `code aanmaken: ${cp.status} ${cp.text}`);

  const acc = A.businessCode;
  await koop(acc, 'parasign', 'business', 'monthly');
  const biz = await beide(acc.key);

  // De kassa: een ander plan naast Business niet, dezelfde Business verlengen wel.
  const voor = S.mollie.payments.size;
  const firm = await kassa(acc, 'firm', 'firm', 'monthly');
  assert.equal(firm.status, 409, `Firm naast een lopende Business-termijn: ${firm.status} ${firm.text}`);
  assert.equal(firm.json && firm.json.error, 'other_plan_running');
  assert.match(String(firm.json && firm.json.message), /ParaSign Business/);
  assert.equal(S.mollie.payments.size, voor, 'er mag geen betaling zijn aangemaakt');
  const verleng = await kassa(acc, 'parasign', 'business', 'monthly');
  assert.equal(verleng.status, 200, `Business verlengen: ${verleng.status} ${verleng.text}`);

  const r = await http(S.relayPort, '/v2/billing/redeem', { method: 'POST', headers: { 'X-Api-Key': acc.key }, body: { code } });
  assert.equal(r.status, 200, `inwisselen: ${r.status} ${r.text}`);
  const na = await beide(acc.key);
  assert.equal(na.ondertekenen, 'business', 'de code zette Business terug naar Pro');
  assert.equal(na.ondertekenenTot, biz.ondertekenenTot);
  assert.equal(na.versturen, 'pro', 'de code geeft Versturen Pro erbij');
  assert.doesNotMatch(String(r.json && r.json.message), /ParaSign Pro/, 'het bericht belooft een plan dat hij niet krijgt');
  assert.match(String(r.json && r.json.message), /ParaSign Business/);

  // Een code die alleen iets geeft wat er al hoger loopt: 409, en niets verbruikt.
  const alleenPro = 'RANGPS' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const cp2 = await http(S.relayPort, '/v2/admin/coupons', { method: 'POST', headers: { 'X-Admin-Token': S.adminToken },
    body: { code: alleenPro, max_redemptions: 5, grants: [{ product: 'parasign', tier: 'pro', days: 30 }] } });
  assert.ok(cp2.status < 300, `tweede code aanmaken: ${cp2.status} ${cp2.text}`);
  const r2 = await http(S.relayPort, '/v2/billing/redeem', { method: 'POST', headers: { 'X-Api-Key': acc.key }, body: { code: alleenPro } });
  assert.equal(r2.status, 409, `een code zonder iets toe te voegen: ${r2.status} ${r2.text}`);
  assert.equal(r2.json && r2.json.error, 'nothing_to_add');
  // Gelezen via de route die bestaat. Een GET op de code zelf geeft 405.
  const doc = await http(S.relayPort, `/v2/admin/coupons/${alleenPro}/redemptions`, { headers: { 'X-Admin-Token': S.adminToken } });
  assert.equal(doc.status, 200, `de inwisselingen lezen: ${doc.status} ${doc.text}`);
  assert.strictEqual(doc.json.coupon.used, 0, 'de code is niet verbruikt');
  assert.deepEqual(doc.json.redemptions, [], 'er staat geen inwisseling op naam van dit account');
  assert.deepEqual(await beide(acc.key), na);
});

test('R3: via de admin wordt Business niet stil verlaagd, en uitdrukkelijk verlagen houdt de einddatum', async () => {
  const acc = A.businessAdmin;
  await koop(acc, 'parasign', 'business', 'monthly');
  const biz = await beide(acc.key);
  // Zoals de admin het doet: via admin/server.js, die het naar elke relay stuurt.
  const sid = 'rang-' + crypto.randomBytes(8).toString('hex');
  await S.redis.set(`paramant:admin:session:${sid}`, '1', { EX: 600 });
  const admin = (body) => http(S.adminPort, '/api/admin/set-product-plan', { method: 'POST', headers: { 'X-Session': sid }, body });

  const stil = await admin({ key: acc.key, product: 'parasign', tier: 'pro' });
  assert.equal(stil.status, 409, `Pro over Business via de admin: ${stil.status} ${stil.text}`);
  assert.equal(stil.json && stil.json.error, 'lower_than_running');
  assert.match(String(stil.json && stil.json.message), /downgrade/, 'de weigering noemt de weg die de termijn houdt');
  assert.doesNotMatch(String(stil.json && stil.json.message), /free first/, 'de oude weg gaf Pro zonder einddatum');
  assert.equal(stil.json && stil.json.partial_failure, undefined, 'een weigering op elke relay is geen gedeeltelijke fout');
  assert.deepEqual(await beide(acc.key), biz, 'een weigering verandert niets');

  const omlaag = await admin({ key: acc.key, product: 'parasign', tier: 'pro', downgrade: true });
  assert.equal(omlaag.status, 200, `uitdrukkelijk verlagen: ${omlaag.status} ${omlaag.text}`);
  const pro = await beide(acc.key);
  assert.equal(pro.ondertekenen, 'pro');
  assert.equal(pro.ondertekenenTot, biz.ondertekenenTot, 'verlagen houdt de einddatum, en wordt geen Pro zonder einde');

  const weg = await admin({ key: acc.key, product: 'parasign', tier: 'free' });
  assert.equal(weg.status, 200, `intrekken: ${weg.status} ${weg.text}`);
  assert.equal((await beide(acc.key)).ondertekenen, 'free');
});

// Als laatste: dit herstart beide relays, met de klok verder gezet op schijf.
// Voor de twee tabbladen is de Business-maand voorbij; voor R9 loopt de
// Firm-maand over zes dagen af. De gedeelde rijen gaan eerst weg, anders
// brengt de oude rij de Business-maand van voor de herstart terug.
test('na een herstart: Pro tot het einde van het jaar, en één Firm-mail', async () => {
  await koop(A.kassa, 'firm', 'firm', 'monthly');
  const over6 = new Date(Date.now() + 6 * DAY).toISOString();
  const gisteren = new Date(Date.now() - DAY).toISOString();
  const tabs = [A.firmJaar.key, A.businessFirm.key];
  const zet = (j) => {
    for (const k of j.api_keys || []) {
      if (k.key === A.kassa.key) {
        k.paid_until_parasign = over6;
        k.paid_until_parasend = over6;
      }
      if (tabs.includes(k.key)) {
        assert.ok(k.terms_parasign && k.terms_parasign.business && k.terms_parasign.pro, 'beide termijnen staan in users.json');
        k.terms_parasign.business.until = gisteren;
        if (k.plan_parasign === 'business') k.paid_until_parasign = gisteren;
      }
    }
  };
  S.resend.clear();
  await S.redis.del('paramant:billing:expiry');
  await S.redis.del('paramant:billing:expiry_meta');
  for (const key of [A.kassa.key, ...tabs]) await S.redis.del(`paramant:entitlements:grant:${key}`);
  for (const welke of ['main', 'health']) await S.restartRelay(welke, zet, { PLAN_EXPIRY_BOOT_DELAY_MS: '1200' });
  await sleep(5000);

  for (const acc of [A.firmJaar, A.businessFirm]) {
    const na = await beide(acc.key);
    assert.equal(na.ondertekenen, 'pro', 'na de Business-maand terug op Pro, niet op free');
    assert.equal(na.ondertekenenTot, plusMaanden(12), 'Pro tot het einde van het betaalde jaar');
    assert.equal(na.versturen, 'pro');
    assert.equal(S.resend.mails.filter((m) => [].concat(m.to).includes(acc.email)).length, 0,
      'het einde van de Business-maand is geen einde van het account, dus geen mail');
  }
  const mails = S.resend.mails.filter((m) => [].concat(m.to).includes(A.kassa.email));
  assert.equal(mails.length, 1, `één termijn, één waarschuwing; kwam: ${mails.map((m) => m.subject).join(' | ')}`);
  assert.match(String(mails[0].subject), /Firm/, 'de waarschuwing noemt het plan dat de klant kocht');
});
