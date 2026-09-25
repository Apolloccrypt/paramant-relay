'use strict';
// De incassolaag op een echt opgestarte relay.js, tegen de fake Mollie.
//
// WAAROM. De betaalflowtest van 25-09 vond zeven fouten in de laag die pas geld
// kost als BILLING_MODE aan gaat (R4, R5, R6, R10, R11, R12, R13). Op productie
// staat die laag uit: BILLING_MODE leeg met een live_-sleutel is live zonder
// mandaten, en dat blijft zo. Juist daarom moet hij kloppen voordat iemand de
// vlag omzet, en dat kan alleen hier: met de relay, de webhookroute en
// lib/mollie.js ongewijzigd, en alleen de overkant van de lijn vervangen
// (tests/helpers/fake-mollie.cjs, via mollie-intercept.cjs).
//
// Per bevinding een scenario. Accounts zijn schaars (vijf per relay, zie ACC):
// de twee R5-gevallen delen er een en R12 draait na R10 op dat van R10; waar
// een vers account nodig is, start de test een tweede relay. De fake roept zelf
// nooit een webhook aan (webhook-off): de test stuurt ze, zoals Mollie dat doet,
// en kan ze dus ook dertig keer tegelijk sturen.
//
// Nodig: een redis in REDIS_URL. De suite neemt een eigen database-index
// (INCASSO_REDIS_DB, standaard 10) en leegt die, omdat de herinneringssweep
// alles leest wat in zijn index staat: in een gedeelde database zou hij mails
// van andere suites versturen.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const fakeMollie = require('../../tests/helpers/fake-mollie.cjs');
const fakeResend = require('../../tests/helpers/fake-resend.cjs');
const entitlements = require('../lib/entitlements');
const billingRecurring = require('../lib/billing-recurring');
const planExpiry = require('../lib/plan-expiry');
const catalog = require('../lib/billing-catalog');
const mollieLib = require('../lib/mollie');

const INTERCEPT = path.join(__dirname, '..', '..', 'tests', 'helpers', 'mollie-intercept.cjs');
const DB = parseInt(process.env.INCASSO_REDIS_DB || '10', 10);
const RUN = `${process.pid}_${Date.now().toString(36)}`;
// Een poort waar niets luistert. Webhook- en redirect-URL's wijzen hierheen,
// zodat ook een verdwaalde aanroep nooit een echte host bereikt.
const NOWHERE = 'http://127.0.0.1:9';
const TEST_KEY = 'test_dummy_key_for_the_fake';
// De veldnamen zoals ze in users.json staan, letterlijk: keys-table leest ze
// onder deze namen terug.
const field = 'mollie_subscription_firm';
const madeBy = 'mollie_subscription_firm_payment';

// Vijf accounts, niet meer: een relay zonder licentie weigert de zesde sleutel
// met 402 (COMMUNITY_KEY_LIMIT). R5 draait zijn twee gevallen na elkaar op één
// account, en R12 draait op het account van R10, na R10.
const ACC = Object.fromEntries(['r4', 'r5', 'r6', 'r10', 'r11'].map((n) => [n, {
  key: `pgp_incasso_${n}_${RUN}`,
  acct: `acct_demo_${n}_${RUN}`,
  email: `${n}-${RUN}@example.test`,
}]));

let redis = null;
let mollie = null;
let resend = null;
let srv = null;
let bootOpts = null;
let checks = 0;
const did = () => { checks++; };

function withDb(url, db) {
  const u = new URL(url);
  u.pathname = '/' + db;
  return u.toString();
}

before(async () => {
  const probe = await requireRedis('redis://127.0.0.1:6379');
  if (!probe) return;
  const url = withDb(probe.options.url, DB);
  await probe.disconnect();
  const { createClient } = require('redis');
  redis = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  redis.on('error', () => {});
  await redis.connect();
  await redis.flushDb();

  mollie = fakeMollie.create();
  const mollieOrigin = await mollie.listen();
  resend = fakeResend.create();
  const resendOrigin = await resend.listen();
  // Voor de eerste betaling: de fake belt nooit zelf een webhook.
  await ctl('/_ctl/webhook-off', { off: true });

  bootOpts = {
    tag: 'incasso',
    usersFile: true,
    users: {
      api_keys: Object.values(ACC).map((a) => ({
        key: a.key, plan: 'community', active: true, parasign: true, account_id: a.acct, email: a.email,
      })),
    },
    env: {
      REDIS_URL: url,
      RELAY_REDIS_URL: url,
      NODE_OPTIONS: `--require ${INTERCEPT}`,
      FAKE_MOLLIE_URL: mollieOrigin,
      FAKE_RESEND_URL: resendOrigin,
      RESEND_API_KEY: 're_test_key_for_the_sink',
      MAIL_PROVIDER: 'resend',
      BILLING_MODE: 'test',
      MOLLIE_TEST_API_KEY: TEST_KEY,
      PARASIGN_PUBLIC_ORIGIN: NOWHERE,
      SITE_URL: NOWHERE,
    },
  };
  srv = await boot(bootOpts);
});

after(async () => {
  await killAll();
  if (mollie) await mollie.close();
  if (resend) await resend.close();
  if (redis) { try { await redis.flushDb(); await redis.disconnect(); } catch (_) { /* al weg */ } }
  summary('incasso-latent', checks);
});

// ── hulpjes ──────────────────────────────────────────────────────────────────

async function ctl(p, body) {
  const r = await fetch(mollie.origin() + p, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}),
  });
  return r.json();
}

async function checkout(a, interval = 'monthly', handle = srv) {
  const r = await handle.post('/v2/billing/checkout', {
    headers: { 'X-Api-Key': a.key },
    body: { product: 'firm', plan: 'firm', interval },
  });
  assert.strictEqual(r.status, 200, `checkout gaf ${r.status}: ${r.text}`);
  return r.json.payment_id;
}

// De koper klikt Betaal op de testkassa. De fake zet de betaling op paid en
// maakt het mandaat; de webhook stuurt de test zelf.
async function pay(id) {
  const r = await fetch(`${mollie.origin()}/checkout/${id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'outcome=paid', redirect: 'manual',
  });
  assert.strictEqual(r.status, 302, 'de testkassa nam de betaling niet aan');
}

function webhook(id, handle = srv) {
  return handle.post('/v2/billing/webhook', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `id=${encodeURIComponent(id)}`,
  });
}

async function buy(a, interval = 'monthly', handle = srv) {
  const id = await checkout(a, interval, handle);
  await pay(id);
  const r = await webhook(id, handle);
  assert.strictEqual(r.status, 200, `webhook gaf ${r.status}: ${r.text}`);
  return id;
}

// Een account dat alleen deze test kent, voor een relay van zijn eigen.
const account = (tag) => ({
  key: `pgp_incasso_${tag}_${RUN}`, acct: `acct_demo_${tag}_${RUN}`, email: `${tag}-${RUN}@example.test`,
});

// Een tweede relay op dezelfde redis, fake Mollie en mailbox, met eigen
// accounts: de eerste zit aan zijn vijf sleutels.
async function relayWith(tag, accounts) {
  return boot({
    ...bootOpts, tag,
    users: {
      api_keys: accounts.map((a) => ({
        key: a.key, plan: 'community', active: true, parasign: true, account_id: a.acct, email: a.email,
      })),
    },
  });
}

// De klanten die Mollie voor dit account kent.
const customersOf = (a) => [...mollie.customers.values()]
  .filter((c) => c.metadata && c.metadata.accountId === a.acct);

const subsOf = (a) => [...mollie.subscriptions.values()]
  .filter((s) => s.metadata && s.metadata.accountId === a.acct);
const activeSubsOf = (a) => subsOf(a).filter((s) => s.status === 'active');

function logLines(handle = srv) {
  return handle.log().split('\n').map((l) => { try { return JSON.parse(l); } catch (_) { return null; } })
    .filter(Boolean);
}

function recordOf(a, handle = srv) {
  const ud = handle.readUsersFile();
  return (ud.api_keys || []).find((k) => k.account_id === a.acct) || {};
}

async function waitFor(fn, ms = 8000, what = 'voorwaarde') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`${what} niet bereikt binnen ${ms} ms`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

const mailsTo = (a) => resend.mails.filter((m) => [].concat(m.to).includes(a.email));
const dayOf = (iso) => new Date(iso).toISOString().slice(0, 10);

// ── R4 ───────────────────────────────────────────────────────────────────────

// Dertig tegelijk, zo gelijk als het kan: de fake houdt de dertig keer ophalen
// van de betaling vast tot ze er alle dertig zijn, en antwoordt ze dan samen.
// Zonder die poort hing de race van de snelheid van de machine af, en bleef de
// test ook zonder slot vaak groen. Met de poort gaf de relay zonder slot in 8 van
// de 10 runs 2 tot 30 abonnementen. Helemaal vast is het niet: of de dertig
// antwoorden in één ronde van de event loop landen, bepaalt de kernel. Het
// bewijs dat het slot nodig is, staat in de test hierna, die zonder slot altijd
// rood is.
test('R4: dertig gelijktijdige webhooks voor één eerste betaling maken één abonnement', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = ACC.r4;
  const id = await checkout(a);
  await pay(id);
  await ctl('/_ctl/barrier', { method: 'GET', match: `^/v2/payments/${id}$`, count: 30, timeoutMs: 5000 });
  const answers = await Promise.all(Array.from({ length: 30 }, () => webhook(id)));
  for (const r of answers) {
    assert.ok([200, 503].includes(r.status), `een webhook gaf ${r.status}: ${r.text}`);
  }
  did();
  // Een 503 is "later nog eens", zoals Mollie dat doet. Daarna is alles rond.
  const again = await webhook(id);
  assert.strictEqual(again.status, 200);

  const active = activeSubsOf(a);
  assert.strictEqual(active.length, 1,
    `verwacht één actief abonnement, er zijn er ${active.length}: elke maand zoveel incasso's`);
  did();
  const granted = logLines().filter((j) => j.msg === 'billing_webhook' && j.payment_id === id && j.result === 'granted');
  assert.strictEqual(granted.length, 1, `de betaling werd ${granted.length} keer toegekend`);
  did();
  // En bij Mollie zelf: het abonnement gaat mee met een Idempotency-Key per
  // betaling, zodat ook een tweede verzoek geen tweede abonnement maakt.
  const posts = mollie.requests.filter((r) => r.method === 'POST' && /\/subscriptions$/.test(r.path)
    && r.idempotencyKey === `sub-${id}`);
  assert.strictEqual(posts.length, 1, 'het abonnement ging niet met Idempotency-Key sub-<betaling> naar Mollie');
  did();
  // En het slot is weer vrij: geen sleutel meer in redis die het account tot
  // het einde van de TTL op 503 houdt.
  assert.deepStrictEqual(await redis.keys(`paramant:billing:lock:acct:${a.acct}`), [],
    'na de laatste webhook staat het slot van het account nog in redis');
  did();
});

// Twee kassa's, allebei betaald, en de tweede webhook komt binnen terwijl de
// eerste nog bezig is. Dat "terwijl" is hier geen timing maar een feit: de fake
// houdt het aanmaken van het eerste abonnement vast (tot er een tweede komt, of
// twee seconden), en pas als de eerste daar staat te wachten, gaat de tweede
// webhook de deur uit. Zonder slot ziet de tweede nog geen abonnement op het
// account, maakt er ook een, en lopen er elke keer twee. Met slot krijgt hij 503
// en komt hij terug zoals Mollie dat doet. Op een eigen relay, omdat de eerste
// er al vijf sleutels heeft.
test('R4: twee aankopen van één account tegelijk geven één abonnement en twee maanden', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = { key: `pgp_incasso_r4b_${RUN}`, acct: `acct_demo_r4b_${RUN}`, email: `r4b-${RUN}@example.test` };
  const h = await boot({
    ...bootOpts, tag: 'incasso-r4b',
    users: { api_keys: [{ key: a.key, plan: 'community', active: true, parasign: true, account_id: a.acct, email: a.email }] },
  });
  try {
    const id1 = await checkout(a, 'monthly', h);
    const id2 = await checkout(a, 'monthly', h);
    await pay(id1);
    await pay(id2);
    const ids = [id1, id2];
    const seen = mollie.requests.length;
    await ctl('/_ctl/barrier', { method: 'POST', match: '/subscriptions$', count: 2, timeoutMs: 2000 });
    const first = webhook(id1, h);
    await waitFor(() => mollie.requests.slice(seen).some((q) => q.method === 'POST' && /\/subscriptions$/.test(q.path)),
      5000, 'de eerste webhook bij het aanmaken van het abonnement');
    const answers = [null, await webhook(id2, h)];
    answers[0] = await first;
    // Wat 503 kreeg, stuurt Mollie later opnieuw, en alleen dat.
    for (let i = 0; i < 10 && answers.some((r) => r.status === 503); i++) {
      await new Promise((res) => setTimeout(res, 100));
      for (let k = 0; k < ids.length; k++) {
        if (answers[k].status === 503) answers[k] = await webhook(ids[k], h);
      }
    }
    assert.deepStrictEqual(answers.map((r) => r.status), [200, 200]);
    const active = activeSubsOf(a);
    assert.strictEqual(active.length, 1, `twee aankopen tegelijk gaven ${active.length} actieve abonnementen`);
    did();
    const pu = entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign;
    const until = await waitFor(() => {
      const rec = (h.readUsersFile().api_keys || []).find((k) => k.account_id === a.acct) || {};
      return rec[pu] && Date.parse(rec[pu]) > Date.now() + 45 * 86400000 ? rec[pu] : null;
    }, 5000, 'twee maanden voor twee betalingen').catch(() => null);
    assert.ok(until, 'twee betalingen tegelijk kochten samen maar één maand');
    assert.strictEqual(active[0].startDate, dayOf(until), 'het abonnement start niet op het einde van de tweede maand');
    did();
  } finally {
    await h.stop();
  }
});

// ── R5 ───────────────────────────────────────────────────────────────────────

for (const [how, what] of [
  ['/_ctl/refund', 'een volledige terugbetaling'],
  ['/_ctl/chargeback', 'een terugboeking'],
]) {
  test(`R5: na ${what} incasseert het abonnement niet meer`, async (t) => {
    if (!srv) return t.skip('geen redis');
    const a = ACC.r5;
    const id = await buy(a);
    assert.strictEqual(activeSubsOf(a).length, 1, 'na de aankoop hoort er één abonnement te lopen');
    await ctl(how, { id });
    const r = await webhook(id);
    assert.strictEqual(r.status, 200);
    const left = activeSubsOf(a);
    assert.strictEqual(left.length, 0,
      `na ${what} loopt er nog ${left.length} abonnement: de volgende maand wordt opnieuw geïncasseerd`);
    did();
    await waitFor(() => !recordOf(a)[billingRecurring.subscriptionFieldOf('firm')], 5000, 'aanwijzer gewist');
    const line = logLines().find((j) => j.msg === 'billing_subscription_revoked' && j.payment_id === id);
    assert.ok(line && line.result === 'cancelled', 'de opzegging staat niet in het log');
    did();
  });
}

// Waar R5 en R10 op leunen: de relay moet na een herstart nog weten welk
// abonnement een account heeft. users.json had de aanwijzers wel, maar de boot
// las ze niet terug (keys-table.parseAccountFields), dus na elke deploy vond de
// opzegknop niets terwijl Mollie bleef incasseren. Op een eigen relay met een
// vers account, zodat niets van de scenario's hierboven meetelt.
test('R5/R10: na een herstart vindt opzeggen het abonnement nog', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = { key: `pgp_incasso_herstart_${RUN}`, acct: `acct_demo_herstart_${RUN}`, email: `herstart-${RUN}@example.test` };
  let h = await boot({
    ...bootOpts, tag: 'incasso-herstart',
    users: { api_keys: [{ key: a.key, plan: 'community', active: true, parasign: true, account_id: a.acct, email: a.email }] },
  });
  try {
    const id = await checkout(a, 'monthly', h);
    await pay(id);
    assert.strictEqual((await webhook(id, h)).status, 200);
    const [sub] = activeSubsOf(a);
    assert.ok(sub, 'de aankoop opende geen abonnement');
    await waitFor(() => recordOf(a, h)[field] === sub.id, 5000, 'aanwijzer op schijf');
    h = await h.restart();
    const r = await h.post('/v2/billing/cancel', { headers: { 'X-Api-Key': a.key }, body: {} });
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.cancelled, `na de herstart vond opzeggen geen abonnement: ${JSON.stringify(r.json.results)}`);
    assert.strictEqual(mollie.subscriptions.get(sub.id).status, 'canceled', 'het abonnement incasseert na het opzeggen nog');
    did();
  } finally {
    await h.stop();
  }
});

// Het deel van de herlaadfix dat productie wel raakt: paid_by_<product>, de
// betaling die de lopende termijn kocht. Zonder redis-markering is dat het
// enige dat een herhaalde webhook na een herstart tegenhoudt. Viel het herladen
// weg, dan kocht één betaling na elke deploy een maand extra.
test('herstart: dezelfde webhook na een herstart zonder redis-markering kent niets opnieuw toe', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('paidby');
  let h = await relayWith('incasso-paidby', [a]);
  try {
    const id = await buy(a, 'monthly', h);
    const pu = entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign;
    const before = await waitFor(() => recordOf(a, h)[pu], 5000, 'termijn op schijf');
    await waitFor(() => recordOf(a, h).paid_by_parasign === id, 5000, 'paid_by op schijf');
    await redis.del(`paramant:billing:done:${id}`);
    h = await h.restart();
    const r = await webhook(id, h);
    assert.strictEqual(r.status, 200, r.text);
    const line = logLines(h).find((j) => j.msg === 'billing_webhook' && j.payment_id === id);
    assert.ok(line, 'geen billing_webhook-regel na de herstart');
    assert.strictEqual(line.result, 'ignored', `na de herstart werd dezelfde betaling opnieuw ${line.result}`);
    assert.strictEqual(line.reason, 'already_processed');
    await new Promise((res) => setTimeout(res, 200));
    assert.strictEqual(recordOf(a, h)[pu], before, 'de termijn schoof op door een betaling die al verwerkt was');
    did();
  } finally {
    await h.stop();
  }
});

// ── De klant bij het abonnement (review #516, punt 1) ────────────────────────
// Opzeggen en vervangen gingen naar de klant die NU op het account staat, en
// een 404 telde als "al weg". Die klant wisselt: bij elke fout op GET
// /customers maakte de kassa een nieuwe. Mollie kent een abonnement alleen
// onder zijn eigen klant (de fake nu ook), dus dan liep het oude abonnement
// door terwijl het log "opgezegd" zei. Drie wegen daarheen, uit de review.
test('klant: een 503 op de klant bij een tweede aankoop geeft geen tweede klant en één abonnement', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('klant503');
  const h = await relayWith('incasso-klant503', [a]);
  try {
    const id1 = await buy(a, 'monthly', h);
    const cst1 = mollie.payments.get(id1).customerId;
    const [sub1] = activeSubsOf(a);
    assert.ok(cst1 && sub1, 'de eerste aankoop opende geen klant en abonnement');
    await ctl('/_ctl/fail', { method: 'GET', match: `^/v2/customers/${cst1}$`, status: 503, times: 1 });
    await buy(a, 'monthly', h);
    assert.strictEqual(customersOf(a).length, 1,
      `een tijdelijke fout op de klant maakte een nieuwe klant (${customersOf(a).length} klanten)`);
    did();
    const active = activeSubsOf(a);
    assert.strictEqual(active.length, 1, `na de tweede aankoop lopen er ${active.length} abonnementen`);
    assert.strictEqual(mollie.subscriptions.get(sub1.id).status, 'canceled', 'het eerste abonnement loopt nog');
    did();
  } finally {
    await h.stop();
  }
});

test('klant: twee kassa\'s tegelijk voor een nieuwe koper geven één abonnement', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('tweekassa');
  const h = await relayWith('incasso-tweekassa', [a]);
  try {
    const ids = await Promise.all([checkout(a, 'monthly', h), checkout(a, 'monthly', h)]);
    for (const id of ids) await pay(id);
    // Eerst de betaling van de klant die NIET op het account bleef staan: dan
    // moet het vervangen straks een abonnement stoppen dat onder de andere
    // klant hangt. Dat is de volgorde waarin de oude code misging.
    const onFile = await waitFor(() => recordOf(a, h).mollie_customer_id, 5000, 'klant op schijf');
    ids.sort((x, y) => (mollie.payments.get(x).customerId === onFile) - (mollie.payments.get(y).customerId === onFile));
    for (const id of ids) assert.strictEqual((await webhook(id, h)).status, 200);
    const active = activeSubsOf(a);
    assert.strictEqual(active.length, 1, `twee kassa's tegelijk gaven ${active.length} actieve abonnementen`);
    did();
  } finally {
    await h.stop();
  }
});

test('klant: een afgebroken kassa na een 503 laat opzeggen het abonnement nog stoppen', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('afgebroken');
  const h = await relayWith('incasso-afgebroken', [a]);
  try {
    const id1 = await buy(a, 'monthly', h);
    const cst1 = mollie.payments.get(id1).customerId;
    const [sub1] = activeSubsOf(a);
    await ctl('/_ctl/fail', { method: 'GET', match: `^/v2/customers/${cst1}$`, status: 503, times: 1 });
    const id2 = await checkout(a, 'monthly', h);
    // De koper breekt af op de kassa.
    const r = await fetch(`${mollie.origin()}/checkout/${id2}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'outcome=canceled', redirect: 'manual',
    });
    assert.strictEqual(r.status, 302);
    assert.strictEqual((await webhook(id2, h)).status, 200);
    const cancel = await h.post('/v2/billing/cancel', { headers: { 'X-Api-Key': a.key }, body: {} });
    assert.strictEqual(cancel.status, 200, cancel.text);
    assert.strictEqual(mollie.subscriptions.get(sub1.id).status, 'canceled',
      `opzeggen antwoordde ${JSON.stringify(cancel.json.results)}, maar het abonnement loopt door`);
    did();
  } finally {
    await h.stop();
  }
});

// ── Terugdraaien stopt alleen het abonnement van die betaling (punt 6) ───────
test('R5: geld terug voor een oude aankoop laat het abonnement van een latere aankoop staan', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('oudterug');
  const h = await relayWith('incasso-oudterug', [a]);
  try {
    const id1 = await buy(a, 'monthly', h);
    await buy(a, 'monthly', h);
    const [sub2] = activeSubsOf(a);
    assert.ok(sub2, 'na twee aankopen loopt er geen abonnement');
    await ctl('/_ctl/refund', { id: id1 });
    assert.strictEqual((await webhook(id1, h)).status, 200);
    assert.strictEqual(mollie.subscriptions.get(sub2.id).status, 'active',
      'geld terug voor de eerste aankoop stopte het abonnement van de tweede');
    did();
  } finally {
    await h.stop();
  }
});

test('R5: een terugboeking van een incasso stopt het abonnement dat die incasso deed', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('incassoterug');
  const h = await relayWith('incasso-incassoterug', [a]);
  try {
    await buy(a, 'monthly', h);
    const [sub] = activeSubsOf(a);
    const collected = await ctl('/_ctl/recurring', { subscriptionId: sub.id });
    assert.strictEqual((await webhook(collected.id, h)).status, 200);
    await ctl('/_ctl/chargeback', { id: collected.id });
    assert.strictEqual((await webhook(collected.id, h)).status, 200);
    assert.strictEqual(mollie.subscriptions.get(sub.id).status, 'canceled',
      'na een terugboeking van de incasso loopt het abonnement door');
    did();
  } finally {
    await h.stop();
  }
});

// ── Een nieuwe aankoop na opzeggen (punt 7) ──────────────────────────────────
// Opzeggen zet in admin paramant:user:plan_cancel_at:<sleutel>, en zolang die
// staat verbergt /account de opzegknop. Na een nieuwe aankoop loopt er weer
// een abonnement, en de verlengmail wijst naar die knop.
test('opzeggen: een nieuwe aankoop wist de geplande opzegging, zodat de knop terugkomt', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('opnieuw');
  const h = await relayWith('incasso-opnieuw', [a]);
  try {
    const marker = `paramant:user:plan_cancel_at:${a.key}`;
    await redis.set(marker, new Date(Date.now() + 86400000).toISOString());
    await buy(a, 'monthly', h);
    await waitFor(async () => (await redis.get(marker)) === null, 3000, 'opzegging gewist').catch(() => null);
    assert.strictEqual(await redis.get(marker), null, 'na een nieuwe aankoop staat de geplande opzegging er nog');
    did();
  } finally {
    await h.stop();
  }
});

// ── R10 ──────────────────────────────────────────────────────────────────────

test('R10: na een tweede aankoop start het abonnement op het nieuwe einde', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = ACC.r10;
  const pu = entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign;
  await buy(a);
  const first = await waitFor(() => recordOf(a)[pu], 5000, 'eerste termijn');
  const [s1] = activeSubsOf(a);
  assert.strictEqual(s1.startDate, dayOf(first), 'het eerste abonnement start niet op het eerste einde');

  await buy(a);
  const second = await waitFor(() => { const v = recordOf(a)[pu]; return v && v !== first ? v : null; },
    5000, 'tweede termijn');
  const active = activeSubsOf(a);
  assert.strictEqual(active.length, 1, `verwacht één actief abonnement, er zijn er ${active.length}`);
  did();
  assert.strictEqual(active[0].startDate, dayOf(second),
    `het abonnement start op ${active[0].startDate}, de betaalde termijn loopt tot ${dayOf(second)}: een maand te vroeg incasseren`);
  did();
  assert.strictEqual(mollie.subscriptions.get(s1.id).status, 'canceled', 'het oude abonnement loopt nog');
  did();
});

// De takken van het vervangen die de relay zelf niet bereikt, tegen de lib.
function recurringFakes(over) {
  const calls = { create: 0, cancel: 0 };
  const m = Object.assign({
    mollieInterval: mollieLib.mollieInterval,
    validMandates: async () => [{ id: 'mdt_1', status: 'valid' }],
    createSubscription: async () => { calls.create++; return { id: 'sub_new' }; },
    cancelSubscription: async () => { calls.cancel++; return { status: 'canceled' }; },
  }, over);
  return { calls, m };
}
const firmPayment = { id: 'tr_second', status: 'paid', sequenceType: 'first', customerId: 'cst_1',
  metadata: { accountId: 'acct_demo', product: 'firm', plan: 'firm', interval: 'monthly' } };
const firmGrant = { result: 'granted', account: 'acct_demo', product: 'firm',
  paidUntil: new Date(Date.now() + 60 * 86400000).toISOString() };

test('R10: dezelfde betaling nog eens, of een abonnement van onbekende herkomst, blijft staan', async () => {
  for (const rec of [{ [field]: 'sub_old', [madeBy]: 'tr_second' }, { [field]: 'sub_old' }]) {
    const { calls, m } = recurringFakes();
    const r = await billingRecurring.ensureSubscription(firmPayment, firmGrant, {
      recurring: true, mode: 'test', getAccount: async () => rec, saveSubscription: async () => {}, mollie: m,
    });
    assert.strictEqual(r.result, 'skipped');
    assert.strictEqual(r.reason, 'already_subscribed');
    assert.deepStrictEqual(calls, { create: 0, cancel: 0 });
  }
  did();
});

test('R10: lukt het opzeggen van het oude abonnement niet, dan komt er geen tweede bij', async () => {
  const { calls, m } = recurringFakes({ cancelSubscription: async () => { throw new Error('mollie_cancel_failed'); } });
  const saved = [];
  const r = await billingRecurring.ensureSubscription(firmPayment, firmGrant, {
    recurring: true, mode: 'test',
    getAccount: async () => ({ [field]: 'sub_old', [madeBy]: 'tr_first', mollie_customer_id: 'cst_1' }),
    saveSubscription: async (...args) => { saved.push(args); }, mollie: m,
  });
  assert.strictEqual(r.result, 'failed');
  assert.match(r.reason, /^replace_cancel_failed/);
  assert.strictEqual(calls.create, 0, 'er kwam een nieuw abonnement naast het oude dat nog loopt');
  assert.deepStrictEqual(saved, [], 'de aanwijzer naar het oude abonnement mag niet weg');
  did();
});

// Opzeggen gaat naar de klant van het abonnement zelf, en een 404 telt alleen
// als "al weg" als het die klant was. Bij de klant die toevallig op het account
// staat zegt een 404 niets over het abonnement.
const notFound = () => { const e = new Error('mollie_cancel_not_found'); e.status = 404; throw e; };
const custOf = 'mollie_subscription_firm_customer';

test('opzeggen: naar de klant van het abonnement, niet naar de klant op het account', async () => {
  const used = [];
  const { m } = recurringFakes({ cancelSubscription: async (mode, cst, sub) => { used.push(`${cst}/${sub}`); return { status: 'canceled' }; } });
  const rec = { [field]: 'sub_1', [custOf]: 'cst_van_abonnement', mollie_customer_id: 'cst_op_account' };
  const r = await billingRecurring.cancelForProduct('acct_demo', 'firm', {
    mode: 'test', getAccount: async () => rec, saveSubscription: async () => {}, mollie: m,
  });
  assert.strictEqual(r.result, 'cancelled');
  assert.deepStrictEqual(used, ['cst_van_abonnement/sub_1'], `opzeggen ging naar ${used.join(', ')}`);
  did();
});

test('opzeggen: een 404 is alleen "al weg" bij de klant van het abonnement', async () => {
  const saved = [];
  const deps = (rec) => ({
    mode: 'test', getAccount: async () => rec,
    saveSubscription: async (...args) => { saved.push(args); },
    mollie: recurringFakes({ cancelSubscription: async () => notFound() }).m,
  });
  const known = await billingRecurring.cancelForProduct('acct_demo', 'firm',
    deps({ [field]: 'sub_1', [custOf]: 'cst_1', mollie_customer_id: 'cst_1' }));
  assert.strictEqual(known.result, 'cancelled', `een 404 bij de eigen klant gaf ${known.result}`);
  assert.strictEqual(saved.length, 1, 'de aanwijzer naar een abonnement dat weg is bleef staan');
  saved.length = 0;
  // Van een abonnement van voor deze wijziging is de klant niet bekend: een 404
  // bij de klant op het account bewijst dan niets, en de aanwijzer blijft.
  const unknown = await billingRecurring.cancelForProduct('acct_demo', 'firm',
    deps({ [field]: 'sub_1', mollie_customer_id: 'cst_2' }));
  assert.strictEqual(unknown.result, 'failed', `een 404 bij een andere klant gaf ${unknown.result}`);
  assert.deepStrictEqual(saved, [], 'de aanwijzer ging weg op een 404 die niets bewijst');
  did();
});

// ── R11 ──────────────────────────────────────────────────────────────────────

// Wat Mollie een maand later doet, maar dan mislukt: een betaling van het
// abonnement, sequenceType recurring, met deze status.
function collectionOf(sub, status, subscriptionId = sub.id) {
  const id = 'tr_mislukt' + crypto.randomBytes(6).toString('hex');
  mollie.payments.set(id, {
    resource: 'payment', id, mode: 'test', status,
    createdAt: new Date().toISOString(), failedAt: new Date().toISOString(),
    amount: sub.amount, description: sub.description, metadata: sub.metadata,
    customerId: sub.customerId, sequenceType: 'recurring', subscriptionId,
  });
  return id;
}
const failMails = (a) => mailsTo(a).filter((m) => /niet gelukt/.test(String(m.subject || '')));

test('R11: een mislukte incasso wordt aan de klant gemeld, één keer', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = ACC.r11;
  await buy(a);
  const [sub] = activeSubsOf(a);
  const failId = collectionOf(sub, 'failed');
  const r = await webhook(failId);
  assert.strictEqual(r.status, 200);
  const mail = await waitFor(() => failMails(a)[0], 5000, 'mail over de mislukte incasso').catch(() => null);
  assert.ok(mail, `de klant kreeg geen mail over de mislukte incasso (mails: ${JSON.stringify(mailsTo(a).map((m) => m.subject))})`);
  did();
  assert.ok(mail.text.includes('EUR 35.09'), 'de mail noemt het bedrag niet');
  assert.ok(!/niets automatisch afgeschreven|nothing is charged automatically/.test(mail.text));
  // Mollie probeert een mislukte incasso meestal zelf opnieuw (tot vijf keer,
  // afhankelijk van de reden). Wie dan ook zelf betaalt, betaalt twee keer: de
  // mail stuurt hem dus niet naar de kassa.
  assert.match(mail.text, /probeert Mollie de betaling automatisch opnieuw/);
  assert.match(mail.text, /Mollie tries the payment again automatically/);
  assert.ok(!mail.text.includes(`${NOWHERE}/pricing`), 'de mail stuurt de klant naar de kassa terwijl Mollie het opnieuw probeert');
  assert.ok(!/tenzij u zelf betaalt|unless you pay yourself|zelf betalen:|pay yourself here/.test(mail.text),
    'de mail vraagt de klant zelf te betalen terwijl Mollie het opnieuw probeert');
  did();
  // Dezelfde melding nog eens (Mollie herhaalt bij twijfel): geen tweede mail.
  await webhook(failId);
  await new Promise((res) => setTimeout(res, 300));
  assert.strictEqual(failMails(a).length, 1, 'dezelfde mislukte incasso gaf een tweede mail');
  did();
  // Mollie probeert opnieuw, en ook die poging mislukt: een nieuwe betaling
  // voor dezelfde periode. Nog steeds één mail, geen mail per poging.
  await webhook(collectionOf(sub, 'failed'));
  await new Promise((res) => setTimeout(res, 300));
  assert.strictEqual(failMails(a).length, 1, 'een tweede poging voor dezelfde periode gaf een tweede mail');
  did();
});

test('R11: geen mail bij een geannuleerde incasso, of bij een incasso van een vervangen abonnement', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = account('r11stil');
  const h = await relayWith('incasso-r11stil', [a]);
  try {
    await buy(a, 'monthly', h);
    const [old] = activeSubsOf(a);
    // Geannuleerd is wat er met een lopende incasso gebeurt als het abonnement
    // stopt of wordt vervangen. Daar is niets mislukt.
    assert.strictEqual((await webhook(collectionOf(old, 'canceled'), h)).status, 200);
    // Een tweede aankoop vervangt het abonnement. Een mislukte betaling van het
    // oude hoort de klant niet te bereiken: zijn nieuwe loopt gewoon.
    await buy(a, 'monthly', h);
    assert.strictEqual(mollie.subscriptions.get(old.id).status, 'canceled');
    assert.strictEqual((await webhook(collectionOf(old, 'failed'), h)).status, 200);
    await new Promise((res) => setTimeout(res, 400));
    assert.deepStrictEqual(failMails(a).map((m) => m.subject), [],
      'een geannuleerde incasso of een incasso van het oude abonnement gaf een mail over een mislukte betaling');
    did();
  } finally {
    await h.stop();
  }
});

// ── R12 ──────────────────────────────────────────────────────────────────────

// Op het account van R10: een lopende termijn en één abonnement. Een betaling
// van 35.091 mag daar niets aan veranderen.
test('R12: een bedrag met een derde decimaal kent niets toe', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = ACC.r10;
  const pu = entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign;
  const before = recordOf(a)[pu];
  const [subBefore] = activeSubsOf(a);
  const id = await checkout(a);
  await pay(id);
  mollie.payments.get(id).amount.value = '35.091';
  const r = await webhook(id);
  assert.strictEqual(r.status, 200);
  const line = logLines().find((j) => j.msg === 'billing_webhook' && j.payment_id === id);
  assert.ok(line, 'geen billing_webhook-regel voor de betaling');
  assert.strictEqual(line.result, 'refused', `35.091 werd gelezen als 35.09 (${line.result}: ${line.reason})`);
  assert.match(String(line.reason), /amount_mismatch/);
  did();
  await new Promise((res) => setTimeout(res, 200));
  assert.strictEqual(recordOf(a)[pu], before, 'de termijn schoof op door een afgewezen bedrag');
  const active = activeSubsOf(a);
  assert.deepStrictEqual(active.map((s) => s.id), [subBefore.id], 'het abonnement veranderde door een afgewezen bedrag');
  did();
});

// Dezelfde regel los: nullen achter de centen blijven gelijk, andere cijfers niet.
test('R12: amountsEqual kapt niet meer af', () => {
  assert.ok(catalog.amountsEqual('35.09', '35.090'), 'een nul achter de centen is hetzelfde bedrag');
  assert.ok(catalog.amountsEqual('18.15', '18.150'), 'een nul achter de centen is hetzelfde bedrag');
  assert.ok(!catalog.amountsEqual('35.09', '35.091'), '35.091 telde als 35.09');
  assert.ok(!catalog.amountsEqual('35.091', '35.09'), '35.091 telde als 35.09');
  assert.ok(!catalog.amountsEqual('35.09', '35.0900001'), '35.0900001 telde als 35.09');
  did();
});

// ── R6 ───────────────────────────────────────────────────────────────────────

test('R6: de herinnering zegt dat er verlengd wordt, niet dat er niets wordt afgeschreven', async (t) => {
  if (!srv) return t.skip('geen redis');
  const a = ACC.r6;
  await buy(a);
  assert.strictEqual(activeSubsOf(a).length, 1);
  const field = billingRecurring.subscriptionFieldOf('firm');
  await waitFor(() => recordOf(a)[field], 5000, 'abonnementsaanwijzer op schijf');

  // De klok verzetten zoals een deploy dat doet: de relay stoppen, de termijn
  // op zes dagen zetten en opnieuw opstarten, met de sweep direct na de boot.
  // De gedeelde rechtenrij gaat eruit, anders zet hij de langere termijn terug.
  await srv.stop();
  const soon = new Date(Date.now() + 6 * 86400000).toISOString();
  const ud = JSON.parse(fs.readFileSync(srv.env.USERS_FILE, 'utf8'));
  for (const k of ud.api_keys) {
    if (k.account_id !== a.acct) continue;
    k[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign] = soon;
    k[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasend] = soon;
  }
  fs.writeFileSync(srv.env.USERS_FILE, JSON.stringify(ud, null, 2));
  await redis.del(`paramant:entitlements:grant:${a.acct}`);
  await redis.sRem('paramant:entitlements:accounts', a.acct);
  srv = await boot({
    ...bootOpts, users: null, dir: srv.dir,
    env: { ...bootOpts.env, PLAN_EXPIRY_BOOT_DELAY_MS: '300' },
  });

  // De factuurmail van de aankoop ging al eerder naar hetzelfde adres; de
  // herinnering is de mail over het einde of de verlenging van de termijn.
  const mail = await waitFor(() => mailsTo(a).find((m) => /loopt af op|verlengd/.test(String(m.subject || ''))),
    15000, 'herinneringsmail').catch(() => null);
  assert.ok(mail, `er kwam geen herinnering (mails: ${JSON.stringify(mailsTo(a).map((m) => m.subject))})`);
  assert.ok(!/Er wordt niets automatisch afgeschreven/.test(mail.text),
    'de herinnering belooft dat er niets wordt afgeschreven, terwijl het abonnement over zes dagen incasseert');
  assert.ok(!/nothing is charged automatically/.test(mail.text));
  did();
  assert.match(mail.text, /automatisch met een maand verlengd en wordt EUR 35\.09 afgeschreven/);
  assert.match(mail.text, /renews automatically for a month, and EUR 35\.09 is collected/);
  assert.ok(mail.text.includes(`${NOWHERE}/account`), 'de mail zegt niet waar de klant kan opzeggen');
  did();
  // Eén incasso, één mail: niet een per product die elk het hele bedrag noemt.
  await new Promise((res) => setTimeout(res, 500));
  const reminders = mailsTo(a).filter((m) => /loopt af op|verlengd/.test(String(m.subject || '')));
  assert.strictEqual(reminders.length, 1, `verwacht één herinnering, kreeg ${JSON.stringify(reminders.map((m) => m.subject))}`);
  did();
});

// De einde-mail van een termijn die zich vanzelf verlengt: pas na de SEPA-marge,
// en dan zonder "er is niets afgeschreven". Tegen de sweep zelf, met een klok.
test('R6: de einde-mail wacht op de incasso en belooft daarna niets wat niet klopt', async () => {
  const DAY = 86400000;
  const now = Date.parse('2026-10-30T09:00:00.000Z');
  const store = memRedis();
  await planExpiry.upsertExpiry(store, {
    accountId: 'acct_demo_einde', product: 'parasign', tier: 'pro', bundle: 'firm',
    paidUntil: new Date(now - 1 * DAY).toISOString(), email: 'einde@example.test',
  });
  const sent = [];
  const renewal = { line: 'firm', amount: '35.09', currency: 'EUR', interval: 'monthly' };
  const sweep = (at, renewalOf) => planExpiry.runSweep({
    redis: store, now: at, siteUrl: 'https://paramant.app', renewalOf,
    sendEmail: async (m) => { sent.push(m); return true; },
  });
  // Een dag na het einde, abonnement loopt: nog geen mail, de incasso kan onderweg zijn.
  await sweep(now, async () => renewal);
  assert.strictEqual(sent.length, 0, 'de einde-mail ging al terwijl de incasso nog kon binnenkomen');
  // Zes dagen na het einde en nog steeds niets binnen: nu wel, en eerlijk.
  await sweep(now + 5 * DAY, async () => renewal);
  assert.strictEqual(sent.length, 1);
  assert.match(sent[0].text, /De automatische verlenging is niet binnengekomen/);
  assert.ok(!/niets afgeschreven|Nothing was charged|eenmalige betaling|one-off payment/.test(sent[0].text));
  did();
  // Zonder abonnement blijft de mail wat hij was.
  const store2 = memRedis();
  await planExpiry.upsertExpiry(store2, {
    accountId: 'acct_demo_los', product: 'parasign', tier: 'pro',
    paidUntil: new Date(now - 1 * DAY).toISOString(), email: 'los@example.test',
  });
  const sent2 = [];
  await planExpiry.runSweep({
    redis: store2, now, siteUrl: 'https://paramant.app', renewalOf: async () => null,
    sendEmail: async (m) => { sent2.push(m); return true; },
  });
  assert.strictEqual(sent2.length, 1);
  assert.match(sent2[0].text, /Er is niets afgeschreven\./);
  assert.match(sent2[0].text, /Elk plan is hier een eenmalige betaling/,
    'zonder BILLING_MODE is elk plan een eenmalige betaling, en dat mag de mail blijven zeggen');
  did();
});

// Met BILLING_MODE aan is een plan een abonnement. Wie opzegde, krijgt aan het
// eind nog steeds "er is niets afgeschreven", maar niet meer de uitleg dat elk
// plan hier een eenmalige betaling is: dat klopt dan niet meer.
test('R6: met BILLING_MODE aan zegt de einde-mail niet dat elk plan een eenmalige betaling is', async () => {
  const DAY = 86400000;
  const now = Date.parse('2026-10-30T09:00:00.000Z');
  const store = memRedis();
  await planExpiry.upsertExpiry(store, {
    accountId: 'acct_demo_opgezegd', product: 'parasign', tier: 'pro', bundle: 'firm',
    paidUntil: new Date(now - 1 * DAY).toISOString(), email: 'opgezegd@example.test',
  });
  const sent = [];
  await planExpiry.runSweep({
    redis: store, now, siteUrl: 'https://paramant.app', renewalOf: async () => null, recurring: true,
    sendEmail: async (m) => { sent.push(m); return true; },
  });
  assert.strictEqual(sent.length, 1);
  assert.match(sent[0].text, /Er is niets afgeschreven\./);
  assert.match(sent[0].text, /Nothing was charged\./);
  assert.ok(!/eenmalige betaling|one-off payment/.test(sent[0].text),
    'met BILLING_MODE aan zegt de einde-mail nog dat elk plan een eenmalige betaling is');
  did();
});

// ── R13 ──────────────────────────────────────────────────────────────────────

test('R13: een live_-waarde in MOLLIE_TEST_API_KEY wordt geweigerd en gaat nooit over de lijn', async (t) => {
  if (!srv) return t.skip('geen redis');
  const other = fakeMollie.create();
  const origin = await other.listen();
  try {
    const a = { key: `pgp_incasso_r13_${RUN}`, acct: `acct_demo_r13_${RUN}` };
    const h = await boot({
      tag: 'incasso-r13',
      users: { api_keys: [{ key: a.key, plan: 'community', active: true, parasign: true, account_id: a.acct, email: 'r13@example.test' }] },
      env: {
        NODE_OPTIONS: `--require ${INTERCEPT}`,
        FAKE_MOLLIE_URL: origin,
        BILLING_MODE: 'test',
        // Geen sleutel: een tekenreeks met het verkeerde voorvoegsel.
        MOLLIE_TEST_API_KEY: 'live_' + 'x'.repeat(30),
        PARASIGN_PUBLIC_ORIGIN: NOWHERE,
      },
    });
    const cfg = logLines(h).find((j) => j.msg === 'billing_config');
    assert.ok(cfg, 'geen billing_config-regel bij de boot');
    assert.strictEqual(cfg.level, 'error', 'een live_-waarde in de testsleutel hoort een error te zijn');
    assert.strictEqual(cfg.key_present, false);
    assert.ok((cfg.problems || []).includes('test_key_wrong_prefix'), `problems: ${JSON.stringify(cfg.problems)}`);
    assert.ok(!JSON.stringify(logLines(h)).includes('x'.repeat(30)), 'de sleutelwaarde staat in het log');
    did();
    const r = await h.post('/v2/billing/checkout', {
      headers: { 'X-Api-Key': a.key }, body: { product: 'firm', plan: 'firm', interval: 'monthly' },
    });
    assert.strictEqual(r.status, 502, `de kassa draaide met een live_-waarde in testmodus (${r.status})`);
    assert.strictEqual(other.requests.length, 0,
      `er gingen ${other.requests.length} verzoeken naar Mollie, met ${JSON.stringify(other.requests.map((q) => q.keyPrefix))}`);
    did();
    await h.stop();
  } finally {
    await other.close();
  }
});

test('R13: een onbekende BILLING_MODE is een error en valt terug op eenmalig betalen', async (t) => {
  if (!srv) return t.skip('geen redis');
  const h = await boot({
    tag: 'incasso-r13b',
    // De intercept wijst Mollie naar een poort waar niets luistert: deze relay
    // hoort niemand te bellen, en mocht hij het toch doen, dan komt hij nergens.
    env: {
      BILLING_MODE: 'prod', MOLLIE_API_KEY: 'live_' + 'y'.repeat(30),
      NODE_OPTIONS: `--require ${INTERCEPT}`, FAKE_MOLLIE_URL: NOWHERE,
    },
  });
  const cfg = logLines(h).find((j) => j.msg === 'billing_config');
  assert.ok(cfg, 'geen billing_config-regel bij de boot');
  assert.strictEqual(cfg.level, 'error', 'BILLING_MODE=prod ging stil door als "niet gezet"');
  assert.ok((cfg.problems || []).includes('billing_mode_unknown'));
  assert.match(cfg.stance, /BILLING_MODE=prod not recognised/);
  // Veilig terugvallen: geen klanten, mandaten of abonnementen.
  assert.strictEqual(cfg.recurring, false);
  assert.strictEqual(cfg.mode, 'live');
  did();
  await h.stop();
});

// De productiestand zelf verandert niet: leeg plus een live_-sleutel is live,
// eenmalig, zonder één probleem.
test('R13: de productiestand blijft zoals hij is', () => {
  const saved = {};
  for (const k of ['BILLING_MODE', 'MOLLIE_API_KEY', 'MOLLIE_TEST_API_KEY']) { saved[k] = process.env[k]; delete process.env[k]; }
  try {
    process.env.MOLLIE_API_KEY = 'live_abcdef';
    assert.deepStrictEqual(mollieLib.billingStance(), { mode: 'live', recurring: false, source: 'inferred', key_present: true });
    assert.strictEqual(mollieLib.apiKeyFor('live'), 'live_abcdef');
    // En de andere kant op: een test_-waarde in de live-sleutel telt niet, want
    // dan kent de relay plannen toe op betalingen die nooit echt geld zijn.
    process.env.MOLLIE_API_KEY = 'test_abcdef';
    assert.strictEqual(mollieLib.apiKeyFor('live'), '', 'een test_-waarde werd als live-sleutel gebruikt');
    did();
    process.env.MOLLIE_API_KEY = 'live_abcdef';
    assert.deepStrictEqual(mollieLib.configProblems(), []);
    process.env.MOLLIE_API_KEY = 'test_abcdef';
    assert.deepStrictEqual(mollieLib.configProblems().map((p) => p.code), ['live_key_wrong_prefix']);
    did();
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

// ── een redis in geheugen, genoeg voor de sweep ──────────────────────────────
function memRedis() {
  const strings = new Map();
  const zsets = new Map();
  const hashes = new Map();
  const zset = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };
  const hash = (k) => { if (!hashes.has(k)) hashes.set(k, new Map()); return hashes.get(k); };
  return {
    isReady: true,
    async set(k, v, opts) { if (opts && opts.NX && strings.has(k)) return null; strings.set(k, String(v)); return 'OK'; },
    async get(k) { return strings.has(k) ? strings.get(k) : null; },
    async del(k) { return strings.delete(k) ? 1 : 0; },
    async zAdd(k, { score, value }) { zset(k).set(value, score); return 1; },
    async zRem(k, m) { return zset(k).delete(m) ? 1 : 0; },
    async zRangeByScore(k, min, max) {
      return [...zset(k).entries()].filter(([, s]) => s >= min && s <= max).sort((x, y) => x[1] - y[1]).map(([m]) => m);
    },
    async hSet(k, f, v) { hash(k).set(f, String(v)); return 1; },
    async hGet(k, f) { const v = hash(k).get(f); return v === undefined ? null : v; },
    async hDel(k, f) { return hash(k).delete(f) ? 1 : 0; },
  };
}
