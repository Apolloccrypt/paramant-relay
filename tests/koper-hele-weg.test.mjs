// De hele weg van een betalende klant, in een echte browser, van kassa tot
// creditnota.
//
// WAAROM DEZE POORT BESTAAT. Tot 5 september kende een geslaagde betaling de
// rechten toe op de relay die het verzoek bediende, terwijl elk scherm en elke
// poort het account uitlazen bij een andere relay. De klant kreeg een
// bevestiging, zag daarna niets veranderen, en zijn volgende handtekening werd
// echt geweigerd. Dat is gerepareerd, maar niemand had de weg ooit helemaal
// afgelopen. Deze poort loopt hem af en wordt rood zodra er onderweg twee
// dingen uit elkaar lopen.
//
// WAT HIER ECHT IS. Alles behalve de twee partijen buiten de deur. Twee echte
// relay.js-processen (main en health, elk met hun eigen users.json, zoals in
// productie), de echte admin-server, de echte frontend achter een
// single-origin-proxy, echte redis, een echte Chromium met een virtuele
// passkey. Alleen api.mollie.com en api.resend.com zijn nagebouwd, en die
// worden bereikt via de code die in productie draait: de https-laag wordt
// omgeleid, lib/mollie.js en de webhook-route zelf zijn onaangeraakt. De
// betaling wordt niet met de hand toegekend; de browser klikt op Betaal in de
// testkassa, en die kassa roept de webhook aan zoals Mollie dat doet.
//
// WAT DEZE POORT NIET IS. Een unittest van billing.js of van de
// invoice-nummering; die staan in relay/test/. Deze poort kijkt alleen naar wat
// een klant ziet en kan, en of die twee hetzelfde zeggen.

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';

const require = createRequire(import.meta.url);
const stack = require('./helpers/koper-stack.cjs');

const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const FIRM_GROSS = '35.09';
const FIRM_NET = '29.00';
const FIRM_VAT = '6.09';
const FIRM_SIGNS = 100;      // tiers.js pro.signs_month
const FIRM_TRANSFERS = 500;  // tiers.js pro.transfers_month
const FREE_SIGNS = 2;        // tiers.js community.signs_month

let S, browser;

test.before(async () => {
  S = await stack.start();
  browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
});
test.after(async () => {
  if (browser) await browser.close();
  if (S) await S.stop();
});

// Een account zoals de admin er een aanmaakt, op BEIDE relays, want dat is wat
// de fan-out in admin/server.js doet. Daarna een setup-token in redis, zodat de
// browser een echte passkey kan registreren zonder mailbox.
async function maakAccount(email) {
  const key = 'pgp_' + crypto.randomBytes(32).toString('hex');
  const body = JSON.stringify({ key, email, label: email.split('@')[0], plan: 'community', active: true });
  for (const port of [S.relayPort, S.healthPort]) {
    const r = await fetch(`http://127.0.0.1:${port}/v2/admin/keys`, {
      method: 'POST',
      headers: { 'X-Admin-Token': S.adminToken, 'Content-Type': 'application/json' },
      body,
    });
    assert.ok(r.ok, `account aanmaken op :${port} gaf ${r.status}`);
  }
  const token = crypto.randomBytes(32).toString('hex');
  await S.redis.set(`paramant:user:setup_token:${token}`, JSON.stringify({ user_id: key, email }), { EX: 1209600 });
  return { key, email, token };
}

// Ingelogd in een echte browser, met een virtuele authenticator zodat de
// passkey-registratie de echte WebAuthn-code doorloopt.
async function login(acc) {
  const ctx = await browser.newContext({ baseURL: S.origin });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await page.goto(`${S.origin}/auth/setup/${acc.token}`);
  await page.waitForLoadState('networkidle');
  await page.click('#passkey-register-btn');
  await page.waitForSelector('#passkey-finish-btn', { timeout: 30000 });
  await page.click('#passkey-finish-btn');
  await page.waitForLoadState('networkidle');
  return page;
}

const api = (page, path, init) => page.evaluate(([p, i]) => fetch(p, i || undefined)
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) })), [path, init || null]);

async function schermtekst(page, pad) {
  await page.goto(S.origin + pad);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1200);
  return (await page.locator('body').innerText()).replace(/\s+/g, ' ');
}

// De rechten zoals de relay ze zelf uitrekent, per relay. Twee relays, want de
// vraag is niet of ze kloppen maar of ze HETZELFDE zijn.
async function rechtenOp(port, key) {
  const r = await fetch(`http://127.0.0.1:${port}/v2/admin/entitlements/${key}`, {
    headers: { 'X-Internal-Auth': S.internalToken, 'X-Admin-Token': S.adminToken },
  });
  const b = await r.json().catch(() => null);
  assert.ok(b && b.entitlements, `entitlements op :${port} gaf ${r.status}`);
  return b.entitlements;
}

// Afrekenen zoals een klant het doet: op de knop op /pricing, door naar de
// kassa, op Betaal, terug naar het dashboard.
async function koopFirm(page, interval = 'monthly') {
  await page.goto(S.origin + '/pricing');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(600);
  const knop = page.locator(`[data-billing-product="firm"][data-billing-interval="${interval}"]`).first();
  await knop.click();
  await page.waitForURL(/\/checkout\//, { timeout: 30000 });
  const kassa = (await page.locator('body').innerText()).replace(/\s+/g, ' ');
  await page.click('#pay');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2500);
  return kassa;
}

test('1. de kassa rekent het bedrag af dat op de knop staat', async () => {
  S.koper = await maakAccount('koper@example.com');
  S.gratis = await maakAccount('gratis@example.com');
  S.pageK = await login(S.koper);
  S.pageG = await login(S.gratis);

  // Voor de betaling zijn beide accounts gratis, op beide relays.
  for (const port of [S.relayPort, S.healthPort]) {
    const e = await rechtenOp(port, S.koper.key);
    assert.equal(e.parasign.tier, 'free');
    assert.equal(e.parasign.quotas.signs_month, FREE_SIGNS);
  }

  const kassa = await koopFirm(S.pageK);
  // Het bedrag op de kassa komt uit de server-side catalogus, niet uit de
  // browser. Als de knop en de kassa ooit uit elkaar lopen, is dat hier rood.
  assert.match(kassa, new RegExp(`EUR ${FIRM_GROSS.replace('.', '\\.')}`),
    `de kassa rekende niet ${FIRM_GROSS} af: ${kassa}`);
  assert.match(S.pageK.url(), /\/dashboard/, 'de klant komt niet terug op het dashboard');
});

test('2. de vier schermen zeggen na de betaling hetzelfde', async () => {
  // Deze vier spraken elkaar tegen: dat is de reden dat poort 6 bestaat.
  const thuis = await schermtekst(S.pageK, '/');
  const account = await schermtekst(S.pageK, '/account');
  const dashboard = await schermtekst(S.pageK, '/dashboard');

  assert.match(thuis, new RegExp(`${FIRM_SIGNS} of ${FIRM_SIGNS} signatures left`),
    'de ingelogde homepage toont de gekochte limiet niet');
  assert.doesNotMatch(thuis, /Community, free for good/,
    'de homepage noemt een betalend account nog Community');
  assert.match(account, /FIRM PLAN/, '/account noemt het plan niet Firm');
  assert.match(dashboard, /FIRM PLAN/, '/dashboard noemt het plan niet Firm');
  // De termijn staat op beide schermen, met dezelfde zin.
  for (const [naam, tekst] of [['account', account], ['dashboard', dashboard]]) {
    assert.match(tekst, /nothing renews automatically/,
      `${naam} zegt niet wat er aan het einde van de termijn gebeurt`);
  }

  // En de API zegt hetzelfde als de schermen. current_plan zei 'community'
  // tegen elke betaler sinds billing bestaat, omdat een aankoop plan_parasign
  // schrijft en het oude veld `plan` met opzet niet aanraakt.
  const status = await api(S.pageK, '/api/user/billing/status');
  assert.equal(status.status, 200);
  assert.equal(status.body.current_plan, 'pro', 'billing/status noemt een Firm-klant nog community');
  assert.equal(status.body.plan_name, 'Firm');
  assert.ok(status.body.access_until, 'billing/status kent de einddatum niet');
});

test('3. beide relays kennen hetzelfde recht, en het is wat het plan belooft', async () => {
  // De bug waar poort 6 uit voortkomt: rechten aan op de ene relay, gelezen bij
  // de andere. Public /v2 gaat naar main, elk scherm leest health.
  const main = await rechtenOp(S.relayPort, S.koper.key);
  const health = await rechtenOp(S.healthPort, S.koper.key);
  assert.deepEqual(
    { sign: main.parasign.tier, send: main.parasend.tier },
    { sign: health.parasign.tier, send: health.parasend.tier },
    'main en health zijn het oneens over wat deze klant gekocht heeft');
  assert.equal(health.parasign.tier, 'pro');
  assert.equal(health.parasend.tier, 'pro');

  // De grens die de poort afdwingt is de grens die het scherm noemt.
  assert.equal(health.parasign.quotas.signs_month, FIRM_SIGNS);
  assert.equal(health.parasend.quotas.transfers_month, FIRM_TRANSFERS);
  const overzicht = await api(S.pageK, '/api/user/dashboard/overview');
  assert.equal(overzicht.body.quota.caps.signs, FIRM_SIGNS,
    'het dashboard toont een andere limiet dan de poort afdwingt');
  assert.equal(overzicht.body.quota.caps.transfers, FIRM_TRANSFERS);

  // En een gratis gebruiker kan echt minder.
  const gratis = await rechtenOp(S.healthPort, S.gratis.key);
  assert.equal(gratis.parasign.quotas.signs_month, FREE_SIGNS);
});

test('4. wat het plan verkoopt kan de koper ook echt gebruiken', async () => {
  // /pricing verkoopt Firm met "a developer API ... so signing can run inside
  // your own software". De enige plek die een sleutel maakte zat achter een
  // e-mail-allowlist van de beheerder en gaf 404 aan elke klant.
  const gratisPoging = await api(S.pageG, '/api/user/parasign-keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"label":"x"}' });
  assert.equal(gratisPoging.status, 403, 'een gratis account kreeg een API-sleutel');

  const koperPoging = await api(S.pageK, '/api/user/parasign-keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"label":"account"}' });
  assert.equal(koperPoging.status, 201, 'de betaler kan de API die hij kocht niet bereiken');
  assert.match(String(koperPoging.body.key), /^psk_(live|test)_/);

  // En de sleutel staat op zijn eigen accountpagina, niet alleen in een JSON.
  const account = await schermtekst(S.pageK, '/account');
  assert.match(account, /ParaSign API keys/i, '/account laat de API-sleutels van het plan niet zien');
});

test('5. de factuur klopt, en het nummer loopt door', async () => {
  const eerste = await api(S.pageK, '/api/user/billing/invoices');
  assert.equal(eerste.status, 200);
  const doc = eerste.body.invoices[0];
  assert.match(doc.number, /^PS-\d{4}-0001$/, 'het eerste document is niet nummer 1');
  // Het btw-bedrag moet optellen tot het bedrag dat echt is afgeschreven. Een
  // factuur waarvan het totaal niet het betaalde bedrag is, is een foute factuur.
  assert.equal(doc.amount_gross, FIRM_GROSS);
  assert.equal(doc.amount_net, FIRM_NET);
  assert.equal(doc.amount_vat, FIRM_VAT);
  assert.equal(doc.vat_rate, 21);
  assert.equal(
    Math.round(Number(doc.amount_net) * 100) + Math.round(Number(doc.amount_vat) * 100),
    Math.round(Number(doc.amount_gross) * 100),
    'netto plus btw is niet het bedrag dat is afgeschreven');

  // Hij komt ook echt aan, met de PDF eraan.
  const mails = S.resend.mails.filter((m) => /PS-\d{4}-0001/.test(String(m.subject)));
  assert.equal(mails.length, 1, 'het document is niet gemaild');
  assert.ok((mails[0].attachments || []).some((a) => /PS-\d{4}-0001\.pdf$/.test(a.filename)),
    'de mail heeft geen document als bijlage');

  // De PDF is leesbaar en noemt hetzelfde bedrag als de regel erboven.
  const pdf = await S.pageK.evaluate(async (nr) => {
    const r = await fetch(`/api/user/billing/invoices/${nr}.pdf`);
    return { status: r.status, txt: (await r.text()).replace(/[^\x20-\x7e]/g, ' ') };
  }, doc.number);
  assert.equal(pdf.status, 200);
  assert.ok(pdf.txt.includes(doc.number), 'de PDF noemt zijn eigen nummer niet');
  assert.ok(pdf.txt.includes(FIRM_GROSS), 'de PDF noemt het betaalde bedrag niet');

  // Tweede aankoop: opvolgend nummer, en de termijn wordt verlengd, niet vervangen.
  const voor = (await api(S.pageK, '/api/user/billing/status')).body.access_until;
  await koopFirm(S.pageK);
  const na = await api(S.pageK, '/api/user/billing/invoices');
  assert.match(na.body.invoices[0].number, /^PS-\d{4}-0002$/, 'het tweede nummer volgt niet op het eerste');
  const naDatum = (await api(S.pageK, '/api/user/billing/status')).body.access_until;
  assert.ok(Date.parse(naDatum) > Date.parse(voor), 'een tweede maand verlengde de termijn niet');
});

test('6. opzeggen stopt de incasso echt', async () => {
  // Er stond een abonnement open: BILLING_MODE staat aan, dus checkout heeft een
  // mandaat en een abonnement geopend. De knop op /account schreef alleen een
  // markering en stuurde een mail; Mollie bleef incasseren.
  const voor = await (await fetch(S.mollieOrigin + '/_ctl/subscriptions')).json();
  assert.ok(voor.some((s) => s.status === 'active'), 'er stond geen incasso open om te stoppen');
  const status0 = await api(S.pageK, '/api/user/billing/status');
  assert.equal(status0.body.auto_renews, true, 'de accountpagina zegt dat er niets incasseert terwijl dat wel zo is');

  S.resend.clear();
  const opzeg = await api(S.pageK, '/api/user/billing/cancel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(opzeg.status, 200, JSON.stringify(opzeg));
  await S.pageK.waitForTimeout(1200);

  const na = await (await fetch(S.mollieOrigin + '/_ctl/subscriptions')).json();
  assert.ok(!na.some((s) => s.status === 'active'),
    'na "Cancellation scheduled" liep de incasso gewoon door');

  // De mail noemt het plan zoals de schermen het noemen.
  const mail = S.resend.mails.find((m) => /cancellation/i.test(String(m.subject)));
  assert.ok(mail, 'er ging geen bevestiging van de opzegging uit');
  assert.match(String(mail.text), /Firm/, 'de opzegmail noemt een ander plan dan de accountpagina');

  // En hij houdt wat hij betaald heeft: opzeggen stopt de volgende incasso,
  // niet de lopende termijn. Zo staat het ook in /terms.
  const rechten = await rechtenOp(S.healthPort, S.koper.key);
  assert.equal(rechten.parasign.tier, 'pro', 'opzeggen nam een betaalde termijn af');
});

test('7. geld terug levert een creditnota op die bij de factuur past', async () => {
  const betalingen = await (await fetch(S.mollieOrigin + '/_ctl/payments')).json();
  const eerste = betalingen.find((p) => p.status === 'paid');
  S.resend.clear();
  await fetch(S.mollieOrigin + '/_ctl/refund', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: eerste.id }),
  });
  await S.pageK.waitForTimeout(1500);

  const docs = (await api(S.pageK, '/api/user/billing/invoices')).body.invoices;
  const credit = docs.find((d) => d.kind === 'credit_note');
  assert.ok(credit, 'er kwam geen creditnota');
  assert.match(credit.number, /^CN-\d{4}-0001$/, 'de creditnota zit niet in zijn eigen reeks');
  const gecrediteerd = docs.find((d) => d.number === credit.credit_for);
  assert.ok(gecrediteerd, 'de creditnota verwijst niet naar een bestaande factuur');
  assert.equal(Number(credit.amount_gross), -Number(gecrediteerd.amount_gross),
    'de creditnota telt niet op tot nul met de factuur');
  assert.ok(gecrediteerd.reversed_at, 'de gecrediteerde factuur draagt geen stempel');
  assert.ok(S.resend.mails.some((m) => /CN-\d{4}-0001/.test(String(m.subject))),
    'de creditnota is niet gemaild');

  // En het recht gaat mee terug. Tot 2026-09-06 stond hier alleen de nota: geld
  // terug, plan behouden. Erger nog, de terugbetaling komt binnen als een
  // betaling die 'paid' BLIJFT met amountRefunded erbij, dus hij liep door de
  // toekenningstak en alleen de idempotentiemarkering hield een verse maand
  // tegen. De vloer per product staat in relay/lib/billing-catalog.js.
  const vloer = { parasign: 'free', parasend: 'community' };
  const gekocht = eerste.metadata && eerste.metadata.product;
  assert.ok(gekocht, 'de betaling draagt geen product in zijn metadata');
  const producten = gekocht === 'firm' ? ['parasign', 'parasend'] : [gekocht];
  for (const [naam, port] of [['main', S.relayPort], ['health', S.healthPort]]) {
    const e = await rechtenOp(port, S.koper.key);
    for (const prod of producten) {
      assert.equal(e[prod].tier, vloer[prod],
        `${naam} geeft na een volledige terugbetaling nog ${prod} op ${e[prod].tier}`);
    }
  }
});

test('8. na een terugboeking is het recht op BEIDE relays weg', async () => {
  // De spiegel van de bug waarvoor deze poort bestaat. Gemeten op 2026-09-05:
  // relay-main nam het recht af, relay-health had er nooit iets van gehoord, en
  // een seconde later zette health met zijn eigen reseed relay-main terug op
  // Pro. Geld terug, plan behouden, op elk scherm.
  const betalingen = await (await fetch(S.mollieOrigin + '/_ctl/payments')).json();
  const levend = betalingen.filter((p) => p.status === 'paid' && !p.amountRefunded);
  assert.ok(levend.length, 'er was geen betaling meer om terug te boeken');
  await fetch(S.mollieOrigin + '/_ctl/chargeback', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: levend[0].id }),
  });
  await S.pageK.waitForTimeout(2000);

  for (const [naam, port] of [['main', S.relayPort], ['health', S.healthPort]]) {
    const e = await rechtenOp(port, S.koper.key);
    assert.equal(e.parasign.tier, 'free', `${naam} geeft na een terugboeking nog ParaSign Pro`);
    assert.equal(e.parasend.tier, 'community', `${naam} geeft na een terugboeking nog ParaSend Pro`);
  }
  // En de API die bij het plan hoorde is ook weg. De toegangsvlag `parasign`
  // werd gezet bij een aankoop en nooit gewist, zodat het geld terugging en de
  // sleutel bleef werken.
  const poging = await api(S.pageK, '/api/user/parasign-keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"label":"x"}' });
  assert.equal(poging.status, 403, 'na een terugboeking kan het account nog API-sleutels maken');
});

test('9. de termijn loopt af zoals de site het aankondigt', async () => {
  // De klok vooruit: paid_until staat op het accountrecord, en dat opnieuw
  // inlezen bij een herstart is precies wat er bij een deploy gebeurt.
  const koper2 = await maakAccount('termijn@example.com');
  const page2 = await login(koper2);
  await koopFirm(page2);
  assert.equal((await rechtenOp(S.healthPort, koper2.key)).parasign.tier, 'pro');

  const zet = (iso) => (j) => {
    for (const k of j.api_keys || []) {
      if (k.paid_until_parasign) k.paid_until_parasign = iso;
      if (k.paid_until_parasend) k.paid_until_parasend = iso;
    }
  };
  const opnieuw = async (iso) => {
    S.resend.clear();
    await S.redis.del('paramant:billing:expiry');
    await S.redis.del('paramant:billing:expiry_meta');
    await S.redis.del(`paramant:entitlements:grant:${koper2.key}`);
    for (const welke of ['main', 'health']) await S.restartRelay(welke, zet(iso), { PLAN_EXPIRY_BOOT_DELAY_MS: '1200' });
    await new Promise((r) => setTimeout(r, 5000));
  };

  // Zeven dagen voor het einde: de aangekondigde waarschuwing.
  await opnieuw(new Date(Date.now() + 6 * 86400000).toISOString());
  const waarschuwing = S.resend.mails.filter((m) => / ends on /.test(String(m.subject)));
  assert.ok(waarschuwing.length >= 1, 'er kwam geen waarschuwing voor het einde van de termijn');
  assert.match(String(waarschuwing[0].text), /nothing is charged automatically/,
    'de waarschuwing zegt iets anders dan /pricing en /terms');
  assert.equal((await rechtenOp(S.healthPort, koper2.key)).parasign.tier, 'pro',
    'het recht viel al weg voordat de termijn om was');

  // Termijn voorbij: de mail zegt Community, en dat is dan ook zo. Op beide relays.
  await opnieuw(new Date(Date.now() - 86400000).toISOString());
  assert.ok(S.resend.mails.some((m) => / has ended$/.test(String(m.subject))),
    'er kwam geen bericht dat de termijn was afgelopen');
  for (const [naam, port] of [['main', S.relayPort], ['health', S.healthPort]]) {
    const e = await rechtenOp(port, koper2.key);
    assert.equal(e.parasign.tier, 'free', `${naam} geeft na afloop van de termijn nog Pro`);
    assert.equal(e.parasign.quotas.signs_month, FREE_SIGNS);
  }
});
