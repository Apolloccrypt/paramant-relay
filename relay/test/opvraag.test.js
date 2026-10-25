'use strict';

// STUKKEN OPVRAGEN, DE OPSLAG.
//
// Zonder relay: de opslag van een verzoek, de grenzen per plan, het einde van
// de geldigheid, en wie wat mag zien. De route-kant en de cryptografie staan in
// route-opvraag.test.js en tests/opvragen-e2e.test.mjs.

const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('crypto');
const { createParaSignStore } = require('../lib/parasign-store');
const { createSendStore } = require('../lib/send');
const opvraag = require('../lib/opvraag');
const tiers = require('../lib/tiers');

const DAG = 86400_000;

function maak(opts = {}) {
  let nu = opts.start || Date.parse('2026-10-25T09:00:00Z');
  const clock = () => nu;
  const store = createParaSignStore({ redis: null, encKey: null, prefix: 'popvr-t', aadPrefix: 'opvraag-t' });
  const sendStore = createParaSignStore({ redis: null, encKey: null, prefix: 'psend-t', aadPrefix: 'parasend-t' });
  const sends = createSendStore({ store: sendStore, now: clock });
  const o = opvraag.createOpvraagStore({ store, budget: sends.budget, now: clock });
  return { o, store, sends, clock, zet: (t) => { nu = t; }, plus: (ms) => { nu += ms; } };
}

function b64u(n) { return crypto.randomBytes(n).toString('base64url'); }
function ecdhPub() { const b = crypto.randomBytes(65); b[0] = 4; return b.toString('base64url'); }

function descriptor(nu, over = {}) {
  return { v: 1, id: opvraag.newId(), office: 'Acme Administratie', greet: 'Demo',
           items: ['Kopie paspoort', 'Loonstrook', 'Jaaropgave 2025'],
           expires_at: nu + 7 * DAG, kem_pub: b64u(1184), ecdh_pub: ecdhPub(), ...over };
}

function nieuw(o, nu, over = {}, extra = {}) {
  const d = descriptor(nu, over);
  return o.create({ accountId: extra.accountId || 'acct_demo', plan: extra.plan || 'pro', office: 'Acme Administratie',
                    descriptor: d, clientName: 'Demo Klant', clientEmail: extra.email === undefined ? 'demo@example.com' : extra.email,
                    lang: 'nl', skWrapped: b64u(2600), kluisId: b64u(16) }).then((r) => ({ r, d }));
}

// Een pakket zoals encrypt_blob het maakt: begint met 0x03, verder ondoorzichtig.
function pakket(n) { const b = crypto.randomBytes(n); b[0] = 3; return b; }

test('elk plan heeft de vier opvraaggrenzen, en het gratis plan de krapste', () => {
  for (const plan of Object.keys(tiers.TIER_LIMITS)) {
    for (const dim of ['opvraag_open', 'opvraag_items', 'opvraag_mb', 'opvraag_ttl_ms']) {
      const v = tiers.tierLimitNum(plan, dim);
      assert.ok(Number.isFinite(v) && v > 0, plan + '.' + dim + ' = ' + v);
    }
  }
  assert.equal(tiers.tierLimitNum('community', 'opvraag_open'), 1);
  assert.ok(tiers.tierLimitNum('pro', 'opvraag_open') > 1);
  // Nooit meer beloven dan de opslag eronder kan houden: per verzoek niet meer
  // dan een verzending, per account niet meer dan het aandeel in de begroting,
  // en nooit langer dan het begrotingsrecord leeft (8 dagen).
  const send = require('../lib/send');
  for (const plan of Object.keys(tiers.TIER_LIMITS)) {
    assert.ok(tiers.tierLimitNum(plan, 'opvraag_mb') <= send.SEND_MAX_MB, plan);
    assert.ok(tiers.tierLimitNum(plan, 'opvraag_mb') <= tiers.tierLimitNum(plan, 'opvraag_total_mb'), plan);
    const deel = plan === 'community' ? send.SEND_FREE_ACCOUNT_MB : send.SEND_ACCOUNT_MB;
    assert.ok(tiers.tierLimitNum(plan, 'opvraag_total_mb') <= deel, plan + ' belooft meer dan zijn aandeel');
    assert.ok(tiers.tierLimitNum(plan, 'opvraag_ttl_ms') <= 7 * DAG, plan);
  }
});

test('een verzoek wordt bewaard zoals de browser het schreef, en de klant ziet alleen de beschrijving', async () => {
  const { o, clock } = maak();
  const { r, d } = await nieuw(o, clock());
  assert.equal(r.ok, true, JSON.stringify(r));
  const v = await o.publicView(d.id);
  assert.equal(v.ok, true);
  assert.deepEqual(v.descriptor, d, 'de beschrijving komt byte voor byte terug, anders klopt de pin niet');
  assert.deepEqual(v.received, [0, 0, 0]);
  const tekst = JSON.stringify(v);
  assert.ok(!tekst.includes('demo@example.com'), 'het adres van de klant gaat niet naar wie de link heeft');
  assert.ok(!tekst.includes('sk_wrapped') && !tekst.includes('acct_demo'), 'geen sleuteldoos en geen account in de publieke blik');
});

test('tekst die niet al schoon is wordt geweigerd, niet stil verbeterd', async () => {
  const { o, clock } = maak();
  for (const over of [{ greet: ' Demo' }, { items: ['Loonstrook '] }, { items: ['a\nb'] }, { items: ['<b>x</b>'] },
                      { items: ['Loonstrook', 'loonstrook'] }, { items: [] }, { office: 'Iemand Anders' },
                      { kem_pub: b64u(1000) }, { ecdh_pub: b64u(65) }, { v: 2 }, { id: 'kort' }]) {
    const { r } = await nieuw(o, clock(), over);
    assert.equal(r.ok, false, 'geweigerd: ' + JSON.stringify(Object.keys(over)));
  }
  const d = descriptor(clock()); d.extra = 1;
  const r2 = await o.create({ accountId: 'acct_demo', plan: 'pro', office: 'Acme Administratie', descriptor: d,
    clientName: 'Demo Klant', clientEmail: '', lang: 'nl', skWrapped: b64u(2600), kluisId: b64u(16) });
  assert.equal(r2.reason, 'bad_descriptor', 'een extra veld valt buiten de hash en wordt dus geweigerd');
});

test('grenzen per plan: open verzoeken, aantal stukken en geldigheid', async () => {
  const { o, clock } = maak();
  const a = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_gratis' });
  assert.equal(a.r.ok, true);
  const b = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_gratis' });
  assert.equal(b.r.reason, 'too_many_open', 'Community: een open verzoek tegelijk');
  await o.close(a.d.id, 'acct_gratis');
  const c = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_gratis' });
  assert.equal(c.r.ok, true, 'na sluiten mag er een nieuw verzoek');

  const veel = Array.from({ length: 6 }, (_, i) => 'Stuk ' + (i + 1));
  assert.equal((await nieuw(o, clock(), { items: veel }, { plan: 'community', accountId: 'acct_x' })).r.reason, 'too_many_items');
  assert.equal((await nieuw(o, clock(), { items: veel }, { plan: 'pro', accountId: 'acct_x' })).r.ok, true);

  assert.equal((await nieuw(o, clock(), { expires_at: clock() + 8 * DAG }, { plan: 'community', accountId: 'acct_y' })).r.reason, 'too_long');
  assert.equal((await nieuw(o, clock(), { expires_at: clock() + 60_000 }, { plan: 'pro', accountId: 'acct_y' })).r.reason, 'too_short');
  assert.equal((await nieuw(o, clock(), { expires_at: clock() + 14 * DAG }, { plan: 'pro', accountId: 'acct_y' })).r.reason, 'too_long');
  assert.equal((await nieuw(o, clock(), { expires_at: clock() + 7 * DAG }, { plan: 'pro', accountId: 'acct_y' })).r.ok, true);
});

test('hetzelfde id twee keer: de tweede wordt geweigerd, ook vanaf een ander account', async () => {
  const { o, clock } = maak();
  const { d } = await nieuw(o, clock());
  const r = await o.create({ accountId: 'acct_ander', plan: 'pro', office: 'Acme Administratie', descriptor: { ...d, kem_pub: b64u(1184) },
    clientName: 'X', clientEmail: '', lang: 'nl', skWrapped: b64u(2600), kluisId: b64u(16) });
  assert.equal(r.reason, 'id_taken');
  assert.equal((await o.publicView(d.id)).descriptor.kem_pub, d.kem_pub, 'de sleutel van het eerste kantoor staat er nog');
});

test('uploaden: alleen versleutelde pakketten, binnen de grenzen per stuk en per verzoek', async () => {
  const { o, clock } = maak();
  const { d } = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_gratis' });
  assert.equal((await o.upload(d.id, 0, Buffer.from('gewoon een bestand'))).reason, 'not_encrypted');
  const leeg = Buffer.alloc(4000, 0x25);
  assert.equal((await o.upload(d.id, 0, leeg)).reason, 'not_encrypted', 'een PDF of foto in het klaar gaat niet de opslag in');
  assert.equal((await o.upload(d.id, 3, pakket(4000))).reason, 'bad_item');
  assert.equal((await o.upload(d.id, 0, pakket(opvraag.FILE_MAX_BYTES + 1))).reason, 'too_large');
  for (let i = 0; i < opvraag.FILES_PER_ITEM; i++) assert.equal((await o.upload(d.id, 0, pakket(4000))).ok, true);
  assert.equal((await o.upload(d.id, 0, pakket(4000))).reason, 'item_full');
  // Community: 10 MB per verzoek.
  assert.equal((await o.upload(d.id, 1, pakket(5 * 1048576))).ok, true);
  assert.equal((await o.upload(d.id, 2, pakket(5 * 1048576))).reason, 'request_full');
  const v = await o.publicView(d.id);
  assert.deepEqual(v.received, [3, 1, 0]);
});

test('de opslagbegroting van de verzendingen geldt ook hier: het gratis deel raakt op', async () => {
  const { o, clock } = maak();
  // Vijf gratis accounts, elk een verzoek van 10 MB vol: de gratis pot (75 MB) en
  // het aandeel per gratis account (25 MB) gelden over beide producten samen.
  let geweigerd = null;
  for (let a = 0; a < 10 && !geweigerd; a++) {
    const { d } = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' + a });
    for (let i = 0; i < 2; i++) {
      const r = await o.upload(d.id, i, pakket(5 * 1048576 - 100));
      if (!r.ok) { geweigerd = r.reason; break; }
    }
  }
  assert.equal(geweigerd, 'store_full', 'de gedeelde pot weigert, in plaats van redis vol te laten lopen');
});

test('na "geldig tot" is alles weg: geen blik, geen upload, geen download', async () => {
  const { o, clock, plus } = maak();
  const { d } = await nieuw(o, clock(), { expires_at: clock() + 2 * 3600_000 });
  assert.equal((await o.upload(d.id, 0, pakket(5000))).ok, true);
  plus(2 * 3600_000 + 1);
  assert.equal((await o.publicView(d.id)).reason, 'unknown');
  assert.equal((await o.upload(d.id, 1, pakket(5000))).reason, 'unknown');
  assert.equal((await o.getFile(d.id, 'acct_demo', 0)).ok, false);
  assert.deepEqual((await o.list('acct_demo')).requests, []);
});

test('gesloten: de klant kan niets meer toevoegen, het kantoor kan nog downloaden', async () => {
  const { o, clock } = maak();
  const { d } = await nieuw(o, clock());
  await o.upload(d.id, 0, pakket(5000));
  assert.equal((await o.close(d.id, 'acct_vreemd')).ok, false, 'alleen het eigen kantoor sluit');
  assert.equal((await o.close(d.id, 'acct_demo')).ok, true);
  const v = await o.publicView(d.id);
  assert.equal(v.reason, 'closed');
  assert.equal(v.office, 'Acme Administratie');
  assert.equal((await o.upload(d.id, 1, pakket(5000))).reason, 'closed');
  assert.equal((await o.getFile(d.id, 'acct_demo', 0)).ok, true);
});

test('rechten: alleen het kantoor ziet de lijst, de details en de bestanden', async () => {
  const { o, clock } = maak();
  const { d } = await nieuw(o, clock());
  const p = pakket(7000);
  await o.upload(d.id, 1, p);
  assert.equal((await o.list('acct_demo')).requests.length, 1);
  assert.equal((await o.list('acct_ander')).requests.length, 0);
  assert.equal((await o.detail(d.id, 'acct_ander')).ok, false);
  assert.equal((await o.getFile(d.id, 'acct_ander', 0)).ok, false);
  assert.equal((await o.remove(d.id, 'acct_ander')).ok, false);
  const det = await o.detail(d.id, 'acct_demo');
  assert.equal(det.ok, true);
  assert.ok(det.sk_wrapped && det.descriptor.id === d.id);
  assert.deepEqual(det.items.map((x) => x.count), [0, 1, 0]);
  const f = await o.getFile(d.id, 'acct_demo', 0);
  assert.ok(f.bytes.equals(p), 'het kantoor krijgt exact de versleutelde bytes terug');
  assert.equal(f.item, 1);
});

test('verwijderen geeft de ruimte in de begroting terug', async () => {
  const { o, clock } = maak();
  const { d } = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' });
  await o.upload(d.id, 0, pakket(5 * 1048576 - 100));
  await o.upload(d.id, 1, pakket(5 * 1048576 - 100));
  assert.equal((await o.remove(d.id, 'acct_g')).ok, true);
  assert.equal((await o.publicView(d.id)).reason, 'unknown');
  const { d: d2 } = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' });
  assert.equal((await o.upload(d2.id, 0, pakket(5 * 1048576 - 100))).ok, true);
  assert.equal((await o.upload(d2.id, 1, pakket(5 * 1048576 - 100))).ok, true, 'het aandeel van het account is weer vrij');
});

test('herinnering: alleen met adres, niet als alles binnen is, met een plafond en een uur ertussen', async () => {
  const { o, clock, plus } = maak();
  const gratis = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_gratis' });
  assert.equal((await o.takeReminder(gratis.d.id, 'acct_gratis')).reason, 'paid_only', 'geen herinneringsmail op het gratis plan');
  const zonder = await nieuw(o, clock(), {}, { email: '' });
  assert.equal((await o.takeReminder(zonder.d.id, 'acct_demo')).reason, 'no_email');
  const { d } = await nieuw(o, clock());
  const r1 = await o.takeReminder(d.id, 'acct_demo');
  assert.equal(r1.ok, true);
  assert.equal(r1.email, 'demo@example.com');
  assert.deepEqual(r1.missing, ['Kopie paspoort', 'Loonstrook', 'Jaaropgave 2025']);
  assert.equal((await o.takeReminder(d.id, 'acct_demo')).reason, 'reminder_too_soon');
  plus(3600_000); assert.equal((await o.takeReminder(d.id, 'acct_demo')).ok, true);
  plus(3600_000); assert.equal((await o.takeReminder(d.id, 'acct_demo')).ok, true);
  plus(3600_000); assert.equal((await o.takeReminder(d.id, 'acct_demo')).reason, 'reminder_limit');
  await o.undoReminder(d.id, 'acct_demo');
  assert.equal((await o.takeReminder(d.id, 'acct_demo')).ok, true, 'een mislukte mail kost geen herinnering');
  assert.equal((await o.takeReminder(d.id, 'acct_ander')).reason, 'unknown');
});

test('kluis: per account, met begrensde passkey-wraps', async () => {
  const { o } = maak();
  const kid = b64u(16);
  assert.equal((await o.kluisPut('acct_demo', { kluis_id: 'x' })).ok, false);
  assert.equal((await o.kluisPut('acct_demo', { kluis_id: kid })).ok, true);
  const w = { cred: b64u(32), salt: b64u(32), iv: b64u(12), ct: b64u(48) };
  assert.equal((await o.kluisPut('acct_demo', { kluis_id: kid, wrap: { ...w, ct: b64u(40) } })).ok, false);
  const r = await o.kluisPut('acct_demo', { kluis_id: kid, wrap: w });
  assert.equal(r.ok, true);
  await o.kluisPut('acct_demo', { kluis_id: kid, wrap: w });
  const lijst = await o.kluisList('acct_demo');
  assert.equal(lijst.length, 1);
  assert.equal(lijst[0].wraps.length, 1, 'dezelfde passkey vervangt zijn eigen wrap');
  assert.deepEqual(await o.kluisList('acct_ander'), []);
});

test('onzichtbare tekens, links en adressen in wat de klant leest: geweigerd', async () => {
  const { o, clock } = maak();
  for (const over of [{ greet: 'De\u200Bmo' }, { items: ['Loon\u202Estrook'] }, { items: ['\uFEFFPaspoort'] },
                      { items: ['Upload via https://evil.example'] }, { items: ['Kijk op www.voorbeeld.nl'] },
                      { items: ['Mail naar demo@example.com'] }, { items: ['factuur.pdf.com'] }, { greet: 'Demo\u2066' }]) {
    assert.equal((await nieuw(o, clock(), over)).r.ok, false, JSON.stringify(over));
  }
  assert.equal((await nieuw(o, clock(), { items: ['Jaaropgave 2025', 'Uittreksel KvK', 'Polis B.V.'] })).r.ok, true,
    'gewone labels met punten blijven werken');
  assert.equal(opvraag.cleanText('Acme\u200F Administratie', 120, false), null);
});

test('een gesloten verzoek met bestanden telt mee tot het verwijderd is', async () => {
  const { o, clock } = maak();
  const a = await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' });
  await o.upload(a.d.id, 0, pakket(5000));
  await o.close(a.d.id, 'acct_g');
  assert.equal((await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' })).r.reason, 'too_many_open');
  await o.remove(a.d.id, 'acct_g');
  assert.equal((await nieuw(o, clock(), {}, { plan: 'community', accountId: 'acct_g' })).r.ok, true);
});

test('per account geldt een totaal over alle verzoeken, gesloten meegeteld', async () => {
  const { o, clock } = maak();
  // Firm: 25 MB per verzoek, 35 MB samen.
  const a = await nieuw(o, clock(), {}, { accountId: 'acct_f' });
  const b = await nieuw(o, clock(), {}, { accountId: 'acct_f' });
  for (const i of [0, 0, 0, 1, 1]) assert.equal((await o.upload(a.d.id, i, pakket(5 * 1048576 - 100))).ok, true);
  await o.close(a.d.id, 'acct_f');
  assert.equal((await o.upload(b.d.id, 0, pakket(5 * 1048576 - 100))).ok, true);
  assert.equal((await o.upload(b.d.id, 1, pakket(5 * 1048576 - 100))).ok, true);
  assert.equal((await o.upload(b.d.id, 2, pakket(5 * 1048576 - 100))).reason, 'account_full');
});
