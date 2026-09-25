'use strict';
// Wat een tweede aankoop, een cadeaucode of een herstart met een lopend recht
// doet. Bevindingen R2, R3, R8 en R9 uit de betaaltest van 25-09-2026, en de
// review van #515.
//
// R2  Een Firm-jaarklant die een maand Business kocht, kreeg dertien maanden
//     Business: de maand werd opgeteld bij de einddatum van het Firm-jaar. De
//     eerste reparatie gaf een maand Business en daarna free: de elf betaalde
//     maanden Pro waren weg (review #515, blokkerend). Nu houdt een product een
//     termijn per tier, en geldt de hoogste tier waarvan de termijn nog loopt.
// R3  Een Business-klant die Firm kocht, of een code inwisselde, stond daarna
//     op ParaSign Pro. Alleen op de relay die het verzoek deed: de andere
//     nemen uit redis geen lager recht over, dus de vloot werd het oneens.
// R8  De kassa verkocht de losse Pro-plannen die geen pagina meer verkoopt.
// R9  Na een herstart vergat de relay dat een termijn Firm was, en de klant
//     kreeg twee waarschuwingsmails over twee plannen die hij nooit kocht.
//
// Dit bestand pint de regels zelf, zonder relay. De weg van de koper over twee
// echte relays staat in tests/rang-en-kassa.test.mjs.
// Run: node --test relay/test/rang-van-een-recht.test.js

const test = require('node:test');
const assert = require('node:assert/strict');

const billing = require('../lib/billing');
const catalog = require('../lib/billing-catalog');
const entitlements = require('../lib/entitlements');
const keysTable = require('../lib/keys-table');
const planExpiry = require('../lib/plan-expiry');
const sharedGrants = require('../lib/shared-grants');

const DAY = 86400000;
const NOW = new Date('2026-09-25T10:00:00.000Z');
const ACCOUNT = 'acct_rang';

// Eén account zoals relay.js het bijhoudt: één record, geschreven met dezelfde
// functie als setProductPlan (entitlements.applyProductTier), de termijn van de
// gekochte tier gelezen zoals de webhook hem leest (termEndOf), en het recht
// gelezen met de regel van elke poort (effectiveProductTier).
function account(rec = {}) {
  const calls = [];
  return {
    rec,
    calls,
    deps: {
      now: NOW,
      currentTermEnd: async (_a, product, tier) => entitlements.termEndOf(rec, product, tier),
      setProductPlan: async (_a, product, tier, paidUntil, bundle) => {
        calls.push({ product, tier, paidUntil: paidUntil ? new Date(paidUntil).toISOString() : null });
        entitlements.applyProductTier(rec, product, tier, paidUntil, bundle, { now: NOW.getTime() });
        return { ok: true, product, tier };
      },
    },
  };
}

// Wat het account geeft op een dag.
function stand(rec, iso) {
  const at = Date.parse(iso);
  return {
    ondertekenen: entitlements.effectiveProductTier(rec, 'parasign', at).tier,
    versturen: entitlements.effectiveProductTier(rec, 'parasend', at).tier,
  };
}

function payment(product, plan, interval, id) {
  const order = catalog.resolveOrder({ product, plan, interval });
  return {
    id: id || `tr_${product}_${plan}_${interval}`,
    status: 'paid',
    amount: { currency: 'EUR', value: order.amount },
    metadata: { accountId: ACCOUNT, product, plan, interval },
  };
}

const JAAR_EIND = '2027-09-25T10:00:00.000Z';
const MAAND_EIND = '2026-10-25T10:00:00.000Z';

// ── R2 en de review: geen betaalde tijd kwijt ────────────────────────────────

test('R2: een Business-maand na een Firm-jaar geeft een maand Business, daarna Pro tot het einde van het jaar', async () => {
  const a = account();
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_jaar'), a.deps);
  const out = await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_maand'), a.deps);
  assert.equal(out.result, 'granted');
  assert.equal(out.level, 'info', 'er valt niets meer te herstellen, dus er is ook geen waarschuwing nodig');
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'business'), MAAND_EIND, 'een maand Business, vanaf nu');
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'pro'), JAAR_EIND, 'het Firm-jaar blijft staan');
  assert.deepEqual(stand(a.rec, '2026-10-01'), { ondertekenen: 'business', versturen: 'pro' });
  assert.deepEqual(stand(a.rec, '2026-10-26'), { ondertekenen: 'pro', versturen: 'pro' },
    'na de Business-maand valt hij terug op Pro, niet op free');
  assert.deepEqual(stand(a.rec, '2027-09-24'), { ondertekenen: 'pro', versturen: 'pro' });
  assert.deepEqual(stand(a.rec, '2027-09-26'), { ondertekenen: 'free', versturen: 'community' });
});

test('twee tabbladen, beide volgordes: Firm-jaar en Business-maand geven hetzelfde, en niets gaat verloren', async () => {
  for (const volgorde of [['firm', 'business'], ['business', 'firm']]) {
    const a = account();
    for (const wat of volgorde) {
      const p = wat === 'firm' ? payment('firm', 'firm', 'yearly', 'tr_tab_firm') : payment('parasign', 'business', 'monthly', 'tr_tab_biz');
      const out = await billing.processPayment(p, a.deps);
      assert.equal(out.result, 'granted', `${volgorde.join(' dan ')}: ${out.reason}`);
      assert.equal(out.level, 'info', `${volgorde.join(' dan ')}: ${out.reason}`);
    }
    const naam = volgorde.join(' dan ');
    assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'business'), MAAND_EIND, naam);
    assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'pro'), JAAR_EIND, naam);
    assert.equal(entitlements.termEndOf(a.rec, 'parasend', 'pro'), JAAR_EIND, naam);
    assert.deepEqual(stand(a.rec, '2026-10-01'), { ondertekenen: 'business', versturen: 'pro' }, naam);
    assert.deepEqual(stand(a.rec, '2026-10-26'), { ondertekenen: 'pro', versturen: 'pro' }, naam);
    assert.deepEqual(stand(a.rec, '2027-09-26'), { ondertekenen: 'free', versturen: 'community' }, naam);
  }
});

test('R2: een verlenging telt vanaf de eigen einddatum van dezelfde tier, ook als er een hogere boven ligt', async () => {
  const a = account();
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_1'), a.deps);
  await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_2'), a.deps);
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_3'), a.deps);
  await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_4'), a.deps);
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'pro'), '2028-09-25T10:00:00.000Z', 'twee Firm-jaren achter elkaar');
  assert.equal(entitlements.termEndOf(a.rec, 'parasend', 'pro'), '2028-09-25T10:00:00.000Z');
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'business'), '2026-11-25T10:00:00.000Z', 'twee Business-maanden achter elkaar');
});

test('R2: vroeg verlengen verliest geen dag', async () => {
  const end = new Date(NOW.getTime() + 10 * DAY).toISOString();
  const a = account({ plan_parasign: 'pro', paid_until_parasign: end, plan_parasend: 'pro', paid_until_parasend: end });
  const out = await billing.processPayment(payment('firm', 'firm', 'monthly'), a.deps);
  assert.equal(out.result, 'granted');
  for (const product of ['parasign', 'parasend']) {
    assert.equal(entitlements.termEndOf(a.rec, product, 'pro'), '2026-11-05T10:00:00.000Z', `${product}: een maand na de lopende einddatum`);
  }
});

// ── R3 ───────────────────────────────────────────────────────────────────────

test('R3: Firm over een lopende Business-termijn laat Business staan, en Pro ligt eronder klaar', async () => {
  const bizEnd = '2026-10-10T10:00:00.000Z';
  const a = account({ plan_parasign: 'business', paid_until_parasign: bizEnd, plan_parasend: 'community' });
  const out = await billing.processPayment(payment('firm', 'firm', 'monthly'), a.deps);
  assert.equal(out.result, 'granted', 'het geld is binnen, de betaling blijft een toekenning met factuur');
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'business'), bizEnd, 'de Business-termijn blijft precies wat hij was');
  assert.deepEqual(stand(a.rec, '2026-10-01'), { ondertekenen: 'business', versturen: 'pro' });
  assert.deepEqual(stand(a.rec, '2026-10-12'), { ondertekenen: 'pro', versturen: 'pro' }, 'daarna het Firm-deel');
  assert.deepEqual(stand(a.rec, '2026-10-26'), { ondertekenen: 'free', versturen: 'community' });
});

test('R3: de regel zelf, per product', () => {
  assert.equal(entitlements.termRelation('parasign', 'pro', 'free'), 'none');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'pro'), 'same');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'business'), 'higher_running');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'enterprise'), 'higher_running');
  assert.equal(entitlements.termRelation('parasign', 'business', 'pro'), 'lower_running');
  assert.equal(entitlements.termRelation('parasend', 'pro', 'community'), 'none');
  assert.equal(entitlements.termRelation('parasend', 'pro', 'enterprise'), 'higher_running');
  // Een verlopen termijn is de vloer, ook als er nog business in het veld staat.
  const lapsed = { plan_parasign: 'business', paid_until_parasign: new Date(NOW.getTime() - DAY).toISOString() };
  assert.equal(entitlements.termRelationOf(lapsed, 'parasign', 'pro', NOW.getTime()), 'none');
  // En een termijn zonder einddatum loopt.
  assert.equal(entitlements.termRelationOf({ plan_parasign: 'business' }, 'parasign', 'pro', NOW.getTime()), 'higher_running');
});

// ── Bestaande data, beide relays, de gedeelde rij en een herstart ────────────

test('een record uit users.json met één paid_until werkt zoals altijd', async () => {
  const x = '2026-12-01T00:00:00.000Z';
  const oud = { plan_parasign: 'pro', paid_until_parasign: x };
  assert.equal(entitlements.termsOf(oud, 'parasign').length, 1);
  assert.deepEqual(stand(oud, '2026-11-30'), { ondertekenen: 'pro', versturen: 'community' });
  assert.deepEqual(stand(oud, '2026-12-02'), { ondertekenen: 'free', versturen: 'community' });
  assert.equal(entitlements.effectiveProductTier(oud, 'parasign', Date.parse('2026-12-02')).expired, true);
  // Zonder einddatum loopt hij door, en een onleesbare datum telt als geen datum.
  assert.equal(entitlements.effectiveProductTier({ plan_parasign: 'business' }, 'parasign', Date.parse('2099-01-01')).tier, 'business');
  assert.equal(entitlements.effectiveProductTier({ plan_parasign: 'business', paid_until_parasign: 'geen-datum' }, 'parasign').tier, 'business');
  // Een tweede tier erbij laat de oude termijn staan.
  const a = account({ ...oud });
  await billing.processPayment(payment('parasign', 'business', 'monthly'), a.deps);
  assert.equal(entitlements.termEndOf(a.rec, 'parasign', 'pro'), x);
  assert.deepEqual(stand(a.rec, '2026-11-01'), { ondertekenen: 'pro', versturen: 'community' });
  // Eén termijn schrijft precies de velden van voor deze wijziging, niets meer.
  const b = account();
  await billing.processPayment(payment('firm', 'firm', 'monthly'), b.deps);
  assert.equal(b.rec.terms_parasign, undefined);
  assert.equal(b.rec.paid_until_parasign, MAAND_EIND);
  assert.equal(b.rec.bundle_parasign, 'firm');
});

test('de gedeelde redis-rij draagt alle termijnen, en beide relays komen op hetzelfde uit', async () => {
  // main nam beide betalingen aan; health zag alleen het Firm-jaar nog.
  const main = account();
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_a'), main.deps);
  const health = account();
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_a'), health.deps);
  await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_b'), main.deps);

  // Wat main in de gedeelde rij zet: alleen strings, zoals een redis-hash.
  const rij = sharedGrants.grantOf(main.rec);
  for (const v of Object.values(rij)) assert.equal(typeof v, 'string');
  const moved = sharedGrants.applyTo(health.rec, rij, NOW.getTime());
  assert.deepEqual(moved, ['parasign'], 'health neemt de Business-maand over');
  for (const dag of ['2026-10-01', '2026-10-26', '2027-09-24', '2027-09-26']) {
    assert.deepEqual(stand(health.rec, dag), stand(main.rec, dag), `main en health verschillen op ${dag}`);
  }
  // Een relay die nog niets van dit account wist, krijgt uit de rij alles.
  const leeg = {};
  sharedGrants.applyTo(leeg, rij, NOW.getTime());
  for (const dag of ['2026-10-01', '2026-10-26', '2027-09-24', '2027-09-26']) {
    assert.deepEqual(stand(leeg, dag), stand(main.rec, dag), `een lege relay verschilt van main op ${dag}`);
  }
  // En de oude rij van health haalt bij main niets weg.
  assert.deepEqual(sharedGrants.applyTo(main.rec, sharedGrants.grantOf({ plan_parasign: 'pro', paid_until_parasign: JAAR_EIND }), NOW.getTime()), []);
  assert.equal(entitlements.termEndOf(main.rec, 'parasign', 'business'), MAAND_EIND);
  // Wie niets meer betaalt, raakt via de rij alles kwijt, ook de onderliggende termijn.
  const weg = { ...main.rec };
  sharedGrants.applyRevocation(weg);
  assert.deepEqual(stand(weg, '2026-10-01'), { ondertekenen: 'free', versturen: 'community' });
  assert.equal(weg.terms_parasign, undefined);
});

test('een herstart leest alle termijnen terug uit users.json', async () => {
  const a = account({});
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_x'), a.deps);
  await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_y'), a.deps);
  // Zo staat het in users.json, en zo leest relay.js het bij het opstarten.
  const raw = JSON.parse(JSON.stringify({ key: 'pgp_rang_herstart', account_id: 'acct_rang_herstart', plan: 'community', active: true, ...a.rec }));
  const apiKeys = new Map([[raw.key, { plan: raw.plan, active: true, ...keysTable.parseAccountFields(raw) }]]);
  const accounts = new Map();
  keysTable.rebuildKeyIndexes(apiKeys, accounts, new Map(), new Map(), () => {});
  const merged = entitlements.mergeAccountRecord(accounts.get(raw.account_id), [apiKeys.get(raw.key)], NOW.getTime());
  for (const dag of ['2026-10-01', '2026-10-26', '2027-09-26']) {
    assert.deepEqual(stand(merged, dag), stand(a.rec, dag), `na een herstart anders op ${dag}`);
  }
});

// ── De admin: omhoog en omlaag zonder dat de termijn verdwijnt ───────────────

test('de admin verplaatst de lopende termijn naar een andere tier, met dezelfde einddatum', () => {
  const at = { now: NOW.getTime() };
  // Omlaag (de relay vraagt daar eerst uitdrukkelijk om): Business tot X wordt Pro tot X.
  const omlaag = { plan_parasign: 'business', paid_until_parasign: MAAND_EIND };
  entitlements.applyProductTier(omlaag, 'parasign', 'pro', undefined, undefined, at);
  assert.equal(omlaag.plan_parasign, 'pro');
  assert.equal(omlaag.paid_until_parasign, MAAND_EIND, 'omlaag houdt de einddatum, en wordt geen Pro zonder einde');
  // Omhoog: Pro tot het einde van het jaar wordt Business tot het einde van het jaar.
  const omhoog = { plan_parasign: 'pro', paid_until_parasign: JAAR_EIND, bundle_parasign: 'firm' };
  entitlements.applyProductTier(omhoog, 'parasign', 'business', undefined, undefined, at);
  assert.equal(omhoog.plan_parasign, 'business');
  assert.equal(omhoog.paid_until_parasign, JAAR_EIND);
  assert.equal(omhoog.bundle_parasign, undefined, 'een Business-termijn is geen Firm meer');
  // Business boven een Firm-jaar, omlaag naar Pro: de langste van de twee blijft.
  const beide = account();
  return (async () => {
    await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_p'), beide.deps);
    await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_q'), beide.deps);
    entitlements.applyProductTier(beide.rec, 'parasign', 'pro', undefined, undefined, at);
    assert.equal(entitlements.termEndOf(beide.rec, 'parasign', 'business'), null);
    assert.equal(entitlements.termEndOf(beide.rec, 'parasign', 'pro'), JAAR_EIND);
    assert.deepEqual(stand(beide.rec, '2026-10-01'), { ondertekenen: 'pro', versturen: 'pro' });
    // Niets lopend: de toekenning die een admin altijd al deed, zonder einde.
    const leeg = { plan_parasign: 'free' };
    entitlements.applyProductTier(leeg, 'parasign', 'pro', undefined, undefined, at);
    assert.equal(leeg.plan_parasign, 'pro');
    assert.equal(leeg.paid_until_parasign, undefined);
  })();
});

// ── De verloopmail kijkt naar de laatste termijn ─────────────────────────────

test('de verloopmail gaat over het echte einde, niet over het einde van de Business-maand', async () => {
  const a = account();
  await billing.processPayment(payment('firm', 'firm', 'yearly', 'tr_m1'), a.deps);
  await billing.processPayment(payment('parasign', 'business', 'monthly', 'tr_m2'), a.deps);
  const laatste = entitlements.finalTermOf(a.rec, 'parasign');
  assert.deepEqual(laatste, { tier: 'pro', paidUntil: JAAR_EIND, bundle: 'firm' });
  const redis = fakeRedis();
  await planExpiry.seedIndex(redis, [{ accountId: ACCOUNT, record: { ...a.rec, email: 'tab@example.test' } }]);
  const vlak = [];
  await planExpiry.runSweep({ redis, now: Date.parse('2026-10-20T10:00:00.000Z'), sendEmail: async (m) => { vlak.push(m); return true; } });
  assert.deepEqual(vlak.map((m) => m.subject), [], 'vijf dagen voor het einde van de Business-maand loopt het account niet af');
  const eind = [];
  await planExpiry.runSweep({ redis, now: Date.parse('2027-09-20T10:00:00.000Z'), sendEmail: async (m) => { eind.push(m); return true; } });
  assert.equal(eind.length, 1, eind.map((m) => m.subject).join(' | '));
  assert.match(eind[0].subject, /Firm/);
});

// ── R8 ───────────────────────────────────────────────────────────────────────

test('R8: de kassa verkoopt alleen wat de site verkoopt', () => {
  for (const { product, plan } of catalog.ON_SALE) {
    for (const interval of catalog.INTERVALS) {
      const sale = catalog.resolveSale({ product, plan, interval });
      assert.ok(!sale.error, `${product}/${plan}/${interval} staat op de site en moet te koop zijn`);
      assert.equal(sale.amount, catalog.priceOf(product, plan, interval));
    }
  }
  for (const [product, plan] of [['parasign', 'pro'], ['parasend', 'pro']]) {
    assert.equal(catalog.resolveSale({ product, plan, interval: 'monthly' }).error, 'not_on_sale',
      `${product}/${plan} staat op geen enkele pagina`);
    // Maar een betaling die al binnen is, of een abonnement van voor Firm, moet
    // de webhook nog steeds kunnen toekennen.
    assert.ok(!catalog.resolveOrder({ product, plan, interval: 'monthly' }).error);
  }
  assert.equal(catalog.resolveSale({ product: 'parasign', plan: 'enterprise', interval: 'monthly' }).error, 'unknown_plan');
});

// ── R9 ───────────────────────────────────────────────────────────────────────

// Genoeg van redis voor de index en de veegronde van lib/plan-expiry.
function fakeRedis() {
  const strings = new Map();
  const zsets = new Map();
  const hashes = new Map();
  const zset = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };
  const hash = (k) => { if (!hashes.has(k)) hashes.set(k, new Map()); return hashes.get(k); };
  return {
    isReady: true,
    async set(k, v, opts) {
      if (opts && opts.NX && strings.has(k)) return null;
      strings.set(k, String(v));
      return 'OK';
    },
    async get(k) { return strings.has(k) ? strings.get(k) : null; },
    async del(k) { return strings.delete(k) ? 1 : 0; },
    async zAdd(k, { score, value }) { zset(k).set(value, score); return 1; },
    async zRem(k, member) { return zset(k).delete(member) ? 1 : 0; },
    async zRangeByScore(k, min, max) {
      return [...zset(k).entries()].filter(([, s]) => s >= min && s <= max).sort((a, b) => a[1] - b[1]).map(([m]) => m);
    },
    async hSet(k, f, v) { hash(k).set(f, String(v)); return 1; },
    async hGet(k, f) { const v = hash(k).get(f); return v === undefined ? null : v; },
    async hDel(k, f) { return hash(k).delete(f) ? 1 : 0; },
  };
}

test('R9: na een herstart weet de relay nog dat de termijn Firm was, en er gaat één mail', async () => {
  const ends = new Date(NOW.getTime() + 6 * DAY).toISOString();
  // Precies wat setProductPlan voor een Firm-betaling in users.json zet.
  const raw = {
    key: 'pgp_rang_firm', account_id: 'acct_rang_firm', email: 'firm@example.test', plan: 'community', active: true,
    plan_parasign: 'pro', paid_until_parasign: ends, bundle_parasign: 'firm',
    plan_parasend: 'pro', paid_until_parasend: ends, bundle_parasend: 'firm',
  };
  // En zo leest relay.js dat bestand in bij het opstarten, dus na elke deploy.
  const apiKeys = new Map([[raw.key, { plan: raw.plan, email: raw.email, active: true, ...keysTable.parseAccountFields(raw) }]]);
  const accounts = new Map();
  keysTable.rebuildKeyIndexes(apiKeys, accounts, new Map(), new Map(), () => {});
  const merged = entitlements.mergeAccountRecord(accounts.get(raw.account_id), [apiKeys.get(raw.key)], NOW.getTime());
  assert.equal(merged.bundle_parasign, 'firm', 'de bundel moet een herstart overleven, net als de einddatum');
  assert.equal(merged.bundle_parasend, 'firm');

  const redis = fakeRedis();
  await planExpiry.seedIndex(redis, [{ accountId: raw.account_id, record: { ...merged, email: raw.email } }]);
  const sent = [];
  await planExpiry.runSweep({ redis, now: NOW.getTime(), sendEmail: async (m) => { sent.push(m); return true; } });
  assert.equal(sent.length, 1, `één termijn, één waarschuwing; kwam: ${sent.map((m) => m.subject).join(' | ')}`);
  assert.match(sent[0].subject, /Firm/, 'de mail noemt het plan dat de klant kocht');
});
