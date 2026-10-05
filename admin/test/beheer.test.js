'use strict';
// Het beheerscherm (lib/beheer.js en de routes die het voeden).
//
// Drie dingen die hier vast moeten staan:
//   1. Geen volle sleutel naar de browser. Elke route die het paneel leest
//      wordt hieronder echt aangeroepen tegen een geboote admin, en geen
//      antwoord mag een pgp_ met meer dan twaalf hex-tekens bevatten.
//   2. Elke gebeurtenis die deze codebase in de audit schrijft heeft een zin
//      in gewone taal. Een nieuwe logAuditEvent zonder vertaling laat dit rood
//      worden in plaats van stil als code op het scherm te verschijnen.
//   3. Omzet en MRR worden gerekend uit de documenten, niet hard op 0 of null.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const beheer = require('../lib/beheer');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const FULL_KEY_RE = /\b(pgp|psk)_[0-9a-f]{13,}/i;

// ── 1. Pure vertaling ────────────────────────────────────────────────────────

test('maskKey en scrubKeys laten geen volle sleutel over, ook niet diep', () => {
  const k = 'pgp_' + 'a'.repeat(64);
  assert.strictEqual(beheer.maskKey(k), 'pgp_aaaa...aaaa');
  const out = beheer.scrubKeys({ note: `sleutel ${k} hier`, nested: [{ [k]: k }], n: 3 });
  assert.doesNotMatch(JSON.stringify(out), FULL_KEY_RE);
  assert.strictEqual(out.n, 3);
});

test('scrubKeys en isKey kennen ook psk_live_ en psk_test_ (review 573 L2)', () => {
  for (const soort of ['live', 'test']) {
    const k = `psk_${soort}_` + 'b'.repeat(64);
    assert.strictEqual(beheer.isKey(k), true, k.slice(0, 12));
    const out = JSON.stringify(beheer.scrubKeys({ note: `sleutel ${k} hier`, nested: [{ [k]: k }] }));
    assert.ok(!out.includes('b'.repeat(13)), `volle psk_${soort}_ sleutel lekt: ${out}`);
  }
});

test('auditRow: wie is het e-mailadres, de sleutel alleen gemaskeerd', () => {
  const k = 'pgp_' + crypto.randomBytes(32).toString('hex');
  const who = beheer.buildWhoMap([{ _full: k, email: 'jan@bakkerij.test', key_id: 'k_abc123' }]);
  const row = beheer.auditRow({ user_id: k, event_type: 'admin_plan_changed', metadata: { from: 'community', to: 'pro', admin_ip: '1.2.3.x' }, ts: 1759600000000 }, who);
  assert.strictEqual(row.who, 'jan@bakkerij.test');
  assert.strictEqual(row.kid, 'k_abc123');
  assert.strictEqual(row.label, 'Plan gewijzigd door jou');
  assert.strictEqual(row.summary, 'van community naar pro');
  assert.doesNotMatch(JSON.stringify(row), FULL_KEY_RE);
  assert.strictEqual(beheer.auditRow({ user_id: 'admin', event_type: 'admin_coupon_created', metadata: { code: 'X', max: 5 } }, who).who, 'Jij (beheer)');
  // Een verwijderd account: de e-mail uit de details, niet de sleutel.
  const gone = beheer.auditRow({ user_id: 'pgp_' + 'b'.repeat(64), event_type: 'totp_reset_requested', metadata: { email: 'weg@x.test' } }, who);
  assert.strictEqual(gone.who, 'weg@x.test');
});

test('elke gebeurtenis die server.js in de audit schrijft heeft een Nederlandse zin', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const names = new Set();
  for (const m of src.matchAll(/logAuditEvent\([^,]+,\s*['"]([a-z0-9_]+)['"]/g)) names.add(m[1]);
  for (const m of src.matchAll(/'(admin_parasign_(?:enabled|disabled))'/g)) names.add(m[1]);
  for (const m of src.matchAll(/cliAudit\.logCommand\('([a-z_]+)'/g)) names.add(m[1]);
  assert.ok(names.size >= 25, 'te weinig namen gevonden: ' + names.size);
  const missing = [...names].filter((n) => !beheer.EVENT_NL[n]);
  assert.deepStrictEqual(missing, [], 'zonder vertaling: ' + missing.join(', '));
});

test('MRR: jaar telt als twaalfde, verlopen en teruggeboekt telt niet', () => {
  const now = Date.parse('2026-10-05T12:00:00Z');
  const docs = [
    { number: 'PS-1', kind: 'invoice', account_id: 'a', product: 'parasign', interval: 'year', amount_net: '1188.00', amount_gross: '1437.48', paid_at: '2026-10-01T00:00:00Z', service_period_end: '2027-10-01T00:00:00Z', invoice_date: '2026-10-01' },
    { number: 'PS-2', kind: 'receipt', account_id: 'b', product: 'parasend', interval: 'month', amount_net: '9.00', amount_gross: '10.89', paid_at: '2026-08-01T00:00:00Z', service_period_end: '2026-09-01T00:00:00Z', invoice_date: '2026-08-01' },
    { number: 'PS-3', kind: 'invoice', account_id: 'c', product: 'parasend', interval: 'month', amount_net: '20.00', amount_gross: '24.20', paid_at: '2026-10-02T00:00:00Z', service_period_end: '2026-11-02T00:00:00Z', invoice_date: '2026-10-02' },
    { number: 'CN-1', kind: 'credit_note', credit_for: 'PS-3', account_id: 'c', amount_net: '-20.00', amount_gross: '-24.20', invoice_date: '2026-10-03' },
  ];
  const m = beheer.computeMrr(docs, now);
  assert.strictEqual(m.mrr_cents, 9900, '1188/12 = 99 euro; PS-2 verlopen, PS-3 volledig terugbetaald');
  assert.strictEqual(m.paying_accounts.size, 1);
  const rev = beheer.monthRevenue(docs, '2026-10');
  assert.strictEqual(rev.net_cents, 118800, 'creditnota telt negatief mee');
  assert.strictEqual(rev.documents, 3);
  const credits = beheer.creditsByInvoice(docs);
  assert.strictEqual(beheer.documentStatus(docs[2], credits, now).code, 'terugbetaald');
  assert.match(beheer.documentStatus(docs[0], credits, now).text, /loopt tot 2027-10-01/);
  assert.match(beheer.documentStatus(docs[1], credits, now).text, /afgelopen/);
});

test('een meting die ontbreekt heet niet gemeten, nooit goed', () => {
  const p = beheer.problems({ relays: null, mails: null, http429: null, ct: null, redisMem: null });
  assert.ok(p.length >= 5);
  for (const x of p) assert.strictEqual(x.level, beheer.NIET, x.id);
  const ok = beheer.problems({ relays: [{ sector: 'main', ok: true }], mails: { total: 0, peak: { count: 0 } }, http429: { total: 3, peak: { hour: '2026-10-05T10:00Z', count: 2 } }, ct: [{ sector: 'main', size: 10, forked: false, persisted: true, growth_24h: 4 }], redisMem: { used_bytes: 1048576, max_bytes: 0 } });
  assert.ok(ok.every((x) => x.level === beheer.GOED), JSON.stringify(ok));
  const forked = beheer.problems({ relays: [], mails: null, http429: null, ct: [{ sector: 'iot', size: 1, forked: true }], redisMem: null });
  assert.strictEqual(forked.find((x) => x.id === 'ctlog').level, beheer.KAPOT);
});

test('parseMetrics en parseRedisInfo lezen wat relay en redis teruggeven', () => {
  const m = beheer.parseMetrics('# TYPE paramant_ct_log gauge\nparamant_ct_log{sector="main"} 42\nparamant_uptime_s{sector="main"} 3600\n');
  assert.strictEqual(m.ct_log, 42);
  assert.strictEqual(m.uptime_s, 3600);
  const r = beheer.parseRedisInfo('# Memory\r\nused_memory:2097152\r\nmaxmemory:4194304\r\nused_memory_peak:3145728\r\n');
  assert.strictEqual(r.used_bytes, 2097152);
  assert.strictEqual(r.max_bytes, 4194304);
});

// ── 2. De routes, tegen een echte admin ──────────────────────────────────────

const PGP = 'pgp_' + crypto.randomBytes(32).toString('hex');
const KID = 'k_' + crypto.randomBytes(6).toString('hex');
const TAG = crypto.randomBytes(4).toString('hex');
const DOCS = [`PS-T${TAG}-1`, `CN-T${TAG}-1`];
let rc = null; let srv = null; let SID = null;

before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); } catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": ${e.message}`);
  }
  rc = c;
  const future = new Date(Date.now() + 200 * 86400000).toISOString();
  const acct = { key: PGP, kid: KID, account_id: PGP, email: `jan-${TAG}@bakkerij.test`, label: 'jansen', plan: 'pro', active: true, created: new Date().toISOString(), plan_parasign: 'business', plan_parasend: 'community', paid_until_parasign: future };
  const relay = await stubRelay(defaultRelayState([acct]));
  srv = await boot({ redisUrl: url, relay, env: { RELAY_MAIN: relay.base, RELAY_LEGAL: relay.base, RELAY_FINANCE: relay.base, RELAY_IOT: relay.base } });
  SID = crypto.randomBytes(16).toString('hex');
  await rc.set(`paramant:admin:session:${SID}`, '1', { EX: 600 });
  // Een auditregel met de volle sleutel als user_id en in de details, zoals
  // server.js ze echt schrijft.
  const ev = { user_id: PGP, event_type: 'admin_plan_changed', metadata: { from: 'community', to: 'pro', note: PGP }, ts: Date.now() };
  await rc.zAdd(`paramant:user:audit:${PGP}`, { score: ev.ts, value: JSON.stringify(ev) });
  const today = new Date().toISOString();
  const inv = { number: DOCS[0], kind: 'invoice', issued_at: today, invoice_date: today.slice(0, 10), account_id: PGP, product: 'parasign', interval: 'year', service_period_end: future, amount_net: '120.00', amount_vat: '25.20', amount_gross: '145.20', currency: 'EUR', buyer: { email: acct.email, company: '' } };
  const cn = { number: DOCS[1], kind: 'credit_note', issued_at: today, invoice_date: today.slice(0, 10), account_id: PGP, credit_for: 'PS-elders', amount_net: '-5.00', amount_vat: '-1.05', amount_gross: '-6.05', currency: 'EUR', buyer: { email: acct.email } };
  await rc.set(`paramant:billing:invoice:doc:${DOCS[0]}`, JSON.stringify(inv));
  await rc.set(`paramant:billing:invoice:doc:${DOCS[1]}`, JSON.stringify(cn));
  await rc.rPush('paramant:billing:invoice:list:all', DOCS);
  await rc.rPush(`paramant:billing:invoice:list:${PGP}`, DOCS);
});
after(async () => {
  await killAll();
  if (rc) {
    try {
      await rc.del([`paramant:user:audit:${PGP}`, `paramant:billing:invoice:list:${PGP}`, ...DOCS.map((d) => `paramant:billing:invoice:doc:${d}`)]);
      for (const d of DOCS) await rc.lRem('paramant:billing:invoice:list:all', 0, d);
      await rc.disconnect();
    } catch (_) { /* gone */ }
  }
});

async function get(p) {
  const r = await fetch(`${srv.base}/api${p}`, { headers: { 'X-Session': SID } });
  const text = await r.text();
  return { status: r.status, text, json: JSON.parse(text) };
}

test('geen enkele route van het paneel geeft een volle sleutel terug', async () => {
  if (!srv) return;
  for (const p of ['/admin/overview', '/admin/users', '/admin/audit?limit=500', '/admin/billing', `/admin/user-details/${KID}`, `/admin/user-detail/${PGP}`, '/admin/relay-detail', '/admin/overview/failures']) {
    const r = await get(p);
    assert.strictEqual(r.status, 200, p + ' ' + r.text.slice(0, 200));
    assert.doesNotMatch(r.text, FULL_KEY_RE, p + ' lekt een volle sleutel');
  }
});

test('de audit zegt wie (e-mail), wat (in woorden) en kent alleen echte gebeurtenissen', async () => {
  if (!srv) return;
  const r = await get(`/admin/audit?q=${encodeURIComponent(`jan-${TAG}`)}`);
  const row = r.json.events.find((e) => e.event_type === 'admin_plan_changed');
  assert.ok(row, JSON.stringify(r.json).slice(0, 300));
  assert.strictEqual(row.who, `jan-${TAG}@bakkerij.test`);
  assert.strictEqual(row.kid, KID);
  assert.strictEqual(row.label, 'Plan gewijzigd door jou');
  assert.strictEqual(row.summary, 'van community naar pro');
  assert.ok(r.json.event_types.includes('admin_plan_changed'));
  assert.strictEqual(r.json.event_labels.admin_plan_changed, 'Plan gewijzigd door jou');
  const none = await get('/admin/audit?q=bestaat-niet-' + TAG);
  assert.strictEqual(none.json.events.length, 0);
});

test('overzicht en betalingen rekenen omzet en MRR uit de documenten', async () => {
  if (!srv) return;
  const ov = (await get('/admin/overview')).json;
  assert.strictEqual(typeof ov.stats.revenue_mrr, 'number');
  assert.ok(ov.stats.revenue_mrr >= 1000, 'jaar van 120 euro is minstens 10 euro per maand: ' + ov.stats.revenue_mrr);
  assert.ok(Array.isArray(ov.relays) && ov.relays.length === 5);
  assert.ok(Array.isArray(ov.problems) && ov.problems.length >= 5);
  assert.ok(ov.recent_signups.some((u) => u.kid === KID));
  const b = (await get('/admin/billing')).json;
  const p = b.payments.find((x) => x.number === DOCS[0]);
  assert.ok(p, 'de factuur staat bij de betalingen');
  assert.strictEqual(p.kid, KID);
  assert.match(p.status_nl, /loopt tot/);
  assert.ok(b.refunds.some((x) => x.number === DOCS[1]));
  assert.ok(b.terms.some((t) => t.kid === KID && t.running));
});

test('de infopagina van een klant heeft plannen, sleutels gemaskeerd, betalingen en audit', async () => {
  if (!srv) return;
  const d = (await get(`/admin/user-details/${KID}`)).json;
  assert.strictEqual(d.key_id, KID, 'het handvat is de kid, niet de sleutel');
  assert.ok(d.paid_until_parasign);
  assert.ok(d.keys.length >= 1 && d.keys.every((k) => /\.\.\./.test(k.key_masked)));
  assert.ok(d.payments.some((x) => x.number === DOCS[0]));
  assert.ok(d.audit.some((a) => a.label === 'Plan gewijzigd door jou'));
});

test('de tellers per uur tellen en lezen terug', async () => {
  if (!rc) return;
  const kind = 'test_' + TAG;
  const now = Date.now();
  await beheer.countHit(rc, kind, now);
  await beheer.countHit(rc, kind, now);
  const r = await beheer.read24h(rc, kind, now);
  assert.strictEqual(r.total, 2);
  assert.strictEqual(r.peak.count, 2);
  await rc.del(beheer.hourKey(kind, now));
});
