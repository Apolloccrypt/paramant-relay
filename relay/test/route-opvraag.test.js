'use strict';

// STUKKEN OPVRAGEN, DE ROUTES VAN EEN ECHTE RELAY.
//
// Twee kanten met elk hun eigen deur. De klant heeft alleen de link: hij leest
// het verzoek en zet versleutelde bestanden erbij, verder niets. Het kantoor
// komt via de admin (X-Internal-Auth plus de user_id van zijn sessie) en is de
// enige die de lijst, de details en de bestanden ziet.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const SLEUTEL = 'pgp_opvraag_kantoor';
const ANDER = 'pgp_opvraag_ander';
const GRATIS = 'pgp_opvraag_gratis';
const INTERN = 'o'.repeat(40);
let BASE;
let usersFile;
const mails = [];

before(async () => {
  usersFile = path.join(os.tmpdir(), `opvraag-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun', INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: SLEUTEL, active: true, plan: 'pro', plan_parasend: 'pro', label: 'Acme Administratie',
        email: 'kantoor@example.com', account_id: 'acct_demo' },
      { key: ANDER, active: true, plan: 'pro', plan_parasend: 'pro', label: 'Andere Firma',
        email: 'ander@example.com', account_id: 'acct_ander' },
      { key: GRATIS, active: true, plan: 'community', label: 'Klein Kantoor',
        email: 'klein@example.com', account_id: 'acct_klein' },
    ] }),
  }, { onLine: (r) => { if (r.includes('mail_dryrun')) { try { mails.push(JSON.parse(r)); } catch (_) { /* geen json */ } } } });
  BASE = relay.base;
});
after(() => { killSpawnedRelays(); try { fs.unlinkSync(usersFile); } catch (_) {} });

const b64u = (n) => crypto.randomBytes(n).toString('base64url');
function ecdhPub() { const b = crypto.randomBytes(65); b[0] = 4; return b.toString('base64url'); }
function pakket(n) { const b = crypto.randomBytes(n); b[0] = 3; return b; }

function intern(op, body, headers = { 'X-Internal-Auth': INTERN }) {
  return fetch(`${BASE}/v2/user/opvraag/${op}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
}

async function maak(userId = SLEUTEL, extra = {}) {
  const info = await (await intern('info', { user_id: userId })).json();
  const d = { v: 1, id: b64u(18), office: info.office, greet: 'Demo', items: ['Kopie paspoort', 'Loonstrook'],
              expires_at: Date.now() + 3 * 86400_000, kem_pub: b64u(1184), ecdh_pub: ecdhPub() };
  const r = await intern('create', { user_id: userId, descriptor: d, client_name: 'Demo Klant',
    client_email: 'demo@example.com', lang: 'nl', sk_wrapped: b64u(2600), kluis_id: b64u(16), ...extra });
  return { r, d, info };
}

test('info: de naam van het kantoor, de grenzen van het plan', async () => {
  const i = await (await intern('info', { user_id: SLEUTEL })).json();
  assert.equal(i.office, 'Acme Administratie');
  assert.equal(i.limits.open, 25);
  assert.equal(i.limits.file_max_bytes, 5 * 1048576);
  const g = await (await intern('info', { user_id: GRATIS })).json();
  assert.equal(g.limits.open, 1);
});

test('zonder X-Internal-Auth komt niemand bij de kantoorkant, ook niet met een API-sleutel', async () => {
  for (const op of ['info', 'list', 'detail', 'file', 'create', 'close', 'delete', 'remind', 'kluis']) {
    const r = await intern(op, { user_id: SLEUTEL }, { 'X-Api-Key': SLEUTEL });
    assert.equal(r.status, 401, op);
  }
  assert.equal((await intern('list', { user_id: 'pgp_bestaat_niet' })).status, 401);
});

test('de hele reis over de draad: maken, lezen, uploaden, downloaden, sluiten', async () => {
  const { r, d } = await maak();
  assert.equal(r.status, 201, await r.clone().text());

  const pub = await fetch(`${BASE}/v2/opvraag/${d.id}`);
  assert.equal(pub.status, 200);
  const v = await pub.json();
  assert.deepEqual(v.descriptor, d);
  assert.ok(!JSON.stringify(v).includes('demo@example.com'));

  const p = pakket(9000);
  const up = await fetch(`${BASE}/v2/opvraag/${d.id}/stuk/1`, { method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' }, body: p });
  assert.equal(up.status, 201);
  const kaal = await fetch(`${BASE}/v2/opvraag/${d.id}/stuk/0`, { method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.from('%PDF-1.7 een bestand in het klaar'.padEnd(2000, ' ')) });
  assert.equal(kaal.status, 400, 'onversleuteld wordt geweigerd');
  const groot = await fetch(`${BASE}/v2/opvraag/${d.id}/stuk/0`, { method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' }, body: pakket(5 * 1048576 + 10) });
  assert.equal(groot.status, 413);

  // Het andere kantoor ziet niets, en hoort hetzelfde als bij een onbekend id.
  assert.equal((await intern('detail', { user_id: ANDER, id: d.id })).status, 404);
  assert.equal((await intern('file', { user_id: ANDER, id: d.id, n: 0 })).status, 404);
  assert.equal((await (await intern('list', { user_id: ANDER })).json()).requests.length, 0);

  const lijst = await (await intern('list', { user_id: SLEUTEL })).json();
  const rij = lijst.requests.find((x) => x.id === d.id);
  assert.deepEqual(rij.items.map((x) => x.count), [0, 1]);
  assert.equal(rij.client_name, 'Demo Klant');

  const f = await intern('file', { user_id: SLEUTEL, id: d.id, n: 0 });
  assert.equal(f.status, 200);
  assert.ok(Buffer.from(await f.arrayBuffer()).equals(p));

  assert.equal((await intern('close', { user_id: SLEUTEL, id: d.id })).status, 200);
  const dicht = await fetch(`${BASE}/v2/opvraag/${d.id}`);
  assert.equal(dicht.status, 410);
  assert.equal((await dicht.json()).office, 'Acme Administratie');
  const laat = await fetch(`${BASE}/v2/opvraag/${d.id}/stuk/0`, { method: 'POST', body: pakket(3000) });
  assert.equal(laat.status, 410);
});

test('een onbekend of verkeerd gevormd id: altijd hetzelfde antwoord', async () => {
  assert.equal((await fetch(`${BASE}/v2/opvraag/${b64u(18)}`)).status, 404);
  assert.equal((await fetch(`${BASE}/v2/opvraag/${b64u(18)}/stuk/0`, { method: 'POST', body: pakket(3000) })).status, 404);
  // Een te grote upload wordt aan de kop herkend, voor er iets gelezen is.
  const groot = await fetch(`${BASE}/v2/opvraag/${b64u(18)}/stuk/0`, { method: 'POST', body: pakket(5 * 1048576 + 1) });
  assert.equal(groot.status, 413);
});

test('de naam boven het verzoek is die van het account, niet wat de browser zegt', async () => {
  const info = await (await intern('info', { user_id: SLEUTEL })).json();
  const d = { v: 1, id: b64u(18), office: 'Een Bekende Bank', greet: '', items: ['Loonstrook'],
              expires_at: Date.now() + 86400_000, kem_pub: b64u(1184), ecdh_pub: ecdhPub() };
  const r = await intern('create', { user_id: SLEUTEL, descriptor: d, client_name: 'X', client_email: '',
    sk_wrapped: b64u(2600), kluis_id: b64u(16) });
  assert.equal(r.status, 409);
  assert.equal((await r.json()).error, 'office_changed');
  assert.notEqual(info.office, d.office);
});

test('Community: een open verzoek tegelijk', async () => {
  const a = await maak(GRATIS);
  assert.equal(a.r.status, 201);
  const b = await maak(GRATIS);
  assert.equal(b.r.status, 403);
  assert.equal((await b.r.json()).error, 'too_many_open');
});

test('herinnering: gaat via de mailer, zonder link, en niet op het gratis plan', async () => {
  const { d } = await maak();
  const r = await intern('remind', { user_id: SLEUTEL, id: d.id });
  assert.equal(r.status, 200, await r.clone().text());
  const m = mails.find((x) => x.text && x.text.includes('Kopie paspoort, Loonstrook'));
  assert.ok(m, 'er ging een mail uit');
  assert.deepEqual(m.to, ['demo@example.com']);
  assert.ok(!/https?:\/\/|\/v\//.test(m.text), 'geen link: die kan alleen het kantoor zelf geven');
  assert.ok(m.text.includes('Gebruik de link die je eerder van Acme Administratie kreeg'));
  assert.match(m.subject, /Acme Administratie/);
  assert.ok(m.text.includes('Kopie paspoort, Loonstrook'), 'de mail noemt wat nog ontbreekt');
  assert.equal((await intern('remind', { user_id: SLEUTEL, id: d.id })).status, 429, 'niet twee keer binnen het uur');
  const zonder = await maak(SLEUTEL, { client_email: '' });
  assert.equal((await intern('remind', { user_id: SLEUTEL, id: zonder.d.id })).status, 409);
  const lijst = await (await intern('list', { user_id: GRATIS })).json();
  const gratisId = lijst.requests[0] && lijst.requests[0].id;
  assert.ok(gratisId, 'het gratis account heeft een verzoek uit de vorige test');
  const g = await intern('remind', { user_id: GRATIS, id: gratisId });
  assert.equal(g.status, 403);
  assert.equal((await g.json()).error, 'paid_only');
});

test('verwijderen: weg voor iedereen', async () => {
  const { d } = await maak();
  await fetch(`${BASE}/v2/opvraag/${d.id}/stuk/0`, { method: 'POST', body: pakket(3000) });
  assert.equal((await intern('delete', { user_id: ANDER, id: d.id })).status, 404);
  assert.equal((await intern('delete', { user_id: SLEUTEL, id: d.id })).status, 200);
  assert.equal((await fetch(`${BASE}/v2/opvraag/${d.id}`)).status, 404);
  assert.equal((await intern('file', { user_id: SLEUTEL, id: d.id, n: 0 })).status, 404);
});
