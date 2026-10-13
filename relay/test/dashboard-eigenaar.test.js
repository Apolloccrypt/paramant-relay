'use strict';

// HET DASHBOARD VAN EEN ECHTE KLANT.
//
// Dit was het duurste gat van de hele ronde, en geen enkele audit had het
// gevonden: de twee kanten noemden het account anders.
//
//   admin/server.js zet `user_id: user.key` in de sessie  -> de API-sleutel
//   relay.js filet de verzending onder acctOf(apiKey)     -> het account_id
//
// Elk account dat via de admin is aangemaakt heeft een account_id. Voor die
// accounts -- dus voor elke betalende klant -- vroeg het dashboard naar
// verzendingen van `pgp_...` terwijl alles onder `acct_...` stond. Lege lijst,
// niets te openen, niemand in te trekken. Precies de track-and-trace waar het
// product op verkocht wordt.
//
// Het werkte alleen voor accounts ZONDER account_id, en die heeft geen klant.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const SLEUTEL = 'pgp_dash_klant';
const ACCOUNT = 'acct_dash_klant';
const INTERN = 'i'.repeat(40);
let BASE = null;
let usersFile;

const wrapSrc = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

before(async () => {
  usersFile = path.join(os.tmpdir(), `dash-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: SLEUTEL, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Zorggroep', email: 'anna@zorg.test', account_id: ACCOUNT },
    ] }),
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) {}
});

async function maakVerzending(adressen) {
  const inhoud = crypto.randomBytes(4096);
  const nb = Buffer.from('dossier.pdf', 'utf8');
  const kop = Buffer.alloc(4); kop.writeUInt32LE(nb.length, 0);
  const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(Buffer.concat([kop, nb, inhoud])), c.final(), c.getAuthTag()]);
  const hash = crypto.createHash('sha256').update(ct).digest('hex');
  await fetch(BASE + '/v2/inbound', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': SLEUTEL },
    body: JSON.stringify({ hash, payload: ct.toString('base64'), meta: { device_id: 'transfer-web-link' } }) });
  const sealed = {};
  for (const a of adressen) {
    const t = wrap.newToken();
    sealed[a] = { token: t, wrapped_key: await wrap.wrap(t, new Uint8Array(Buffer.concat([rawKey, iv]))) };
  }
  const r = await fetch(BASE + '/v2/sends', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': SLEUTEL },
    body: JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                           filename: 'dossier.pdf', ttl_ms: 3600000 }) });
  return { status: r.status, body: await r.json().catch(() => ({})), sealed };
}

const intern = (pad, body) => fetch(BASE + pad, { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
  body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

test('de klant ziet zijn eigen verzending, met de sleutel die de sessie draagt', async () => {
  const gemaakt = await maakVerzending(['partner1@extern.test', 'partner2@extern.test']);
  assert.equal(gemaakt.status, 201, JSON.stringify(gemaakt.body));

  // DIT is wat het dashboard stuurt: admin/server.js zet user.key in de sessie.
  const lijst = await intern('/v2/user/sends', { user_id: SLEUTEL });
  assert.equal(lijst.status, 200);
  assert.equal((lijst.body.sends || []).length, 1,
    'het dashboard van een echte klant was leeg: de admin stuurt de API-sleutel '
    + 'en de verzending staat onder het account_id');
  assert.equal(lijst.body.sends[0].id, gemaakt.body.send_id);
});

test('en kan hem openen en er iemand uit intrekken', async () => {
  const gemaakt = await maakVerzending(['a@extern.test', 'b@extern.test']);
  const id = gemaakt.body.send_id;

  const detail = await intern('/v2/user/sends/detail', { user_id: SLEUTEL, send_id: id });
  assert.equal(detail.status, 200, JSON.stringify(detail.body));
  assert.equal((detail.body.recipients || []).length, 2);

  const trek = await intern('/v2/user/sends/revoke',
    { user_id: SLEUTEL, send_id: id, email: 'a@extern.test' });
  assert.equal(trek.status, 200, 'intrekken moet werken: ' + JSON.stringify(trek.body));

  const na = await intern('/v2/user/sends/detail', { user_id: SLEUTEL, send_id: id });
  const a = (na.body.recipients || []).find((r) => r.email === 'a@extern.test');
  assert.equal(a.status, 'revoked', 'en daarna ook echt ingetrokken zijn');
});

test('het account_id werkt nog steeds, want dat stuurde het al', async () => {
  const lijst = await intern('/v2/user/sends', { user_id: ACCOUNT });
  assert.equal(lijst.status, 200);
  assert.ok((lijst.body.sends || []).length >= 1,
    'de vertaling mag de kant die het al deed niet breken');
});

test('een vreemde sleutel komt nergens', async () => {
  for (const wie of ['pgp_iemand_anders', 'acct_iemand_anders', '', 'null']) {
    const r = await intern('/v2/user/sends', { user_id: wie });
    const n = (r.body.sends || []).length;
    assert.equal(n, 0, 'user_id "' + wie + '" kreeg ' + n + ' verzendingen te zien');
  }
});
