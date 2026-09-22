'use strict';

// De randen, tegen een echt draaiende relay.
//
// De reis werkt (groep-e2e). Dit is de andere helft van de vraag: wat gebeurt
// er als iemand eroverheen gaat. Een grens die alleen in een tabel staat is
// geen grens; hij moet op de route vuren, met een getal dat klopt.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const FIRM = 'pgp_grens_firm';
const GRATIS = 'pgp_grens_gratis';
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

function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; }
function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

// Verzegelt een klein bestand en geeft { hashes, sealedVoor(adressen) }.
async function klaarzetten(sleutel, adressen, bytes) {
  const inhoud = crypto.randomBytes(bytes || 2048);
  const naamBytes = Buffer.from('doc.pdf', 'utf8');
  const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, inhoud]);
  const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  const LINK_MAX = 5 * 1024 * 1024;
  const hashes = [];
  for (let at = 0; at < ct.length; at += LINK_MAX) {
    const deel = ct.subarray(at, Math.min(at + LINK_MAX, ct.length));
    const hash = sha256hex(deel);
    const r = await fetch(BASE + '/v2/inbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
      body: JSON.stringify({ hash, payload: deel.toString('base64'),
                             meta: { device_id: 'transfer-web-link' } }),
    });
    if (r.status !== 200) {
      const j = await r.json().catch(() => ({}));
      return { uploadFout: { status: r.status, body: j } };
    }
    hashes.push(hash);
  }
  const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));
  const sealed = {};
  for (const a of adressen) {
    const t = wrap.newToken();
    sealed[a] = { token: t, wrapped_key: await wrap.wrap(t, geheim) };
  }
  return { hashes, sealed };
}

async function verstuur(sleutel, adressen, extra) {
  const k = await klaarzetten(sleutel, adressen, extra && extra.bytes);
  if (k.uploadFout) return { fase: 'upload', ...k.uploadFout };
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
    body: JSON.stringify({ hashes: k.hashes, recipients: adressen, sealed: k.sealed,
                           filename: 'doc.pdf', ttl_ms: 3600_000 }),
  });
  const j = await r.json().catch(() => ({}));
  return { fase: 'send', status: r.status, body: j };
}

const adres = (n, tag) => Array.from({ length: n }, (_, i) => `p${i}-${tag}@extern.test`);

before(async () => {
  usersFile = path.join(os.tmpdir(), `grenzen-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: FIRM, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Firm', email: 'firm@test', account_id: 'acct_firm' },
      { key: GRATIS, active: true, plan: 'community', plan_parasend: 'community',
        label: 'Gratis', email: 'gratis@test', account_id: 'acct_gratis' },
    ] }),
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) {}
});

test('precies dertig gaat door, eenendertig niet', async () => {
  const goed = await verstuur(FIRM, adres(30, 'dertig'));
  assert.equal(goed.status, 201, 'dertig moet passen: ' + JSON.stringify(goed.body));
  assert.equal(goed.body.recipients, 30);

  const over = await verstuur(FIRM, adres(31, 'eenendertig'));
  assert.equal(over.status, 403, 'eenendertig hoort geweigerd: ' + JSON.stringify(over.body));
  assert.equal(over.body.error, 'over_limit');
  assert.equal(over.body.limit, 30);
  assert.equal(over.body.asked, 31,
    'en het getal moet kloppen met wat zij opgaf, niet met limit+1');
});

test('het gratis plan krijgt er een, en hoort het echte aantal terug', async () => {
  const r = await verstuur(GRATIS, adres(20, 'gratis'));
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'over_limit');
  assert.equal(r.body.limit, 1);
  assert.equal(r.body.asked, 20,
    'de pagina zei ooit "u gaf er 2 op" tegen iemand die er twintig plakte');
});

test('de uurrem vuurt, en geeft de plaatsen terug bij een weigering', async () => {
  // Firm mag 500 mails per uur. Zestien volle verzendingen van dertig is 480;
  // de zeventiende gaat eroverheen. De twee hierboven telden al mee.
  let laatste = null;
  let geslaagd = 0;
  for (let i = 0; i < 20; i++) {
    const r = await verstuur(FIRM, adres(30, 'rem' + i));
    laatste = r;
    if (r.status === 201) { geslaagd += 1; continue; }
    break;
  }
  assert.equal(laatste.status, 429,
    'de rem vuurde niet, laatste antwoord: ' + laatste.status + ' ' + JSON.stringify(laatste.body));
  assert.equal(laatste.body.error, 'too_many_invitations');
  assert.equal(laatste.body.dimension, 'outbound_per_hour');
  assert.equal(laatste.body.limit, 500);
  assert.ok(laatste.body.retry_after_s > 0, 'en zeggen wanneer het weer mag');
  assert.ok(geslaagd >= 10 && geslaagd <= 16,
    'ergens rond de zestien volle verzendingen per uur, kreeg ' + geslaagd);
});

test('een bestand boven de verzendgrens wordt geweigerd', async () => {
  // SEND_MAX_MB is 25: wat de opslag dagenlang kan vasthouden zonder andermans
  // handtekening om te leggen. 26 MB hoort er netjes uit te vallen.
  const r = await verstuur(GRATIS, ['een@extern.test'], { bytes: 26 * 1024 * 1024 });
  if (r.fase === 'upload') {
    // Ook goed: dan sloeg de blokkenpoort al aan voor we bij /v2/sends waren.
    assert.ok([402, 413, 429].includes(r.status),
      'onverwachte uploadweigering: ' + r.status + ' ' + JSON.stringify(r.body));
    return;
  }
  assert.equal(r.status, 413, 'een te groot bestand hoort 413: ' + JSON.stringify(r.body));
  assert.equal(r.body.error, 'too_large');
  assert.equal(r.body.limit, 25);
});
