'use strict';
// AANVAL OP DE MAANDTELLER. Met een echte Redis, want zonder Redis faalt
// quota.gateTransfer open (lib/quota.js:220) en handhaaft de relay niets.
//
// Draaien:
//   REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/geld-gaten-quota.test.js

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');
const quota = require('../lib/quota');
const { requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(5).toString('hex');
const GRATIS = 'pgq_gratis_' + RUN;
const FIRM = 'pgq_firm_' + RUN;
const A_GRATIS = 'acct_q_gratis_' + RUN;
const A_FIRM = 'acct_q_firm_' + RUN;

let BASE = null, rc = null, usersFile = null;
const opgeruimd = [];

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

// Precies wat frontend/js/parashare.page.js:1221 doet (device_id
// 'transfer-web-link', GEEN file_id), tenzij de test een meta meegeeft.
async function upload(sleutel, bytes, extraMeta) {
  const inhoud = crypto.randomBytes(bytes || 2048);
  const naamBytes = Buffer.from('doc.pdf', 'utf8');
  const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, inhoud]);
  const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const LINK_MAX = 5 * 1024 * 1024;
  const hashes = [];
  const antwoorden = [];
  for (let at = 0; at < ct.length; at += LINK_MAX) {
    const deel = ct.subarray(at, Math.min(at + LINK_MAX, ct.length));
    const hash = sha256hex(deel);
    const r = await fetch(BASE + '/v2/inbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
      body: JSON.stringify({ hash, payload: deel.toString('base64'),
                             meta: { device_id: 'transfer-web-link', ...(extraMeta || {}) } }),
    });
    const j = await r.json().catch(() => ({}));
    antwoorden.push({ status: r.status, body: j });
    if (r.status !== 200) return { uploadFout: { status: r.status, body: j }, antwoorden, blokken: antwoorden.length };
    hashes.push(hash);
  }
  return { hashes, antwoorden, blokken: antwoorden.length,
           geheim: new Uint8Array(Buffer.concat([rawKey, iv])) };
}

async function verzegel(geheim, adressen) {
  const sealed = {};
  for (const a of adressen) {
    const t = wrap.newToken();
    sealed[a] = { token: t, wrapped_key: await wrap.wrap(t, new Uint8Array(geheim)) };
  }
  return sealed;
}

async function sends(sleutel, hashes, adressen, sealed) {
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
    body: JSON.stringify({ hashes, recipients: adressen, sealed,
                           filename: 'doc.pdf', ttl_ms: 3600_000 }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

const adres = (n, tag) => Array.from({ length: n }, (_, i) => `p${i}-${tag}@extern.test`);

async function teller(acct) {
  const v = await rc.get(quota.transfersKey(acct));
  return v == null ? 0 : parseInt(v, 10);
}
async function zetTeller(acct, n) {
  const k = quota.transfersKey(acct);
  opgeruimd.push(k);
  await rc.set(k, String(n), { EX: 3600 });
}

// Wat deze suite heeft getoetst, geteld in plaats van geraden. summary() kreeg
// hier een hardgecodeerde nul, en dat is precies de toestand waar die functie
// tegen bedacht is: vier tests die slagen en een slotregel die "SKIPPED - 0
// checks ran" zegt. De CI-poort in de crypto-baan las die regel, terecht, als
// een suite die niets toetste.
let gedaan = 0;
const geteld = (naam, fn) => test(naam, async (t) => { await fn(t); gedaan += 1; });

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  usersFile = path.join(os.tmpdir(), `geldgaten-q-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
    REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: GRATIS, active: true, plan: 'community', plan_parasend: 'community',
        label: 'Gratis', email: 'gratis@test', account_id: A_GRATIS },
      { key: FIRM, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Firm', email: 'firm@test', account_id: A_FIRM },
    ] }),
  });
  BASE = relay.base;
});

after(async () => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) {}
  if (rc) {
    for (const k of opgeruimd) { try { await rc.del(k); } catch (_) {} }
    for (const a of [A_GRATIS, A_FIRM]) {
      try { await rc.del(quota.transfersKey(a)); } catch (_) {}
      try { for (const k of await rc.keys(`paramant:quota:seen:${a}:*`)) await rc.del(k); } catch (_) {}
    }
    try { await rc.disconnect(); } catch (_) {}
  }
  summary('geld-gaten-quota', gedaan);
});

// ── GAT 4. De grens van transfers_month ─────────────────────────────────────

geteld('gat 4a: de laatste transfer is OP voordat de verzending bestaat', async () => {
  if (!rc) return;
  // De teller loopt op /v2/inbound (relay.js:6937), NIET op /v2/sends. En er is
  // geen releaseTransfer: lib/quota.js kent alleen releaseSign (regel 268).
  // Dus wie zijn vijftigste transfer uploadt en daarna op de ontvangergrens
  // stuit, is die transfer kwijt zonder dat er ooit iets verstuurd is.
  await zetTeller(A_GRATIS, 49);

  const u = await upload(GRATIS);
  assert.equal(u.antwoorden[0].status, 200, 'de vijftigste mag nog');
  assert.equal(await teller(A_GRATIS), 50, 'en is geteld');

  // Nu de verzending: twee ontvangers op community (max_recipients 1).
  const sealed = await verzegel(u.geheim, adres(2, 'op'));
  const s = await sends(GRATIS, u.hashes, adres(2, 'op'), sealed);
  assert.equal(s.status, 403, JSON.stringify(s.body));
  assert.equal(s.body.error, 'over_limit');

  assert.equal(await teller(A_GRATIS), 50,
    'de transfer wordt NIET teruggegeven: geen verzending, wel betaald');

  // En de volgende upload is meteen dicht.
  const u2 = await upload(GRATIS);
  assert.equal(u2.uploadFout.status, 402, JSON.stringify(u2.uploadFout.body));
  assert.equal(u2.uploadFout.body.error, 'monthly_transfer_quota_reached');
  assert.equal(u2.uploadFout.body.dimension, 'transfers_month');
  assert.equal(u2.uploadFout.body.limit, 50, 'community: 50, lib/tiers.js:67');
  assert.equal(u2.uploadFout.body.plan, 'community');
});

// ── GAT 6. Wat een transfer werkelijk is ────────────────────────────────────

geteld('gat 6a: een vaste meta.file_id zet de maandteller stil', async () => {
  if (!rc) return;
  // relay.js:6930 maakt de dedup-sleutel uit meta.file_id, en die komt UIT DE
  // CLIENT: frontend/js/parashare.page.js:824 maakt er acht willekeurige bytes
  // van, maar niets dwingt dat af. Wie steeds dezelfde string stuurt, valt
  // 24 uur lang in de dedup-tak van GATE_TRANSFER_LUA (lib/quota.js:177) en
  // betaalt een transfer voor een onbeperkt aantal uploads.
  await zetTeller(A_FIRM, 0);
  const vast = { file_id: 'altijd-dezelfde-' + RUN };
  opgeruimd.push(quota.seenKey(A_FIRM,
    crypto.createHash('sha3-256').update(vast.file_id).digest('hex')));

  for (let i = 0; i < 8; i++) {
    const u = await upload(FIRM, 4096, vast);
    assert.ok(!u.uploadFout, 'upload ' + i + ' hoort door te gaan: '
      + JSON.stringify(u.uploadFout && u.uploadFout.body));
  }
  assert.equal(await teller(A_FIRM), 1,
    'acht losse bestanden, een transfer geteld');
});

geteld('gat 6b: zonder file_id kost EEN bestand een transfer PER BLOK', async () => {
  if (!rc) return;
  // De verzendpagina (frontend/js/parashare.page.js:1221) stuurt GEEN file_id,
  // dus de dedup-sleutel valt terug op quota.firstChunkHash(blob) -- per blok
  // een andere. Blokken zijn 5 MiB, dus een bestand van 12 MB is drie
  // transfers. Op 500 MB (tiers.js file_mb) is dat ruim honderd, en dan is
  // "500 transfers a month" (frontend/pricing.html:373) in de praktijk
  // ongeveer vier bestanden.
  await zetTeller(A_FIRM, 0);
  const u = await upload(FIRM, 12 * 1024 * 1024);
  assert.ok(!u.uploadFout, JSON.stringify(u.uploadFout && u.uploadFout.body));
  assert.equal(u.blokken, 3, 'twaalf MB is drie blokken van 5 MiB');
  assert.equal(await teller(A_FIRM), 3,
    'en dus drie transfers voor een bestand');
  for (const h of u.hashes) void h;
});

// ── GAT X. Twee verzendingen uit een upload (GEEN gat gevonden) ─────────────

geteld('gat X (dicht): dezelfde blokken tegelijk twee keer versturen', async () => {
  if (!rc) return;
  // relay.js:4652 laat `blobDrop` pas los NA `await _sendStore().create(...)`.
  // Met Redis is die create echte IO, dus het venster tussen de
  // eigendomscontrole (relay.js:4583) en het opruimen staat open.
  await zetTeller(A_FIRM, 0);
  const u = await upload(FIRM);
  const a = await verzegel(u.geheim, adres(3, 'dupa'));
  const b = await verzegel(u.geheim, adres(3, 'dupb'));
  const [r1, r2] = await Promise.all([
    sends(FIRM, u.hashes, adres(3, 'dupa'), a),
    sends(FIRM, u.hashes, adres(3, 'dupb'), b),
  ]);
  const gelukt = [r1, r2].filter(r => r.status === 201);
  const na = await teller(A_FIRM);
  console.log('  gat X: uitkomsten', JSON.stringify([r1.status, r2.status]),
              'verzendingen', gelukt.length, 'transfers geteld', na);
  assert.equal(na, 1, 'hoe dan ook: een upload, een transfer');
  assert.ok(gelukt.length >= 1);
  if (gelukt.length === 2) {
    assert.notEqual(gelukt[0].body.send_id, gelukt[1].body.send_id,
      'twee losse verzendingen, zes ontvangers, op de prijs van een transfer');
  }
});
