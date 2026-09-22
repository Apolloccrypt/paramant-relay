'use strict';

// WAT EEN ONTVANGER MEER KAN DAN ZIJN EIGEN BESTAND.
//
// Tegen een echt draaiende relay, met de echte browsercode uit
// frontend/js/send-wrap.js. Drie vragen:
//
//   1. Zijn token, andermans verpakking. En andersom.
//   2. Een verpakking uit een ANDERE verzending, onder hetzelfde token.
//   3. Wat kan iemand die een token in handen krijgt zonder de mailbox?
//
// De uitkomst van 2 is het interessantst en staat hieronder uitgeschreven: de
// wikkel is WEL overdraagbaar (geen AAD, send-wrap.js:78), en wat dat tegenhoudt
// is geen cryptografie maar een uniekheidscontrole in de opslag
// (lib/send.js:287-299). Dat is een ander soort garantie, en dat verschil telt.
//
// Draaien:
//   cd /home/mick/paramant-ontvangers/relay && node --test test/wikkel-ontvanger-aanval.test.js

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_wikkel_ontvanger_aanval';
let BASE = null;
let usersFile;
const post = [];

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

before(async () => {
  usersFile = path.join(os.tmpdir(), `wikkel-ontv-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
                   account_id: 'acct_wikkel_ontv' }],
    }),
  }, {
    onLine: (line) => {
      if (!line.includes('mail_dryrun')) return;
      try { post.push(JSON.parse(line)); } catch (_) { /* geen JSON-regel */ }
    },
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) { /* best effort */ }
});

// Een hele verzending over de draad, met echte wikkels. Geeft de tokens,
// de wikkels en de bestandssleutel terug, zodat een test kan kruisen.
async function verzend(adressen, inhoudTekst, tokensVooraf) {
  const naam = 'dossier.pdf';
  const nb = Buffer.from(naam, 'utf8');
  const plain = Buffer.concat([u32le(nb.length), nb, Buffer.from(inhoudTekst, 'utf8')]);
  const rawKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  const hash = sha256hex(ct);
  const r = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: ct.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(r.status, 200, 'blokupload faalde');

  const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));
  const sealed = {};
  const tokens = {};
  for (const adres of adressen) {
    const token = (tokensVooraf && tokensVooraf[adres]) || wrap.newToken();
    sealed[adres] = { token, wrapped_key: await wrap.wrap(token, geheim) };
    tokens[adres] = token;
  }
  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                           filename: naam, ttl_ms: 3600e3 }),
  });
  const vj = await vr.json().catch(() => ({}));
  return { status: vr.status, body: vj, tokens, sealed, rawKey, iv, geheim, ct, naam };
}

// ---------------------------------------------------------------------------
// 2. Zijn token, andermans verpakking
// ---------------------------------------------------------------------------

test('het token van de een opent de wikkel van de ander niet', async () => {
  const adressen = ['a@extern.test', 'b@extern.test'];
  const v = await verzend(adressen, 'de jaarrekening');
  assert.equal(v.status, 201, JSON.stringify(v.body));

  const tokenA = v.tokens['a@extern.test'];
  const tokenB = v.tokens['b@extern.test'];
  const wikkelA = v.sealed['a@extern.test'].wrapped_key;
  const wikkelB = v.sealed['b@extern.test'].wrapped_key;

  // Zijn token, andermans verpakking.
  await assert.rejects(() => wrap.unwrap(tokenA, wikkelB), 'A opende de wikkel van B');
  // Zijn verpakking, andermans token.
  await assert.rejects(() => wrap.unwrap(tokenB, wikkelA), 'B opende de wikkel van A');

  // Elk opent alleen de zijne, en dan komt DEZELFDE bestandssleutel eruit.
  // Dat is geen lek: binnen een verzending is er een blob en een sleutel, en
  // beiden mogen dat bestand hebben. Het is wel de reden dat wikkels omwisselen
  // binnen een verzending niets oplevert.
  const uitA = await wrap.unwrap(tokenA, wikkelA);
  const uitB = await wrap.unwrap(tokenB, wikkelB);
  assert.deepEqual(Buffer.from(uitA.rawKey), Buffer.from(uitB.rawKey));
  assert.deepEqual(Buffer.from(uitA.rawKey), v.rawKey);
});

// ---------------------------------------------------------------------------
// 3. Een verpakking uit een ANDERE verzending, onder hetzelfde token
// ---------------------------------------------------------------------------

test('een wikkel is overdraagbaar: alleen de opslag houdt dat tegen', async () => {
  const adressen = ['c@extern.test'];
  const een = await verzend(adressen, 'verzending EEN');
  assert.equal(een.status, 201, JSON.stringify(een.body));
  const token = een.tokens['c@extern.test'];

  // Poging over de draad: hetzelfde token nog eens gebruiken in een tweede
  // verzending. De relay weigert, want de tokenindex is een sleutelruimte over
  // alle accounts heen (lib/send.js:287-299).
  const twee = await verzend(['d@extern.test'], 'verzending TWEE',
                             { 'd@extern.test': token });
  assert.equal(twee.status, 400, 'de tweede verzending had geweigerd moeten worden');
  assert.equal(twee.body.error, 'token_taken');

  // MAAR: dat is een boekhoudkundige controle, geen cryptografische. De wikkel
  // zelf draagt geen send-id, geen ontvanger en geen afzender:
  // send-wrap.js:75-80 roept crypto.subtle.encrypt aan ZONDER additionalData.
  // Wie een wikkel op een andere plek kan neerleggen, krijgt hem geopend.
  const vreemdeWikkel = await wrap.wrap(token, twee.geheim);   // sleutel van EEN ANDER bestand
  const uit = await wrap.unwrap(token, vreemdeWikkel);
  assert.deepEqual(Buffer.from(uit.rawKey), twee.rawKey,
    'de wikkel van een andere verzending ging onder dit token gewoon open');

  // En het is niet te zien aan wat de ontvanger krijgt: de naam zit in de
  // versleutelde bytes, die de vervalser zelf koos.
  const d = crypto.createDecipheriv('aes-256-gcm',
    Buffer.from(uit.rawKey), Buffer.from(uit.iv));
  d.setAuthTag(twee.ct.subarray(twee.ct.length - 16));
  const plat = Buffer.concat([d.update(twee.ct.subarray(0, twee.ct.length - 16)), d.final()]);
  const nl = plat.readUInt32LE(0);
  assert.equal(plat.subarray(4 + nl).toString('utf8'), 'verzending TWEE');
});

// ---------------------------------------------------------------------------
// Wat een tokenhouder zonder de mailbox kan
// ---------------------------------------------------------------------------

test('een gestolen token haalt niets op, maar sluit de ontvanger wel buiten', async () => {
  const adressen = ['e@extern.test'];
  const v = await verzend(adressen, 'de jaarrekening');
  assert.equal(v.status, 201, JSON.stringify(v.body));
  const token = v.tokens['e@extern.test'];

  // De dief vraagt een code aan. Die komt in de mailbox van de ontvanger, niet
  // bij hem: relay.js:7095-7107 mailt naar vraag.email uit het record.
  post.length = 0;
  const r1 = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(r1.status, 200);
  await new Promise((r) => setTimeout(r, 200));
  const codeMail = post.find((p) => /code to open the file/i.test(p.subject || ''));
  assert.ok(codeMail, 'geen codemail');
  assert.equal((codeMail.to || [])[0], 'e@extern.test',
    'de code ging naar de dief in plaats van naar de ontvanger');

  // Zonder die code komt hij nergens.
  const mis = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: '000000' }),
  });
  assert.equal(mis.status, 401);

  // Maar het plafond is per LINK, niet per beller: lib/send.js:95-96,
  // MAX_CODE_REQUESTS = 5 en MAX_WRONG_TOTAL = 9, en niets daarvan reset.
  // Vier keer nog vragen en de link is dood, met vier extra mails naar een
  // postvak dat niets vroeg.
  let laatste = null;
  for (let i = 0; i < 6; i++) {
    laatste = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'code' }),
    });
    if (laatste.status !== 200) break;
  }
  const lj = await laatste.json().catch(() => ({}));
  assert.equal(laatste.status, 429, 'de link was niet dicht te krijgen: ' + JSON.stringify(lj));
  assert.equal(lj.error, 'too_many_codes');

  // En de echte ontvanger komt er nu ook niet meer in. Een herinnering maakt
  // geen nieuw token (lib/recipients.js:307-323), dus de enige uitweg is de
  // hele verzending opnieuw.
  const echt = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(echt.status, 429, 'de rechtmatige ontvanger kon nog wel ophalen');
});
