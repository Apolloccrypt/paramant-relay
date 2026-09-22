'use strict';
// AANVAL OP HET GELD. Alles wat een euro raakt, tegen een echt draaiende relay.
//
// groep-grenzen.test.js toetst dat de grenzen vuren. Dit bestand toetst of je
// eromheen kunt. Elke test is een aanval, met de bestandsregel die hem mogelijk
// maakt of tegenhoudt erboven.
//
// Draaien: node --test relay/test/geld-gaten.test.js

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const INTERN = 'intern-geheim-voor-deze-test';
let BASE = null;
let usersFile;
// Elke mail_dryrun-regel die de relay logt. Zo tellen we wat er ECHT de deur
// uit zou gaan, niet wat een antwoordveld beweert.
const mails = [];
function mailsSinds(n) { return mails.length - n; }
// Alleen post aan externe ontvangers: een Pro-account krijgt bij elke upload
// ook zelf een melding (relay.js transferNotify.maybeNotify), en die is geen
// uitnodiging.
function naarExtern(n) {
  return mails.slice(n).filter(m => String((m && m.to) || '').includes('extern.test')).length;
}

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

// Zet een bestand op de relay. Geeft { hashes, geheim } terug, zodat dezelfde
// blokken later voor MEER dan een verzending gebruikt kunnen worden.
async function upload(sleutel, bytes, extraMeta) {
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
                             meta: { device_id: 'transfer-web-link', ...(extraMeta || {}) } }),
    });
    if (r.status !== 200) {
      const j = await r.json().catch(() => ({}));
      return { uploadFout: { status: r.status, body: j } };
    }
    hashes.push(hash);
  }
  return { hashes, geheim: new Uint8Array(Buffer.concat([rawKey, iv])) };
}

// De `sealed`-map die de browser maakt: adres -> { token, wrapped_key }.
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

// Upload + verzegel + verstuur, het normale pad.
async function verstuur(sleutel, adressen, opt) {
  const u = await upload(sleutel, (opt && opt.bytes), (opt && opt.meta));
  if (u.uploadFout) return { fase: 'upload', ...u.uploadFout };
  const sealed = await verzegel(u.geheim, (opt && opt.sealedVoor) || adressen);
  return { fase: 'send', ...(await sends(sleutel, u.hashes, adressen, sealed)) };
}

const adres = (n, tag) => Array.from({ length: n }, (_, i) => `p${i}-${tag}@extern.test`);

// VIJF sleutels, niet meer: relay.js:3641 zet elke sleutel boven de vijfde op
// over_limit en antwoordt 402 op alles. De Community Edition-grens van de relay
// zelf, geen tier-grens.
const K = {
  gratis:  'pgp_gat_gratis',   // community
  reach:   'pgp_gat_reach',    // community, apart budget voor de bereiktest
  firm:    'pgp_gat_firm',     // pro
  biz:     'pgp_gat_biz',      // plan business, plan_parasend leeg
  race:    'pgp_gat_race',     // plan free, plan_parasend pro (de webhook-koper)
};

before(async () => {
  usersFile = path.join(os.tmpdir(), `geldgaten-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: K.gratis, active: true, plan: 'community', plan_parasend: 'community',
        label: 'Gratis', email: 'gratis@test', account_id: 'acct_gratis' },
      { key: K.reach, active: true, plan: 'community', plan_parasend: 'community',
        label: 'Reach', email: 'reach@test', account_id: 'acct_reach' },
      { key: K.firm, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Firm', email: 'firm@test', account_id: 'acct_firm' },
      // NIET te koop voor ParaSend (entitlements.PARASEND_TIERS mist 'business'),
      // en plan_parasend is leeg. Wat krijgt deze?
      { key: K.biz, active: true, plan: 'business',
        label: 'Biz', email: 'biz@test', account_id: 'acct_biz' },
      // Betaald via de webhook: die schrijft ALLEEN plan_parasend.
      { key: K.race, active: true, plan: 'free', plan_parasend: 'pro',
        label: 'Race', email: 'race@test', account_id: 'acct_race' },
    ] }),
  }, {
    onLine(line) {
      if (line.includes('mail_dryrun')) {
        try { mails.push(JSON.parse(line)); } catch (_) { mails.push({ raw: line }); }
      }
    },
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) {}
});

// ── GAT 1. Bereikt een gratis account meer dan een ontvanger? ────────────────

test('gat 1a: plus-adressering en gmail-punten tellen als APARTE ontvangers', async () => {
  // lib/tiers.js normaliseAddress doet NFC + trim + lowercase, meer niet: geen
  // plus-strip, geen punt-strip. Dus anna@ en anna+1@ zijn twee ontvangers en
  // een community-account (max_recipients 1, lib/tiers.js:73) wordt geweigerd.
  const plus = await verstuur(K.gratis, ['anna@gmail.test', 'anna+factuur@gmail.test']);
  assert.equal(plus.status, 403, JSON.stringify(plus.body));
  assert.equal(plus.body.error, 'over_limit');
  assert.equal(plus.body.limit, 1);

  const punt = await verstuur(K.gratis, ['anna@gmail.test', 'a.nna@gmail.test']);
  assert.equal(punt.status, 403);
  assert.equal(punt.body.limit, 1);

  // Hoofdletters WEL: die vouwen samen, dus dit is er een en gaat door.
  const hoofd = await verstuur(K.gratis, ['Bea@Extern.Test', 'bea@extern.test']);
  assert.equal(hoofd.status, 201, JSON.stringify(hoofd.body));
  assert.equal(hoofd.body.recipients, 1);
});

test('gat 1b: een gepadde `sealed` levert GEEN extra mail op', async () => {
  // relay.js:4607 telt de zitplaatsen uit `sealed`, maar lib/recipients.js:146
  // loopt over `checked.recipients` (uit input.recipients). Dus dertig sealed
  // entries bij een ontvanger kost je dertig zitplaatsen en levert een mail.
  const voor = mails.length;
  const r = await verstuur(K.gratis, ['carla@extern.test'],
    { sealedVoor: ['carla@extern.test', ...adres(29, 'pad')] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.recipients, 1, 'sealed mag het aantal niet opblazen');
  assert.equal(naarExtern(voor), 1, 'en er mag er precies een de deur uit');
});

test('gat 1c: DE ECHTE: een gratis account bereikt 50 mensen per uur', async () => {
  // Er is GEEN grens op het aantal verzendingen per uur, alleen op ontvangers
  // per verzending (max_recipients 1) en op uitnodigingen per uur
  // (outbound_per_hour 50, lib/tiers.js:79). Dus vijftig losse verzendingen
  // van een persoon = vijftig bereikte mensen op het gratis plan, terwijl
  // frontend/pricing.html:469 zegt "one on Community".
  const voor = mails.length;
  let bereikt = 0;
  let laatste = null;
  for (let i = 0; i < 55; i++) {
    const r = await verstuur(K.reach, [`los${i}-reach@extern.test`]);
    laatste = r;
    if (r.status === 201) { bereikt += 1; continue; }
    break;
  }
  assert.equal(laatste.status, 429, 'pas de uurrem stopt dit: ' + JSON.stringify(laatste.body));
  assert.equal(laatste.body.limit, 50);
  assert.equal(bereikt, 50,
    'vijftig verschillende mensen op een plan dat er een belooft, kreeg ' + bereikt);
  assert.equal(naarExtern(voor), 50, 'en vijftig echte mails');
});

// ── GAT 2. Wat kost een verzending naar dertig mensen? ──────────────────────

test('gat 2: dertig ontvangers = EEN transfer, dertig uitnodigingen', async () => {
  const voor = mails.length;
  const r = await verstuur(K.firm, adres(30, 'kosten'));
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.recipients, 30);
  assert.equal(r.body.invited, 30);
  // De uitnodiging nu; de codemail volgt pas als iemand de link opent. De
  // "x2" uit de lib/tiers.js:100 kostenberekening is dus een bovengrens.
  assert.equal(naarExtern(voor), 30, 'dertig uitnodigingen bij het versturen');
});

// ── GAT 5. Plannen die niet te koop zijn ────────────────────────────────────

test('gat 5a: plan business, plan_parasend LEEG, krijgt toch dertig', async () => {
  // entitlements.js:37 PARASEND_TIERS = [community, pro, enterprise]: business
  // is NIET te koop. Maar entitlements.js:52 PARASEND_LADDER bevat hem wel en
  // derivePlanParasend('business') -> 'business' (entitlements.js:260), dus de
  // limieten komen uit de business-rij van tiers.js: 30 ontvangers, 2000 mails
  // per uur, 2000 transfers. Een tier die niemand kan kopen maar iedereen krijgt
  // zodra `plan` op business staat.
  const r = await verstuur(K.biz, adres(30, 'biz'));
  assert.equal(r.status, 201, 'business krijgt dertig zonder ooit ParaSend te kopen: '
    + JSON.stringify(r.body));
  assert.equal(r.body.recipients, 30);

  // 31 hoort nog steeds te stuiten: het plafond is 30, niet oneindig.
  const over = await verstuur(K.biz, adres(31, 'bizover'));
  assert.equal(over.status, 403);
  assert.equal(over.body.limit, 30);
});

test('gat 5b: betaalde plan_parasend pro met plan free KRIJGT zijn dertig', async () => {
  // Dit is de goede kant van parasendLimitsOf (relay.js:1806): de Mollie-webhook
  // schrijft alleen plan_parasend, en de route leest de productas.
  const r = await verstuur(K.race, adres(30, 'prosend'));
  assert.equal(r.status, 201, 'een betalende Firm-koper hoort dertig te krijgen: '
    + JSON.stringify(r.body));
  assert.equal(r.body.recipients, 30);
});

// ── GAT 3. Is de uurrem te omzeilen met gelijktijdigheid? ───────────────────

test('gat 3: twintig gelijktijdige verzendingen breken de uurrem NIET', async () => {
  // inviteRateOk (relay.js:2318) leest en schrijft de teller zonder await
  // ertussen, dus binnen een Node-proces is het atomair. Dit account gaf in
  // gat 5b hierboven al dertig zitplaatsen uit, dus er is 470 van de 500 over:
  // vijftien volle verzendingen passen (15 x 30 = 450, samen 480), de
  // zestiende zou op 510 komen en hoort 429 te krijgen.
  const u = [];
  for (let i = 0; i < 20; i++) u.push(await upload(K.race));
  const sealeds = [];
  for (let i = 0; i < 20; i++) sealeds.push(await verzegel(u[i].geheim, adres(30, 'race' + i)));
  const uit = await Promise.all(u.map((x, i) =>
    sends(K.race, x.hashes, adres(30, 'race' + i), sealeds[i])));
  const door = uit.filter(r => r.status === 201).length;
  const geweigerd = uit.filter(r => r.status === 429).length;
  assert.equal(door, 15, 'vijftien passen in de resterende 470, kreeg ' + door);
  assert.equal(geweigerd, 5);
  // De weigering vertelt eerlijk hoeveel er op staat, en dat is precies het
  // getal dat de gelukte verzendingen verklaren. Geen enkele lekte erdoor.
  const rem = uit.find(r => r.status === 429);
  assert.equal(rem.body.limit, 500);
  assert.equal(rem.body.used, 30 + door * 30);
  assert.ok(rem.body.used + 30 > 500);
});

// ── GAT 7. De heruitnodiging als gratis mailkanaal ──────────────────────────

test('gat 7: heruitnodigen kost GEEN zitplaats op de uurrem', async () => {
  // relay.js:4795 (reinvite op regel 4804) roept inviteRateOk NIET aan. MAX_REMINDERS is 3
  // (lib/send.js:52), per ONTVANGER, dus een verzending naar dertig mensen is
  // negentig extra mails buiten outbound_per_hour om.
  const ontvangers = adres(3, 'rem');
  const r = await verstuur(K.firm, ontvangers);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const sendId = r.body.send_id;

  const voor = mails.length;
  const antwoorden = [];
  for (const email of ontvangers) {
    for (let poging = 0; poging < 5; poging++) {
      const x = await fetch(BASE + '/v2/user/sends/reinvite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
        body: JSON.stringify({ user_id: 'acct_firm', send_id: sendId, email }),
      });
      antwoorden.push({ email, status: x.status, body: await x.json().catch(() => ({})) });
    }
  }
  const gelukt = antwoorden.filter(a => a.status === 200);
  const gestuit = antwoorden.filter(a => a.status === 429);
  assert.equal(gelukt.length, 9, 'drie herinneringen per ontvanger, dus negen');
  assert.equal(gestuit.length, 6);
  assert.equal(gestuit[0].body.error, 'reminder_limit');
  assert.equal(gestuit[0].body.limit, 3);
  assert.equal(naarExtern(voor), 9, 'negen mails, en geen ervan telde mee voor de uurrem');
});
