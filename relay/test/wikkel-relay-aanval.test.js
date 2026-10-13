'use strict';

// WAT DE RELAY ZELF KAN.
//
// De belofte: "de relay houdt een gesloten doos zonder sleutel, de mailprovider
// draagt een sleutel zonder doos" (frontend/js/send-wrap.js:16-17).
//
// Deze suite scheidt twee dingen die in die zin door elkaar lopen:
//
//   1. WAT DE RELAY BEWAART. De hele opslag wordt leeggekiept en doorzocht.
//      Het token staat er niet in, de bestandssleutel ook niet, en uit wat er
//      wel staat valt geen van beide af te leiden. Dat deel van de belofte
//      houdt stand.
//
//   2. WAT DE RELAY TIJDENS EEN VERZOEK IN HANDEN HEEFT. Het token komt op
//      /v2/pickup/:token binnen en gaat als argument naar collect(). Op dat
//      moment heeft de relay beide helften tegelijk. Hij kan het bestand dan
//      openen, en hij kan ook een EIGEN bestand inpakken dat de browser van de
//      ontvanger zonder klagen uitpakt.
//
// De opslag wordt precies zo bedraad als relay.js:2077-2087 dat doet, zodat dit
// dezelfde bytes zijn als die in productie in Redis staan.
//
// Draaien:
//   cd /home/mick/paramant-ontvangers/relay && node --test test/wikkel-relay-aanval.test.js

const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const sendMod = require('../lib/send');
const recipients = require('../lib/recipients');
const parasignStoreMod = require('../lib/parasign-store');

// De echte browsercode, ongewijzigd.
const wrapSrc = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

const NUL = '\x00';
const WRAP_LABEL = 'paramant/send-wrap/v1' + NUL;        // send-wrap.js:30
const TOKEN_LABEL = 'paramant/pickup-token/v1' + NUL;    // recipients.js:83

function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; }

// Exact de bedrading van relay.js:2078-2084.
function nieuweOpslag() {
  const store = parasignStoreMod.createParaSignStore({
    redis: null, encKey: null, log: null, prefix: 'psend', aadPrefix: 'parasend',
  });
  return { store, sends: sendMod.createSendStore({ store, log: null }) };
}

// Een verzending zoals parashare.page.js hem maakt: bestand verzegeld met een
// sleutel die de relay nooit ziet, en per ontvanger een wikkel onder zijn token.
async function verzend(sends, adressen, tekst) {
  const naam = 'dossier.pdf';
  const naamBytes = Buffer.from(naam, 'utf8');
  const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, Buffer.from(tekst, 'utf8')]);
  const rawKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const blob = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));   // 44 bytes
  const sealed = Object.create(null);
  const tokens = Object.create(null);
  for (const adres of adressen) {
    const token = wrap.newToken();
    sealed[adres] = { token, wrapped_key: await wrap.wrap(token, geheim) };
    tokens[adres] = token;
  }
  const made = await sends.create({
    plan: 'pro', blob, addresses: adressen, ttlMs: 3600e3,
    filename: naam, accountId: 'acct_aanval', sealed,
    sender: { naam: 'Zorggroep', email: 'anna@zorggroep.test' },
  });
  assert.equal(made.ok, true, 'verzending geweigerd: ' + JSON.stringify(made));
  return { made, tokens, rawKey, iv, geheim, blob, naam, sealed };
}

// Alles wat er werkelijk in de opslag staat, als lijst sleutel -> bytes.
function dumpOpslag(store) {
  const uit = [];
  for (const [k, v] of store._mem) uit.push({ key: k, bytes: Buffer.from(v.val) });
  return uit;
}

// ---------------------------------------------------------------------------
// 1. Kan de relay het bestand openen met ALLEEN wat hij bewaart?
// ---------------------------------------------------------------------------

test('wat de relay bewaart bevat het token noch de bestandssleutel', async () => {
  const { store, sends } = nieuweOpslag();
  const adressen = ['partner1@extern.test', 'partner2@extern.test'];
  const v = await verzend(sends, adressen, 'de jaarrekening van de stichting');

  const alles = dumpOpslag(store);
  assert.ok(alles.length >= 4, 'verwacht: send-record, twee tokenindexen, blob');

  const gezamenlijk = Buffer.concat(alles.map((r) => r.bytes));

  // Wat er WEL in staat.
  const record = JSON.parse(
    alles.find((r) => r.key === 'psend:meta:' + v.made.id).bytes.toString('utf8'));
  assert.equal(record.records.length, 2);
  assert.equal(record.records[0].wrapped_key, v.sealed[adressen[0]].wrapped_key,
    'de wikkel staat er, want die moet terug naar de ontvanger');
  assert.equal(record.records[0].token_hash,
    recipients.tokenHash(v.tokens[adressen[0]]),
    'en de HASH van het token, lib/recipients.js:181');
  assert.equal(record.records[0].token, undefined, 'het token zelf staat er niet');

  // Wat er NIET in staat. Elk van deze drie zou de belofte breken.
  for (const adres of adressen) {
    assert.ok(!gezamenlijk.includes(Buffer.from(v.tokens[adres], 'utf8')),
      'het token van ' + adres + ' staat ergens in de opslag');
  }
  assert.ok(!gezamenlijk.includes(v.rawKey), 'de bestandssleutel staat in de opslag');
  assert.ok(!gezamenlijk.includes(Buffer.concat([v.rawKey, v.iv])),
    'het 44-byte geheim staat in de opslag');
  // De wikkelsleutel zelf: SHA-256 over label + token.
  const wikkelsleutel = crypto.createHash('sha256')
    .update(Buffer.from(WRAP_LABEL, 'utf8'))
    .update(Buffer.from(v.tokens[adressen[0]], 'utf8')).digest();
  assert.ok(!gezamenlijk.includes(wikkelsleutel),
    'de afgeleide wikkelsleutel staat in de opslag');
});

test('uit het opgeslagen record valt de wikkel niet open te krijgen', async () => {
  const { store, sends } = nieuweOpslag();
  const adressen = ['partner1@extern.test'];
  const v = await verzend(sends, adressen, 'de jaarrekening van de stichting');
  const token = v.tokens[adressen[0]];

  const record = await store.getMeta(v.made.id);
  const bewaard = record.records[0];

  // De enige velden die iets met het token te maken hebben, en de send-id.
  const kandidaten = [
    bewaard.token_hash,                                           // hex
    Buffer.from(bewaard.token_hash, 'hex').toString('base64url'),
    bewaard.email_hash,
    v.made.id,
    'tok-' + bewaard.token_hash,
  ];
  for (const k of kandidaten) {
    await assert.rejects(() => wrap.unwrap(k, bewaard.wrapped_key),
      'wat de relay bewaart opende de wikkel: ' + k);
  }

  // WAAROM het niet kan, en niet alleen DAT het niet lukte.
  //
  //   token_hash  = SHA3-256('paramant/pickup-token/v1\0' || token)  recipients.js:80-86
  //   wikkelkey   = SHA-256 ('paramant/send-wrap/v1\0'    || token)  send-wrap.js:65-71
  //
  // Twee eenwegfuncties over dezelfde 32 willekeurige bytes, met verschillende
  // domeinscheiding. De een geeft de ander niet, en het token terugrekenen uit
  // de hash is 2^256. De relay mist dus een echte invoer, niet een stap.
  const A = crypto.createHash('sha3-256')
    .update(Buffer.from(TOKEN_LABEL, 'utf8'))
    .update(Buffer.from(token, 'utf8')).digest('hex');
  const B = crypto.createHash('sha256')
    .update(Buffer.from(WRAP_LABEL, 'utf8'))
    .update(Buffer.from(token, 'utf8')).digest('hex');
  assert.equal(A, bewaard.token_hash, 'de opgeslagen hash is inderdaad de tokenhash');
  assert.notEqual(A, B, 'zelfde token, andere domeinscheiding');
  assert.equal(Buffer.from(token, 'base64url').length, 32,
    'het token is 32 willekeurige bytes: er valt niets te raden');
});

// ---------------------------------------------------------------------------
// 6. En tijdens het verzoek? Dan heeft de relay beide helften.
// ---------------------------------------------------------------------------

test('tijdens een ophaalverzoek KAN de relay het bestand lezen', async () => {
  const { sends } = nieuweOpslag();
  const adressen = ['partner1@extern.test'];
  const inhoud = 'de jaarrekening van de stichting';
  const v = await verzend(sends, adressen, inhoud);
  const token = v.tokens[adressen[0]];

  // Precies wat relay.js:7089 en :7144 binnenkrijgen: het token uit het pad.
  const vraag = await sends.requestPickup(token);
  assert.equal(vraag.ok, true);
  const got = await sends.collect(token, vraag.code);
  assert.equal(got.ok, true);

  // Nu doet de relay wat hij zegt niet te kunnen. Geen truc: dit is het token
  // uit het verzoek plus de wikkel uit zijn eigen opslag.
  const sleutel = await wrap.unwrap(token, got.wrapped_key);
  const d = crypto.createDecipheriv('aes-256-gcm',
    Buffer.from(sleutel.rawKey), Buffer.from(sleutel.iv));
  d.setAuthTag(got.blob.subarray(got.blob.length - 16));
  const uit = Buffer.concat([d.update(got.blob.subarray(0, got.blob.length - 16)), d.final()]);
  const naamLen = uit.readUInt32LE(0);

  assert.equal(uit.subarray(4, 4 + naamLen).toString('utf8'), v.naam);
  assert.equal(uit.subarray(4 + naamLen).toString('utf8'), inhoud,
    'de relay las de inhoud van het bestand');
  assert.deepEqual(Buffer.from(sleutel.rawKey), v.rawKey,
    'en hield de bestandssleutel zelf in handen');
});

test('de relay kan een EIGEN bestand inpakken dat de ontvanger opent', async () => {
  const { sends } = nieuweOpslag();
  const adressen = ['partner1@extern.test'];
  const v = await verzend(sends, adressen, 'het echte bestand');
  const token = v.tokens[adressen[0]];

  // De relay ziet het token op /v2/pickup/:token. Meer heeft hij niet nodig:
  // send-wrap.js bindt de wikkel aan niets anders. Geen send-id, geen adres,
  // geen afzender: crypto.subtle.encrypt op send-wrap.js:78 krijgt geen
  // additionalData. Wie het token heeft kan een geldige wikkel MAKEN.
  const valsNaam = 'dossier.pdf';                    // dezelfde naam
  const valsTekst = 'VERVALST DOOR DE RELAY';
  const nb = Buffer.from(valsNaam, 'utf8');
  const valsPlain = Buffer.concat([u32le(nb.length), nb, Buffer.from(valsTekst, 'utf8')]);
  const valsKey = crypto.randomBytes(32);
  const valsIv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', valsKey, valsIv);
  const valsBlob = Buffer.concat([c.update(valsPlain), c.final(), c.getAuthTag()]);
  const valsWikkel = await wrap.wrap(token, new Uint8Array(Buffer.concat([valsKey, valsIv])));

  // De ontvanger doet exact wat ophalen.page.js:213-222 doet.
  const sleutel = await wrap.unwrap(token, valsWikkel);
  const d = crypto.createDecipheriv('aes-256-gcm',
    Buffer.from(sleutel.rawKey), Buffer.from(sleutel.iv));
  d.setAuthTag(valsBlob.subarray(valsBlob.length - 16));
  const uit = Buffer.concat([d.update(valsBlob.subarray(0, valsBlob.length - 16)), d.final()]);
  const naamLen = uit.readUInt32LE(0);

  assert.equal(uit.subarray(4, 4 + naamLen).toString('utf8'), valsNaam);
  assert.equal(uit.subarray(4 + naamLen).toString('utf8'), valsTekst,
    'de ontvanger kreeg het bestand van de relay en merkte niets');
  // En er is niets in de wikkel of in de bytes waar een ontvanger dit aan kan
  // zien: geen handtekening van de afzender, geen binding aan send-id.
  assert.notDeepEqual(Buffer.from(sleutel.rawKey), v.rawKey);
});
