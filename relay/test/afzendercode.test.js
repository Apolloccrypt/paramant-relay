'use strict';

// De eigen code van de afzender, in de browsercode en in de opslag.
//
// Bij versturen op naam gaan de link en de mailcode naar dezelfde mailbox, via
// dezelfde mailprovider. Wie die mailbox leest, had alles. Daarom gaat de
// bestandssleutel nu ook op slot onder een code die de browser van de afzender
// maakt en die de afzender zelf doorgeeft. Deze tests houden vast:
//
//   - met de goede code en de link gaat het slot open, met een foute niet
//   - de link alleen (de oude manier van uitpakken) opent een nieuwe send niet
//   - wat naar de server gaat (zout, check, bewijs) bevat de code niet
//   - de opslag vraagt het bewijs pas na de goede mailcode
//   - vijf foute bewijzen en de link is op, ook voor een nieuwe mailcode
//   - een send zonder vlag werkt precies als voorheen

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const { createSendStore, proofCheck, MAX_SENDER_CODE_WRONG } = require('../lib/send');
const { sealedVoor } = require('./_sealed');

const SOURCE = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(SOURCE, scope);
const W = scope.paramantSendWrap;

function geheim() {
  const u = new Uint8Array(44);
  globalThis.crypto.getRandomValues(u);
  return u;
}

function nepStore() {
  const blobs = new Map(), meta = new Map();
  return {
    blobs, meta,
    async putBlob(id, buf) { blobs.set(id, Buffer.from(buf)); },
    async getBlob(id) { const b = blobs.get(id); return b ? Buffer.from(b) : null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj) { meta.set(id, JSON.parse(JSON.stringify(obj))); },
    async delMeta(id) { meta.delete(id); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r)) : null; },
  };
}

// Eén keer rekken voor het hele bestand: PBKDF2 met 600 000 rondes kost tijd,
// en dat is precies de bedoeling.
const CODE = W.newSenderCode();
const ZOUT = W.newCodeSalt();
let GEREKT = null;
test.before(async () => { GEREKT = await W.stretchCode(CODE, ZOUT); });

// ── de vorm van de code ─────────────────────────────────────────────────────

test('de code is tien tekens uit een alfabet zonder verwarbare tekens', () => {
  assert.equal(W.CODE_ALPHABET.length, 31);
  assert.doesNotMatch(W.CODE_ALPHABET, /[01ILO]/, '0, 1, I, L en O lijken op elkaar');
  for (let i = 0; i < 200; i++) {
    const c = W.newSenderCode();
    assert.equal(c.length, 10);
    for (const ch of c) assert.ok(W.CODE_ALPHABET.includes(ch), 'teken buiten het alfabet: ' + ch);
  }
  assert.ok(Math.log2(31) * 10 > 49, 'minstens 49 bits');
  assert.ok(W.CODE_ROUNDS >= 600000, 'PBKDF2 met het OWASP-aantal rondes');
});

test('codes herhalen zich niet en elk teken komt voor', () => {
  const gezien = new Set(), tekens = new Set();
  for (let i = 0; i < 2000; i++) {
    const c = W.newSenderCode();
    gezien.add(c);
    for (const ch of c) tekens.add(ch);
  }
  assert.equal(gezien.size, 2000);
  assert.equal(tekens.size, 31, 'elk teken van het alfabet moet kunnen voorkomen');
});

test('wat een mens intikt, wordt dezelfde code', () => {
  const opgemaakt = W.formatCode(CODE);
  assert.match(opgemaakt, /^[2-9A-Z]{5}-[2-9A-Z]{5}$/);
  assert.equal(W.normaliseCode(opgemaakt), CODE);
  assert.equal(W.normaliseCode(' ' + opgemaakt.toLowerCase() + ' '), CODE);
  assert.equal(W.normaliseCode(CODE.slice(0, 5) + ' ' + CODE.slice(5)), CODE);
  assert.equal(W.normaliseCode(CODE.slice(0, 9)), '', 'te kort');
  assert.equal(W.normaliseCode('O' + CODE.slice(1)), '', 'buiten het alfabet wordt niet geraden');
});

// ── inpakken en uitpakken ──────────────────────────────────────────────────

test('met link en code gaat het slot open', async () => {
  const s = geheim();
  const token = W.newToken();
  const w = await W.wrapWithCode(token, s, GEREKT);
  const terug = await W.unwrapWithCode(token, w.wrapped_key, GEREKT);
  assert.deepEqual(Array.from(terug.rawKey), Array.from(s.subarray(0, 32)));
  assert.deepEqual(Array.from(terug.iv), Array.from(s.subarray(32, 44)));
});

test('een foute code opent het niet, ook niet met de goede link', async () => {
  const token = W.newToken();
  const w = await W.wrapWithCode(token, geheim(), GEREKT);
  let fout = W.newSenderCode();
  while (fout === CODE) fout = W.newSenderCode();
  const verkeerd = await W.stretchCode(fout, ZOUT);
  await assert.rejects(() => W.unwrapWithCode(token, w.wrapped_key, verkeerd));
  // Zelfde code met een ander zout is ook een andere sleutel.
  const anderZout = await W.stretchCode(CODE, W.newCodeSalt());
  await assert.rejects(() => W.unwrapWithCode(token, w.wrapped_key, anderZout));
});

test('de link alleen opent een nieuwe wikkeling niet', async () => {
  const token = W.newToken();
  const w = await W.wrapWithCode(token, geheim(), GEREKT);
  await assert.rejects(() => W.unwrap(token, w.wrapped_key),
    'wie alleen de mail heeft, mag met de oude manier van uitpakken niets bereiken');
  await assert.rejects(() => W.unwrapWithCode(W.newToken(), w.wrapped_key, GEREKT),
    'de code met de link van iemand anders opent het ook niet');
});

test('zonder code werkt het oude inpakken nog precies zo', async () => {
  const s = geheim();
  const token = W.newToken();
  const terug = await W.unwrap(token, await W.wrap(token, s));
  assert.deepEqual(Array.from(terug.rawKey), Array.from(s.subarray(0, 32)));
});

test('wat naar de server gaat, bevat de code niet en de server kan het bewijs controleren', async () => {
  const token = W.newToken();
  const w = await W.wrapWithCode(token, geheim(), GEREKT);
  const bewijs = await W.proofFor(token, GEREKT);
  const naarServer = JSON.stringify({ salt: ZOUT, wrapped_key: w.wrapped_key,
                                      code_check: w.code_check, sender_proof: bewijs });
  for (const vorm of [CODE, W.formatCode(CODE), CODE.toLowerCase()]) {
    assert.ok(!naarServer.includes(vorm), 'de code staat in wat de server krijgt');
  }
  assert.ok(!naarServer.includes(Buffer.from(CODE).toString('base64').replace(/=+$/, '')));
  assert.equal(proofCheck(bewijs), w.code_check, 'de server herkent het goede bewijs');
  assert.notEqual(bewijs, w.code_check, 'de server bewaart niet het bewijs zelf');
  const ander = await W.proofFor(W.newToken(), GEREKT);
  assert.notEqual(proofCheck(ander), w.code_check, 'het bewijs hoort bij precies deze link');
});

// ── de opslag ────────────────────────────────────────────────────────────────

const ADRES = 'demo@example.com';
const INHOUD = Buffer.from('een vertrouwelijk stuk');

async function metCode() {
  const store = nepStore();
  const sends = createSendStore({ store });
  const token = W.newToken();
  const w = await W.wrapWithCode(token, geheim(), GEREKT);
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: [ADRES],
    sealed: { [ADRES]: { token, wrapped_key: w.wrapped_key, code_check: w.code_check } },
    senderCode: { salt: ZOUT } });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.sender_code, true);
  const bewijs = await W.proofFor(token, GEREKT);
  return { store, sends, token, w, bewijs, id: r.id };
}

test('opslag: een send met de vlag bewaart zout en check, nooit de code', async () => {
  const { store, id } = await metCode();
  const bewaard = JSON.stringify([...store.meta.values()]);
  assert.ok(!bewaard.includes(CODE));
  const send = store.meta.get(id);
  assert.equal(send.sender_code, true);
  assert.equal(send.code_salt, ZOUT);
  assert.match(send.records[0].code_check, /^[A-Za-z0-9_-]{43}$/);
});

test('opslag: met de vlag aan is een rij zonder check een weigering', async () => {
  const sends = createSendStore({ store: nepStore() });
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: [ADRES],
    sealed: sealedVoor([ADRES]), senderCode: { salt: ZOUT } });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing_code_check');
  const r2 = await sends.create({ plan: 'business', blob: INHOUD, addresses: [ADRES],
    sealed: sealedVoor([ADRES]), senderCode: { salt: 'kort' } });
  assert.equal(r2.reason, 'bad_code_salt');
});

test('opslag: de codevraag meldt de vlag en het zout', async () => {
  const { sends, token } = await metCode();
  const v = await sends.requestPickup(token);
  assert.equal(v.ok, true);
  assert.equal(v.sender_code, true);
  assert.equal(v.code_salt, ZOUT);
});

test('opslag: zonder bewijs geen bestand, en dat kost geen poging', async () => {
  const { sends, token, store, id } = await metCode();
  const v = await sends.requestPickup(token);
  const r = await sends.collect(token, v.code, '');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'sender_code_required');
  assert.equal(store.meta.get(id).records[0].sender_wrong, 0);
});

test('opslag: het bewijs telt pas na de goede mailcode', async () => {
  const { sends, token, store, id } = await metCode();
  await sends.requestPickup(token);
  const r = await sends.collect(token, '000000', 'x'.repeat(43));
  assert.equal(r.ok, false);
  assert.equal(r.reason === 'wrong_code' || r.reason === 'too_many_tries', true);
  assert.equal(store.meta.get(id).records[0].sender_wrong, 0,
    'wie de mailbox niet heeft, mag de pogingen van de ontvanger niet opmaken');
});

test('opslag: een fout bewijs laat de mailcode staan, het goede geeft het bestand', async () => {
  const { sends, token, bewijs, w } = await metCode();
  const v = await sends.requestPickup(token);
  const fout = await sends.collect(token, v.code, 'A'.repeat(43));
  assert.equal(fout.ok, false);
  assert.equal(fout.reason, 'wrong_sender_code');
  assert.equal(fout.tries_left, MAX_SENDER_CODE_WRONG - 1);
  const goed = await sends.collect(token, v.code, bewijs);
  assert.equal(goed.ok, true, JSON.stringify(goed));
  assert.deepEqual(goed.blob, INHOUD);
  assert.equal(goed.wrapped_key, w.wrapped_key);
});

test('opslag: vijf foute bewijzen en de link is op, ook met een nieuwe mailcode', async () => {
  const { sends, token, bewijs } = await metCode();
  const v = await sends.requestPickup(token);
  let laatste = null;
  for (let i = 0; i < MAX_SENDER_CODE_WRONG; i++) {
    laatste = await sends.collect(token, v.code, 'B'.repeat(43));
  }
  assert.equal(laatste.reason, 'sender_code_locked');
  assert.equal(laatste.tries_left, 0);
  const nogEens = await sends.collect(token, v.code, bewijs);
  assert.equal(nogEens.ok, false);
  assert.equal(nogEens.reason, 'sender_code_locked', 'ook het goede bewijs helpt dan niet meer');
  const nieuweCode = await sends.requestPickup(token);
  assert.equal(nieuweCode.ok, false);
  assert.equal(nieuweCode.reason, 'sender_code_locked', 'en er gaat geen nieuwe mail meer uit');
});

test('opslag: een send zonder vlag werkt als voorheen, een meegestuurd bewijs verandert niets', async () => {
  const store = nepStore();
  const sends = createSendStore({ store });
  const sealed = sealedVoor([ADRES]);
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: [ADRES], sealed });
  assert.equal(r.ok, true);
  assert.equal(r.sender_code, false);
  const send = store.meta.get(r.id);
  assert.equal('sender_code' in send, false, 'een oude send krijgt geen nieuw veld');
  assert.equal('code_check' in send.records[0], false);
  const token = r.tokens[ADRES];
  const v = await sends.requestPickup(token);
  assert.equal(v.sender_code, false);
  assert.equal(v.code_salt, '');
  const goed = await sends.collect(token, v.code, 'C'.repeat(43));
  assert.equal(goed.ok, true);
  assert.deepEqual(goed.blob, INHOUD);
});

test('opslag: een record van voor deze wijziging (zonder velden) wordt nog opgehaald', async () => {
  const store = nepStore();
  const sends = createSendStore({ store });
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: [ADRES], sealed: sealedVoor([ADRES]) });
  // Precies wat een send uit de vorige versie in de opslag heeft.
  const oud = store.meta.get(r.id);
  for (const rec of oud.records) { delete rec.code_check; delete rec.sender_wrong; }
  delete oud.sender_code; delete oud.code_salt;
  store.meta.set(r.id, oud);
  const token = r.tokens[ADRES];
  const v = await sends.requestPickup(token);
  const goed = await sends.collect(token, v.code);
  assert.equal(goed.ok, true);
});
