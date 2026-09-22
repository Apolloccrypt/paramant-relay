'use strict';

// Verse-ogen audit op feat/meerdere-ontvangers.
//
// Elke test hieronder stelt vast wat WAAR ZOU MOETEN ZIJN. Een test die faalt
// is dus een defect, niet een kapotte test. Niets in deze file raakt broncode.
//
// Het draait om een detail dat de commentaren in recipients.js verkeerd hebben:
// "Node runs this without interleaving, so the pair is atomic here". Dat klopt
// voor een array in het geheugen. Het klopt NIET voor send.js, want daar loopt
// elk record door parasign-store heen, en die doet
//
//     putMeta -> JSON.stringify -> (seal) -> redis
//     getMeta -> redis -> (unseal) -> JSON.parse
//
// Elke getMeta levert dus een VERSE kopie. Twee gelijktijdige verzoeken op
// dezelfde verzending werken elk op hun eigen kopie en schrijven allebei de
// hele verzending terug. Read-modify-write zonder slot, over een await heen.
//
// De nepstore hieronder doet precies dat, met een tik vertraging zodat de
// interleaving vast ligt in plaats van van de microtask-volgorde af te hangen.

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const { createSendStore } = require('../lib/send');
const recipients = require('../lib/recipients');
const tiers = require('../lib/tiers');

const RELAY_SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

// ── de store, zoals parasign-store.js zich echt gedraagt ────────────────────
function duurzameStore(vertragingMs) {
  const ms = vertragingMs == null ? 2 : vertragingMs;
  const blobs = new Map();
  const meta = new Map();
  const tik = () => new Promise(r => setTimeout(r, ms));
  return {
    blobs, meta,
    async putBlob(id, buf, ttl) { await tik(); blobs.set(id, { buf: Buffer.from(buf), ttl }); },
    async getBlob(id) { await tik(); const r = blobs.get(id); return r ? Buffer.from(r.buf) : null; },
    async delBlob(id) { await tik(); blobs.delete(id); },
    // JSON heen en terug: exact wat put('meta') / get('meta') doet.
    async putMeta(id, obj, ttl) { await tik(); meta.set(id, { json: JSON.stringify(obj || {}), ttl }); },
    async getMeta(id) { await tik(); const r = meta.get(id); return r ? JSON.parse(r.json) : null; },
    async delMeta(id) { await tik(); meta.delete(id); },
  };
}

function maak(vertraging) {
  const store = duurzameStore(vertraging);
  return { store, sends: createSendStore({ store }) };
}

// Dezelfde store, maar de EERSTE schrijfactie op de verzending duurt langer.
// Dat legt de volgorde vast: wie als eerste begint te schrijven landt als
// laatste, en overschrijft dus wat de ander intussen heeft weggezet. Zonder
// dit hangt de uitkomst van de microtask-volgorde af en is de test wisselvallig.
function traagEersteSchrijf(store, sendId, extraMs) {
  const echt = store.putMeta.bind(store);
  let eerste = true;
  store.putMeta = async function (id, obj, ttl) {
    if (id === sendId && eerste) {
      eerste = false;
      await new Promise(r => setTimeout(r, extraMs == null ? 40 : extraMs));
    }
    return echt(id, obj, ttl);
  };
}

const DRIE = ['anna@example.org', 'bob@example.org', 'carla@example.org'];
const INHOUD = Buffer.from('een vertrouwelijk rapport');

function anderCode(code) { return code === '000000' ? '111111' : '000000'; }

function blokUit(bron, anker, lengte) {
  const i = bron.indexOf(anker);
  assert.ok(i > 0, 'anker niet gevonden in relay.js: ' + anker);
  return bron.slice(i, i + lengte);
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Twee gelijktijdige ophalingen met hetzelfde token
// ═══════════════════════════════════════════════════════════════════════════
test('een token levert het bestand precies een keer, ook bij twee kliks tegelijk', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 filename: 'rapport.pdf', accountId: 'acct-1' });
  const token = r.tokens['anna@example.org'];
  const vraag = await sends.requestPickup(token);

  const [a, b] = await Promise.all([
    sends.collect(token, vraag.code),
    sends.collect(token, vraag.code),
  ]);

  const geleverd = [a, b].filter(x => x.ok).length;
  assert.equal(geleverd, 1,
    'twee gelijktijdige verzoeken met hetzelfde eenmalige token kregen allebei de bytes');
});

test('en het overzicht telt geen ophaling minder dan er bytes de deur uit gingen', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const token = r.tokens['anna@example.org'];
  const vraag = await sends.requestPickup(token);
  const uit = await Promise.all([
    sends.collect(token, vraag.code),
    sends.collect(token, vraag.code),
  ]);
  const geleverd = uit.filter(x => x.ok).length;
  const ov = await sends.overview(r.id);
  assert.equal(ov.collected, geleverd,
    'de afzender ziet ' + ov.collected + ' ophaling(en) terwijl het bestand ' +
    geleverd + ' keer is uitgeleverd');
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Twee ontvangers die tegelijk een code vragen
// ═══════════════════════════════════════════════════════════════════════════
test('de code van de ene ontvanger overleeft het codeverzoek van de andere', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const tA = r.tokens['anna@example.org'];
  const tB = r.tokens['bob@example.org'];

  const [va, vb] = await Promise.all([sends.requestPickup(tA), sends.requestPickup(tB)]);
  assert.equal(va.ok, true);
  assert.equal(vb.ok, true);

  const a = await sends.collect(tA, va.code);
  assert.equal(a.ok, true,
    'anna kreeg een code gemaild die bob met zijn eigen verzoek heeft weggeschreven: ' +
    (a.reason || ''));
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. De drie pogingen op de code
// ═══════════════════════════════════════════════════════════════════════════
test('veertig gelijktijdige foute codes verbruiken de drie pogingen', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const token = r.tokens['anna@example.org'];
  const vraag = await sends.requestPickup(token);
  const fout = anderCode(vraag.code);

  await Promise.all(Array.from({ length: 40 }, () => sends.collect(token, fout)));
  const nog = await sends.collect(token, fout);
  assert.equal(nog.reason, 'too_many_tries',
    'na veertig foute codes staat de teller nog op ' + (nog.tries_left != null
      ? String(3 - nog.tries_left) : '?') + ': de zescijferige code is parallel te raden');
});

test('het aantal codeverzoeken per link heeft een plafond', async () => {
  const { sends } = maak(0);
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const token = r.tokens['anna@example.org'];

  let geweigerd = 0;
  for (let i = 0; i < 200; i++) {
    const v = await sends.requestPickup(token);
    if (!v.ok) geweigerd++;
  }
  assert.ok(geweigerd > 0,
    'tweehonderd codeverzoeken op een link leverden tweehonderd mails op, ' +
    'en elk verzoek zet code_tries terug op nul');
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Intrekken terwijl iemand ophaalt
// ═══════════════════════════════════════════════════════════════════════════
test('een intrekking overleeft een ophaling die op hetzelfde moment loopt', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const tAnna = r.tokens['anna@example.org'];
  const tBob = r.tokens['bob@example.org'];
  const vraag = await sends.requestPickup(tAnna);

  const [, rv] = await Promise.all([
    sends.collect(tAnna, vraag.code),
    sends.revoke(r.id, 'bob@example.org'),
  ]);
  assert.equal(rv.ok, true, 'de intrekking zelf moest slagen');

  const ov = await sends.overview(r.id);
  const bob = ov.recipients.find(x => x.email === 'bob@example.org');
  assert.equal(bob.status, 'revoked',
    'de afzender trok bob in, maar het overzicht zegt "' + bob.status + '"');

  const nog = await sends.requestPickup(tBob);
  assert.equal(nog.ok, false,
    'de ingetrokken link van bob werkt nog steeds');
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Opnieuw uitnodigen terwijl iemand ophaalt
// ═══════════════════════════════════════════════════════════════════════════
test('opnieuw uitnodigen wist geen ophaling uit die op dat moment loopt', async () => {
  const { store, sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const token = r.tokens['anna@example.org'];
  const vraag = await sends.requestPickup(token);
  traagEersteSchrijf(store, r.id);

  const [c, ri] = await Promise.all([
    sends.collect(token, vraag.code),
    sends.reinvite(r.id, 'anna@example.org'),
  ]);
  assert.equal(c.ok, true, 'de ophaling zelf moest slagen');

  const ov = await sends.overview(r.id);
  assert.equal(ov.collected, 1,
    'anna heeft het bestand gekregen, maar het overzicht telt ' + ov.collected +
    ' ophalingen: de reinvite schreef de hele verzending terug over de ophaling heen');

  if (ri.ok) {
    const tweede = await sends.requestPickup(ri.token);
    assert.equal(tweede.ok, false,
      'het verse token levert het bestand een tweede keer aan dezelfde persoon');
  }
});

test('twee keer opnieuw uitnodigen laat precies een werkende link achter', async () => {
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });

  const [a, b] = await Promise.all([
    sends.reinvite(r.id, 'anna@example.org'),
    sends.reinvite(r.id, 'anna@example.org'),
  ]);
  const gemaild = [a, b].filter(x => x.ok);
  const werkend = [];
  for (const x of gemaild) {
    const v = await sends.requestPickup(x.token);
    if (v.ok) werkend.push(x.token);
  }
  assert.equal(werkend.length, gemaild.length,
    gemaild.length + ' verse links per mail de deur uit, waarvan er ' + werkend.length +
    ' werken: de ontvanger krijgt een mail met een link die nooit iets doet');
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. De tokenindex loopt vol
// ═══════════════════════════════════════════════════════════════════════════
test('een dode token laat geen indexregel achter', async () => {
  const { store, sends } = maak(0);
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  for (let i = 0; i < 50; i++) {
    const ri = await sends.reinvite(r.id, 'anna@example.org');
    assert.equal(ri.ok, true, 'reinvite ' + i + ' moest slagen');
  }
  const tok = [...store.meta.keys()].filter(k => k.startsWith('tok-'));
  assert.equal(tok.length, DRIE.length,
    'vijftig keer opnieuw uitnodigen liet ' + tok.length + ' tokenregels achter ' +
    'voor drie ontvangers, elk met de volle bewaartijd van de verzending');
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. De accountindex bij gelijktijdig aanmaken
// ═══════════════════════════════════════════════════════════════════════════
test('twee verzendingen tegelijk staan allebei op het dashboard', async () => {
  const { sends } = maak();
  await Promise.all([
    sends.create({ plan: 'business', blob: INHOUD, addresses: ['a@x.org'],
                   filename: 'een.pdf', accountId: 'acct-1' }),
    sends.create({ plan: 'business', blob: INHOUD, addresses: ['b@x.org'],
                   filename: 'twee.pdf', accountId: 'acct-1' }),
  ]);
  const lijst = await sends.list('acct-1');
  assert.equal(lijst.sends.length, 2,
    'een van de twee verzendingen staat niet in de accountindex en is daarmee ' +
    'onbereikbaar voor het dashboard: niet te zien, niet in te trekken');
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Halverwege stukgelopen aanmaak
// ═══════════════════════════════════════════════════════════════════════════
test('een half aangemaakte verzending laat het bestand niet achter', async () => {
  const echt = duurzameStore(0);
  let n = 0;
  const kapot = {
    putBlob: echt.putBlob, getBlob: echt.getBlob, delBlob: echt.delBlob,
    getMeta: echt.getMeta, delMeta: echt.delMeta,
    async putMeta(id, obj, ttl) {
      if (String(id).startsWith('tok-') && ++n === 2) throw new Error('redis weg');
      return echt.putMeta(id, obj, ttl);
    },
  };
  const sends = createSendStore({ store: kapot });
  await assert.rejects(sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                      accountId: 'acct-1' }));
  assert.equal(echt.blobs.size, 0,
    'de blob staat nog in de durende opslag terwijl de aanroeper een 500 kreeg: ' +
    'niemand kent het id, niemand kan hem ophalen, en hij blijft tot de bewaartijd om is');
});

// ═══════════════════════════════════════════════════════════════════════════
// 9. Grootte
// ═══════════════════════════════════════════════════════════════════════════
test('een verzending wordt getoetst aan de bestandsgrens van het plan', async () => {
  const { sends } = maak(0);
  const grens = tiers.tierLimitNum('community', 'file_mb') * 1048576;
  // 24 MiB: ruim boven MAX_BLOB (5 MiB) en ruim onder file_mb, puur om te laten
  // zien dat er helemaal niets getoetst wordt. De echte route kan 512 blokken
  // van 5 MiB samenvoegen tot 2,5 GB.
  const groot = Buffer.alloc(24 * 1024 * 1024, 1);
  const r = await sends.create({ plan: 'community', blob: groot,
                                 addresses: ['a@x.org'], accountId: 'acct-1' });
  assert.ok(Number.isFinite(grens));
  assert.equal(r.ok, true, 'voorwaarde van de test');
  // send.js kent geen enkele bovengrens op blob.length.
  assert.match(require('fs').readFileSync(path.join(__dirname, '..', 'lib', 'send.js'), 'utf8'),
    /file_mb|MAX_BLOB|blob\.length\s*>/,
    'send.js toetst de omvang van de blob nergens: create() neemt wat hij krijgt');
});

test('POST /v2/sends voegt een hash niet twee keer samen', () => {
  const blok = blokUit(RELAY_SRC, "path === '/v2/sends'", 2200);
  assert.match(blok, /new Set|gezien|dedup|seen/,
    '512 keer dezelfde hash in de lijst is 512 x entry.blob in Buffer.concat: ' +
    'uit een upload van 5 MiB komt een bestand van 2,5 GB, binnen de 64 KB body');
});

test('POST /v2/sends toetst de omvang van het samengevoegde bestand', () => {
  const blok = blokUit(RELAY_SRC, "path === '/v2/sends'", 2200);
  assert.match(blok, /file_mb|blob\.length\s*>|totaal|te_groot|too_large/,
    'niets tussen Buffer.concat en putBlob kijkt naar hoe groot het geworden is');
});

// ═══════════════════════════════════════════════════════════════════════════
// 10. De uitnodigingsmail
// ═══════════════════════════════════════════════════════════════════════════
test('de bestandsnaam in de uitnodigingsmail gaat door escHtml', () => {
  const blok = blokUit(RELAY_SRC, "const naam = (input.filename", 1800);
  assert.match(blok, /escHtml\(\s*naam\s*\)|escHtml\(input\.filename/,
    'de afzender bepaalt input.filename en die gaat onge-escaped in de HTML van ' +
    'maximaal dertig mails naar derden; relay.js heeft escHtml en gebruikt hem ' +
    'wel in de DPA- en factuurmails');
});

test('de afzender krijgt te horen dat de post niet aankwam', () => {
  const blok = blokUit(RELAY_SRC, 'function sendResendEmail', 1200);
  assert.match(blok, /await\s+mailer\.stuur|return\s+mailer\.stuur/,
    'sendResendEmail vuurt mailer.stuur af en geeft meteen true terug; ' +
    '"invited: 30" in het 201-antwoord telt pogingen, geen bezorgingen, ' +
    'en een 4xx van de provider komt alleen in het log terecht');
});

// ═══════════════════════════════════════════════════════════════════════════
// 11. De sleutelpoort
// ═══════════════════════════════════════════════════════════════════════════
test('GET /v2/pickup/:token is bereikbaar zonder API-sleutel', () => {
  const poort = RELAY_SRC.indexOf("} else if (!keyData?.active && !isEnvelopePublic");
  const route = RELAY_SRC.indexOf('const pickm = path.match(');
  assert.ok(poort > 0 && route > 0, 'poort of route niet gevonden');

  const uitzondering = RELAY_SRC.slice(poort, poort + 200);
  const genoemd = /pickup/.test(uitzondering);

  assert.ok(route < poort || genoemd,
    'de sleutelpoort staat op regel ' + (RELAY_SRC.slice(0, poort).split('\n').length) +
    ' en de pickup-route op regel ' + (RELAY_SRC.slice(0, route).split('\n').length) +
    ': een ontvanger zonder account krijgt 401 "Invalid API key" voordat de ' +
    'route ooit draait. /v2/pickup staat ook niet in lib/public-routes.js.');
});

test('pickup wordt niet door een GET van een mailscanner afgevuurd', () => {
  const blok = blokUit(RELAY_SRC, 'const pickm = path.match(', 900);
  assert.doesNotMatch(blok, /pickm && req\.method === 'GET'/,
    'de link in de uitnodiging is een GET met een bijwerking: elke Safe-Links- ' +
    'of antivirusscanner die de mail opent stuurt de ontvanger ongevraagd een ' +
    'code en zet code_tries terug op nul');
});

// ═══════════════════════════════════════════════════════════════════════════
// 12. Kleinere dingen
// ═══════════════════════════════════════════════════════════════════════════
test('een foute gok van de een wist de ophaling van de ander niet uit', async () => {
  // Elke schrijfactie zet de HELE verzending terug, ook de goedkoopste: een
  // foute code. Wie een token heeft en blijft gokken, rolt daarmee de staat van
  // iedereen terug, en een teruggerolde ophaling is een tweede levering.
  const { store, sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const tAnna = r.tokens['anna@example.org'];
  const tBob = r.tokens['bob@example.org'];
  const vA = await sends.requestPickup(tAnna);
  await sends.requestPickup(tBob);
  traagEersteSchrijf(store, r.id);

  const [c] = await Promise.all([
    sends.collect(tAnna, vA.code),
    sends.collect(tBob, '000000'),   // fout, en dus een volle terugschrijving
  ]);
  assert.equal(c.ok, true, 'anna kreeg haar bestand');

  const ov = await sends.overview(r.id);
  const her = await sends.requestPickup(tAnna);
  const nogmaals = her.ok ? await sends.collect(tAnna, her.code) : { ok: false };
  assert.equal(ov.collected, 1,
    'bobs foute gok schreef de verzending terug over annas ophaling heen: ' +
    'het overzicht telt ' + ov.collected + ' ophalingen, en annas eenmalige link ' +
    'levert het bestand ' + (nogmaals.ok ? 'opnieuw uit' : 'niet opnieuw uit'));
});

test('checkRecipients stopt bij het plafond in plaats van de hele lijst te lopen', () => {
  const lijst = new Array(50000).fill('anna@example.org');
  lijst.push('dit is geen adres');
  const r = tiers.checkRecipients('community', lijst);
  assert.notEqual(r.reason, 'invalid_address',
    'de break kijkt naar recipients.length, en duplicaten laten die staan: ' +
    'de lus normaliseert de hele lijst voordat hij iets weigert');
});

test('overview lekt geen token of hash', async () => {
  const { sends } = maak(0);
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const ov = await sends.overview(r.id);
  const tekst = JSON.stringify(ov);
  assert.doesNotMatch(tekst, /token_hash|email_hash|code_hash|salt/, 'hash in het overzicht');
  for (const t of Object.values(r.tokens)) assert.ok(!tekst.includes(t), 'token in het overzicht');
});

test('recipients.claimPickup is atomair over een store heen', async () => {
  // De aanname die in recipients.js staat opgeschreven, getoetst op de laag
  // die hem gebruikt. Binnen een array klopt hij; door send.js heen niet.
  const { sends } = maak();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 accountId: 'acct-1' });
  const token = r.tokens['carla@example.org'];
  const vraag = await sends.requestPickup(token);
  const uit = await Promise.all(Array.from({ length: 5 },
    () => sends.collect(token, vraag.code)));
  assert.equal(uit.filter(x => x.ok).length, 1,
    'vijf gelijktijdige verzoeken, ' + uit.filter(x => x.ok).length + ' leveringen; ' +
    'het commentaar bij claimPickup belooft dat dit niet kan');
  assert.ok(recipients.claimPickup);
});
