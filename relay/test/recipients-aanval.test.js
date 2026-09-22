'use strict';

// Aanvalstests op de ontvangerslaag.
//
// Elke test hieronder FAALT zolang het gat open staat en SLAAGT zodra het
// gedicht is. Ze zijn geschreven vanuit de aanvaller: wat kan iemand die niet
// op de lijst staat, of iemand die er wel op staat maar meer wil dan zijn ene
// ophaalbeurt, met deze API voor elkaar krijgen.
//
// Draaien:
//   cd /home/mick/paramant-ontvangers && node --test relay/test/recipients-aanval.test.js

const assert = require('node:assert/strict');
const test = require('node:test');

const rec = require('../lib/recipients');
const tiers = require('../lib/tiers');
const { sealedVoor } = require('./_sealed');

// Werkt zowel met de huidige plain-object tokens-map als met een Map, zodat de
// test ook slaagt als het gat met een Map gedicht wordt.
function uitgedeeldeTokens(tokens) {
  if (tokens instanceof Map) return [...tokens.values()];
  return Object.values(tokens || {});
}

function tokenVoor(built, email) {
  return built.tokens instanceof Map ? built.tokens.get(email) : built.tokens[email];
}

// Ophalen via de sterkste stap die de module aanbiedt. Zo blijven de tests die
// alleen een toestand willen opzetten geldig, ook als het opeisen later aan het
// token gebonden wordt of een atomaire claimPickup krijgt.
function haalOp(records, token, now) {
  if (typeof rec.claimPickup === 'function') return !!rec.claimPickup(records, token, now);
  const r = rec.findByToken(records, token);
  return rec.markPickedUp(r, now, token) || rec.markPickedUp(r, now);
}

// ---------------------------------------------------------------------------
// 1. buildRecipients, regel 79-80: tokens[email] = token
// Een ontvanger die '__proto__' heet slikt zijn eigen token op. De setter van
// __proto__ negeert een string, dus het record bestaat wel maar het token is
// nergens meer op te halen. Gevolg: die persoon kan nooit ophalen, allSettled
// wordt nooit waar en de blob blijft tot de TTL staan.
// ---------------------------------------------------------------------------
test('gat 1: een ontvanger die __proto__ heet laat zijn token verdwijnen', () => {
  const built = rec.buildRecipients('community', ['__proto__'], undefined, sealedVoor(['__proto__']));
  if (!built.ok) return; // het adres weigeren dicht het gat ook

  const tokens = uitgedeeldeTokens(built.tokens);
  assert.equal(tokens.length, built.records.length,
    'elk aangemaakt record moet een token hebben dat de caller kan versturen');

  for (const r of built.records) {
    assert.ok(tokens.some(t => rec.tokenHash(t) === r.token_hash),
      `record ${r.email} heeft een token_hash waar geen uitgedeeld token bij hoort`);
  }
});

test('gat 1b: een onbereikbaar record houdt de blob eeuwig in de lucht', () => {
  const built = rec.buildRecipients('pro', ['__proto__', 'anna@example.org'], undefined, sealedVoor(['__proto__', 'anna@example.org']));
  if (!built.ok) return;

  for (const t of uitgedeeldeTokens(built.tokens)) haalOp(built.records, t, 1000);

  assert.equal(rec.allSettled(built.records), true,
    'iedereen die een token kreeg heeft opgehaald, dus de blob mag weg; ' +
    'nu blijft hij staan door een record waarvan het token nooit bestond');
});

// ---------------------------------------------------------------------------
// 2. tiers.checkRecipients, regel 176: String(raw).trim().toLowerCase()
// Er is nergens adresvalidatie. Een geneste array of een komma in een string
// telt als EEN ontvanger maar is op de SMTP-lijn er twee. Een community-account
// met max_recipients = 1 bereikt zo twee mensen, met hetzelfde token.
// ---------------------------------------------------------------------------
test('gat 2: komma-smokkel geeft een gratis account meer dan een ontvanger', () => {
  const genest = tiers.checkRecipients('community', [['a@example.org', 'b@example.org']]);
  assert.equal(genest.ok, false,
    'een geneste array wordt een komma-string en telt als een ontvanger');

  const komma = rec.buildRecipients('community', ['a@example.org, b@example.org'], undefined, sealedVoor(['a@example.org, b@example.org']));
  assert.equal(komma.ok, false,
    'twee adressen in een veld tellen als een, en delen dan ook nog een token');
});

test('gat 2b: een adres met een newline smokkelt mailheaders mee', () => {
  const built = rec.buildRecipients('community', ['a@example.org\nBcc: evil@example.org'], undefined, sealedVoor(['a@example.org\nBcc: evil@example.org']));
  if (!built.ok) return;

  for (const r of built.records) {
    assert.ok(!/[\u0000-\u001f\u007f]/.test(r.email),
      `het opgeslagen adres bevat een stuurteken: ${JSON.stringify(r.email)}`);
  }
});

test('gat 2c: willekeurige rommel wordt als adres geaccepteerd', () => {
  for (const rommel of [{}, 12345, true, ['x']]) {
    const built = rec.buildRecipients('community', [rommel], undefined, sealedVoor([rommel]));
    assert.equal(built.ok, false,
      `${JSON.stringify(rommel)} is geen adres maar wordt wel een ontvanger ` +
      `(${JSON.stringify(built.records[0] && built.records[0].email)})`);
  }
});

test('gat 2d: er staat geen maximum op de lengte van een adres', () => {
  const lang = 'a'.repeat(1_000_000) + '@example.org';
  const built = rec.buildRecipients('community', [lang], undefined, sealedVoor([lang]));
  if (!built.ok) return;

  assert.ok(built.records[0].email.length <= 254,
    `een adres van ${built.records[0].email.length} tekens wordt gehasht en ` +
    'opgeslagen; RFC 5321 stopt bij 254');
});

// ---------------------------------------------------------------------------
// 3. tiers.checkRecipients, regel 175-187
// De volledige lijst wordt eerst opgebouwd en daarna pas tegen de limiet
// gehouden, en komt ook bij afwijzing compleet terug. Een gratis account met
// limiet 1 laat de relay zo een lijst van willekeurige lengte materialiseren.
// ---------------------------------------------------------------------------
test('gat 3: een afgewezen send bouwt eerst de hele lijst in het geheugen', () => {
  const veel = Array.from({ length: 100_000 }, (_, i) => `p${i}@example.org`);
  const r = tiers.checkRecipients('community', veel);

  assert.equal(r.ok, false);
  assert.ok(r.recipients.length <= 1000,
    `de afwijzing draagt ${r.recipients.length} genormaliseerde adressen mee; ` +
    'boven de limiet hoort de lus te stoppen in plaats van door te tellen');
});

// ---------------------------------------------------------------------------
// 4. recipients.findByToken, regel 96-98 -> tokenHash, regel 48-54
// Het aangeboden token wordt integraal gehasht. Geen lengtecap, dus de
// aanvaller bepaalt hoeveel rekenwerk een ongeauthenticeerd pickup-verzoek
// kost. Een echt token is 43 tekens.
// ---------------------------------------------------------------------------
test('gat 4: een token van 10 MB wordt gewoon gehasht (geen lengtecap)', () => {
  const built = rec.buildRecipients('pro', ['a@example.org'], undefined, sealedVoor(['a@example.org']));
  const echt = rec.newPickupToken();

  const meet = (tok, n) => {
    const s = process.hrtime.bigint();
    for (let i = 0; i < n; i++) rec.findByToken(built.records, tok);
    return Number(process.hrtime.bigint() - s) / 1e6 / n;
  };
  meet(echt, 200); // opwarmen

  const kort = meet(echt, 500);
  const groot = meet('x'.repeat(10 * 1024 * 1024), 3);

  assert.ok(groot < Math.max(kort * 25, 1),
    `een token van 10 MB kost ${groot.toFixed(2)} ms tegen ${kort.toFixed(4)} ms ` +
    'voor een echt token; de lengte hoort begrensd te zijn voordat er gehasht wordt');
});

// ---------------------------------------------------------------------------
// 5. recipients.reinvite, regel 130-138: record.revoked_at = null
// Intrekken is niet definitief. Een re-invite zet revoked_at terug op null en
// geeft een werkend token. In de overview is er daarna geen spoor meer van de
// intrekking: de status staat weer op 'waiting'.
// ---------------------------------------------------------------------------
test('gat 5: een re-invite wekt een ingetrokken ontvanger weer tot leven', () => {
  const built = rec.buildRecipients('pro', ['weg@example.org'], undefined, sealedVoor(['weg@example.org']));
  const record = rec.findByToken(built.records, tokenVoor(built, 'weg@example.org'));

  assert.equal(rec.revoke(record, 100), true);
  const nieuw = rec.reinvite(record, 200);

  assert.equal(nieuw, null,
    'een ingetrokken ontvanger hoort niet via de herinnerknop terug te komen');
  assert.ok(record.revoked_at,
    'revoked_at is stilletjes gewist, dus de intrekking is uit de administratie verdwenen');
});

// ---------------------------------------------------------------------------
// 6. recipients.allSettled, regel 142-146 in combinatie met reinvite
// allSettled is de trigger om de blob te laten vallen. Zodra hij waar is geweest
// mag hij niet meer terug naar onwaar, anders krijgt iemand een werkende link
// naar een blob die al weg is.
// ---------------------------------------------------------------------------
test('gat 6: re-invite draait allSettled terug nadat de blob al weg mocht', () => {
  const built = rec.buildRecipients('pro', ['x@example.org', 'y@example.org'], undefined, sealedVoor(['x@example.org', 'y@example.org']));
  const x = rec.findByToken(built.records, tokenVoor(built, 'x@example.org'));
  const y = rec.findByToken(built.records, tokenVoor(built, 'y@example.org'));

  rec.revoke(x, 100);
  haalOp(built.records, tokenVoor(built, 'y@example.org'), 100);
  assert.equal(rec.allSettled(built.records), true, 'de blob mag hier weg');

  rec.reinvite(x, 200);
  assert.equal(rec.allSettled(built.records), true,
    'na een re-invite staat de send weer open terwijl de blob al opgeruimd is; ' +
    'x krijgt een werkend token naar niets');
});

// ---------------------------------------------------------------------------
// 7. recipients.markPickedUp, regel 116-120
// markPickedUp kijkt naar het RECORD, niet naar het token waarmee het record
// gevonden is. Een verzoek dat al binnen was met het oude token haalt daarna
// alsnog op, terwijl regel 19 belooft dat het oude token op dat moment sterft.
// ---------------------------------------------------------------------------
test('gat 7: een herinnering laat de link heel, want een nieuwe ging nooit open', () => {
  // Dit gat werd gedicht door de oorzaak weg te nemen in plaats van het gevolg.
  // Een nieuw token kon de wikkeling in de opslag niet openen en de relay kan
  // niet opnieuw wikkelen, want hij heeft de bestandssleutel niet. De
  // ontvanger verbrandde dus zijn eenmalige link op bytes die nergens mee
  // opengingen. Een herinnering wijst nu naar de uitnodiging die hij al heeft.
  const built = rec.buildRecipients('pro', ['bob@example.org'], undefined, sealedVoor(['bob@example.org']));
  const token = tokenVoor(built, 'bob@example.org');
  const record = rec.findByToken(built.records, token);

  rec.reinvite(record, 300);

  assert.ok(rec.findByToken(built.records, token), 'zijn link blijft vindbaar');
  assert.equal(rec.markPickedUp(record, 400, token), true, 'en haalt gewoon op');
  assert.equal(rec.markPickedUp(record, 500, token), false, 'maar precies een keer');
});

// ---------------------------------------------------------------------------
// 8. recipients.findByToken + pickupRefusal + markPickedUp
// Er is geen enkele stap die een token opzoekt en in dezelfde handeling opeist.
// Een streamende relay kan niet eerst markeren (dan verbrandt een afgebroken
// download het token), dus het venster tussen kijken en markeren is echt.
// ---------------------------------------------------------------------------
test('gat 8: twee gelijktijdige verzoeken krijgen allebei de blob', async () => {
  const built = rec.buildRecipients('pro', ['race@example.org'], undefined, sealedVoor(['race@example.org']));
  const token = tokenVoor(built, 'race@example.org');
  let uitgeleverd = 0;

  async function pickup() {
    // Met een atomaire stap is dit veilig; die bestaat nu niet.
    if (typeof rec.claimPickup === 'function') {
      if (!rec.claimPickup(built.records, token, 500)) return 'geweigerd';
      await new Promise(r => setImmediate(r));
      uitgeleverd += 1;
      return 'geteld';
    }
    // Zonder atomaire stap is dit de enige volgorde die werkt: eerst markeren
    // zou het token verbranden op een download die halverwege afbreekt.
    const record = rec.findByToken(built.records, token);
    if (rec.pickupRefusal(record)) return 'geweigerd';
    await new Promise(r => setImmediate(r)); // de blob gaat over de lijn
    uitgeleverd += 1;
    return rec.markPickedUp(record, 500, token) ? 'geteld' : 'niet geteld';
  }

  await Promise.all([pickup(), pickup()]);

  assert.equal(uitgeleverd, 1,
    'de blob ging twee keer over de lijn terwijl de teller op een blijft staan');
  assert.equal(rec.overview(built.records).collected, 1);
});

// ---------------------------------------------------------------------------
// 9. tiers.checkRecipients, regel 176: alleen trim + toLowerCase
// Geen NFC. Twee unicode-schrijfwijzen van hetzelfde postvak zijn twee
// ontvangers met twee tokens. Wie er een intrekt heeft niets ingetrokken: het
// tweede token in hetzelfde postvak werkt gewoon door.
// ---------------------------------------------------------------------------
test('gat 9: unicode-varianten van een postvak leveren twee losse tokens', () => {
  const nfd = 'ann' + 'a\u0308' + '@example.org'; // a + combinerend trema
  const nfc = 'ann\u00e4@example.org';            // voorgecomponeerde a-umlaut
  assert.equal(nfd.normalize('NFC'), nfc, 'dit is hetzelfde adres');

  const r = tiers.checkRecipients('pro', [nfd, nfc]);
  assert.ok(r.count <= 1,
    `twee schrijfwijzen van hetzelfde postvak leveren ${r.count} ontvangers op; ` +
    'die persoon krijgt twee losse tokens, dus een intrekking haalt er maar een weg ' +
    '(vouwen naar een, of allebei weigeren, sluit het allebei)');
});

test('gat 9b: de hoofdletter I met punt vouwt niet terug op i', () => {
  const r = tiers.checkRecipients('pro', ['\u0130nfo@example.org', 'info@example.org']);
  assert.ok(r.count <= 1,
    `I-met-punt en i leveren ${r.count} ontvangers op voor een postvak`);
});

// ---------------------------------------------------------------------------
// 10. recipients.findByToken regel 100-101, allSettled regel 145, overview 150
// Een gat in de tabel (een null uit een halve deserialisatie) laat de
// ongeauthenticeerde pickup-route omvallen met een TypeError in plaats van
// nette 404.
// ---------------------------------------------------------------------------
test('gat 10: een lege plek in de tabel laat de pickup-route crashen', () => {
  const built = rec.buildRecipients('pro', ['anna@example.org'], undefined, sealedVoor(['anna@example.org']));
  const kapot = [null, ...built.records];
  const token = tokenVoor(built, 'anna@example.org');

  assert.doesNotThrow(() => rec.findByToken(kapot, token),
    'findByToken valt om op een null-rij');
  assert.doesNotThrow(() => rec.allSettled(kapot), 'allSettled valt om op een null-rij');
  assert.doesNotThrow(() => rec.overview(kapot), 'overview valt om op een null-rij');
});

// ---------------------------------------------------------------------------
// 11. recipients.recipientEmailHash, regel 34-41
// De hash is ongezouten en ongesleuteld over een invoer met weinig entropie.
// Wie een adres raadt, bevestigt het offline tegen de opgeslagen hash. Overal
// waar email_hash zonder de platte tekst terechtkomt (logs, kruisverwijzing
// met ParaSign, een half dump) is dat geen pseudoniem maar het adres zelf.
// ---------------------------------------------------------------------------
test('gat 11: email_hash is offline terug te rekenen door te raden', () => {
  const built = rec.buildRecipients('pro', ['Anna@Example.org'], undefined, sealedVoor(['Anna@Example.org']));
  const geraden = rec.recipientEmailHash('anna@example.org');

  assert.notEqual(built.records[0].email_hash, geraden,
    'een geraden adres bevestigt zichzelf tegen de opgeslagen hash; ' +
    'er zit geen sleutel of zout per send in');
});
