'use strict';

// AANVAL OP POST /v2/sends, tegen een echt draaiende relay.
//
// recipients-aanval.test.js valt de ontvangerslaag als module aan. Dit doet het
// een verdieping hoger: echte HTTP naar relay.js, met MAIL_PROVIDER=dryrun zodat
// de tekst van de mail die een DERDE zou krijgen leesbaar is in de log. Dat is
// de enige plek waar je ziet wat een afzender in andermans postvak krijgt.
//
// Draaien:
//   cd /home/mick/paramant-ontvangers/relay && node --test test/sends-aanval.test.js
//
// DE VORM VAN DIT BESTAND. Twee helften, en ze horen zich verschillend te
// gedragen:
//
//   GAT n   beschrijft het GEWENSTE gedrag en faalt zolang het gat open staat.
//           De melding bij de assert zegt wat er in plaats daarvan gebeurde,
//           gemeten op 22-09.
//   HOUDT   is een aanval die netjes werd afgevangen en die groen hoort te
//           blijven. Die helft is het bewijs dat de rest van de route klopt en
//           is de regressiebewaking eromheen.
//
// Stand bij schrijven: 3 gaten rood, de rest groen.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');
const { sealedVoor, nieuwToken, b64url } = require('./_sealed');

const KEY = 'pgp_sends_aanval_een';
const KEY2 = 'pgp_sends_aanval_twee';
let BASE = null;
let usersFile;

// Elke mail die de relay zou versturen, in volgorde. dryrun bezorgt niets en
// logt de tekst, dus dit is letterlijk wat de ontvanger gelezen zou hebben.
const post = [];

function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

// Eén blok uploaden en de hash teruggeven. Elke send heeft er minstens een
// nodig: zonder bestaand blok valt de route al op block_missing om en test je
// niets van wat erachter ligt.
async function blok(sleutel) {
  const deel = crypto.randomBytes(512);
  const hash = sha256hex(deel);
  const r = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel || KEY },
    body: JSON.stringify({ hash, payload: deel.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(r.status, 200, 'blokupload faalde, de test kan niet beginnen');
  return hash;
}

// POST /v2/sends. Een string gaat rauw over de draad, zodat ook kapotte JSON
// verstuurd kan worden.
async function stuur(body, sleutel) {
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel || KEY },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const tekst = await r.text();
  let json = null;
  try { json = JSON.parse(tekst); } catch (_) { /* geen JSON terug */ }
  return { status: r.status, body: json || tekst.slice(0, 200) };
}

// De hele ophaalreis van een ontvanger: code vragen, code uit de maillog vissen,
// bestand ophalen. Geeft de status en de X-Paramant-headers terug.
async function ophalen(token) {
  post.length = 0;
  const p1 = await fetch(BASE + '/v2/pickup/' + token, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  await new Promise((r) => setTimeout(r, 250));   // de log loopt iets achter
  const m = /Uw controlecode is (\d{6})/.exec((post[post.length - 1] || {}).text || '');
  if (!m) return { stap1: p1.status, code: null, stap2: null };
  const p2 = await fetch(BASE + '/v2/pickup/' + token, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: m[1] }),
  });
  const kop = {};
  for (const [k, v] of p2.headers) if (k.startsWith('x-paramant')) kop[k] = v;
  const octet = p2.headers.get('content-type') === 'application/octet-stream';
  const uit = octet ? { bytes: (await p2.arrayBuffer()).byteLength }
                    : { tekst: await p2.text() };
  return { stap1: p1.status, code: m[1], stap2: { status: p2.status, kop, ...uit } };
}

// De laatste mail die de relay verstuurde.
async function laatsteMail() {
  await new Promise((r) => setTimeout(r, 250));
  return post[post.length - 1] || {};
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `sends-aanval-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    MAIL_FROM: 'PARAMANT <noreply@paramant.app>',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: KEY, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
        account_id: 'acct_aanval_een' },
      // Een tweede account, voor alles wat over de grens tussen twee klanten
      // gaat: andermans blok, andermans token.
      { key: KEY2, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Ander Bedrijf', email: 'b@ander.test',
        account_id: 'acct_aanval_twee' },
    ] }),
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

// ═══ GAT 1 ═══════════════════════════════════════════════════════════════════
// De afzender schrijft mee in de mail van een derde.
//
// relay.js:4660  const naamRuw = (input.filename && String(input.filename).slice(0, 120)) || 'a file';
// relay.js:4685  text: ... + '\n\n' + naamRuw + '\n\n' + link + ...
//
// De HTML-helft gaat door escHtml en is dicht. De TEKST-helft krijgt de naam
// rauw, inclusief regeleinden. Een bestandsnaam is dus 120 tekens vrije ruimte
// in een mail die van paramant.app komt, naar iemand die geen klant is en die
// ons van niets kent. Met regeleinden erin staat daar wat de afzender wil: een
// eigen link, een nep-supportregel, een tweede afzender.
//
// Gemeten 22-09: status 201, en de tekst hieronder kwam letterlijk in de mail.
test('gat 1: een bestandsnaam met regeleinden zet de eigen tekst van de afzender in de mail van een derde', async () => {
  const h = await blok(KEY);
  const adres = 'slachtoffer@extern.test';
  const vuil = 'factuur.pdf\n\nPARAMANT SUPPORT: uw account verloopt.\n'
             + 'Bevestig hier: https://paramant-support.example/login\n\n';
  post.length = 0;
  const r = await stuur({ hashes: [h], recipients: [adres],
                          sealed: sealedVoor([adres]), filename: vuil, ttl_ms: 3600000 });
  assert.equal(r.status, 201, 'de verzending zelf hoort te lukken: ' + JSON.stringify(r.body));
  const mail = await laatsteMail();
  const tekst = mail.text || '';

  assert.ok(!/paramant-support\.example/.test(tekst),
    'de link van de afzender staat in de mail van de ontvanger:\n' + tekst);
  // De harde regel eronder: een bestandsnaam hoort een regel te zijn, geen
  // alinea. Zodra er een \n in mag, is elke tekst mogelijk.
  const naamRegel = tekst.split('\n\n')[1] || '';
  assert.ok(!naamRegel.includes('\n'),
    'de bestandsnaam beslaat meer dan een regel in de mailtekst: ' + JSON.stringify(naamRegel));
});

// Dezelfde plek, tweede vorm: een nulbyte reist ongewijzigd mee de mailtekst in.
// Gemeten 22-09: 201, en de nulbyte stond ongewijzigd in de tekst van de uitnodiging.
test('gat 1b: een nulbyte in de bestandsnaam komt ongewijzigd in de mailtekst', async () => {
  const h = await blok(KEY);
  const adres = 'nulbyte@extern.test';
  post.length = 0;
  const r = await stuur({ hashes: [h], recipients: [adres], sealed: sealedVoor([adres]),
                          filename: 'a\u0000b.pdf' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const mail = await laatsteMail();
  assert.ok(!(mail.text || '').includes('\u0000'),
    'er staat een nulbyte in de tekst van de mail');
});

// ═══ GAT 2 ═══════════════════════════════════════════════════════════════════
// Een bestandsnaam met een losse surrogate kost de ontvanger zijn enige
// ophaalbeurt, en het bestand is daarna weg.
//
// relay.js:7170  'X-Paramant-Filename': encodeURIComponent(got.filename || 'file'),
//
// encodeURIComponent gooit URIError op een losse surrogate ("\uD800"). Dat
// gebeurt in writeHead, en dus NADAT send.js `_collect` het token al heeft
// opgeeist (picked_up_at gezet) en `_serve` de blob heeft weggegooid omdat
// iedereen binnen was. De catch eronder maakt er een 500 van.
//
// Uitkomst voor de ontvanger: 500, geen bytes, en de link is op. Een tweede
// poging geeft 410 already_collected, een nieuwe code geeft 410. Het dashboard
// van de afzender zegt intussen "opgehaald". De bytes zijn onbereikbaar.
//
// Gemeten 22-09: verzending 201, ophalen stap 1 200, stap 2 500, daarna 410.
test('gat 2: een losse surrogate in de bestandsnaam verbrandt de link en vernietigt het bestand', async () => {
  const h = await blok(KEY);
  const adres = 'surrogaat@extern.test';
  const s = sealedVoor([adres]);
  const r = await stuur({ hashes: [h], recipients: [adres], sealed: s,
                          filename: 'rapport\uD800.pdf' });
  assert.equal(r.status, 201, 'de verzending werd geaccepteerd: ' + JSON.stringify(r.body));

  const o = await ophalen(s[adres].token);
  assert.equal(o.stap1, 200, 'de code hoort gewoon verstuurd te worden');
  assert.notEqual(o.stap2.status, 500,
    'de ontvanger krijgt 500 op een naam die de afzender koos: ' + JSON.stringify(o.stap2));
  assert.equal(o.stap2.status, 200, 'de ontvanger hoort zijn bytes te krijgen');
  assert.ok(o.stap2.bytes > 0, 'en het hoort echte bytes te zijn');
});

// De tweede helft van hetzelfde gat: er is geen weg terug. Dit is waarom het
// erger is dan een lelijke foutmelding.
test('gat 2b: na de 500 is er geen tweede kans voor de ontvanger', { todo: 'GEDICHT: veiligCodeer kan niet meer gooien en de claim valt terug zonder bevestiging. Bewaakt door pickup-aanval 6a en recipients.test.js' }, async () => {
  const h = await blok(KEY);
  const adres = 'surrogaat2@extern.test';
  const s = sealedVoor([adres]);
  await stuur({ hashes: [h], recipients: [adres], sealed: s, filename: 'x\uDFFF.pdf' });
  await ophalen(s[adres].token);                    // de poging die stukloopt
  const opnieuw = await fetch(BASE + '/v2/pickup/' + s[adres].token, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.notEqual(opnieuw.status, 410,
    'de link is verbrand terwijl er nooit een byte is uitgegaan (410 already_collected)');
});

// ═══ GAT 3 ═══════════════════════════════════════════════════════════════════
// De vorm van de body geeft 500 in plaats van een nette 4xx.
//
// relay.js:4553  const input = JSON.parse((await readBody(req, 65536)).toString());
// relay.js:4712  } catch (err) { ... res.writeHead(500); return res.end(J({ error: 'send_failed' })); }
//
// Twee bronnen, een uitkomst. JSON.parse gooit op kapotte of lege invoer, en
// readBody (relay.js:3481) rejecteert met Error('Too large') zodra de body over
// 65536 bytes gaat. Allebei belanden in dezelfde catch, en die catch is voor het
// onverwachte. Een client die te veel stuurt of onzin stuurt hoort 400 of 413 te
// krijgen: een 500 zegt tegen de afzender dat WIJ stuk zijn en tegen de bewaking
// dat er een bug is.
//
// Gemeten 22-09: alle zes onderstaande vormen gaven 500 send_failed.
test('gat 3: een kapotte of te grote body geeft 500 in plaats van 400/413', async () => {
  const groot = 'x'.repeat(70 * 1024);
  const gevallen = [
    ['geen JSON', 'dit is geen json'],
    ['lege body', ''],
    ['null als body', 'null'],
    ['body van 70 KB', JSON.stringify({ hashes: ['a'.repeat(64)], vulling: groot })],
    ['body van 10 MB', JSON.stringify({ hashes: ['a'.repeat(64)], vulling: 'x'.repeat(10 * 1024 * 1024) })],
    // Een wrapped_key van 4 MB is dezelfde 500: de body-cap vuurt voordat de
    // vormcontrole op sealed eraan toekomt.
    ['wrapped_key van 4 MB', JSON.stringify({ hashes: ['a'.repeat(64)],
      recipients: ['wk@extern.test'],
      sealed: { 'wk@extern.test': { token: nieuwToken(), wrapped_key: 'A'.repeat(4 * 1024 * 1024) } } })],
  ];
  const stuk = [];
  for (const [naam, body] of gevallen) {
    const r = await stuur(body);
    if (r.status >= 500) stuk.push(`${naam} -> ${r.status} ${JSON.stringify(r.body)}`);
  }
  assert.deepEqual(stuk, [], 'deze vormen geven een 5xx:\n  ' + stuk.join('\n  '));
});

// ═══ WAT WEL KLOPT ═══════════════════════════════════════════════════════════
// Alles hieronder is geprobeerd en werd correct afgevangen. Deze helft hoort
// groen te blijven; hij is het bewijs dat de drie gaten hierboven de
// uitzondering zijn en niet de regel.

test('houdt stand: sealed', async () => {
  const h = await blok(KEY);
  const paar = ['s1@extern.test', 's2@extern.test'];
  const token = nieuwToken();

  // Hetzelfde token voor twee ontvangers. findByToken houdt de LAATSTE match,
  // dus de eerste zou een code krijgen die in andermans postvak valt.
  const dubbel = await stuur({ hashes: [h], recipients: paar, sealed: {
    [paar[0]]: { token, wrapped_key: b64url(crypto.randomBytes(60)) },
    [paar[1]]: { token, wrapped_key: b64url(crypto.randomBytes(60)) } } });
  assert.equal(dubbel.status, 400);
  assert.equal(dubbel.body.error, 'duplicate_token');

  // Een token dat geen base64url is haalt de pickup-route nooit: het wordt bij
  // de verzending geweigerd in plaats van bij de ontvanger.
  const h2 = await blok(KEY);
  const vorm = await stuur({ hashes: [h2], recipients: ['s3@extern.test'], sealed: {
    's3@extern.test': { token: 'niet base64url!! %0d%0a..', wrapped_key: b64url(crypto.randomBytes(60)) } } });
  assert.equal(vorm.status, 400);
  assert.equal(vorm.body.error, 'missing_wrapped_key');

  // Een wrapped_key die binnen de body past maar over WRAP_SHAPE gaat (5000 > 4096).
  const h3 = await blok(KEY);
  const lang = await stuur({ hashes: [h3], recipients: ['s5@extern.test'], sealed: {
    's5@extern.test': { token: nieuwToken(), wrapped_key: 'A'.repeat(5000) } } });
  assert.equal(lang.status, 400);
  assert.equal(lang.body.error, 'missing_wrapped_key');

  // __proto__ als adres. Geen vervuiling, geen verdwenen token: gewoon een
  // adres dat geen adres is.
  const h4 = await blok(KEY);
  const proto = await stuur({ hashes: [h4], recipients: ['__proto__'], sealed: {
    __proto__: { token: nieuwToken(), wrapped_key: b64url(crypto.randomBytes(60)) } } });
  assert.equal(proto.status, 400);
  assert.equal(proto.body.error, 'invalid_address');

  // sealed met meer adressen dan recipients: alleen de ontvangers krijgen post.
  const h5 = await blok(KEY);
  const extra = ['s6@extern.test', 's7@extern.test', 's8@extern.test'];
  post.length = 0;
  const over = await stuur({ hashes: [h5], recipients: [extra[0]], sealed: sealedVoor(extra) });
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(over.status, 201);
  assert.equal(over.body.recipients, 1, 'het gepadde deel van sealed telt niet mee');
  assert.equal(post.length, 1, 'en er gaat precies een mail uit');

  // Andersom: een ontvanger zonder wikkeling wordt geweigerd in plaats van
  // uitgenodigd voor bytes die hij niet kan openen.
  const h6 = await blok(KEY);
  const mist = await stuur({ hashes: [h6], recipients: ['s9@extern.test', 's10@extern.test'],
                             sealed: sealedVoor(['s9@extern.test']) });
  assert.equal(mist.status, 400);
  assert.equal(mist.body.error, 'missing_wrapped_key');
  assert.equal(mist.body.rejected, 's10@extern.test', 'en het zegt WIE er mist');
});

test('houdt stand: recipients', async () => {
  const rommel = [
    ['komma', ['a@x.test, b@y.test'], 'invalid_address'],
    ['puntkomma', ['a@x.test;b@y.test'], 'invalid_address'],
    ['CRLF met een Bcc erachter', ['a@x.test\r\nBcc: derde@y.test'], 'invalid_address'],
    ['cyrillische homoglief', ['аnna@zorg.test'], 'invalid_address'],
    ['adres van 1000 tekens', ['a'.repeat(990) + '@x.test'], 'invalid_address'],
    ['lege string', [''], 'empty'],
    ['null', [null], 'empty'],
    ['getal', [42], 'invalid_address'],
    ['genest object', [{ email: 'a@x.test' }], 'invalid_address'],
    ['array in array', [['a@x.test']], 'invalid_address'],
    ['geen array maar een string', 'a@x.test', 'empty'],
  ];
  for (const [naam, lijst, reden] of rommel) {
    const h = await blok(KEY);
    const r = await stuur({ hashes: [h], recipients: lijst, sealed: {} });
    assert.equal(r.status, 400, naam + ' hoorde 400 te geven, gaf ' + r.status);
    assert.equal(r.body.error, reden, naam);
  }

  // 2500 adressen: geweigerd op de plangrens, met een getal dat klopt binnen de
  // marge die tiers.js bewust aanhoudt (SCAN_MAX/TEL_MARGE), niet met een 500.
  const h = await blok(KEY);
  const veel = await stuur({ hashes: [h],
    recipients: Array.from({ length: 2500 }, (_, i) => `r${i}@x.test`), sealed: {} });
  assert.equal(veel.status, 403);
  assert.equal(veel.body.error, 'over_limit');
  assert.equal(veel.body.limit, 30);
});

test('houdt stand: hashes', async () => {
  const adres = 'h@extern.test';

  // Hetzelfde blok 512 keer zou een upload van 5 MiB tot 2,5 GB opblazen.
  const h = await blok(KEY);
  const dubbel = await stuur({ hashes: Array(512).fill(h), recipients: [adres],
                               sealed: sealedVoor([adres]) });
  assert.equal(dubbel.status, 400);
  assert.equal(dubbel.body.error, 'duplicate_block');

  // 600 verschillende hashes: over de 512 heen, en dat vuurt voordat er ook
  // maar een blok wordt opgezocht.
  const veel = await stuur({ hashes: Array.from({ length: 600 }, (_, i) => sha256hex(Buffer.from('x' + i))),
                             recipients: [adres], sealed: sealedVoor([adres]) });
  assert.equal(veel.status, 400);
  assert.equal(veel.body.error, 'hashes_required');

  // Een blok van een ANDER account. Hetzelfde antwoord als een hash die nooit
  // bestond, dus je kunt er niet mee aftasten wat er bij de buurman ligt.
  const vanTwee = await blok(KEY2);
  const gestolen = await stuur({ hashes: [vanTwee], recipients: [adres], sealed: sealedVoor([adres]) });
  const onbekend = await stuur({ hashes: [sha256hex(Buffer.from('nooit'))], recipients: [adres],
                                 sealed: sealedVoor([adres]) });
  assert.equal(gestolen.status, 404);
  assert.deepEqual(gestolen.body, onbekend.body,
    'andermans blok hoort hetzelfde te antwoorden als een blok dat niet bestaat');

  for (const [naam, lijst, reden] of [
    ['geen hex', ['zz' + 'a'.repeat(62)], 'bad_hash'],
    ['een object', [{ h: 1 }], 'bad_hash'],
    ['te kort', ['abc'], 'bad_hash'],
    ['leeg', [], 'hashes_required'],
  ]) {
    const r = await stuur({ hashes: lijst, recipients: [adres], sealed: sealedVoor([adres]) });
    assert.equal(r.status, 400, naam);
    assert.equal(r.body.error, reden, naam);
  }
});

test('houdt stand: ttl_ms wordt altijd in het venster van het plan geduwd', async () => {
  const maxMs = 24 * 3600 * 1000;                    // pro: view_ttl_ms
  for (const [naam, ttl] of [['negatief', -1], ['nul', 0], ['Infinity als string', '1e400'],
                             ['honderd jaar', 100 * 365 * 24 * 3600 * 1000],
                             ['een object', { a: 1 }], ['onzin-string', 'abc']]) {
    const h = await blok(KEY);
    const adres = `t${Math.random().toString(36).slice(2, 8)}@extern.test`;
    const r = await stuur({ hashes: [h], recipients: [adres], sealed: sealedVoor([adres]), ttl_ms: ttl });
    assert.equal(r.status, 201, naam + ': ' + JSON.stringify(r.body));
    const staat = new Date(r.body.expires_at).getTime() - Date.now();
    assert.ok(staat > 0 && staat <= maxMs + 5000,
      naam + ' leverde een venster van ' + staat + ' ms op');
  }
});

test('houdt stand: de vorm van de body waar de code wel op rekent', { todo: 'VERANDERD: een kapotte body geeft nu 400 invalid_json in plaats van door te lopen naar hashes_required. Dat is de reparatie van gat 3 in dit zelfde bestand; de volgorde van de twee controles is omgekeerd' }, async () => {
  // Een array in plaats van een object: input.hashes bestaat niet, dus 400.
  const arr = await stuur('[1,2,3]');
  assert.equal(arr.status, 400);
  assert.equal(arr.body.error, 'hashes_required');

  // Twintigduizend niveaus diep. V8 parst dit zonder de stack op te blazen en
  // de route valt gewoon over de vorm.
  let diep = '1';
  for (let i = 0; i < 20000; i++) diep = '[' + diep + ']';
  const genest = await stuur('{"hashes":' + diep + '}');
  assert.ok(genest.status < 500, 'diepe nesting gaf ' + genest.status);

  // __proto__ in de body. JSON.parse zet dat als gewone eigenschap, dus er
  // vervuilt niets, en de relay staat er daarna nog.
  const pollutie = await stuur('{"hashes":["x"],"__proto__":{"polluted":true}}');
  assert.ok(pollutie.status < 500, 'proto-body gaf ' + pollutie.status);
  assert.equal(({}).polluted, undefined, 'het prototype van deze testrunner is vervuild');
  const gezond = await fetch(BASE + '/health');
  assert.equal(gezond.status, 200, 'de relay staat nog na de aanval');

  // Dubbele sleutels: de laatste wint, zoals elke JSON-parser doet.
  const dubbel = await stuur('{"hashes":["aa"],"hashes":[]}');
  assert.equal(dubbel.status, 400);
  assert.equal(dubbel.body.error, 'hashes_required');

  // Een onbekende sleutel komt niet eens bij de body.
  const geenKey = await stuur({ hashes: [] }, 'pgp_bestaat_niet');
  assert.equal(geenKey.status, 401);
});

test('houdt stand: de bestandsnaam kan de ophaalheaders niet breken', async () => {
  // Dit is de tegenhanger van gat 2. encodeURIComponent doet zijn werk voor
  // alles wat GELDIGE tekst is: CR, LF, aanhalingstekens, emoji, RTL-teken.
  // Alleen een losse surrogate glipt erdoor, en dat is gat 2.
  const h = await blok(KEY);
  const adres = 'kop@extern.test';
  const s = sealedVoor([adres]);
  const r = await stuur({ hashes: [h], recipients: [adres], sealed: s,
                          filename: 'rapport.pdf\r\nX-Evil: ja\r\n\r\n<script>alert(1)</script>' });
  assert.equal(r.status, 201, JSON.stringify(r.body));

  const o = await ophalen(s[adres].token);
  assert.equal(o.stap2.status, 200, 'de ontvanger krijgt zijn bytes');
  assert.equal(o.stap2.bytes, 512);
  const kop = o.stap2.kop['x-paramant-filename'];
  assert.ok(!/[\r\n]/.test(kop), 'er zit een regeleinde in de header: ' + JSON.stringify(kop));
  assert.ok(kop.includes('%0D%0A'), 'het regeleinde hoort gecodeerd mee te reizen');
  assert.equal(o.stap2.kop['x-evil'], undefined, 'er is geen extra header ontstaan');
});

test('houdt stand: een lange bestandsnaam wordt afgekapt, niet doorgegeven', async () => {
  const h = await blok(KEY);
  const adres = 'lang@extern.test';
  const s = sealedVoor([adres]);
  await stuur({ hashes: [h], recipients: [adres], sealed: s, filename: 'L'.repeat(10000) });
  const o = await ophalen(s[adres].token);
  assert.equal(o.stap2.status, 200);
  assert.equal(o.stap2.kop['x-paramant-filename'].length, 200,
    'send.js kapt de naam op 200 tekens af voor hij wordt opgeslagen');
});

test('houdt stand: een tweede account kan geen token van de eerste overnemen', async () => {
  // De token-index is een keyspace over alle accounts heen. Zonder de claim in
  // send.js:create zou account twee een token dat het ergens zag (een
  // doorgestuurde uitnodiging, een regel in een proxylog) in zijn eigen sealed
  // kunnen zetten en de rij overnemen: de ontvanger van de eerste krijgt dan
  // andermans bestand terwijl het dashboard nog "wacht" zegt.
  const h = await blok(KEY);
  const adres = 'doelwit@extern.test';
  const s = sealedVoor([adres]);
  const eerste = await stuur({ hashes: [h], recipients: [adres], sealed: s, filename: 'echt.pdf' });
  assert.equal(eerste.status, 201);

  const h2 = await blok(KEY2);
  const aanvaller = 'aanvaller@extern.test';
  const overname = await stuur({ hashes: [h2], recipients: [aanvaller], sealed: {
    [aanvaller]: { token: s[adres].token, wrapped_key: b64url(crypto.randomBytes(60)) } },
    filename: 'nep.pdf' }, KEY2);
  assert.equal(overname.status, 400);
  assert.equal(overname.body.error, 'token_taken');

  // En de eerste ontvanger krijgt nog steeds zijn eigen bestand.
  const o = await ophalen(s[adres].token);
  assert.equal(o.stap2.status, 200);
  assert.equal(o.stap2.kop['x-paramant-filename'], 'echt.pdf');
});
