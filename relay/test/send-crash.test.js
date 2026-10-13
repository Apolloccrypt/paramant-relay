'use strict';

// KAN IK DE RELAY OM KRIJGEN?
//
// Dit is de zwaarste bevinding die er in deze codebase te halen valt, en dat
// komt door relay.js:10372-10381:
//
//   process.on('unhandledRejection', ...) -> emergencyZeroAndExit(..., 1)
//   process.on('uncaughtException',  ...) -> emergencyZeroAndExit(..., 1)
//
// emergencyZeroAndExit (relay.js:10344) nulled ELKE blob in blobStore en doet
// process.exit(). Een enkele onafgehandelde promise-rejection, waar ook in het
// proces, kost dus alle klanten hun lopende overdracht tegelijk. Er is geen
// vangnet per verzoek dat daar nog iets aan doet.
//
// Er staat er al een vangnet omheen voor het normale pad:
//   relay.js:3548  createServer((req,res) => handleRelayRequest(...).catch(...))
// Deze suite gaat erachteraan zoeken of er nog iets buiten dat vangnet valt.
//
// De toets is steeds dezelfde en staat onderaan elke test: leeft het proces
// nog, en antwoordt /health nog. De exitcode en de laatste 2 KB stdout/stderr
// komen uit _boot-relay.js mee in de foutmelding.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { killSpawnedRelays } = require('./_boot-relay');
const H = require('./_send-race');

const CRLF = '\r\n';
let R = null;
const B = () => R.base;

before(async () => { R = await H.bootSendRelay(); });
after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(R.usersFile); } catch (_) { /* best effort */ }
});

async function nogLevend(waar) {
  const dood = H.levendOf(R);
  assert.equal(dood, null, waar + ': ' + dood);
  let h;
  try { h = await fetch(B() + '/health'); }
  catch (e) { assert.fail(waar + ': /health onbereikbaar (' + e.message + ')\n' + R.output()); }
  assert.ok(h.ok, waar + ': /health antwoordde ' + h.status + '\n' + R.output());
  await h.text();
}

// Rauwe socket: hiermee kan een verzoek halverwege worden afgebroken, wat met
// fetch() niet betrouwbaar lukt.
function rauw(port, tekst, opties = {}) {
  return new Promise((klaar) => {
    const s = net.connect(port, '127.0.0.1', () => {
      s.write(tekst);
      if (opties.kapAfNa != null) setTimeout(() => s.destroy(), opties.kapAfNa);
    });
    let uit = '';
    s.on('data', (d) => {
      uit += d.toString();
      if (opties.kapBijEersteByte) s.destroy();
    });
    s.on('close', () => klaar(uit));
    s.on('error', () => klaar(uit));
    setTimeout(() => { s.destroy(); klaar(uit); }, opties.wacht || 2000);
  });
}

// ── A. Rommel op de ophaalroute ────────────────────────────────────────────
test('rommelige invoer op /v2/pickup laat het proces staan', async () => {
  const adres = 'rommel@extern.test';
  const v = await H.maakVerzending(B(), [adres], { bytes: 256 });
  const token = v.tokens[adres];

  const rommel = [
    '',                                   // leeg
    'niet eens json',
    '{',                                  // half
    '[]',                                 // array in plaats van object
    'null',
    '"tekst"',
    '123',
    JSON.stringify({ action: { toString: 1 } }),
    JSON.stringify({ code: { a: 1 } }),                 // code als object
    JSON.stringify({ code: 'x'.repeat(3000) }),         // code tegen de bodygrens
    '{"action":"code","__proto__":{"x":1}}',
    JSON.stringify({ code: null }),
    JSON.stringify({ code: ['000000'] }),
    '[' + '['.repeat(400) + ']'.repeat(400) + ']',      // diep genest
    'a'.repeat(8192),                                   // boven de 4096-grens
  ];
  for (const body of rommel) {
    const r = await fetch(B() + '/v2/pickup/' + encodeURIComponent(token), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    await r.text();
    assert.ok(r.status >= 200 && r.status < 600, 'geen antwoord op body: ' + body.slice(0, 40));
  }

  // En op tokens die de routematch net wel of net niet halen.
  for (const t of ['A'.repeat(16), 'A'.repeat(128), 'A'.repeat(129), '%00', '..', 'a/b',
                   '%20', 'A'.repeat(15)]) {
    const r = await fetch(B() + '/v2/pickup/' + t, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'code' }),
    }).catch(() => null);
    if (r) await r.text();
  }
  await nogLevend('na rommelige ophaalverzoeken');
});

// ── B. Rommel op de verzendroute ───────────────────────────────────────────
test('rommelige invoer op /v2/sends laat het proces staan', async () => {
  const inhoud = crypto.randomBytes(128);
  const hash = await H.uploadBlok(B(), inhoud);
  const goed = H.nieuwToken();

  const pogingen = [
    { hashes: [hash], recipients: ['a@b.test'], sealed: null },
    { hashes: [hash], recipients: ['a@b.test'], sealed: { 'a@b.test': null } },
    { hashes: [hash], recipients: ['a@b.test'], sealed: { 'a@b.test': { token: 1, wrapped_key: 2 } } },
    { hashes: [hash], recipients: [{ toString: 1 }], sealed: {} },
    { hashes: [hash], recipients: 'a@b.test', sealed: {} },
    { hashes: 'nietarray', recipients: [], sealed: {} },
    { hashes: [hash, hash], recipients: ['a@b.test'], sealed: { 'a@b.test': { token: goed, wrapped_key: goed } } },
    { hashes: Array.from({ length: 513 }, () => hash), recipients: [] },
    { hashes: ['nietgeldig'], recipients: [] },
    { hashes: [hash], recipients: ['a@b.test'], sealed: { 'a@b.test': { token: goed, wrapped_key: goed } }, ttl_ms: -1 },
    { hashes: [hash], recipients: ['a@b.test'], sealed: { 'a@b.test': { token: goed, wrapped_key: goed } }, ttl_ms: 'veel' },
    { hashes: [hash], recipients: ['a@b.test'], sealed: { 'a@b.test': { token: goed, wrapped_key: goed } }, ttl_ms: Number.MAX_SAFE_INTEGER },
  ];
  for (const p of pogingen) {
    const r = await fetch(B() + '/v2/sends', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Key': H.API_KEY },
      body: JSON.stringify(p),
    });
    await r.text();
  }

  // __proto__ als adres: buildRecipients gebruikt Object.create(null) juist
  // hiervoor, dus dit hoort een nette weigering te zijn en geen omvaller.
  const proto = await fetch(B() + '/v2/sends', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Key': H.API_KEY },
    body: '{"hashes":["' + hash + '"],"recipients":["__proto__"],' +
          '"sealed":{"__proto__":{"token":"' + goed + '","wrapped_key":"' + goed + '"}}}',
  });
  await proto.text();

  // En niet-JSON.
  for (const body of ['', '{', 'x'.repeat(70000)]) {
    const r = await fetch(B() + '/v2/sends', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Key': H.API_KEY }, body,
    });
    await r.text();
  }
  await nogLevend('na rommelige verzendverzoeken');
});

// ── C. Een bestandsnaam met stuurtekens, tot in de responseheader ──────────
test('een bestandsnaam met CR/LF komt heel door de ophaalheader', async () => {
  const adres = 'header@extern.test';
  const naam = 'kwaad' + CRLF + 'X-Injected: 1  naam.pdf';
  const v = await H.maakVerzending(B(), [adres], { bytes: 256, filename: naam });
  const code = await H.haalCode(R, v.tokens[adres], adres);
  const r = await H.pickup(B(), v.tokens[adres], { code });
  assert.equal(r.status, 200, 'ophalen faalde met status ' + r.status);
  assert.ok((await r.arrayBuffer()).byteLength > 0);
  assert.equal(r.headers.get('X-Injected'), null, 'headerinjectie via de bestandsnaam');
  await nogLevend('na stuurtekens in de bestandsnaam');
});

// ── D. Verbindingen die halverwege wegvallen ───────────────────────────────
test('afgebroken verbindingen tijdens ophalen en uploaden', async () => {
  const port = Number(new URL(B()).port);

  // Dertig ontvangers, ieder een eigen token, en de verbinding wordt afgekapt
  // zodra de eerste byte van het antwoord binnen is: midden in res.end(blob).
  const adressen = Array.from({ length: 30 }, (_, i) => 'k' + i + '@extern.test');
  const v = await H.maakVerzending(B(), adressen, { bytes: 2 * 1024 * 1024 });
  const codes = {};
  for (const a of adressen) codes[a] = await H.haalCode(R, v.tokens[a], a);

  await Promise.all(adressen.map((a) => {
    const body = JSON.stringify({ code: codes[a] });
    return rauw(port,
      'POST /v2/pickup/' + v.tokens[a] + ' HTTP/1.1' + CRLF + 'Host: 127.0.0.1' + CRLF +
      'Content-Type: application/json' + CRLF +
      'Content-Length: ' + Buffer.byteLength(body) + CRLF +
      'Connection: close' + CRLF + CRLF + body,
      { kapBijEersteByte: true, wacht: 4000 });
  }));
  await nogLevend('na afgekapte downloads');

  // Een body die is aangekondigd en nooit komt, en een die halverwege stopt.
  await Promise.all([
    rauw(port, 'POST /v2/sends HTTP/1.1' + CRLF + 'Host: 127.0.0.1' + CRLF +
               'X-Api-Key: ' + H.API_KEY + CRLF + 'Content-Type: application/json' + CRLF +
               'Content-Length: 40000' + CRLF + CRLF + '{"hashes":[',
               { kapAfNa: 120, wacht: 3000 }),
    rauw(port, 'POST /v2/inbound HTTP/1.1' + CRLF + 'Host: 127.0.0.1' + CRLF +
               'X-Api-Key: ' + H.API_KEY + CRLF + 'Content-Type: application/json' + CRLF +
               'Content-Length: 9000000' + CRLF + CRLF + '{"hash":"' + 'a'.repeat(64) +
               '","payload":"' + 'A'.repeat(4096),
               { kapAfNa: 150, wacht: 3000 }),
    rauw(port, 'POST /v2/pickup/' + 'A'.repeat(43) + ' HTTP/1.1' + CRLF + 'Host: 127.0.0.1' + CRLF +
               'Content-Length: 500' + CRLF + CRLF + '{"action":', { kapAfNa: 100, wacht: 3000 }),
    // Wel Content-Length, geen body, verbinding blijft hangen.
    rauw(port, 'POST /v2/sends HTTP/1.1' + CRLF + 'Host: 127.0.0.1' + CRLF +
               'Content-Length: 10' + CRLF + CRLF, { wacht: 1500 }),
    // Kapotte requestregel en binaire troep.
    rauw(port, 'GARBAGE / HTTP/9.9' + CRLF + CRLF, { wacht: 1000 }),
    rauw(port, Buffer.from([0, 1, 2, 3]).toString('latin1') + 'troep' + CRLF + CRLF, { wacht: 1000 }),
  ]);
  await nogLevend('na afgebroken uploads en kapotte verzoeken');
}, { timeout: 120000 });

// ── E. Een storm, met afbrekers ertussen ───────────────────────────────────
test('300 verzoeken door elkaar, met afbrekers, en de relay staat er nog', async () => {
  const port = Number(new URL(B()).port);
  const werk = [];
  for (let i = 0; i < 100; i++) {
    werk.push(H.maakVerzending(B(), ['s' + i + '@extern.test'], { bytes: 128 }).catch(() => null));
    werk.push(H.pickup(B(), H.nieuwToken(), { action: 'code' }).then(r => r.text()).catch(() => null));
    werk.push(rauw(port, 'POST /v2/pickup/' + H.nieuwToken() + ' HTTP/1.1' + CRLF + 'Host: x' + CRLF +
                         'Content-Length: 200' + CRLF + CRLF + '{"code":"1',
                   { kapAfNa: 20, wacht: 2000 }));
  }
  await Promise.all(werk);
  await nogLevend('na de storm');
}, { timeout: 180000 });
