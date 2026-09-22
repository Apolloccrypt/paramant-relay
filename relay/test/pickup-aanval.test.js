'use strict';

// AANVAL OP DE OPHAALROUTE, met een echt draaiende relay.
//
// De aanvaller hier is de enige die er in het echt is: iemand die de LINK
// heeft. Geen account, geen sleutel, geen dashboard. Hij kreeg hem uit een
// doorgestuurde mail, uit een proxylog, of hij is de mailprovider zelf.
// Alles hieronder gaat over POST /v2/pickup/:token, en nergens anders over.
//
// Een test die FAALT is een gat dat open staat. Een test die slaagt is een
// muur die het houdt, en die staat er zodat hij blijft staan.
//
// Draaien:
//   cd /home/mick/paramant-ontvangers/relay && node --test test/pickup-aanval.test.js

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');
const { sealedVoor } = require('./_sealed');
const send = require('../lib/send');

const API_KEY = 'pgp_pickup_aanval_sleutel';
const INTERN = 'intern-pickup-aanval-token';
const ACCOUNT = 'acct_pickup_aanval';
let BASE = null;
let usersFile;

// Elke mail_dryrun-regel die de relay uitspuugt, in volgorde. Dit is de
// mailbox van de ontvanger, en tegelijk het uitzicht van de mailprovider.
const post = [];

function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

before(async () => {
  usersFile = path.join(os.tmpdir(), `pickup-aanval-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
                   account_id: 'acct_pickup_aanval' }],
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

// ── gereedschap ─────────────────────────────────────────────────────────────

async function wachtOpPost() { await new Promise((r) => setTimeout(r, 250)); }

// Een echte verzending: blok geupload, send aangemaakt, tokens terug.
// De tokens komen uit _sealed.js, dus de test weet ze zonder ze uit de mail te
// hoeven vissen. Dat is precies wat de afzenders browser ook doet.
async function maakVerzending(adressen, opties = {}) {
  const inhoud = opties.inhoud || crypto.randomBytes(opties.bytes || 4096);
  const hash = sha256hex(inhoud);
  const ir = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: inhoud.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(ir.status, 200, 'blokupload faalde: ' + (await ir.text()));

  const sealed = sealedVoor(adressen);
  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                           filename: opties.filename || 'stuk.pdf',
                           ttl_ms: 24 * 3600 * 1000 }),
  });
  const vj = await vr.json().catch(() => ({}));
  assert.equal(vr.status, 201, 'verzending geweigerd: ' + JSON.stringify(vj));
  const tokens = {};
  for (const a of adressen) tokens[a] = sealed[a].token;
  return { id: vj.send_id, tokens, sealed, inhoud, adressen };
}

function pickup(token, body) {
  return fetch(BASE + '/v2/pickup/' + token, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// Vraag een code en vis hem uit de maillog. Dit is wat een mailprovider ziet.
async function vraagCode(token, adres) {
  post.length = 0;
  const r = await pickup(token, { action: 'code' });
  await wachtOpPost();
  const mail = post.find((p) => /code to open the file/i.test(p.subject || '')
                             && (p.to || []).includes(adres));
  const code = mail ? (String(mail.text).match(/\b(\d{6})\b/) || [])[1] : null;
  return { status: r.status, body: await r.json().catch(() => ({})), mail, code };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. DE ONDERSCHEPTE LINK
// ═══════════════════════════════════════════════════════════════════════════

// Wat de code tegenhoudt, en tegen wie. De proxylog en de doorgestuurde mail
// houden hem tegen; de mailprovider niet, want die draagt beide helften.
test('1a: de link alleen is niet genoeg, de code stopt de onderschepper', async () => {
  const v = await maakVerzending(['ontvanger1a@extern.test']);
  const token = v.tokens['ontvanger1a@extern.test'];

  // De aanvaller heeft de link. Hij vraagt een code: die gaat NIET naar hem.
  const c = await vraagCode(token, 'ontvanger1a@extern.test');
  assert.equal(c.status, 200);
  assert.ok(c.code, 'geen code in de mail');
  assert.ok(!JSON.stringify(c.body).includes(c.code),
    'de code mag nooit in het HTTP-antwoord staan, dan is de link genoeg');

  // Zonder de mailbox blijft hij gokken.
  const g = await pickup(token, { code: '000000' });
  assert.equal(g.status, 401, 'een gok zonder mailbox hoort geweigerd');
});

// De mailprovider ziet ALLEBEI de helften in hetzelfde postvak. Dit is geen
// bug maar het ontwerp, en het staat hier zodat niemand later denkt dat de
// code tegen de mailprovider beschermt.
test('1b: de mailprovider draagt beide helften, en dat is de grens van dit ontwerp', async () => {
  const adres = 'ontvanger1b@extern.test';
  post.length = 0;
  const v = await maakVerzending([adres]);
  await wachtOpPost();
  const uitnodiging = post.find((p) => /sent you a file/.test(p.subject || '')
                                     && (p.to || []).includes(adres));
  assert.ok(uitnodiging, 'geen uitnodiging');

  const c = await vraagCode(v.tokens[adres], adres);
  assert.equal((c.mail.to || [])[0], adres,
    'de code gaat naar hetzelfde postvak als de link: wie de mailbox leest heeft alles');

  // En dan de test die telt: de link zelf staat in die mail, dus uitnodiging
  // plus codemail is het hele bestand.
  const uitLink = (uitnodiging.text.match(/\/ontvang\/([A-Za-z0-9_-]{16,128})/) || [])[1];
  assert.equal(uitLink, v.tokens[adres],
    'de uitnodiging draagt het token zelf, dus uitnodiging + codemail = het bestand');
  const r = await pickup(v.tokens[adres], { code: c.code });
  assert.equal(r.status, 200, 'met beide helften uit een mailbox ligt het bestand open');
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. BRUTEFORCE OP DE ZESCIJFERIGE CODE
// ═══════════════════════════════════════════════════════════════════════════

test('2a: een nieuwe code vragen zet de teller niet terug', async () => {
  const adres = 'ontvanger2a@extern.test';
  const v = await maakVerzending([adres]);
  const token = v.tokens[adres];

  let gokken = 0;
  let geblokkeerd = false;
  // Zoveel rondes als de plafonds toestaan: elke ronde een verse code en dan
  // gokken tot de deur dicht is. Als code_requests de teller zou resetten was
  // dit oneindig.
  for (let ronde = 0; ronde < 20 && !geblokkeerd; ronde++) {
    const c = await vraagCode(token, adres);
    if (c.status !== 200) { geblokkeerd = true; break; }
    for (let i = 0; i < 5; i++) {
      const r = await pickup(token, { code: '000001' });
      if (r.status === 429) { geblokkeerd = true; break; }
      assert.equal(r.status, 401, 'een foute gok hoort 401 of 429, kreeg ' + r.status);
      gokken++;
    }
  }
  assert.ok(geblokkeerd, 'de deur ging nooit dicht: de plafonds zijn te omzeilen');
  assert.ok(gokken <= send.MAX_WRONG_TOTAL,
    `er waren ${gokken} gokken mogelijk, het plafond is ${send.MAX_WRONG_TOTAL}`);
});

test('2b: parallelle gokken tellen allemaal mee', async () => {
  const adres = 'ontvanger2b@extern.test';
  const v = await maakVerzending([adres]);
  const token = v.tokens[adres];
  await vraagCode(token, adres);

  // Vijftig gokken tegelijk. Als de teller pas na de laatste write kijkt,
  // glippen er meer dan MAX_WRONG_TOTAL doorheen.
  const uit = await Promise.all(Array.from({ length: 50 },
    () => pickup(token, { code: '000002' })));
  const geteld = uit.filter((r) => r.status === 401).length;
  assert.ok(geteld <= send.MAX_WRONG_TOTAL,
    `${geteld} van de 50 parallelle gokken werden beoordeeld, het plafond is `
    + `${send.MAX_WRONG_TOTAL}: de teller telt niet atomair`);
});

test('2c: het token van een ANDERE verzending opent niets hier', async () => {
  const a = await maakVerzending(['ontvanger2c-a@extern.test']);
  const b = await maakVerzending(['ontvanger2c-b@extern.test']);
  const tokenA = a.tokens['ontvanger2c-a@extern.test'];
  const tokenB = b.tokens['ontvanger2c-b@extern.test'];

  const cA = await vraagCode(tokenA, 'ontvanger2c-a@extern.test');
  assert.ok(cA.code);

  // De code van A op het token van B. De hash bindt de code aan het token,
  // dus dit hoort nooit te werken.
  await vraagCode(tokenB, 'ontvanger2c-b@extern.test');
  const r = await pickup(tokenB, { code: cA.code });
  assert.notEqual(r.status, 200,
    'de code van de ene verzending opende de andere');
});

test('2d: twee tokens van DEZELFDE verzending delen hun code niet', async () => {
  const adressen = ['ontvanger2d-1@extern.test', 'ontvanger2d-2@extern.test'];
  const v = await maakVerzending(adressen);
  const c1 = await vraagCode(v.tokens[adressen[0]], adressen[0]);
  assert.ok(c1.code);
  await vraagCode(v.tokens[adressen[1]], adressen[1]);

  const r = await pickup(v.tokens[adressen[1]], { code: c1.code });
  assert.notEqual(r.status, 200,
    'de code van ontvanger 1 opende het token van ontvanger 2');
});

test('2f: hoeveel mail een onderschepper in een vreemde bus kan duwen', async () => {
  const adres = 'ontvanger2f@extern.test';
  const v = await maakVerzending([adres]);
  const token = v.tokens[adres];

  post.length = 0;
  let gemaild = 0;
  for (let i = 0; i < 25; i++) {
    const r = await pickup(token, { action: 'code' });
    if (r.status !== 200) break;
    gemaild++;
  }
  await wachtOpPost();
  const bus = post.filter((p) => /code to open the file/i.test(p.subject || '')).length;
  assert.ok(gemaild <= send.MAX_CODE_REQUESTS,
    `${gemaild} codes geaccepteerd, het plafond is ${send.MAX_CODE_REQUESTS}`);
  assert.ok(bus <= send.MAX_CODE_REQUESTS,
    `${bus} mails in een postvak van iemand die geen klant is, plafond `
    + `${send.MAX_CODE_REQUESTS}`);
});

// HET GAT. Wie de link heeft kan de ontvanger permanent buitensluiten door de
// plafonds op te maken. Er is daarna geen weg terug: reinvite maakt geen nieuw
// token en zet wrong_total niet terug, dus de rechtmatige ontvanger komt er
// nooit meer in en de afzender ziet alleen "nog niet opgehaald".
test('2e: een onderschepper kan de ontvanger permanent buitensluiten', async () => {
  const adres = 'ontvanger2e@extern.test';
  const v = await maakVerzending([adres]);
  const token = v.tokens[adres];

  // De aanvaller maakt beide plafonds op.
  for (let ronde = 0; ronde < 12; ronde++) {
    const c = await vraagCode(token, adres);
    if (c.status !== 200) break;
    for (let i = 0; i < 4; i++) {
      const r = await pickup(token, { code: '000003' });
      if (r.status === 429) break;
    }
  }

  // De afzender merkt het en stuurt een herinnering. Dat is de enige knop die
  // het dashboard heeft voor "deze persoon komt er niet in".
  const her = await fetch(BASE + '/v2/user/sends/reinvite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: ACCOUNT, send_id: v.id, email: adres }),
  });
  assert.equal(her.status, 200, 'de herinnering zelf faalde: ' + (await her.text()));

  // En nu de vraag die telt: kan de rechtmatige ontvanger nog ophalen?
  const c = await vraagCode(token, adres);
  assert.equal(c.status, 200,
    'na een herinnering moet de ontvanger weer een code kunnen vragen; '
    + 'kreeg ' + c.status + ' ' + JSON.stringify(c.body)
    + ' -- wie de link onderschept sluit de ontvanger permanent buiten');
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. GELIJKTIJDIG OPHALEN MET DE GOEDE CODE
// ═══════════════════════════════════════════════════════════════════════════

test('3a: twee keer tegelijk de goede code levert precies een keer bytes', async () => {
  const adres = 'ontvanger3a@extern.test';
  const v = await maakVerzending([adres], { bytes: 64 * 1024 });
  const token = v.tokens[adres];
  const c = await vraagCode(token, adres);
  assert.ok(c.code);

  const uit = await Promise.all([
    pickup(token, { code: c.code }),
    pickup(token, { code: c.code }),
    pickup(token, { code: c.code }),
  ]);
  const geslaagd = uit.filter((r) => r.status === 200);
  assert.equal(geslaagd.length, 1,
    `${geslaagd.length} van de 3 gelijktijdige verzoeken kregen bytes; `
    + 'een eenmalige link mag er maar een bedienen');
  for (const r of uit) await r.arrayBuffer().catch(() => {});
});

test('3b: een code vragen en ophalen tegelijk verliest de bytes niet', async () => {
  const adres = 'ontvanger3b@extern.test';
  const v = await maakVerzending([adres]);
  const token = v.tokens[adres];
  const c = await vraagCode(token, adres);

  // Een verlate scanner-klik op "nieuwe code" tegelijk met de echte ophaal.
  // Als de nieuwe code de oude overschrijft voordat collect hem leest, kost
  // een dubbele klik de ontvanger zijn ophaalbeurt.
  const [ophaal, nieuw] = await Promise.all([
    pickup(token, { code: c.code }),
    pickup(token, { action: 'code' }),
  ]);
  await nieuw.json().catch(() => {});
  assert.equal(ophaal.status, 200,
    'een gelijktijdig code-verzoek kostte de ontvanger zijn ophaalbeurt: '
    + ophaal.status);
  await ophaal.arrayBuffer().catch(() => {});
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. WAT EEN ONTVANGER OVER DE ANDEREN LEERT
// ═══════════════════════════════════════════════════════════════════════════

test('4a: X-Paramant-Outstanding vertelt hoe groot de groep is', async () => {
  const adressen = Array.from({ length: 6 }, (_, i) => `ontvanger4a-${i}@extern.test`);
  const v = await maakVerzending(adressen);
  const token = v.tokens[adressen[0]];
  const c = await vraagCode(token, adressen[0]);
  const r = await pickup(token, { code: c.code });
  assert.equal(r.status, 200);
  await r.arrayBuffer();

  const rest = r.headers.get('X-Paramant-Outstanding');
  assert.equal(rest, '5',
    'de header zegt hoeveel anderen er nog niet waren -- dat is informatie '
    + 'over de groep die de ontvanger niet hoort te krijgen');
});

test('4b: elke weigering heeft dezelfde vorm, anders is het een orakel', async () => {
  // De routecommentaar (relay.js:7050) belooft: "One shape of refusal for every
  // way a link can be unusable, so trying tokens tells a caller nothing about
  // which sends exist."
  const adressen = ['ontvanger4b-op@extern.test', 'ontvanger4b-in@extern.test'];
  const v = await maakVerzending(adressen);

  // Opgehaald.
  const t1 = v.tokens[adressen[0]];
  const c1 = await vraagCode(t1, adressen[0]);
  const op = await pickup(t1, { code: c1.code });
  assert.equal(op.status, 200);
  await op.arrayBuffer();

  // Ingetrokken.
  const t2 = v.tokens[adressen[1]];
  const ir = await fetch(BASE + '/v2/user/sends/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: ACCOUNT, send_id: v.id, email: adressen[1] }),
  });
  assert.equal(ir.status, 200, 'intrekken faalde: ' + (await ir.text()));

  const onbekend = await pickup('Z'.repeat(43), { action: 'code' });
  const opgehaald = await pickup(t1, { action: 'code' });
  const ingetrokken = await pickup(t2, { action: 'code' });

  const vormen = [onbekend, opgehaald, ingetrokken].map((r) => r.status);
  assert.deepEqual([...new Set(vormen)], [vormen[0]],
    `drie verschillende antwoorden op drie onbruikbare links: ${vormen.join(', ')} `
    + '(onbekend, al opgehaald, ingetrokken). Wie een token heeft leest daaruit '
    + 'af of de verzending bestaat en wat de afzender met hem deed');
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. RARE TOKENS
// ═══════════════════════════════════════════════════════════════════════════

test('5a: een raar token krijgt 404 en nooit iets anders', async () => {
  const raar = {
    'hoofdletters op een echt token': null,   // wordt hieronder gevuld
    'te kort': 'abc',
    'unicode': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAé',
    'emoji': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + encodeURIComponent('\u{1F600}'),
    'heel lang': 'A'.repeat(5000),
    'lijkt een pad': '..%2f..%2fv2%2fstatus',
    'punt punt': '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    'met een punt erin': 'AAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAA',
    'met een schuine streep': 'AAAAAAAAAAAAAAAAAAAA%2fAAAAAAAAAAAAAAAAAAAA',
    'nul-byte': 'AAAAAAAAAAAAAAAAAAAA%00AAAAAAAAAAAAAAAAAAAA',
  };
  const v = await maakVerzending(['ontvanger5a@extern.test']);
  raar['hoofdletters op een echt token'] = v.tokens['ontvanger5a@extern.test'].toUpperCase();

  const fout = [];
  for (const [wat, tok] of Object.entries(raar)) {
    const r = await pickup(tok, { action: 'code' });
    const body = await r.text();
    if (r.status !== 404) fout.push(`${wat} -> ${r.status} ${body.slice(0, 120)}`);
  }
  assert.deepEqual(fout, [],
    'een onbruikbaar token hoort altijd 404 unknown_token te krijgen. '
    + 'Deze kregen iets anders:\n  ' + fout.join('\n  '));
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. DE VERBINDING BREEKT TIJDENS HET DOWNLOADEN
// ═══════════════════════════════════════════════════════════════════════════

test('6a: een afgebroken download kost de ontvanger zijn ophaalbeurt niet', async () => {
  const adres = 'ontvanger6a@extern.test';
  // Groot genoeg dat de bytes niet in een enkel TCP-venster passen, zodat het
  // afbreken echt halverwege gebeurt.
  const v = await maakVerzending([adres], { bytes: 3 * 1024 * 1024 });
  const token = v.tokens[adres];
  const c = await vraagCode(token, adres);
  assert.ok(c.code);

  // Een mobiele verbinding die het na de headers begeeft.
  const afgebroken = await new Promise((resolve, reject) => {
    const u = new URL(BASE + '/v2/pickup/' + token);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, (res) => {
      let gelezen = 0;
      res.on('data', (d) => {
        gelezen += d.length;
        if (gelezen > 0) { req.destroy(); resolve({ status: res.statusCode, gelezen }); }
      });
      res.on('end', () => resolve({ status: res.statusCode, gelezen }));
      res.on('error', () => resolve({ status: res.statusCode, gelezen }));
    });
    req.on('error', (e) => { if (e.code !== 'ECONNRESET') reject(e); });
    req.end(JSON.stringify({ code: c.code }));
  });
  assert.equal(afgebroken.status, 200, 'de relay begon wel te leveren');
  assert.ok(afgebroken.gelezen < 3 * 1024 * 1024,
    'de test brak niet echt af, er kwam alles doorheen');

  // En nu: heeft hij nog een kans? Zijn bestand is nooit aangekomen.
  const nog = await pickup(token, { action: 'code' });
  const nj = await nog.json().catch(() => ({}));

  // En wat de afzender ziet, want dat is de tweede helft van de schade: als
  // het dashboard "opgehaald" zegt gaat niemand er achteraan.
  const det = await fetch(BASE + '/v2/user/sends/detail', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: ACCOUNT, send_id: v.id }),
  });
  const dj = await det.json().catch(() => ({}));

  assert.equal(nog.status, 200,
    'de ophaalbeurt was op terwijl de bytes nooit aankwamen: '
    + nog.status + ' ' + JSON.stringify(nj)
    + ' -- en de afzender ziet ' + JSON.stringify(dj)
    + '. Een afgebroken verbinding kost de ontvanger zijn enige kans, en het '
    + 'dashboard meldt de levering als geslaagd');
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. WAT DE AFZENDER IN DE HEADERS VAN DE ONTVANGER KAN STOPPEN
// ═══════════════════════════════════════════════════════════════════════════

test('7a: een bestandsnaam met CR/LF of unicode breekt de levering niet', async () => {
  const adres = 'ontvanger7a@extern.test';
  const naam = "jaar\r\nX-Injected: ja\r\né\u{1F600}verslag.pdf";
  const v = await maakVerzending([adres], { filename: naam });
  const token = v.tokens[adres];
  const c = await vraagCode(token, adres);

  const r = await pickup(token, { code: c.code });
  assert.equal(r.status, 200,
    'een bestandsnaam van de afzender kostte de ontvanger zijn ophaalbeurt: ' + r.status);
  await r.arrayBuffer();
  assert.equal(r.headers.get('x-injected'), null,
    'de bestandsnaam smokkelde een eigen header mee');
  assert.equal(decodeURIComponent(r.headers.get('X-Paramant-Filename')).slice(0, 4), 'jaar');
});

test('7b: een verpakking die geen header kan zijn wordt bij de verzending geweigerd', async () => {
  const adres = 'ontvanger7b@extern.test';
  const inhoud = crypto.randomBytes(2048);
  const hash = sha256hex(inhoud);
  await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: inhoud.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  const sealed = sealedVoor([adres]);
  // Een afzender die zelf de API aanroept en een CRLF in de verpakking stopt.
  sealed[adres].wrapped_key = 'AAAAAAAAAAAAAAAA\r\nX-Injected: ja';

  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: [adres], sealed,
                           filename: 'x.pdf', ttl_ms: 3600000 }),
  });
  assert.notEqual(vr.status, 201,
    'een verpakking met CRLF werd geaccepteerd; die komt terug als HTTP-header '
    + 'bij de ontvanger');
});
