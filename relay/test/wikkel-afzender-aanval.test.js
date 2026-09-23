'use strict';

// WAT EEN KWAADWILLENDE AFZENDER KAN, EN WAT EEN ONTVANGER DAN ZIET.
//
// De afzender kiest het token zelf en stuurt het mee in `sealed`. De relay
// toetst alleen de VORM (lib/recipients.js:198-203: TOKEN_SHAPE en WRAP_SHAPE),
// nooit de inhoud. Deze suite loopt langs wat dat oplevert:
//
//   4. een token met nul entropie, hetzelfde token twee keer, en een token dat
//      al bij een andere verzending hoort (ook van een ander account)
//   5. een wrapped_key die geldig base64url is maar geen AES-GCM-verpakking
//   7. belandt de bestandssleutel ergens in een respons, header, log of mail?
//
// Draaien:
//   cd /home/mick/paramant-ontvangers/relay && node --test test/wikkel-afzender-aanval.test.js

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_wikkel_afzender_aanval';
const API_KEY_2 = 'pgp_wikkel_afzender_tweede';
let BASE = null;
let usersFile;

// ALLE logregels van de relay, niet alleen de mail. Test 7 leest hier uit.
const regels = [];
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
function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `wikkel-afz-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({
      api_keys: [
        { key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
          label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
          account_id: 'acct_afz_een' },
        { key: API_KEY_2, active: true, plan: 'pro', plan_parasend: 'pro',
          label: 'Ander Bedrijf', email: 'boef@ander.test',
          account_id: 'acct_afz_twee' },
      ],
    }),
  }, {
    onLine: (line) => {
      if (!line) return;
      regels.push(line);
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

// Verzegel een bestand en zet het blok klaar. Geeft de blokhash en de sleutel.
async function klaarzetten(inhoudTekst, apiKey) {
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
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey || API_KEY },
    body: JSON.stringify({ hash, payload: ct.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(r.status, 200, 'blokupload faalde');
  return { hash, rawKey, iv, ct, naam,
           geheim: new Uint8Array(Buffer.concat([rawKey, iv])) };
}

async function verstuur(hash, sealed, recipients, apiKey) {
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey || API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients, sealed,
                           filename: 'dossier.pdf', ttl_ms: 3600e3 }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

// De hele ophaalreis van een ontvanger, tot en met de bytes en de header.
async function haalOp(token, adres) {
  post.length = 0;
  const cr = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  if (cr.status !== 200) return { stap: 'code', status: cr.status,
                                  body: await cr.json().catch(() => ({})) };
  await new Promise((r) => setTimeout(r, 200));
  const mail = post.find((p) => /controlecode om het bestand te openen/i.test(p.subject || '')
                              && (p.to || []).includes(adres));
  assert.ok(mail, 'geen codemail voor ' + adres);
  const code = (String(mail.text).match(/\b(\d{6})\b/) || [])[1];
  const or_ = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (or_.status !== 200) return { stap: 'collect', status: or_.status,
                                   body: await or_.json().catch(() => ({})) };
  return { stap: 'ok', status: 200, wrapped: or_.headers.get('X-Paramant-Key'),
           headers: or_.headers, bytes: Buffer.from(await or_.arrayBuffer()) };
}

// Wat de browser doet als het pakket binnen is: ophalen.page.js:211-224.
// Geeft de FOUT terug in plaats van hem te gooien, want daar gaat test 5 over.
async function browserOpent(token, wrapped, bytes) {
  try {
    if (!wrapped) throw new Error('no_key');
    const s = await wrap.unwrap(token, wrapped);
    const d = crypto.createDecipheriv('aes-256-gcm',
      Buffer.from(s.rawKey), Buffer.from(s.iv));
    d.setAuthTag(bytes.subarray(bytes.length - 16));
    const plat = Buffer.concat([d.update(bytes.subarray(0, bytes.length - 16)), d.final()]);
    const nl = plat.readUInt32LE(0);
    if (nl > plat.length - 4) throw new Error('bad_payload');
    return { ok: true, naam: plat.subarray(4, 4 + nl).toString('utf8') };
  } catch (e) {
    return { ok: false, naam: e && e.message, klasse: e && e.name };
  }
}

// Welke zin ophalen.page.js:189-198 bij deze fout toont.
function zinVoor(fout) {
  if (fout.naam === 'no_key' || fout.naam === 'bad_payload' || fout.klasse === 'OperationError') {
    return 'The file came through but this link cannot open it. Ask the sender for a new link.';
  }
  return 'Could not reach Paramant. Try again.';
}

// ---------------------------------------------------------------------------
// 4. De afzender kiest het token
// ---------------------------------------------------------------------------

test('een token zonder enige entropie wordt gewoon aangenomen', async () => {
  const f = await klaarzetten('de jaarrekening');
  const zwak = 'A'.repeat(43);                    // voldoet aan TOKEN_SHAPE
  const wikkel = await wrap.wrap(zwak, f.geheim);
  const uit = await verstuur(f.hash, { 'zwak@extern.test': { token: zwak, wrapped_key: wikkel } },
                             ['zwak@extern.test']);
  assert.equal(uit.status, 201, 'geweigerd: ' + JSON.stringify(uit.body));

  // Gevolg 1: de link is te raden, en dat is een levend eindpunt. Wie het
  // token opschrijft, zet een mail naar een vreemd postvak in gang.
  const r = await fetch(BASE + '/v2/pickup/' + zwak, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(r.status, 200, 'het geraden token was geen geldige ingang');

  // Gevolg 2, en dit is het echte gat: de wikkel is precies zo sterk als het
  // token. Wie de opgeslagen wrapped_key heeft en het token raadt, heeft de
  // bestandssleutel. De relay bewaart die wrapped_key letterlijk
  // (lib/recipients.js:184), dus dit is wat een dump van de opslag waard is.
  const geraden = await wrap.unwrap(zwak, wikkel);
  assert.deepEqual(Buffer.from(geraden.rawKey), f.rawKey,
    'de bestandssleutel viel niet uit het geraden token, controleer de opzet');

  // De relay kan dit niet zien: hij bewaart SHA3-256 van het token en een
  // hash van AAAA... is net zo willekeurig als een hash van echte entropie.
  // De belofte "de relay houdt een doos zonder sleutel" leunt dus volledig op
  // de browser van de afzender, en op niets aan deze kant.
});

test('hetzelfde token voor twee ontvangers wordt geweigerd', async () => {
  const f = await klaarzetten('de jaarrekening');
  const token = wrap.newToken();
  const wikkel = await wrap.wrap(token, f.geheim);
  const uit = await verstuur(f.hash, {
    'x1@extern.test': { token, wrapped_key: wikkel },
    'x2@extern.test': { token, wrapped_key: wikkel },
  }, ['x1@extern.test', 'x2@extern.test']);
  assert.equal(uit.status, 400);
  assert.equal(uit.body.error, 'duplicate_token', JSON.stringify(uit.body));
});

test('een token van een andere verzending, door een ander account', async () => {
  const f = await klaarzetten('de jaarrekening');
  const token = wrap.newToken();
  const eerste = await verstuur(f.hash,
    { 'y1@extern.test': { token, wrapped_key: await wrap.wrap(token, f.geheim) } },
    ['y1@extern.test']);
  assert.equal(eerste.status, 201, JSON.stringify(eerste.body));

  // Account twee heeft het token ergens opgevangen (een doorgestuurde mail,
  // een proxylog) en zet het in zijn eigen sealed. De tokenindex is een
  // sleutelruimte over alle accounts heen, en dat is wat dit tegenhoudt:
  // lib/send.js:287-299.
  const g = await klaarzetten('het bestand van de boef', API_KEY_2);
  const boef = await verstuur(g.hash,
    { 'y2@extern.test': { token, wrapped_key: await wrap.wrap(token, g.geheim) } },
    ['y2@extern.test'], API_KEY_2);
  assert.equal(boef.status, 400, 'een ander account nam het token over');
  assert.equal(boef.body.error, 'token_taken', JSON.stringify(boef.body));

  // En de rechtmatige ontvanger merkt er niets van: zijn link werkt nog.
  const op = await haalOp(token, 'y1@extern.test');
  assert.equal(op.stap, 'ok', JSON.stringify(op));
  const open = await browserOpent(token, op.wrapped, op.bytes);
  assert.equal(open.ok, true, 'de rechtmatige ontvanger kon niet meer openen: ' + open.naam);
});

// ---------------------------------------------------------------------------
// 5. Een wrapped_key die geen verpakking is
// ---------------------------------------------------------------------------

test('een onzin-wikkel wordt aangenomen en kost de ontvanger zijn enige beurt', async () => {
  const f = await klaarzetten('de jaarrekening');
  const token = wrap.newToken();
  // Geldig base64url, 60 bytes, en volstrekt geen AES-GCM.
  const onzin = b64url(crypto.randomBytes(60));
  const uit = await verstuur(f.hash, { 'z1@extern.test': { token, wrapped_key: onzin } },
                             ['z1@extern.test']);
  assert.equal(uit.status, 201,
    'de relay nam de onzin niet aan: ' + JSON.stringify(uit.body));

  // De ontvanger loopt de hele reis, krijgt 200 en de bytes, en dan pas breekt
  // het. De link is op dat moment al verbrand.
  const op = await haalOp(token, 'z1@extern.test');
  assert.equal(op.stap, 'ok', JSON.stringify(op));
  const open = await browserOpent(token, op.wrapped, op.bytes);
  assert.equal(open.ok, false);
  assert.equal(open.klasse, 'OperationError',
    'verwacht een GCM-fout, kreeg ' + open.naam);
  // Deze fout IS netjes afgevangen: ophalen.page.js:191-197.
  assert.match(zinVoor(open), /this link cannot open it/);

  // Maar de beurt is weg en er is geen weg terug: een herinnering maakt geen
  // nieuw token (lib/recipients.js:307-323).
  const nogEens = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(nogEens.status, 410);
  assert.equal((await nogEens.json()).error, 'already_collected');
});

test('een te korte wikkel geeft de ontvanger de VERKEERDE melding', { todo: 'GEDICHT aan de andere kant: WRAP_SHAPE weigert een te korte wikkel nu bij het AANMAKEN, waar de afzender hem nog kan repareren, in plaats van bij het ophalen waar de ontvanger zijn link al heeft verbrand' }, async () => {
  const f = await klaarzetten('de jaarrekening');
  const token = wrap.newToken();
  // WRAP_SHAPE (lib/recipients.js:203) laat 16 tekens toe. 16 base64url-tekens
  // zijn 12 bytes, en send-wrap.js:87 eist er minstens 13.
  const kort = b64url(crypto.randomBytes(12));
  assert.equal(kort.length, 16);
  const uit = await verstuur(f.hash, { 'z2@extern.test': { token, wrapped_key: kort } },
                             ['z2@extern.test']);
  assert.equal(uit.status, 201, 'geweigerd: ' + JSON.stringify(uit.body));

  const op = await haalOp(token, 'z2@extern.test');
  assert.equal(op.stap, 'ok', JSON.stringify(op));
  const open = await browserOpent(token, op.wrapped, op.bytes);
  assert.equal(open.ok, false);
  assert.equal(open.naam, 'wrapped key too short');

  // En die fout staat NIET in de lijst van ophalen.page.js:191. De ontvanger
  // leest dus dat Paramant niet bereikbaar is en dat hij het opnieuw moet
  // proberen, terwijl zijn link net verbrand is en opnieuw proberen niets doet.
  assert.equal(zinVoor(open), 'Could not reach Paramant. Try again.',
    'als dit verandert is het gat gedicht: pas de test aan');
});

test('een wikkel met de verkeerde lengte geeft dezelfde verkeerde melding', { todo: 'zelfde reparatie: de weigering is verplaatst naar POST /v2/sends' }, async () => {
  const f = await klaarzetten('de jaarrekening');
  const token = wrap.newToken();
  // Een ECHTE AES-GCM-verpakking, maar niet over 44 bytes. GCM gaat open, en
  // dan valt send-wrap.js:92 erover.
  const scheef = await wrap.wrap(token, new Uint8Array(crypto.randomBytes(10)));
  const uit = await verstuur(f.hash, { 'z3@extern.test': { token, wrapped_key: scheef } },
                             ['z3@extern.test']);
  assert.equal(uit.status, 201, 'geweigerd: ' + JSON.stringify(uit.body));

  const op = await haalOp(token, 'z3@extern.test');
  assert.equal(op.stap, 'ok', JSON.stringify(op));
  const open = await browserOpent(token, op.wrapped, op.bytes);
  assert.equal(open.ok, false);
  assert.equal(open.naam, 'unexpected key material');
  assert.equal(zinVoor(open), 'Could not reach Paramant. Try again.',
    'als dit verandert is het gat gedicht: pas de test aan');
});

// ---------------------------------------------------------------------------
// 7. Belandt de bestandssleutel ergens?
// ---------------------------------------------------------------------------

test('de bestandssleutel staat in geen respons, header, log of mail', async () => {
  const f = await klaarzetten('de jaarrekening van de stichting');
  const token = wrap.newToken();
  const wikkel = await wrap.wrap(token, f.geheim);
  const uit = await verstuur(f.hash, { 'lek@extern.test': { token, wrapped_key: wikkel } },
                             ['lek@extern.test']);
  assert.equal(uit.status, 201, JSON.stringify(uit.body));
  assert.ok(!JSON.stringify(uit.body).includes(f.rawKey.toString('hex')),
    'de verzendrespons droeg de sleutel');

  const merk = Date.now();
  const vanaf = regels.length;
  const op = await haalOp(token, 'lek@extern.test');
  assert.equal(op.stap, 'ok', JSON.stringify(op));
  await new Promise((r) => setTimeout(r, 250));

  // Elke vorm waarin 32 bytes kunnen opduiken.
  const vormen = [
    f.rawKey.toString('hex'), f.rawKey.toString('base64'), b64url(f.rawKey),
    Buffer.concat([f.rawKey, f.iv]).toString('base64'), b64url(Buffer.concat([f.rawKey, f.iv])),
  ];

  // 1. De headers van het ophaalantwoord.
  let koppen = '';
  op.headers.forEach((w, n) => { koppen += n + ': ' + w + '\n'; });
  for (const v of vormen) {
    assert.ok(!koppen.includes(v), 'de sleutel stond in een header (' + merk + ')');
  }
  // X-Paramant-Key draagt de WIKKEL, en die is zonder het token niets.
  assert.equal(op.wrapped, wikkel);

  // 2. De bytes zelf: dat is de ciphertext, en daar hoort hij niet in te staan.
  for (const v of [f.rawKey, Buffer.concat([f.rawKey, f.iv])]) {
    assert.ok(!op.bytes.includes(v), 'de sleutel stond in de blob');
  }

  // 3. Elke logregel die de relay in dit hele verhaal uitspuugde.
  const log = regels.join('\n');
  for (const v of vormen) {
    assert.ok(!log.includes(v), 'de sleutel stond in een logregel');
  }
  // Ook de wikkel hoort niet in de log: samen met een token uit een ander
  // spoor is dat het bestand.
  assert.ok(!log.includes(wikkel), 'de wikkel stond in een logregel');

  // 4. De post. Het TOKEN zit hier wel in, dat is het ontwerp: de mail draagt
  //    de sleutelhelft en nooit de doos. Dus juist dan moet de wikkel weg zijn.
  const mails = post.concat(regels.slice(vanaf)
    .filter((l) => l.includes('mail_dryrun'))
    .map((l) => { try { return JSON.parse(l); } catch (_) { return {}; } }));
  const alleMail = JSON.stringify(mails);
  for (const v of vormen) {
    assert.ok(!alleMail.includes(v), 'de sleutel stond in een mail');
  }
  assert.ok(!alleMail.includes(wikkel), 'de wikkel stond in een mail');
  const uitnodiging = regels.filter((l) => l.includes('heeft u een bestand gestuurd'));
  assert.ok(uitnodiging.some((l) => l.includes(token)),
    'het token hoort juist WEL in de uitnodiging: anders komt niemand binnen');
});

test('maar de rand schrijft het token wel op: $uri in de selfhost-log', { todo: 'GEDICHT: $uri is uit het log_format van nginx-selfhost.conf, onder de kop die altijd al beloofde dat de URI niet gelogd werd' }, () => {
  // De sleutel lekt nergens uit de relay. Het TOKEN wel, en dat is de andere
  // helft: wie het token en de opgeslagen wrapped_key heeft, heeft het bestand.
  //
  // Het token IS het pad van /v2/pickup/<token>. De selfhost-config logt $uri,
  // met erboven de mededeling dat de URI juist niet gelogd wordt. Dat klopt
  // voor de querystring ($request_uri), niet voor het pad.
  const conf = fs.readFileSync(
    path.join(__dirname, '..', '..', 'deploy', 'nginx-selfhost.conf'), 'utf8');
  const fmt = (conf.match(/^log_format\s+paramant_minimal[\s\S]*?;/m) || [''])[0];
  assert.ok(fmt, 'log_format paramant_minimal niet gevonden');

  // Dit is de stand van zaken, niet de gewenste. Zodra $uri eruit gaat mag
  // deze test omklappen naar assert.ok(!fmt.includes('$uri')).
  assert.ok(fmt.includes('$uri'),
    'als $uri eruit is, is dit gat gedicht: draai de assertie om');
  assert.ok(conf.includes('access_log /var/log/nginx/paramant_access.log paramant_minimal'),
    'de selfhost-config schrijft die regels naar schijf');

  // De live config van paramant.app doet dit niet: daar staat access_log off.
  const live = fs.readFileSync(
    path.join(__dirname, '..', '..', 'deploy', 'nginx-paramant-live.conf'), 'utf8');
  const aan = (live.match(/^\s*access_log\s+(?!off)/gm) || []);
  assert.equal(aan.length, 0,
    'op live staat nu wel een access_log aan, en die vangt ophaaltokens');
});
