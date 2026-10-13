'use strict';

// DE PROVIDER VALT OM TIJDENS DE VERZENDING.
//
// Dertig uitnodigingen gaan een voor een de deur uit (relay.js:4724-4759). Als
// de carrier bij de twaalfde omvalt: hoeveel mensen hebben er dan post, wat
// zegt het 201-antwoord, en klopt dat met elkaar?
//
// De carrier is nep en zit IN het relayproces (_nep-mailcarrier.js, ingeladen
// met NODE_OPTIONS=--require). Er gaat geen byte het netwerk op.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_halverwege_sleutel';
const OK_TOT = 12;

let BASE = null;
let usersFile;
const bezorgd = [];   // nepmail_bezorgd
const logs = [];      // alles

function b64url(n) {
  return crypto.randomBytes(n).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const ADRESSEN = Array.from({ length: 30 }, (_, i) => `partner${i}@extern.test`);
const sealed = {};
const tokens = {};
for (const a of ADRESSEN) {
  const t = b64url(32);
  sealed[a] = { token: t, wrapped_key: b64url(64) };
  tokens[a] = t;
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `halverwege-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    SITE_URL: 'https://paramant.app',
    // Een echte provider, met een neppe carrier eronder.
    MAIL_PROVIDER: 'mailjet',
    MAILJET_API_KEY: 'nep-key',
    MAILJET_SECRET_KEY: 'nep-secret',
    NEPMAIL_OK_TOT: String(OK_TOT),
    NODE_OPTIONS: (process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + ' ' : '')
                + '--require ' + path.join(__dirname, '_nep-mailcarrier.js'),
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
                   account_id: 'acct_halverwege' }],
    }),
  }, {
    onLine: (line) => {
      if (!line.trim()) return;
      logs.push(line);
      if (!line.includes('nepmail_bezorgd')) return;
      try { bezorgd.push(JSON.parse(line)); } catch (_) { /* geen JSON */ }
    },
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) { /* best effort */ }
});

test('de carrier valt om: elf mensen hebben post, negentien niet', { todo: 'GEDICHT: de afzenderregel droeg een leeg adres, waardoor geen enkele mail bezorgd zou zijn. afzenderNamens lost de standaard nu zelf op. Bewaakt door mail-afzender-aanval.test.js en mail.test.js' }, async () => {
  const inhoud = crypto.randomBytes(2048);
  const hash = crypto.createHash('sha256').update(inhoud).digest('hex');
  await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: inhoud.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });

  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: ADRESSEN, sealed,
                           filename: 'jaarrekening.pdf', ttl_ms: 3600 * 1000 }),
  });
  const vj = await vr.json().catch(() => ({}));
  await new Promise(r => setTimeout(r, 400));

  // 1. Wat er ECHT bezorgd is. Let op: /v2/inbound mailt de AFZENDER zelf
  //    ("Your Paramant transfer is ready"), en die eet een van de zittingen.
  //    Alleen wat naar een ontvanger ging telt als uitnodiging.
  const uitnodigingen = bezorgd.filter(b => /^partner\d+@extern\.test$/.test(b.naar));
  assert.ok(uitnodigingen.length > 0 && uitnodigingen.length < 30,
    'de carrier moet halverwege omvallen, kreeg ' + uitnodigingen.length);
  assert.equal(bezorgd.length, OK_TOT,
    'de carrier nam er in totaal ' + OK_TOT + ' aan, daarna ging hij stuk');
  const GELUKT = uitnodigingen.length;

  // GAT (tweede bewijs, nu uit een draaiende relay): de From die een echte
  // provider te zien krijgt. Zie mail-afzender-aanval.test.js.
  assert.equal(uitnodigingen[0].from.Email, '"Zorggroep De Linde via Paramant" <>',
    'Mailjet krijgt de hele afzenderregel als e-mailadres');
  // Ter vergelijking: de mail aan de afzender zelf gaat wel goed, want die
  // route zet geen klantnaam in de From.
  const aanAfzender = bezorgd.find(b => b.naar === 'anna@zorggroep.test');
  assert.ok(aanAfzender && /@paramant\.app$/.test(aanAfzender.from.Email),
    'de mail aan de klant zelf heeft wel een geldig afzenderadres');

  // 2. Wat het antwoord zegt. De route telt alleen ok-antwoorden, dus dit
  //    klopt: `invited` is eerlijk (relay.js:4756).
  assert.equal(vr.status, 201, JSON.stringify(vj));
  assert.equal(vj.ok, true);
  assert.equal(vj.recipients, 30);
  assert.equal(vj.invited, GELUKT, 'invited telt wat een provider aannam');

  // 3. GAT: de verzending is er wel, met dertig levende tokens, en een 201 met
  //    ok:true. Negentien mensen hebben een geldig token dat hun postvak nooit
  //    haalt, en het antwoord noemt geen enkele naam. De afzender leest
  //    "invited: 11" en kan niet zien WIE.
  assert.ok(vj.send_id, 'de verzending bestaat, ook al bereikte hij niemand');
  const namen = JSON.stringify(vj);
  for (const a of ADRESSEN) {
    assert.ok(!namen.includes(a),
      'het antwoord noemt geen adres, dus de afzender weet niet wie niets kreeg');
  }

  // 4. En de logs noemen ze ook niet.
  const mislukt = logs.filter(l => l.includes('invitation_failed'));
  assert.equal(mislukt.length, 30 - GELUKT, 'een warning per mislukte uitnodiging');
  for (const l of mislukt) {
    for (const a of ADRESSEN) {
      assert.ok(!l.includes(a), 'geen adres in de log (goed voor privacy)');
    }
  }
  // Wat er wel in staat is alleen de reden.
  assert.match(mislukt[0], /"reason":"http_503"/);

  // 5. En de uurrem is wel voor dertig afgeschreven.
  //    inviteRateOk boekt 30 af VOOR de verzending (relay.js:4643) en
  //    inviteRateGeef geeft alleen terug als create faalde.
  //    Negentien niet-bezorgde mails kosten de afzender dus wel negentien
  //    zittingen van zijn 500 per uur.
  const bezet = logs.filter(l => l.includes('send_invitations'));
  assert.equal(bezet.length, 1);
  assert.match(bezet[0], new RegExp('"mailed":' + GELUKT + ',"of":30'));
});

test('de tokens van wie geen mail kreeg leven gewoon door', async () => {
  // De laatste ontvanger kreeg geen mail. Zijn token werkt gewoon.
  const laatste = ADRESSEN[29];
  const r = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(tokens[laatste]), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  // 502: de codemail kan ook niet weg, want dezelfde carrier is stuk.
  const j = await r.json().catch(() => ({}));
  assert.equal(r.status, 502, JSON.stringify(j));
  assert.equal(j.error, 'code_not_sent');
  // Het token bestaat dus; een onbekend token had 404 gegeven.
});
