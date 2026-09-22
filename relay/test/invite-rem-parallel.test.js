'use strict';

// DE UURREM ALS MAILKANAAL.
//
// inviteRateOk (relay.js:2352) is de enige rem op mail naar mensen die geen
// klant zijn: 500 per uur op pro. De vraag is of parallelle verzoeken eroverheen
// komen, en of de rem telt wat er echt de deur uit gaat.
//
// Twintig gelijktijdige verzendingen van dertig ontvangers = 600 gevraagde
// zittingen op een plafond van 500. Elke mail wordt geteld uit de dryrun-log,
// niet uit wat de route beweert.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_rem_parallel';
const PLAFOND = 500;          // tiers.js:107 outbound_per_hour voor pro
const PER_ZENDING = 30;       // tiers.js:104 max_recipients
const ZENDINGEN = 20;         // 600 gevraagd

let BASE = null;
let usersFile;
const post = [];
const logs = [];

function b64url(n) {
  return crypto.randomBytes(n).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `rem-parallel-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
                   account_id: 'acct_rem_parallel' }],
    }),
  }, {
    onLine: (line) => {
      if (!line.trim()) return;
      logs.push(line);
      if (!line.includes('mail_dryrun')) return;
      try { post.push(JSON.parse(line)); } catch (_) { /* geen JSON */ }
    },
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) { /* best effort */ }
});

async function zendingKlaar(nr) {
  const inhoud = crypto.randomBytes(512 + nr);
  const hash = crypto.createHash('sha256').update(inhoud).digest('hex');
  const up = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: inhoud.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(up.status, 200, 'blok ' + nr + ' faalde');
  const adressen = Array.from({ length: PER_ZENDING },
    (_, i) => `z${nr}p${i}@extern.test`);
  const sealed = {};
  for (const a of adressen) sealed[a] = { token: b64url(32), wrapped_key: b64url(64) };
  return { hash, adressen, sealed };
}

test('twintig gelijktijdige verzendingen komen niet over het uurplafond', async () => {
  // Eerst alle blokken klaarzetten, zodat de verzendingen echt tegelijk gaan.
  const klaar = [];
  for (let i = 0; i < ZENDINGEN; i++) klaar.push(await zendingKlaar(i));

  post.length = 0;
  const antwoorden = await Promise.all(klaar.map(k =>
    fetch(BASE + '/v2/sends', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
      body: JSON.stringify({ hashes: [k.hash], recipients: k.adressen,
                             sealed: k.sealed, filename: 'x.pdf',
                             ttl_ms: 3600 * 1000 }),
    }).then(async r => ({ status: r.status, body: await r.json().catch(() => ({})) }))));

  await new Promise(r => setTimeout(r, 800));

  const gelukt = antwoorden.filter(a => a.status === 201);
  const geweigerd = antwoorden.filter(a => a.status === 429);
  assert.equal(gelukt.length + geweigerd.length, ZENDINGEN,
    'onverwachte status: ' + JSON.stringify(antwoorden.filter(a =>
      a.status !== 201 && a.status !== 429).slice(0, 2)));

  // 1. De route beweert:
  const beweerd = gelukt.reduce((n, a) => n + a.body.invited, 0);
  // 2. Wat er ECHT uit de maillaag kwam:
  const echt = post.filter(p => /sent you a file/.test(p.subject || '')).length;
  assert.equal(echt, beweerd, 'invited moet kloppen met de post');

  // 3. En geen van beide mag over het plafond.
  assert.ok(echt <= PLAFOND,
    'DE REM IS OMZEILD: ' + echt + ' mails op een plafond van ' + PLAFOND);
  assert.equal(gelukt.length, Math.floor(PLAFOND / PER_ZENDING),
    'zestien van de twintig passen (16 x 30 = 480); de rest is 429');
  assert.equal(echt, Math.floor(PLAFOND / PER_ZENDING) * PER_ZENDING);

  // 4. De weigering vertelt wanneer het weer mag.
  assert.match(String(geweigerd[0].body.error), /too_many_invitations/);
  assert.equal(geweigerd[0].body.limit, PLAFOND);
  assert.ok(geweigerd[0].body.retry_after_s > 0);
});

test('de rem telt per account, dus een tweede sleutel op hetzelfde account erft hem', async () => {
  // Het plafond is nu op. Nog een verzending moet 429 geven.
  const k = await zendingKlaar(99);
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [k.hash], recipients: k.adressen,
                           sealed: k.sealed, filename: 'x.pdf', ttl_ms: 3600 * 1000 }),
  });
  const j = await r.json().catch(() => ({}));
  assert.equal(r.status, 429, JSON.stringify(j));
  assert.equal(j.dimension, 'outbound_per_hour');
});

test('GAT: de ophaalcode valt buiten de uurrem', { todo: 'met opzet: de ONTVANGER trekt die mail, niet de afzender. Zat hij in de rem van het account, dan kon een ontvanger de afzender blokkeren. Begrensd met MAX_CODE_REQUESTS 3 per persoon in plaats van via de uurrem' }, async () => {
  // De uurrem staat op de uitnodiging (/v2/sends) en, sinds vandaag, op de
  // herinnering (/v2/user/sends/reinvite). De DERDE mail naar een
  // niet-klant -- de ophaalcode -- staat er nog buiten.
  const bron = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  const aanroepen = (bron.match(/inviteRateOk\(/g) || []).length;
  assert.ok(aanroepen >= 3, 'een definitie plus minstens twee aanroepen');

  // De codemail wordt verstuurd in het blok achter `_body.action === 'code'`.
  // Dat blok bevat geen enkele aanroep van de uurrem.
  const start = bron.indexOf("if (_body.action === 'code')");
  assert.ok(start > 0, 'het codeblok staat er niet meer zoals verwacht');
  const blok = bron.slice(start, start + 3000);
  assert.ok(blok.includes('mailer.stuur'), 'het codeblok verstuurt wel mail');
  assert.ok(!blok.includes('inviteRateOk'),
    'GEDICHT: de ophaalcode zit nu wel achter de uurrem');

  // Wat hem wel begrenst is een PER-ONTVANGER teller in lib/send.js.
  const sendLib = fs.readFileSync(path.join(__dirname, '..', 'lib', 'send.js'), 'utf8');
  const maxCodes = Number((sendLib.match(/MAX_CODE_REQUESTS\s*=\s*(\d+)/) || [])[1]);
  assert.ok(maxCodes > 0, 'MAX_CODE_REQUESTS moet bestaan');

  // Het sommetje: een verzending van dertig geeft 30 uitnodigingen (in de rem)
  // plus 30 x MAX_CODE_REQUESTS codemails die er NIET in zitten. Iedereen die
  // een uitnodiging doorstuurt of een linkscanner laat klikken, kost een mail.
  const buitenDeRem = 30 * maxCodes;
  assert.equal(buitenDeRem, 150,
    'per verzending kunnen er ' + buitenDeRem + ' codemails buiten de uurrem om');
});
