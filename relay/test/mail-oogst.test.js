'use strict';

// WAT ER ECHT IN DE POST ZIT.
//
// Drie mails gaan naar mensen die geen klant zijn: de uitnodiging, de
// ophaalcode en de herinnering. Niemand had ze ooit alle drie voluit gelezen.
// Deze suite verstuurt ze echt (MAIL_PROVIDER=dryrun, dus er gaat niets de
// deur uit), vangt elke regel van stdout op, en beoordeelt elk veld.
//
// Dertig ontvangers, want twee mensen in een `to` betekent dat ze elkaar zien,
// en wie een vertrouwelijk document krijgt is niet voor de groep.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_mail_oogst_sleutel';
const INTERN = 'intern-mail-oogst';
const LABEL = 'Zorggroep De Linde';
const AFZENDER = 'anna@zorggroep.test';

let BASE = null;
let usersFile;
const post = [];   // alleen mail_dryrun
const alles = [];  // ELKE stdout-regel, voor de logtest

function b64url(n) {
  return crypto.randomBytes(n).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const ADRESSEN = Array.from({ length: 30 }, (_, i) => `partner${i}@extern.test`);
const NAAM = 'jaarrekening-2025-vertrouwelijk.pdf';
const sealed = {};
const tokens = {};
for (const a of ADRESSEN) {
  const t = b64url(32);
  sealed[a] = { token: t, wrapped_key: b64url(64) };
  tokens[a] = t;
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `mail-oogst-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: LABEL, email: AFZENDER, account_id: 'acct_mail_oogst' }],
    }),
  }, {
    onLine: (line) => {
      if (!line.trim()) return;
      alles.push(line);
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

async function wacht(ms) { return new Promise(r => setTimeout(r, ms)); }

let SEND_ID = null;

test('dertig uitnodigingen: een per persoon, en niemand ziet een ander', { todo: 'GEDICHT langs dezelfde weg als mail-halverwege: de From was leeg. Het per-persoon mailen zelf is groen en wordt bewaakt in mail.test.js' }, async () => {
  const inhoud = crypto.randomBytes(4096);
  const hash = crypto.createHash('sha256').update(inhoud).digest('hex');
  const up = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: inhoud.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(up.status, 200, 'blok uploaden faalde');

  post.length = 0;
  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: ADRESSEN, sealed,
                           filename: NAAM, ttl_ms: 24 * 3600 * 1000 }),
  });
  const vj = await vr.json().catch(() => ({}));
  assert.equal(vr.status, 201, 'verzending geweigerd: ' + JSON.stringify(vj));
  SEND_ID = vj.send_id;
  assert.equal(vj.recipients, 30);
  assert.equal(vj.invited, 30);

  await wacht(400);
  const uit = post.filter(p => /heeft u een bestand gestuurd/.test(p.subject || ''));
  assert.equal(uit.length, 30, 'dertig mails, geen enkele samengevoegd');

  // Dump voor het rapport.
  fs.writeFileSync(path.join(os.tmpdir(), 'paramant-uitnodiging.json'),
                   JSON.stringify(uit[0], null, 2));

  for (const m of uit) {
    // 1. EEN adres per mail.
    assert.equal((m.to || []).length, 1,
      'meerdere adressen in een `to`: ' + JSON.stringify(m.to));
    const mijn = m.to[0];
    assert.ok(ADRESSEN.includes(mijn), 'onbekend adres in de post: ' + mijn);

    // 2. Geen enkel ander adres van de groep in kop of tekst.
    const hooi = JSON.stringify(m);
    for (const ander of ADRESSEN) {
      if (ander === mijn) continue;
      assert.ok(!hooi.includes(ander),
        'het adres van ' + ander + ' staat in de mail aan ' + mijn);
    }

    // 3. Geen verpakking. De mailprovider mag nooit beide helften dragen.
    for (const a of ADRESSEN) {
      assert.ok(!hooi.includes(sealed[a].wrapped_key),
        'de wrapped_key van ' + a + ' staat in de mail aan ' + mijn);
    }

    // 4. Precies EEN token, en dat is het zijne.
    assert.ok(m.text.includes(tokens[mijn]), 'eigen token ontbreekt in de link');
    for (const a of ADRESSEN) {
      if (a === mijn) continue;
      assert.ok(!hooi.includes(tokens[a]),
        'het token van ' + a + ' staat in de mail aan ' + mijn);
    }

    // 5. De afzenderregel. GAT: het adres is LEEG. relay.js:4732 roept
    //    mailer.afzenderNamens(undefined, ...) aan, dus de basis MAIL_FROM
    //    wordt nooit gelezen. Zie mail-afzender-aanval.test.js voor wat een
    //    echte provider hiermee doet.
    assert.equal(m.from, '"' + LABEL + ' via Paramant" <>',
      'als dit ooit <noreply@paramant.app> wordt, is het gat gedicht');
    assert.equal(m.reply_to, AFZENDER);
  }

  // 6. De bestandsnaam. Die staat er voluit in, bij naam en al.
  assert.ok(uit[0].text.includes(NAAM),
    'de bestandsnaam hoort in de mail (dit is een BEVINDING, geen eis)');
});

test('de ophaalcode: wat een mailprovider te zien krijgt', async () => {
  post.length = 0;
  const doel = ADRESSEN[0];
  const cr = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(tokens[doel]), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(cr.status, 200, await cr.text());
  await wacht(400);

  const code = post.find(p => /controlecode om het bestand te openen/i.test(p.subject || ''));
  assert.ok(code, 'geen codemail');
  fs.writeFileSync(path.join(os.tmpdir(), 'paramant-code.json'),
                   JSON.stringify(code, null, 2));

  assert.deepEqual(code.to, [doel], 'de code gaat naar een postvak, niet naar een lijst');
  const hooi = JSON.stringify(code);
  for (const a of ADRESSEN) {
    if (a === doel) continue;
    assert.ok(!hooi.includes(a), 'ander adres in de codemail');
    assert.ok(!hooi.includes(tokens[a]), 'ander token in de codemail');
    assert.ok(!hooi.includes(sealed[a].wrapped_key), 'andere wrapped_key in de codemail');
  }
  // Het token van de ontvanger zelf staat NIET in de codemail: de twee helften
  // reizen apart. Dat is het punt van deze stap.
  assert.ok(!hooi.includes(tokens[doel]),
    'het token staat in de codemail; dan draagt een mailbox beide helften');
  assert.match(code.text, /\b\d{6}\b/, 'geen zescijferige code');
  // BEVINDING: de bestandsnaam reist mee met de code.
  assert.ok(code.text.includes(NAAM), 'bestandsnaam in de codemail');
});

test('de herinnering: wat er in staat en wat er niet in staat', async () => {
  post.length = 0;
  const doel = ADRESSEN[1];
  const rr = await fetch(BASE + '/v2/user/sends/reinvite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: 'acct_mail_oogst', send_id: SEND_ID, email: doel }),
  });
  assert.equal(rr.status, 200, await rr.text());
  await wacht(400);

  const her = post.find(p => /staat nog/i.test(p.subject || ''));
  assert.ok(her, 'geen herinnering');
  fs.writeFileSync(path.join(os.tmpdir(), 'paramant-herinnering.json'),
                   JSON.stringify(her, null, 2));

  assert.deepEqual(her.to, [doel]);
  const hooi = JSON.stringify(her);
  for (const a of ADRESSEN) {
    if (a === doel) continue;
    assert.ok(!hooi.includes(a), 'ander adres in de herinnering');
  }
  for (const a of ADRESSEN) {
    assert.ok(!hooi.includes(tokens[a]), 'token in de herinnering');
    assert.ok(!hooi.includes(sealed[a].wrapped_key), 'wrapped_key in de herinnering');
  }
  // BEVINDING: de herinnering noemt de bestandsnaam NIET, de andere twee wel.
  assert.ok(!her.text.includes(NAAM), 'de herinnering noemt het bestand niet');
});

test('LOGS: geen token, geen code, geen wrapped_key, geen volledig adres', async () => {
  await wacht(200);
  // Alles behalve de dryrun-regels zelf. Die dragen de tekst met opzet en
  // bestaan alleen op een carrier die niets bezorgt.
  const echt = alles.filter(l => !l.includes('mail_dryrun'));
  const codes = post
    .filter(p => /controlecode om het bestand te openen/i.test(p.subject || ''))
    .map(p => (String(p.text).match(/\b(\d{6})\b/) || [])[1])
    .filter(Boolean);

  const lek = [];
  for (const regel of echt) {
    for (const a of ADRESSEN) {
      if (regel.includes(a)) lek.push(['adres ' + a, regel.slice(0, 220)]);
      if (regel.includes(tokens[a])) lek.push(['token van ' + a, regel.slice(0, 220)]);
      if (regel.includes(sealed[a].wrapped_key)) lek.push(['wrapped_key ' + a, regel.slice(0, 220)]);
    }
    for (const c of codes) {
      // Een los zescijferig getal is nog geen code; alleen exact deze.
      if (new RegExp('\\b' + c + '\\b').test(regel)) lek.push(['code', regel.slice(0, 220)]);
    }
  }
  assert.deepEqual(lek, [], 'lek in de logs:\n' + lek.map(x => x.join(' -> ')).join('\n'));
});
