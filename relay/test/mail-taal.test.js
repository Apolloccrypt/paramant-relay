'use strict';

// DE TAAL VAN DE MAIL AAN EEN ONTVANGER.
//
// De verzendpagina geeft de taal mee waarin hij werd getoond ('nl' of 'en').
// Zonder taal krijgt de ontvanger Nederlands met het Engels eronder, zodat
// niemand een mail krijgt die hij niet kan lezen. De uitnodiging, de code en
// de herinnering volgen alle drie de taal van de verzending.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_mail_taal_sleutel';
let BASE = null;
let usersFile;
const post = [];

const wrapSrc = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

before(async () => {
  usersFile = path.join(os.tmpdir(), `mail-taal-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Acme', email: 'demo@example.com',
                   account_id: 'acct_demo_taal' }],
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

const wacht = (ms) => new Promise((r) => setTimeout(r, ms));

// Een verzending naar een ontvanger, met of zonder taal. Geeft de uitnodiging,
// het token en het send-id terug.
async function verstuur(lang, adres) {
  const blok = crypto.randomBytes(2048);
  const hash = crypto.createHash('sha256').update(blok).digest('hex');
  const up = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: blok.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(up.status, 200, 'blok uploaden faalde');
  const token = wrap.newToken();
  const sealed = { [adres]: { token, wrapped_key: await wrap.wrap(token, new Uint8Array(44)) } };
  const body = { hashes: [hash], recipients: [adres], sealed,
                 filename: 'offerte.pdf', ttl_ms: 24 * 3600 * 1000 };
  if (lang !== undefined) body.lang = lang;
  post.length = 0;
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  assert.equal(r.status, 201, 'verzending geweigerd: ' + JSON.stringify(j));
  await wacht(300);
  const mail = post.find((p) => (p.to || []).includes(adres));
  assert.ok(mail, 'geen uitnodiging voor ' + adres);
  return { mail, token, id: j.send_id };
}

async function vraagCode(token) {
  post.length = 0;
  const r = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(r.status, 200, 'code aanvragen faalde');
  await wacht(300);
  const mail = post[post.length - 1];
  assert.ok(mail, 'geen codemail');
  return mail;
}

test('zonder taal: Nederlands, met het Engels eronder', async () => {
  const { mail, token } = await verstuur(undefined, 'een@example.com');
  assert.match(mail.subject, /^Acme heeft u een bestand gestuurd$/);
  assert.match(mail.text, /heeft u via Paramant een bestand gestuurd/);
  assert.match(mail.text, /-- English --/);
  assert.match(mail.text, /Acme sent you a file through Paramant\./);
  assert.ok(mail.text.indexOf('Beschikbaar tot') < mail.text.indexOf('Available until'),
    'het Nederlands staat boven het Engels');
  assert.match(mail.text, /https:\/\/paramant\.app\/ontvang\//,
    'de link blijft op het Nederlandse pad, waar ook oudere mails heen wijzen');

  const code = await vraagCode(token);
  assert.match(code.subject, /^Uw controlecode om het bestand te openen$/);
  assert.match(code.text, /Uw controlecode is \d{6}\./);
  assert.match(code.text, /Your code is \d{6}\./);
});

test('taal nl: alleen Nederlands', async () => {
  const { mail, token } = await verstuur('nl', 'twee@example.com');
  assert.match(mail.subject, /heeft u een bestand gestuurd/);
  assert.doesNotMatch(mail.text, /English|sent you a file|Available until/);
  const code = await vraagCode(token);
  assert.match(code.text, /Uw controlecode is \d{6}\./);
  assert.doesNotMatch(code.text, /Your code is/);
});

test('taal en: alleen Engels, en de link naar de Engelse pagina', async () => {
  const { mail, token, id } = await verstuur('en', 'drie@example.com');
  assert.match(mail.subject, /^Acme sent you a file$/);
  assert.match(mail.text, /Acme sent you a file through Paramant\./);
  assert.match(mail.text, /The link is yours alone and works once\./);
  assert.doesNotMatch(mail.text, /heeft u|Beschikbaar tot/);
  assert.match(mail.text, /https:\/\/paramant\.app\/en\/ontvang\//);

  const code = await vraagCode(token);
  assert.match(code.subject, /^Your code to open the file$/);
  assert.match(code.text, /Your code is \d{6}\. It works for \d+ minutes\./);
  assert.doesNotMatch(code.text, /controlecode/);
  assert.ok(id, 'send-id ontbreekt');
});

test('een onbekende taal telt als geen taal', async () => {
  const { mail } = await verstuur('fr', 'vier@example.com');
  assert.match(mail.subject, /heeft u een bestand gestuurd/);
  assert.match(mail.text, /-- English --/);
});
