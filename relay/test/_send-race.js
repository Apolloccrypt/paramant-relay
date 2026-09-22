'use strict';

// Gedeeld gereedschap voor de race-aanvallen op de verzendroute.
//
// WAAROM DIT BESTAAT. De aanval moet met ECHTE gelijktijdige HTTP-verzoeken
// gebeuren, niet met nepstores: het gat dat opVolgorde in lib/send.js dicht
// moet houden zit precies tussen de `await` van een lezing en die van de
// bijbehorende schrijving, en dat venster bestaat alleen in een draaiend
// proces. Dus boot elke suite hier relay.js als apart proces, net zoals
// groep-e2e.test.js dat doet, en praat er over de draad mee.
//
// De wikkeling is hier NIET echt: recipients.buildRecipients keurt `token` op
// TOKEN_SHAPE (/^[A-Za-z0-9_-]{32,128}$/) en `wrapped_key` op WRAP_SHAPE
// (/^[A-Za-z0-9_-]{16,4096}$/) en kijkt verder niet naar de inhoud. Voor een
// racetest telt alleen of er bytes uitkomen en hoe vaak; of die bytes daarna
// te openen zijn is wat groep-e2e.test.js al bewijst.

const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay } = require('./_boot-relay');

const API_KEY = 'pgp_race_sleutel';
const INTERN = 'race-intern-token';
const ACCOUNT = 'acct_race';

function nieuwToken() { return crypto.randomBytes(32).toString('base64url'); }
function nieuweWikkel() { return crypto.randomBytes(48).toString('base64url'); }
function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

// Boot een relay met dryrun-post en de interne poort open.
// `post` vult zich met elke mail_dryrun-regel, in volgorde.
//
// opties.traagMs > 0 zet er een opzettelijk trage nep-redis onder
// (_traag-redis.js). Dat is geen luxe: zonder redis valt de verzendopslag terug
// op een Map in het geheugen (lib/parasign-store.js:91) en lost elke get/put
// SYNCHROON op. Er is dan geen opschortpunt tussen lezen en schrijven, dus de
// race die opVolgorde moet dichthouden kan in die opstelling niet eens
// optreden. Met de stub kost elke get en put echte milliseconden en staat het
// venster wijd open -- zo meet de test iets.
async function bootSendRelay(extra = {}, opties = {}) {
  const post = [];
  let stub = null;
  if (opties.traagMs) {
    const { startTraagRedis } = require('./_traag-redis');
    stub = await startTraagRedis({ vertragingMs: opties.traagMs });
    extra = { REDIS_URL: stub.url,
              PARASIGN_STORE_KEY: crypto.randomBytes(32).toString('base64'),
              ...extra };
  }
  const usersFile = path.join(os.tmpdir(),
    `send-race-users-${process.pid}-${crypto.randomBytes(4).toString('hex')}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.test',
    INTERNAL_AUTH_TOKEN: INTERN,
    // enterprise: outbound_per_hour is er ongelimiteerd, anders hakt de
    // uitnodigingslimiet de massatest om voordat de wachtrij aan bod komt.
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'enterprise',
                   plan_parasend: 'enterprise', label: 'Racekantoor',
                   email: 'baas@race.test', account_id: ACCOUNT }],
    }),
    ...extra,
  }, {
    onLine: (line) => {
      if (!line.includes('mail_dryrun')) return;
      try { post.push(JSON.parse(line)); } catch (_) { /* geen JSON */ }
    },
  });
  relay.post = post;
  relay.usersFile = usersFile;
  relay.stub = stub;
  relay.backend = stub ? 'redis' : 'memory';
  return relay;
}

// De uploadroute heeft toelatingsbeheer: boven een aantal gelijktijdige
// uploads antwoordt hij 503 met inbound_rejected_ram. Dat is opzet en geen
// fout, maar het staat een massatest in de weg, dus hier wordt er kort op
// gewacht. Alleen op 503; elke andere status is wel een bevinding.
async function uploadBlok(base, bytes, pogingen = 25) {
  const hash = sha256hex(bytes);
  for (let i = 0; ; i++) {
    const r = await fetch(base + '/v2/inbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
      body: JSON.stringify({ hash, payload: bytes.toString('base64'),
                             meta: { device_id: 'transfer-web-link' } }),
    });
    await r.text();
    if (r.status === 200) return hash;
    if (r.status !== 503 || i >= pogingen) {
      throw new Error('blokupload faalde: ' + r.status + ' na ' + (i + 1) + ' pogingen');
    }
    await new Promise((res) => setTimeout(res, 40 + i * 20));
  }
}

// Maak een verzending. Geeft { id, tokens, adressen, inhoud } terug.
async function maakVerzending(base, adressen, opties = {}) {
  const inhoud = opties.inhoud || crypto.randomBytes(opties.bytes || 64);
  const hash = await uploadBlok(base, inhoud);
  const sealed = {};
  const tokens = {};
  for (const a of adressen) {
    const t = nieuwToken();
    sealed[a] = { token: t, wrapped_key: nieuweWikkel() };
    tokens[a] = t;
  }
  const r = await fetch(base + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                           filename: opties.filename || 'stuk.pdf',
                           ttl_ms: opties.ttlMs || 3600_000 }),
  });
  const j = await r.json().catch(() => ({}));
  if (r.status !== 201) throw new Error('verzending geweigerd: ' + r.status + ' ' + JSON.stringify(j));
  return { id: j.send_id, tokens, adressen, inhoud, body: j };
}

function pickup(base, token, body) {
  return fetch(base + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function intern(base, pad, body) {
  return fetch(base + pad, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: ACCOUNT, ...body }),
  });
}

// Vraag een code aan en vis hem uit de dryrun-log.
async function haalCode(relay, token, adres) {
  const voor = relay.post.length;
  const r = await pickup(relay.base, token, { action: 'code' });
  if (r.status !== 200) throw new Error('code aanvragen faalde: ' + r.status);
  for (let i = 0; i < 60; i++) {
    const mail = relay.post.slice(voor).find(
      (p) => /code to open the file/i.test(p.subject || '') && (p.to || []).includes(adres));
    if (mail) {
      const code = (String(mail.text).match(/\b(\d{6})\b/) || [])[1];
      if (code) return code;
    }
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error('geen codemail gezien voor ' + adres);
}

// Leeft het proces nog, en zo nee: waaraan ging het dood?
function levendOf(relay) {
  if (!relay.exited) return null;
  return `relay is AFGESLOTEN code=${relay.exitCode} signal=${relay.exitSignal}\n${relay.output()}`;
}

module.exports = { API_KEY, INTERN, ACCOUNT, bootSendRelay, uploadBlok,
                   maakVerzending, pickup, intern, haalCode, levendOf,
                   nieuwToken, nieuweWikkel, sha256hex };
