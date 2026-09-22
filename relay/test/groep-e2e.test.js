'use strict';

// DE HELE REIS, tegen een echt draaiende relay.
//
// Alles wat hiervoor bestond was unit: nepstores, losse functies, en greps op
// de broncode. Geen enkele test had de route ooit als server aangeroepen, en
// niemand had de reis van afzender tot ontvanger één keer gelopen. Dat is
// precies het soort gat waar "het is af" wordt gezegd over iets dat niemand
// bereikt: deze functie had er vier tegelijk.
//
// Dus: een relay uit relay.js, een bestand dat niet in één blok past, dertig
// ontvangers, de uitnodiging onderschept uit de maillog, de code eruit gevist,
// en aan het eind de vraag die telt -- komen de bytes er heel uit.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_groep_e2e_sleutel';
let BASE = null;
let usersFile;

// Elke maildryrun-regel die de relay uitspuugt, in volgorde.
const post = [];

// De echte wikkelcode uit de browser, in deze test geladen zoals send-wrap.test
// dat doet. Dezelfde bytes aan beide kanten, of het bewijs is niets waard.
const wrapSrc = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

const LINK_MAX_BLOB = 5 * 1024 * 1024;

function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; }
function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

before(async () => {
  usersFile = path.join(os.tmpdir(), `groep-e2e-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    // dryrun bezorgt niets en logt wat er verstuurd zou zijn. Zo kan de test
    // de uitnodiging en de code lezen zonder dat er post de deur uit gaat.
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
                   account_id: 'acct_groep_e2e' }],
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

test('een bestand van 12 MB naar 25 mensen, en er komt er een ophalen', async () => {
  // ── 1. De afzender verzegelt, precies zoals parashare.page.js doet ──────
  const inhoud = crypto.randomBytes(12 * 1024 * 1024);
  const naam = 'jaarrekening-2025.pdf';
  const naamBytes = Buffer.from(naam, 'utf8');
  const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, inhoud]);

  const rawKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  // ── 2. In blokken die over de draad passen, en elk apart geüpload ───────
  const stukken = [];
  for (let at = 0; at < ct.length; at += LINK_MAX_BLOB) {
    stukken.push(ct.subarray(at, Math.min(at + LINK_MAX_BLOB, ct.length)));
  }
  assert.ok(stukken.length > 1,
    'twaalf megabyte hoort meer dan een blok te zijn, anders test dit niets');

  const hashes = [];
  for (const deel of stukken) {
    const hash = sha256hex(deel);
    const r = await fetch(BASE + '/v2/inbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
      body: JSON.stringify({ hash, payload: deel.toString('base64'),
                             meta: { device_id: 'transfer-web-link' } }),
    });
    const j = await r.json().catch(() => ({}));
    assert.equal(r.status, 200, 'blokupload faalde: ' + JSON.stringify(j));
    hashes.push(hash);
  }

  // ── 3. Vijfentwintig ontvangers, elk met een eigen gewikkelde sleutel ───
  const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));  // 44 bytes
  const adressen = Array.from({ length: 25 }, (_, i) => `partner${i}@extern.test`);
  const sealed = {};
  const tokens = {};
  for (const adres of adressen) {
    const token = wrap.newToken();
    sealed[adres] = { token, wrapped_key: await wrap.wrap(token, geheim) };
    tokens[adres] = token;
  }

  // ── 4. De verzending ────────────────────────────────────────────────────
  post.length = 0;
  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes, recipients: adressen, sealed,
                           filename: naam, ttl_ms: 24 * 3600 * 1000 }),
  });
  const vj = await vr.json().catch(() => ({}));
  assert.equal(vr.status, 201, 'de verzending werd geweigerd: ' + JSON.stringify(vj));
  assert.equal(vj.recipients, 25, 'vijfentwintig mensen op een Firm-account');
  assert.equal(vj.invited, 25, 'en vijfentwintig uitnodigingen die de deur uit gingen');
  assert.equal(vj.size, ct.length, 'de blokken zijn tot precies het bestand samengevoegd');

  // ── 5. Wat er in de bus valt ────────────────────────────────────────────
  await new Promise((r) => setTimeout(r, 200));   // de log loopt iets achter
  const uitnodigingen = post.filter((p) => /sent you a file/.test(p.subject || ''));
  assert.equal(uitnodigingen.length, 25, 'een mail per persoon, nooit een cc');

  const voorEen = uitnodigingen.find((p) => (p.to || []).includes(adressen[0]));
  assert.ok(voorEen, 'de eerste ontvanger kreeg geen post');
  assert.match(voorEen.from, /Zorggroep De Linde via Paramant/,
    'de klant staat boven de mail, anders leest hij als phishing');
  assert.equal(voorEen.reply_to, 'anna@zorggroep.test',
    'en een antwoord komt bij de afzender, niet bij noreply');
  assert.match(voorEen.text, /\?r=health/,
    'de link draagt de sector, anders vraagt de ontvanger het aan de verkeerde relay');
  assert.ok(!voorEen.text.includes(sealed[adressen[0]].wrapped_key),
    'de verpakking mag NOOIT in de mail: dan draagt de mailprovider beide helften');

  // ── 6. De ontvanger haalt op ────────────────────────────────────────────
  const token = tokens[adressen[0]];
  post.length = 0;
  const cr = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  const cj = await cr.json().catch(() => ({}));
  assert.equal(cr.status, 200, 'code aanvragen faalde: ' + JSON.stringify(cj));
  assert.match(cj.sent_to || '', /\*/, 'het adres komt gemaskeerd terug, niet voluit');

  await new Promise((r) => setTimeout(r, 200));
  const codeMail = post.find((p) => /code to open the file/i.test(p.subject || ''));
  assert.ok(codeMail, 'er kwam geen codemail');
  assert.equal((codeMail.to || [])[0], adressen[0],
    'de code gaat naar het postvak van de uitnodiging, en nergens anders heen');
  const code = (String(codeMail.text).match(/\b(\d{6})\b/) || [])[1];
  assert.ok(code, 'geen zescijferige code in de mail: ' + codeMail.text);

  // Een foute gok eerst, want dat is wat een mens doet.
  const fout = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: '000000' }),
  });
  const fj = await fout.json().catch(() => ({}));
  // 401, niet 400: de route behandelt een foute code als "niet aangetoond dat
  // je het bent", en dat is dezelfde familie als een ontbrekende sleutel.
  assert.equal(fout.status, 401,
    'een foute code hoort geweigerd te worden, kreeg ' + fout.status + ': ' + JSON.stringify(fj));
  assert.equal(fj.error, 'wrong_code');
  assert.ok(typeof fj.tries_left === 'number', 'en zeggen hoeveel pogingen er over zijn');

  // En dan de goede.
  const or_ = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  assert.equal(or_.status, 200, 'de goede code werd niet geaccepteerd');

  const gewikkeld = or_.headers.get('X-Paramant-Key');
  assert.ok(gewikkeld, 'zonder de verpakking kan de ontvanger niets openen');
  const bytes = Buffer.from(await or_.arrayBuffer());

  // ── 7. DE VRAAG DIE TELT: komt het bestand er heel uit ──────────────────
  const sleutel = await wrap.unwrap(token, gewikkeld);
  const d = crypto.createDecipheriv('aes-256-gcm',
    Buffer.from(sleutel.rawKey), Buffer.from(sleutel.iv));
  d.setAuthTag(bytes.subarray(bytes.length - 16));
  const uit = Buffer.concat([d.update(bytes.subarray(0, bytes.length - 16)), d.final()]);

  const naamLen = uit.readUInt32LE(0);
  assert.equal(uit.subarray(4, 4 + naamLen).toString('utf8'), naam,
    'de bestandsnaam kwam er niet heel uit');
  assert.ok(uit.subarray(4 + naamLen).equals(inhoud),
    'het bestand kwam er niet byte voor byte uit');

  // ── 8. En precies een keer ──────────────────────────────────────────────
  const nogEens = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(nogEens.status, 410, 'de link hoort op te zijn');
  const nj = await nogEens.json().catch(() => ({}));
  assert.equal(nj.error, 'already_collected');

  // ── 9. En de sleutel van de een opent die van de ander niet ─────────────
  await assert.rejects(() => wrap.unwrap(tokens[adressen[1]], gewikkeld),
    'een ander token mag deze verpakking nooit openen');
});

test('een ontvanger die niet op de lijst staat komt nergens', async () => {
  const vreemd = 'A'.repeat(43);
  const r = await fetch(BASE + '/v2/pickup/' + vreemd, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(r.status, 404);
  const j = await r.json().catch(() => ({}));
  assert.equal(j.error, 'unknown_token');
});

test('de ophaalroute vraagt geen API-sleutel, want een ontvanger heeft er geen', async () => {
  // Dit was ooit stuk: de route stond achter de sleutelpoort, dus iedere
  // ontvanger kreeg 401 en de functie bereikte niemand.
  const r = await fetch(BASE + '/v2/pickup/' + 'B'.repeat(43), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.notEqual(r.status, 401, 'een ontvanger zonder account moet hier gewoon langs');
});
