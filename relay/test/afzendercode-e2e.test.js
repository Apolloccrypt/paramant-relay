'use strict';

// DE EIGEN CODE VAN DE AFZENDER, tegen een echt draaiende relay.
//
// De relay draait hier met de regel aan (SEND_SENDER_CODE niet gezet): een
// nieuwe send op naam zonder eigen code wordt geweigerd. Dan de hele reis met
// code: verzegelen zoals parashare.page.js doet, de uitnodiging uit de maillog,
// de mailcode, een fout bewijs, het goede bewijs, en de bytes. Onderweg kijkt
// de test in alles wat de server te zien kreeg (verzoeken, mails, logregels)
// of de code er ergens in staat.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_afzendercode_e2e';
let BASE = null;
let usersFile;
const post = [];
const regels = [];

const wrapSrc = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const W = scope.paramantSendWrap;

function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; }
function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }
const wacht = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  usersFile = path.join(os.tmpdir(), `afzendercode-e2e-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile,
    RELAY_MODE: 'full',
    MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    // De regel zelf: niet optioneel.
    SEND_SENDER_CODE: '',
    USERS_JSON: JSON.stringify({
      api_keys: [{ key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
                   label: 'Acme', email: 'demo@example.com',
                   account_id: 'acct_demo_afzendercode' }],
    }),
  }, {
    onLine: (line) => {
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

async function blokOp(ct) {
  const hash = sha256hex(ct);
  const r = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hash, payload: ct.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(r.status, 200, 'blokupload faalde');
  return hash;
}

function verzegel(inhoud, naam) {
  const nb = Buffer.from(naam, 'utf8');
  const plain = Buffer.concat([u32le(nb.length), nb, inhoud]);
  const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  return { ct, geheim: new Uint8Array(Buffer.concat([rawKey, iv])) };
}

function pickup(token, lijf) {
  return fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(lijf),
  });
}

async function mailcode(token, adres) {
  post.length = 0;
  const cr = await pickup(token, { action: 'code' });
  const cj = await cr.json().catch(() => ({}));
  assert.equal(cr.status, 200, 'code aanvragen faalde: ' + JSON.stringify(cj));
  await wacht(200);
  const m = post.find((p) => (p.to || []).includes(adres) && /controlecode/i.test(p.subject || ''));
  assert.ok(m, 'er kwam geen codemail');
  return { antwoord: cj, code: (String(m.text).match(/\b(\d{6})\b/) || [])[1], mail: m };
}

test('een nieuwe send op naam zonder eigen code wordt geweigerd', async () => {
  const { ct, geheim } = verzegel(crypto.randomBytes(1024), 'oud.pdf');
  const hash = await blokOp(ct);
  const adres = 'oud@example.com';
  const token = W.newToken();
  const sealed = { [adres]: { token, wrapped_key: await W.wrap(token, geheim) } };
  post.length = 0;
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: JSON.stringify({ hashes: [hash], recipients: [adres], sealed, ttl_ms: 3600000 }),
  });
  const j = await r.json().catch(() => ({}));
  assert.equal(r.status, 400);
  assert.equal(j.error, 'sender_code_required');
  await wacht(150);
  assert.equal(post.length, 0, 'en er ging geen uitnodiging de deur uit');
});

test('de hele reis met de eigen code, en de server ziet de code nergens', async () => {
  const inhoud = crypto.randomBytes(256 * 1024);
  const naam = 'contract.pdf';
  const { ct, geheim } = verzegel(inhoud, naam);
  const hash = await blokOp(ct);

  // ── de afzender, precies zoals parashare.page.js het doet ───────────────
  const adressen = ['demo1@example.com', 'demo2@example.com'];
  const code = W.newSenderCode();
  const zout = W.newCodeSalt();
  const gerekt = await W.stretchCode(code, zout);
  const sealed = {}, tokens = {};
  for (const a of adressen) {
    const token = W.newToken();
    const w = await W.wrapWithCode(token, geheim, gerekt);
    sealed[a] = { token, wrapped_key: w.wrapped_key, code_check: w.code_check };
    tokens[a] = token;
  }
  const verzoek = JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                                   ttl_ms: 3600000, lang: 'nl', sender_code: { salt: zout } });
  post.length = 0;
  const vr = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
    body: verzoek,
  });
  const vj = await vr.json().catch(() => ({}));
  assert.equal(vr.status, 201, 'de verzending werd geweigerd: ' + JSON.stringify(vj));

  const vormen = [code, W.formatCode(code), code.toLowerCase()];
  const zonder = (tekst, waar) => {
    for (const v of vormen) assert.ok(!String(tekst).includes(v), 'de code staat in ' + waar);
  };
  zonder(verzoek, 'het verzoek aan de server');
  zonder(JSON.stringify(vj), 'het antwoord van de server');

  // ── de uitnodiging ─────────────────────────────────────────────────────
  await wacht(200);
  const uitnodigingen = post.filter((p) => /heeft u een bestand gestuurd/.test(p.subject || ''));
  assert.equal(uitnodigingen.length, 2);
  for (const m of uitnodigingen) {
    zonder(JSON.stringify(m), 'de uitnodiging');
    assert.match(m.text, /De afzender geeft je apart een code\. Die heb je nodig om het bestand te openen\./);
    // De dryrun-log draagt niet altijd de HTML-helft; staat hij erin, dan ook daar.
    if (m.html) assert.match(m.html, /De afzender geeft je apart een code/);
  }

  // ── de ontvanger ───────────────────────────────────────────────────────
  const a = adressen[0], token = tokens[a];
  const mc = await mailcode(token, a);
  assert.equal(mc.antwoord.sender_code, true, 'de pagina moet weten dat er een tweede code is');
  assert.equal(mc.antwoord.code_salt, zout);
  zonder(JSON.stringify(mc.antwoord), 'het antwoord op de codevraag');
  zonder(JSON.stringify(mc.mail), 'de codemail');

  // Alleen de mailcode: dan nog niets.
  const zonderBewijs = await pickup(token, { code: mc.code });
  assert.equal(zonderBewijs.status, 400);
  assert.equal((await zonderBewijs.json()).error, 'sender_code_required');

  // Een verkeerd getypte code van de afzender.
  let fout = W.newSenderCode();
  while (fout === code) fout = W.newSenderCode();
  const foutBewijs = await W.proofFor(token, await W.stretchCode(fout, zout));
  const fr = await pickup(token, { code: mc.code, sender_proof: foutBewijs });
  const fj = await fr.json().catch(() => ({}));
  assert.equal(fr.status, 401);
  assert.equal(fj.error, 'wrong_sender_code');
  assert.equal(fj.tries_left, 4);

  // En de goede, met dezelfde mailcode: die bleef staan.
  const bewijs = await W.proofFor(token, gerekt);
  const verzoekOphalen = JSON.stringify({ code: mc.code, sender_proof: bewijs });
  zonder(verzoekOphalen, 'het ophaalverzoek');
  const or_ = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(token), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: verzoekOphalen,
  });
  assert.equal(or_.status, 200, 'het goede bewijs werd niet geaccepteerd');
  const gewikkeld = or_.headers.get('X-Paramant-Key');
  const bytes = Buffer.from(await or_.arrayBuffer());

  // Met de link alleen gaat hij niet open; met link en code wel.
  await assert.rejects(() => W.unwrap(token, gewikkeld));
  const sleutel = await W.unwrapWithCode(token, gewikkeld, gerekt);
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(sleutel.rawKey), Buffer.from(sleutel.iv));
  d.setAuthTag(bytes.subarray(bytes.length - 16));
  const uit = Buffer.concat([d.update(bytes.subarray(0, bytes.length - 16)), d.final()]);
  const nl = uit.readUInt32LE(0);
  assert.equal(uit.subarray(4, 4 + nl).toString('utf8'), naam);
  assert.ok(uit.subarray(4 + nl).equals(inhoud), 'het bestand kwam er niet heel uit');

  // ── vijf keer fout en de link is op ─────────────────────────────────────
  const b = adressen[1], tokenB = tokens[b];
  const mcB = await mailcode(tokenB, b);
  let laatste = null;
  for (let i = 0; i < 5; i++) {
    const r = await pickup(tokenB, { code: mcB.code, sender_proof: 'A'.repeat(43) });
    laatste = { status: r.status, body: await r.json().catch(() => ({})) };
  }
  assert.equal(laatste.body.error, 'sender_code_locked');
  assert.equal(laatste.status, 403);
  const daarna = await pickup(tokenB, { action: 'code' });
  assert.equal(daarna.status, 403, 'na vijf keer fout gaat er geen nieuwe mailcode meer uit');
  assert.equal((await daarna.json()).error, 'sender_code_locked');

  // ── nergens in de logregels ─────────────────────────────────────────────
  await wacht(150);
  zonder(regels.join('\n'), 'de logregels van de relay');
});
