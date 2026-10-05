'use strict';

// HETZELFDE, MAAR DAN ZOALS DE BUITENWERELD HET ZIET.
//
// verzending-levensduur.test.js telt wat er in de opslag blijft liggen. Deze
// suite stelt de vraag die de ontvanger en de afzender stellen: wat ANTWOORDT
// de relay als de tijd om is, als de relay opnieuw is opgestart, en als er
// blokken zijn geupload die nooit een verzending zijn geworden.
//
// Een echte relay uit relay.js (bootHealthyRelay), echte HTTP, mail in dryrun.
// Zonder REDIS_URL, dus de opslag is de Map in het procesgeheugen
// (lib/parasign-store.js, `useRedis = !!(redis && key)`). Er draait hier geen
// redis, dus de redis-variant is NIET gemeten.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const API_KEY = 'pgp_levensduur_pro';
const KLEIN_KEY = 'pgp_levensduur_community';
const INTERN = 'intern-levensduur-token';

let BASE = null;
let usersFile;
const post = [];

const USERS = JSON.stringify({
  api_keys: [
    { key: API_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
      label: 'Zorggroep De Linde', email: 'anna@zorggroep.test',
      account_id: 'acct_levensduur' },
    // Een eigen account voor de weesblokken, zodat de teller van de andere
    // tests er niet doorheen loopt.
    { key: KLEIN_KEY, active: true, plan: 'pro', plan_parasend: 'pro',
      label: 'Klein Kantoor', email: 'klein@extern.test',
      account_id: 'acct_weesblok' },
  ],
});

function relayEnv(extra) {
  return { USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
           SITE_URL: 'https://paramant.app', INTERNAL_AUTH_TOKEN: INTERN,
           USERS_JSON: USERS, ...(extra || {}) };
}

const vangMail = { onLine: (line) => {
  if (!line.includes('mail_dryrun')) return;
  try { post.push(JSON.parse(line)); } catch (_) { /* geen JSON */ }
} };

before(async () => {
  usersFile = path.join(os.tmpdir(), `levensduur-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay(relayEnv(), vangMail);
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) { /* best effort */ }
});

const wacht = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

async function uploadBlok(base, key, bytes, ttlMs) {
  const blok = crypto.randomBytes(bytes);
  const hash = sha256hex(blok);
  const body = { hash, payload: blok.toString('base64'),
                 meta: { device_id: 'transfer-web-link' } };
  if (ttlMs) body.ttl_ms = ttlMs;
  const r = await fetch(base + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': key },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})), hash };
}

function zegel(adressen) {
  const sealed = {}, tokens = {};
  for (const a of adressen) {
    const token = crypto.randomBytes(32).toString('base64url');
    sealed[a] = { token, wrapped_key: crypto.randomBytes(60).toString('base64url') };
    tokens[a] = token;
  }
  return { sealed, tokens };
}

async function verstuur(base, key, hashes, adressen, opts = {}) {
  const { sealed, tokens } = zegel(adressen);
  const r = await fetch(base + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': key },
    body: JSON.stringify({ hashes, recipients: adressen, sealed,
                           filename: opts.filename || 'stuk.pdf',
                           ttl_ms: opts.ttlMs }),
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, body, tokens };
}

const codeVragen = (base, token) => fetch(base + '/v2/pickup/' + encodeURIComponent(token), {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ action: 'code' }),
});

// ── 1. DE VERLOPEN LINK ──────────────────────────────────────────────────────
test('een link die verliep zegt tegen de ontvanger hetzelfde als een verzonnen link', async () => {
  const blok = await uploadBlok(BASE, API_KEY, 4096);
  assert.equal(blok.status, 200, JSON.stringify(blok.body));
  const v = await verstuur(BASE, API_KEY, [blok.hash], ['laat@extern.test'],
    { ttlMs: 2000, filename: 'te-laat.pdf' });
  assert.equal(v.status, 201, JSON.stringify(v.body));

  await wacht(2400);

  const r = await codeVragen(BASE, v.tokens['laat@extern.test']);
  const j = await r.json().catch(() => ({}));
  // GEMETEN. De tokenregel heeft dezelfde TTL als de verzending, dus hij is
  // tegelijk weg en _zoekSend valt terug op 'unknown_token'. De 'expired'-tak
  // in _locate (410) is voor deze route dus onbereikbaar.
  assert.equal(r.status, 404, 'kreeg ' + r.status + ': ' + JSON.stringify(j));
  assert.equal(j.error, 'unknown_token');

  const verzonnen = await codeVragen(BASE, 'Z'.repeat(43));
  const vj = await verzonnen.json().catch(() => ({}));
  assert.equal(verzonnen.status, 404);
  assert.deepEqual(j, vj,
    'de ontvanger van een verlopen link krijgt exact hetzelfde antwoord als iemand met een verzonnen token');
});

// ── 2. WAT DE AFZENDER ERVAN OVERHOUDT ───────────────────────────────────────
test('de afzender houdt van een verlopen verzending alleen een id over', async () => {
  const blok = await uploadBlok(BASE, API_KEY, 4096);
  const v = await verstuur(BASE, API_KEY, [blok.hash], ['weg@extern.test'],
    { ttlMs: 2000, filename: 'kwartaalcijfers.pdf' });
  assert.equal(v.status, 201, JSON.stringify(v.body));
  const id = v.body.send_id;

  const lijst = async () => {
    const r = await fetch(BASE + '/v2/user/sends', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
      body: JSON.stringify({ user_id: 'acct_levensduur', limit: 200 }),
    });
    assert.equal(r.status, 200, 'het overzicht gaf ' + r.status);
    return (await r.json()).sends;
  };

  const vers = (await lijst()).find(s => s.id === id);
  assert.equal(vers.filename, 'kwartaalcijfers.pdf');
  assert.equal(vers.status, 'open');
  assert.equal(vers.total, 1);

  await wacht(2400);

  const oud = (await lijst()).find(s => s.id === id);
  assert.ok(oud, 'de rij verdwijnt niet, dat is het goede deel');
  assert.deepEqual(oud, { id, status: 'expired' },
    'maar dit is alles wat er van over is');
});

// ── 3. DE HERSTART ───────────────────────────────────────────────────────────
test('een herstart wist elke lopende verzending, en de ontvanger hoort waarom niets', async () => {
  // Een eigen relay, want deze gaat eraan.
  const eerste = await bootHealthyRelay(relayEnv(), vangMail);
  const blok = await uploadBlok(eerste.base, API_KEY, 4096);
  const v = await verstuur(eerste.base, API_KEY, [blok.hash], ['herstart@extern.test'],
    { ttlMs: 24 * 3600 * 1000, filename: 'contract.pdf' });
  assert.equal(v.status, 201, JSON.stringify(v.body));
  const token = v.tokens['herstart@extern.test'];

  // Werkt hij nu wel? Anders bewijst de rest niets.
  const voor = await codeVragen(eerste.base, token);
  assert.equal(voor.status, 200, 'de link werkte voor de herstart niet eens');

  eerste.kill();
  await wacht(300);

  const tweede = await bootHealthyRelay(relayEnv(), vangMail);
  const na = await codeVragen(tweede.base, token);
  const j = await na.json().catch(() => ({}));
  // GEMETEN: zonder redis is de hele verzending weg. De ontvanger heeft een
  // geldige link van 24 uur oud en leest 'unknown_token' -- niets zegt dat het
  // bestand bestond en dat de afzender hem opnieuw kan sturen.
  assert.equal(na.status, 404, 'kreeg ' + na.status + ': ' + JSON.stringify(j));
  assert.equal(j.error, 'unknown_token');

  // En de afzender ziet in zijn overzicht helemaal niets meer: de index zat in
  // hetzelfde geheugen.
  const r = await fetch(tweede.base + '/v2/user/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ user_id: 'acct_levensduur' }),
  });
  const lijst = (await r.json()).sends;
  assert.equal(lijst.length, 0,
    'na een herstart is ook het overzicht van de afzender leeg, niet eens een expired-rij');
  tweede.kill();
});

// ── 4. BLOKKEN DIE NOOIT EEN VERZENDING WERDEN ───────────────────────────────
test('geuploade blokken die nooit gejoind worden houden hun plek bezet tot hun eigen TTL', async () => {
  // Het plafond dat ECHT geldt is niet het getal uit tiers.js (pro: 24) maar
  // entitlements._blobCeiling: max(eigen, ceil(file_mb / 5) + 8) = 108, want
  // file_mb is 500 op elke betaalde rij. Gemeten, niet aangenomen.
  const PLAFOND = 108;
  const hashes = [];
  for (let i = 0; i < PLAFOND; i++) {
    const uit = await uploadBlok(BASE, KLEIN_KEY, 1024, 600_000);
    assert.equal(uit.status, 200, 'blok ' + i + ': ' + JSON.stringify(uit.body));
    hashes.push(uit.hash);
  }

  // Niets gejoind, niets opgehaald, geen ontvanger in zicht -- en toch zit het
  // account op slot. Een blok dat nooit een verzending wordt telt gewoon mee.
  const overheen = await uploadBlok(BASE, KLEIN_KEY, 1024, 600_000);
  assert.equal(overheen.status, 429, JSON.stringify(overheen.body));
  assert.equal(overheen.body.error, 'too_many_blocks_in_flight');
  assert.equal(overheen.body.dimension, 'concurrent_blobs');
  assert.equal(overheen.body.held, PLAFOND);
  assert.equal(overheen.body.limit, PLAFOND);
  // De hint klopt niet voor dit geval: er is geen ontvanger die ze kan pakken.
  assert.equal(overheen.body.hint, 'blocks free up as the receiver takes them');

  // Joinen ruimt ze wel meteen op (relay.js: `for (const h of hashes) blobDrop(h)`
  // direct na _sendStore().create). Een van de 108 is genoeg om dat te laten zien.
  const v = await verstuur(BASE, KLEIN_KEY, hashes.slice(0, 4), ['een@extern.test'],
    { ttlMs: 600_000, filename: 'vier-blokken.pdf' });
  assert.equal(v.status, 201, JSON.stringify(v.body));
  assert.equal(v.body.size, 4 * 1024, 'de vier blokken zijn tot een bestand samengevoegd');

  const weer = await uploadBlok(BASE, KLEIN_KEY, 1024, 600_000);
  assert.equal(weer.status, 200,
    'gejoinde blokken geven hun plek terug: ' + JSON.stringify(weer.body));

  // En de 104 die NIET gejoind zijn blijven staan: er kwamen vier plekken vrij
  // en geen een meer, dus binnen vier uploads zit het account er weer op.
  for (let i = 0; i < 4; i++) {
    const nog = await uploadBlok(BASE, KLEIN_KEY, 1024, 600_000);
    if (nog.status === 429) {
      assert.equal(nog.body.held, PLAFOND,
        'de weesblokken staan er nog: ' + JSON.stringify(nog.body));
      return;
    }
  }
  assert.fail('de weesblokken hadden de teller vol moeten houden');
});

test('een weesblok mag zijn plek net zo lang vasthouden als het hele plan-venster', async () => {
  // Er is geen ondergrens en geen aparte grens voor losse blokken: de client
  // vraagt en krijgt het plafond van zijn plan (relay.js:
  // `const ttl = Math.min(parseInt(ttl_ms || TTL_MS), _maxTtl)`).
  const uit = await uploadBlok(BASE, API_KEY, 1024, 999_999_999);
  assert.equal(uit.status, 200, JSON.stringify(uit.body));
  assert.equal(uit.body.ttl_ms, 86_400_000,
    'pro: een los blok dat nooit een verzending wordt houdt 24 uur een plek bezet');

  // Zonder ttl_ms is het vijf minuten (TTL_MS).
  const kort = await uploadBlok(BASE, API_KEY, 1024);
  assert.equal(kort.body.ttl_ms, 300_000);
});
