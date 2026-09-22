'use strict';

// DE AFZENDERSKANT, AANGEVALLEN. Tegen een echt draaiende relay.
//
// /v2/user/sends, /detail, /revoke en /reinvite zijn de vier routes waarmee het
// dashboard laat zien wie het bestand ophaalde en waarmee een afzender iemand
// eruit gooit. Ze staan achter X-Internal-Auth en ze nemen het account UIT DE
// BODY. Dat is precies de vorm waar een gat in zit als de eigenaarscontrole
// ook maar een keer overgeslagen wordt: wie de body schrijft, kiest het account.
//
// Deze suite schrijft de body zelf. Twee accounts, een echte verzending, en dan
// alles wat account B kan proberen tegen de verzending van account A.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const vm = require('vm');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const SLEUTEL_A = 'pgp_aanval_a';
const SLEUTEL_B = 'pgp_aanval_b';
const ACCT_A = 'acct_aanval_a';
const ACCT_B = 'acct_aanval_b';
const INTERN = 'intern_aanval_geheim_0123456789';

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

function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; }
function sha256hex(b) { return crypto.createHash('sha256').update(b).digest('hex'); }

// Een echte verzending: blok uploaden, wikkelen, /v2/sends. Geeft de tokens
// terug, want die heeft de test nodig om een ophaling na te spelen.
async function verstuur(sleutel, adressen) {
  const inhoud = crypto.randomBytes(4096);
  const naamBytes = Buffer.from('doc.pdf', 'utf8');
  const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, inhoud]);
  const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  const hash = sha256hex(ct);
  const up = await fetch(BASE + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
    body: JSON.stringify({ hash, payload: ct.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  assert.equal(up.status, 200, 'blokupload faalde: ' + up.status);

  const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));
  const sealed = {}, tokens = {};
  for (const a of adressen) {
    const t = wrap.newToken();
    tokens[a] = t;
    sealed[a] = { token: t, wrapped_key: await wrap.wrap(t, geheim) };
  }
  const r = await fetch(BASE + '/v2/sends', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': sleutel },
    body: JSON.stringify({ hashes: [hash], recipients: adressen, sealed,
                           filename: 'doc.pdf', ttl_ms: 3600_000 }),
  });
  const j = await r.json().catch(() => ({}));
  assert.equal(r.status, 201, 'verzenden faalde: ' + JSON.stringify(j));
  return { id: j.send_id, tokens, sealed };
}

// Een interne call, met de kop die het dashboard ook zet. `kop === null` laat
// hem weg; anders gaat precies deze waarde de draad op.
async function intern(pad, body, kop = INTERN) {
  const headers = { 'Content-Type': 'application/json' };
  if (kop !== null) headers['X-Internal-Auth'] = kop;
  const r = await fetch(BASE + pad, { method: 'POST', headers, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { status: r.status, body: j };
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `aanval-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  const relay = await bootHealthyRelay({
    USERS_FILE: usersFile, RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
    SITE_URL: 'https://paramant.app',
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({ api_keys: [
      { key: SLEUTEL_A, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Account A', email: 'a@test', account_id: ACCT_A },
      { key: SLEUTEL_B, active: true, plan: 'pro', plan_parasend: 'pro',
        label: 'Account B', email: 'b@test', account_id: ACCT_B },
    ] }),
  }, {
    onLine: (line) => {
      if (!line.includes('mail_dryrun')) return;
      try { post.push(JSON.parse(line)); } catch (_) { /* geen JSON */ }
    },
  });
  BASE = relay.base;
});

after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(usersFile); } catch (_) {}
});

// ── 1. Kan B bij A? ─────────────────────────────────────────────────────────
test('account B komt nergens bij de verzending van account A', async () => {
  const s = await verstuur(SLEUTEL_A, ['een@extern.test', 'twee@extern.test']);

  // A ziet hem zelf wel, anders test de rest niets.
  const vanA = await intern('/v2/user/sends', { user_id: ACCT_A });
  assert.equal(vanA.status, 200);
  assert.ok(vanA.body.sends.some((x) => x.id === s.id),
    'A moet zijn eigen verzending zien, kreeg: ' + JSON.stringify(vanA.body));

  // Het overzicht van B is leeg.
  const vanB = await intern('/v2/user/sends', { user_id: ACCT_B });
  assert.equal(vanB.status, 200);
  assert.equal(vanB.body.count, 0, 'B ziet iets van A: ' + JSON.stringify(vanB.body));

  // En de drie routes die een id nemen, met dat echte id van A.
  for (const pad of ['/v2/user/sends/detail', '/v2/user/sends/revoke', '/v2/user/sends/reinvite']) {
    const r = await intern(pad, { user_id: ACCT_B, send_id: s.id, email: 'een@extern.test' });
    assert.equal(r.status, 404, pad + ' liet B binnen: ' + JSON.stringify(r.body));
    assert.equal(r.body.error, 'unknown_send',
      pad + ' verraadt dat het id bestaat: ' + JSON.stringify(r.body));
  }

  // Een id dat niet bestaat geeft exact hetzelfde antwoord, dus B kan niet
  // aftasten welke ids echt zijn.
  const verzonnen = await intern('/v2/user/sends/detail',
    { user_id: ACCT_B, send_id: crypto.randomBytes(18).toString('base64url') });
  assert.equal(verzonnen.status, 404);
  assert.deepEqual(verzonnen.body, { error: 'unknown_send' },
    'een bestaand id van een ander hoort te klinken als een id dat nooit bestond');
});

// ── 2. Rare user_id-waarden ─────────────────────────────────────────────────
test('een verzonnen, leeg, reusachtig, null of object user_id opent niets', async () => {
  const s = await verstuur(SLEUTEL_A, ['drie@extern.test']);

  const gevallen = [
    ['ontbreekt', undefined],
    ['leeg', ''],
    ['null', null],
    ['verzonnen', 'acct_bestaat_niet'],
    ['drieduizend tekens', 'x'.repeat(3000)],
    ['object', { account_id: ACCT_A }],
    ['getal', 0],
    ['true', true],
  ];
  for (const [naam, waarde] of gevallen) {
    const d = await intern('/v2/user/sends/detail', { user_id: waarde, send_id: s.id });
    assert.equal(d.status, 404, 'detail liet "' + naam + '" door: ' + JSON.stringify(d.body));
    const l = await intern('/v2/user/sends', { user_id: waarde });
    assert.ok([200, 400].includes(l.status), 'lijst gaf ' + l.status + ' op "' + naam + '"');
    if (l.status === 200) {
      assert.equal(l.body.count, 0, 'lijst gaf rijen op "' + naam + '": ' + JSON.stringify(l.body));
    }
  }

  // De lijstroute is de enige met een eigen lengtegrens (relay.js:4729,
  // `userId.length > 200`); die hoort te vuren met een nette 400.
  const lang = await intern('/v2/user/sends', { user_id: 'x'.repeat(201) });
  assert.equal(lang.status, 400, 'de lijst heeft een grens van 200 tekens');
  assert.equal(lang.body.error, 'invalid_user_id');

  // De drie id-routes hebben die grens NIET; ze leunen volledig op ownedBy.
  // Dat mag, zolang het antwoord 404 is. Vastleggen dat het zo is.
  const langDetail = await intern('/v2/user/sends/detail',
    { user_id: 'x'.repeat(3000), send_id: s.id });
  assert.equal(langDetail.status, 404,
    'detail kent geen lengtegrens, dus de eigenaarscontrole moet het alleen doen');

  // BOVEN HET BODYPLAFOND. Alle vier de routes lezen met readBody(req, 4096)
  // (relay.js:3481: die rejectt met Error('Too large')), en alle vier vangen
  // dat in hun eigen catch af als 500 {"error":"internal"}. Dicht, dus geen
  // gat, maar het is de verkeerde status en het schrijft een interne fout weg
  // voor iets wat de beller zelf fout deed. 413 hoort hier.
  for (const pad of ['/v2/user/sends', '/v2/user/sends/detail',
                     '/v2/user/sends/revoke', '/v2/user/sends/reinvite']) {
    const groot = await intern(pad, { user_id: 'x'.repeat(10000), send_id: s.id });
    assert.equal(groot.status, 500,
      pad + ' gaf niet de verwachte 500 op een body boven 4096 bytes: ' + groot.status);
    assert.equal(groot.body.error, 'internal');
    assert.ok(!JSON.stringify(groot.body).includes('Too large'),
      'de foutmelding van binnen mag niet naar buiten');
  }
});

// ── 3. De kop ───────────────────────────────────────────────────────────────
test('zonder of met een foute X-Internal-Auth komt er niets door', async () => {
  const s = await verstuur(SLEUTEL_A, ['vier@extern.test']);
  const paden = ['/v2/user/sends', '/v2/user/sends/detail',
                 '/v2/user/sends/revoke', '/v2/user/sends/reinvite'];
  // GEEN spatie-variant hier, en dat is met opzet. Een X-Internal-Auth met een
  // spatie of tab ervoor of erachter komt WEL door, en dat is goed: RFC 7230
  // zegt dat omringende witruimte geen deel van de waarde is, en de HTTP-parser
  // van Node knipt hem eraf voor de route hem ziet. Nagelopen met een rauwe
  // socket, niet met fetch, dus het is de server en niet de client. Een test
  // die daar 401 van eist, test de HTTP-laag en niet deze poort.
  const koppen = [
    ['geen kop', null],
    ['lege kop', ''],
    ['fout', 'fout_token'],
    ['bijna goed', INTERN.slice(0, -1)],
    ['een teken anders', INTERN.slice(0, 5) + 'X' + INTERN.slice(6)],
    ['een teken langer', INTERN + 'x'],
    ['hoofdletters', INTERN.toUpperCase()],
  ];
  for (const pad of paden) {
    for (const [naam, waarde] of koppen) {
      const r = await intern(pad, { user_id: ACCT_A, send_id: s.id, email: 'vier@extern.test' },
                             waarde);
      assert.equal(r.status, 401, pad + ' liet "' + naam + '" door: ' + JSON.stringify(r.body));
      assert.equal(r.body.error, 'unauthorized');
    }
  }
});

// ── 4. Lekt het overzicht iets? ─────────────────────────────────────────────
test('het overzicht draagt geen token, geen verpakking, geen hash en geen zout', async () => {
  const s = await verstuur(SLEUTEL_A, ['vijf@extern.test', 'zes@extern.test']);
  const d = await intern('/v2/user/sends/detail', { user_id: ACCT_A, send_id: s.id });
  assert.equal(d.status, 200, JSON.stringify(d.body));

  // Elk veld, recursief, met naam en waarde.
  const velden = [];
  (function loop(v, pad) {
    if (v && typeof v === 'object') {
      for (const [k, w] of Object.entries(v)) loop(w, pad ? pad + '.' + k : k);
      return;
    }
    velden.push([pad, v]);
  })(d.body, '');

  const ruw = JSON.stringify(d.body);
  for (const [adres, token] of Object.entries(s.tokens)) {
    assert.ok(!ruw.includes(token), 'het token van ' + adres + ' staat in het overzicht');
    assert.ok(!ruw.includes(s.sealed[adres].wrapped_key),
      'de verpakking van ' + adres + ' staat in het overzicht');
    // Ook de hash van het token niet: die identificeert de rij net zo goed.
    const th = crypto.createHash('sha3-256').update(token).digest('hex');
    assert.ok(!ruw.includes(th), 'een hash van het token staat in het overzicht');
  }
  for (const [naam] of velden) {
    assert.ok(!/token|wrapped|hash|salt|code_|account_id/i.test(naam),
      'verdacht veld in het overzicht: ' + naam + ' (' + ruw + ')');
  }
  // Wat er WEL hoort te staan, want een leeg antwoord haalt de test ook.
  assert.equal(d.body.total, 2);
  assert.equal(d.body.recipients.length, 2);
  assert.deepEqual(Object.keys(d.body.recipients[0]).sort(),
    ['email', 'invited_at', 'picked_up_at', 'reminders', 'status']);
  // Het adres staat er voluit. Dat is de eigen adreslijst van de afzender, dus
  // dat hoort, maar het is wel de enige persoonsgegevens in dit antwoord.
  assert.equal(d.body.recipients[0].email, 'vijf@extern.test');
});

// ── 5. De volgorde van de werkelijkheid ─────────────────────────────────────
test('intrekken na ophalen kan niet, en herinneren na intrekken ook niet', async () => {
  const s = await verstuur(SLEUTEL_A, ['zeven@extern.test', 'acht@extern.test']);

  // Zeven haalt echt op.
  post.length = 0;
  const cr = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(s.tokens['zeven@extern.test']), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.equal(cr.status, 200, 'code aanvragen faalde');
  await new Promise((r) => setTimeout(r, 250));
  const mail = post.find((p) => /code to open the file/i.test(p.subject || ''));
  assert.ok(mail, 'geen codemail');
  const code = (String(mail.text).match(/\b(\d{6})\b/) || [])[1];
  const op = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(s.tokens['zeven@extern.test']), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  assert.equal(op.status, 200, 'ophalen faalde');

  // Het overzicht zegt dat hij binnen is.
  const na = await intern('/v2/user/sends/detail', { user_id: ACCT_A, send_id: s.id });
  const zeven = na.body.recipients.find((r) => r.email === 'zeven@extern.test');
  assert.equal(zeven.status, 'collected');

  // Intrekken van wie al ophaalde: 409, en het antwoord moet niet doen alsof.
  const in1 = await intern('/v2/user/sends/revoke',
    { user_id: ACCT_A, send_id: s.id, email: 'zeven@extern.test' });
  assert.equal(in1.status, 409, 'intrekken na ophalen werd geaccepteerd: ' + JSON.stringify(in1.body));
  assert.equal(in1.body.error, 'already_collected');

  // Herinneren van wie al ophaalde: ook 409, en er mag geen mail uit.
  post.length = 0;
  const her1 = await intern('/v2/user/sends/reinvite',
    { user_id: ACCT_A, send_id: s.id, email: 'zeven@extern.test' });
  assert.equal(her1.status, 409, JSON.stringify(her1.body));
  assert.equal(her1.body.error, 'already_collected');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(post.filter((p) => (p.to || []).includes('zeven@extern.test')).length, 0,
    'er ging post naar iemand die al had opgehaald');

  // Acht wordt ingetrokken. Daarna herinneren: 409, en geen mail.
  const in2 = await intern('/v2/user/sends/revoke',
    { user_id: ACCT_A, send_id: s.id, email: 'acht@extern.test' });
  assert.equal(in2.status, 200, JSON.stringify(in2.body));

  post.length = 0;
  const her2 = await intern('/v2/user/sends/reinvite',
    { user_id: ACCT_A, send_id: s.id, email: 'acht@extern.test' });
  assert.equal(her2.status, 409, 'een ingetrokken ontvanger kreeg een herinnering: '
    + JSON.stringify(her2.body));
  assert.equal(her2.body.error, 'revoked');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(post.filter((p) => (p.to || []).includes('acht@extern.test')).length, 0,
    'er ging post naar iemand die was ingetrokken');

  // En het intrekken is echt: acht komt er niet meer in.
  const poging = await fetch(BASE + '/v2/pickup/' + encodeURIComponent(s.tokens['acht@extern.test']), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'code' }),
  });
  assert.notEqual(poging.status, 200,
    'de link van een ingetrokken ontvanger werkt nog, terwijl het dashboard zegt van niet');

  // Twee keer intrekken van dezelfde: geen dubbele boekhouding.
  const in3 = await intern('/v2/user/sends/revoke',
    { user_id: ACCT_A, send_id: s.id, email: 'acht@extern.test' });
  assert.equal(in3.status, 409);
  assert.equal(in3.body.error, 'revoked');

  // Een adres dat niet op de lijst staat.
  const vreemd = await intern('/v2/user/sends/revoke',
    { user_id: ACCT_A, send_id: s.id, email: 'nooitgezien@extern.test' });
  assert.equal(vreemd.status, 409);
  assert.equal(vreemd.body.error, 'unknown_recipient');
});

// ── 6. Het account waarop het dashboard vraagt ──────────────────────────────
//
// admin/server.js:2990 zet `const { user_id } = req.userSession` en stuurt dat
// door. Die user_id is de API-SLEUTEL zelf (admin/server.js:1393 schrijft
// `user_id: user.key` in de sessie). De relay slaat de verzending op onder
// `accountId: acctOf(apiKey)` (relay.js:4622), en acctOf is
// `(v && v.account_id) || apiKey` (relay.js:1758).
//
// Voor een account MET account_id in users.json zijn dat twee verschillende
// strings. Deze test legt vast wat daar dan gebeurt.
test('het dashboard vraagt op de sleutel en ziet zijn verzending gewoon', { todo: 'GEDICHT: relay.js vertaalt de API-sleutel nu naar het account (accountVan). Bewaakt door test/dashboard-eigenaar.test.js, dat het juiste gedrag pint in plaats van het kapotte' }, async () => {
  const s = await verstuur(SLEUTEL_A, ['negen@extern.test']);

  const opAccount = await intern('/v2/user/sends', { user_id: ACCT_A });
  assert.equal(opAccount.status, 200);
  assert.ok(opAccount.body.sends.some((x) => x.id === s.id),
    'op account_id hoort de verzending gewoon in de lijst te staan');

  // En nu precies wat admin/server.js:2992 stuurt: de sleutel uit de sessie.
  const opSleutel = await intern('/v2/user/sends', { user_id: SLEUTEL_A });
  const detailOpSleutel = await intern('/v2/user/sends/detail',
    { user_id: SLEUTEL_A, send_id: s.id });
  const trekOpSleutel = await intern('/v2/user/sends/revoke',
    { user_id: SLEUTEL_A, send_id: s.id, email: 'negen@extern.test' });

  // DRAAI DEZE DRIE OM zodra het gat dicht is. Nu leggen ze vast wat er echt
  // gebeurt: de afzender ziet niets en kan niemand intrekken.
  assert.equal(opSleutel.body.count, 0,
    'de lijst op de sleutel is nu leeg; is hij gevuld, dan is het gat gedicht');
  assert.equal(detailOpSleutel.status, 404,
    'detail op de sleutel geeft nu 404 op de eigen verzending');
  assert.equal(trekOpSleutel.status, 404,
    'intrekken op de sleutel geeft nu 404 op de eigen verzending');

  // Het gaat dus NIET om een kapotte eigenaarscontrole: die doet precies wat
  // er staat. De twee kanten noemen het account alleen anders.
  //   admin/server.js:1393   user_id: user.key         -> 'pgp_aanval_a'
  //   relay.js:4622          accountId: acctOf(apiKey) -> 'acct_aanval_a'
  //   relay.js:1758          acctOf = (v && v.account_id) || apiKey
  // Een account ZONDER account_id in users.json valt terug op de sleutel en
  // werkt daardoor wel. Een account MET account_id (elke klant die via de
  // admin is aangemaakt, en elke firm met meerdere sleutels) werkt niet.
});
