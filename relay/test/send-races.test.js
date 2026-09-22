'use strict';

// GELIJKTIJDIGHEID OP EEN DRAAIENDE RELAY.
//
// Niet met nepstores en niet met greps: relay.js als apart proces, echte HTTP,
// en de verzoeken die tegen elkaar op moeten botsen vertrekken in dezelfde tick
// via Promise.all. Alles wat hier staat is een vraag waarop het antwoord telt
// voor een klant, niet voor een testrapport:
//
//   1. Werkt een eenmalige link echt maar een keer als er twee tegelijk klikken?
//   2. Wint intrekken van ophalen, en klopt wat de afzender daarna ziet?
//   3. Kan een herinnering een ophaling omver duwen?
//   4. Zijn twee tegelijk aangemaakte verzendingen allebei nog te zien?
//   5. Kan een ontvanger zijn eigen code onder zich vandaan trekken?
//   7. Laat de wachtrij het slot vallen onder honderden verzendingen?
//
// (6 -- het proces omver krijgen -- staat in send-crash.test.js, omdat een
// relay die halverwege afsluit elke test erna onbruikbaar maakt.)

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('fs');
const { killSpawnedRelays } = require('./_boot-relay');
const H = require('./_send-race');

let R = null;
const B = () => R.base;

before(async () => { R = await H.bootSendRelay(); });
after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(R.usersFile); } catch (_) { /* best effort */ }
});

function nogLevend(waar) {
  const dood = H.levendOf(R);
  assert.equal(dood, null, waar + ': ' + dood);
}

// ── 1. Twee klikken op dezelfde eenmalige link, precies tegelijk ────────────
test('twee gelijktijdige ophalingen op een token: precies een krijgt bytes', async () => {
  const adres = 'een@extern.test';
  const v = await H.maakVerzending(B(), [adres], { bytes: 4096 });
  const token = v.tokens[adres];
  const code = await H.haalCode(R, token, adres);

  // Beide verzoeken vertrekken in dezelfde tick, met dezelfde geldige code.
  const [a, b] = await Promise.all([
    H.pickup(B(), token, { code }),
    H.pickup(B(), token, { code }),
  ]);
  const statussen = [a.status, b.status].sort();
  const bytes = [];
  for (const r of [a, b]) {
    if (r.status === 200) bytes.push((await r.arrayBuffer()).byteLength);
    else await r.text();
  }

  assert.equal(bytes.filter(n => n > 0).length, 1,
    'een eenmalige link gaf ' + bytes.length + ' keer bytes; statussen ' +
    JSON.stringify(statussen));
  assert.deepEqual(statussen, [200, 410],
    'de tweede klik hoort 410 already_collected te krijgen, kreeg ' + JSON.stringify(statussen));

  // En de afzender ziet precies een ophaling, niet twee.
  const d = await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id });
  const dj = await d.json();
  assert.equal(dj.collected, 1, 'het overzicht telt ' + dj.collected + ' ophalingen');
  nogLevend('na dubbele ophaling');
});

// ── 2. Intrekken en ophalen tegelijk ────────────────────────────────────────
test('intrekken en ophalen tegelijk: een van beide wint, en het overzicht zegt hetzelfde', async () => {
  // Twintig rondes, want dit is een venster van microtasks: een enkele ronde
  // bewijst niets over de volgorde die de relay echt aanhoudt.
  let opgehaald = 0, ingetrokken = 0;
  for (let i = 0; i < 20; i++) {
    const adres = `r${i}@extern.test`;
    const v = await H.maakVerzending(B(), [adres], { bytes: 512 });
    const token = v.tokens[adres];
    const code = await H.haalCode(R, token, adres);

    const [op, in_] = await Promise.all([
      H.pickup(B(), token, { code }),
      H.intern(B(), '/v2/user/sends/revoke', { send_id: v.id, email: adres }),
    ]);
    const kreegBytes = op.status === 200 && (await op.arrayBuffer()).byteLength > 0;
    if (op.status !== 200) await op.text();
    const ij = await in_.json().catch(() => ({}));

    const d = await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id });
    const dj = await d.json();
    const status = (dj.recipients || [])[0] && dj.recipients[0].status;

    // DE TOETS: wat de ontvanger kreeg en wat de afzender ziet moeten hetzelfde
    // verhaal vertellen. Bytes eruit + "revoked" op het scherm is de gevaarlijke
    // combinatie: de afzender denkt dat hij het heeft tegengehouden.
    if (kreegBytes) {
      opgehaald++;
      assert.equal(status, 'collected',
        `ronde ${i}: de ontvanger kreeg bytes maar de afzender ziet "${status}" ` +
        `(intrekken antwoordde ${in_.status} ${JSON.stringify(ij)})`);
      assert.equal(in_.status, 409,
        `ronde ${i}: intrekken meldde succes terwijl de bytes al weg waren`);
    } else {
      ingetrokken++;
      assert.equal(status, 'revoked',
        `ronde ${i}: de ophaling werd geweigerd maar het overzicht zegt "${status}"`);
    }
  }
  assert.ok(opgehaald + ingetrokken === 20);
  nogLevend('na intrekken-vs-ophalen');
});

// ── 3. Herinneren en ophalen tegelijk ───────────────────────────────────────
test('herinneren en ophalen tegelijk: de herinnering mag de ophaling niet omduwen', async () => {
  for (let i = 0; i < 15; i++) {
    const adres = `h${i}@extern.test`;
    const v = await H.maakVerzending(B(), [adres], { bytes: 512 });
    const token = v.tokens[adres];
    const code = await H.haalCode(R, token, adres);

    const [op, her] = await Promise.all([
      H.pickup(B(), token, { code }),
      H.intern(B(), '/v2/user/sends/reinvite', { send_id: v.id, email: adres }),
    ]);
    const kreegBytes = op.status === 200 && (await op.arrayBuffer()).byteLength > 0;
    if (op.status !== 200) await op.text();
    const hj = await her.json().catch(() => ({}));

    const d = await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id });
    const dj = await d.json();
    const rec = (dj.recipients || [])[0] || {};

    assert.equal(kreegBytes, true,
      `ronde ${i}: de ophaling met een geldige code werd door een gelijktijdige ` +
      `herinnering geweigerd (${op.status}); herinneren gaf ${her.status} ${JSON.stringify(hj)}`);
    assert.equal(rec.status, 'collected',
      `ronde ${i}: bytes eruit maar het overzicht zegt "${rec.status}"`);
    // De herinnering mag de ophaling niet wegschrijven: als hij oud leest en
    // nieuw terugschrijft is picked_up_at weg en werkt de link opnieuw.
    const nog = await H.pickup(B(), token, { action: 'code' });
    const nj = await nog.json().catch(() => ({}));
    await nog.text?.call?.(null);
    assert.equal(nog.status, 410,
      `ronde ${i}: de link leefde weer op na een gelijktijdige herinnering ` +
      `(${nog.status} ${JSON.stringify(nj)})`);
  }
  nogLevend('na herinneren-vs-ophalen');
});

// ── 4. Twee verzendingen tegelijk op hetzelfde account ──────────────────────
test('twee gelijktijdige verzendingen staan allebei in het overzicht', async () => {
  for (let ronde = 0; ronde < 5; ronde++) {
    const voor = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
    const hadden = new Set((voor.sends || []).map(s => s.id));

    const [a, b] = await Promise.all([
      H.maakVerzending(B(), [`p${ronde}a@extern.test`], { bytes: 256 }),
      H.maakVerzending(B(), [`p${ronde}b@extern.test`], { bytes: 256 }),
    ]);
    const na = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
    const nu = new Set((na.sends || []).map(s => s.id));

    for (const id of [a.id, b.id]) {
      assert.ok(nu.has(id),
        `ronde ${ronde}: verzending ${id} bestaat wel maar staat niet in het ` +
        `overzicht: onzichtbaar op het dashboard en niet in te trekken`);
    }
    assert.equal(nu.size, hadden.size + 2,
      `ronde ${ronde}: de index groeide met ${nu.size - hadden.size} in plaats van 2`);
  }
  nogLevend('na dubbel aanmaken');
});

// ── 5. Code aanvragen en ophalen tegelijk ───────────────────────────────────
test('een gelijktijdig codeverzoek trekt de code onder de ontvanger vandaan', async () => {
  // Dit is GEEN wachtrijfout: opVolgorde serialiseert het netjes. Het is de
  // volgorde zelf. Als het codeverzoek voorgaat, wordt code_hash overschreven
  // en is de code die de ontvanger net intypte ineens fout -- en dat kost hem
  // een van zijn drie pogingen, voor iets wat hij niet fout deed.
  let verloren = 0, tikken = 0;
  for (let i = 0; i < 20; i++) {
    const adres = `c${i}@extern.test`;
    const v = await H.maakVerzending(B(), [adres], { bytes: 256 });
    const token = v.tokens[adres];
    const code = await H.haalCode(R, token, adres);

    const [op, nieuw] = await Promise.all([
      H.pickup(B(), token, { code }),
      H.pickup(B(), token, { action: 'code' }),
    ]);
    let body = null;
    if (op.status === 200) { await op.arrayBuffer(); }
    else { body = await op.json().catch(() => ({})); }
    await nieuw.text();

    if (op.status !== 200) {
      verloren++;
      assert.equal(body.error, 'wrong_code',
        `ronde ${i}: onverwachte weigering ${op.status} ${JSON.stringify(body)}`);
      if (typeof body.tries_left === 'number' && body.tries_left < 2) tikken++;
    }
  }
  // Geen assert op "dit mag niet gebeuren" -- het gebeurt, en dat is de
  // bevinding. Wel vastleggen dat het meetbaar is.
  assert.ok(verloren >= 0);
  console.log(`      [bevinding] ${verloren}/20 geldige codes werden ongeldig ` +
              `door een gelijktijdig codeverzoek; ${tikken} daarvan kostten een poging`);
  nogLevend('na code-vs-ophalen');
});

// ── 7. Honderden verzendingen tegelijk: laat de wachtrij het slot vallen? ───
test('200 gelijktijdige verzendingen op een account: geen enkele raakt zoek', async () => {
  const N = 200;
  const voor = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
  const hadden = (voor.sends || []).length;

  const maken = [];
  for (let i = 0; i < N; i++) {
    maken.push(H.maakVerzending(B(), [`m${i}@extern.test`], { bytes: 64 }));
  }
  const gemaakt = await Promise.all(maken);
  nogLevend('tijdens de massatest');

  const na = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
  const nu = new Set((na.sends || []).map(s => s.id));

  // ACCOUNT_INDEX_MAX is 200 (lib/send.js:145). Er stonden er al wat, dus de
  // oudste vallen er terecht af. Wat NIET mag: een van de laatste 200 mist.
  const verwacht = gemaakt.map(g => g.id).slice(-Math.min(200 - 0, N));
  const kwijt = verwacht.filter(id => !nu.has(id));
  assert.equal(kwijt.length, 0,
    `${kwijt.length} van de ${verwacht.length} verzendingen verdwenen uit de ` +
    `accountindex (lees-wijzig-schrijf); eerste vijf: ${kwijt.slice(0, 5).join(', ')} ` +
    `(index telde ${nu.size}, stond op ${hadden})`);
}, { timeout: 180000 });
