'use strict';

// DEZELFDE AANVALLEN, MAAR MET HET VENSTER OPEN.
//
// send-races.test.js draait tegen de geheugenbackend van parasign-store
// (lib/parasign-store.js:91). Daar lossen getMeta en putMeta SYNCHROON op: er
// is geen enkel opschortpunt tussen het lezen en het terugschrijven van een
// verzending, dus twee HTTP-verzoeken kunnen daar niet tussen elkaar door
// lopen, of `opVolgorde` nu bestaat of niet. Die suite is een vangnet tegen
// regressies, geen bewijs.
//
// Productie is redis. Daar is elke getMeta en elke putMeta een netwerkronde en
// staat het gat tussen lezen en schrijven millisecondenlang open. Deze suite
// zet dat gat na met _traag-redis.js: een RESP-stub in Node die elke GET, SET
// en DEL met opzet 6 ms laat duren. Dat is honderden keren breder dan het
// venster in productie, dus een verloren schrijfactie kan hier niet aan het
// toeval ontsnappen.
//
// Wat deze suite aanvalt zijn precies de lees-wijzig-schrijf-plekken:
//   lib/send.js:238-246   readSend / writeSend, de hele verzending per keer
//   lib/send.js:357-362   de accountindex, EEN sleutel voor alle verzendingen
//   lib/send.js:445-452   code_requests + code_hash
//   lib/send.js:497-503   code_tries + wrong_total
//   lib/send.js:510-535   claimPickup + allSettled + delBlob

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('fs');
const { killSpawnedRelays } = require('./_boot-relay');
const H = require('./_send-race');
// De plafonds uit de bron lezen, niet overtikken: ze zijn in beweging.
const { MAX_CODE_REQUESTS, CODE_TRIES } = require('../lib/send');

const TRAAG_MS = 6;
let R = null;
const B = () => R.base;

before(async () => { R = await H.bootSendRelay({}, { traagMs: TRAAG_MS }); });
after(async () => {
  killSpawnedRelays();
  if (R && R.stub) await R.stub.stop();
  try { fs.unlinkSync(R.usersFile); } catch (_) { /* best effort */ }
});

function nogLevend(waar) {
  const dood = H.levendOf(R);
  assert.equal(dood, null, waar + ': ' + dood);
}

// ── 0. Eerst bewijzen dat we echt op de trage backend zitten ───────────────
test('de verzendopslag draait op redis, niet op de geheugenterugval', async () => {
  const v = await H.maakVerzending(B(), ['backend@extern.test'], { bytes: 128 });
  assert.ok(v.id, 'geen verzending gemaakt');
  assert.match(R.stdoutTail + '', /send_store_backend/,
    'de relay logde geen send_store_backend; onduidelijk welke opslag dit is');
  assert.ok(/"msg":"send_store_backend"[^\n]*"backend":"redis"/.test(R.stdoutTail),
    'de verzendopslag viel terug op geheugen; dan meet deze suite niets:\n' + R.output());
  assert.ok(R.stub.tel.get > 0 && R.stub.tel.set > 0,
    'de stub kreeg geen verkeer: get=' + R.stub.tel.get + ' set=' + R.stub.tel.set);
});

// ── 1. Twee klikken op dezelfde eenmalige link ─────────────────────────────
test('twee gelijktijdige ophalingen op een token, venster wijd open', async () => {
  for (let i = 0; i < 10; i++) {
    const adres = `t${i}@extern.test`;
    const v = await H.maakVerzending(B(), [adres], { bytes: 2048 });
    const token = v.tokens[adres];
    const code = await H.haalCode(R, token, adres);

    const [a, b] = await Promise.all([
      H.pickup(B(), token, { code }),
      H.pickup(B(), token, { code }),
    ]);
    let metBytes = 0;
    for (const r of [a, b]) {
      if (r.status === 200 && (await r.arrayBuffer()).byteLength > 0) metBytes++;
      else if (r.status !== 200) await r.text();
    }
    assert.equal(metBytes, 1,
      `ronde ${i}: ${metBytes} van de 2 gelijktijdige klikken kregen bytes ` +
      `(statussen ${a.status}/${b.status}); "werkt precies een keer" is dan niet waar`);

    const dj = await (await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id })).json();
    assert.equal(dj.collected, 1, `ronde ${i}: het overzicht telt ${dj.collected} ophalingen`);
  }
  nogLevend('na dubbele ophalingen op redis');
}, { timeout: 120000 });

// ── 2. Intrekken en ophalen tegelijk ───────────────────────────────────────
test('intrekken en ophalen tegelijk, venster wijd open', async () => {
  let opgehaald = 0, ingetrokken = 0;
  for (let i = 0; i < 15; i++) {
    const adres = `ri${i}@extern.test`;
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

    const dj = await (await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id })).json();
    const status = (dj.recipients || [])[0] && dj.recipients[0].status;

    if (kreegBytes) {
      opgehaald++;
      // DE GEVAARLIJKE COMBINATIE: de ontvanger heeft het bestand en de
      // afzender krijgt te horen dat hij het heeft tegengehouden.
      assert.equal(in_.status, 409,
        `ronde ${i}: intrekken meldde ${in_.status} ${JSON.stringify(ij)} terwijl ` +
        `de bytes al de deur uit waren`);
      assert.equal(status, 'collected',
        `ronde ${i}: bytes eruit maar het overzicht zegt "${status}"`);
    } else {
      ingetrokken++;
      assert.equal(status, 'revoked',
        `ronde ${i}: de ophaling werd geweigerd (${op.status}) maar het overzicht ` +
        `zegt "${status}"`);
    }
  }
  assert.equal(opgehaald + ingetrokken, 15);
  console.log(`      [verdeling] ${opgehaald}x ophalen won, ${ingetrokken}x intrekken won`);
  nogLevend('na intrekken-vs-ophalen op redis');
}, { timeout: 120000 });

// ── 3. Herinneren en ophalen tegelijk ──────────────────────────────────────
test('herinneren en ophalen tegelijk, venster wijd open', async () => {
  for (let i = 0; i < 12; i++) {
    const adres = `he${i}@extern.test`;
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

    assert.equal(kreegBytes, true,
      `ronde ${i}: geldige ophaling geweigerd (${op.status}) door een gelijktijdige ` +
      `herinnering (${her.status} ${JSON.stringify(hj)})`);

    // De herinnering schrijft de HELE verzending terug. Leest hij oud en
    // schrijft hij nieuw, dan is picked_up_at weg en leeft de eenmalige link op.
    const nog = await H.pickup(B(), token, { action: 'code' });
    const nj = await nog.json().catch(() => ({}));
    assert.equal(nog.status, 410,
      `ronde ${i}: de opgebruikte link leefde weer op na een gelijktijdige ` +
      `herinnering (${nog.status} ${JSON.stringify(nj)})`);

    const dj = await (await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id })).json();
    assert.equal(dj.collected, 1, `ronde ${i}: het overzicht telt ${dj.collected} ophalingen`);
  }
  nogLevend('na herinneren-vs-ophalen op redis');
}, { timeout: 120000 });

// ── 4. Gelijktijdig aanmaken: de accountindex is EEN sleutel ───────────────
test('tien gelijktijdige verzendingen staan allemaal in het overzicht', async () => {
  for (let ronde = 0; ronde < 3; ronde++) {
    const voor = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
    const hadden = new Set((voor.sends || []).map(s => s.id));

    const gemaakt = await Promise.all(Array.from({ length: 10 }, (_, i) =>
      H.maakVerzending(B(), [`ai${ronde}-${i}@extern.test`], { bytes: 256 })));

    const na = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
    const nu = new Set((na.sends || []).map(s => s.id));
    const kwijt = gemaakt.map(g => g.id).filter(id => !nu.has(id));
    assert.deepEqual(kwijt, [],
      `ronde ${ronde}: ${kwijt.length} van de 10 verzendingen bestaan wel maar staan ` +
      `niet in de accountindex -- onzichtbaar op het dashboard en niet in te trekken`);
    assert.equal(nu.size, hadden.size + 10,
      `ronde ${ronde}: de index groeide met ${nu.size - hadden.size} in plaats van 10`);
  }
  nogLevend('na gelijktijdig aanmaken op redis');
}, { timeout: 180000 });

// ── 5. Alle ontvangers tegelijk: verloren schrijfacties op EEN verzending ──
test('twintig gelijktijdige ophalingen op een verzending: alle twintig geteld', async () => {
  const adressen = Array.from({ length: 20 }, (_, i) => `ag${i}@extern.test`);
  const v = await H.maakVerzending(B(), adressen, { bytes: 1024 });
  const codes = {};
  for (const a of adressen) codes[a] = await H.haalCode(R, v.tokens[a], a);

  const antwoorden = await Promise.all(adressen.map(
    (a) => H.pickup(B(), v.tokens[a], { code: codes[a] })));
  let metBytes = 0, nul = 0;
  for (const r of antwoorden) {
    if (r.status === 200) {
      if ((await r.arrayBuffer()).byteLength > 0) metBytes++;
      if (r.headers.get('X-Paramant-Outstanding') === '0') nul++;
    } else { await r.text(); }
  }
  assert.equal(metBytes, 20, 'maar ' + metBytes + ' van de 20 kregen bytes');

  const dj = await (await H.intern(B(), '/v2/user/sends/detail', { send_id: v.id })).json();
  assert.equal(dj.collected, 20,
    'het overzicht telt ' + dj.collected + ' van de 20: er gingen schrijfacties verloren, ' +
    'dus allSettled wordt nooit waar en het bestand blijft zijn hele venster staan');
  assert.equal(dj.outstanding, 0, 'er staat nog ' + dj.outstanding + ' open');
  assert.equal(nul, 1, 'precies een ophaling hoort de laatste te zijn, er waren er ' + nul);
  nogLevend('na twintig gelijktijdige ophalingen op redis');
}, { timeout: 180000 });

// ── 6. De teller onder gelijktijdige codeverzoeken ─────────────────────────
test('gelijktijdige codeverzoeken: er komen er precies MAX_CODE_REQUESTS door', async () => {
  const adres = 'tellerredis@extern.test';
  const v = await H.maakVerzending(B(), [adres], { bytes: 128 });
  const rs = await Promise.all(Array.from({ length: MAX_CODE_REQUESTS + 5 },
    () => H.pickup(B(), v.tokens[adres], { action: 'code' })));
  const statussen = [];
  for (const r of rs) { statussen.push(r.status); await r.text(); }
  const ok = statussen.filter(s => s === 200).length;
  assert.equal(ok, MAX_CODE_REQUESTS,
    'er kwamen ' + ok + ' codeverzoeken door in plaats van ' + MAX_CODE_REQUESTS + ' (' +
    JSON.stringify(statussen) + '): het plafond op code_requests verliest dan ' +
    'schrijfacties en is een advies in plaats van een grens');
  nogLevend('na gelijktijdige codeverzoeken op redis');
}, { timeout: 60000 });

// ── 7. Een verkeerde gok en een goede, tegelijk ────────────────────────────
test('gelijktijdige foute gokken vreten precies CODE_TRIES pogingen', async () => {
  // CODE_TRIES komt uit lib/send.js. Meer gokken tegelijk dan dat: als de
  // teller schrijfacties verliest komen er meer doorheen dan het plafond, en
  // dan is de rem op het raden van een zescijferige code niet wat hij belooft.
  const adres = 'gok@extern.test';
  const v = await H.maakVerzending(B(), [adres], { bytes: 128 });
  const token = v.tokens[adres];
  await H.haalCode(R, token, adres);

  const N = CODE_TRIES + 5;
  const rs = await Promise.all(Array.from({ length: N },
    () => H.pickup(B(), token, { code: '000000' })));
  const uitslagen = [];
  for (const r of rs) uitslagen.push({ s: r.status, j: await r.json().catch(() => ({})) });
  const fout = uitslagen.filter(u => u.j.error === 'wrong_code').length;
  const dicht = uitslagen.filter(u => u.j.error === 'too_many_tries').length;
  assert.equal(fout, CODE_TRIES,
    'er werden ' + fout + ' foute gokken geteld in plaats van ' + CODE_TRIES +
    ' (CODE_TRIES); ' + JSON.stringify(uitslagen.map(u => u.s + ':' + u.j.error)));
  assert.equal(dicht, N - CODE_TRIES, 'de rest hoort too_many_tries te krijgen');
  nogLevend('na acht foute gokken op redis');
}, { timeout: 60000 });

// ── 8. Massaal aanmaken ────────────────────────────────────────────────────
test('honderd gelijktijdige verzendingen: geen enkele raakt zoek', async () => {
  const N = 100;
  const gemaakt = await Promise.all(Array.from({ length: N }, (_, i) =>
    H.maakVerzending(B(), [`mm${i}@extern.test`], { bytes: 64 })));
  nogLevend('tijdens de massatest op redis');

  const na = await (await H.intern(B(), '/v2/user/sends', { limit: 200 })).json();
  const nu = new Set((na.sends || []).map(s => s.id));
  const kwijt = gemaakt.map(g => g.id).filter(id => !nu.has(id));
  assert.equal(kwijt.length, 0,
    `${kwijt.length} van de ${N} verzendingen verdwenen uit de accountindex ` +
    `(lees-wijzig-schrijf op een sleutel, lib/send.js:326); eerste vijf: ` +
    kwijt.slice(0, 5).join(', '));
}, { timeout: 300000 });
