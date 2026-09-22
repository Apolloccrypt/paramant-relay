'use strict';

// WAT BLIJFT ER LIGGEN, EN WAT VERDWIJNT TE VROEG OF TE LAAT.
//
// De reis van afzender tot ontvanger is elders getest (groep-e2e). Niemand had
// ooit geteld wat er NA afloop nog in de opslag staat: de blob, de tokenregels,
// het accountoverzicht. Dat is precies waar een lek zit dat niemand ziet, want
// een lek levert geen foutmelding op -- alleen geheugen dat niet terugkomt.
//
// Deze suite praat rechtstreeks met de echte opslag (lib/parasign-store.js in
// zijn geheugenvorm, precies wat de relay zonder REDIS_URL gebruikt) en met de
// echte lib/send.js. Geen nepstore: `telling()` leest de Map zelf, ZONDER de
// opslag aan te raken, want elke get() doet memSweep() en zou juist wegpoetsen
// wat we willen meten.

const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('crypto');

const { createParaSignStore } = require('../lib/parasign-store');
const { createSendStore, accountIndexId } = require('../lib/send');

// De relay zonder redis: createParaSignStore({}) -> backend 'memory'.
function nieuweOpslag() {
  const store = createParaSignStore({});
  assert.equal(store.backend, 'memory', 'deze suite meet de geheugenvariant');
  return store;
}

// Wat er FYSIEK in de Map staat. Leest `_mem` rechtstreeks, dus zonder de lazy
// memSweep die elke get() uitvoert.
function telling(store) {
  const uit = { blob: [], send: [], tok: [], acct: [], bytes: 0 };
  for (const [k, v] of store._mem) {
    const deel = k.split(':');
    const kind = deel[1];
    const id = deel.slice(2).join(':');
    uit.bytes += (v.val && v.val.length) || 0;
    if (kind === 'blob') uit.blob.push(id);
    else if (id.startsWith('tok-')) uit.tok.push(id);
    else if (id.startsWith('acct-')) uit.acct.push(id);
    else uit.send.push(id);
  }
  return uit;
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

async function maakVerzending(sends, adressen, opts = {}) {
  const { sealed, tokens } = zegel(adressen);
  const made = await sends.create({
    plan: opts.plan || 'pro',
    blob: opts.blob || crypto.randomBytes(opts.bytes || 4096),
    addresses: adressen,
    sealed,
    ttlMs: opts.ttlMs,
    filename: opts.filename || 'stuk.pdf',
    accountId: opts.accountId || 'acct_levensduur',
    sender: { naam: 'Zorggroep De Linde', email: 'anna@zorggroep.test' },
  });
  assert.equal(made.ok, true, 'verzending geweigerd: ' + JSON.stringify(made));
  return { made, tokens };
}

// Ophalen kost twee stappen: code vragen, code invullen.
async function haalOp(sends, token) {
  const vraag = await sends.requestPickup(token);
  assert.equal(vraag.ok, true, 'code vragen faalde: ' + JSON.stringify(vraag));
  return sends.collect(token, vraag.code);
}

const wacht = (ms) => new Promise((r) => setTimeout(r, ms));

// ── 1. NIEMAND HAALT OP ──────────────────────────────────────────────────────
test('niemand haalt op: na de TTL staat alles er nog, tot iets de opslag leest', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const { made, tokens } = await maakVerzending(sends, ['a@extern.test', 'b@extern.test'],
    { ttlMs: 1200, bytes: 200_000 });

  const voor = telling(store);
  assert.deepEqual(voor.blob, [made.id], 'de blob hoort er te staan');
  assert.equal(voor.tok.length, 2, 'een tokenregel per ontvanger');
  assert.equal(voor.acct.length, 1, 'en een accountindex');
  assert.ok(voor.bytes > 200_000, 'de bytes staan echt in het geheugen: ' + voor.bytes);

  await wacht(1500);   // de TTL is voorbij, niemand heeft iets gedaan

  // HET GAT: verlopen is niet hetzelfde als opgeruimd. De geheugenvariant
  // ruimt alleen op bij een get() (memSweep) of via een timer die elke
  // 300_000 ms loopt (parasign-store.js, `memTimer`). Een relay waar niemand
  // iets doet houdt de hele blob dus tot vijf minuten NA de TTL vast.
  const na = telling(store);
  assert.deepEqual(na.blob, [made.id],
    'de blob staat na de TTL nog steeds in het geheugen');
  assert.ok(na.bytes > 200_000, 'inclusief alle bytes: ' + na.bytes);
  assert.equal(na.tok.length, 2, 'en de tokenregels ook');

  // Eén aanraking en het is weg: memSweep loopt over de hele Map.
  const poging = await sends.requestPickup(tokens['a@extern.test']);
  assert.equal(poging.ok, false);
  assert.equal(poging.reason, 'unknown_token',
    'een verlopen link heet hier `unknown_token`, niet `expired`');

  const opgeruimd = telling(store);
  assert.deepEqual(opgeruimd.blob, [], 'de blob is nu weg');
  assert.deepEqual(opgeruimd.send, [], 'de records ook');
  assert.deepEqual(opgeruimd.tok, [], 'de tokenregels ook');
  assert.equal(opgeruimd.acct.length, 1,
    'alleen de accountindex blijft: die heeft een eigen TTL van 30 dagen');
});

// ── 2. IEDEREEN HAALT OP ─────────────────────────────────────────────────────
test('iedereen haalt op: de blob gaat pas weg als de bytes de deur uit zijn', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const adressen = ['a@extern.test', 'b@extern.test', 'c@extern.test'];
  const { made, tokens } = await maakVerzending(sends, adressen, { bytes: 50_000 });

  for (const a of adressen.slice(0, 2)) {
    const uit = await haalOp(sends, tokens[a]);
    assert.equal(uit.ok, true);
    assert.equal(uit.settled, false, 'zolang er iemand wacht is het niet klaar');
    // drained() op een verzending die nog niet rond is laat de blob staan.
    assert.deepEqual(await sends.drained(made.id), { ok: true, kept: true });
    assert.deepEqual(telling(store).blob, [made.id], 'de blob blijft voor de rest');
  }

  const laatste = await haalOp(sends, tokens[adressen[2]]);
  assert.equal(laatste.ok, true);
  assert.equal(laatste.settled, true);
  // GEMETEN op de stand van 22-09 19:09. collect() laat de blob EXPRES staan:
  // de route dropt hem pas op res 'finish' (relay.js, res.on('finish') ->
  // _sendStore().drained(got.send_id)). Een afgebroken download geeft via
  // releaseClaim() de beurt terug in plaats van het bestand te vernietigen.
  assert.deepEqual(telling(store).blob, [made.id],
    'na de laatste ophaler staat de blob er nog: collect() dropt niet meer zelf');

  assert.deepEqual(await sends.drained(made.id), { ok: true, dropped: true });
  assert.deepEqual(telling(store).blob, [], 'pas drained() ruimt op');
  const rest = telling(store);
  assert.equal(rest.send.length, 1, 'de records blijven, zodat de afzender ziet wie ophaalde');
  assert.equal(rest.tok.length, 3,
    'en de drie tokenregels blijven ook staan, tot de TTL van de verzending');

  const beeld = await sends.overview(made.id);
  assert.equal(beeld.collected, 3);
  assert.equal(beeld.outstanding, 0);
});

// ── 3. IEDEREEN INGETROKKEN ──────────────────────────────────────────────────
test('iedereen ingetrokken: de blob gaat net zo hard weg', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const adressen = ['a@extern.test', 'b@extern.test'];
  const { made } = await maakVerzending(sends, adressen, { bytes: 50_000 });

  const een = await sends.revoke(made.id, adressen[0]);
  assert.equal(een.ok, true);
  assert.equal(een.settled, false);
  assert.deepEqual(telling(store).blob, [made.id], 'er wacht er nog een');

  const twee = await sends.revoke(made.id, adressen[1]);
  assert.equal(twee.ok, true);
  assert.equal(twee.settled, true);
  assert.deepEqual(telling(store).blob, [],
    'alles ingetrokken hoort dezelfde opruiming te krijgen als alles opgehaald');
  assert.equal(telling(store).send.length, 1, 'de records blijven staan');
});

// ── 4. GEMENGD ───────────────────────────────────────────────────────────────
test('gemengd: een opgehaald, een ingetrokken, een wachtend -- de blob blijft terecht staan', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const adressen = ['a@extern.test', 'b@extern.test', 'c@extern.test'];
  const { made, tokens } = await maakVerzending(sends, adressen, { bytes: 50_000 });

  assert.equal((await haalOp(sends, tokens[adressen[0]])).ok, true);
  await sends.drained(made.id);
  assert.equal((await sends.revoke(made.id, adressen[1])).settled, false);
  assert.deepEqual(telling(store).blob, [made.id],
    'zolang er een wacht hoort de blob te blijven');

  const beeld = await sends.overview(made.id);
  assert.deepEqual([beeld.collected, beeld.revoked, beeld.outstanding], [1, 1, 1]);

  // En zodra de wachtende ophaalt EN zijn bytes binnen zijn, is het klaar.
  const laatste = await haalOp(sends, tokens[adressen[2]]);
  assert.equal(laatste.settled, true);
  assert.deepEqual(telling(store).blob, [made.id], 'nog niet: de bytes zijn nog onderweg');
  await sends.drained(made.id);
  assert.deepEqual(telling(store).blob, [], 'nu pas weg');
});

// ── 5. WAT DE AFZENDER ZIET VAN EEN VERLOPEN VERZENDING ──────────────────────
test('een verlopen verzending is in het overzicht alleen nog een id', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const { made } = await maakVerzending(sends, ['a@extern.test'],
    { ttlMs: 1200, filename: 'jaarrekening-2025.pdf', bytes: 50_000 });

  const vers = await sends.list('acct_levensduur');
  assert.equal(vers.sends[0].filename, 'jaarrekening-2025.pdf');
  assert.equal(vers.sends[0].total, 1);

  await wacht(1500);

  const oud = await sends.list('acct_levensduur');
  assert.equal(oud.sends.length, 1, 'de rij blijft staan, dat is het goede deel');
  // GEMETEN: dit is alles wat er overblijft.
  assert.deepEqual(oud.sends[0], { id: made.id, status: 'expired' });
  assert.equal(oud.sends[0].filename, undefined,
    'geen bestandsnaam meer, dus een week later zegt de rij niet WAT er verstuurd is');
  assert.equal(oud.sends[0].total, undefined, 'en ook niet aan hoeveel mensen');
  assert.equal(oud.sends[0].created_at, undefined, 'en ook niet wanneer');
});

// ── 6. DE ACCOUNTINDEX LOOPT VOL ─────────────────────────────────────────────
test('verzending 201 duwt de eerste uit het overzicht terwijl blob en token blijven leven', async () => {
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const acct = 'acct_tweehonderdeen';

  // Een lange TTL, zodat er niets vanzelf verdwijnt: enterprise mag 7 dagen.
  const eerste = await maakVerzending(sends, ['eerste@extern.test'],
    { plan: 'enterprise', ttlMs: 7 * 24 * 3600 * 1000, accountId: acct, bytes: 1024,
      filename: 'de-eerste.pdf' });

  for (let i = 2; i <= 201; i++) {
    await maakVerzending(sends, [`nr${i}@extern.test`],
      { plan: 'enterprise', ttlMs: 7 * 24 * 3600 * 1000, accountId: acct, bytes: 256 });
  }

  const index = await store.getMeta(accountIndexId(acct));
  assert.equal(index.sends.length, 200, 'de index is gecapt op ACCOUNT_INDEX_MAX = 200');
  assert.equal(index.sends.includes(eerste.made.id), false,
    'en verzending 1 is eruit gevallen');

  const lijst = await sends.list(acct, 200);
  assert.equal(lijst.sends.some(s => s.id === eerste.made.id), false,
    'de afzender ziet hem niet meer in zijn overzicht');

  // HET GAT: onzichtbaar, maar springlevend.
  const tel = telling(store);
  assert.ok(tel.blob.includes(eerste.made.id),
    'de blob van de weggevallen verzending staat er gewoon nog, zeven dagen lang');
  assert.ok(tel.send.includes(eerste.made.id), 'inclusief de ontvangerslijst');

  // En de ontvanger kan nog gewoon ophalen, van een verzending die de afzender
  // niet meer kan zien en dus ook niet meer kan intrekken via zijn overzicht.
  const uit = await haalOp(sends, eerste.tokens['eerste@extern.test']);
  assert.equal(uit.ok, true, 'de link werkt nog: ' + JSON.stringify(uit));
  assert.equal(uit.blob.length, 1024, 'en levert het hele bestand');
});

// ── 7. DE INTREKKING DIE TE VROEG OPRUIMT ────────────────────────────────────
test('intrekken vernietigt niets onder een ophaling die nog loopt', async () => {
  // De ophaalkant is op 22-09 verbouwd: collect() laat de blob staan en de
  // route dropt hem pas als de bytes echt zijn aangekomen (drained), zodat een
  // dode verbinding de beurt teruggeeft (releaseClaim) in plaats van het
  // bestand te vernietigen. _revoke() is NIET meegegaan: die dropt nog inline
  // (lib/send.js:635, `if (settled) await store.delBlob(id)`).
  //
  // Dat is precies de volgorde die op een telefoon gewoon voorkomt.
  const store = nieuweOpslag();
  const sends = createSendStore({ store });
  const adressen = ['ophaler@extern.test', 'tweede@extern.test'];
  const { made, tokens } = await maakVerzending(sends, adressen, { bytes: 50_000 });

  // 1. De ophaler klikt, krijgt zijn bytes toegewezen, maar de verbinding valt
  //    weg voordat ze binnen zijn. De route dropt dus niets.
  const uit = await haalOp(sends, tokens[adressen[0]]);
  assert.equal(uit.ok, true);
  assert.equal(uit.settled, false);

  // 2. De afzender trekt de tweede in. Nu is alles 'settled' en de blob gaat
  //    er direct af, terwijl de eerste zijn bestand nog nooit heeft gezien.
  const ing = await sends.revoke(made.id, adressen[1]);
  assert.equal(ing.settled, true);
  assert.deepEqual(telling(store).blob, [],
    'intrekken ruimt meteen op, zonder te kijken of de bytes al binnen waren');

  // 3. De verbinding van de ophaler valt weg: de route geeft zijn beurt terug.
  const terug = await sends.releaseClaim(tokens[adressen[0]]);
  assert.deepEqual(terug, { ok: true, returned: true });

  // 4. Hij probeert het opnieuw, binnen zijn venster van 24 uur.
  const vraag = await sends.requestPickup(tokens[adressen[0]]);
  assert.equal(vraag.ok, true, 'de link leeft nog: ' + JSON.stringify(vraag));
  const weer = await sends.collect(tokens[adressen[0]], vraag.code);
  assert.equal(weer.ok, false);
  assert.equal(weer.reason, 'expired',
    'het bestand is weg terwijl de verzending nog uren open staat');

  // En wat de afzender ziet: iemand die nog altijd "wacht" op een bestand dat
  // niet meer bestaat.
  const beeld = await sends.overview(made.id);
  assert.equal(beeld.outstanding, 1);
  assert.equal(beeld.recipients.find(r => r.email === adressen[0]).status, 'waiting');
});
