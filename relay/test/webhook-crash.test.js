'use strict';

// EEN JSON-VELD DAT DE HELE RELAY AFSLUIT.
//
// DEZE SUITE HOORT NU ROOD TE ZIJN. Hij beschrijft wat er moet gebeuren; wat er
// gebeurt is dat het proces afsluit en alle blobs van alle klanten meeneemt.
//
// DE KETEN, drie regels ver uit elkaar:
//
//   1. relay.js:7462   POST /v2/webhook
//        webhooks.get(k).push({ url: d.url, secret: d.secret || '' });
//      `d.secret` komt rechtstreeks uit de JSON-body. Er is geen String(),
//      alleen `|| ''` voor falsy waarden. Een getal, een array, een object of
//      `true` overleeft dat en wordt opgeslagen zoals hij binnenkwam.
//
//   2. relay.js:7055   POST /v2/inbound, nadat de blob is opgeslagen
//        pushWebhooks(apiKey, deviceId, 'blob_ready', {...});
//      Geen await, geen .catch. De teruggegeven promise gaat nergens heen.
//
//   3. relay.js:3336   in pushWebhooks, EEN REGEL BOVEN de try op 3337
//        const sig = hook.secret
//          ? crypto.createHmac('sha256', hook.secret).update(payload)...
//      createHmac gooit ERR_INVALID_ARG_TYPE op alles wat geen string,
//      Buffer, TypedArray of KeyObject is. Synchroon gooien in een async
//      functie is een rejected promise, en niemand vangt hem.
//
// EN DAN relay.js:10372 (process.on('unhandledRejection')) -> 10344
// emergencyZeroAndExit: elke blob in blobStore wordt genulled en het proces
// doet process.exit(1). Niet alleen de verzending van de aanvaller: ALLES wat
// er op dat moment in dit proces staat, van elke klant.
//
// WIE DIT KAN. De route zit achter een ParaSend Pro+ poort (relay.js:7452), dus
// er is een betalende sleutel voor nodig. Eén klant met een Pro-abonnement kan
// hiermee de relay voor alle anderen omleggen, en het blijft werken: de
// webhookregistratie blijft staan, dus elke volgende upload op dat device_id
// doet het opnieuw.
//
// De registratie doet alleen een syntactische SSRF-controle (isSsrfSafeUrl
// kijkt naar protocol en hostnaam, niet naar DNS), en de throw gebeurt VOOR
// safeHttpsRequest. De URL hoeft dus nergens heen te wijzen.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('fs');
const crypto = require('crypto');
const { killSpawnedRelays } = require('./_boot-relay');
const H = require('./_send-race');

let R = null;
const B = () => R.base;
const DEVICE = 'toestel-van-de-aanvaller';

before(async () => { R = await H.bootSendRelay(); });
after(() => {
  killSpawnedRelays();
  try { fs.unlinkSync(R.usersFile); } catch (_) { /* best effort */ }
});

async function registreerWebhook(secret) {
  const r = await fetch(B() + '/v2/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': H.API_KEY },
    // secret gaat er RAUW in, zodat het type overleeft.
    body: '{"device_id":"' + DEVICE + '","url":"https://voorbeeld.example/haak",' +
          '"secret":' + secret + '}',
  });
  const j = await r.json().catch(() => ({}));
  return { status: r.status, j };
}

async function uploadOpDevice() {
  const bytes = crypto.randomBytes(64);
  const hash = crypto.createHash('sha256').update(bytes).digest('hex');
  const r = await fetch(B() + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': H.API_KEY },
    body: JSON.stringify({ hash, payload: bytes.toString('base64'),
                           meta: { device_id: DEVICE } }),
  }).catch((e) => ({ status: 0, err: e.message }));
  if (r.text) await r.text().catch(() => {});
  return r.status;
}

test('een webhook-secret dat geen string is legt de relay niet om', async () => {
  const reg = await registreerWebhook('12345');
  assert.equal(reg.status, 200,
    'de registratie werd geweigerd (' + reg.status + ' ' + JSON.stringify(reg.j) +
    '); dan kan deze test het gat niet aantonen');

  // De blob van een ANDERE klant die op dit moment in het proces staat. Als de
  // relay hierop afsluit, is deze ook weg -- dat is de eigenlijke schade.
  const vanEenAnder = await H.maakVerzending(B(), ['onschuldig@extern.test'], { bytes: 2048 });

  const status = await uploadOpDevice();

  // Even wachten: pushWebhooks wordt zonder await aangeroepen, dus de rejection
  // komt pas nadat het antwoord al verstuurd is.
  await new Promise((r) => setTimeout(r, 600));

  assert.equal(H.levendOf(R), null,
    'de relay sloot af op een JSON-veld. Upload antwoordde ' + status + '. ' +
    'De verzending van een andere klant (' + vanEenAnder.id + ') is hiermee ook weg.');

  const h = await fetch(B() + '/health');
  assert.ok(h.ok, '/health antwoordt niet meer');
  await h.text();
});

test('de andere niet-stringvormen doen hetzelfde', async () => {
  // Draait alleen nog als de relay de eerste test overleefde. Anders zegt de
  // foutmelding hierboven al genoeg.
  assert.equal(H.levendOf(R), null, 'de relay lag al om na de eerste test');
  for (const vorm of ['{"a":1}', '[1,2,3]', 'true', '1.5']) {
    const reg = await registreerWebhook(vorm);
    assert.equal(reg.status, 200, 'registratie met secret=' + vorm + ' gaf ' + reg.status);
    await uploadOpDevice();
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(H.levendOf(R), null, 'de relay sloot af op secret=' + vorm);
  }
});
