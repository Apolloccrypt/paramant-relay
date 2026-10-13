'use strict';

// WAT ALS INTERNAL_AUTH_TOKEN NIET GEZET IS.
//
// De vier afzendersroutes staan achter _internalOk() (relay.js:4189), en die
// delegeert naar authGate.internalAuthOk (lib/auth-gate.js:28). Die functie
// begint met `!!configuredToken`: zonder token in de omgeving is de poort
// DICHT, niet open. Dat is de goede kant op falen, maar het is ook precies het
// soort ding dat een refactor omdraait zonder dat iemand het merkt, want in
// productie staat de variabele altijd. Dus: een relay die zonder dat token
// boot, en dan langs de vier deuren.

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

let BASE = null;

const PADEN = ['/v2/user/sends', '/v2/user/sends/detail',
               '/v2/user/sends/revoke', '/v2/user/sends/reinvite'];

async function klop(pad, kop) {
  const headers = { 'Content-Type': 'application/json' };
  if (kop !== null) headers['X-Internal-Auth'] = kop;
  const r = await fetch(BASE + pad, {
    method: 'POST', headers,
    body: JSON.stringify({ user_id: 'acct_wie_dan_ook', send_id: 'wat_dan_ook',
                           email: 'iemand@extern.test' }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

before(async () => {
  const relay = await bootHealthyRelay(
    { RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun',
      USERS_JSON: JSON.stringify({ api_keys: [] }) },
    // Genuinely absent, niet alleen leeg: anders erft de test de variabele uit
    // de shell van de ontwikkelaar of uit de runner en test hij niets.
    { unset: ['INTERNAL_AUTH_TOKEN'] });
  BASE = relay.base;
});

after(() => killSpawnedRelays());

test('zonder INTERNAL_AUTH_TOKEN staan de vier afzendersroutes dicht, niet open', async () => {
  for (const pad of PADEN) {
    // Geen kop.
    const zonder = await klop(pad, null);
    assert.equal(zonder.status, 401, pad + ' stond open zonder kop: ' + JSON.stringify(zonder.body));
    assert.equal(zonder.body.error, 'unauthorized');

    // De lege string, want dat is wat nginx op elke publieke locatie zet. Als
    // "leeg is leeg" ooit als gelijk zou tellen, is dit de request die binnenkomt.
    const leeg = await klop(pad, '');
    assert.equal(leeg.status, 401, pad + ' accepteerde de lege kop die nginx zet: '
      + JSON.stringify(leeg.body));

    // En een willekeurige waarde, want zonder ingestelde token is er niets om
    // tegen te vergelijken.
    const gok = await klop(pad, 'wat_je_maar_verzint');
    assert.equal(gok.status, 401, pad + ' accepteerde een gok: ' + JSON.stringify(gok.body));
  }
});
