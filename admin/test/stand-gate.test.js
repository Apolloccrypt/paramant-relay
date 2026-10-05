'use strict';
// De sabotagetoets op de standpagina.
//
// De pagina is gebouwd omdat negen waarborgen er als een waarborg uitzagen en
// niets deden. Een statuspagina die daar bij komt is alleen iets waard als
// aantoonbaar is dat hij een echte storing ook werkelijk toont. Deze toets
// breekt daarom om de beurt iets kapot en eist dat de pagina dat zegt, en eist
// vooral het omgekeerde: dat er nergens groen verschijnt waar niets gemeten is.
//
//   node --test admin/test/stand-gate.test.js

const test = require('node:test');
const assert = require('node:assert');
const { meetDeStand, punt, slechtste, soortVanHandeling, runOordeel,
        GOED, LET_OP, NIET_GEMETEN, KAPOT } = require('../lib/stand');

const NU = Date.parse('2026-09-06T20:00:00Z');
const UUR = 3600 * 1000;

function alleP(stand) {
  const uit = [];
  for (const b of stand.blokken) for (const p of b.punten) uit.push(p);
  return uit;
}
function zoek(stand, naam) {
  return alleP(stand).find(p => p.naam === naam);
}

// Een wereld waarin alles het doet. Elke toets hieronder verandert er precies
// één ding aan, zodat de uitslag nooit aan iets anders kan liggen.
function gezondeIo(over = {}) {
  const io = {
    nu: () => NU,
    site: 'https://paramant.app',
    sectors: ['main', 'health', 'legal', 'finance', 'iot'],
    zelftestAccounts: ['pgp_kanarie'],

    relay: async (sector, pad) => {
      if (pad === '/health') return { status: 200, body: { ok: true, version: '3.1.0', sector } };
      if (pad === '/v2/health/deep') {
        return { status: 200, body: { overall: 'green', version: '3.1.0', sector, checks: [
          { name: 'storage', status: 'green', detail: 'data dir writable (/data)' },
          { name: 'redis', status: 'green', detail: 'reachable' },
        ] } };
      }
      throw new Error('onverwacht pad ' + pad);
    },

    web: async () => ({ status: 200, text: 'x'.repeat(2000), ms: 120 }),

    sleutels: async () => ([
      { account_id: 'acct_demo', active: true },
      { account_id: 'acct_tweede', active: true },
      { account_id: 'acct_uit', active: false },
    ]),

    auditRegels: async () => ([
      { user_id: 'acct_demo', event_type: 'webauthn_login', metadata: {}, ts: NU - 2 * UUR },
      { user_id: 'acct_demo', event_type: 'parasign_doc_signed', metadata: {}, ts: NU - 3 * UUR },
      { user_id: 'acct_beheer', event_type: 'admin_user_viewed', metadata: {}, ts: NU - UUR },
      { user_id: 'pgp_kanarie', event_type: 'webauthn_login', metadata: {}, ts: NU - UUR },
      { user_id: 'acct_x', event_type: 'parasign_doc_signed', metadata: { original_filename: 'canary-abc.bin' }, ts: NU - UUR },
    ]),

    laatsteProef: async () => ({ ok: true, ts: NU - 2 * UUR, ms: 340, bytes: 64 }),

    laatsteRun: async (bestand) => {
      if (bestand === 'test.yml') return { status: 'completed', conclusion: 'success', ts: NU - UUR, nummer: 900 };
      return { status: 'completed', conclusion: 'success', ts: NU - 6 * UUR, nummer: 12 };
    },

    hoofdCommit: async () => '6ab3647fabcdef1234567890',
    codeManifest: async () => ({ git_commit: '6ab3647fabcdef1234567890', published: '2026-09-06T05:40:00Z' }),
    openPRs: async () => ([{ nummer: 470, ts: NU - 2 * 86400000 }]),
  };
  return Object.assign(io, over);
}

// ── De grondregels ──────────────────────────────────────────────────────────

test('een punt zonder meting kan nooit groen worden, wat de aanroeper ook vraagt', () => {
  const p = punt('verzonnen', GOED, 'alles prima', null, 'nergens');
  assert.strictEqual(p.stand, NIET_GEMETEN);
  assert.strictEqual(p.meting, null);
  const q = punt('ook verzonnen', GOED, 'alles prima', undefined, 'nergens');
  assert.strictEqual(q.stand, NIET_GEMETEN);
});

test('een meting van nul is wel een meting en mag wel groen zijn', () => {
  // Nul handelingen is een uitkomst, geen gebrek aan uitkomst. Zou 0 hier als
  // "niet gemeten" gelden, dan werd een eerlijk nul stilgezet.
  const p = punt('nul', GOED, 'nul gezien', 0, 'de telling');
  assert.strictEqual(p.stand, GOED);
});

test('niet gemeten weegt zwaarder dan let op', () => {
  assert.strictEqual(slechtste([GOED, LET_OP, NIET_GEMETEN]), NIET_GEMETEN);
  assert.strictEqual(slechtste([GOED, NIET_GEMETEN, KAPOT]), KAPOT);
  assert.strictEqual(slechtste([GOED, GOED]), GOED);
});

test('een overgeslagen run geldt niet als geslaagd', () => {
  assert.strictEqual(runOordeel({ status: 'completed', conclusion: 'skipped' }), 'overgeslagen');
  assert.strictEqual(runOordeel({ status: 'completed', conclusion: 'success' }), 'geslaagd');
  assert.strictEqual(runOordeel({ status: 'in_progress', conclusion: null }), 'bezig');
  assert.strictEqual(runOordeel(null), null);
});

// ── De gezonde wereld ───────────────────────────────────────────────────────

test('gaat alles goed, dan zegt de pagina dat in een zin en is niets kapot', async () => {
  const stand = await meetDeStand(gezondeIo());
  assert.strictEqual(stand.kop.stand, GOED);
  for (const b of stand.blokken) assert.strictEqual(b.stand, GOED, `blok ${b.id} is ${b.stand}`);
  assert.ok(stand.kop.zin.length > 10);
  assert.deepStrictEqual(stand.blokken.map(b => b.id), ['werkt', 'gebruik', 'rood', 'mick']);
});

// ── Sabotage, een voor een ──────────────────────────────────────────────────

test('sabotage: een relay ligt eruit en de pagina noemt hem bij naam', async () => {
  const io = gezondeIo();
  const echt = io.relay;
  io.relay = async (sector, pad) => {
    if (sector === 'legal' && pad === '/health') return { status: 502, body: null };
    return echt(sector, pad);
  };
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'De relays');
  assert.strictEqual(p.stand, KAPOT);
  assert.match(p.zin, /legal/);
  assert.strictEqual(stand.kop.stand, KAPOT);
});

test('sabotage: de diepe controle zegt rood terwijl de statuscode 200 blijft', async () => {
  // Dit is de fout van 34 deploys op rij: de statuscode klopte, de uitslag
  // erin niet, en de deploy las de verkeerde van de twee.
  const io = gezondeIo();
  io.relay = async (sector, pad) => {
    if (pad === '/health') return { status: 200, body: { version: '3.1.0', sector } };
    return { status: 200, body: { overall: sector === 'health' ? 'red' : 'green', checks: [
      { name: 'storage', status: sector === 'health' ? 'red' : 'green', detail: 'not writable (/data): EROFS' },
    ] } };
  };
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'De diepe controle');
  assert.strictEqual(p.stand, KAPOT, 'een rode uitslag achter een 200 moet kapot zijn');
  assert.match(p.zin, /storage/);
  assert.match(p.zin, /health/);
});

test('sabotage: de weg van een klant loopt vast', async () => {
  const io = gezondeIo();
  io.web = async (url) => {
    if (url.endsWith('/sign')) return { status: 302, text: '', ms: 30 };
    return { status: 200, text: 'x'.repeat(2000), ms: 100 };
  };
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'De weg van een klant');
  assert.strictEqual(p.stand, KAPOT);
  assert.match(p.zin, /tekenpagina/);
});

test('sabotage: een pagina antwoordt 200 maar is leeg, en dat telt als kapot', async () => {
  // Een route die 200 zegt en niets levert is precies waar de oude rookproef
  // op slaagde. Een antwoord is nog geen pagina.
  const io = gezondeIo();
  io.web = async () => ({ status: 200, text: '', ms: 10 });
  const stand = await meetDeStand(io);
  assert.strictEqual(zoek(stand, 'De weg van een klant').stand, KAPOT);
});

test('sabotage: de uurlijkse zelftest wordt overgeslagen', async () => {
  const io = gezondeIo();
  io.laatsteRun = async (bestand) => {
    if (bestand === 'heartbeat.yml') return { status: 'completed', conclusion: 'skipped', ts: NU - UUR };
    if (bestand === 'test.yml') return { status: 'completed', conclusion: 'success', ts: NU - UUR };
    return { status: 'completed', conclusion: 'success', ts: NU - 6 * UUR };
  };
  const stand = await meetDeStand(io);

  const controles = zoek(stand, 'De dagelijkse controles');
  assert.strictEqual(controles.stand, KAPOT, 'een overgeslagen controle mag nooit groen zijn');
  assert.match(controles.zin, /zelftest/);

  // En het moet als werk voor Mick op de pagina staan, met de commando's erbij.
  const sleutels = zoek(stand, 'De twee sleutels van de zelftest');
  assert.strictEqual(sleutels.stand, KAPOT);
  assert.ok(Array.isArray(sleutels.hoe), 'er hoort te staan wat hij precies moet doen');
  assert.ok(sleutels.hoe.some(r => r.includes('PARAMANT_CANARY_KEY')));
  assert.ok(sleutels.hoe.some(r => r.includes('PARASIGN_CANARY_KEY')));
  assert.match(sleutels.zin, /klant/, 'er hoort te staan wat er niet gebeurt zolang het blijft liggen');
});

test('sabotage: een controle die al twee dagen niets van zich liet horen is stil, niet groen', async () => {
  const io = gezondeIo();
  io.laatsteRun = async (bestand) => {
    if (bestand === 'test.yml') return { status: 'completed', conclusion: 'success', ts: NU - UUR };
    return { status: 'completed', conclusion: 'success', ts: NU - 100 * UUR };
  };
  const stand = await meetDeStand(io);
  assert.strictEqual(zoek(stand, 'De dagelijkse controles').stand, KAPOT);
});

test('sabotage: de server draait andere code dan de repo', async () => {
  const io = gezondeIo();
  io.codeManifest = async () => ({ git_commit: '0fcbb746deadbeef', published: '2026-09-04T02:00:00Z' });
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'Repo en server');
  assert.strictEqual(p.stand, KAPOT);
  assert.match(p.zin, /0fcbb746/);
  assert.match(p.zin, /6ab3647f/);
});

test('sabotage: de laatste echte proef is mislukt', async () => {
  const io = gezondeIo();
  io.laatsteProef = async () => ({ ok: false, ts: NU - UUR, reden: 'het bestand overleefde het lezen' });
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'De laatste echte proef');
  assert.strictEqual(p.stand, KAPOT);
  assert.match(p.zin, /overleefde/);
});

test('sabotage: er is nog nooit een echte proef gedaan', async () => {
  const io = gezondeIo();
  io.laatsteProef = async () => null;
  const stand = await meetDeStand(io);
  assert.strictEqual(zoek(stand, 'De laatste echte proef').stand, NIET_GEMETEN);
});

test('sabotage: wijzigingen blijven te lang buiten de hoofdtak', async () => {
  const io = gezondeIo();
  io.openPRs = async () => ([
    { nummer: 1, ts: NU - 40 * 86400000 },
    { nummer: 2, ts: NU - 9 * 86400000 },
    { nummer: 3, ts: NU - 86400000 },
  ]);
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'De landingspoort');
  assert.strictEqual(p.stand, LET_OP);
  assert.strictEqual(p.meting.te_oud, 2);
});

// ── De les van de 485 ───────────────────────────────────────────────────────

test('de zelftest telt niet mee als gebruik, en staat er apart bij', async () => {
  const stand = await meetDeStand(gezondeIo());
  const p = zoek(stand, 'Handelingen door mensen, laatste zeven dagen');
  // Twee mensen, een beheerhandeling, en twee zelftesthandelingen: een van een
  // aangemerkt account en een aan het kanarie-kenmerk herkend.
  assert.deepStrictEqual(p.meting, { mens: 2, mick: 1, zelftest: 2 });
  const z = zoek(stand, 'Wat de zelftest zelf deed');
  assert.strictEqual(z.meting.zelftest, 2);
});

test('bestaat het gebruik alleen uit de zelftest, dan is het cijfer nul en zegt de pagina dat', async () => {
  const io = gezondeIo();
  io.auditRegels = async () => {
    const uit = [];
    for (let i = 0; i < 485; i++) {
      uit.push({ user_id: 'pgp_kanarie', event_type: 'parasign_doc_signed', metadata: { original_filename: 'canary-x.bin' }, ts: NU - i * 60000 });
    }
    return uit;
  };
  const stand = await meetDeStand(io);
  const p = zoek(stand, 'Handelingen door mensen, laatste zeven dagen');
  assert.strictEqual(p.meting.mens, 0, '485 kanarieregels mogen nooit als gebruik tellen');
  assert.strictEqual(p.meting.zelftest, 485);
  assert.strictEqual(p.stand, LET_OP);
  assert.match(p.zin, /niemand gebruikt het/);

  const laatste = zoek(stand, 'De laatste handeling door een mens');
  assert.strictEqual(laatste.stand, LET_OP);
});

test('de indeling van een handeling volgt een regel die na te rekenen is', () => {
  const z = ['pgp_kanarie'];
  assert.strictEqual(soortVanHandeling({ user_id: 'a', event_type: 'admin_key_viewed' }, z), 'mick');
  assert.strictEqual(soortVanHandeling({ user_id: 'pgp_kanarie', event_type: 'webauthn_login' }, z), 'zelftest');
  assert.strictEqual(soortVanHandeling({ user_id: 'a', event_type: 'x', metadata: { f: 'canary-1' } }, z), 'zelftest');
  assert.strictEqual(soortVanHandeling({ user_id: 'a', event_type: 'x', metadata: { f: 'stand-1' } }, z), 'zelftest');
  assert.strictEqual(soortVanHandeling({ user_id: 'a', event_type: 'webauthn_login', metadata: {} }, z), 'mens');
});

// ── De belangrijkste toets van allemaal ─────────────────────────────────────

test('valt alles weg, dan is niets groen en zegt de kop dat het onbekend is', async () => {
  // Dit is de hele les van de nacht van 5 op 6 september in een toets. Negen
  // waarborgen zagen eruit als een waarborg en deden niets, en zolang niemand
  // keek stond alles op groen. Hier mag dat niet kunnen.
  const stuk = async () => { throw new Error('niets bereikbaar'); };
  const io = gezondeIo({
    relay: stuk, web: stuk, sleutels: stuk, auditRegels: stuk, laatsteProef: stuk,
    laatsteRun: stuk, hoofdCommit: stuk, codeManifest: stuk, openPRs: stuk,
  });
  const stand = await meetDeStand(io);

  const groen = alleP(stand).filter(p => p.stand === GOED);
  assert.deepStrictEqual(groen.map(p => p.naam), [], 'geen enkel punt mag groen zijn als er niets gemeten is');
  assert.notStrictEqual(stand.kop.stand, GOED);

  // Elk punt zonder meting moet ook werkelijk null als meting hebben, zodat de
  // pagina geen getal kan tonen dat nergens vandaan komt.
  for (const p of alleP(stand)) {
    if (p.stand === NIET_GEMETEN) assert.strictEqual(p.meting, null, `${p.naam} heeft een meting terwijl hij niet gemeten is`);
  }
});

test('een enkel weggevallen blok trekt de kop weg van groen', async () => {
  const io = gezondeIo({ openPRs: async () => { throw new Error('github stil'); } });
  const stand = await meetDeStand(io);
  assert.strictEqual(zoek(stand, 'De landingspoort').stand, NIET_GEMETEN);
  assert.notStrictEqual(stand.kop.stand, GOED, 'een weggevallen meting mag niet als goed doorgaan');
  assert.match(stand.kop.zin, /niet alles meten/);
});

test('elk punt draagt een bron, zodat elk getal te herleiden is', async () => {
  const stand = await meetDeStand(gezondeIo());
  for (const p of alleP(stand)) {
    assert.ok(p.bron && p.bron.length > 4, `${p.naam} heeft geen bron`);
    assert.ok(p.zin && p.zin.length > 10, `${p.naam} heeft geen leesbare zin`);
  }
});
