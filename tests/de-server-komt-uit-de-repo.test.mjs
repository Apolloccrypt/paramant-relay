// De poort die de repo naast de gemeten werkelijkheid legt.
//
// Waarom hij bestaat: deploy/deploy-3.1.sh installeert geen enkele nginx-conf
// uit de repo. Het patcht de confs die op de server staan op ankerregels, en
// het enige bestand dat het echt kopieert is het limit_req-snippet. De confs in
// de repo zijn daarmee een verslag en geen bron, en een verslag kan uiteenlopen
// met wat het beschrijft zonder dat iets het merkt. Op 2026-09-05 was dat geen
// theorie: de repo zei client_max_body_size 12M, productie weigerde alles boven
// 10485760 bytes, en dat getal stond in geen enkel repobestand.
//
// Twee helften. De eerste heeft geen netwerk nodig en bewaakt de afspraak zelf.
// De tweede meet productie. Die tweede draait standaard mee, en dat is een
// besluit: tests/verify-knows-the-fleet.test.mjs heeft een live-helft achter
// FLEET_LIVE=1 en niemand heeft die variabele ooit gezet, dus die helft heeft
// nooit gedraaid. Aanzetten-op-verzoek is uit. Wie hem uit wil zetten moet
// DE_SERVER_OFFLINE=1 zetten, en de eerste helft bewaakt dat geen enkele
// workflow dat stiekem doet.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  ROOT, PUBLIEKE_CONF, leesPubliekeConf, naarBytes, leesAfspraak, leesAnkers,
  verwachting, meet, vergelijk,
} from '../scripts/meet-de-server.mjs';

const verw = verwachting();

// --- de afspraak zelf, zonder netwerk ------------------------------------

test('elke host in de afspraak heeft een rol en een sectorveld', () => {
  for (const h of verw.afspraak.hosts) {
    assert.ok(h.host, 'een host zonder naam');
    assert.ok(h.rol, h.host + ' heeft geen rol; dan weet niemand waarom hij bestaat');
    assert.ok('sector' in h, h.host + ' zegt niet of hij een relay is');
  }
});

// De kern van het ontwerp, overgenomen uit tests/knoppen-compleet.test.mjs: een
// ontbrekende richtlijn is een waarde en geen leegte. nginx waarschuwt niet als
// client_max_body_size ontbreekt, hij neemt zijn eigen 1 MB. Zou iemand de
// regel uit de conf halen, dan zou de vergelijking hem stilzwijgend overslaan.
// Daarom is het hier een fout.
test('elke relay-host heeft een grens in de publieke conf, want een ontbrekende grens is stil', () => {
  for (const [naam, v] of Object.entries(verw.perHost)) {
    if (!v.sector) continue;
    assert.notEqual(v.limiet, null,
      naam + ' heeft geen client_max_body_size in ' + PUBLIEKE_CONF
      + '; nginx valt dan terug op 1 MB en niets in de repo zegt dat');
    assert.ok(v.limietBron, naam + ' heeft geen bronregel voor zijn grens');
  }
});

test('nginx-groottes worden exact gelezen, want 10M en 10485760 mogen niet door elkaar lopen', () => {
  assert.equal(naarBytes('12M'), 12582912);
  assert.equal(naarBytes('10m'), 10485760);
  assert.equal(naarBytes('35M'), 36700160);
  assert.equal(naarBytes('64k'), 65536);
  assert.equal(naarBytes('10485760'), 10485760);
  assert.throws(() => naarBytes('10MB'), /onleesbare/);
});

test('de publieke conf levert voor elke host uit de afspraak een serverblok op', () => {
  const blokken = leesPubliekeConf();
  const namen = new Set(blokken.flatMap((b) => b.namen));
  for (const h of verw.afspraak.hosts) {
    if (h.host === 'addin.paramant.app') continue; // eigen conf, zie de afspraak
    assert.ok(namen.has(h.host), h.host + ' komt in geen enkel serverblok van ' + PUBLIEKE_CONF + ' voor');
  }
});

test('elke vastgezette relaysleutel hoort bij een host uit de afspraak', () => {
  const hosts = new Set(verw.afspraak.hosts.map((h) => h.host));
  for (const a of leesAnkers()) {
    assert.ok(hosts.has(a.host),
      a.host + ' staat vastgezet in frontend/js/relay-trust-anchors.js maar niet in deploy/de-server.json');
  }
});

// Een bekend verschil zonder gemeten waarde is een excuus, geen registratie.
test('elk bekend verschil is volledig opgeschreven', () => {
  const afspraak = leesAfspraak();
  for (const a of afspraak.afwijkingen) {
    assert.ok(a.host && a.wat, 'een afwijking zonder host of onderwerp');
    assert.ok(a.gemeten, a.host + '/' + a.wat + ': geen gemeten waarde, dus niets om op te merken dat het verandert');
    assert.ok(a.verwacht, a.host + '/' + a.wat + ': geen repowaarde, dan mag de repo ongemerkt verder weglopen');
    assert.match(String(a.sinds), /^\d{4}-\d{2}-\d{2}$/, a.host + '/' + a.wat + ': geen datum');
    assert.ok(String(a.reden).length > 80,
      a.host + '/' + a.wat + ': de reden is te kort om een besluit te zijn');
  }
});

// De laag die nergens in de repo staat mag niet stilletjes uit de afspraak
// verdwijnen: dan zou de poort groen worden juist omdat er niets meer over hem
// gezegd wordt.
test('de laag voor nginx staat verklaard, met een reden', () => {
  const rand = leesAfspraak().rand;
  assert.ok(rand && rand.naam, 'er staat geen randlaag in deploy/de-server.json');
  assert.ok(String(rand.reden).length > 120, 'de randlaag staat er zonder uitgelegd te zijn');
  assert.match(rand.bron, /niet in de repo/, 'als de randlaag wel uit de repo komt, hoort dit bestand dat te zeggen');
});

// Het lek van FLEET_LIVE, dichtgezet: een live helft die je aan moet zetten
// draait nooit. Deze test bewaakt dat niemand hem alsnog uitzet.
test('geen enkele workflow zet de live helft uit', () => {
  const map = path.join(ROOT, '.github/workflows');
  for (const naam of fs.readdirSync(map)) {
    const bron = fs.readFileSync(path.join(map, naam), 'utf8');
    assert.doesNotMatch(bron, /DE_SERVER_OFFLINE/,
      naam + ' zet DE_SERVER_OFFLINE; dan meet niemand productie meer en is deze poort een decor');
  }
});

// --- de gemeten werkelijkheid --------------------------------------------

test('wat productie doet is wat de repo zegt, of het staat als verschil opgeschreven', async (t) => {
  if (process.env.DE_SERVER_OFFLINE === '1') {
    t.diagnostic('DE_SERVER_OFFLINE=1: productie is niet gemeten. Dit is geen groen.');
    return;
  }
  const meting = await meet();
  const regels = vergelijk(verw, meting);
  const rood = regels.filter((r) => r.status === 'rood' || r.status === 'opgelost');
  const uitleg = rood.map((r) =>
    `${r.host} ${r.wat}\n    repo zegt   ${r.verwacht}  (${r.bron})\n`
    + `    server doet ${r.gemeten}\n    ${r.uitleg || 'niet opgeschreven in deploy/de-server.json'}`).join('\n');
  assert.equal(rood.length, 0,
    rood.length + ' verschil(len) tussen de repo en productie die niet in deploy/de-server.json staan:\n' + uitleg);
  assert.ok(regels.filter((r) => r.status === 'goed').length > 40,
    'er zijn te weinig controles gelukt; waarschijnlijk was productie niet bereikbaar');
});
