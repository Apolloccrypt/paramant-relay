// deploy/email-blocklist.json: heel, met bron, en nooit een aanbieder die
// mensen blijvend lezen.
//
// Deze toets eist:
//   1. het bestand is heel: elke categorie heeft een omschrijving; elke bron
//      een naam, url, licentie en datum; elke handmatige regel een reden, een
//      datum en een bron; een categorie zonder bron zegt wat er overwogen is;
//   2. de uitzonderingen: elke privacyvriendelijke en grote gewone aanbieder
//      staat erin, en geen van hen (of een domein erboven of eronder) staat op
//      een lijst. Dat geldt ook na een automatische update: het script haalt
//      ze eruit en meldt het, en dit bestand faalt als het er toch in komt;
//   3. het script: een bron met proton.me erin levert een lijst zonder
//      proton.me; een lege of kapotte bron schrijft niets;
//   4. een externe bron staat in deploy/partners.json als actieve
//      blocklist-bron, met zijn host.
//
// Run: node --test tests/email-blocklist.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normaliseer, parseLijst, pasToe, raaktUitzondering } from '../scripts/update-email-blocklist.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const lijst = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/email-blocklist.json'), 'utf8'));
const partners = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/partners.json'), 'utf8'));

// Nooit blokkeren. Staat hier los van het bestand, zodat een update die de
// uitzonderingen zelf inkort ook faalt.
const NOOIT = [
  'proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me',
  'tuta.com', 'tuta.io', 'tutanota.com', 'tutanota.de', 'tutamail.com', 'keemail.me',
  'mailbox.org', 'posteo.de', 'posteo.net', 'disroot.org', 'riseup.net',
  'startmail.com', 'mailfence.com', 'runbox.com', 'fastmail.com', 'fastmail.fm',
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'icloud.com', 'me.com', 'aol.com', 'gmx.de', 'gmx.net', 'web.de',
  't-online.de', 'ziggo.nl', 'kpnmail.nl', 'xs4all.nl', 'telenet.be', 'skynet.be', 'zoho.com',
];

const isoDatum = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));

function alleGeblokkeerd() {
  const uit = [];
  for (const [cat, c] of Object.entries(lijst.categorieen)) {
    for (const d of c.domeinen || []) uit.push([d, cat]);
    for (const h of c.handmatig || []) uit.push([h.domein, cat]);
  }
  return uit;
}

test('het bestand is heel: bron, licentie en datum per bron, reden per regel', () => {
  const fout = [];
  assert.ok(Array.isArray(lijst._) && /NOOIT voor ontvangers/.test(lijst._.join(' ')),
    'de uitleg bovenaan moet zeggen dat ontvangers nooit getoetst worden');
  assert.ok(isoDatum(lijst.gewijzigd), 'gewijzigd moet een datum zijn');
  for (const cat of ['wegwerp', 'misbruik']) assert.ok(lijst.categorieen[cat], `categorie ${cat} ontbreekt`);
  for (const [cat, c] of Object.entries(lijst.categorieen)) {
    const w = (m) => fout.push(`${cat}: ${m}`);
    if (!c.omschrijving) w('omschrijving ontbreekt');
    if (!Array.isArray(c.bronnen) || !Array.isArray(c.handmatig) || !Array.isArray(c.domeinen)) w('bronnen, handmatig en domeinen moeten lijsten zijn');
    for (const b of c.bronnen || []) {
      for (const k of ['naam', 'url', 'licentie', 'licentie_bron']) if (!b[k]) w(`bron ${b.naam}: ${k} ontbreekt`);
      if (!/^https:\/\//.test(b.url || '')) w(`bron ${b.naam}: url moet https zijn`);
      if (!isoDatum(b.bijgewerkt_op)) w(`bron ${b.naam}: bijgewerkt_op is geen datum`);
      if (!(b.aantal > 0)) w(`bron ${b.naam}: aantal ontbreekt`);
    }
    if ((c.domeinen || []).length && !(c.bronnen || []).length) w('domeinen zonder bron; alleen handmatig mag zonder, met een bron per regel');
    if (!(c.bronnen || []).length && !(c.overwogen || c.handmatig.length || c.tlds)) w('geen bron en niet gezegd wat er overwogen is');
    for (const o of c.overwogen || []) if (!o.naam || !o.url || !o.waarom_niet) w(`overwogen ${o.naam}: naam, url en waarom_niet`);
    for (const h of c.handmatig || []) {
      if (!h.domein || !h.reden || !h.bron || !isoDatum(h.datum)) w(`handmatig ${h.domein}: domein, reden, datum en bron`);
    }
    for (const t of c.tlds || []) if (!t.tld || !t.bron) w(`tld ${t.tld}: bron ontbreekt`);
    const d = c.domeinen || [];
    if (d.some((x, i) => i && d[i - 1] >= x)) w('domeinen zijn niet gesorteerd of niet uniek');
    for (const x of d) if (normaliseer(x) !== x) w(`${x} is niet genormaliseerd (kleine letters, punycode)`);
  }
  for (const u of lijst.uitzonderingen) if (!u.domein || !u.reden) fout.push(`uitzondering ${u.domein} zonder reden`);
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
  assert.ok(lijst.categorieen.wegwerp.domeinen.length > 1000, 'de wegwerplijst is bijna leeg; de bron is waarschijnlijk kapot');
  for (const d of ['mailinator.com', 'yopmail.com', 'guerrillamail.com']) {
    assert.ok(lijst.categorieen.wegwerp.domeinen.includes(d), `${d} staat niet meer op de wegwerplijst`);
  }
});

test('de uitzonderingen: geen privacyvriendelijke of grote aanbieder op een lijst', () => {
  const uitz = lijst.uitzonderingen.map((u) => u.domein);
  const mist = NOOIT.filter((d) => !uitz.includes(d));
  assert.deepEqual(mist, [], `deze aanbieders ontbreken onder uitzonderingen: ${mist.join(', ')}`);
  const botsing = alleGeblokkeerd()
    .map(([d, cat]) => [d, cat, raaktUitzondering(d, NOOIT) || raaktUitzondering(d, uitz)])
    .filter(([, , u]) => u)
    .map(([d, cat, u]) => `${d} (${cat}) raakt ${u}`);
  assert.deepEqual(botsing, [], `\n  een aanbieder die mensen blijvend lezen staat op de lijst:\n  ${botsing.join('\n  ')}\n`);
});

test('het script haalt een aanbieder uit een bron en meldt het', () => {
  const data = structuredClone(lijst);
  const vals = ['mailinator.com', 'Proton.me', 'sub.tuta.com', 'me', 'Wegwerp-Voorbeeld.NL.', '# commentaar',
    ...Array.from({ length: 150 }, (_, i) => `wegwerp-${i}.example-bron.nl`)].join('\n');
  const verslag = pasToe(data, { 'disposable-email-domains': { tekst: vals, commit: 'abc' } }, '2026-09-23');
  const d = data.categorieen.wegwerp.domeinen;
  assert.ok(d.includes('mailinator.com') && d.includes('wegwerp-voorbeeld.nl'));
  for (const x of ['proton.me', 'sub.tuta.com']) assert.ok(!d.includes(x), `${x} kwam door de uitzonderingen heen`);
  assert.ok(!d.includes('me'), 'een losse tld hoort nooit op de lijst');
  const v = verslag.find((r) => r.categorie === 'wegwerp');
  assert.equal(v.tegengehouden.length, 2, v.tegengehouden.join(', '));
  assert.ok(v.eraf.length > 1000, 'het verslag laat niet zien wat eraf gaat');
  assert.equal(data.categorieen.wegwerp.bronnen[0].commit, 'abc');
  assert.equal(data.categorieen.wegwerp.bronnen[0].bijgewerkt_op, '2026-09-23');
  // Handmatige regels en uitzonderingen blijven staan.
  assert.deepEqual(data.categorieen.wegwerp.handmatig, lijst.categorieen.wegwerp.handmatig);
  assert.deepEqual(data.uitzonderingen, lijst.uitzonderingen);
});

test('een kapotte bron schrijft niets', () => {
  const data = structuredClone(lijst);
  assert.throws(() => pasToe(data, { 'disposable-email-domains': { tekst: '<html>404</html>' } }), /kapot/);
  assert.deepEqual(data.categorieen.wegwerp.domeinen, lijst.categorieen.wegwerp.domeinen);
  assert.deepEqual(parseLijst('a.nl\nA.NL\n\nb.nl # x\n'), ['a.nl', 'b.nl']);
});

test('elke externe bron staat in deploy/partners.json als actieve blocklist-bron', () => {
  assert.ok(partners.rollen['blocklist-bron'], 'de rol blocklist-bron ontbreekt in partners.json');
  const fout = [];
  for (const c of Object.values(lijst.categorieen)) {
    for (const b of c.bronnen || []) {
      const host = new URL(b.url).hostname;
      const p = partners.partijen.find((x) => x.rol === 'blocklist-bron' && (x.hosts || []).includes(host));
      if (!p) { fout.push(`${b.naam}: geen blocklist-bron in partners.json met host ${host}`); continue; }
      if (p.status !== 'actief') fout.push(`${b.naam}: ${p.id} staat op ${p.status}`);
      if (!/^geen\b/i.test(p.gegevens.nl)) fout.push(`${p.id}: een blocklist-bron krijgt geen gegevens; gegevens.nl moet met "Geen" beginnen`);
      if (!(p.code || []).includes('scripts/update-email-blocklist.mjs')) fout.push(`${p.id}: code noemt het updatescript niet`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

// De wekelijkse workflow draait alleen op een schema. Stopt hij, dan merkt
// niemand dat, behalve deze toets: na 30 dagen zonder verversing gaat elke
// pull request rood (scripts/check-guards.mjs verwijst hiernaar).
test('elke bron is in de laatste 30 dagen ververst', () => {
  const grens = Date.now() - 30 * 86400000;
  for (const c of Object.values(lijst.categorieen)) {
    for (const b of c.bronnen || []) {
      assert.ok(Date.parse(b.bijgewerkt_op) >= grens,
        `${b.naam} is sinds ${b.bijgewerkt_op} niet ververst; draai de workflow email-blocklist of node scripts/update-email-blocklist.mjs --write`);
    }
  }
});

test('de wekelijkse update opent een pull request en merget niet', () => {
  const wf = fs.readFileSync(path.join(ROOT, '.github/workflows/email-blocklist.yml'), 'utf8');
  assert.match(wf, /schedule:/);
  assert.match(wf, /scripts\/update-email-blocklist\.mjs --write/);
  assert.match(wf, /gh pr create/);
  assert.ok(!/gh pr merge|--auto\b|automerge|auto-merge/i.test(wf), 'de workflow mag niet zelf mergen');
  assert.match(wf, /node --test tests\/email-blocklist\.test\.mjs/, 'de workflow draait deze toets voor de pull request');
});
