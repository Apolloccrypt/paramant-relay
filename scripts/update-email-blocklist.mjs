#!/usr/bin/env node
// Werkt deploy/email-blocklist.json bij vanuit de bronnen die erin staan.
//
// Per categorie met bronnen: haal elke bron op, normaliseer (kleine letters,
// punycode), haal alles eruit wat onder een uitzondering valt, en laat zien
// wat erbij komt en wat eraf gaat. Handmatige regels en uitzonderingen raakt
// het script niet aan.
//
//   node scripts/update-email-blocklist.mjs            laat de diff zien, schrijft niets
//   node scripts/update-email-blocklist.mjs --write    schrijft het bestand
//   node scripts/update-email-blocklist.mjs --check    exit 1 als het bestand achterloopt
//   --bron <naam>=<bestand>                            lees een bron van schijf (tests, offline)
//
// De wekelijkse workflow (.github/workflows/email-blocklist.yml) draait
// --write en opent een pull request. Nooit automatisch mergen: een mens kijkt
// naar wat er bij komt.
import fs from 'node:fs';
import path from 'node:path';
import { domainToASCII } from 'node:url';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const STANDAARD = path.join(ROOT, 'deploy/email-blocklist.json');

export function normaliseer(regel) {
  const d = String(regel).replace(/#.*/, '').trim().toLowerCase().replace(/\.+$/, '');
  if (!d || /\s/.test(d) || !d.includes('.')) return '';
  return domainToASCII(d) || '';
}

export function parseLijst(tekst) {
  return [...new Set(tekst.split('\n').map(normaliseer).filter(Boolean))].sort();
}

// Een domein valt onder een uitzondering als het de uitzondering is, er een
// subdomein van is, of er een bovenliggend domein van is (een lijst met "me"
// zou pm.me en proton.me meenemen).
export function raaktUitzondering(domein, uitzonderingen) {
  return uitzonderingen.find((u) => domein === u || domein.endsWith('.' + u) || u.endsWith('.' + domein)) || null;
}

export function pasToe(data, opgehaald, vandaag = new Date().toISOString().slice(0, 10)) {
  const uitz = (data.uitzonderingen || []).map((u) => normaliseer(u.domein)).filter(Boolean);
  const verslag = [];
  for (const [categorie, c] of Object.entries(data.categorieen)) {
    if (!c.bronnen || !c.bronnen.length) continue;
    const nieuw = new Set();
    const tegengehouden = [];
    for (const bron of c.bronnen) {
      const o = opgehaald[bron.naam];
      if (!o) throw new Error(`bron ${bron.naam} niet opgehaald`);
      const lijst = parseLijst(o.tekst);
      if (lijst.length < 100) throw new Error(`bron ${bron.naam} gaf maar ${lijst.length} domeinen; waarschijnlijk kapot, niets geschreven`);
      for (const d of lijst) {
        const u = raaktUitzondering(d, uitz);
        if (u) tegengehouden.push(`${d} (uitzondering ${u})`);
        else nieuw.add(d);
      }
      bron.aantal = lijst.length;
      bron.bijgewerkt_op = vandaag;
      if (o.commit) bron.commit = o.commit;
    }
    const oud = new Set(c.domeinen || []);
    const lijst = [...nieuw].sort();
    verslag.push({
      categorie,
      erbij: lijst.filter((d) => !oud.has(d)),
      eraf: [...oud].filter((d) => !nieuw.has(d)).sort(),
      tegengehouden,
      totaal: lijst.length,
    });
    c.domeinen = lijst;
  }
  return verslag;
}

async function haalOp(bron) {
  const r = await fetch(bron.url, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`${bron.naam}: HTTP ${r.status} op ${bron.url}`);
  const tekst = await r.text();
  let commit = null;
  const m = /github\.com\/([^/]+\/[^/]+)$/.exec(bron.project || '');
  if (m) {
    try {
      const c = await fetch(`https://api.github.com/repos/${m[1]}/commits?per_page=1`, { signal: AbortSignal.timeout(15000) });
      if (c.ok) commit = (await c.json())[0]?.sha?.slice(0, 12) || null;
    } catch { /* de commit is een extraatje; de lijst zelf telt */ }
  }
  return { tekst, commit };
}

function toon(verslag) {
  for (const v of verslag) {
    console.log(`${v.categorie}: ${v.totaal} domeinen, +${v.erbij.length} -${v.eraf.length}`);
    for (const d of v.erbij.slice(0, 50)) console.log(`  + ${d}`);
    if (v.erbij.length > 50) console.log(`  + ... en ${v.erbij.length - 50} meer`);
    for (const d of v.eraf.slice(0, 50)) console.log(`  - ${d}`);
    if (v.eraf.length > 50) console.log(`  - ... en ${v.eraf.length - 50} meer`);
    for (const t of v.tegengehouden) console.log(`  ! tegengehouden door de uitzonderingen: ${t}`);
  }
}

async function main(argv) {
  const schrijf = argv.includes('--write');
  const check = argv.includes('--check');
  const bestandArg = argv.indexOf('--bestand');
  const bestand = bestandArg >= 0 ? argv[bestandArg + 1] : STANDAARD;
  const vanSchijf = {};
  argv.forEach((a, i) => {
    if (a === '--bron') {
      const [naam, f] = argv[i + 1].split('=');
      vanSchijf[naam] = f;
    }
  });
  const ruw = fs.readFileSync(bestand, 'utf8');
  const data = JSON.parse(ruw);
  const opgehaald = {};
  for (const c of Object.values(data.categorieen)) {
    for (const bron of c.bronnen || []) {
      opgehaald[bron.naam] = vanSchijf[bron.naam]
        ? { tekst: fs.readFileSync(vanSchijf[bron.naam], 'utf8'), commit: null }
        : await haalOp(bron);
    }
  }
  const verslag = pasToe(data, opgehaald);
  toon(verslag);
  const veranderd = verslag.some((v) => v.erbij.length || v.eraf.length);
  if (veranderd) data.gewijzigd = new Date().toISOString().slice(0, 10);
  const uit = JSON.stringify(data, null, 2) + '\n';
  if (check) {
    if (veranderd) { console.error('deploy/email-blocklist.json loopt achter op de bron'); process.exit(1); }
    return;
  }
  if (schrijf && uit !== ruw) {
    fs.writeFileSync(bestand, uit);
    console.log(`geschreven: ${path.relative(ROOT, bestand) || bestand}`);
  } else if (!schrijf) {
    console.log('niets geschreven (gebruik --write)');
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exit(1); });
}
