// Elke externe partij, gelegd naast de site, de code en productie.
//
// Op 22 september 2026 kwam op elke pagina te staan dat mail via Mailjet in
// Parijs liep. Mailjet was nooit aangezet: geen account, geen sleutels in de
// prod-.env, en de relay viel terug op Resend in de VS. De code kende Mailjet,
// dus de site klonk geloofwaardig, en niets legde de tekst naast wat er echt
// draaide. PR #500 zette daar deploy/mail-provider.json tegenover, voor mail
// alleen. Dit bestand doet hetzelfde voor elke partij: hosting, DNS, mail,
// betaling, boekhouding, code-hosting en de rest.
//
// deploy/partners.json is de enige bron. Deze toets eist:
//   1. het bestand is heel: elke claim heeft een bron, een onbekend
//      moederbedrijf staat er als "onbekend", een dode sleutel heeft een
//      opruimdatum;
//   2. de code: de mail-, QES- en boekhoudkeuze die de code maakt met de
//      sleutels van productie (en de standaarden uit docker-compose.yml) valt
//      op een actieve partij; elke drager die de code kent staat in het
//      bestand; elke externe host in de code hoort bij een partij of staat
//      met reden onder niet_opgenomen;
//   3. de site: /privacy en /dpa (NL en EN) noemen elke actieve subverwerker,
//      met de naam en het land uit het bestand; geen pagina noemt een
//      niet-actieve partij als huidige partij; de blokken met
//      data-partners-rollen (home, /security) noemen alleen actieve partijen,
//      in hun rol; elke pagina die een partij noemt linkt naar /partners;
//   4. /partners leest het bestand zelf (frontend/partners.json is er een
//      kopie van, byte voor byte);
//   5. productie, alleen als PARTNERS_PROD_SSH of PARTNERS_PROD_NAMEN gezet
//      is: de sleutels van elke actieve partij staan in de prod-.env, die van
//      een niet-actieve niet, tenzij als dode rest met een opruimdatum die nog
//      niet voorbij is. Zonder die variabele wordt dit deel overgeslagen, met
//      een melding: dat is geen groen.
//
// Een niet-actieve naam mag op de site alleen binnen een element met
// data-partner-context="<id> <reden>" staan (voorwaardelijk, historie,
// gepland, geen-partij). Zo'n element moet de naam dan ook echt bevatten, zodat
// een vergeten markering opvalt.
//
// Run: node --test tests/partners.test.mjs
// Live: PARTNERS_PROD_SSH=root@116.203.86.81 PARTNERS_PROD_SSH_KEY=~/.ssh/... node --test tests/partners.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const BRON = path.join(ROOT, 'deploy/partners.json');
const partners = JSON.parse(fs.readFileSync(BRON, 'utf8'));
const mail = require(path.join(ROOT, 'relay/lib/mail.js'));
const qes = require(path.join(ROOT, 'relay/lib/qes/index.js'));
const moneybird = require(path.join(ROOT, 'relay/lib/moneybird.js'));

const STATUSSEN = ['actief', 'in-code-niet-actief', 'uitgefaseerd'];
const REDENEN = ['voorwaardelijk', 'historie', 'gepland', 'geen-partij'];
const actief = partners.partijen.filter((p) => p.status === 'actief');
const nietActief = partners.partijen.filter((p) => p.status !== 'actief');
const perId = new Map(partners.partijen.map((p) => [p.id, p]));

function namen(p) {
  return (p.site_namen || []).map((s) => new RegExp(s));
}

function leesPagina(rel) {
  return fs.readFileSync(path.join(ROOT, 'frontend', rel), 'utf8');
}

function paginas(dir = path.join(ROOT, 'frontend'), pre = '') {
  const uit = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) uit.push(...paginas(path.join(dir, e.name), pre + e.name + '/'));
    else if (e.name.endsWith('.html')) uit.push(pre + e.name);
  }
  return uit.sort();
}

function zonderContext(html, id) {
  if (!id) return html;
  const re = new RegExp(`<(\\w+)\\b[^>]*\\bdata-partner-context="${id} [a-z-]+"[^>]*>[\\s\\S]*?<\\/\\1>`, 'g');
  return html.replace(re, ' ');
}

function tekst(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&euml;/g, 'ë')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ');
}

function zichtbaar(html, id) {
  return tekst(zonderContext(html, id));
}

function isoDatum(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
}

// --- 1. het bestand ------------------------------------------------------

test('deploy/partners.json is heel: elke partij met bron, status en sleutels', () => {
  assert.ok(Array.isArray(partners._) && partners._.join(' ').includes('Omschakelen'),
    'de "_"-uitleg bovenaan moet zeggen hoe omschakelen gaat');
  assert.ok(isoDatum(partners.gewijzigd), 'gewijzigd moet een datum zijn (JJJJ-MM-DD)');
  const ids = new Set();
  const fout = [];
  for (const p of partners.partijen) {
    const w = (m) => fout.push(`${p.id}: ${m}`);
    if (ids.has(p.id)) w('id staat er twee keer');
    ids.add(p.id);
    if (!STATUSSEN.includes(p.status)) w(`onbekende status ${p.status}`);
    if (!partners.rollen[p.rol]) w(`rol ${p.rol} staat niet onder rollen`);
    if (!p.handelsnaam) w('handelsnaam ontbreekt');
    if (!('naam' in p)) w('naam (juridisch) ontbreekt; null mag, met bron "onbekend"');
    if (!p.land || !p.land.nl || !p.land.en) w('land nl/en ontbreekt');
    if (typeof p.subverwerker !== 'boolean') w('subverwerker moet true of false zijn');
    for (const taal of ['nl', 'en']) {
      if (!p.gegevens?.[taal]) w(`gegevens.${taal} ontbreekt`);
      if (!p.nooit?.[taal]) w(`nooit.${taal} ontbreekt`);
    }
    for (const k of ['naam', 'land', 'moederbedrijf', 'status', 'sinds', 'dpa_url']) {
      if (typeof p.bronnen?.[k] !== 'string' || !p.bronnen[k].trim()) w(`bronnen.${k} ontbreekt`);
    }
    if (p.moederbedrijf === null && p.bronnen?.moederbedrijf !== 'onbekend') w('moederbedrijf null zonder bronnen.moederbedrijf "onbekend"');
    if (p.moederbedrijf && !p.moederbedrijf_land) w('moederbedrijf zonder land');
    if (p.naam === null && !/onbekend/.test(p.bronnen?.naam || '')) w('naam null zonder "onbekend" in bronnen.naam');
    if (p.dpa_url !== null && !/^https:\/\//.test(p.dpa_url)) w('dpa_url moet https zijn of null');
    if (p.sinds !== null && !isoDatum(p.sinds)) w('sinds moet een datum zijn of null');
    if (!('tot' in p) || (p.tot !== null && !isoDatum(p.tot))) w('tot moet bestaan: een datum of null');
    if (p.status === 'actief' && p.tot) w('actief met een einddatum');
    if (!Array.isArray(p.sleutels) || !Array.isArray(p.dode_resten)) w('sleutels en dode_resten moeten lijsten zijn');
    if (p.status === 'actief' && p.dode_resten.length) w('een actieve partij heeft geen dode resten');
    for (const d of p.dode_resten || []) {
      if (!p.sleutels.includes(d.sleutel)) w(`dode rest ${d.sleutel} staat niet onder sleutels`);
      if (!isoDatum(d.opruimen_voor)) w(`dode rest ${d.sleutel} zonder opruimdatum`);
    }
    for (const s of p.site_namen || []) {
      try { new RegExp(s); } catch { w(`site_naam ${s} is geen regex`); }
    }
  }
  for (const o of partners.overwogen || []) {
    if (ids.has(o.id)) fout.push(`${o.id} staat onder partijen en onder overwogen`);
    if (!o.bron) fout.push(`overwogen ${o.id} zonder bron`);
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
  assert.ok(actief.length >= 3, 'minder dan drie actieve partijen: de lijst is waarschijnlijk leeggeraakt');
});

test('één bron: frontend/partners.json is deploy/partners.json, en mail-provider.json bestaat niet meer', () => {
  const kopie = fs.readFileSync(path.join(ROOT, 'frontend/partners.json'), 'utf8');
  assert.equal(kopie, fs.readFileSync(BRON, 'utf8'),
    'frontend/partners.json wijkt af van deploy/partners.json; draai: cp deploy/partners.json frontend/partners.json');
  assert.ok(!fs.existsSync(path.join(ROOT, 'deploy/mail-provider.json')),
    'deploy/mail-provider.json is opgegaan in deploy/partners.json; twee bronnen lopen uit elkaar');
});

// --- 2. de code ----------------------------------------------------------

// De omgeving waarmee productie draait: de standaarden uit docker-compose.yml
// (wat een container krijgt als .env niets zegt) plus de sleutels van elke
// actieve partij. Waarden zijn nep; het gaat om welke namen er zijn.
function prodOmgeving() {
  const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
  const sleutels = new Set(actief.flatMap((p) => p.sleutels));
  const env = {};
  for (const k of ['MAIL_PROVIDER', 'MAIL_FALLBACK_PROVIDER', 'PARASIGN_QES_PROVIDER']) {
    const standaarden = [...compose.matchAll(new RegExp(`^\\s*${k}:\\s*"\\$\\{${k}:-([^}]*)\\}"`, 'gm'))].map((m) => m[1]);
    assert.ok(new Set(standaarden).size <= 1, `docker-compose.yml geeft ${k} verschillende standaarden: ${standaarden.join(', ')}`);
    if (!sleutels.has(k) && standaarden[0]) env[k] = standaarden[0];
  }
  for (const k of sleutels) env[k] = '123';
  return env;
}

test('elke drager die de code kent staat in partners.json', () => {
  const fout = [];
  const kent = (module, naam) => partners.partijen.some((p) =>
    p.code_keuze && p.code_keuze.module === module && naam.startsWith(p.code_keuze.naam_in_code));
  for (const n of mail.PROVIDERS.filter((n) => n !== 'dryrun')) {
    if (!kent('relay/lib/mail.js', n)) fout.push(`relay/lib/mail.js kent ${n}; partners.json niet`);
  }
  const qesProviders = ['cleverbase-sandbox', 'cleverbase'].filter((n) => qes.provider({ PARASIGN_QES_PROVIDER: n }) === n);
  assert.ok(qesProviders.length, 'relay/lib/qes kent geen enkele provider meer; pas deze toets aan');
  for (const n of qesProviders) {
    if (!kent('relay/lib/qes/index.js', n)) fout.push(`relay/lib/qes kent ${n}; partners.json niet`);
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

test('met de omgeving van productie kiest de code alleen actieve partijen', () => {
  const env = prodOmgeving();
  const partijVoor = (module, naam) => partners.partijen.find((p) =>
    p.code_keuze && p.code_keuze.module === module && naam.startsWith(p.code_keuze.naam_in_code));
  const cfg = mail.config(env);
  const drager = partijVoor('relay/lib/mail.js', cfg.provider);
  assert.ok(drager && drager.status === 'actief',
    `met de prod-sleutels en de standaarden uit docker-compose.yml mailt de code via ${cfg.provider}, `
    + `en dat is ${drager ? drager.status : 'geen partij in partners.json'}`);
  if (cfg.fallback) {
    const terug = partijVoor('relay/lib/mail.js', cfg.fallback);
    assert.ok(terug && terug.status === 'actief',
      `de terugvaldrager is ${cfg.fallback}, en dat is ${terug ? terug.status : 'geen partij'}`);
  }
  // Zonder MAIL_PROVIDER, zoals de oude toets het eiste: alleen de sleutels.
  const kaal = { ...env };
  delete kaal.MAIL_PROVIDER;
  delete kaal.MAIL_FALLBACK_PROVIDER;
  const zelf = partijVoor('relay/lib/mail.js', mail.config(kaal).provider);
  assert.ok(zelf && zelf.status === 'actief', `met alleen de prod-sleutels kiest de code ${mail.config(kaal).provider}`);

  const q = qes.provider(env);
  if (q) {
    const p = partijVoor('relay/lib/qes/index.js', q);
    assert.ok(p && p.status === 'actief', `QES staat met de prod-omgeving aan op ${q}, en die partij is niet actief`);
  }
  const mb = perId.get('moneybird');
  assert.equal(moneybird.configured(moneybird.configFromEnv(env)), mb?.status === 'actief',
    'relay/lib/moneybird.js staat met de prod-sleutels ' + (moneybird.configured(moneybird.configFromEnv(env)) ? 'aan' : 'uit')
    + `, en partners.json zegt ${mb?.status}`);
});

test('de sleutels van een partij bestaan in de code, en een actieve komt de container in', () => {
  const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
  const fout = [];
  for (const p of partners.partijen) {
    if (p.status === 'uitgefaseerd') continue;
    const bronnen = (p.code || []).map((f) => {
      const vol = path.join(ROOT, f);
      assert.ok(fs.existsSync(vol), `${p.id}: code-bestand ${f} bestaat niet`);
      return fs.readFileSync(vol, 'utf8');
    }).join('\n');
    for (const k of p.sleutels) {
      if (!bronnen.includes(k)) fout.push(`${p.id}: ${k} staat in geen van ${p.code.join(', ') || '(geen code)'}`);
      if (p.status === 'actief' && !new RegExp(`^\\s*${k}:`, 'm').test(compose)) {
        fout.push(`${p.id}: ${k} komt niet door docker-compose.yml naar de container`);
      }
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

function externeHosts() {
  const lijst = execFileSync('git', ['ls-files', 'relay', 'admin', 'deploy', 'scripts', 'docker-compose.yml'],
    { cwd: ROOT, encoding: 'utf8' }).split('\n').filter((f) =>
    /\.(js|mjs|cjs|py|sh)$/.test(f) && !/(^|\/)(test|tests|node_modules|vendor)\//.test(f) && !/\.test\./.test(f));
  const hosts = new Map();
  for (const f of lijst) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    for (const m of src.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) hosts.set(m[1].toLowerCase(), f);
    for (const m of src.matchAll(/^const [A-Z_]*HOST\s*=\s*['"`]([^'"`]+)/gm)) hosts.set(m[1].toLowerCase(), f);
  }
  const intern = (h) => /(^|\.)paramant\.app$/.test(h) || /(^|\.)(example|test|local|invalid)$/.test(h)
    || /(^|\.)example\.(com|org|net)$/.test(h) || /yourdomain|localhost/.test(h) || /^\d+\.\d+\.\d+\.\d+$/.test(h);
  return [...hosts].filter(([h]) => !intern(h));
}

test('elke externe host in de code hoort bij een partij of staat met reden onder niet_opgenomen', () => {
  const bekend = new Set([
    ...partners.partijen.flatMap((p) => p.hosts || []),
    ...(partners.niet_opgenomen || []).flatMap((n) => n.hosts || []),
  ]);
  const hosts = externeHosts();
  assert.ok(hosts.length >= 5, `maar ${hosts.length} externe hosts gevonden; de veeg ziet de aanroepen niet meer`);
  const onbekend = hosts.filter(([h]) => !bekend.has(h)).map(([h, f]) => `${h} (in ${f})`);
  assert.deepEqual(onbekend, [],
    `\n  een externe partij in de code die niet in deploy/partners.json staat:\n  ${onbekend.join('\n  ')}\n`);
  for (const n of partners.niet_opgenomen || []) assert.ok(n.reden && n.reden.length > 20, 'niet_opgenomen zonder reden');
});

// --- 3. de site ----------------------------------------------------------

function vindPartij(naamTekst) {
  return partners.partijen.find((p) => naamTekst.includes(p.handelsnaam) || (p.naam && naamTekst.includes(p.naam)));
}

function isVoorwaardelijk(openTag, inhoud, p) {
  return new RegExp(`data-partner-context="${p.id} voorwaardelijk"`).test(openTag)
    && /alleen als|only when|only where/i.test(tekst(inhoud));
}

for (const [taal, pre, kop, link] of [
  ['nl', '', '<h2>Subverwerkers</h2>', '/partners'],
  ['en', 'en/', '<h2>Subprocessors</h2>', '/en/partners'],
]) {
  test(`/${pre}privacy: de subverwerkerslijst klopt met partners.json (${taal})`, () => {
    const html = leesPagina(`${pre}privacy.html`);
    const at = html.indexOf(kop);
    assert.ok(at > 0, `${pre}privacy.html heeft geen ${kop} meer`);
    const sectie = html.slice(at, html.indexOf('<h2', at + kop.length));
    const fout = [];
    const gezien = new Set();
    for (const m of sectie.matchAll(/(<li\b[^>]*>)([\s\S]*?)<\/li>/g)) {
      const naam = (/<strong>([^<]+)<\/strong>/.exec(m[2]) || [])[1] || '';
      const p = vindPartij(naam);
      if (!p) { fout.push(`"${naam}" staat in de lijst en niet in partners.json`); continue; }
      gezien.add(p.id);
      const t = tekst(m[2]);
      if (!naam.includes(p.handelsnaam)) fout.push(`${p.id}: de lijst schrijft "${naam}", partners.json "${p.handelsnaam}"`);
      if (!t.includes(p.land[taal]) && !t.includes(p.land.nl) && !(p.land.code && t.includes(`(${p.land.code}`))) {
        fout.push(`${p.id}: het land "${p.land[taal]}" staat niet in de regel`);
      }
      if (p.status !== 'actief' && !isVoorwaardelijk(m[1], m[2], p)) {
        fout.push(`${p.id} is ${p.status}, en de lijst noemt hem zonder data-partner-context="${p.id} voorwaardelijk" en "alleen als"/"only when"`);
      }
    }
    for (const p of actief.filter((x) => x.subverwerker)) {
      if (!gezien.has(p.id)) fout.push(`${p.handelsnaam} is een actieve subverwerker en staat niet in de lijst`);
    }
    if (!sectie.includes(`href="${link}"`)) fout.push(`de sectie linkt niet naar ${link}`);
    assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
  });

  test(`/${pre}dpa: de tabel in artikel 5 klopt met partners.json (${taal})`, () => {
    const html = leesPagina(`${pre}dpa.html`);
    const at = html.indexOf('id="subprocessors"');
    assert.ok(at > 0, `${pre}dpa.html heeft geen id="subprocessors" meer`);
    const eind = html.indexOf('<h2', at + 10);
    const sectie = html.slice(at, eind);
    const tabel = sectie.slice(sectie.indexOf('<tbody>'), sectie.indexOf('</tbody>'));
    const fout = [];
    const gezien = new Set();
    for (const m of tabel.matchAll(/(<tr\b[^>]*>)([\s\S]*?)<\/tr>/g)) {
      const cellen = [...m[2].matchAll(/<td>([\s\S]*?)<\/td>/g)].map((c) => tekst(c[1]).trim());
      const p = vindPartij(cellen[0] || '');
      if (!p) { fout.push(`rij "${cellen[0]}" staat niet in partners.json`); continue; }
      gezien.add(p.id);
      if (!p.subverwerker) fout.push(`${p.id} staat in de DPA maar is in partners.json geen subverwerker`);
      if (!p.naam || !cellen[0].includes(p.naam)) fout.push(`${p.id}: de DPA schrijft "${cellen[0]}", de juridische naam is "${p.naam}"`);
      if (!cellen[0].includes(p.handelsnaam.replace(/\.net$/, ''))) fout.push(`${p.id}: de handelsnaam ${p.handelsnaam} staat niet in de rij`);
      const plek = cellen[1] || '';
      if (![p.land[taal], p.land.code].filter(Boolean).some((l) => plek.startsWith(l))) {
        fout.push(`${p.id}: de DPA zegt "${plek}", partners.json "${p.land[taal]}"`);
      }
      if (p.status !== 'actief' && !isVoorwaardelijk(m[1], m[2], p)) {
        fout.push(`${p.id} is ${p.status}, en de DPA noemt hem zonder voorwaarde en markering`);
      }
    }
    for (const p of actief.filter((x) => x.subverwerker)) {
      if (!gezien.has(p.id)) fout.push(`${p.naam} is een actieve subverwerker en staat niet in artikel 5`);
    }
    if (!sectie.includes(`href="${link}"`)) fout.push(`artikel 5 linkt niet naar ${link}`);
    assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
  });
}

test('geen pagina noemt een niet-actieve of overwogen partij als huidige partij (NL en EN)', () => {
  const lijst = paginas();
  assert.ok(lijst.includes('index.html') && lijst.includes('en/index.html') && lijst.length > 60,
    'de veeg vindt de pagina\'s niet meer');
  const verboden = [
    ...nietActief.map((p) => ({ id: p.id, naam: p.handelsnaam, res: namen(p), waarom: p.status })),
    ...(partners.overwogen || []).map((o) => ({ id: o.id, naam: o.naam, res: o.site_namen.map((s) => new RegExp(s)), waarom: 'nooit gebruikt' })),
  ];
  const fout = [];
  for (const rel of lijst) {
    const html = leesPagina(rel);
    for (const v of verboden) {
      const t = zichtbaar(html, v.id);
      for (const re of v.res) {
        const m = re.exec(t);
        if (m) fout.push(`${rel}: noemt ${m[0]} (${v.waarom}); markeer het element met data-partner-context="${v.id} <reden>" als het over vroeger, later of een voorwaarde gaat`);
      }
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

test('elke data-partner-context is geldig en bevat de naam die hij uitzondert', () => {
  const fout = [];
  const alle = new Map([...perId, ...(partners.overwogen || []).map((o) => [o.id, { ...o, handelsnaam: o.naam }])]);
  for (const rel of paginas()) {
    const html = leesPagina(rel);
    for (const m of html.matchAll(/<(\w+)\b[^>]*\bdata-partner-context="([^"]*)"[^>]*>([\s\S]*?)<\/\1>/g)) {
      const [id, reden] = m[2].split(' ');
      const p = alle.get(id);
      if (!p) { fout.push(`${rel}: data-partner-context noemt onbekende partij "${id}"`); continue; }
      if (!REDENEN.includes(reden)) fout.push(`${rel}: data-partner-context="${m[2]}": reden moet een van ${REDENEN.join(', ')} zijn`);
      if (p.status === 'actief') fout.push(`${rel}: ${id} is actief en heeft geen uitzondering nodig`);
      const res = p.site_namen.map((s) => new RegExp(s));
      if (!res.some((re) => re.test(tekst(m[3])))) fout.push(`${rel}: data-partner-context="${m[2]}" staat op een element zonder de naam; weghalen`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

test('de weg van uw bestanden (home) en de kaart en tabel op /security noemen alleen actieve partijen, in hun rol', () => {
  const eis = { 'index.html': 1, 'en/index.html': 1, 'security.html': 2, 'en/security.html': 2 };
  const fout = [];
  for (const [rel, minstens] of Object.entries(eis)) {
    const html = leesPagina(rel);
    const blokken = [...html.matchAll(/<(\w+)\b[^>]*\bdata-partners-rollen\b[^>]*>([\s\S]*?)<\/\1>/g)];
    if (blokken.length < minstens) { fout.push(`${rel}: ${blokken.length} blok(ken) met data-partners-rollen, verwacht ${minstens}`); continue; }
    const link = rel.startsWith('en/') ? '/en/partners' : '/partners';
    for (const b of blokken) {
      if (!b[2].includes(`href="${link}"`)) fout.push(`${rel}: een blok met data-partners-rollen linkt niet naar ${link}`);
      const zinnen = tekst(b[2]).split(/(?<=[.;])\s+/);
      let genoemd = 0;
      for (const p of partners.partijen) {
        for (const z of zinnen) {
          if (!namen(p).some((re) => re.test(z))) continue;
          genoemd += 1;
          if (p.status !== 'actief') fout.push(`${rel}: "${z.trim()}" noemt ${p.handelsnaam}, en die is ${p.status}`);
          const woorden = partners.rollen[p.rol].woorden;
          if (!woorden.some((w) => z.toLowerCase().includes(w.toLowerCase()))) {
            fout.push(`${rel}: "${z.trim()}" noemt ${p.handelsnaam} zonder zijn rol (${partners.rollen[p.rol].nl}: ${woorden.join('/')})`);
          }
        }
      }
      if (!genoemd) fout.push(`${rel}: een blok met data-partners-rollen noemt geen enkele partij meer`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

test('elke pagina die een partij noemt linkt naar /partners, en de vaste plekken ook buiten de voet', () => {
  const fout = [];
  for (const rel of paginas()) {
    if (/^(en\/)?partners\.html$/.test(rel)) continue;
    // De installatiewizard voor wie zelf host: Let's Encrypt is daar de
    // leverancier van de installateur zelf, niet een partij van Paramant.
    if (/^(en\/)?setup\.html$/.test(rel)) continue;
    const html = leesPagina(rel);
    const t = zichtbaar(html);
    const noemt = partners.partijen.find((p) => namen(p).some((re) => re.test(t)));
    if (!noemt) continue;
    if (!/href="(\/en)?\/partners"/.test(html)) fout.push(`${rel}: noemt ${noemt.handelsnaam} en linkt nergens naar /partners`);
  }
  const vast = ['privacy', 'dpa', 'security', 'index', 'trust', 'press', 'docs', 'docs/paramant-ot-brief'];
  for (const naam of vast) {
    for (const [rel, link] of [[`${naam}.html`, '/partners'], [`en/${naam}.html`, '/en/partners']]) {
      const html = leesPagina(rel).replace(/<footer\b[\s\S]*?<\/footer>/g, ' ');
      if (!html.includes(`href="${link}"`)) fout.push(`${rel}: geen link naar ${link} buiten de voet`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});

// --- 4. /partners ----------------------------------------------------------

test('/partners en /en/partners lezen partners.json en schrijven zelf geen partij', () => {
  const js = fs.readFileSync(path.join(ROOT, 'frontend/js/partners.page.js'), 'utf8');
  assert.match(js, /fetch\('\/partners\.json'/, 'de pagina leest /partners.json niet meer');
  for (const p of partners.partijen) {
    assert.ok(!js.includes(p.handelsnaam), `partners.page.js noemt ${p.handelsnaam} zelf; de lijst hoort uit het bestand te komen`);
  }
  for (const [rel, zin] of [
    ['partners.html', 'Dit is de volledige lijst. De site en de code worden er automatisch tegen getoetst.'],
    ['en/partners.html', 'This is the complete list. The site and the code are checked against it automatically.'],
  ]) {
    const html = leesPagina(rel);
    assert.ok(html.includes(zin), `${rel} mist de openingszin`);
    assert.match(html, /<script src="\/js\/partners\.page\.js\?v=\d+" defer><\/script>/, `${rel} laadt partners.page.js niet`);
    assert.match(html, /id="partners-gewijzigd"/, `${rel} toont de datum van laatste wijziging niet`);
    assert.match(html, /id="partners-lijst"/, `${rel} heeft geen plek voor de lijst`);
  }
});

// --- 5. productie -----------------------------------------------------------

function prodSleutelnamen() {
  if (process.env.PARTNERS_PROD_NAMEN) {
    return fs.readFileSync(process.env.PARTNERS_PROD_NAMEN, 'utf8');
  }
  const doel = process.env.PARTNERS_PROD_SSH;
  const args = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=10'];
  if (process.env.PARTNERS_PROD_SSH_KEY) args.push('-i', process.env.PARTNERS_PROD_SSH_KEY.replace(/^~/, os.homedir()));
  // Alleen de namen: alles na het eerste = blijft op de server.
  return execFileSync('ssh', [...args, doel, 'cut -d= -f1 /opt/paramant-relay/.env'], { encoding: 'utf8', timeout: 30000 });
}

test('productie: de sleutels van actieve partijen staan in de prod-.env, die van andere niet', (t) => {
  if (!process.env.PARTNERS_PROD_SSH && !process.env.PARTNERS_PROD_NAMEN) {
    t.skip('PARTNERS_PROD_SSH (of PARTNERS_PROD_NAMEN) niet gezet: de sleutels op productie zijn NIET vergeleken. Dit is geen groen.');
    return;
  }
  const namenOpProd = new Set(prodSleutelnamen().split('\n').map((r) => r.trim())
    .filter((r) => r && !r.startsWith('#')).map((r) => r.replace(/^export\s+/, '')));
  assert.ok(namenOpProd.size > 5, `maar ${namenOpProd.size} namen gelezen; de prod-.env is waarschijnlijk niet gelezen`);
  const vandaag = new Date().toISOString().slice(0, 10);
  const fout = [];
  for (const p of partners.partijen) {
    if (p.status === 'actief') {
      for (const k of p.sleutels) if (!namenOpProd.has(k)) fout.push(`${p.id} is actief, maar ${k} staat niet in de prod-.env`);
      continue;
    }
    for (const k of [...p.sleutels, ...(p.sleutels_optioneel || [])]) {
      if (!namenOpProd.has(k)) continue;
      const rest = p.dode_resten.find((d) => d.sleutel === k);
      if (!rest) fout.push(`${k} staat in de prod-.env, en ${p.id} is ${p.status}; zet de partij op actief of meld de sleutel als dode rest met opruimdatum`);
      else if (rest.opruimen_voor < vandaag) fout.push(`dode rest ${k} (${p.id}) had voor ${rest.opruimen_voor} van de server moeten zijn`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});
