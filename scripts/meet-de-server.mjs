// Legt de repo naast de gemeten werkelijkheid en wordt rood bij verschil.
//
// De aanleiding staat in deploy/de-server.md: deploy/deploy-3.1.sh installeert
// geen enkele nginx-conf uit de repo, het patcht wat er op de server staat. De
// confs in de repo zijn daarmee een verslag en geen bron. Zolang dat zo is kan
// een waarde in de repo veranderen zonder dat productie meebeweegt, en andersom,
// en niets merkt het. Op 2026-09-05 was dat geen theorie: de repo zei
// client_max_body_size 12M, productie weigerde alles boven 10485760 bytes, en
// dat getal stond in geen enkel repobestand.
//
// Dit meet wat er van buitenaf te meten valt en vergelijkt het met wat de repo
// zegt. Geen ssh, geen sleutel, geen toegang: alleen DNS, TLS en HTTP. Dat is
// precies het stuk werkelijkheid dat een klant ook ziet.
//
//   node scripts/meet-de-server.mjs           tabel, exitcode 1 bij verschil
//   node scripts/meet-de-server.mjs --json    hetzelfde als JSON
//
// De vergelijking zelf zit in vergelijk(), zonder netwerk, zodat de test hem
// met opgenomen metingen kan draaien.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------
// 1. Wat de repo zegt
// ---------------------------------------------------------------------------

// De publieke conf is het bestand dat de zes publieke hosts beschrijft. Het is
// geen deployartefact (niets kopieert het naar de server), maar het is wel de
// plek waar iemand een waarde verandert in de veronderstelling dat productie
// meebeweegt. Juist daarom is dit de bron voor de verwachting.
export const PUBLIEKE_CONF = 'deploy/nginx-paramant-public.conf';

// Een serverblok uitlezen is geen nginx-parser bouwen. Wat hier telt is: welke
// server_name hoort bij welk blok, en welke client_max_body_size geldt daar.
// De richtlijn staat soms op een eigen regel en soms midden in een location-
// regel op een enkele regel; beide vormen komen in dit bestand voor.
export function leesPubliekeConf(root = ROOT) {
  const bestand = path.join(root, PUBLIEKE_CONF);
  const regels = fs.readFileSync(bestand, 'utf8').split('\n');
  const blokken = [];
  let huidig = null;
  let diepte = 0;
  regels.forEach((regel, i) => {
    const kaal = regel.replace(/#.*$/, '');
    if (/(^|\s)server\s*\{/.test(kaal) && diepte === 0) {
      huidig = { namen: [], limiet: null, limietRegel: null, hsts: null, startRegel: i + 1 };
      blokken.push(huidig);
      diepte = 1;
      return;
    }
    if (!huidig) return;
    diepte += (kaal.match(/\{/g) || []).length;
    diepte -= (kaal.match(/\}/g) || []).length;
    const naam = kaal.match(/^\s*server_name\s+([^;]+);/);
    if (naam) huidig.namen = naam[1].trim().split(/\s+/);
    // Ook ingesprongen, en ook achter een accolade of puntkomma: in dit bestand
    // staat de richtlijn zowel op een eigen regel als midden in een eenregelig
    // location-blok. Verankeren aan het regelbegin las de tweede vorm niet.
    const lim = kaal.match(/(?:^\s*|[{;]\s*)client_max_body_size\s+([0-9]+[kKmMgG]?)\s*;/);
    if (lim && huidig.limiet === null) { huidig.limiet = lim[1]; huidig.limietRegel = i + 1; }
    const hsts = kaal.match(/add_header\s+Strict-Transport-Security\s+"([^"]+)"/i);
    if (hsts) huidig.hsts = hsts[1];
    if (diepte <= 0) huidig = null;
  });
  return blokken.filter((b) => b.namen.length);
}

// nginx schrijft groottes als 12M of 512k. Een getal zonder achtervoegsel is
// bytes. Dit moet exact zijn, want het verschil tussen 10M en 10485760 is
// precies het soort verschil waar dit voor gebouwd is.
export function naarBytes(maat) {
  const m = String(maat).match(/^([0-9]+)\s*([kKmMgG]?)$/);
  if (!m) throw new Error('onleesbare nginx-grootte: ' + maat);
  const factor = { '': 1, k: 1024, m: 1024 * 1024, g: 1024 * 1024 * 1024 }[m[2].toLowerCase()];
  return Number(m[1]) * factor;
}

// De afspraak zelf: wat hoort productie te doen, en waar komt die verwachting
// vandaan. Alles wat de repo niet bepaalt staat hier met een reden, want een
// verwachting zonder bron is een gok en die hoort niet in een poort.
export function leesAfspraak(root = ROOT) {
  const a = JSON.parse(fs.readFileSync(path.join(root, 'deploy/de-server.json'), 'utf8'));
  // Een verschil dat op zes hosts hetzelfde is, is een verschil met een reden,
  // niet zes redenen. In het bestand staat het een keer met een lijst hosts;
  // hier wordt het uitgevouwen zodat de vergelijking per host kan werken.
  a.afwijkingen = (a.afwijkingen || []).flatMap((x) =>
    (x.hosts || [x.host]).map((h) => ({ ...x, host: h, hosts: undefined })));
  return a;
}

export function leesVersie(root = ROOT) {
  return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
}

export function leesAnkers(root = ROOT) {
  const bron = fs.readFileSync(path.join(root, 'frontend/js/relay-trust-anchors.js'), 'utf8');
  const ankers = [];
  const re = /\{\s*name:\s*'([^']+)',\s*host:\s*'([^']+)',\s*sector:\s*'([^']+)',\s*alg:\s*'([^']+)',[\s\S]*?fingerprint:\s*'([^']+)',[\s\S]*?key:\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(bron))) ankers.push({ name: m[1], host: m[2], sector: m[3], alg: m[4], fingerprint: m[5], key: m[6] });
  return ankers;
}

// De verwachting per host, afgeleid uit het bovenstaande. Dit is de enige plek
// waar repo-waarden verwachtingen worden.
export function verwachting(root = ROOT) {
  const afspraak = leesAfspraak(root);
  const blokken = leesPubliekeConf(root);
  const ankers = leesAnkers(root);
  const versie = leesVersie(root);
  const perHost = {};
  for (const host of afspraak.hosts) {
    const blok = blokken.find((b) => b.namen.includes(host.host) && b.limiet !== null);
    const bekend = afspraak.afwijkingen.find((a) =>
      a.host === host.host && a.wat === 'weigert boven de grens uit de repo');
    perHost[host.host] = {
      ...host,
      bekendeGrens: bekend ? bekend.gemeten : null,
      limiet: blok ? naarBytes(blok.limiet) : null,
      limietBron: blok ? `${PUBLIEKE_CONF}:${blok.limietRegel}` : null,
      hsts: blok ? blok.hsts : null,
      anker: ankers.find((a) => a.host === host.host) || null,
      versie: host.sector ? versie : null,
    };
  }
  return { afspraak, perHost, versie, ankers };
}

// ---------------------------------------------------------------------------
// 2. Wat productie doet
// ---------------------------------------------------------------------------

const TIMEOUT = Number(process.env.METING_TIMEOUT_MS || 8000);
// Onder de grens antwoordt nginx niet: hij wacht op de body die nooit komt.
// Dat wachten is het signaal, dus dit mag kort zijn.
const WACHT = Number(process.env.METING_WACHT_MS || 1500);

// De grens meten zonder een byte te uploaden. nginx vergelijkt Content-Length
// met client_max_body_size voordat hij de body leest, dus alleen de kop sturen
// is genoeg: 413 betekent boven de grens, stilte betekent eronder.
export function kopProbe(host, lengte) {
  return new Promise((klaar) => {
    let af = false;
    const gedaan = (v) => { if (!af) { af = true; klaar(v); } };
    const s = tls.connect({ host, port: 443, servername: host, ALPNProtocols: ['http/1.1'] }, () => {
      s.write(`POST /__meting HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${lengte}\r\n`
        + `Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n`);
    });
    let buf = '';
    const t = setTimeout(() => { s.destroy(); gedaan('wacht'); }, WACHT);
    s.on('data', (d) => {
      buf += d;
      if (buf.includes('\r\n')) { clearTimeout(t); s.destroy(); gedaan(Number(buf.split(' ')[1])); }
    });
    s.on('error', (e) => { clearTimeout(t); gedaan('fout: ' + e.message); });
  });
}

// Twee metingen, geen zoektocht: precies op de verwachte grens moet het door
// mogen, en een byte erboven niet. Dat toetst de waarde uit de repo in plaats
// van hem te ontdekken, en het kost twee verbindingen in plaats van dertig.
export async function meetGrens(host, verwacht) {
  const op = await kopProbe(host, verwacht);
  const erboven = await kopProbe(host, verwacht + 1);
  if (op === 'wacht' && erboven === 413) return { klopt: true, grens: verwacht };
  return { klopt: false, op, erboven };
}

// Bij verschil is "het klopt niet" te weinig; dan wil je het echte getal weten.
// Pas hier mag het zoeken, en alleen dan.
//
// Met een budget, want dit is duur: elke meting onder de grens levert geen
// antwoord op maar een stilte, en op die stilte moet gewacht worden. Een
// ongebreidelde zoektocht over zes hosts liep in de sabotagetoets van
// 2026-09-05 buiten de tijd van de test, en een poort die bij een verschil
// blijft hangen in plaats van rood te worden is geen poort.
export async function zoekGrens(host, onder = 1024, boven = 64 * 1024 * 1024) {
  if (await kopProbe(host, onder) === 413) return { grens: null, opmerking: 'weigert al op ' + onder };
  if (await kopProbe(host, boven) !== 413) return { grens: null, opmerking: 'accepteert nog op ' + boven };
  let stappen = 0;
  while (onder < boven - 1 && stappen < 20) {
    const mid = Math.floor((onder + boven) / 2);
    if (await kopProbe(host, mid) === 413) boven = mid; else onder = mid;
    stappen += 1;
  }
  return onder === boven - 1 ? { grens: onder } : { grens: onder, bijBenadering: true };
}

async function haal(url, opties = {}) {
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT), ...opties });
  const koppen = {};
  for (const [k, v] of res.headers) koppen[k.toLowerCase()] = v;
  return { status: res.status, koppen, tekst: await res.text().catch(() => '') };
}

export function meetCertificaat(host) {
  return new Promise((klaar) => {
    const s = tls.connect({ host, port: 443, servername: host }, () => {
      const c = s.getPeerCertificate();
      s.destroy();
      klaar({
        uitgever: c.issuer && c.issuer.O,
        onderwerp: c.subject && c.subject.CN,
        tot: c.valid_to,
        sans: (c.subjectaltname || '').split(',').map((x) => x.trim().replace(/^DNS:/, '')).filter(Boolean),
      });
    });
    s.setTimeout(TIMEOUT, () => { s.destroy(); klaar({ fout: 'timeout' }); });
    s.on('error', (e) => klaar({ fout: e.message }));
  });
}

export async function meet(root = ROOT) {
  const { perHost } = verwachting(root);
  const meting = { gemeten: new Date().toISOString(), hosts: {}, cert: null };
  let gezocht = null;
  meting.cert = await meetCertificaat('paramant.app');
  for (const [naam, v] of Object.entries(perHost)) {
    const h = { host: naam };
    try { h.adressen = (await dns.resolve4(naam)).sort(); } catch (e) { h.adressen = []; h.dnsFout = e.code; }
    try {
      const r = await haal('https://' + naam + '/');
      h.status = r.status;
      h.server = r.koppen.server;
      h.via = r.koppen.via;
      h.hsts = r.koppen['strict-transport-security'];
      h.altSvc = r.koppen['alt-svc'];
    } catch (e) { h.fout = String(e.message || e); }
    try {
      const r = await haal('http://' + naam + '/');
      h.klaarhttp = { status: r.status, server: r.koppen.server, location: r.koppen.location };
    } catch (e) { h.klaarhttp = { fout: String(e.message || e) }; }
    if (v.sector) {
      try {
        const r = await haal('https://' + naam + '/health');
        const j = JSON.parse(r.tekst);
        h.sector = j.sector; h.versie = j.version; h.editie = j.edition;
      } catch (e) { h.healthFout = String(e.message || e); }
      try {
        const r = await haal('https://' + naam + '/v2/pubkey');
        const j = JSON.parse(r.tekst);
        h.sleutel = j.public_key; h.alg = j.alg;
      } catch (e) { h.sleutelFout = String(e.message || e); }
    }
    if (v.limiet !== null) {
      const g = await meetGrens(naam, v.limiet);
      h.grensKlopt = g.klopt;
      if (g.klopt) { meting.hosts[naam] = h; continue; }
      // Klopt het niet, dan is het bekende getal de eerste gok. Scheelt een
      // binaire zoektocht van dertig verbindingen per host bij elke deploy,
      // en het antwoord is even hard: twee metingen op de grens.
      const bekend = Number(String(v.bekendeGrens || '').replace(/[^0-9]/g, ''));
      if (bekend) {
        const b = await meetGrens(naam, bekend);
        if (b.klopt) { h.grens = bekend; meting.hosts[naam] = h; continue; }
      }
      // Een zoektocht per meting. Een grens die afwijkt wijkt in deze vloot op
      // alle hosts tegelijk af, want hij komt uit een gedeeld http-blok. De
      // eerste zoektocht levert het getal; de rest krijgt hetzelfde vermoeden
      // en wordt evengoed rood, want ze klopten al niet.
      if (gezocht === null) { const z = await zoekGrens(naam); gezocht = z.grens; h.grens = z.grens; }
      else h.grens = gezocht;
    }
    meting.hosts[naam] = h;
  }
  return meting;
}

// ---------------------------------------------------------------------------
// 3. De vergelijking (zonder netwerk, zodat de test hem kan draaien)
// ---------------------------------------------------------------------------

// Een verschil dat je kent is iets anders dan een verschil dat je niet kent.
// Een poort die altijd rood staat wordt weggeklikt, en een poort die bekende
// verschillen wegpoetst bewaakt niets. Dus: elk verschil moet in
// deploy/de-server.json staan onder "afwijkingen", met de gemeten waarde erbij
// en een reden. Dan is de poort groen zolang de werkelijkheid is wat er staat,
// en rood zodra er iets bijkomt, iets verandert, of iets opgelost is en het
// bestand het nog niet weet. Verschillen worden zo geteld in plaats van
// gevoeld, en het aantal hoort omlaag te lopen.
function beoordeel(uit, afwijkingen) {
  const gebruikt = new Set();
  for (const r of uit) {
    if (r.ok) {
      const a = afwijkingen.find((x) => x.host === r.host && x.wat === r.wat);
      if (a) {
        gebruikt.add(a);
        r.status = 'opgelost';
        r.ok = false;
        r.uitleg = 'dit verschil staat nog als bekend in deploy/de-server.json maar is weg; haal het daar weg';
      } else r.status = 'goed';
      continue;
    }
    const a = afwijkingen.find((x) => x.host === r.host && x.wat === r.wat);
    if (!a) { r.status = 'rood'; continue; }
    gebruikt.add(a);
    // Een verschil heeft twee kanten en beide moeten vastliggen. Alleen de
    // gemeten kant pinnen laat de andere kant vrij bewegen: dan mag iemand de
    // waarde in de repo van 12M naar 20M zetten en blijft de poort groen,
    // terwijl het verschil net zo hard groter is geworden.
    if (String(a.gemeten) !== String(r.gemeten)) {
      r.status = 'rood';
      r.uitleg = 'bekend verschil, maar de server doet nu iets anders dan op ' + a.sinds
        + ' gemeten werd (' + a.gemeten + ')';
      continue;
    }
    if (String(a.verwacht) !== String(r.verwacht)) {
      r.status = 'rood';
      r.uitleg = 'bekend verschil, maar de repo zegt nu iets anders dan op ' + a.sinds
        + ' opgeschreven werd (' + a.verwacht + ')';
      continue;
    }
    r.status = 'bekend';
    r.ok = true;
    r.reden = a.reden;
  }
  for (const a of afwijkingen) {
    if (!gebruikt.has(a)) {
      uit.push({ host: a.host, wat: a.wat, verwacht: '-', gemeten: '-', bron: 'deploy/de-server.json',
        ok: false, status: 'rood',
        uitleg: 'deze afwijking staat in deploy/de-server.json maar er is geen controle die hem meet' });
    }
  }
  return uit;
}

export function vergelijk(verw, meting) {
  const uit = [];
  const zeg = (host, wat, verwacht, gemeten, bron, ok) =>
    uit.push({ host, wat, verwacht, gemeten, bron, ok });

  const cert = meting.cert || {};
  const certHosts = (verw.afspraak.hosts || []).map((h) => h.host);
  zeg('-', 'certificaat dekt elke host uit de afspraak', certHosts.join(' '), (cert.sans || []).join(' '),
    'deploy/de-server.json', certHosts.every((h) => (cert.sans || []).includes(h)));
  if (cert.tot) {
    const dagen = Math.floor((new Date(cert.tot) - new Date(meting.gemeten)) / 86400000);
    zeg('-', 'certificaat verloopt niet binnen ' + verw.afspraak.cert.minimaleDagen + ' dagen',
      '>= ' + verw.afspraak.cert.minimaleDagen, dagen + ' dagen (tot ' + cert.tot + ')',
      'deploy/de-server.json', dagen >= verw.afspraak.cert.minimaleDagen);
  }
  zeg('-', 'certificaat is van de verwachte uitgever', verw.afspraak.cert.uitgever, cert.uitgever,
    'deploy/de-server.json', cert.uitgever === verw.afspraak.cert.uitgever);

  for (const [naam, v] of Object.entries(verw.perHost)) {
    const m = meting.hosts[naam] || {};
    zeg(naam, 'wijst naar het verwachte adres', verw.afspraak.adres.ip, (m.adressen || []).join(' '),
      'deploy/de-server.json', (m.adressen || []).join(' ') === verw.afspraak.adres.ip);
    zeg(naam, 'antwoordt', '200', String(m.status), 'deploy/de-server.json', m.status === 200);

    // De laag die nergens in de repo staat. Zolang die er is, is hij een
    // verwachting met een reden en geen verrassing: verdwijnt hij, dan is dat
    // een verandering die iemand moet hebben besloten.
    const rand = verw.afspraak.rand;
    zeg(naam, 'staat achter ' + rand.naam, rand.viaKop, m.via, rand.bron, m.via === rand.viaKop);
    zeg(naam, 'wordt bediend door nginx', 'nginx', m.server, PUBLIEKE_CONF, m.server === 'nginx');
    zeg(naam, 'stuurt http door naar https', String(rand.httpStatus) + ' via ' + rand.naam,
      (m.klaarhttp || {}).status + ' via ' + (m.klaarhttp || {}).server, rand.bron,
      (m.klaarhttp || {}).status === rand.httpStatus && (m.klaarhttp || {}).server === rand.serverKop);

    if (v.hsts) zeg(naam, 'zet HSTS zoals de conf zegt', v.hsts, m.hsts,
      PUBLIEKE_CONF, (m.hsts || '').includes(v.hsts));

    if (v.limiet !== null) {
      zeg(naam, 'weigert boven de grens uit de repo', v.limiet + ' bytes',
        m.grensKlopt ? v.limiet + ' bytes' : (m.grens === undefined ? 'niet gemeten' : m.grens + ' bytes'),
        v.limietBron, m.grensKlopt === true);
    }
    if (v.sector) {
      zeg(naam, 'noemt zichzelf de juiste sector', v.sector, m.sector, 'deploy/de-server.json', m.sector === v.sector);
      zeg(naam, 'draait de versie uit package.json', v.versie, m.versie, 'package.json', m.versie === v.versie);
    }
    if (v.anker) {
      zeg(naam, 'publiceert de vastgezette sleutel', v.anker.key.slice(0, 24) + '...',
        (m.sleutel || '').slice(0, 24) + '...', 'frontend/js/relay-trust-anchors.js', m.sleutel === v.anker.key);
    }
  }
  return beoordeel(uit, verw.afspraak.afwijkingen || []);
}

// ---------------------------------------------------------------------------
// 4. CLI
// ---------------------------------------------------------------------------

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const verw = verwachting();
  const meting = await meet();
  const regels = vergelijk(verw, meting);
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify({ meting, regels }, null, 2));
  } else {
    const getoond = new Set();
    const merk = { goed: 'ok    ', bekend: 'bekend', rood: 'ROOD  ', opgelost: 'OP    ' };
    for (const r of regels) {
      if (r.status === 'goed') continue;
      console.log(`${merk[r.status]} ${String(r.host).padEnd(22)} ${r.wat}`);
      if (r.status !== 'goed') console.log(`       repo zegt ${r.verwacht}  (${r.bron})`);
      if (r.status !== 'goed') console.log(`       server doet ${r.gemeten}`);
      if (r.reden && !getoond.has(r.reden)) { getoond.add(r.reden); console.log(`       waarom bekend: ${r.reden}`); }
      else if (r.reden) console.log(`       waarom bekend: zie hierboven`);
      if (r.uitleg) console.log(`       ${r.uitleg}`);
    }
    const tel = (s) => regels.filter((r) => r.status === s).length;
    console.log(`\n${tel('goed')} goed, ${tel('bekend')} bekend verschil, `
      + `${tel('rood')} rood, ${tel('opgelost')} opgelost maar nog opgeschreven`);
  }
  process.exit(regels.some((r) => !r.ok) ? 1 : 0);
}
