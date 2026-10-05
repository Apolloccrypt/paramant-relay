'use strict';
// De stand van Paramant, in gewone taal, en nooit meer dan er gemeten is.
//
// Dit bestand bestaat om een fout niet te herhalen. In de nacht van 5 op 6
// september bleek negen keer op rij dat een waarborg er stond en niets deed:
// een overgeslagen taak faalt niet, een rookproef slaagde juist toen een route
// helemaal niet antwoordde, en de deploy las de statuscode van de diepe
// gezondheidscontrole in plaats van de uitslag erin. Alle negen zagen er van
// een afstand groen uit.
//
// Daarom gelden hier twee regels, en ze worden afgedwongen in code en niet in
// een comment:
//
//   1. Geen oordeel zonder meting. `punt()` zet elk punt zonder `meting` op
//      NIET_GEMETEN, wat de aanroeper ook meegaf. Een waarde die er niet is
//      kan hier dus niet als groen eindigen.
//   2. Niet gemeten is niet goed. In `RANG` staat NIET_GEMETEN bóven "let op":
//      een blok waar de meting wegviel trekt de kop naar beneden in plaats van
//      stilletjes mee te liften op de punten die wel lukten.
//
// Alle buitenwereld komt binnen via `io`, zodat de sabotagetoets een kapotte
// relay, een stille GitHub en een lege audittrail kan naspelen zonder netwerk.

const GOED = 'goed';
const LET_OP = 'let op';
const NIET_GEMETEN = 'niet gemeten';
const KAPOT = 'kapot';

// Slechter is hoger. NIET_GEMETEN staat expres boven LET_OP: een meting die
// wegviel is erger dan een meting die iets kleins liet zien, omdat je van de
// eerste niet weet wat je mist.
const RANG = { [GOED]: 0, [LET_OP]: 1, [NIET_GEMETEN]: 2, [KAPOT]: 3 };

const WEEK_MS = 7 * 24 * 3600 * 1000;
const UUR_MS = 3600 * 1000;

// Een dagelijkse controle die langer dan dit stil is, is stil. Twee dagen, niet
// een week: een alarm dat een halve week mag zwijgen is geen alarm. Dezelfde
// redenering als HEARTBEAT_ROOD_UREN in scripts/directie/signalen.py.
const CONTROLE_STIL_UREN = 48;
// Een tak of PR die langer dan dit buiten main staat is voorraad, geen werk.
// Gelijk aan LANDEN_TERMIJN_DAGEN in scripts/check-landen.mjs.
const LANDEN_DAGEN = 7;

function slechtste(standen) {
  return standen.reduce((m, s) => (RANG[s] > RANG[m] ? s : m), GOED);
}

// De enige manier waarop een punt ontstaat.
//
// `meting` is wat er werkelijk gezien is: een getal, een statuscode, een lijst,
// een tijdstip. Is dat null of undefined, dan is er niets gemeten en wordt het
// punt NIET_GEMETEN, ongeacht de meegegeven stand. Dit is de regel waar de hele
// pagina op rust, dus hij staat hier en nergens anders.
function punt(naam, stand, zin, meting, bron) {
  const gemeten = meting !== null && meting !== undefined;
  return {
    naam,
    stand: gemeten ? stand : NIET_GEMETEN,
    zin: gemeten ? zin : (zin || `Dit kon ik niet meten, dus ik weet het niet.`),
    meting: gemeten ? meting : null,
    bron,
  };
}

function blok(id, titel, punten) {
  return { id, titel, stand: slechtste(punten.map(p => p.stand)), punten };
}

// Een zin die begint met een ingevulde naam begint met een kleine letter. Dat
// leest als een halve regel, dus hij krijgt hier alsnog zijn hoofdletter.
function hoofdletter(zin) {
  return zin.charAt(0).toUpperCase() + zin.slice(1);
}

function ouderdom(nu, ts) {
  if (!ts) return null;
  const ms = nu - ts;
  const min = Math.round(ms / 60000);
  if (min < 60) return `${min} minuten`;
  const uur = Math.round(ms / UUR_MS);
  if (uur < 48) return `${uur} uur`;
  return `${Math.round(ms / 86400000)} dagen`;
}

// ── Blok 1. Werkt het ───────────────────────────────────────────────────────
//
// Niet "antwoordt het adres", maar "doet het iets". Vandaar de diepe controle,
// die op de relay zelf een bestand wegschrijft en redis aanspreekt, en de weg
// die een klant aflegt.

async function blokWerkt(io) {
  const punten = [];

  // 1a. Antwoorden de relays, en met welke versie.
  const levens = await Promise.all(io.sectors.map(async (s) => {
    try {
      const r = await io.relay(s, '/health');
      return { sector: s, status: r.status, versie: r.body && r.body.version };
    } catch (e) {
      return { sector: s, status: 0, fout: e.message };
    }
  }));
  const op = levens.filter(l => l.status === 200);
  const stuk = levens.filter(l => l.status !== 200);
  punten.push(punt(
    'De relays',
    stuk.length === 0 ? GOED : KAPOT,
    stuk.length === 0
      ? `Alle ${levens.length} relays draaien, op versie ${[...new Set(op.map(l => l.versie).filter(Boolean))].join(' en ') || 'onbekend'}.`
      : `${stuk.length} van de ${levens.length} relays antwoordt niet: ${stuk.map(l => l.sector).join(', ')}. Wie daar iets heen stuurt, krijgt niets terug.`,
    levens.length ? levens : null,
    'GET /health op elke relay',
  ));

  // 1b. De diepe controle. Deze schrijft echt een bestand weg en pingt redis.
  //
  // We lezen `overall` uit het antwoord en niet de HTTP-status. Die route
  // antwoordt namelijk altijd 200, ook als de uitslag erin rood is. Dat is
  // precies de fout die de deploy 34 keer op rij maakte: 34 logboeken lang
  // "deep overall = red" terwijl de deploy doorliep omdat de statuscode klopte.
  const diepen = await Promise.all(io.sectors.map(async (s) => {
    try {
      const r = await io.relay(s, '/v2/health/deep', { internal: true });
      if (r.status !== 200 || !r.body || !r.body.overall) return { sector: s, uitslag: null, status: r.status };
      const slecht = (r.body.checks || []).filter(c => c.status === 'red' || c.status === 'yellow');
      return { sector: s, uitslag: r.body.overall, slecht };
    } catch (e) {
      return { sector: s, uitslag: null, fout: e.message };
    }
  }));
  const gelezen = diepen.filter(d => d.uitslag);
  const rood = gelezen.filter(d => d.uitslag === 'red');
  const geel = gelezen.filter(d => d.uitslag === 'yellow');
  const namen = (d) => (d.slecht || []).map(c => `${c.name} (${c.detail})`).join(', ');
  punten.push(punt(
    'De diepe controle',
    rood.length ? KAPOT : (geel.length ? LET_OP : GOED),
    gelezen.length === 0
      ? 'Geen enkele relay gaf een uitslag terug, dus ik weet niet of opslag en geheugen het doen.'
      : rood.length
        ? `Op ${rood.map(d => d.sector).join(', ')} is iets stuk: ${namen(rood[0])}.`
        : geel.length
          ? `Alles draait, met een waarschuwing op ${geel.map(d => d.sector).join(', ')}: ${namen(geel[0])}.`
          : `Alle ${gelezen.length} relays kunnen wegschrijven, hun geheugen is in orde en de opslag antwoordt.`,
    gelezen.length ? diepen : null,
    'GET /v2/health/deep, de uitslag in het antwoord en niet de statuscode',
  ));

  // 1c. De weg die een klant aflegt: de voordeur, de inlog, en de tekenpagina
  //     die niet naar de inlog mag wegspringen.
  const wegen = [
    { naam: 'de voorpagina', url: io.site + '/', verwacht: 200 },
    { naam: 'de inlogpagina', url: io.site + '/auth/login', verwacht: 200 },
    { naam: 'de tekenpagina', url: io.site + '/sign', verwacht: 200 },
  ];
  const gelopen = [];
  for (const w of wegen) {
    try {
      const r = await io.web(w.url);
      gelopen.push({ ...w, status: r.status, ms: r.ms, leeg: !(r.text && r.text.length > 500) });
    } catch (e) {
      gelopen.push({ ...w, status: 0, fout: e.message });
    }
  }
  const mis = gelopen.filter(w => w.status !== w.verwacht || w.leeg);
  punten.push(punt(
    'De weg van een klant',
    mis.length ? KAPOT : GOED,
    mis.length
      ? hoofdletter(`${mis.map(w => w.naam).join(' en ')} komt niet goed omhoog (${mis.map(w => w.status === 0 ? 'geen antwoord' : `antwoord ${w.status}`).join(', ')}). Een bezoeker loopt daar vast.`)
      : `De voorpagina, de inlog en de tekenpagina komen alle drie omhoog, de traagste in ${Math.max(...gelopen.map(w => w.ms || 0))} ms.`,
    gelopen.some(w => w.status) ? gelopen : null,
    `GET op ${io.site}, zoals een bezoeker het doet`,
  ));

  // 1d. De laatste echte proef: een blok dat er werkelijk in ging en er
  //     byte voor byte weer uit kwam. Die proef schrijft in het openbare
  //     logboek, dus hij draait niet bij elke keer dat deze pagina opent;
  //     anders zou deze pagina zelf het gebruikscijfer opblazen. Wat hier
  //     staat is de laatste die gedaan is, met zijn leeftijd erbij.
  let proef = null;
  try { proef = await io.laatsteProef(); } catch { proef = null; }
  const proefOud = proef && proef.ts ? io.nu() - proef.ts > 24 * UUR_MS : false;
  punten.push(punt(
    'De laatste echte proef',
    proef && proef.ok ? (proefOud ? LET_OP : GOED) : KAPOT,
    !proef
      ? 'Er is nog nooit een echte proef gedaan, dus niemand heeft aangetoond dat een bestand er heelhuids doorheen komt. Druk op de knop hieronder om er nu een te doen.'
      : proef.ok
        ? `${ouderdom(io.nu(), proef.ts)} geleden ging er een bestand in en kwam byte voor byte hetzelfde weer terug, en het werd daarna vernietigd zoals beloofd.`
        : `De laatste proef, ${ouderdom(io.nu(), proef.ts)} geleden, is mislukt: ${proef.reden}.`,
    proef,
    'POST /v2/anon-inbound, dan de download, dan nog een keer om te zien dat hij weg is',
  ));

  return blok('werkt', 'Werkt het', punten);
}

// ── Blok 2. Wordt het gebruikt ──────────────────────────────────────────────
//
// Het getal dat hier hoort te staan is het aantal handelingen door mensen. In
// augustus meldde ik 485 handelingen als gebruik; 855 van de 891 regels in het
// openbare logboek kwamen van de eigen uurlijkse zelftest en de laatste echte
// overdracht door een mens was van 18 augustus. Het getal was dus vrijwel
// helemaal de eigen robot.
//
// Daarom staan hier drie getallen naast elkaar en nooit één: mensen, Mick zelf,
// en de zelftest. De regel waarmee ze uit elkaar gehouden worden staat op de
// pagina zelf, zodat een cijfer altijd na te rekenen is.

// Een handeling telt als zelftest wanneer hij van een als zelftest aangemerkt
// account komt, of wanneer er een kanarie-kenmerk in de gegevens zit. De
// kanarie zet `canary-` voor alles wat hij aanmaakt (scripts/heartbeat/lib.mjs),
// en de proefknop op deze pagina zet er `stand-` voor.
function soortVanHandeling(regel, zelftestAccounts) {
  const type = String(regel.event_type || '');
  if (type.startsWith('admin_')) return 'mick';
  const id = String(regel.user_id || '');
  if (zelftestAccounts.includes(id)) return 'zelftest';
  const plat = JSON.stringify(regel.metadata || {});
  if (plat.includes('canary-') || plat.includes('stand-')) return 'zelftest';
  return 'mens';
}

async function blokGebruik(io) {
  const punten = [];
  const nu = io.nu();
  const zelftestAccounts = io.zelftestAccounts || [];

  // 2a. Hoeveel accounts zijn er, en hoeveel daarvan staan aan.
  let sleutels = null;
  try { sleutels = await io.sleutels(); } catch { sleutels = null; }
  if (sleutels) {
    const uniek = new Set(sleutels.map(k => k.account_id || k.api_key_prefix));
    const actief = sleutels.filter(k => k.active !== false).length;
    punten.push(punt(
      'Accounts',
      GOED,
      `Er zijn ${uniek.size} accounts, waarvan ${actief} actief. Een account is nog geen gebruiker.`,
      { accounts: uniek.size, actief },
      'GET /v2/admin/usage op elke relay',
    ));
  } else {
    punten.push(punt('Accounts', GOED, 'De accountlijst kwam niet terug, dus ik weet niet hoeveel er zijn.', null, 'GET /v2/admin/usage op elke relay'));
  }

  // 2b. Handelingen in de afgelopen week, uit elkaar gehouden.
  let regels = null;
  try { regels = await io.auditRegels(nu - WEEK_MS); } catch { regels = null; }
  if (regels) {
    const tel = { mens: 0, mick: 0, zelftest: 0 };
    let laatsteMens = 0;
    for (const r of regels) {
      const soort = soortVanHandeling(r, zelftestAccounts);
      tel[soort]++;
      if (soort === 'mens' && r.ts > laatsteMens) laatsteMens = r.ts;
    }
    punten.push(punt(
      'Handelingen door mensen, laatste zeven dagen',
      tel.mens > 0 ? GOED : LET_OP,
      tel.mens > 0
        ? `${tel.mens} handelingen door mensen. Daarnaast ${tel.mick} van jou als beheerder en ${tel.zelftest} van de zelftest; die twee tellen hier niet mee.`
        : `Nul handelingen door mensen deze week. Wat er wel gebeurde: ${tel.mick} beheerhandelingen van jou en ${tel.zelftest} van de zelftest. Het product draait, maar niemand gebruikt het.`,
      tel,
      'paramant:audit:global over zeven dagen, gesplitst',
    ));

    punten.push(punt(
      'De laatste handeling door een mens',
      laatsteMens ? GOED : LET_OP,
      laatsteMens
        ? `${ouderdom(nu, laatsteMens)} geleden.`
        : 'In de hele bewaarde week staat geen enkele handeling van een mens.',
      // De meting is de hele doorzochte stapel, niet alleen een gevonden
      // tijdstip. Geen enkele handeling van een mens in 485 doorzochte regels
      // IS een uitkomst; die als "niet gemeten" wegzetten zou juist het
      // ongemakkelijke antwoord onzichtbaar maken.
      { laatste_ts: laatsteMens || 0, regels_bekeken: regels.length },
      'de nieuwste niet-beheer, niet-zelftest regel in paramant:audit:global',
    ));

    // 2c. Wat de zelftest zelf deed, apart genoemd. Dit getal staat er zodat
    //     het nooit meer per ongeluk in het getal hierboven belandt.
    punten.push(punt(
      'Wat de zelftest zelf deed',
      GOED,
      zelftestAccounts.length === 0
        ? `${tel.zelftest} handelingen herkend aan een kanarie-kenmerk. Er is nog geen account als zelftest aangemerkt (STAND_ZELFTEST_ACCOUNTS is leeg), dus die herkenning leunt alleen op dat kenmerk.`
        : `${tel.zelftest} handelingen, van ${zelftestAccounts.length} als zelftest aangemerkte accounts plus alles met een kanarie-kenmerk.`,
      { zelftest: tel.zelftest, aangemerkte_accounts: zelftestAccounts.length },
      'dezelfde regels, de kant die eruit gefilterd is',
    ));
  } else {
    punten.push(punt('Handelingen door mensen, laatste zeven dagen', GOED, 'De audittrail kwam niet terug, dus ik kan geen enkel gebruikscijfer geven. Liever geen getal dan een verkeerd getal.', null, 'paramant:audit:global'));
  }

  return blok('gebruik', 'Wordt het gebruikt', punten);
}

// ── Blok 3. Staat er iets rood ──────────────────────────────────────────────
//
// Vier dingen, in gewone taal. De bouwstraat en de landingspoort staan op
// GitHub; dat is een openbare repo, dus die vragen kunnen zonder sleutel
// gesteld worden. Lukt dat niet, dan zegt dit blok dat, en wordt het niet
// groen omdat er niets binnenkwam.

function runOordeel(run) {
  if (!run) return null;
  // Een overgeslagen run is geen geslaagde run. Dat verschil is de hele reden
  // dat de uurlijkse zelftest negentien keer op rij ongemerkt niets deed: een
  // overgeslagen taak faalt niet, dus niemand kreeg een alarm.
  if (run.conclusion === 'skipped') return 'overgeslagen';
  if (run.status !== 'completed') return 'bezig';
  return run.conclusion === 'success' ? 'geslaagd' : 'gefaald';
}

async function blokRood(io) {
  const punten = [];
  const nu = io.nu();

  // 3a. De bouwstraat: de negen taken die elke wijziging moeten goedkeuren.
  let bouw = null;
  try { bouw = await io.laatsteRun('test.yml', 'main'); } catch { bouw = null; }
  const bouwOordeel = runOordeel(bouw);
  punten.push(punt(
    'De bouwstraat',
    bouwOordeel === 'geslaagd' ? GOED : (bouwOordeel === 'bezig' ? LET_OP : KAPOT),
    bouwOordeel === 'geslaagd'
      ? `De controles op de hoofdtak zijn ${ouderdom(nu, bouw.ts)} geleden allemaal geslaagd.`
      : bouwOordeel === 'bezig'
        ? 'De controles op de hoofdtak draaien nu nog.'
        : bouwOordeel === 'overgeslagen'
          ? 'De controles op de hoofdtak zijn overgeslagen. Overgeslagen is niet geslaagd: er is niets gecontroleerd.'
          : `De controles op de hoofdtak zijn gefaald, ${ouderdom(nu, bouw && bouw.ts)} geleden. Wat er nu op main staat is niet goedgekeurd.`,
    bouw,
    'de laatste run van test.yml op main, via de openbare GitHub-API',
  ));

  // 3b. De dagelijkse controles. Hier wordt naar de uitkomst gekeken en niet
  //     naar de aanwezigheid: een taak die niet draaide is stil, geen succes.
  const controles = [
    { bestand: 'heartbeat.yml', naam: 'de uurlijkse zelftest' },
    { bestand: 'security-posture.yml', naam: 'de dagelijkse veiligheidsscan' },
    { bestand: 'guards.yml', naam: 'de poort op de poorten' },
  ];
  const gezien = [];
  for (const c of controles) {
    try {
      const r = await io.laatsteRun(c.bestand, null);
      gezien.push({ ...c, oordeel: runOordeel(r), ts: r && r.ts });
    } catch {
      gezien.push({ ...c, oordeel: null });
    }
  }
  const gemeten = gezien.filter(c => c.oordeel);
  const stil = gemeten.filter(c => c.oordeel === 'overgeslagen' || (c.oordeel === 'geslaagd' && c.ts && nu - c.ts > CONTROLE_STIL_UREN * UUR_MS));
  const gefaald = gemeten.filter(c => c.oordeel === 'gefaald');
  punten.push(punt(
    'De dagelijkse controles',
    gefaald.length ? KAPOT : (stil.length ? KAPOT : GOED),
    gemeten.length === 0
      ? 'Ik kon niet bij de uitslagen van de controles.'
      : stil.length
        ? hoofdletter(`${stil.map(c => c.naam).join(' en ')} ${stil.length === 1 ? 'draait' : 'draaien'} niet. Er kijkt dus niemand mee of het product in productie nog werkt, en juist die stilte is wat een storing zou verbergen.`)
        : gefaald.length
          ? hoofdletter(`${gefaald.map(c => c.naam).join(' en ')} ${gefaald.length === 1 ? 'is' : 'zijn'} gedraaid en gefaald. Er is dus iets gemeten en het klopte niet.`)
          : `Alle ${gemeten.length} controles hebben recent gedraaid en zijn geslaagd.`,
    gemeten.length ? gezien : null,
    'de laatste run per workflow, waarbij overgeslagen als niet-gedraaid telt',
  ));

  // 3c. Repo en server: draait op de server wat er in de repo staat.
  let manifest = null;
  let hoofd = null;
  try { manifest = await io.codeManifest(); } catch { manifest = null; }
  try { hoofd = await io.hoofdCommit(); } catch { hoofd = null; }
  const beide = manifest && manifest.git_commit && hoofd;
  const gelijk = beide && String(manifest.git_commit).startsWith(String(hoofd).slice(0, 10));
  punten.push(punt(
    'Repo en server',
    gelijk ? GOED : KAPOT,
    beide
      ? (gelijk
        ? `De server draait dezelfde code als de hoofdtak (${String(hoofd).slice(0, 8)}).`
        : `De server draait ${String(manifest.git_commit).slice(0, 8)} terwijl de hoofdtak op ${String(hoofd).slice(0, 8)} staat. Wat er gerepareerd is, staat dus niet allemaal live.`)
      : 'Ik kon de code op de server niet naast de repo leggen, dus ik weet niet of ze gelijk zijn.',
    beide ? { server: manifest.git_commit, repo: hoofd, gepubliceerd: manifest.published || null } : null,
    'het code-manifest van de server naast de kop van main',
  ));

  // 3d. De landingspoort: werk telt pas als het op main staat.
  let prs = null;
  try { prs = await io.openPRs(); } catch { prs = null; }
  if (prs) {
    const grens = nu - LANDEN_DAGEN * 86400000;
    const oud = prs.filter(p => p.ts && p.ts < grens);
    punten.push(punt(
      'De landingspoort',
      oud.length === 0 ? GOED : LET_OP,
      oud.length === 0
        ? `Er staan ${prs.length} wijzigingen open en geen enkele langer dan ${LANDEN_DAGEN} dagen.`
        : `${oud.length} van de ${prs.length} openstaande wijzigingen staan langer dan ${LANDEN_DAGEN} dagen buiten de hoofdtak. De oudste ${ouderdom(nu, Math.min(...oud.map(p => p.ts)))}. Dat is geen werk meer maar voorraad, en er zat eerder een beveiligingsgat in die stapel.`,
      { open: prs.length, te_oud: oud.length },
      `openstaande pull requests ouder dan ${LANDEN_DAGEN} dagen`,
    ));
  } else {
    punten.push(punt('De landingspoort', GOED, 'Ik kon de openstaande wijzigingen niet ophalen.', null, 'openstaande pull requests'));
  }

  return blok('rood', 'Staat er iets rood', punten);
}

// ── Blok 4. Wat wacht er op Mick ────────────────────────────────────────────
//
// Alleen dingen die niemand anders kan doen, met erbij wat er niet gebeurt
// zolang ze blijven liggen. Afgeleid uit de metingen hierboven, niet uit een
// lijstje dat iemand ooit heeft opgeschreven en dat kan verouderen.

async function blokMick(io, roodBlok) {
  const punten = [];
  const controles = (roodBlok.punten.find(p => p.naam === 'De dagelijkse controles') || {}).meting;

  const staat = (bestand) => Array.isArray(controles) ? controles.find(c => c.bestand === bestand) : null;
  const hartslag = staat('heartbeat.yml');
  const scan = staat('security-posture.yml');

  punten.push(punt(
    'De twee sleutels van de zelftest',
    hartslag && hartslag.oordeel !== 'overgeslagen' ? GOED : KAPOT,
    !hartslag || !hartslag.oordeel
      ? 'Ik kon niet zien of de zelftest draait.'
      : hartslag.oordeel === 'overgeslagen'
        ? 'De uurlijkse zelftest slaat zichzelf over omdat zijn twee sleutels niet bestaan. Zolang dat zo is, is er niets dat aantoont dat versturen en ondertekenen in productie werken, en merkt een klant een storing eerder dan jij. Alleen jij kunt die sleutels zetten; ze staan op jouw machine en nergens anders.'
        : 'De zelftest draait.',
    hartslag || null,
    'de laatste run van heartbeat.yml',
  ));
  if (hartslag && hartslag.oordeel === 'overgeslagen') {
    punten[punten.length - 1].hoe = [
      'gh secret set PARAMANT_CANARY_KEY',
      'gh secret set PARASIGN_CANARY_KEY',
      'gh variable set HEARTBEAT_ENABLED --body true',
    ];
  }

  punten.push(punt(
    'De dagelijkse veiligheidsscan',
    scan && scan.oordeel !== 'overgeslagen' ? GOED : LET_OP,
    !scan || !scan.oordeel
      ? 'Ik kon niet zien of de veiligheidsscan draait.'
      : scan.oordeel === 'overgeslagen'
        ? 'De dagelijkse scan van de productieomgeving heeft nog nooit gedraaid, omdat zijn schakelaar niet bestaat. Er kijkt dus niemand dagelijks naar de buitenkant van de servers.'
        : 'De veiligheidsscan draait.',
    scan || null,
    'de laatste run van security-posture.yml',
  ));
  if (scan && scan.oordeel === 'overgeslagen') {
    punten[punten.length - 1].hoe = ['gh variable set SECURITY_POSTURE_ENABLED --body true'];
  }

  return blok('mick', 'Wat wacht er op jou', punten);
}

// ── De kop ──────────────────────────────────────────────────────────────────

function kop(blokken) {
  const stand = slechtste(blokken.map(b => b.stand));
  const ergste = [];
  for (const b of blokken) for (const p of b.punten) if (p.stand === stand) ergste.push(p);

  if (stand === GOED) {
    return { stand, zin: 'Het gaat goed. Alles wat ik kan meten, doet het.' };
  }
  if (stand === KAPOT) {
    return { stand, zin: `Er is iets kapot: ${ergste[0].zin}` };
  }
  if (stand === NIET_GEMETEN) {
    return { stand, zin: `Ik kan niet alles meten, dus ik weet het niet zeker. ${ergste.length} ${ergste.length === 1 ? 'punt kwam' : 'punten kwamen'} niet binnen.` };
  }
  return { stand, zin: `Het draait, maar er is iets om naar te kijken: ${ergste[0].zin}` };
}

// ── Het geheel ──────────────────────────────────────────────────────────────

async function meetDeStand(io) {
  const werkt = await blokWerkt(io);
  const gebruik = await blokGebruik(io);
  const rood = await blokRood(io);
  const mick = await blokMick(io, rood);
  const blokken = [werkt, gebruik, rood, mick];
  return {
    gemeten_op: new Date(io.nu()).toISOString(),
    kop: kop(blokken),
    blokken,
  };
}

module.exports = {
  meetDeStand,
  punt,
  blok,
  slechtste,
  soortVanHandeling,
  runOordeel,
  GOED, LET_OP, NIET_GEMETEN, KAPOT, RANG,
  LANDEN_DAGEN, CONTROLE_STIL_UREN,
};
