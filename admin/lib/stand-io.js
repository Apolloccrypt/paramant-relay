'use strict';
// De buitenwereld voor lib/stand.js: relays, de eigen site, redis en de
// openbare GitHub-API.
//
// Twee dingen zijn hier met opzet zo:
//
// * GitHub wordt zonder sleutel bevraagd. paramant-relay is een openbare repo,
//   dus de uitslag van een workflow en de lijst openstaande wijzigingen zijn
//   openbaar. Geen token betekent geen extra geheim dat gezet, bewaard of
//   gelekt kan worden, en het betekent dat deze pagina niets nieuws mag dat de
//   admin nog niet mocht. De prijs is de anonieme limiet van 60 vragen per uur,
//   en die wordt met een korte cache in redis ruim onder gebleven.
// * Elke functie hier geeft bij twijfel `null` terug en verzint nooit iets.
//   lib/stand.js zet een punt zonder meting automatisch op "niet gemeten", dus
//   een fout hier eindigt zichtbaar op de pagina en niet als groen bolletje.

const crypto = require('crypto');

const GH_API = 'https://api.github.com';
const GH_CACHE_S = 300;
const WEB_TIMEOUT_MS = 8000;

function repoNaam() {
  return process.env.PARAMANT_REPO || 'Apolloccrypt/paramant-relay';
}

function siteUrl() {
  return (process.env.PARAMANT_SITE_URL || 'https://paramant.app').replace(/\/$/, '');
}

// De accounts die als eigen zelftest gelden. Leeg is een geldige stand en de
// pagina zegt dat er dan alleen op het kanarie-kenmerk gefilterd wordt.
function zelftestAccounts() {
  return String(process.env.STAND_ZELFTEST_ACCOUNTS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
}

// `binair: true` levert de ruwe bytes. Dat is niet hetzelfde als de tekst door
// een Buffer halen: een tekstdecodering vervangt alles wat geen geldige UTF-8
// is door een vervangingsteken, en dan zou de vergelijking "kwamen dezelfde
// bytes terug" slagen op bytes die onderweg kapot zijn gegaan.
async function haal(url, opts = {}) {
  const t0 = Date.now();
  const r = await fetch(url, {
    ...opts,
    signal: AbortSignal.timeout(opts.timeoutMs || WEB_TIMEOUT_MS),
    headers: { 'User-Agent': 'paramant-stand', ...(opts.headers || {}) },
  });
  if (opts.binair) {
    const bytes = Buffer.from(await r.arrayBuffer());
    return { status: r.status, bytes, ms: Date.now() - t0 };
  }
  const text = await r.text();
  return { status: r.status, text, ms: Date.now() - t0 };
}

// Een GitHub-vraag met een korte cache. Een mislukte vraag wordt niet gecachet
// en niet gladgestreken: hij gooit, en het punt erboven wordt "niet gemeten".
function maakGh(redis) {
  return async function gh(pad) {
    const sleutel = 'paramant:stand:gh:' + crypto.createHash('sha256').update(pad).digest('hex').slice(0, 32);
    try {
      const uit = await redis().get(sleutel);
      if (uit) return JSON.parse(uit);
    } catch { /* geen cache is geen fout, dan vragen we het opnieuw */ }

    const r = await haal(GH_API + pad, { headers: { Accept: 'application/vnd.github+json' } });
    if (r.status !== 200) throw new Error(`github ${r.status} op ${pad}`);
    const body = JSON.parse(r.text);
    try { await redis().set(sleutel, JSON.stringify(body), { EX: GH_CACHE_S }); } catch { /* cache is optioneel */ }
    return body;
  };
}

// De echte proef: een blok gaat erin, moet er byte voor byte uitkomen, en moet
// daarna vernietigd zijn. Dezelfde drie stappen als de kanarie in
// scripts/heartbeat/parasend.mjs, want dat is de belofte van het product.
//
// Deze proef schrijft een regel in het openbare transparantielogboek. Daarom
// draait hij alleen als iemand erom vraagt en niet bij elk bezoek aan de
// pagina: een statuspagina die zichzelf meetelt is precies hoe 485 handelingen
// in augustus bijna allemaal de eigen robot bleken te zijn.
async function doeProef(site) {
  const id = crypto.randomUUID();
  const buf = Buffer.from(`stand-proef ${id} ${new Date().toISOString()}`);
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  const ts = Date.now();
  const stappen = [];

  const mislukt = (reden) => ({ ok: false, ts, reden, id: `stand-${id}`, stappen });

  let op;
  try {
    op = await haal(`${site}/v2/anon-inbound`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash, payload: buf.toString('base64'), ttl_ms: 60000 }),
    });
  } catch (e) { return mislukt(`het versturen liep vast (${e.message})`); }
  stappen.push({ stap: 'versturen', status: op.status, ms: op.ms });
  if (op.status !== 200) return mislukt(`de relay weigerde het bestand met antwoord ${op.status}`);

  let uit;
  try { uit = JSON.parse(op.text); } catch { return mislukt('de relay gaf geen leesbaar antwoord op het versturen'); }
  if (uit.hash !== hash) return mislukt('de relay bewaarde het bestand onder een andere naam dan het meekreeg');
  const token = uit.download_token;
  if (!token) return mislukt('er kwam geen ophaallink terug, dus een ontvanger zou er niet bij kunnen');

  let neer;
  try { neer = await haal(`${site}/v2/dl/${token}/get`, { binair: true }); } catch (e) { return mislukt(`het ophalen liep vast (${e.message})`); }
  stappen.push({ stap: 'ophalen', status: neer.status, ms: neer.ms });
  if (neer.status !== 200) return mislukt(`het ophalen mislukte met antwoord ${neer.status}`);
  const terug = crypto.createHash('sha256').update(neer.bytes).digest('hex');
  if (terug !== hash) return mislukt('er kwamen andere bytes terug dan er in gingen');

  let weer;
  try { weer = await haal(`${site}/v2/dl/${token}/get`); } catch (e) { return mislukt(`de vernietigingscontrole liep vast (${e.message})`); }
  stappen.push({ stap: 'nog een keer ophalen', status: weer.status, ms: weer.ms });
  if (weer.status !== 410) return mislukt(`het bestand overleefde het lezen: een tweede keer ophalen gaf ${weer.status} in plaats van 410. Wat eenmalig heet, is dat niet`);

  return {
    ok: true, ts, id: `stand-${id}`, bytes: buf.length, hash_heen: hash, hash_terug: terug,
    ms: stappen.reduce((n, s) => n + (s.ms || 0), 0), stappen,
  };
}

// Bouwt het io-object dat lib/stand.js verwacht.
//
// `relayFetch` en `sectors` komen uit server.js, zodat deze module niets weet
// van de admin-token en er geen tweede plek ontstaat waar dat geheim leeft.
function maakIo({ redis, relayFetch, sectors, adminToken }) {
  const site = siteUrl();
  const gh = maakGh(redis);
  const repo = repoNaam();

  return {
    nu: () => Date.now(),
    site,
    sectors,
    zelftestAccounts: zelftestAccounts(),

    relay: (sector, pad, opts = {}) =>
      relayFetch(sector, pad, 'GET', null, false, adminToken, !!opts.internal),

    web: (url) => haal(url),

    // Alle accounts over alle relays heen, ontdubbeld door de aanroeper.
    async sleutels() {
      const uit = [];
      let gelukt = 0;
      await Promise.all(sectors.map(async (s) => {
        try {
          const r = await relayFetch(s, '/v2/admin/usage', 'GET', null, false, adminToken, true);
          if (r.status === 200 && r.body && Array.isArray(r.body.accounts)) {
            gelukt++;
            uit.push(...r.body.accounts);
          }
        } catch { /* een relay die niet antwoordt telt niet mee */ }
      }));
      if (gelukt === 0) throw new Error('geen enkele relay gaf een accountlijst');
      return uit;
    },

    // De audittrail over een venster. Elke regel is JSON zoals lib/audit.js
    // hem wegschrijft; een regel die niet te lezen is wordt overgeslagen en
    // niet geraden.
    async auditRegels(vanafMs) {
      const ruw = await redis().zRangeByScore('paramant:audit:global', vanafMs, '+inf');
      const uit = [];
      for (const r of ruw) {
        try { uit.push(JSON.parse(r)); } catch { /* onleesbare regel telt niet mee */ }
      }
      return uit;
    },

    async laatsteProef() {
      const ruw = await redis().get('paramant:stand:proef');
      return ruw ? JSON.parse(ruw) : null;
    },

    async bewaarProef(p) {
      await redis().set('paramant:stand:proef', JSON.stringify(p));
    },

    doeProef: () => doeProef(site),

    // De laatste run van een workflow. `tak` mag null zijn voor "welke tak dan
    // ook", wat nodig is voor de geplande controles: die draaien op main maar
    // worden door GitHub niet altijd aan een tak gehangen.
    async laatsteRun(bestand, tak) {
      const q = new URLSearchParams({ per_page: '1' });
      if (tak) q.set('branch', tak);
      const body = await gh(`/repos/${repo}/actions/workflows/${bestand}/runs?${q}`);
      const run = (body.workflow_runs || [])[0];
      if (!run) return null;
      return {
        status: run.status,
        conclusion: run.conclusion,
        ts: Date.parse(run.updated_at || run.created_at) || null,
        nummer: run.run_number,
      };
    },

    async hoofdCommit() {
      const body = await gh(`/repos/${repo}/commits/main`);
      return body.sha || null;
    },

    async openPRs() {
      const body = await gh(`/repos/${repo}/pulls?state=open&per_page=100`);
      return body.map(p => ({ nummer: p.number, ts: Date.parse(p.created_at) || null }));
    },

    async codeManifest() {
      const r = await haal(`${site}/v1/code-manifest`);
      if (r.status !== 200) throw new Error(`code-manifest gaf ${r.status}`);
      return JSON.parse(r.text);
    },
  };
}

module.exports = { maakIo, doeProef, siteUrl, repoNaam, zelftestAccounts };
