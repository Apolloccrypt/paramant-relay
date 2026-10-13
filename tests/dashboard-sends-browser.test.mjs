// HET OVERZICHT VAN DE AFZENDER, IN EEN ECHTE BROWSER.
//
// Dit is de derde reis: de afzender komt de volgende dag terug en wil weten wie
// het heeft opgehaald. Dat is precies wat het product verkoopt boven een
// gedeelde downloadlink, en het was het enige scherm van de drie dat nooit in
// een browser was geopend.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HIER, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml' };

const checks = [];
const ok = (naam, cond, detail='') => checks.push({ naam, pass: !!cond, detail: String(detail) });

// Wat de server antwoordt, per test omzetbaar.
let sendsAntwoord = { status: 200, body: { sends: [] } };
let detailAntwoord = { status: 200, body: {} };

const VAST = {
  '/api/user/session/verify': { authenticated: true, email: 'anna@zorg.test' },
  '/api/user/me': { email: 'anna@zorg.test', plan: 'pro', usage_purpose: 'organisation' },
  '/api/user/account': { email: 'anna@zorg.test', plan: 'pro', api_key_masked: 'pgp...cafe',
                         created_at: '2026-06-01T10:00:00.000Z', sessions: [] },
  '/api/user/documents': { documents: [] },
  '/api/user/billing/summary': {},
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const stuur = (status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  if (u.pathname === '/api/user/sends') return stuur(sendsAntwoord.status, sendsAntwoord.body);
  if (/^\/api\/user\/sends\/[^/]+$/.test(u.pathname)) return stuur(detailAntwoord.status, detailAntwoord.body);
  if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/v2/')) {
    for (const [pad, body] of Object.entries(VAST)) if (u.pathname === pad) return stuur(200, body);
    return stuur(200, {});
  }
  const bestand = path.join(ROOT, u.pathname === '/dashboard' ? 'dashboard.html'
    : u.pathname === '/en/dashboard' ? 'en/dashboard.html'
    : u.pathname === '/' ? 'index.html' : u.pathname);
  if (!bestand.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(bestand, (e, body) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(bestand)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const fouten = [];

async function open(pad = '/dashboard') {
  const page = await browser.newPage();
  page.on('pageerror', (e) => fouten.push(String(e).slice(0, 160)));
  await page.goto(`${ORIGIN}${pad}`);
  await page.waitForTimeout(800);
  return page;
}

// ── 1. Twintig ontvangers, acht nog niet opgehaald ─────────────────────────
const mensen = Array.from({ length: 20 }, (_, i) => ({
  email: `partner${i}@extern.test`,
  status: i < 12 ? 'collected' : 'waiting',
  picked_up_at: i < 12 ? '2026-09-22T09:15:00.000Z' : null,
  invited_at: '2026-09-22T08:00:00.000Z',
  reminders: 0,
}));
sendsAntwoord = { status: 200, body: { sends: [{
  id: 'snd_abc', filename: 'jaarrekening-2025.pdf', status: 'open',
  count: 20, collected: 12, outstanding: 8,
  created_at: '2026-09-22T08:00:00.000Z', expires_at: '2026-09-23T08:00:00.000Z',
}] } };
detailAntwoord = { status: 200, body: { id: 'snd_abc', filename: 'jaarrekening-2025.pdf',
  count: 20, collected: 12, outstanding: 8, recipients: mensen } };

let page = await open();
ok('de verzending staat op het dashboard',
   ((await page.textContent('body')) || '').includes('jaarrekening-2025.pdf'));
const lijf = (await page.textContent('body')) || '';
ok('en het zegt hoeveel mensen er nog niet ophaalden', /8 mensen hebben het nog niet opgehaald/.test(lijf),
   (lijf.match(/[^.]*opgehaald[^.]*/) || [''])[0].slice(0, 80));
// Dezelfde zin op de Engelse kopie, die hetzelfde script laadt.
{
  const en = await open('/en/dashboard');
  const lijfEn = (await en.textContent('body')) || '';
  ok('en op /en/dashboard in het Engels', /8 people have not collected/.test(lijfEn),
     (lijfEn.match(/[^.]*collected[^.]*/) || [''])[0].slice(0, 80));
  await en.close();
}

// ── 2. Wie het heeft opgehaald, per persoon ────────────────────────────────
const rij = await page.$('[data-pa-action="send-open"], .dh-document-open, #dh-sends .dh-row');
if (rij) { await rij.click(); await page.waitForTimeout(500); }
const naOpenen = (await page.textContent('body')) || '';
ok('na het openen staan de mensen er per naam',
   naOpenen.includes('partner0@extern.test') && naOpenen.includes('partner19@extern.test'));
ok('en er staat NERGENS een token of een sleutel op het scherm',
   !/token|wrapped|email_hash/i.test(naOpenen));

// ── 3. Tikdoelen op een telefoon ───────────────────────────────────────────
await page.setViewportSize({ width: 390, height: 844 });
await page.waitForTimeout(300);
const teKlein = await page.evaluate(() => {
  const uit = [];
  for (const b of document.querySelectorAll('.dh-send-person button, .dh-rowbtn')) {
    const r = b.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (r.height < 32) uit.push(`${(b.textContent || '').trim().slice(0, 12)}=${Math.round(r.height)}px`);
  }
  return uit;
});
ok('de knoppen per persoon zijn op een telefoon aan te tikken (32px of meer)',
   teKlein.length === 0, teKlein.join(', '));
await page.close();

// ── 4. DE STILLE VERDWIJNING ───────────────────────────────────────────────
// Faalt de aanroep, dan verdween de hele sectie. Niet te onderscheiden van
// "ik heb nooit iets verstuurd", en de Refresh-knop zat in de verborgen
// sectie, dus er was geen weg terug.
sendsAntwoord = { status: 500, body: { error: 'boom' } };
page = await open();
const sectieWeg = await page.evaluate(() => {
  const s = document.getElementById('dh-sends-section');
  return !s || s.hidden || getComputedStyle(s).display === 'none';
});
const tekstBijFout = (await page.textContent('body')) || '';
ok('bij een storing verdwijnt het overzicht niet spoorloos',
   !sectieWeg, 'de sectie is verborgen: de afzender ziet niets en kan niets');
ok('en er staat een zin die uitlegt wat er aan de hand is',
   /not be read|could not|opnieuw|try again|nothing has changed/i.test(tekstBijFout),
   'geen uitleg gevonden');
await page.close();

// ── 5. Geen verzendingen is iets anders dan een storing ────────────────────
sendsAntwoord = { status: 200, body: { sends: [] } };
page = await open();
const leegVerborgen = await page.evaluate(() => {
  const s = document.getElementById('dh-sends-section');
  return !s || s.hidden || getComputedStyle(s).display === 'none';
});
ok('zonder verzendingen blijft de sectie terecht weg', leegVerborgen);
await page.close();

ok('geen javascriptfouten', fouten.length === 0, fouten.join(' | ').slice(0, 250));

await browser.close();
server.close();

let gezakt = 0;
for (const c of checks) {
  console.log(`${c.pass ? 'ok  ' : 'FOUT'} - ${c.naam}${c.pass || !c.detail ? '' : '  [' + c.detail + ']'}`);
  if (!c.pass) gezakt++;
}
console.log(`\n${checks.length - gezakt}/${checks.length} geslaagd`);
process.exit(gezakt ? 1 : 0);
