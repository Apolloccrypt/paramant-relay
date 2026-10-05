// HET VERZENDSCHERM, IN EEN ECHTE BROWSER.
//
// Hier typt de klant zijn twintig adressen in. De bug die dit vangt zat er tot
// vanmiddag in: setSendMode draaide alleen op een klik, dus de pagina opende
// met stand 'live' terwijl de ontvangerskaart zichtbaar was. Twintig adressen
// invullen, op de live-knop drukken, en niemand kreeg post. Dat is geen
// storing die iemand meldt, dat is een klant die denkt dat het product niet
// werkt.
//
// Deze test opent de echte pagina en kijkt wat een mens ziet. Geen relay
// nodig: het gaat hier om het scherm, niet om de verzending.

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

// De pagina praat met een paar endpoints voordat ze bruikbaar is. Die worden
// hier beantwoord zodat niets faalt om een andere reden dan de reden onder test.
const ANTWOORDEN = {
  '/api/user/session/verify': { authenticated: true, email: 'anna@zorg.test' },
  '/api/user/me': { email: 'anna@zorg.test', plan: 'pro' },
  '/api/user/account': { email: 'anna@zorg.test', plan: 'pro', api_key_masked: 'pgp...cafe' },
  '/v2/check-key': { valid: true, plan: 'pro', sector: 'health' },
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  for (const [pad, body] of Object.entries(ANTWOORDEN)) {
    if (u.pathname === pad || u.pathname.endsWith(pad)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(body));
    }
  }
  if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/v2/')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end('{}');
  }
  const bestand = path.join(ROOT, u.pathname === '/parashare' ? 'parashare.html'
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
const page = await browser.newPage();
const fouten = [];
page.on('pageerror', (e) => fouten.push(String(e).slice(0, 160)));

await page.goto(`${ORIGIN}/parashare`);
await page.waitForSelector('#ps-mode-group', { timeout: 15000 });
await page.waitForTimeout(600);   // de pagina doet werk bij het laden

// ── 1. DE BUG DIE HIER ZAT ─────────────────────────────────────────────────
// Sinds 24 september 2026 opent de pagina op "Naar één persoon" met een
// gewone link; de live overdracht is het vinkje Extra veilig. De les van toen
// blijft: een lijstveld mag alleen open staan als de gekozen verzending die
// lijst ook echt gebruikt.
const kaartZichtbaarBijLaden = await page.isVisible('#recipients-input');
ok('bij het laden staat het lijstveld NIET open: de keuze is één persoon',
   !kaartZichtbaarBijLaden,
   kaartZichtbaarBijLaden ? 'het lijstveld staat open bij één persoon' : '');
ok('en "Naar één persoon" staat aangevinkt',
   (await page.getAttribute('#ps-mode-link', 'aria-checked')) === 'true');

await page.check('#ps-extra-safe');
await page.waitForTimeout(200);
ok('met Extra veilig staat er geen adresveld: de ontvanger zit achter het scherm',
   !(await page.isVisible('#recipient-one')) && !(await page.isVisible('#recipients-input')));
await page.uncheck('#ps-extra-safe');

// ── 2. Naar meerdere mensen toont het veld wel ─────────────────────────────
await page.click('#ps-mode-group');
await page.waitForTimeout(200);
ok('na het kiezen van "Naar meerdere mensen" verschijnt het ontvangersveld',
   await page.isVisible('#recipients-input'));
ok('en die kaart is nu de aangevinkte',
   (await page.getAttribute('#ps-mode-group', 'aria-checked')) === 'true');

// ── 3. De teller die meetelt terwijl je typt ───────────────────────────────
const twintig = Array.from({ length: 20 }, (_, i) => `partner${i}@extern.test`).join('\n');
await page.fill('#recipients-input', twintig);
await page.waitForTimeout(300);
const status = await page.textContent('#ps-count');
ok('de teller noemt het aantal dat er staat', /20/.test(status || ''), status);

// Dubbelen horen niet dubbel te tellen.
await page.fill('#recipients-input', 'anna@x.org\nanna@x.org\nANNA@X.ORG\nbob@x.org');
await page.waitForTimeout(300);
const status2 = await page.textContent('#ps-count');
ok('en telt dezelfde persoon in drie schrijfwijzen als een',
   /\b2\b/.test(status2 || ''), status2);

// ── 4. Terug naar één persoon: het lijstveld gaat weer dicht ───────────────
await page.click('#ps-mode-link');
await page.waitForTimeout(200);
ok('terug bij één persoon is het lijstveld weer weg',
   !(await page.isVisible('#recipients-input')));

// ── 5. Wat een mens op het eerste scherm ziet ──────────────────────────────
const zichtbaar = await page.evaluate(() => {
  const uit = [];
  for (const el of document.querySelectorAll('button, input, select, textarea, a[href]')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0 && r.top < window.innerHeight) uit.push(el.tagName.toLowerCase());
  }
  return uit.length;
});
ok('het eerste scherm telt minder dan vijfentwintig bedienbare dingen',
   zichtbaar < 25, zichtbaar + ' bedienbare elementen in beeld');

// ── 6. Techniek hoort niet in het gezicht van de klant ─────────────────────
// ZICHTBARE tekst, niet alles wat in de bron staat. Jargon achter een
// <details> is precies goed: daar zoekt de lezer die het wil, en de rest loopt
// er niet tegenaan. Wat niet mag is het in het gezicht van iemand die alleen
// een dossier wil versturen.
const zichtbareTekst = await page.evaluate(() => {
  const uit = [];
  const loop = (n) => {
    for (const k of n.children) {
      if (k.tagName === 'DETAILS' && !k.open) continue;          // ingeklapt telt niet
      const st = getComputedStyle(k);
      if (st.display === 'none' || st.visibility === 'hidden' || k.hidden) continue;
      if (!k.children.length) { uit.push(k.textContent || ''); continue; }
      loop(k);
    }
  };
  loop(document.body);
  return uit.join(' ');
});
const jargon = ['ML-KEM', 'ECDH', 'ciphertext', 'Blobs in flight', 'pgp_', 'pst_'];
const gevonden = jargon.filter((w) => zichtbareTekst.includes(w));
ok('geen cryptojargon in het gezicht van de klant', gevonden.length === 0, gevonden.join(', '));

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
