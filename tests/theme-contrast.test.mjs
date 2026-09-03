// Elk tekstpaar op elke pagina, gemeten in plaats van aangenomen.
//
// Waarom dit bestand bestaat. Op de commit hiervoor haalde de site 3544 van de
// 8896 gemeten tekstparen niet: 336 unieke combinaties onder WCAG AA, in de
// LICHTE modus, op de pagina's die een koper als eerste ziet. Een token deed
// het meeste werk: --ink-dim stond op rgba(11,58,106,.65) en landt daarmee op
// 3.96:1 tegen de voet, 4.09:1 tegen het papier en 4.18:1 op een witte kaart.
// Drie keer net onder de 4.5 die AA vraagt, en drie keer op de tekst die de
// prijs, de limiet en de kleine letter draagt. Dat is niet te zien met het
// blote oog en het is wel het verschil tussen voldoen en niet voldoen.
//
// design-system.css v4.1 zet --ink-dim (en de v3-aliassen --lime-dim en
// --black-dim) op --ink-2, #40505F, 7.95:1 op het papier. Wat er van die 336
// overblijft staat hieronder met naam en toenaam in KNOWN_LIGHT, en alle
// overgebleven gevallen zitten in het style-blok van een pagina en niet in het
// ontwerpsysteem. Die lijst mag korter worden en nooit langer: een nieuwe regel
// eronder is een regressie, ook als niemand hem ziet.
//
// De meting zelf. Voor elk tekstknooppunt wordt de tekstkleur afgevlakt tegen
// de eerste ondoorzichtige achtergrond erboven, precies zoals een browser hem
// samenstelt, en dan door de WCAG 2.1 relatieve-luminantie formule gehaald.
// 4.5:1 voor gewone tekst, 3:1 voor groot (>=24px, of >=18.66px vetgedrukt).
//
// GEEN DONKERE MODUS. Een eerdere versie van dit bestand mat ook donker, tegen
// een donkere tokenset die achter [data-theme] stond zonder schakelaar in de
// nav. Die laag is uit de tak gehaald: hij was op /security, /pricing en het
// dashboard onleesbaar (wit op lime, 1.07:1) en kostte 31 KB op elke pagina.
// Wat hier overblijft is de meting die wel iets bewaakt wat een bezoeker
// vandaag ziet. Komt donker terug, dan komt de tweede helft van dit bestand
// mee terug, met een schakelaar en met nul open gevallen.
//
// Run: node --test tests/theme-contrast.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2','.json':'application/json','.ico':'image/x-icon' };

// Dezelfde routes die nginx serveert, zodat de test dezelfde URL's loopt als
// een bezoeker. deploy/nginx-paramant-live.conf:105 zet /help op een index.
const aliases = {
  '/':'/index.html', '/pricing':'/pricing.html', '/dashboard':'/dashboard.html',
  '/parasign':'/parasign.html', '/parasend':'/parasend.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/account':'/account.html',
  '/security':'/security.html', '/trust':'/trust.html', '/docs':'/docs.html',
  '/about':'/about.html', '/help':'/help/index.html', '/download':'/download.html',
  '/login':'/auth/login.html',
};
const PAGES = Object.keys(aliases);
const SIZES = [[390, 844], [1440, 900]];

// Wat er na de tokenfix overbleef, elk met de reden dat hij er nog staat.
// Alles wat hier niet in staat is een regressie. Het formaat is pagina +
// selector, want de kleurwaarden veranderen mee met het merk en de plek niet.
//
// Geen van de vijf komt uit het ontwerpsysteem: alle vijf staan als letterlijke
// kleur in het style-blok van de pagina zelf, en alle vijf stonden er al voor
// deze tak. Ze horen bij de groep die zo'n scherm onder handen neemt, niet bij
// een tokenronde die geen woord tekst en geen pagina-CSS aanraakt.
//
// De statusregel van /parashare stond hier ook, op rgba(248,250,252,.65),
// bijna-wit op bijna-wit. #381 heeft hem opgelost, dus hij is hier weg. Zo
// hoort deze lijst te bewegen: korter, nooit langer.
const KNOWN_LIGHT = [
  // about.html geeft de primaire knop cobalt tekst op een cobalt vlak.
  { slug: '/about', sel: 'a.btn.btn-primary' },
  // security.html zet het vinkje in lime op papier: 1.16:1. Lime is 1.17 op
  // papier en dus per definitie nooit tekst. Het vinkje is hier bullet en geen
  // inhoud: de zin ernaast draagt de betekenis volledig. Lime hier vervangen is
  // een merkbesluit en geen herstel, dus het staat hier met naam in plaats van
  // dat het stil wordt weggepoetst.
  { slug: '/security', sel: 'span.check' },
  // docs.html zet inline code en links op gekleurde blokken zonder de
  // tekstkleur mee te kantelen. Vier gevallen, alle vier in dat style-blok.
  { slug: '/docs', sel: 'code' },
  { slug: '/docs', sel: 'a' },
  // index.html kreeg met #382 een eigen palet in zijn kritieke CSS, met
  // --hp-ink-3 op #66727F. Op het lichte papier (#FAF8F3) haalt dat 4.69:1, op
  // het tweede papier (#F3F0E8) 4.31:1, en daar staat de mono-kicker boven elke
  // sectie. Gemeten op main, dus hij kwam met die homepage mee en niet hiermee.
  // Eén hex lost het op: #5F6B78 geeft 4.71:1 op het tweede papier. Dat is een
  // wijziging aan de homepage van #382 en hoort in die tak, niet in deze.
  { slug: '/', sel: 'p.hp-kicker' },
];

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = aliases[pathname] || pathname;
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

// Draait in de pagina. Vlakt elke tekstkleur af tegen de stapel achtergronden
// erboven tot de eerste ondoorzichtige, en rekent WCAG 2.1.
const probe = () => {
  const parse = (c) => { const m = c.match(/[\d.]+/g); if (!m) return null; return { r:+m[0], g:+m[1], b:+m[2], a: m[3] === undefined ? 1 : +m[3] }; };
  const over = (fg, bg) => ({ r: fg.r*fg.a + bg.r*(1-fg.a), g: fg.g*fg.a + bg.g*(1-fg.a), b: fg.b*fg.a + bg.b*(1-fg.a), a: 1 });
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); }; return 0.2126*f(c.r) + 0.7152*f(c.g) + 0.0722*f(c.b); };
  const ratio = (a, b) => { const l1 = lum(a), l2 = lum(b); return (Math.max(l1,l2)+0.05) / (Math.min(l1,l2)+0.05); };
  const bgOf = (el) => {
    const stack = [];
    for (let node = el; node; node = node.parentElement) {
      const c = parse(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0) { stack.push(c); if (c.a === 1) break; }
    }
    let base = { r:255, g:255, b:255, a:1 };
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };
  const out = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.nodeValue.trim()) continue;
    const el = n.parentElement;
    if (!el || seen.has(el)) continue;
    seen.add(el);
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) continue;
    const box = el.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) continue;
    const fg = parse(cs.color);
    if (!fg) continue;
    const bg = bgOf(el);
    const c = ratio(over(fg, bg), bg);
    const px = parseFloat(cs.fontSize);
    const need = (px >= 24 || (px >= 18.66 && Number(cs.fontWeight) >= 700)) ? 3 : 4.5;
    if (c >= need - 0.005) { out.push(null); continue; }
    const cls = (el.className && typeof el.className === 'string') ? '.' + el.className.trim().split(/\s+/).slice(0, 3).join('.') : '';
    out.push({
      c: Math.round(c*100)/100, need,
      sel: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + cls,
      text: n.nodeValue.replace(/\s+/g, ' ').trim().slice(0, 48),
      color: cs.color, bg: `rgb(${Math.round(bg.r)}, ${Math.round(bg.g)}, ${Math.round(bg.b)})`,
    });
  }
  return { measured: out.length, fails: out.filter(Boolean) };
};

async function scan(slug) {
  const rows = [];
  let measured = 0;
  for (const [width, height] of SIZES) {
    const page = await browser.newPage({ viewport: { width, height }, colorScheme: 'light' });
    await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
    await page.goto(ORIGIN + slug, { waitUntil: 'networkidle' });
    // Een kleurtransitie die nog loopt levert een kleur op die op geen enkel
    // moment de bedoeling was. Deze test sampelde ooit na 120ms terwijl .btn
    // 200ms overgangstijd heeft, en gaf daardoor op de ene machine groen en op
    // CI rood op dezelfde code. Transities gaan hier dus uit, en daarna is er
    // ruim tijd voor de binnenkomstanimaties, waarvan de langste 320ms duurt.
    await page.addStyleTag({ content: '*,*::before,*::after{transition:none !important}' });
    await page.waitForTimeout(450);
    const result = await page.evaluate(probe);
    measured += result.measured;
    for (const row of result.fails) rows.push({ ...row, width });
    await page.close();
  }
  // Eén regel per unieke combinatie van plek en kleurenpaar; 390 en 1440 tellen
  // hetzelfde geval anders twee keer.
  const uniq = [...new Map(rows.map((r) => [`${r.sel}|${r.color}|${r.bg}`, r])).values()];
  return { measured, uniq };
}

test('every page clears WCAG AA in light, and the known page defects do not grow', async (t) => {
  let measured = 0;
  const unexpected = [];
  const stillThere = new Set();
  for (const slug of PAGES) {
    const result = await scan(slug);
    measured += result.measured;
    for (const hit of result.uniq) {
      const known = KNOWN_LIGHT.find((k) => k.slug === slug && k.sel === hit.sel);
      if (known) { stillThere.add(`${slug} ${hit.sel}`); continue; }
      unexpected.push(`${slug} ${hit.sel}: ${hit.c}:1 (needs ${hit.need}), ${hit.color} on ${hit.bg}, "${hit.text}"`);
    }
  }
  t.diagnostic(`light: ${measured} text pairs measured across ${PAGES.length} pages at 390 and 1440`);
  t.diagnostic(`light: ${stillThere.size} of the ${KNOWN_LIGHT.length} known page defects still present`);
  assert.deepEqual(unexpected, [],
    `New contrast failures in light mode. Every one of these is below WCAG AA and none of them is on the known list:\n  ${unexpected.join('\n  ')}\n`
    + 'Fix the colour, or, if it is a deliberate page-owned defect that predates this run, add it to KNOWN_LIGHT with the reason. Do not loosen the ratio.');
});

test.after(async () => { await browser.close(); server.close(); });
