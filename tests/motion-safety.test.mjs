// prefers-reduced-motion mag beweging weghalen en nooit een toestand.
//
// De valkuil is bekend en hij is stil. Een blok dat binnenkomt met
// `animation: rise-in ... both` staat op opacity 0 in zijn eerste keyframe. Zet
// je onder `reduce` alleen de duur op bijna nul, dan is dat meestal goed. Zet
// iemand er `animation: none` neer, dan blijft het element op de waarde staan
// die de auteur eromheen zette, en op een pagina met `.rise-in` op elke kaart
// is dat een leeg scherm voor precies de bezoeker die om minder beweging
// vroeg. Dat is geen smaakverschil, dat is WCAG 2.3.3 aan de ene kant en een
// onbruikbare pagina aan de andere.
//
// EEN PAGINA, DRIE OPNAMES, EEN VARIABELE. Deze test laadde eerst elke pagina
// twee keer, een keer met en een keer zonder `reduce`, en legde de twee
// lijsten naast elkaar. Dat vergelijkt twee paginaladingen en niet twee
// instellingen: /parashare start 400 ms na het laden een WebGL-globe waarvan
// het aantal knopen op een vast meetmoment in de ene lading wel en in de
// andere nog niet staat, gemeten acht keer op rij 272 tegen 267, en op de
// CI-runner kwam dat binnen twintig seconden nooit tot stilstand. Zo'n
// verschil zegt iets over de runner en niets over de CSS.
//
// Nu wordt elke pagina EEN keer geladen. Als de binnenkomst klaar is:
//
//   A  opname zoals de pagina staat
//   B  page.emulateMedia({ reducedMotion: 'reduce' }), opnieuw opnemen
//   C  terug naar no-preference, nog een keer opnemen
//
// Dezelfde DOM, dezelfde scripts, dezelfde toestand. Het enige dat tussen A en
// B verandert is de media query, en dat is precies wat hier op de proef staat.
// C is de controle: een knoop die door een timer of een poll van de pagina
// verdwijnt is in C ook weg, en telt dus niet als schade van `reduce`. Wat
// alleen in B weg is, is door de CSS weggehaald.
//
// WAT ER WORDT VERGELEKEN zijn de elementen die een layoutbox hebben. Een
// element in een display:none-tak zet niets op het scherm, en daar valt dus
// ook niets aan te verliezen. Dat is geen versoepeling maar een scherpere
// claim: uit beeld verdwijnen IS de fout waar dit bestand voor bestaat, dus
// een element dat in A en C een box heeft en in B niet meer, is hier rood.
//
// Elementen met een ONEINDIGE animatie doen niet mee aan de dekkingsvergelijking.
// De homepage draait sinds #377 een cyclus van zestien seconden; een opname op
// een vast moment landt daar op een willekeurig frame. Ze worden geteld en als
// diagnose afgedrukt, en of ze een box hebben wordt nog steeds streng geeist.
//
// Run: node --test tests/motion-safety.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.ico':'image/x-icon' };
const aliases = {
  '/':'/index.html', '/pricing':'/pricing.html', '/dashboard':'/dashboard.html',
  '/sign':'/sign.html', '/parashare':'/parashare.html', '/signup':'/signup.html',
  '/account':'/account.html', '/login':'/auth/login.html',
};

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

// Lang genoeg dat elke binnenkomst klaar is; de langste in het systeem is
// --duration-slow op 320ms.
const ENTRANCE = 1500;
// Een media query landt op de volgende style recalc. Ruim genomen, want een
// paar honderd milliseconden per pagina kost hier niets.
const RECALC = 400;

// Draait in de pagina. Van elk element in de body: waar het staat, of het een
// layoutbox heeft, en wat het laat zien.
const collect = () => Array.from(document.querySelectorAll('body *')).map((el) => {
  const cs = getComputedStyle(el);
  const box = el.getBoundingClientRect();
  // De dekking wordt afgerond op een tiende: een element dat in een pulse
  // staat is geen fout, een element dat weg is wel.
  const opacity = Number(cs.opacity) >= 0.99 ? 1 : Math.round(Number(cs.opacity) * 10) / 10;
  // Een pad in plaats van een volgnummer, zodat een knoop die er tussenuit
  // valt niet alles daarachter een plaats opschuift.
  const path = [];
  for (let node = el; node && node.tagName !== 'BODY'; node = node.parentElement) {
    const among = node.parentElement ? Array.prototype.indexOf.call(node.parentElement.children, node) : 0;
    path.unshift(`${node.tagName.toLowerCase()}(${among + 1})`);
  }
  return {
    key: path.join('>'),
    tag: el.tagName,
    rendered: el.getClientRects().length > 0,
    visibility: cs.visibility,
    opacity,
    w: Math.round(box.width),
    h: Math.round(box.height),
    looping: cs.animationIterationCount.split(',').some((n) => n.trim() === 'infinite'),
  };
});

async function measure(slug) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
  await page.goto(ORIGIN + slug, { waitUntil: 'networkidle' });
  await page.waitForTimeout(ENTRANCE);
  const moving = await page.evaluate(collect);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForTimeout(RECALC);
  const still = await page.evaluate(collect);
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.waitForTimeout(RECALC);
  const control = await page.evaluate(collect);
  await page.close();
  return { moving, still, control };
}

for (const slug of Object.keys(aliases)) {
  test(`${slug} loses no state under prefers-reduced-motion`, async (t) => {
    const { moving, still, control } = await measure(slug);
    const byKey = new Map(still.map((row) => [row.key, row]));
    const afterwards = new Map(control.map((row) => [row.key, row]));
    const lost = [];
    let compared = 0;
    let looping = 0;
    let offscreen = 0;
    let volatile_ = 0;
    for (const a of moving) {
      if (!a.rendered) { offscreen++; continue; }
      // De controle-opname. Wat de pagina zelf weghaalt tussen twee metingen
      // door is in C ook weg en is geen schade van reduce.
      const c = afterwards.get(a.key);
      if (!c || !c.rendered) { volatile_++; continue; }
      const b = byKey.get(a.key);
      if (!b) { lost.push(`${a.tag} ${a.key} is gone entirely`); continue; }
      if (!b.rendered) { lost.push(`${a.tag} ${a.key} stopped being rendered (${a.w}x${a.h} without reduce, no layout box with it)`); continue; }
      // Een oneindige animatie heeft geen eindstand om tegen te vergelijken.
      if (a.looping || b.looping) { looping++; continue; }
      compared++;
      if (b.visibility === 'hidden' && a.visibility !== 'hidden') lost.push(`${a.tag} ${a.key} became visibility:hidden`);
      // Dekking mag omhoog (een pulse die stilstaat op vol), nooit omlaag.
      if (b.opacity < a.opacity) lost.push(`${a.tag} ${a.key} faded from opacity ${a.opacity} to ${b.opacity}`);
      if (a.w > 0 && a.h > 0 && (b.w === 0 || b.h === 0)) lost.push(`${a.tag} ${a.key} collapsed from ${a.w}x${a.h} to ${b.w}x${b.h}`);
    }
    assert.deepEqual(lost, [],
      `${slug} loses state when the visitor asks for less motion:\n  ${lost.join('\n  ')}\n`
      + 'Reduced motion must shorten animations, not switch them off on an element whose first keyframe is invisible.');
    assert.ok(compared > 0, `${slug}: nothing was compared. The page rendered nothing, or every element on it moves forever.`);
    t.diagnostic(`${slug}: ${compared} rendered elements compared, ${looping} skipped as endlessly animating, ${offscreen} in a display:none branch, ${volatile_} changed by the page itself`);
  });
}

test.after(async () => { await browser.close(); server.close(); });
