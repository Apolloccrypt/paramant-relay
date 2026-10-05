// Geen enkele pagina mag stuk gaan bij laden of bij de eerste aanraking.
//
// Waarom dit bestand bestaat, en wat er GEEN reden voor is.
//
// PR #431 verplaatste `const GLOBE_ACCENT_RGB` naar binnen in initGlobe()
// terwijl _globeApplyState() en _globeBurst() hem van buitenaf lazen. Vanaf die
// merge gooide /parashare "GLOBE_ACCENT_RGB is not defined" bij elke
// animatietik, en dat stond live in deploy 25.
//
// De eerste lezing was: er ontbrak een poort op de pull request. Dat is niet
// waar, en het staat in de logs. tests/product-heartbeat.test.mjs draait wel
// degelijk op pull requests (.github/workflows/product-heartbeat.yml, trigger
// `pull_request`), heet daar `heartbeat - this checkout`, en staat in de
// required status checks van main. Op #431 ging hij rood, om
// 2026-09-04T10:41:28Z, met precies deze regel:
//
//   uncaught GLOBE_ACCENT_RGB is not defined
//   (actions/runs/33864291529/job/100995493049)
//
// #431 is vijftien seconden later gemerged, om 10:41:43Z. Op main staat
// `enforce_admins` uit, dus een merge via de API loopt langs elke verplichte
// check heen zonder een woord te zeggen. Het gat van vannacht zit daar, in een
// instelling, en niet in een ontbrekende test. Deze suite dicht dat gat niet en
// doet alsof ook niet.
//
// Wat deze suite wel toevoegt is bereik. De heartbeat kijkt naar zeven
// pagina's, uitgelogd, op een breedte, en oordeelt bij het laden. Hier gaat
// dezelfde vraag over vijfentwintig pagina's en tweeendertig sessietoestanden,
// in beide thema's, op 390 en 1440, en pas na de eerste vanzelfsprekende klik.
// De fout van #431 zat op /parashare, een pagina die de heartbeat toevallig
// kent. De volgende zit even goed op /account of /developer, en die staan daar
// niet in.
//
// Hij landt vanzelf op de pull request: de stap "Browser suites" in
// .github/workflows/sign-e2e.yml selecteert op `from 'playwright'`.
//
// Wat een fout is:
//   1. een uncaught page error (ReferenceError, SyntaxError, TypeError, ...)
//   2. een unhandled promise rejection
//   3. een console.error
//
// Wat GEEN fout is staat in KNOWN hieronder, met een reden per regel. Die
// lijst mag korter worden en nooit langer.
//
// Run: node --test tests/no-uncaught-errors.test.mjs
import { chromium } from 'playwright';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.woff2':'font/woff2','.woff':'font/woff','.ico':'image/x-icon','.map':'application/json' };

// Dezelfde routes die nginx serveert. De eerste zeventien zijn exact de lijst
// van tests/theme-contrast.test.mjs; daaronder staan de app- en authschermen
// die tests/app-contrast.test.mjs en tests/navigation-shell.test.mjs kennen.
const ALIAS = {
  '/':'/index.html', '/pricing':'/pricing.html', '/dashboard':'/dashboard.html',
  '/parasign':'/parasign.html', '/parasend':'/parasend.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/account':'/account.html',
  '/security':'/security.html', '/trust':'/trust.html', '/docs':'/docs.html',
  '/about':'/about.html', '/help':'/help/index.html', '/download':'/download.html',
  '/login':'/auth/login.html', '/verify':'/verify.html',
  '/developer':'/developer.html', '/ontvang':'/ontvang.html',
  '/gereedschap':'/gereedschap.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html',
  '/auth/backup':'/auth/backup.html', '/auth/request-reset':'/auth/request-reset.html',
  '/auth/reset-confirm':'/auth/reset-confirm.html',
  '/signup/verified':'/signup/verified.html',
};

// states: welke sessietoestanden deze pagina echt anders maken. 'out' is de
// bezoeker zonder sessie, 'in' de ingelogde. Een marketingpagina die niets aan
// de sessie afleest krijgt er een, want de tweede zou dezelfde bytes meten.
const PAGES = [
  { url:'/',          states:['out','in'] },   // signed-in home is een ander scherm (#429)
  { url:'/pricing',   states:['out','in'] },   // pricing-billing.js leest het huidige plan
  { url:'/dashboard', states:['out','in'] },
  { url:'/account',   states:['out','in'] },
  { url:'/sign',      states:['out','in'] },
  { url:'/parashare', states:['out','in'] },   // hier stond de fout van #431
  { url:'/developer', states:['out','in'] },
  { url:'/parasign',  states:['out'] },
  { url:'/parasend',  states:['out'] },
  { url:'/security',  states:['out'] },
  { url:'/trust',     states:['out'] },
  { url:'/docs',      states:['out'] },
  { url:'/about',     states:['out'] },
  { url:'/help',      states:['out'] },
  { url:'/download',  states:['out'] },
  { url:'/verify',    states:['out'] },
  { url:'/gereedschap', states:['out'] },
  { url:'/signup',    states:['out'] },
  { url:'/login',     states:['out'] },
  { url:'/auth/login',         states:['out'] },
  { url:'/auth/setup',         states:['in']  },  // je komt hier met een halve sessie
  { url:'/auth/backup',        states:['in']  },
  { url:'/auth/request-reset', states:['out'] },
  { url:'/auth/reset-confirm', states:['out'] },
  { url:'/signup/verified',    states:['out'] },
  // Met een token dat geen relay accepteert. Genoeg om de pagina zijn echte
  // clientwerk te laten doen; of de relay het kent is hier niet de vraag.
  { url:'/ontvang', query:'?s=inv_00000000000000000000000000000000', states:['out'] },
];

const VIEWPORTS = [{ w:390, h:844 }, { w:1440, h:900 }];
const THEMES = ['light', 'dark'];
const THEME_KEY = 'paramant.theme.v1';   // frontend/js/theme.js

// Bekende, bewust genegeerde meldingen. Elke regel heeft een reden en een
// pagina-filter waar dat kan, zodat hij niet per ongeluk een echte fout
// elders wegpoetst. DEZE LIJST MAG ALLEEN KORTER WORDEN.
const KNOWN = [
  {
    match: /^resource [^ ]+ failed: /,
    why: 'De testserver serveert frontend/ letterlijk en beantwoordt geen /api. Een bestand of endpoint dat hier ontbreekt en op nginx wel bestaat is een tekort van de opstelling, niet van de pagina. Dat een van onze eigen assets 404t is de vierde regel van tests/product-heartbeat.test.mjs en hoort daar thuis, met de vergelijking tegen productie erbij.',
  },
  {
    match: /wss?:\/\/[^ ]*relay\.paramant\.app|WebSocket connection to/i,
    why: 'De relay is een aparte host die in CI niet draait. Een geweigerde socket daarheen zegt niets over de frontend; wat er over die socket hoort te gebeuren staat in scripts/heartbeat/parasend.mjs, tegen de echte relay.',
  },
];

// De lijst begon op vijf. Drie regels (favicon, /api/, net::ERR_*) zijn er na
// de eerste volle run af gehaald omdat geen enkele van de 128 toestanden ze
// nodig had, en een filter dat niets wegneemt kan alleen nog per ongeluk een
// echte fout wegnemen. Dat is de richting waarin deze lijst mag bewegen.
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = ALIAS[pathname] || pathname;
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;

const future = new Date(Date.now() + 30 * 86400000).toISOString();
const ME = {
  email:'demo@example.com', label:'Demo', plan:'pro', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:future, usage_purpose:'organisation',
  api_key_masked:'pgp_****', sessions:[], keys:[], passkeys:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};
const DOCS = { documents:[
  { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement 2026.pdf', status:'sent', created_at:'2026-08-21T10:00:00.000Z', party_count:3, signed_count:0 },
  { id:'env_complete_abcdefghijklmnop', original_filename:'Consultancy contract.pdf', status:'complete', created_at:'2026-08-19T10:00:00.000Z', party_count:2, signed_count:2 },
] };

// Playwright probeert handlers van nieuw naar oud, dus de vangnetregel gaat er
// als eerste in. Zelfde volgorde en dezelfde antwoorden als
// tests/navigation-shell.test.mjs en tests/app-contrast.test.mjs.
async function stub(page, signedIn) {
  const json = (body) => (r) => r.fulfill({ status:200, contentType:'application/json', body });
  await page.route('**/api/**', json('{}'));
  await page.route('**/api/user/**', json('{}'));
  await page.route('**/api/user/session/verify', json(signedIn
    ? '{"authenticated":true,"email":"demo@example.com"}'
    : '{"authenticated":false}'));
  await page.route('**/api/user/me', json(JSON.stringify(ME)));
  await page.route('**/api/user/account', json(JSON.stringify(ME)));
  await page.route('**/api/user/account/**', json('{"keys":[{"label":"Signing key"}],"passkeys":[{"label":"Passkey"}]}'));
  await page.route('**/api/user/documents**', json(JSON.stringify(DOCS)));
  await page.route('**/api/user/dashboard/overview', json('{"documents":[],"usage":{}}'));
  await page.route('**/api/user/billing/status', json(JSON.stringify({ current_plan:'pro', ...ME })));
  await page.route('**/api/user/billing/history', json('{"history":[]}'));
  await page.route('**/api/developer/**', json('{}'));
}

// Draait voordat er ook maar een regel paginascript loopt, want een rejection
// die tijdens het parsen van een module ontstaat is anders al voorbij als de
// test hem wil horen. page.on('pageerror') dekt in Playwright niet elke
// unhandled rejection, dus die wordt hier expliciet opgevangen.
const CATCH_REJECTIONS = () => {
  window.__unhandledRejections = [];
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    window.__unhandledRejections.push(
      (reason && (reason.stack || reason.message)) ? String(reason.stack || reason.message) : String(reason),
    );
  });
};

// De eerste vanzelfsprekende interactie, in deze volgorde: op de telefoon het
// hamburgermenu, anders de eerste tab, anders de eerste knop die niets
// wegnavigeert en niets kapotmaakt. Kiezen gebeurt IN de pagina zodat er geen
// tweede ronde locators overheen hoeft.
const PICK_INTERACTION = (narrow) => {
  const visible = (el) => {
    const box = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return box.width > 1 && box.height > 1 && cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0;
  };
  // Alles wat geld kost, iets weggooit, uitlogt of een bestand vraagt blijft af.
  const FORBIDDEN = /(verwijder|delete|remove|wis\b|log ?uit|uitloggen|log ?out|sign ?out|afmelden|betaal|checkout|upgrade|koop|buy|abonneer|subscribe|opzegg|cancel|annuleer|intrekk|revoke|reset|herstel|verstuur|verzend|send|submit|opslaan|save|bevestig|confirm|download|export)/i;

  if (narrow) {
    const burger = document.querySelector('#nav-hamburger');
    if (burger && visible(burger)) { burger.click(); return 'hamburger'; }
  }
  const tab = Array.from(document.querySelectorAll('[role="tab"], [data-tab], .tab'))
    .find((el) => visible(el) && el.getAttribute('aria-selected') !== 'true' && !el.classList.contains('active'));
  if (tab) { tab.click(); return 'tab ' + (tab.textContent || '').trim().slice(0, 24); }

  const button = Array.from(document.querySelectorAll('button, [role="button"]')).find((el) => {
    if (!visible(el) || el.disabled) return false;
    if (el.closest('a')) return false;
    if (el.tagName === 'BUTTON' && el.type === 'submit') return false;
    if (el.hasAttribute('href') || el.hasAttribute('download')) return false;
    const label = ((el.textContent || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('data-act') || '')).trim();
    if (FORBIDDEN.test(label)) return false;
    // Een knop die een <input type=file> opent laat de test op een dialoog wachten.
    if (el.closest('label')?.querySelector('input[type=file]')) return false;
    return true;
  });
  if (button) { button.click(); return 'button ' + ((button.textContent || '').trim().slice(0, 24) || button.id); }
  return 'none';
};

const known = (message) => KNOWN.find((entry) => entry.match.test(message));
const usedKnown = new Set();

const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

// Een pagina-toestand: url + sessie + thema + breedte. Geeft de gevonden
// fouten terug, ontdubbeld, met de klik die eraan voorafging.
async function visit({ page: spec, signedIn, theme, vp }) {
  const label = `${spec.url} [${signedIn ? 'ingelogd' : 'uitgelogd'} | ${theme} | ${vp.w}]`;
  const context = await browser.newContext({ viewport:{ width:vp.w, height:vp.h }, colorScheme:theme });
  await context.addInitScript(([key, value]) => {
    try { window.localStorage.setItem(key, value); } catch { /* storage uit */ }
  }, [THEME_KEY, theme]);
  await context.addInitScript(CATCH_REJECTIONS);
  const page = await context.newPage();
  const found = [];
  page.on('pageerror', (error) => found.push({ kind:'uncaught', message:error.message, stack:(error.stack || '').split('\n').slice(0, 4).join('\n') }));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    // "Failed to load resource" draagt zijn url niet in de tekst maar in de
    // locatie. Zonder die url is de melding niet te beoordelen en niet smal te
    // filteren, dus hij wordt er hier bij gezet.
    const where = message.location?.().url || '';
    const text = /^Failed to load resource/.test(message.text()) && where
      ? `resource ${new URL(where, ORIGIN).pathname} failed: ${message.text()}`
      : message.text();
    found.push({ kind:'console.error', message:text, stack:'' });
  });
  // Een dialoog zonder handler laat de pagina hangen; wegklikken en doorgaan.
  page.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));
  page.on('filechooser', (chooser) => chooser.setFiles([]).catch(() => {}));
  await stub(page, signedIn);

  let interaction = 'niet uitgevoerd';
  try {
    await page.goto(ORIGIN + spec.url + (spec.query || ''), { waitUntil:'load', timeout:45000 });
    // networkidle als doel, niet als eis: /parashare en /ontvang houden een
    // verbinding open en worden nooit stil. Vandaar catch en doorgaan, want de
    // vaste 1500 ms hieronder is wat de animaties nodig hebben. De globe tikt
    // pas na initGlobe(), en die staat zelf op een setTimeout van 400 ms.
    await page.waitForLoadState('networkidle', { timeout:10000 }).catch(() => {});
    await page.waitForTimeout(1500);
    interaction = await page.evaluate(PICK_INTERACTION, vp.w < 700);
    // Na de klik opnieuw wachten: een handler die een fout gooit doet dat vaak
    // een frame later, en een menu dat opent start zijn eigen animatie.
    await page.waitForTimeout(1200);
  } catch (error) {
    found.push({ kind:'test', message:`de pagina kon niet geladen of aangeraakt worden: ${error.message}`, stack:'' });
  }

  for (const reason of await page.evaluate(() => window.__unhandledRejections || []).catch(() => [])) {
    found.push({ kind:'unhandled rejection', message:reason.split('\n')[0], stack:reason.split('\n').slice(0, 4).join('\n') });
  }
  await context.close();

  const problems = [];
  const seen = new Set();
  for (const one of found) {
    const hit = known(one.message);
    if (hit) { usedKnown.add(hit.why); continue; }
    const key = `${one.kind}|${one.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    problems.push(`${label} na "${interaction}"\n    ${one.kind}: ${one.message}${one.stack ? '\n    ' + one.stack.replace(/\n/g, '\n    ') : ''}`);
  }
  return { label, interaction, problems };
}

// Zes tegelijk. Dat is parallellisme, geen retry: elke toestand wordt precies
// een keer bezocht en het oordeel verandert er niet van. Serieel duurt deze
// suite ruim tien minuten en past hij niet naast sign-full en de andere
// browsersuites in het budget van tien minuten dat
// .github/workflows/sign-e2e.yml heeft. Op vier stond de suite op 162s op een
// runner; het getal hoort in de pull request, niet in dit commentaar.
async function pool(jobs, workers, run) {
  const out = [];
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(workers, jobs.length) }, async () => {
    for (let i = next++; i < jobs.length; i = next++) out[i] = await run(jobs[i]);
  }));
  return out;
}

test('no page throws an uncaught error on load or on first interaction', async (t) => {
  const jobs = [];
  for (const spec of PAGES) {
    for (const state of spec.states) {
      for (const theme of THEMES) {
        for (const vp of VIEWPORTS) jobs.push({ page: spec, signedIn: state === 'in', theme, vp });
      }
    }
  }
  const results = await pool(jobs, 6, visit);
  const problems = results.flatMap((one) => one.problems);

  t.diagnostic(`${jobs.length} pagina-toestanden bezocht: ${PAGES.length} pagina's, ${PAGES.reduce((n, p) => n + p.states.length, 0)} sessietoestanden, ${THEMES.length} thema's, ${VIEWPORTS.length} breedtes`);
  const noInteraction = results.filter((one) => one.interaction === 'none').map((one) => one.label);
  t.diagnostic(`${jobs.length - noInteraction.length} toestanden kregen een eerste interactie, ${noInteraction.length} hadden er geen te bieden`);
  for (const entry of KNOWN) {
    if (!usedKnown.has(entry.why)) t.diagnostic(`KNOWN ongebruikt in deze run, kandidaat om te schrappen: ${String(entry.match)}`);
  }

  assert.deepEqual(problems, [], '\n\n' + problems.join('\n\n')
    + `\n\nElk van deze meldingen is een fout die een bezoeker in zijn console ziet.\n`
    + 'Repareer de pagina. Zet hem alleen op de KNOWN-lijst met een reden als de melding\n'
    + 'aantoonbaar van de testopstelling komt en niet van het product.\n');
});

test.after(async () => { await browser.close(); server.close(); });
