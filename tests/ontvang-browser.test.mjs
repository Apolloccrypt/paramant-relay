// DE ONTVANGER, IN EEN ECHTE BROWSER.
//
// Alles wat tot nu toe bestond test de relay. Niemand had ophalen.html ooit in
// een browser geopend, terwijl dat het enige scherm is dat de klant van onze
// klant te zien krijgt. De repo heeft achtendertig browsersuites en geen enkele
// raakte deze functie.
//
// Hier staat de echte relay achter een statische server, en chromium loopt de
// reis: de link openen, om een code vragen, hem verkeerd typen, hem goed typen,
// en het bestand opslaan. De laatste vraag is dezelfde als altijd: komen de
// bytes er heel uit, nu ook door de browsercode heen.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { startRelay } from './_relay-stack.mjs';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HIER, '..', 'frontend');
const RELAYDIR = path.join(HIER, '..', 'relay');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml' };

const checks = [];
const ok = (naam, cond, detail='') => checks.push({ naam, pass: !!cond, detail: String(detail) });

// ---- de echte relay, via de enige weg die er is -------------------------
// startRelay() uit tests/_relay-stack.mjs is niet alleen gemak: die import is
// wat scripts/browser-suites.mjs deze suite in de CI-baan met een echte
// backend zet. Zelf spawnen werkte hier en faalde in CI op een ontbrekende
// argon2, met een melding die naar de test wees in plaats van naar de baan.
const API_KEY = 'pgp_browser_reis';
const mails = [];
const stack = await startRelay({
  onLine: (r) => {
    if (!r.includes('mail_dryrun')) return;
    try { mails.push(JSON.parse(r)); } catch { /* geen json, geen mail */ }
  },
  env: {
    USERS_JSON: JSON.stringify({ api_keys: [{ key: API_KEY, active: true, plan: 'pro',
      plan_parasend: 'pro', label: 'Zorggroep De Linde', email: 'anna@zorg.test',
      account_id: 'acct_browser' }] }),
  },
});
const RELAY = stack.basis;
const RELAY_PORT = stack.poort;
const relay = stack.proces;
const usersFile = stack.usersFile;


// ── de statische site, met /v2/ doorgestuurd naar de relay ──────────────────
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname.startsWith('/v2/')) {
    const brokken = []; for await (const c of req) brokken.push(c);
    const r = await fetch(RELAY + req.url, {
      method: req.method,
      headers: { 'Content-Type': req.headers['content-type'] || 'application/json' },
      body: brokken.length ? Buffer.concat(brokken) : undefined,
    });
    const kop = {}; r.headers.forEach((v, k) => { kop[k] = v; });
    res.writeHead(r.status, kop);
    return res.end(Buffer.from(await r.arrayBuffer()));
  }
  // /ontvang/<token> serveert ophalen.html, precies zoals de nginx-regel doet.
  const bestand = u.pathname.startsWith('/ontvang/')
    ? path.join(ROOT, 'ophalen.html')
    : path.join(ROOT, u.pathname === '/' ? 'index.html' : u.pathname);
  if (!bestand.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(bestand, (e, body) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(bestand)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;

// ── een verzending klaarzetten, zoals de afzender hem maakt ─────────────────
const wrapSrc = fs.readFileSync(path.join(ROOT, 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
const vm = await import('node:vm');
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

const inhoud = crypto.randomBytes(64 * 1024);
const naam = 'dossier.pdf';
const nb = Buffer.from(naam, 'utf8');
const kop4 = Buffer.alloc(4); kop4.writeUInt32LE(nb.length, 0);
const plain = Buffer.concat([kop4, nb, inhoud]);
const rawKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
const hash = crypto.createHash('sha256').update(ct).digest('hex');

await fetch(RELAY + '/v2/inbound', { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
  body: JSON.stringify({ hash, payload: ct.toString('base64'), meta: { device_id: 'transfer-web-link' } }) });

const token = wrap.newToken();
const adres = 'partner@extern.test';
const sealed = { [adres]: { token, wrapped_key: await wrap.wrap(token, new Uint8Array(Buffer.concat([rawKey, iv]))) } };
const vr = await fetch(RELAY + '/v2/sends', { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Api-Key': API_KEY },
  body: JSON.stringify({ hashes: [hash], recipients: [adres], sealed, filename: naam, ttl_ms: 3600000 }) });
ok('de verzending is aangemaakt', vr.status === 201, 'status ' + vr.status);

// ── EN NU DE BROWSER ────────────────────────────────────────────────────────
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const page = await browser.newPage({ acceptDownloads: true });
const fouten = [];
page.on('pageerror', (e) => fouten.push(String(e)));
// De browser logt elke 4xx als console-fout, en deze test lokt er bewust een
// uit met een foute code. Die ene telt niet mee; al het andere wel, want een
// onverwachte fout op dit scherm is het soort ding dat een ontvanger een
// kapotte pagina bezorgt zonder dat iemand het merkt.
const verwacht401 = [];
page.on('response', (r) => {
  if (r.status() === 401 && r.url().includes('/v2/pickup/')) verwacht401.push(r.url());
});
page.on('console', (m) => {
  if (m.type() !== 'error') return;
  const t = m.text();
  if (/status of 401/.test(t) && verwacht401.length) return;   // de foute code
  fouten.push('console: ' + t);
});

await page.goto(`${ORIGIN}/ontvang/${encodeURIComponent(token)}`);
await page.waitForSelector('#step-start', { state: 'visible', timeout: 10000 });
ok('de ontvangerspagina opent op de eerste stap',
   await page.isVisible('#step-start'));
ok('en niet meteen op een foutscherm', !(await page.isVisible('#step-stop')));

mails.length = 0;
await page.click('#ask');
await page.waitForSelector('#step-code', { state: 'visible', timeout: 10000 });
ok('na "stuur mij de code" komt het codescherm', await page.isVisible('#step-code'));

const gemaskeerd = await page.textContent('#sent-to');
ok('het adres staat gemaskeerd op het scherm', /\*/.test(gemaskeerd || ''), gemaskeerd);
ok('en het volledige adres staat er NIET',
   !(await page.content()).includes(adres), 'volledig adres lekt op de pagina');

await new Promise((r) => setTimeout(r, 300));
const codeMail = mails.find((m) => /code to open the file/i.test(m.subject || ''));
ok('er is een codemail verstuurd', !!codeMail);
const code = codeMail ? (String(codeMail.text).match(/\b(\d{6})\b/) || [])[1] : null;
ok('met een zescijferige code erin', !!code);

// Eerst fout typen, want dat doet een mens.
await page.fill('#code', '000000');
await page.click('#open');
await page.waitForFunction(() => {
  const n = document.getElementById('code-say');
  // ophalen.html is Nederlands sinds 23 september 2026: "Die code klopt niet. Nog N pogingen over."
  return n && /klopt niet.*poging/i.test(n.textContent || '');
}, { timeout: 10000 }).catch(() => {});
const naFout = await page.textContent('#code-say');
ok('een foute code geeft een leesbare melding', /Die code klopt niet\. Nog \d+ pogingen? over\./.test(naFout || ''), naFout);
ok('en de knop blijft bruikbaar', !(await page.isDisabled('#open')));

// En dan goed.
const wachtDownload = page.waitForEvent('download', { timeout: 20000 });
await page.fill('#code', code);
await page.click('#open');
const download = await wachtDownload;

ok('de browser start een download', !!download);
ok('met de naam die de afzender koos', download.suggestedFilename() === naam,
   download.suggestedFilename());

const pad = await download.path();
const gedownload = fs.readFileSync(pad);
ok('en het bestand is byte voor byte het bestand dat erin ging',
   gedownload.equals(inhoud), `${gedownload.length} bytes tegen ${inhoud.length}`);

await page.waitForSelector('#step-done', { state: 'visible', timeout: 10000 }).catch(() => {});
ok('het scherm zegt dat het klaar is', await page.isVisible('#step-done'));

// De link is nu op. Opnieuw openen hoort dat te zeggen.
const page2 = await browser.newPage();
await page2.goto(`${ORIGIN}/ontvang/${encodeURIComponent(token)}`);
await page2.click('#ask');
await page2.waitForSelector('#step-stop', { state: 'visible', timeout: 10000 }).catch(() => {});
ok('een tweede bezoek krijgt een stopscherm', await page2.isVisible('#step-stop'));
const stopTitel = await page2.textContent('#stop-title');
ok('en dat scherm legt uit wat er aan de hand is',
   (stopTitel || '').length > 10 && !/undefined/i.test(stopTitel || ''), stopTitel);

ok('de foute code gaf inderdaad de 401 die we uitlokten', verwacht401.length === 1,
   verwacht401.length + ' keer 401, verwacht 1');
ok('en verder geen enkele fout op de pagina', fouten.length === 0, fouten.join(' | ').slice(0, 300));

// ── afsluiten ───────────────────────────────────────────────────────────────
await browser.close();
server.close();
relay.kill('SIGKILL');
try { fs.unlinkSync(usersFile); } catch {}

let gezakt = 0;
for (const c of checks) {
  console.log(`${c.pass ? 'ok  ' : 'FOUT'} - ${c.naam}${c.pass || !c.detail ? '' : '  [' + c.detail + ']'}`);
  if (!c.pass) gezakt++;
}
console.log(`\n${checks.length - gezakt}/${checks.length} geslaagd`);
process.exit(gezakt ? 1 : 0);
