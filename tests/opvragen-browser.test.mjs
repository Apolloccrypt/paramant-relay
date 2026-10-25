// STUKKEN OPVRAGEN, IN EEN ECHTE BROWSER, MET EEN ECHTE RELAY.
//
// De twee reizen die het product zijn:
//
//   het kantoor   maakt een link (sleutels in de browser, hash in het fragment),
//                 ziet wat er binnenkwam en downloadt het
//   de klant      opent de link op een telefoon zonder account, kiest per stuk
//                 een foto of bestand en verstuurt
//
// En de drie dingen die niet mogen: dat er onversleutelde bytes de browser
// uitgaan, dat een relay ongemerkt een andere sleutel kan voorschuiven, en dat
// een link zonder de juiste hash toch iets verstuurt. In het Nederlands en in
// het Engels; de Engelse reis loopt via een passkey met PRF en opent de
// download in een browser zonder kopie van de kluissleutel.
//
// Schermafdrukken (390x844) van de vier schermen: zet OPVRAGEN_SHOTS=<map>.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startRelay } from './_relay-stack.mjs';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HIER, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const SHOTS = process.env.OPVRAGEN_SHOTS || '';
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
               '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2' };

const checks = [];
const ok = (naam, cond, detail = '') => checks.push({ naam, pass: !!cond, detail: String(detail) });

const SLEUTEL = 'pgp_opvragen_browser';
const INTERN = 'b'.repeat(40);
const mails = [];
const stack = await startRelay({
  onLine: (r) => { if (r.includes('mail_dryrun')) { try { mails.push(JSON.parse(r)); } catch { /* geen json */ } } },
  env: {
    INTERNAL_AUTH_TOKEN: INTERN,
    USERS_JSON: JSON.stringify({ api_keys: [{ key: SLEUTEL, active: true, plan: 'pro', plan_parasend: 'pro',
      label: 'Acme Administratie', email: 'kantoor@example.com', account_id: 'acct_demo' }] }),
  },
});
const RELAY = stack.basis;

// ── wat over de draad gaat, alles ──────────────────────────────────────────
const verkeer = [];          // { pad, body: Buffer }
let passkeys = [];
let vervalsSleutel = false;  // laat de "relay" een andere publieke sleutel teruggeven

async function relayIntern(op, body) {
  return fetch(RELAY + '/v2/user/opvraag/' + op, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN },
    body: JSON.stringify({ ...body, user_id: SLEUTEL }) });
}

// Wat admin/server.js doet: de sessie levert het account, de browser alleen een id.
async function adminNa(req, u, body) {
  const m = u.pathname.match(/^\/api\/user\/opvragen(?:\/([A-Za-z0-9_-]+))?(?:\/(bestand|sluiten|verwijderen|herinnering))?(?:\/(\d+))?$/);
  const json = body.length ? JSON.parse(body.toString() || '{}') : {};
  if (!m) return null;
  const [, id, actie, n] = m;
  if (req.method === 'GET' && !id) return relayIntern('list', {});
  if (req.method === 'POST' && !id) return relayIntern('create', json);
  if (id === 'info' && !actie) return relayIntern('info', {});
  if (id === 'kluis' && req.method === 'POST') return relayIntern('kluis', json);
  if (req.method === 'GET' && !actie) return relayIntern('detail', { id });
  if (actie === 'bestand') return relayIntern('file', { id, n: Number(n) });
  if (actie === 'sluiten') return relayIntern('close', { id });
  if (actie === 'verwijderen') return relayIntern('delete', { id });
  if (actie === 'herinnering') return relayIntern('remind', { id, pin: json.pin });
  return null;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const brokken = []; for await (const c of req) brokken.push(c);
  const body = Buffer.concat(brokken);
  if (u.pathname.startsWith('/v2/') || u.pathname.startsWith('/api/')) verkeer.push({ pad: u.pathname, body });
  if (u.pathname === '/api/user/account/webauthn/credentials') {
    res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ passkeys }));
  }
  if (u.pathname.startsWith('/api/user/opvragen')) {
    const r = await adminNa(req, u, body);
    if (!r) { res.writeHead(404); return res.end('{}'); }
    const kop = {}; r.headers.forEach((v, k) => { if (k !== 'content-length' && k !== 'transfer-encoding') kop[k] = v; });
    res.writeHead(r.status, kop);
    return res.end(Buffer.from(await r.arrayBuffer()));
  }
  if (u.pathname.startsWith('/v2/')) {
    const r = await fetch(RELAY + req.url, { method: req.method,
      headers: { 'Content-Type': req.headers['content-type'] || 'application/json' }, body: body.length ? body : undefined });
    let uit = Buffer.from(await r.arrayBuffer());
    if (vervalsSleutel && req.method === 'GET' && /^\/v2\/opvraag\/[^/]+$/.test(u.pathname) && r.ok) {
      const v = JSON.parse(uit.toString());
      v.descriptor.kem_pub = crypto.randomBytes(1184).toString('base64url');
      uit = Buffer.from(JSON.stringify(v));
    }
    const kop = {}; r.headers.forEach((v, k) => { if (k !== 'content-length' && k !== 'transfer-encoding') kop[k] = v; });
    res.writeHead(r.status, kop);
    return res.end(uit);
  }
  let bestand;
  if (/^\/v\/[^/]+$/.test(u.pathname)) bestand = path.join(ROOT, 'v', 'index.html');
  else if (/^\/en\/v\/[^/]+$/.test(u.pathname)) bestand = path.join(ROOT, 'en', 'v', 'index.html');
  else if (u.pathname === '/opvragen') bestand = path.join(ROOT, 'opvragen.html');
  else if (u.pathname === '/en/opvragen') bestand = path.join(ROOT, 'en', 'opvragen.html');
  else bestand = path.join(ROOT, u.pathname);
  if (!bestand.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(bestand, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(bestand)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;

// ── de bestanden van de klant, met merktekens om ze terug te vinden ─────────
const MERK_PASPOORT = 'PASPOORT-MERKTEKEN-' + crypto.randomBytes(8).toString('hex');
const MERK_LOON = 'LOONSTROOK-MERKTEKEN-' + crypto.randomBytes(8).toString('hex');
const paspoort = Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n'), Buffer.from(MERK_PASPOORT), crypto.randomBytes(300 * 1024)]);
const loonstrook = Buffer.concat([Buffer.from('%PDF-1.4\n' + MERK_LOON + '\n'), crypto.randomBytes(120 * 1024)]);
const LOON_NAAM = 'loonstrook-demo-oktober.pdf';

function lekt(merk) {
  const vormen = [Buffer.from(merk), Buffer.from(Buffer.from(merk).toString('base64')), Buffer.from(Buffer.from(merk).toString('base64url'))];
  return verkeer.filter((v) => vormen.some((f) => v.body.includes(f))).map((v) => v.pad);
}

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const fouten = [];
function luister(page, wie) {
  page.on('pageerror', (e) => fouten.push(wie + ': ' + String(e)));
  page.on('console', (m) => { if (m.type() === 'error' && !/status of (404|410)/.test(m.text())) fouten.push(wie + ' console: ' + m.text()); });
}
const shot = async (page, n) => { if (SHOTS) await page.screenshot({ path: path.join(SHOTS, 'opvragen-echt-' + n + '.png') }); };

async function maakLink(page, prefix, naam, mail) {
  await page.goto('about:blank');
  await page.goto(ORIGIN + prefix + '/opvragen#nieuw');
  await page.waitForSelector('#v-nieuw:not([hidden]) #make', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelectorAll('#items input[type=checkbox]').length >= 3);
  await page.fill('#client-name', naam);
  if (mail) await page.fill('#client-email', mail);
  await page.click('#make');
  await page.waitForSelector('#linkcard:not([hidden])', { timeout: 30000 });
  return page.getAttribute('#link-url', 'title');
}

async function kies(page, knop, nth, file) {
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.locator('button', { hasText: knop }).nth(nth).click()]);
  await fc.setFiles(file);
}

async function reis(lang) {
  const en = lang === 'en';
  const P = en ? '/en' : '';
  const L = en
    ? { maak: 'Make link', foto: 'Take photo', bestand: 'Choose file', klaar: 'Your link is ready', verstuurd: 'Sent.',
        heeft: 'Acme Administratie has your documents.', calm: 'Your files are locked on your phone. Only Acme Administratie can open them.',
        tweeVan: '2 of 3', ontbreekt: 'still missing', klopt: 'This link is not right', paspoort: 'Copy of passport' }
    : { maak: 'Maak link', foto: 'Foto maken', bestand: 'Bestand kiezen', klaar: 'Je link staat klaar', verstuurd: 'Verstuurd.',
        heeft: 'Acme Administratie heeft je stukken.', calm: 'Je bestanden gaan op slot op je telefoon. Alleen Acme Administratie kan ze openen.',
        tweeVan: '2 van 3', ontbreekt: 'ontbreekt nog', klopt: 'Deze link klopt niet', paspoort: 'Kopie paspoort' };

  // ── het kantoor: een passkey met PRF in de Engelse reis ─────────────────
  const kantoor = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, acceptDownloads: true });
  const kp = await kantoor.newPage();
  luister(kp, lang + ' kantoor');
  let cdp = null;
  if (en) {
    await kp.goto(ORIGIN + '/en/opvragen');
    cdp = await kp.context().newCDPSession(kp);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    const credId = await kp.evaluate(async () => {
      const c = await navigator.credentials.create({ publicKey: { rp: { id: 'localhost', name: 'Paramant' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'demo@example.com', displayName: 'Demo' },
        challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, extensions: { prf: {} } } });
      const b = new Uint8Array(c.rawId); let s = ''; for (const x of b) s += String.fromCharCode(x);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    });
    passkeys = [{ credId, prfSupported: true }];
  } else {
    passkeys = [];
  }

  // Eerst een verzoek waar niets op binnenkomt, dan het verzoek van de reis.
  await maakLink(kp, P, 'Demo Twee', '');
  const link = await maakLink(kp, P, 'Demo Klant', 'demo@example.com');
  ok(lang + ': de link staat klaar', !!link && (await kp.textContent('#linkcard .head')).includes(L.klaar), link);
  ok(lang + ': de link wijst naar /v/ met een hash in het fragment', /\/v\/[A-Za-z0-9_-]{24}#[A-Za-z0-9_-]{43}$/.test(link || ''), link);
  ok(lang + ': de taal zit in de link', en ? (link || '').includes('/en/v/') : !(link || '').includes('/en/'), link);
  const wa = await kp.getAttribute('#wa', 'href');
  ok(lang + ': WhatsApp krijgt de link mee', (wa || '').startsWith('https://wa.me/?text=') && decodeURIComponent(wa).includes(link), wa);
  const mailHref = await kp.getAttribute('#mail', 'href');
  ok(lang + ': de mailknop opent een mail aan de klant', (mailHref || '').startsWith('mailto:demo%40example.com') || (mailHref || '').startsWith('mailto:demo@example.com'), mailHref);
  const notitie = await kp.isVisible('#carry-note');
  ok(lang + (en ? ': met passkey geen waarschuwing over "alleen deze browser"' : ': zonder passkey zegt de pagina dat het alleen hier opent'), en ? !notitie : notitie);
  if (!en) await shot(kp, 1);

  // ── de klant: een andere browser, geen account, een telefoon ─────────────
  const klant = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const cp = await klant.newPage();
  luister(cp, lang + ' klant');
  await cp.goto(link);
  await cp.waitForSelector('#v-form:not([hidden])', { timeout: 15000 });
  ok(lang + ': de klant ziet van wie het verzoek komt', (await cp.textContent('#office')) === 'Acme Administratie');
  ok(lang + ': en de geruststelling met de naam van het kantoor', (await cp.textContent('#calm')) === L.calm, await cp.textContent('#calm'));
  ok(lang + ': drie stukken', (await cp.locator('.req').count()) === 3);
  ok(lang + ': Versturen kan pas als er iets is', await cp.isDisabled('#send'));
  await kies(cp, L.foto, 0, { name: 'IMG_0412.png', mimeType: 'image/png', buffer: paspoort });
  ok(lang + ': het paspoort staat erbij', (await cp.locator('.req').first().textContent()).includes(en ? 'Added' : 'Toegevoegd'));
  if (!en) await shot(cp, 2);
  await kies(cp, L.bestand, 0, { name: LOON_NAAM, mimeType: 'application/pdf', buffer: loonstrook });
  const voorUpload = verkeer.length;
  await cp.click('#send');
  await cp.waitForSelector('#v-done:not([hidden])', { timeout: 30000 });
  ok(lang + ': het bevestigingsscherm', (await cp.textContent('#v-done h1')) === L.verstuurd && (await cp.textContent('#done-lead')) === L.heeft);
  ok(lang + ': met twee regels', (await cp.locator('#receipt .item').count()) === 2);
  if (!en) await shot(cp, 3);
  const uploads = verkeer.slice(voorUpload).filter((v) => /\/stuk\/\d+$/.test(v.pad));
  ok(lang + ': twee uploads', uploads.length === 2, uploads.length);
  ok(lang + ': elke upload is een encrypt_blob-pakket (0x03), ingekort tot een veelvoud van 64 KiB',
     uploads.every((v) => v.body[0] === 3 && v.body.length % 65536 === 0 && v.body.length < 5 * 1048576),
     uploads.map((v) => v.body.length).join(','));

  // ── het kantoor ziet wat er binnen is ───────────────────────────────────
  await kp.goto(ORIGIN + P + '/opvragen');
  await kp.waitForSelector('.client', { timeout: 15000 });
  const kaart = await kp.textContent('.client');
  ok(lang + ': de kaart zegt 2 van 3', kaart.includes(L.tweeVan), kaart);
  ok(lang + ': en wat er nog ontbreekt', kaart.includes(L.ontbreekt));
  ok(lang + ': het lege verzoek staat ingeklapt eronder', (await kp.locator('.mini').count()) === 1);
  if (!en) await shot(kp, 4);

  if (en) {
    // Een andere browser met dezelfde passkey: geen kopie van de kluissleutel
    // hier, dus de passkey moet hem openen.
    await kp.evaluate(() => new Promise((r) => { const q = indexedDB.deleteDatabase('paramant-opvragen'); q.onsuccess = q.onerror = q.onblocked = () => r(); }));
  }
  const [dl] = await Promise.all([kp.waitForEvent('download', { timeout: 30000 }),
    kp.locator('.client button[data-a=download]').first().click()]);
  const zip = fs.readFileSync(await dl.path());
  ok(lang + ': de download is een zip met de klantnaam', /Demo Klant/.test(dl.suggestedFilename()) && dl.suggestedFilename().endsWith('.zip'), dl.suggestedFilename());
  ok(lang + ': met het paspoort byte voor byte', zip.includes(paspoort));
  ok(lang + ': en de loonstrook byte voor byte', zip.includes(loonstrook));
  ok(lang + ': onder de oorspronkelijke naam, achter het stuk', zip.includes(Buffer.from(LOON_NAAM)));
  ok(lang + ': de foto heet naar het stuk, niet naar de camera', zip.includes(Buffer.from(L.paspoort + ' - ')) && !zip.includes(Buffer.from('IMG_0412')));

  // Herinnering: mail met de link en dezelfde hash.
  mails.length = 0;
  await kp.locator('.client button[data-a=remind]').first().click();
  await kp.waitForFunction(() => /verstuurd|sent/i.test(document.querySelector('.client .say')?.textContent || ''), null, { timeout: 15000 }).catch(() => {});
  await new Promise((r) => setTimeout(r, 300));
  const m = mails.find((x) => (x.text || '').includes('/v/'));
  // De relay bouwt de link op SITE_URL; pad en fragment moeten die van het kantoor zijn.
  const padEnHash = link.replace(/^https?:\/\/[^/]+/, '');
  ok(lang + ': de herinnering ging uit met precies de link van het kantoor', !!m && m.text.includes(padEnHash), m && m.text);
  ok(lang + ': en noemt wat er nog ontbreekt', !!m && m.text.includes(en ? 'Annual statement' : 'Jaaropgave'), m && m.text);
  ok(lang + ': en de datum zonder tijdzone-rest', !!m && !/ (om|at) [A-Z]{3,4}\b/.test(m.text), m && m.text);

  // ── wat niet mag ────────────────────────────────────────────────────────
  // Een link met een andere hash: niets versturen.
  const nep = link.replace(/#.*$/, '#' + crypto.randomBytes(32).toString('base64url'));
  const p2 = await klant.newPage(); luister(p2, lang + ' nep');
  await p2.goto(nep);
  await p2.waitForSelector('#v-stop:not([hidden])', { timeout: 15000 });
  ok(lang + ': een link met de verkeerde hash weigert', (await p2.textContent('#stop-title')) === L.klopt);
  // Een relay die een eigen sleutel voorschuift: de telefoon merkt het.
  vervalsSleutel = true;
  const p3 = await klant.newPage(); luister(p3, lang + ' vervalst');
  const voor = verkeer.length;
  await p3.goto(link);
  await p3.waitForSelector('#v-stop:not([hidden])', { timeout: 15000 });
  vervalsSleutel = false;
  ok(lang + ': een vervangen publieke sleutel wordt geweigerd', (await p3.textContent('#stop-title')) === L.klopt);
  ok(lang + ': en dan gaat er niets omhoog', !verkeer.slice(voor).some((v) => /\/stuk\//.test(v.pad)));

  if (!en) {
    // Sluiten: de klant kan daarna niets meer sturen; dan verwijderen.
    kp.on('dialog', (d) => d.accept());
    await kp.locator('.client button[data-a=close]').first().click();
    await kp.waitForFunction(() => /\(1\)/.test(document.getElementById('seg-open').textContent), null, { timeout: 15000 });
    const p4 = await klant.newPage(); luister(p4, lang + ' gesloten');
    await p4.goto(link);
    await p4.waitForSelector('#v-stop:not([hidden])', { timeout: 15000 });
    ok(lang + ': na sluiten zegt de link dat het kantoor het verzoek sloot',
       (await p4.textContent('#stop-title')) === 'Acme Administratie heeft dit verzoek gesloten', await p4.textContent('#stop-title'));
    await kp.click('#seg-done');
    await kp.waitForSelector('.client button[data-a=delete]', { timeout: 15000 });
    await kp.locator('.client button[data-a=delete]').first().click();
    await kp.waitForFunction(() => /\(0\)/.test(document.getElementById('seg-done').textContent), null, { timeout: 15000 });
    const weg = await fetch(RELAY + '/v2/opvraag/' + link.match(/\/v\/([^#?]+)/)[1]);
    ok(lang + ': na verwijderen is het verzoek weg bij de relay', weg.status === 404, weg.status);
    // Het lege verzoek ook dicht, zodat de Engelse reis schoon begint.
    await kp.click('#seg-open');
    await kp.locator('.mini').first().click();
    await kp.locator('.client button[data-a=close]').first().click();
    await kp.waitForFunction(() => /\(0\)/.test(document.getElementById('seg-open').textContent), null, { timeout: 15000 });
  }

  if (cdp) await cdp.detach().catch(() => {});
  await klant.close();
  await kantoor.close();
}

await reis('nl');
await reis('en');

ok('geen merkteken van het paspoort in enig verzoek naar de server', lekt(MERK_PASPOORT).length === 0, lekt(MERK_PASPOORT).join(','));
ok('geen merkteken van de loonstrook in enig verzoek naar de server', lekt(MERK_LOON).length === 0, lekt(MERK_LOON).join(','));
ok('en de bestandsnaam ook niet', lekt(LOON_NAAM).length === 0, lekt(LOON_NAAM).join(','));
ok('geen fouten op de pagina\'s', fouten.length === 0, fouten.join(' | ').slice(0, 600));

await browser.close();
server.close();
stack.stop();

let gezakt = 0;
for (const c of checks) {
  console.log(`${c.pass ? 'ok  ' : 'FOUT'} - ${c.naam}${c.pass || !c.detail ? '' : '  [' + c.detail + ']'}`);
  if (!c.pass) gezakt++;
}
console.log(`\n${checks.length - gezakt}/${checks.length} geslaagd`);
process.exit(gezakt ? 1 : 0);
