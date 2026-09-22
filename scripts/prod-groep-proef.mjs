// DE GROEPSVERZENDING, OP DE ECHTE SERVER.
//
// Alles eromheen is lokaal groen, en lokaal is niet productie: daar staat een
// andere nginx, een andere mailconfiguratie en een echte Redis. De vraag die
// hier beantwoord wordt is de vraag van de eerste klant, gesteld aan de server
// die zij ook gebruikt.
//
//   node scripts/prod-groep-proef.mjs --key <api-sleutel> [--host relay.paramant.app]
//                                     [--aantal 30] [--adres jij@voorbeeld.nl]
//
// Wat het NIET doet: de ophaalcode invoeren. Die komt per mail aan bij de
// ontvanger, en dat postvak hoort niet van ons te zijn. Alles ervoor en
// eromheen wordt wel echt gedaan, en de proefverzending wordt daarna weer
// ingetrokken.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const arg = (naam, standaard) => {
  const i = process.argv.indexOf('--' + naam);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : standaard;
};
const HOST = arg('host', 'relay.paramant.app');
const KEY = arg('key', process.env.PARAMANT_API_KEY || '');
const AANTAL = Number(arg('aantal', '30'));
const EIGEN = arg('adres', '');
// Een host met schema erin mag ook, zodat deze proef eerst tegen een relay op
// deze machine kan draaien. Een rode uitslag hoort de server te betekenen, niet
// een fout in de proef, en dat weet je alleen als hij ergens groen is geweest.
const BASE = /^https?:\/\//.test(HOST) ? HOST.replace(/\/$/, '') : 'https://' + HOST;
const SITE = arg('site', BASE.includes('127.0.0.1') || BASE.includes('localhost')
  ? BASE : 'https://paramant.app');
const LINK_MAX_BLOB = 5 * 1024 * 1024;

if (!KEY) {
  console.error('geen sleutel. Geef --key <api-sleutel> of zet PARAMANT_API_KEY.');
  process.exit(2);
}

// Dezelfde wikkelcode die de browser van de afzender draait. Een eigen
// implementatie hier zou bewijzen dat twee versies van mij het eens zijn,
// en dat is niet de vraag.
const wrapSrc = fs.readFileSync(path.join(HIER, '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(wrapSrc, scope);
const wrap = scope.paramantSendWrap;

const uit = [];
const ok = (naam, waar, detail = '') => {
  uit.push({ naam, pass: !!waar });
  console.log((waar ? 'ok   ' : 'NIET ') + naam + (detail ? '   ' + detail : ''));
};
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; };
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const api = (pad, opties = {}) => fetch(BASE + pad, {
  ...opties,
  headers: { 'Content-Type': 'application/json', 'X-Api-Key': KEY, ...(opties.headers || {}) },
});

// ---- 1. leeft de server -------------------------------------------------
const gezond = await fetch(BASE + '/health').then((r) => r.ok).catch(() => false);
ok('de relay antwoordt', gezond, BASE);
if (!gezond) process.exit(1);

// ---- 2. een echt bestand, verzegeld zoals de browser het doet -----------
const inhoud = crypto.randomBytes(1024 * 1024);
const naam = 'paramant-proef.bin';
const naamBytes = Buffer.from(naam, 'utf8');
const plain = Buffer.concat([u32le(naamBytes.length), naamBytes, inhoud]);
const rawKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

const hashes = [];
for (let at = 0; at < ct.length; at += LINK_MAX_BLOB) {
  const deel = ct.subarray(at, Math.min(at + LINK_MAX_BLOB, ct.length));
  const hash = sha256hex(deel);
  const r = await api('/v2/inbound', {
    method: 'POST',
    body: JSON.stringify({ hash, payload: deel.toString('base64'),
                           meta: { device_id: 'transfer-web-link' } }),
  });
  if (r.status !== 200) {
    ok('het bestand kon worden geupload', false, 'status ' + r.status + ' ' + (await r.text()).slice(0, 140));
    process.exit(1);
  }
  hashes.push(hash);
}
ok('het bestand is geupload', hashes.length > 0, hashes.length + ' blok(ken)');

// ---- 3. de ontvangers, elk met een eigen gewikkelde sleutel -------------
const geheim = new Uint8Array(Buffer.concat([rawKey, iv]));
const adressen = Array.from({ length: AANTAL }, (_, i) =>
  (i === 0 && EIGEN) ? EIGEN : 'proef+groep' + (i + 1) + '@paramant.app');
const sealed = {};
for (const adres of adressen) {
  const token = wrap.newToken();
  sealed[adres] = { token, wrapped_key: await wrap.wrap(token, geheim) };
}

// ---- 4. een te grote groep hoort te worden geweigerd --------------------
const teveelAdres = 'proef+teveel@paramant.app';
const teveelSealed = { ...sealed };
const tvToken = wrap.newToken();
teveelSealed[teveelAdres] = { token: tvToken, wrapped_key: await wrap.wrap(tvToken, geheim) };
const teveel = await api('/v2/sends', {
  method: 'POST',
  body: JSON.stringify({ hashes, recipients: adressen.concat([teveelAdres]),
                         sealed: teveelSealed, filename: naam, ttl_ms: 3600 * 1000 }),
});
const teveelTekst = await teveel.text();
ok('een ontvanger te veel wordt geweigerd', teveel.status === 400 || teveel.status === 403,
   'status ' + teveel.status);
ok('en de weigering noemt het gevraagde aantal',
   teveelTekst.includes(String(AANTAL + 1)), teveelTekst.slice(0, 140));

// ---- 5. de echte verzending --------------------------------------------
const vr = await api('/v2/sends', {
  method: 'POST',
  body: JSON.stringify({ hashes, recipients: adressen, sealed, filename: naam,
                         ttl_ms: 3600 * 1000 }),
});
const vj = await vr.json().catch(() => ({}));
ok('de verzending naar ' + AANTAL + ' mensen wordt aangenomen', vr.status === 201,
   'status ' + vr.status + ' ' + JSON.stringify(vj).slice(0, 180));
ok('er zijn ' + AANTAL + ' ontvangers vastgelegd', vj.recipients === AANTAL, 'kreeg ' + vj.recipients);
ok('en er gingen ' + AANTAL + ' uitnodigingen de deur uit', vj.invited === AANTAL, 'kreeg ' + vj.invited);
ok('de blokken zijn tot het hele bestand samengevoegd', vj.size === ct.length,
   vj.size + ' van ' + ct.length);

// ---- 6. de pagina waar de ontvanger binnenkomt --------------------------
const eersteToken = sealed[adressen[0]].token;
const paginaUrl = SITE + '/ontvang/' + encodeURIComponent(eersteToken);
// Alleen zinvol tegen de echte site: de statische pagina wordt door nginx
// geserveerd, en een losse relay op deze machine heeft die niet. Lokaal zou
// dit altijd rood staan en daarmee niets zeggen.
if (SITE !== BASE) {
  const pagina = await fetch(paginaUrl, { redirect: 'manual' }).catch(() => null);
  ok('de ontvangstpagina bestaat (geen 404)', pagina && pagina.status === 200,
     paginaUrl + ' -> ' + (pagina ? pagina.status : 'onbereikbaar'));
  if (pagina && pagina.status === 200) {
    const html = await pagina.text();
    ok('en het is de ophaalpagina', /ophalen|ontvang/i.test(html), html.length + ' bytes');
  }

  // EN DRAAIT DE PAGINA OOK. Een 200 zegt alleen dat nginx het bestand vond.
  // Productie draagt een CSP die hier lokaal niet bestaat (script-src 'self',
  // connect-src alleen de eigen sectorhosts), en als die de scripts tegenhoudt
  // ziet de ontvanger een pagina die niets doet. Dat is met een fetch niet te
  // zien en met een browser in tien seconden.
  try {
    const { chromium } = await import('playwright');
    const browser = await chromium.launch();
    const pg = await browser.newPage();
    const fouten = [];
    pg.on('pageerror', (e) => fouten.push(String(e.message).slice(0, 120)));
    pg.on('console', (m) => { if (m.type() === 'error') fouten.push(m.text().slice(0, 120)); });
    await pg.goto(paginaUrl, { waitUntil: 'networkidle', timeout: 30000 });
    const zichtbaar = await pg.evaluate(() => document.body.innerText.slice(0, 2000));
    ok('de pagina draait zijn javascript zonder fouten', fouten.length === 0,
       fouten.slice(0, 2).join(' | '));
    ok('en hij biedt de ontvanger een volgende stap',
       /code|ophalen|open/i.test(zichtbaar), zichtbaar.replace(/\s+/g, ' ').slice(0, 90));
    await browser.close();
  } catch (e) {
    // Geen playwright is geen reden om de rest af te keuren, maar het moet wel
    // opvallen: zonder deze stap is de CSP niet nagemeten.
    console.log('-    de browserstap is overgeslagen: ' + String(e.message).slice(0, 80));
  }
} else {
  console.log('-    de ontvangstpagina wordt overgeslagen: geen nginx voor ' + BASE);
}

// ---- 7. een verkeerde code hoort te worden geweigerd --------------------
// Eerst een code aanvragen, want die gaat naar het postvak van de ontvanger
// en bestaat tot dat moment niet. Zonder die stap antwoordde de relay 409: er
// viel niets te bevestigen. Dat was een fout in deze proef, niet in de server.
const ophalen = (body) => fetch(BASE + '/v2/pickup/' + encodeURIComponent(eersteToken), {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
}).catch(() => null);

const gevraagd = await ophalen({ action: 'code' });
ok('de ontvanger kan een code aanvragen', gevraagd && gevraagd.status === 200,
   'status ' + (gevraagd ? gevraagd.status : 'onbereikbaar'));

// De code gaat zonder action mee: dat IS stap twee. `action: confirm` is iets
// anders, namelijk de melding achteraf dat het bestand openging, en die gaf
// hier 409 omdat er niets te bevestigen viel.
const fout = await ophalen({ code: '000000' });
const foutTekst = fout ? await fout.text() : '';
ok('een verkeerde code wordt geweigerd', fout && fout.status === 401,
   'status ' + (fout ? fout.status : 'onbereikbaar') + ' ' + foutTekst.slice(0, 90));
ok('en de ontvanger hoort hoeveel pogingen hij nog heeft',
   /tries_left/.test(foutTekst), foutTekst.slice(0, 90));

// ---- 8. opruimen --------------------------------------------------------
if (vj.id) {
  const weg = await api('/v2/sends/' + encodeURIComponent(vj.id), { method: 'DELETE' });
  ok('de proefverzending is ingetrokken', weg.status === 200 || weg.status === 204,
     'status ' + weg.status);
}

const gezakt = uit.filter((u) => !u.pass);
console.log('\n' + (uit.length - gezakt.length) + '/' + uit.length + ' geslaagd op ' + HOST);
if (gezakt.length) {
  console.log('\nniet goed:');
  for (const g of gezakt) console.log('  - ' + g.naam);
}
process.exit(gezakt.length ? 1 : 0);
