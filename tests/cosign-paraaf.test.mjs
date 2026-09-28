// Paraaf op elke pagina, voor elke ondertekenaar.
//
// Op 27-09-2026 schreef een klant dat hij een document door twee mensen moest
// laten tekenen, met op elk blad een paraaf, en dat hij die functie niet zag.
// Hij had gelijk: meerdere ondertekenaars bestonden al, maar alleen de afzender
// kon zijn stempel op elke pagina herhalen, en een uitgenodigde ondertekenaar
// op /co-sign kon precies een handtekening en een datum plaatsen. Het woord
// "paraaf" stond nergens in het product.
//
// Deze suite houdt vier dingen vast:
//   1. relay en browser accepteren het veldtype 'initials' en hashen het gelijk
//      (recept 5), zodat een paraaf onder de handtekening valt;
//   2. een paraaf is EEN veld dat op elke pagina getekend wordt, dus ook een
//      contract van veertig pagina's past binnen het plafond van acht velden;
//   3. /co-sign (NL en EN) heeft de knop, en co-sign.js verbindt hem;
//   4. /sign noemt de paraaf op de plek waar je ondertekenaars kiest.
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { signMessageBytes, normaliseAppearance, appearanceHash } = require('../relay/envelope.js');
const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FRONT = path.join(REPO, 'frontend');
const readFront = (rel) => fs.readFileSync(path.join(FRONT, rel), 'utf8');

// ── 1. relay accepteert de paraaf, en niets anders nieuws ─────────────────────
const paraafManifest = normaliseAppearance({ version: 1, fields: [
  { type: 'seal', page_index: 3, x: .5, y: .8, w: .36, h: .105 },
  { type: 'initials', page_index: 0, x: .85, y: .92, w: .1, h: .045 },
] });
assert.equal(paraafManifest.fields[1].type, 'initials', 'relay houdt het paraafveld vast');
assert.throws(() => normaliseAppearance({ version: 1, fields: [{ type: 'stamp', page_index: 0, x: .1, y: .1, w: .1, h: .1 }] }),
  /invalid appearance type/, 'een onbekend veldtype blijft geweigerd');
assert.notEqual(appearanceHash(paraafManifest),
  appearanceHash({ version: 1, fields: [paraafManifest.fields[0]] }),
  'de paraaf zit in de hash: weglaten geeft een andere handtekening');

// ── 2. een paraaf is een veld, getekend op elke pagina ────────────────────────
const cosignSrc = readFront('co-sign.js');
function extract(name) {
  const start = cosignSrc.indexOf('export function ' + name + '(');
  assert.ok(start >= 0, 'co-sign.js exporteert ' + name);
  let depth = 0; let i = cosignSrc.indexOf('{', start);
  for (; i < cosignSrc.length; i++) {
    if (cosignSrc[i] === '{') depth++;
    else if (cosignSrc[i] === '}' && --depth === 0) break;
  }
  return cosignSrc.slice(start, i + 1).replace(/^export /, '');
}
const helpers = new Function(extract('initialsOf') + '\n' + extract('fieldPageIndexes') + '\nreturn { initialsOf, fieldPageIndexes };')();
assert.deepEqual(helpers.fieldPageIndexes({ type: 'initials', page_index: 0 }, 40), Array.from({ length: 40 }, (_, i) => i),
  'een paraaf komt op alle veertig pagina\'s');
assert.deepEqual(helpers.fieldPageIndexes({ type: 'seal', page_index: 2 }, 5), [2], 'een handtekening blijft op haar eigen pagina');
assert.deepEqual(helpers.fieldPageIndexes({ type: 'seal', page_index: 9 }, 5), [], 'een veld buiten het document wordt niet getekend');
assert.equal(helpers.initialsOf('Sandra de Vries'), 'S.D.V.');
assert.equal(helpers.initialsOf('j.jansen@example.nl'), 'J.J.');
assert.equal(helpers.initialsOf(''), '·');
assert.match(cosignSrc, /for \(const pageIndex of fieldPageIndexes\(field, pages\.length\)\)/,
  'het getekende pdf-bestand zet de paraaf op elke pagina');

// ── 3. de knop op /co-sign, in beide talen ────────────────────────────────────
for (const [rel, label] of [['co-sign.html', 'Paraaf op elke pagina'], ['en/co-sign.html', 'Initial every page']]) {
  const html = readFront(rel);
  assert.match(html, new RegExp('id="appearance-initials"[^>]*>' + label + '</button>'), rel + ' toont de paraafknop');
}
assert.match(cosignSrc, /\$\('appearance-initials'\)[^\n]*armAppearanceTool\('initials'\)/, 'de knop is verbonden');

// ── 4. /sign noemt de paraaf waar je ondertekenaars kiest ─────────────────────
for (const [rel, word] of [['sign.html', 'paraaf op elke pagina'], ['en/sign.html', 'initial every page']]) {
  const html = readFront(rel);
  const invite = html.slice(html.indexOf('data-mode="invite"'), html.indexOf('data-mode="alone"'));
  assert.ok(invite.toLowerCase().includes(word), rel + ': de kaart Handtekeningen vragen noemt de paraaf');
  assert.match(html, /id="ds-invite-paraaf-tip"/, rel + ': de afzender ziet bij het handtekeningvak dat ondertekenaars kunnen parafen');
}

// ── browser en relay hashen een manifest met paraaf gelijk ────────────────────
const MIME = { '.js': 'text/javascript', '.html': 'text/html', '.wasm': 'application/wasm' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/') pathname = '/index.html';
  const file = path.join(FRONT, pathname);
  if (!file.startsWith(FRONT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'domcontentloaded' });
  const input = { envelopeId: 'env_demo_paraaf', docHash: 'c'.repeat(64), emailHash: 'd'.repeat(64),
    signerPublicKey: Buffer.from('generic-public-key').toString('base64'), appearance: paraafManifest };
  const actual = await page.evaluate(async (inp) => {
    const signer = await import('/js/parasign-signer.js?v=18');
    const normalized = signer.normaliseSigningAppearance(inp.appearance);
    const message = signer.buildDocSignMessage({ envelopeId: inp.envelopeId, docHash: inp.docHash, partyIndex: 1,
      emailHash: inp.emailHash, recipeVersion: 5, signerPublicKey: inp.signerPublicKey, appearance: normalized });
    return { hex: Array.from(message, (b) => b.toString(16).padStart(2, '0')).join(''), normalized };
  }, input);
  const expected = signMessageBytes(input.envelopeId, input.docHash, 1, input.emailHash, 5, input.signerPublicKey, appearanceHash(paraafManifest)).toString('hex');
  assert.equal(actual.hex, expected, 'browser en relay maken dezelfde recept-5-bytes met een paraaf');
  assert.deepEqual(actual.normalized, paraafManifest, 'browser en relay normaliseren de paraaf gelijk');
} finally {
  await browser.close();
  server.close();
}
console.log('cosign-paraaf: paraaf op elke pagina, relay en browser gelijk, vindbaar op /sign en /co-sign');
