// Eindmatrix DASH-09-L: the .psign from the dashboard next to the pdf with
// every signature (the readable copy) said "Dit is niet het ondertekende
// bestand". The proof is for the original, so the customer had to hunt for
// it. The readable copy that /co-sign makes now carries the signed original
// inside it, byte for byte, as a PDF attachment, and /verify checks that
// embedded original. It counts only when its SHA3-256 is the signed hash, so
// an attachment can never make another file pass.
// Chromium and WebKit.
// Run: node --test tests/verify-ingebed-origineel.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.png': 'image/png' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const browsers = [['chromium', await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) })]];
// WebKit runs where the host can start it (the Playwright image, pw-webkit.sh);
// a host without its libraries runs the Chromium half only.
try { browsers.push(['webkit', await webkit.launch({ headless: true })]); } catch { /* no WebKit on this host */ }
after(async () => { for (const [, b] of browsers) await b.close(); server.close(); });

test('co-sign embeds the signed original in the readable copy', () => {
  const src = fs.readFileSync(path.join(ROOT, 'co-sign.js'), 'utf8');
  const fn = src.slice(src.indexOf('async function renderPdfWithRecords'), src.indexOf('return new Uint8Array(await pdf.save'));
  assert.match(fn, /await pdf\.attach\(__documentBytes,/, 'the copy must carry the exact signed bytes');
});

for (const [kind, browser] of browsers) {
  test(`${kind}: the readable copy plus the proof verifies against the embedded original`, async () => {
    const page = await browser.newPage({ viewport: { width: 1000, height: 900 } });
    await page.route('**/v2/lookup-signer/**', (r) => r.abort());
    await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
    await page.addScriptTag({ url: '/vendor/pdf-lib/pdf-lib.min.js?v=1' });
    const fx = await page.evaluate(async () => {
      const { PDFDocument, StandardFonts } = window.PDFLib;
      const pqc = await import('/vendor/paramant-pqc.js');
      const signer = await import('/js/parasign-signer.js?v=23');
      const enc = new TextEncoder();
      const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
      const b64 = (b) => { let v = ''; for (const x of b) v += String.fromCharCode(x); return btoa(v); };
      const mk = async (line) => {
        const d = await PDFDocument.create();
        const f = await d.embedFont(StandardFonts.Helvetica);
        d.addPage([400, 300]).drawText(line, { x: 40, y: 200, size: 14, font: f });
        return new Uint8Array(await d.save({ useObjectStreams: false }));
      };
      const signed = await mk('Het contract zoals iedereen het tekende');
      const other = await mk('Een ander contract');
      // The readable copy, as co-sign.js renderPdfWithRecords makes it.
      const copyOf = async (embed) => {
        const d = await PDFDocument.load(signed);
        const f = await d.embedFont(StandardFonts.TimesRomanItalic);
        d.getPage(0).drawText('Demo Signer', { x: 40, y: 80, size: 18, font: f });
        if (embed) await d.attach(embed, 'contract.pdf', { mimeType: 'application/pdf', description: 'Het ondertekende origineel' });
        return new Uint8Array(await d.save({ useObjectStreams: false }));
      };
      const keys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
      const pk = b64(keys.publicKey);
      const emailHash = hex(pqc.sha3_256(enc.encode('demo@example.com')));
      const appearance = signer.normaliseSigningAppearance({ version: 1, fields: [] });
      const envelopeId = 'env_embedded_original';
      const signedHash = hex(pqc.sha3_256(signed));
      const msg = signer.buildDocSignMessage({ envelopeId, docHash: signedHash, partyIndex: 0, emailHash, recipeVersion: 5, signerPublicKey: pk, appearance });
      const psign = {
        version: 'parasign-doc-3', recipe_version: 5, sign_domain: 'paramant/parasign/doc/v1',
        algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256', original_filename: 'contract.pdf',
        stamped_hash: signedHash, stamped_filename: 'contract.pdf',
        signer_public_key: pk, party_email_hash: emailHash,
        appearance, appearance_hash: hex(signer.signingAppearanceHash(appearance)),
        signature: b64(pqc.ml_dsa65.sign(keys.secretKey, msg)),
        multiparty: { envelope_id: envelopeId, party_index: 0 },
      };
      return {
        signed: Array.from(signed), psign,
        copyWith: Array.from(await copyOf(signed)),
        copyWithout: Array.from(await copyOf(null)),
        copyOther: Array.from(await copyOf(other)),
        // Review #565, M1: visible pages that say something else, with the
        // real signed original attached.
        forgedVisible: Array.from(await (async () => {
          const d = await PDFDocument.load(other);
          await d.attach(signed, 'contract.pdf', { mimeType: 'application/pdf' });
          return new Uint8Array(await d.save({ useObjectStreams: false }));
        })()),
      };
    });

    async function check(doc) {
      await page.goto(origin + '/verify.html', { waitUntil: 'domcontentloaded' });
      await page.locator('#vf-document').setInputFiles({ name: 'contract-getekend.pdf', mimeType: 'application/pdf', buffer: Buffer.from(doc) });
      await page.locator('#vf-envelope').setInputFiles({ name: 'p.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fx.psign)) });
      await page.locator('#vf-verify').click();
      await page.waitForFunction(() => { const b = document.querySelector('#vf-result .ps-banner'); return b && (!b.classList.contains('info') || /klopt met dit document/.test(b.textContent)); }, null, { timeout: 20000 });
      await page.waitForTimeout(200);
      return {
        text: (await page.locator('#vf-result').innerText()).replace(/\s+/g, ' '),
        cls: await page.locator('#vf-result .ps-banner').first().getAttribute('class'),
        embedded: await page.locator('#vf-embedded').count(),
      };
    }

    const ok = await check(fx.copyWith);
    assert.doesNotMatch(ok.cls, /\berr\b/, ok.text);
    // Never the plain green: the visible pages of this file were not checked.
    assert.doesNotMatch(ok.cls, /\bok\b/, 'the full green banner on a copy whose visible pages are not covered');
    assert.match(ok.cls, /\bwarn\b/, ok.text);
    assert.match(ok.text, /De handtekeningen zijn geldig, voor het origineel in deze pdf\. Alleen dat origineel is gecontroleerd, niet de pagina.s die u nu ziet\./);
    assert.equal(ok.embedded, 1, ok.text);
    assert.match(ok.text, /Het origineel zit als bijlage in deze pdf\./);
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#vf-embedded-save')]);
    const saved = fs.readFileSync(await dl.path());
    assert.deepEqual([...saved], fx.signed, 'the saved original is the signed file, byte for byte');

    const forgedPages = await check(fx.forgedVisible);
    assert.match(forgedPages.cls, /\bwarn\b/, 'other visible pages with the real original attached: amber, never green');
    assert.match(forgedPages.text, /niet de pagina.s die u nu ziet/);
    assert.equal(forgedPages.embedded, 1);

    const plain = await check(fx.copyWithout);
    assert.match(plain.cls, /\berr\b/, 'a copy without the original stays red');
    assert.equal(plain.embedded, 0);
    const forged = await check(fx.copyOther);
    assert.match(forged.cls, /\berr\b/, 'another file embedded never passes');
    assert.equal(forged.embedded, 0);
    const orig = await check(fx.signed);
    assert.doesNotMatch(orig.cls, /\berr\b/, 'the original itself still verifies');
    assert.doesNotMatch(orig.text, /De pagina.s die u in dit bestand ziet/, 'the original itself is not called unchecked');
    assert.equal(orig.embedded, 0);
    await page.close();
  });
}
