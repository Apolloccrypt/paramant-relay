// De PDF-sweep van 2026-10-04 (76 echte pdf's door de echte /sign-UI) vond in
// de solo-route zes dingen die stil misgingen. Elk krijgt hier een geval:
//
//   B1  Geen vrije hoek: de paraaf ging zonder melding over de tekst. Nu eerst
//       verder zoeken langs de margebanden; lukt dat niet, dan rood omlijnd en
//       een melding met het paginanummer.
//   B2  /UserUnit: pdf.js toont de pagina vergroot, pdf-lib tekent in gewone
//       user space; het zegel viel van de pagina (userunit-2) of ontbrak
//       (userunit-10). Nu landt het waar het stond.
//   B3  Een bestaande digitale handtekening wordt ongeldig als pdf-lib het
//       bestand opnieuw schrijft: dat staat nu vóór het tekenen op het scherm.
//   (B4, de 5 MB-grens bij versturen ter ondertekening, hoort bij het
//   co-sign-pad en staat elders.)
//   B5  Voorloopbytes vóór %PDF gaven "geen pdf".
//   B6  Een PDF/A-bestand claimde na tekenen nog PDF/A (met niet-ingebedde
//       fonts erbij): de claim gaat uit de XMP.
//
// Run: node --test tests/sign-pdf-sweep.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, launch, newPage, openSign, makePdf, pickBytes, waitPlaced, clickPage, uiBoxes, signAndDownload, measurePdf } from './helpers/sign-flow-harness.mjs';

const { server, origin } = await startServer();
const browser = await launch();
after(async () => { await browser.close(); server.close(); });

function pdfLib() {
  const req = createRequire(import.meta.url);
  return req(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'vendor', 'pdf-lib', 'pdf-lib.min.js'));
}

// A page of size w x h (points) with text rows over the given y ranges, each
// row spanning x0..x1. rows: [{ y0, y1, x0, x1 }].
async function textPdf(pages) {
  const P = pdfLib();
  const doc = await P.PDFDocument.create();
  const font = await doc.embedFont(P.StandardFonts.Helvetica);
  for (const { size, rows } of pages) {
    const pg = doc.addPage(size);
    for (const r of rows) {
      for (let y = r.y0; y <= r.y1; y += 9) {
        let line = '';
        while (font.widthOfTextAtSize(line + 'tekst ', 8) < r.x1 - r.x0) line += 'tekst ';
        pg.drawText(line.trim(), { x: r.x0, y, size: 8, font });
      }
    }
  }
  return Buffer.from(await doc.save());
}

test('B1: geen vrije plek in de marge: rood omlijnd en een melding, niet stil over de tekst', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const A4 = [595.28, 841.89];
  const full = { size: A4, rows: [{ y0: 4, y1: 836, x0: 4, x1: 590 }] };
  const pdf = await textPdf([{ size: A4, rows: [{ y0: 700, y1: 800, x0: 56, x1: 500 }] }, full]);
  await pickBytes(page, pdf, 'vol.pdf');
  await waitPlaced(page, 2);
  await page.locator('#ds-allpages').check();
  await clickPage(page, 0, 0.5, 0.6);
  await page.waitForFunction(() => document.querySelectorAll('.ds-paraaf').length >= 1, null, { timeout: 20000 });
  const notice = page.locator('#ds-paraaf-over-text');
  await notice.waitFor({ timeout: 10000 });
  assert.match(await notice.textContent(), /Op pagina 2 is in de marge geen vrije plek: de paraaf komt daar over de tekst/);
  assert.equal(await page.locator('.ds-paraaf[data-over-text="1"]').count(), 1);
  // Zet de signer "elke pagina" uit, dan is de melding weg.
  await page.locator('#ds-allpages').uncheck();
  await page.waitForFunction(() => !document.getElementById('ds-paraaf-over-text'), null, { timeout: 10000 });
  await page.context().close();
});

test('B1: hoeken bezet maar de zijmarge vrij: de paraaf gaat in de margeband, niet over de tekst', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const A4 = [595.28, 841.89];
  // Volle breedte bovenaan en onderaan (alle vier de hoeken), smal ertussen.
  const rows = [{ y0: 4, y1: 200, x0: 4, x1: 590 }, { y0: 640, y1: 836, x0: 4, x1: 590 }, { y0: 210, y1: 630, x0: 56, x1: 380 }];
  const pdf = await textPdf([{ size: A4, rows: [{ y0: 700, y1: 800, x0: 56, x1: 500 }] }, { size: A4, rows }]);
  await pickBytes(page, pdf, 'hoeken.pdf');
  await waitPlaced(page, 2);
  await page.locator('#ds-allpages').check();
  await clickPage(page, 0, 0.5, 0.6);
  await page.waitForFunction(() => document.querySelectorAll('.ds-paraaf').length >= 1, null, { timeout: 20000 });
  await page.waitForTimeout(300);
  const p = (await uiBoxes(page)).find((b) => b.kind === 'paraaf' && b.page === 1);
  assert.ok(p, 'een paraaf op pagina 2');
  // Vrij betekent: tussen y 210 en 630 pt en rechts van x 380 pt (als fractie).
  const top = 1 - 630 / 841.89, bottom = 1 - 210 / 841.89;
  assert.ok(p.y >= top - 0.005 && p.y + p.h <= bottom + 0.005, `paraaf y ${p.y.toFixed(3)}..${(p.y + p.h).toFixed(3)} buiten de vrije band ${top.toFixed(3)}..${bottom.toFixed(3)}`);
  assert.ok(p.x >= 380 / 595.28, `paraaf x ${p.x.toFixed(3)} over de smalle tekst`);
  assert.equal(await page.locator('#ds-paraaf-over-text').count(), 0);
  await page.context().close();
});

for (const uu of [2, 10]) {
  test(`B2: /UserUnit ${uu}: het zegel landt waar het stond`, async () => {
    const page = await newPage(browser);
    await openSign(page, origin);
    const P = pdfLib();
    const base = await makePdf(page, { pages: [{ size: [595.28 / uu, 841.89 / uu] }] });
    const doc = await P.PDFDocument.load(base);
    doc.getPage(0).node.set(P.PDFName.of('UserUnit'), P.PDFNumber.of(uu));
    const pdf = Buffer.from(await doc.save());
    await pickBytes(page, pdf, `userunit-${uu}.pdf`);
    await waitPlaced(page, 1);
    await clickPage(page, 0, 0.5, 0.82);
    const seal = (await uiBoxes(page)).find((b) => b.kind === 'seal');
    assert.ok(seal, 'zegel geplaatst');
    const res = await signAndDownload(page);
    assert.equal(res.error, undefined, res.error);
    const m = (await measurePdf(page, res.pdf, 0))[0];
    assert.ok(m.navy, 'het zegel staat in de getekende pdf');
    for (const k of ['x', 'y', 'w', 'h']) assert.ok(Math.abs(m.navy[k] - seal[k]) <= 0.01, `${k}: getekend ${m.navy[k].toFixed(4)} vs getoond ${seal[k].toFixed(4)}`);
    await page.context().close();
  });
}

test('B3: een pdf met een digitale handtekening: de waarschuwing staat er vóór het tekenen', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const P = pdfLib();
  const doc = await P.PDFDocument.load(await makePdf(page, { pages: [{ size: [595.28, 841.89] }] }));
  const sig = doc.context.obj({ Type: 'Sig', Filter: 'Adobe.PPKLite', SubFilter: 'ETSI.CAdES.detached', ByteRange: [0, 100, 200, 300], Contents: P.PDFHexString.of('00'.repeat(16)) });
  doc.catalog.set(P.PDFName.of('ParamantTestSig'), doc.context.register(sig));
  const pdf = Buffer.from(await doc.save({ useObjectStreams: false }));
  await pickBytes(page, pdf, 'getekend.pdf');
  await waitPlaced(page, 1);
  const warn = page.locator('#ds-existing-sig');
  await warn.waitFor({ timeout: 10000 });
  assert.match(await warn.textContent(), /heeft al een digitale handtekening[\s\S]*geldt die bestaande digitale handtekening daarna niet meer/);
  await page.context().close();
});

test('B3: een gewone pdf krijgt die waarschuwing niet', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  await pickBytes(page, await makePdf(page, { pages: [{ size: [595.28, 841.89] }] }), 'gewoon.pdf');
  await waitPlaced(page, 1);
  assert.equal(await page.locator('#ds-existing-sig').count(), 0);
  await page.context().close();
});

test('B5: bytes vóór %PDF: de pdf opent en tekent', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const pdf = await makePdf(page, { pages: [{ size: [595.28, 841.89] }] });
  const junk = Buffer.alloc(1025, 0x41);
  await pickBytes(page, Buffer.concat([junk, pdf]), 'voorloop.pdf');
  await waitPlaced(page, 1);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.equal(res.error, undefined, res.error);
  assert.equal(res.pdf.subarray(0, 5).toString('latin1'), '%PDF-');
  await page.context().close();
});

test('B6: een PDF/A-claim staat na tekenen niet meer in de XMP', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const P = pdfLib();
  const doc = await P.PDFDocument.load(await makePdf(page, { pages: [{ size: [595.28, 841.89] }] }));
  const xmp = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    + '<rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/" pdfaid:part="2" pdfaid:conformance="B"/>'
    + '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title><rdf:Alt><rdf:li xml:lang="x-default">Huurcontract</rdf:li></rdf:Alt></dc:title></rdf:Description>'
    + '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>';
  doc.catalog.set(P.PDFName.of('Metadata'), doc.context.register(doc.context.stream(new TextEncoder().encode(xmp), { Type: 'Metadata', Subtype: 'XML' })));
  const pdf = Buffer.from(await doc.save());
  await pickBytes(page, pdf, 'pdfa.pdf');
  await waitPlaced(page, 1);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.equal(res.error, undefined, res.error);
  const out = await P.PDFDocument.load(res.pdf);
  const st = out.context.lookup(out.catalog.get(P.PDFName.of('Metadata')));
  const text = new TextDecoder().decode(st instanceof P.PDFRawStream ? P.decodePDFRawStream(st).decode() : st.getContents());
  assert.doesNotMatch(text, /pdfaid:(part|conformance)/, 'PDF/A-claim staat er nog');
  assert.match(text, /Huurcontract/, 'de rest van de metadata blijft');
  await page.context().close();
});
