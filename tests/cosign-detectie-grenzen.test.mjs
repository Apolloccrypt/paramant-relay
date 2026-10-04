// Security review ronde 2, punt (g): de tekst- en pixeldetectie van /sign en
// /co-sign moet een kwaadaardige pdf aankunnen.
//
//  G2  buildOccupancy markeerde per tekstbox elke rastercel: 50.000 paginagrote
//      boxen bevroren de tab 19,5 s. Nu: onder 200 ms.
//  G1  textOfAllPages las elke pagina zonder grens: 2.000 lege pagina's werden
//      na elkaar gerenderd. Nu: hooguit 300 pagina's, en de pagina blijft
//      tussendoor vrij (geen gat in de event loop boven 200 ms).
//  G3  één onzichtbaar teken maakte een pagina "tekst", zodat de pixelscan niet
//      draaide; tekst van grootte 0 telde mee; een pagina die niet te lezen is
//      gold als vrij. Nu: met ink:true tellen pixels altijd mee, grootte 0 is
//      geen tekst, en een onleesbare pagina geeft een fout (de aanroeper kiest
//      dan het handtekeningblad).
// Run: node --test tests/cosign-detectie-grenzen.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { paraafSpotsForParties } from '../frontend/js/cosign-layout.js';
import { textBoxesFromItems } from '../frontend/js/paraaf-place.js';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const A4 = { width: 595.28, height: 841.89 };

test('G2: 50.000 paginagrote tekstboxen kosten minder dan 200 ms', () => {
  const big = Array.from({ length: 50000 }, () => ({ x: 0, y: 0, w: A4.width, h: A4.height }));
  const t0 = performance.now();
  const spots = paraafSpotsForParties({ pages: [A4], textBoxesPerPage: [big], count: 3, avoid: [] });
  const ms = performance.now() - t0;
  assert.equal(spots.length, 3);
  assert.ok(ms < 200, `${Math.round(ms)} ms`);
});

test("G2: 2.000 pagina's met elk 25 grote boxen kosten minder dan 200 ms", () => {
  const pages = Array.from({ length: 2000 }, () => A4);
  const boxes = pages.map(() => Array.from({ length: 25 }, (_, i) => ({ x: 0, y: i * 30, w: A4.width, h: 400 })));
  const t0 = performance.now();
  paraafSpotsForParties({ pages, textBoxesPerPage: boxes, count: 2, avoid: [] });
  const ms = performance.now() - t0;
  assert.ok(ms < 200, `${Math.round(ms)} ms`);
});

test('G3: tekst van grootte 0 of zonder breedte is geen tekst', () => {
  const items = [
    { str: 'x', transform: [0, 0, 0, 0, 10, 10], width: 0, height: 0 },
    { str: 'x', transform: [0.1, 0, 0, 0.1, 10, 10], width: 0.05, height: 0.1 },
    { str: 'Artikel 1', transform: [11, 0, 0, 11, 56, 700], width: 50, height: 11 },
  ];
  assert.equal(textBoxesFromItems(items).length, 1);
});

// The browser half: the real pdf.js on real pdfs built with pdf-lib.
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.wasm': 'application/wasm', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>t</title>'); }
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });
const page = await browser.newPage();
await page.goto(`http://127.0.0.1:${server.address().port}/`);
await loadPdfLibs(page);
await page.waitForFunction(() => window.PDFLib && window.pdfjsLib, null, { timeout: 30000 });

const scan = await page.evaluate(async () => {
  const { scanPdfPages, pdfjsPageBoxes } = await import('/js/paraaf-place.js?v=5');
  const doc = await window.PDFLib.PDFDocument.create();
  for (let i = 0; i < 2000; i++) doc.addPage([595.28, 841.89]);
  const bytes = await doc.save();
  const pdf = await window.pdfjsLib.getDocument({ data: bytes }).promise;
  let last = performance.now(), maxGap = 0;
  const timer = setInterval(() => { const now = performance.now(); maxGap = Math.max(maxGap, now - last); last = now; }, 10);
  const t0 = performance.now();
  const { pages, results } = await scanPdfPages(pdf, (p) => pdfjsPageBoxes(p), 300);
  const ms = performance.now() - t0;
  clearInterval(timer);
  return { numPages: pdf.numPages, read: pages.length, results: results.length, maxGap: Math.round(maxGap), ms: Math.round(ms) };
});

const g3 = await page.evaluate(async () => {
  const { pdfjsPageBoxes, inkBoxesOfPdfjsPage } = await import('/js/paraaf-place.js?v=5');
  const L = window.PDFLib;
  const doc = await L.PDFDocument.create();
  const font = await doc.embedFont(L.StandardFonts.Helvetica);
  const pg = doc.addPage([595.28, 841.89]);
  // One invisible character in a corner (render mode 3)...
  pg.pushOperators(L.beginText(), L.setFontAndSize(font.name, 10), L.setTextRenderingMode(L.TextRenderingMode.Invisible), L.moveText(20, 20), L.showText(font.encodeText('.')), L.endText());
  // ...and the "articles" as a picture: dark blocks in the middle of the page.
  for (let i = 0; i < 12; i++) pg.drawRectangle({ x: 60, y: 300 + i * 30, width: 470, height: 14, color: L.rgb(0, 0, 0) });
  // A page far taller than wide, which no canvas can hold.
  doc.addPage([10, 14400]);
  const pdf = await window.pdfjsLib.getDocument({ data: await doc.save() }).promise;
  const p1 = await pdf.getPage(1);
  const textOnly = await pdfjsPageBoxes(p1);
  const withInk = await pdfjsPageBoxes(p1, { ink: true });
  const middle = { x: 60, y: 300, w: 470, h: 360 };
  const covered = (boxes) => boxes.some((b) => b.x < middle.x + middle.w && middle.x < b.x + b.w && b.y < middle.y + middle.h && middle.y < b.y + b.h);
  let tallError = false;
  try { await inkBoxesOfPdfjsPage(await pdf.getPage(2)); } catch { tallError = true; }
  return { textOnlyCovers: covered(textOnly), withInkCovers: covered(withInk), tallError };
});

test("G1: van 2.000 pagina's worden er hooguit 300 gelezen, zonder de pagina te blokkeren", () => {
  assert.equal(scan.numPages, 2000);
  assert.equal(scan.read, 300);
  assert.equal(scan.results, 300);
  assert.ok(scan.maxGap < 200, `grootste gat in de event loop ${scan.maxGap} ms (totaal ${scan.ms} ms)`);
});

test('G3: met ink:true telt beeld onder een onzichtbaar teken mee', () => {
  assert.equal(g3.textOnlyCovers, false, 'zonder pixels ziet de tekstlaag alleen de hoek');
  assert.equal(g3.withInkCovers, true, 'met pixels is het midden bezet');
});

test('G3: een pagina die niet te renderen is geeft een fout, geen "vrij"', () => {
  assert.equal(g3.tallError, true);
});
