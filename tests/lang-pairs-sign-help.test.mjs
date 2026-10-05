// The signing pages and the help articles, Dutch and English, 23 September 2026.
//
// /sign, /co-sign, /parasign and every /help article are Dutch on their own
// path, with the English text kept under /en/. Each pair must say which it is,
// point at the other the way search engines read it (canonical and hreflang),
// and carry a visible link across. The scripts the signing pages load are one
// file for both languages: every L(nl, en) call in them must hand over two real
// sentences, so the English page never shows an empty string or the Dutch one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const ORIGIN = 'https://paramant.app';

const helpSlugs = fs.readdirSync(path.join(ROOT, 'frontend/help'))
  .filter((f) => f.endsWith('.html')).map((f) => f.slice(0, -5));
const PAIRS = [
  ['sign', '/sign'], ['co-sign', '/co-sign'], ['parasign', '/parasign'],
  ...helpSlugs.map((s) => [`help/${s}`, s === 'index' ? '/help' : `/help/${s}`]),
];

test('every signing and help page has an English twin, and each points at the other', () => {
  const problems = [];
  for (const [file, nl] of PAIRS) {
    const en = `/en${nl}`;
    const nlHtml = read(`frontend/${file}.html`);
    const enPath = `frontend/en/${file}.html`;
    if (!fs.existsSync(path.join(ROOT, enPath))) { problems.push(`${enPath} is missing`); continue; }
    const enHtml = read(enPath);
    if (!/^<!DOCTYPE html>\s*<html lang="nl">/i.test(nlHtml)) problems.push(`${file}: <html lang="nl">`);
    if (!/^<!DOCTYPE html>\s*<html lang="en">/i.test(enHtml)) problems.push(`en/${file}: <html lang="en">`);
    for (const [name, html, canonical] of [[file, nlHtml, nl], [`en/${file}`, enHtml, en]]) {
      if (!html.includes(`<link rel="canonical" href="${ORIGIN}${canonical}">`)) problems.push(`${name}: canonical must be ${canonical}`);
      for (const [lang, href] of [['nl', nl], ['en', en], ['x-default', nl]]) {
        if (!html.includes(`<link rel="alternate" hreflang="${lang}" href="${ORIGIN}${href}">`)) problems.push(`${name}: hreflang ${lang} must point at ${href}`);
      }
    }
    const nlBody = nlHtml.slice(nlHtml.indexOf('<body'));
    const enBody = enHtml.slice(enHtml.indexOf('<body'));
    if (!new RegExp(`href="${en}" hreflang="en" lang="en">This page in English<`).test(nlBody)) problems.push(`${file}: no visible way to ${en}`);
    if (!new RegExp(`href="${nl}" hreflang="nl" lang="nl">Deze pagina in het Nederlands<`).test(enBody)) problems.push(`en/${file}: no visible way back to ${nl}`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('nginx serves the English help index the way it serves /help', () => {
  assert.match(read('deploy/nginx-paramant-live.conf'), /location = \/en\/help \{ try_files \/en\/help\/index\.html =404; \}/);
});

test('the Dutch pages read Dutch and the English copies keep the English text', () => {
  const says = [
    ['frontend/sign.html', 'Laat een belangrijk document ondertekenen.'],
    ['frontend/sign.html', 'Dit document ondertekenen'],
    ['frontend/en/sign.html', 'Get an important document signed.'],
    ['frontend/en/sign.html', 'Sign this document'],
    ['frontend/en/help/index.html', 'Signing a document needs an account'],
  ];
  for (const [file, phrase] of says) assert.ok(read(file).includes(phrase), `${file} must say "${phrase}"`);
  // The English copy logs in and comes back to itself, not to the Dutch page.
  assert.match(read('frontend/en/sign.html'), /href="\/auth\/login\?next=\/en\/sign"/);
});

// Every L( call, its two string literals, parsed the way the browser would read
// them. An empty or identical pair is a sentence one of the two pages lost.
function lCalls(src) {
  const calls = [];
  const lit = /\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`)\s*/y;
  for (let i = src.indexOf('L('); i !== -1; i = src.indexOf('L(', i + 2)) {
    if (i > 0 && /[\w$.]/.test(src[i - 1])) continue;
    lit.lastIndex = i + 2;
    const a = lit.exec(src); if (!a) continue;
    if (src[lit.lastIndex] !== ',') continue;
    lit.lastIndex += 1;
    const b = lit.exec(src); if (!b || src[lit.lastIndex] !== ')') continue;
    calls.push([a[1] ?? a[2] ?? a[3], b[1] ?? b[2] ?? b[3]]);
  }
  return calls;
}

test('the signing scripts carry both languages in one file, Dutch by default', () => {
  for (const file of ['frontend/sign-flow.js', 'frontend/js/totp-prompt.js', 'frontend/js/parasign-document-capsule.js', 'frontend/js/parasign-pdf-ops.js']) {
    const src = read(file);
    assert.match(src, /const L = \(nl, en\) => \(.*=== 'en' \? en : nl\)|const L = \(nl, en\) => \(EN \? en : nl\)/, `${file}: L() must fall back to Dutch`);
    const calls = lCalls(src);
    assert.ok(calls.length > 0, `${file}: no L() calls found`);
    // 'Delete page ' + n + L(' verwijderen', '') is the one pair whose English
    // half is empty on purpose: English puts the verb in front.
    const bad = calls.filter(([nl, en]) => !nl.trim() || (!en.trim() && nl !== ' verwijderen'));
    assert.deepEqual(bad, [], `${file}: an L() pair with an empty half`);
  }
  const sf = lCalls(read('frontend/sign-flow.js'));
  assert.ok(sf.length >= 200, `sign-flow.js should carry its sentences through L(), found ${sf.length}`);
  assert.ok(sf.some(([nl, en]) => nl === 'Dit document wordt klaargezet om te ondertekenen...' && en === 'Preparing this document for signing...'));
});

test('the signature sheet in the PDF is bilingual and the seal keeps its fixed text', () => {
  const sf = read('frontend/sign-flow.js');
  for (const pair of [
    ["'ParaSign-handtekeningblad'", "'ParaSign signature sheet'"],
    ["'Bronbestand', 'Source file'", "'Ondertekend op', 'Signed at'"],
    ["'Controleer de getekende pdf samen met het bijbehorende .psign-bestand.", "'Verify the signed PDF together with its .psign file."],
  ]) for (const s of pair) assert.ok(sf.includes(s), `sign-flow.js must draw ${s} on the sheet`);
  assert.equal((sf.match(/'POST-QUANTUM SIGNED'/g) || []).length, 2, 'the seal badge is one fixed text in both languages');
  assert.match(read('frontend/co-sign.js'), /page\.drawText\('PARAMANT SIGNED'/, 'the co-sign seal is one fixed text in both languages');
});
