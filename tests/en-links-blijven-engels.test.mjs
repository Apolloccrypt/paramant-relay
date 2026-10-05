// Een Engelse pagina stuurt een Engelse lezer niet naar een Nederlandse pagina.
//
// Fase 1 (2026-10-04, SITE-03-F, SIGN-49) vond 283 links in de tekst van
// frontend/en/*.html die naar het Nederlandse pad gingen terwijl er een Engelse
// tegenhanger bestond: /en/parasign "Sign a document" naar /sign, /en -> /pricing,
// /en/about -> /security. De balk en de voet zijn al goed (apply-nav.py zet ze
// om); dit gaat over de links in de tekst zelf.
//
// Uitzondering: een link die zegt dat hij Nederlands is (hreflang="nl" of
// lang="nl"), zoals "Deze pagina in het Nederlands".
//
// Run: node --test tests/en-links-blijven-engels.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('EN-marketing- en hulppagina’s linken naar de Engelse tegenhanger', () => {
  const fe = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
  // App-pagina's met een eigen eigenaar vallen (nog) buiten deze poort.
  const buiten = /^en\/(co-sign|dashboard|parashare|get|ontvang|account|auth\/|billing|signup|setup|redeem|vault|ophalen|claim|request-key)/;
  const enBestaat = (p) => p === '/' ||
    fs.existsSync(path.join(fe, 'en', p.replace(/^\/|\/$/g, '') + '.html')) ||
    fs.existsSync(path.join(fe, 'en', p.replace(/^\/|\/$/g, ''), 'index.html'));
  const lopen = (dir) => fs.readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return fs.statSync(p).isDirectory() ? lopen(p) : (n.endsWith('.html') ? [p] : []);
  });
  const fout = [];
  for (const fp of lopen(path.join(fe, 'en'))) {
    const rel = path.relative(fe, fp).split(path.sep).join('/');
    if (buiten.test(rel)) continue;
    // De gegenereerde balk, la en voet laten we aan apply-nav.py.
    const html = fs.readFileSync(fp, 'utf8')
      .replace(/<nav class="nav">[\s\S]*?<\/nav>/g, '')
      .replace(/<footer>[\s\S]*?<\/footer>/g, '');
    for (const tag of html.match(/<a\b[^>]*>/gi) || []) {
      if (/hreflang="nl"|lang="nl"|class="nav-/.test(tag)) continue;
      // The no-JS fallback of a checkout button (en/pricing) is pinned to
      // /auth/login by relay/test/pricing-page.test.js; the JS path decides.
      if (/data-billing-product=/.test(tag)) continue;
      const m = tag.match(/href="(\/[^"#?]*)/);
      if (!m) continue;
      const p = m[1];
      if (/^\/(en(\/|$)|v1\/|v2\/|api\/|\.well-known\/|admin\/|dl\/)/.test(p)) continue;
      if (/\.[a-z0-9]{2,5}$/.test(p)) continue;
      if (enBestaat(p)) fout.push(`${rel}: ${tag.slice(0, 120)}`);
    }
  }
  assert.deepEqual(fout, [], `Engelse pagina's met een link naar de Nederlandse versie:\n${fout.join('\n')}`);
});

// /developer bestaat alleen in het Nederlands (de route is afgeschermd in
// nginx). Een Engelse link ernaartoe zegt dat dus, zoals /en/dashboard al deed:
// /en/account en het accountmenu stuurden zonder "(in Dutch)" naar de
// Nederlandse pagina (acceptatie 3.1.1 ronde 2, P5).
test('een Engelse link naar /developer zegt dat de pagina Nederlands is', () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
  const fout = [];
  const lopen = (dir) => fs.readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return fs.statSync(p).isDirectory() ? lopen(p) : (n.endsWith('.html') ? [p] : []);
  });
  for (const fp of lopen(path.join(root, 'en'))) {
    const html = fs.readFileSync(fp, 'utf8');
    for (const m of html.matchAll(/<a\b[^>]*href="\/developer"[^>]*>([^<]*)<\/a>/gi)) {
      if (!/hreflang="nl"/.test(m[0]) || !/\(in Dutch\)/.test(m[1])) fout.push(`${path.relative(root, fp)}: ${m[0]}`);
    }
  }
  assert.deepEqual(fout, []);
  const nav = fs.readFileSync(path.join(root, 'js', 'nav-auth.js'), 'utf8');
  assert.match(nav, /dev: 'Developer settings \(in Dutch\)', devLang: 'nl'/);
});
