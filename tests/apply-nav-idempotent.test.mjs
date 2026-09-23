// frontend/apply-nav.py is de stempel: hij schrijft de nav, de mobiele la, de
// voet, de legal-strip en de vier verwijzingen naar design-system.css, nav.css,
// nav.js en nav-auth.js in elke pagina die de gedeelde schil draagt.
//
// Waarom deze poort bestaat. Die verwijzingen dragen een cache-bust, en de
// nginx-conf serveert CSS als `immutable, max-age=1y`. Een gewijzigd bestand
// moet dus onder een nieuwe url, en dat nummer staat op twee plekken: in de 58
// pagina's en in de constanten DS_LINK en NAV_LINK bovenin de generator. Wie
// alleen de pagina's bijwerkt, krijgt een generator die de bump terugdraait
// zodra iemand hem draait. Precies dat gebeurde in deze tak: de pagina's
// stonden op design-system.css?v=24 en de generator nog op ?v=23, en een
// onschuldige `python3 frontend/apply-nav.py` zou 58 pagina's stil hebben
// teruggezet naar een stylesheet die niet meer bestaat.
//
// Een generator die zijn eigen uitvoer niet reproduceert is geen generator maar
// een eenmalige patch. Deze test draait hem op een kopie van frontend/ en eist
// een lege diff: geen bestand gewijzigd, geen byte verschil.
//
// Alles staat in functiescope. tests/*.mjs is één gedeelde top-level
// naamruimte waar elke openstaande pull request in schrijft; scripts/
// check-test-declarations.sh bewaakt dat en dit bestand voegt er niets aan toe.
//
// Run: node --test tests/apply-nav-idempotent.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('apply-nav.py reproduces frontend/ byte for byte', () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'apply-nav-'));
  try {
    const copy = path.join(work, 'frontend');
    fs.cpSync(root, copy, { recursive: true });

    // De generator vindt zijn bestanden via os.path.dirname(__file__), dus een
    // kopie van de map is een volledige, geïsoleerde draai. Niets in de
    // werkboom wordt aangeraakt.
    const output = execFileSync('python3', [path.join(copy, 'apply-nav.py')], { encoding: 'utf8' });

    const walk = (dir, base, into) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full, base, into);
        else into.set(path.relative(base, full).split(path.sep).join('/'), fs.readFileSync(full));
      }
      return into;
    };
    const before = walk(root, root, new Map());
    const after = walk(copy, copy, new Map());

    const missing = [...before.keys()].filter((name) => !after.has(name));
    const extra = [...after.keys()].filter((name) => !before.has(name));
    assert.deepEqual(missing, [], `apply-nav.py lost these files: ${missing.join(', ')}`);
    assert.deepEqual(extra, [], `apply-nav.py created these files: ${extra.join(', ')}`);

    const changed = [];
    for (const [name, body] of before) {
      if (!after.get(name).equals(body)) {
        const was = body.toString('utf8').split('\n');
        const now = after.get(name).toString('utf8').split('\n');
        const at = was.findIndex((line, index) => line !== now[index]);
        changed.push(`${name}:${at + 1}\n      committed: ${String(was[at]).trim().slice(0, 120)}\n      generated: ${String(now[at]).trim().slice(0, 120)}`);
      }
    }
    assert.deepEqual(changed, [],
      `frontend/apply-nav.py is not idempotent. Running it on a clean checkout rewrites:\n  ${changed.join('\n  ')}\n`
      + 'The generator and the pages disagree. Update DS_LINK, NAV_LINK, NAV_JS or NAV_AUTH_JS in '
      + 'frontend/apply-nav.py to the version the pages carry, or run the generator and commit its output. '
      + `Its own report of that run:\n${output.split('\n').slice(0, 3).join('\n')}`);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

// The language switch (23 September 2026). Every page with the shared bar says
// NL | EN, marks the language it is in, and each half goes to the same page in
// that language: the path with or without /en in front. A page without a
// counterpart sends the other half to that language's home page, never to a
// 404. A page that declares lang="en" carries the English bar, every other
// page the Dutch one.
test('every shared bar carries NL | EN, pointing at the same page in the other language', () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
  const urlOf = (rel) => {
    let slug = rel.replace(/\.html$/, '');
    if (slug === 'index') return '/';
    if (slug.endsWith('/index')) slug = slug.slice(0, -'/index'.length);
    return '/' + slug;
  };
  const pages = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (!['node_modules', 'vendor'].includes(entry.name)) walk(full); }
      else if (entry.name.endsWith('.html')) pages.push(path.relative(root, full).split(path.sep).join('/'));
    }
  };
  walk(root);
  const problems = [];
  let stamped = 0;
  for (const rel of pages) {
    const html = fs.readFileSync(path.join(root, rel), 'utf8');
    const nav = (html.match(/<nav class="nav">[\s\S]*?<\/nav>/) || [''])[0];
    if (!nav || !/nav-hamburger/.test(nav)) continue;
    // co-sign and developer keep their own, narrower app nav (KEEP_OWN_NAV in
    // apply-nav.py); the generator does not stamp them, so neither does this.
    if (['co-sign.html', 'developer.html'].includes(rel)) continue;
    stamped++;
    // Where the page sits decides the two links; what it says it is (<html
    // lang>) decides which half is current and which bar it carries.
    const underEn = rel.startsWith('en/');
    const english = /<html\b[^>]*\blang="en/i.test(html);
    const nlRel = underEn ? rel.slice(3) : rel;
    const enRel = underEn ? rel : `en/${rel}`;
    const nl = fs.existsSync(path.join(root, nlRel)) ? urlOf(nlRel) : '/';
    const en = fs.existsSync(path.join(root, enRel)) ? urlOf(enRel) : '/en';
    const sw = (nav.match(/<div class="nav-lang"[^>]*>[\s\S]*?<\/div>/) || [''])[0];
    if (!sw) { problems.push(`${rel}: no language switch in the bar`); continue; }
    if (!/aria-label="Taal \/ Language"/.test(sw)) problems.push(`${rel}: the switch has no "Taal / Language" label`);
    if (!sw.includes(`<a href="${nl}" hreflang="nl" lang="nl"${english ? '' : ' aria-current="true"'}>NL</a>`)) problems.push(`${rel}: NL should go to ${nl}${english ? '' : ' and be marked current'}`);
    if (!sw.includes(`<a href="${en}" hreflang="en" lang="en"${english ? ' aria-current="true"' : ''}>EN</a>`)) problems.push(`${rel}: EN should go to ${en}${english ? ' and be marked current' : ''}`);
    const dutchBar = /class="nav-link">Versturen</.test(nav);
    if (english === dutchBar) problems.push(`${rel}: carries the ${dutchBar ? 'Dutch' : 'English'} bar`);
  }
  assert.ok(stamped > 40, `expected the shared bar on most pages, found ${stamped}`);
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});
