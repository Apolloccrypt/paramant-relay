// Which root suites drive a browser, answered by the import graph instead of
// by the first line of the file.
//
// Two workflows split tests/*.mjs in half: test.yml runs the half that needs
// no browser (it installs no Chromium), sign-e2e.yml runs the half that does.
// Both asked the question with `grep -l "from 'playwright'" tests/*.mjs`, which
// reads one file and stops there.
//
// On 2026-09-04 that cost the repo three hours of CI. tests/ui-elements-contrast
// .test.mjs (PR #431) imports scripts/ui-contrast-sweep.mjs, and the sweep is
// what imports playwright. The grep saw no playwright in the test file, so the
// no-browser job took the suite, PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD meant there
// was no Chromium to launch, and the step never came back. The same blind spot
// kept the suite out of sign-e2e, so the only new gate of that pull request ran
// nowhere while it was hanging everywhere.
//
// So the question is asked of everything the suite pulls in: this walks the
// relative imports from each test file, as deep as they go, and reports a suite
// as a browser suite as soon as anything it reaches imports playwright. A
// helper that grows a browser dependency moves its suites with it, on the run
// after the commit, with no list to keep.
//
//   node scripts/browser-suites.mjs --browser      needs a browser
//   node scripts/browser-suites.mjs --no-browser   the rest
//
// Paths are printed one per line, sorted, relative to the repo root, so the
// output drops straight into `node --test $(...)`.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BROWSER_PACKAGES = new Set(['playwright', 'playwright-core', '@playwright/test']);

// `from '...'`, `import '...'` and `import('...')`, which is every shape an
// import specifier takes in this repo. A specifier inside a string or a comment
// would be a false positive; erring towards "needs a browser" is the safe side,
// since that half of the split installs one.
const SPECIFIERS = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"\n]+)['"]/g;

function specifiers(file) {
  let source;
  try { source = fs.readFileSync(file, 'utf8'); } catch { return []; }
  return [...source.matchAll(SPECIFIERS)].map((m) => m[1]);
}

// Bare specifier: is it the browser, or is it anything else. Relative: keep
// walking. A directory or an extensionless path is resolved the way node does,
// enough of it for the files that live here.
function resolveLocal(from, spec) {
  const base = path.resolve(path.dirname(from), spec);
  const tries = [base, base + '.mjs', base + '.js', path.join(base, 'index.mjs'), path.join(base, 'index.js')];
  for (const one of tries) {
    try { if (fs.statSync(one).isFile()) return one; } catch { /* next */ }
  }
  return null;
}

export function needsBrowser(entry) {
  const seen = new Set();
  const queue = [path.resolve(entry)];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    for (const spec of specifiers(file)) {
      if (BROWSER_PACKAGES.has(spec) || [...BROWSER_PACKAGES].some((p) => spec.startsWith(p + '/'))) return true;
      if (spec.startsWith('.')) {
        const local = resolveLocal(file, spec);
        if (local) queue.push(local);
      }
    }
  }
  return false;
}

const suites = fs.readdirSync(path.join(ROOT, 'tests'))
  .filter((name) => name.endsWith('.test.mjs'))
  .map((name) => path.join('tests', name))
  .sort();

const wanted = process.argv.includes('--browser') ? true
  : process.argv.includes('--no-browser') ? false
  : null;

if (wanted === null) {
  process.stderr.write('usage: node scripts/browser-suites.mjs --browser | --no-browser\n');
  process.exit(2);
}

for (const suite of suites) {
  if (needsBrowser(path.join(ROOT, suite)) === wanted) console.log(suite);
}
