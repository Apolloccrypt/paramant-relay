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
// A BROWSER IS NOT THE ONLY THING A SUITE CAN NEED. On 2026-09-05 the same
// blind spot cost a red run again, one question further along:
// tests/koper-hele-weg.test.mjs drives a browser AND boots two real relay.js
// processes plus the admin server, and sign-e2e is self-contained by design
// (it serves frontend/ and stubs /api, and installs no relay deps, no
// @paramant/core and no redis). Being a browser suite put it in the only job
// that could not possibly run it: nine failures, all of them
// "Cannot find module .../admin/node_modules/redis".
//
// So the same import walk answers a second question. Anything a suite reaches
// that spawns relay.js means the suite needs the full stack, and the two
// answers together split the browser suites into the job that stubs the
// backend and the job that builds one. Asked of the import graph, so a suite
// that grows a backend dependency moves jobs on the run after the commit,
// with no list to keep. The two browser lists partition the set, so a suite
// cannot fall out of both.
//
//   node scripts/browser-suites.mjs --browser            needs a browser
//   node scripts/browser-suites.mjs --no-browser         the rest
//   node scripts/browser-suites.mjs --browser-no-stack   browser, stubbed backend
//   node scripts/browser-suites.mjs --stack              boots a real relay.js
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

// Walk the relative imports from `entry` as deep as they go, and ask `hit` of
// every file reached and of every bare specifier it names. One walk, two
// questions, so the answers can never be asked of different graphs.
function reaches(entry, hit) {
  const seen = new Set();
  const queue = [path.resolve(entry)];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const specs = specifiers(file);
    if (hit({ file, specs })) return true;
    for (const spec of specs) {
      if (spec.startsWith('.')) {
        const local = resolveLocal(file, spec);
        if (local) queue.push(local);
      }
    }
  }
  return false;
}

export function needsBrowser(entry) {
  return reaches(entry, ({ specs }) => specs.some((spec) =>
    BROWSER_PACKAGES.has(spec) || [...BROWSER_PACKAGES].some((p) => spec.startsWith(p + '/'))));
}

// Does anything this suite reaches START A RELAY. A helper that spawns
// relay.js needs everything a relay needs: the relay's own node_modules, the
// @paramant/core binding it loads eagerly at boot, the admin dependencies and
// a reachable redis. Naming the file it spawns is the honest signal, and it is
// in the source of the helper rather than in a list here.
const RELAY_ENTRYPOINT = /['"]relay\.js['"]/;
export function needsStack(entry) {
  return reaches(entry, ({ file }) => {
    if (path.resolve(file) === path.resolve(entry)) return false;
    try { return RELAY_ENTRYPOINT.test(fs.readFileSync(file, 'utf8')); } catch { return false; }
  });
}

const suites = fs.readdirSync(path.join(ROOT, 'tests'))
  .filter((name) => name.endsWith('.test.mjs'))
  .map((name) => path.join('tests', name))
  .sort();

const MODES = {
  '--browser': (b) => b,
  '--no-browser': (b) => !b,
  '--browser-no-stack': (b, s) => b && !s,
  '--stack': (b, s) => s,
};
const mode = Object.keys(MODES).find((flag) => process.argv.includes(flag));

if (!mode) {
  process.stderr.write(`usage: node scripts/browser-suites.mjs ${Object.keys(MODES).join(' | ')}\n`);
  process.exit(2);
}

for (const suite of suites) {
  const full = path.join(ROOT, suite);
  if (MODES[mode](needsBrowser(full), needsStack(full))) console.log(suite);
}
