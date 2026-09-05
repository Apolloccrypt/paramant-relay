// Every knob that changes how PARAMANT behaves is written down in one place,
// and this suite is what keeps that place from going stale.
//
// deploy/.env.example already covers the environment variables the relay and
// the admin panel read; tests/env-documented.test.mjs guards that file. It
// stops at those two directories and at process.env. Measured on 2026-09-05,
// the knobs it cannot see:
//
//   34 environment variables read in frontend/, scripts/, tests/ and
//      extensions/ that appear in no .env.example, including
//      PARAMANT_INTERNAL_AUTH_TOKEN, PARAMANT_OPERATOR_IPS and HEARTBEAT_SLOW_MS
//   68 shell knobs of the form ${VAR:-default} in deploy/ and scripts/, of
//      which 7 were documented
//   every nginx directive, in seven conf files, none of which the deploy
//      script installs whole. Production answers 413 above 10485760 bytes and
//      no file in this repo says 10m anywhere.
//   8 places that spell out the same 5 MB, some of them a limit and some of
//      them the crypto padding block, which is not the same thing
//   3 defaults that admin/lib/config-schema.js and deploy/.env.example already
//      disagree about
//
// deploy/knoppen.md is that one place. It does not repeat the 97 variables in
// .env.example, it points at them and covers everything that file cannot.
//
// This suite is green on the tree as it stands. It goes red the moment a knob
// appears, moves or changes value without the registry moving with it. That is
// the whole point: a list that ages is worse than no list.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'deploy/knoppen.md';
const ENV_EXAMPLE = 'deploy/.env.example';

const registryText = readFileSync(join(ROOT, REGISTRY), 'utf8');

// ── reading the registry ─────────────────────────────────────────────────────
// Each table is preceded by an HTML comment marker so the parser never has to
// guess which heading it is under. A table is rows of `| a | b | c |`.
function table(marker) {
  const at = registryText.indexOf(`<!-- knoppen:${marker} -->`);
  assert.notEqual(at, -1, `${REGISTRY} is missing the marker <!-- knoppen:${marker} -->`);
  const rest = registryText.slice(at);
  const rows = [];
  let started = false;
  for (const line of rest.split('\n').slice(1)) {
    if (!line.startsWith('|')) {
      if (started) break;
      continue;
    }
    started = true;
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.every((c) => /^-*:?-*$/.test(c)) || cells[0] === '') continue;
    rows.push(cells);
  }
  assert.ok(rows.length > 1, `the table at <!-- knoppen:${marker} --> in ${REGISTRY} is empty`);
  return rows.slice(1); // drop the header row
}

function stripCode(s) {
  return s.replace(/^`|`$/g, '').trim();
}

// ── what the environment documents ───────────────────────────────────────────
const documented = new Set(
  [...readFileSync(join(ROOT, ENV_EXAMPLE), 'utf8').matchAll(/^#?\s*([A-Z][A-Z0-9_]*)=/gm)]
    .map((m) => m[1])
);

// ── walking the tree ─────────────────────────────────────────────────────────
const SKIP_DIRS = new Set(['node_modules', '.git', 'pkg', 'dist', 'build', 'coverage', 'target']);

function walk(dir, match, acc = []) {
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) return acc;
  for (const e of readdirSync(abs, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) walk(p, match, acc);
    else if (match.test(e.name)) acc.push(p);
  }
  return acc;
}

// ── K1: environment variables read outside the reach of env-documented ───────
// env-documented.test.mjs scans relay/ and admin/. Everything else in the repo
// reads from the environment too, and until now nothing looked.
const OUTSIDE = ['frontend', 'scripts', 'tests', 'extensions', 'monitoring', 'bron-seo', 'crypto-wasm'];
const READ = /(?:process\.)?\benv\.([A-Z][A-Z0-9_]*)\b(?!\s*=[^=])/g;

// A comment that explains a variable is not a read of it. tests/env-documented.test.mjs
// spells out "process.env.X" in prose to describe its own regex; without that, X
// becomes a knob. Only WHOLE comment lines are dropped, never part of a line: a
// trailing-comment stripper ate two real reads in tests/user-dashboard-documents.test.mjs,
// which put `{ path: process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH }` on a code line.
function stripComments(src) {
  return src
    .split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
}

function envReadsOutside() {
  const found = new Map(); // NAME -> Set(file)
  for (const dir of OUTSIDE) {
    for (const f of walk(dir, /\.(js|mjs|cjs)$/)) {
      for (const m of stripComments(readFileSync(join(ROOT, f), 'utf8')).matchAll(READ)) {
        if (!found.has(m[1])) found.set(m[1], new Set());
        found.get(m[1]).add(f);
      }
    }
  }
  return found;
}

test('K1 every environment variable read outside relay/ and admin/ is registered', () => {
  const registered = new Map(table('env-buiten').map((r) => [stripCode(r[0]), r]));
  const found = envReadsOutside();
  const missing = [...found.keys()]
    .filter((n) => !documented.has(n) && !registered.has(n))
    .sort()
    .map((n) => `${n}  (read in ${[...found.get(n)].sort().join(', ')})`);
  assert.deepEqual(missing, [],
    `Environment variables read outside relay/ and admin/ that neither ${ENV_EXAMPLE} ` +
    `nor the "env-buiten" table in ${REGISTRY} knows about. Add a row: name, where it ` +
    'is read, what it does, its default, and what happens when it is absent.');
});

test('K1b nothing in the env-buiten table has quietly stopped being read', () => {
  // A registry entry for a variable nothing reads any more is a lie with a
  // longer shelf life than a missing one.
  const found = envReadsOutside();
  const dead = table('env-buiten')
    .map((r) => stripCode(r[0]))
    .filter((n) => !found.has(n) && !documented.has(n))
    .sort();
  assert.deepEqual(dead, [],
    `The "env-buiten" table in ${REGISTRY} lists variables that nothing in ` +
    `${OUTSIDE.join(', ')} reads any more. Remove the rows.`);
});

// ── K2: shell knobs ──────────────────────────────────────────────────────────
// The operator-overridable form: ${VAR:-default} or ${VAR:=default}. A bare
// $VAR is a local variable nine times out of ten and would drown the signal.
const SHELL_DIRS = ['deploy', 'scripts'];
const SHELL_FILES = ['install.sh', 'deploy.sh', 'build.sh'];
const SHELL_KNOB = /\$\{([A-Z][A-Z0-9_]{2,}):[-=]/g;

function shellKnobs() {
  const found = new Map();
  const files = [...SHELL_DIRS.flatMap((d) => walk(d, /\.sh$/)), ...SHELL_FILES.filter((f) => existsSync(join(ROOT, f)))];
  for (const f of files) {
    for (const m of readFileSync(join(ROOT, f), 'utf8').matchAll(SHELL_KNOB)) {
      if (!found.has(m[1])) found.set(m[1], new Set());
      found.get(m[1]).add(f);
    }
  }
  return found;
}

test('K2 every shell knob an operator can override is registered', () => {
  const registered = new Set(table('shell').map((r) => stripCode(r[0])));
  const found = shellKnobs();
  const missing = [...found.keys()]
    .filter((n) => !documented.has(n) && !registered.has(n))
    .sort()
    .map((n) => `${n}  (in ${[...found.get(n)].sort().join(', ')})`);
  assert.deepEqual(missing, [],
    `Shell knobs of the form \${VAR:-default} that neither ${ENV_EXAMPLE} nor the ` +
    `"shell" table in ${REGISTRY} knows about. Every one of these changes what a ` +
    'deploy or an operator script does. Add a row, or give it a reason.');
});

test('K2b nothing in the shell table has quietly disappeared', () => {
  const found = shellKnobs();
  const dead = table('shell')
    .map((r) => stripCode(r[0]))
    .filter((n) => !found.has(n))
    .sort();
  assert.deepEqual(dead, [],
    `The "shell" table in ${REGISTRY} lists knobs that no script under ` +
    `${SHELL_DIRS.join(', ')} reads any more. Remove the rows.`);
});

// ── K3: the two places that both declare defaults ────────────────────────────
// admin/lib/config-schema.js carries a `default` per key and deploy/.env.example
// carries a commented-out assignment per key. They are written by hand, in two
// files, and nothing has ever compared them. Three of them already disagree;
// those three are named in the registry with a reason, and no fourth may join
// them silently.
test('K3 config-schema.js and .env.example agree on every default', async () => {
  const schema = (await import(join(ROOT, 'admin/lib/config-schema.js'))).default;
  const exampleText = readFileSync(join(ROOT, ENV_EXAMPLE), 'utf8');
  const commented = new Map(
    [...exampleText.matchAll(/^#\s*([A-Z][A-Z0-9_]*)=(.*)$/gm)]
      .map((m) => [m[1], m[2].trim().replace(/^['"]|['"]$/g, '')])
  );
  const known = new Set(table('afwijkingen').map((r) => stripCode(r[0])));

  const drift = [];
  for (const [name, spec] of Object.entries(schema)) {
    if (!commented.has(name)) continue; // required, no default to compare
    const a = String(spec.default);
    const b = commented.get(name);
    if (a.trim() !== b.trim() && !known.has(name)) {
      drift.push(`${name}: config-schema says ${JSON.stringify(a)}, ${ENV_EXAMPLE} says ${JSON.stringify(b)}`);
    }
  }
  assert.deepEqual(drift.sort(), [],
    'A default is declared twice and the two declarations disagree. Make them match, ' +
    `or add the name to the "afwijkingen" table in ${REGISTRY} with the reason it may stand.`);
});

test('K3b every registered exception really is still an exception', async () => {
  // Keeps the exception list from outliving the exceptions. Once the two files
  // agree again, the row must go, otherwise it hides the next real drift.
  const schema = (await import(join(ROOT, 'admin/lib/config-schema.js'))).default;
  const commented = new Map(
    [...readFileSync(join(ROOT, ENV_EXAMPLE), 'utf8').matchAll(/^#\s*([A-Z][A-Z0-9_]*)=(.*)$/gm)]
      .map((m) => [m[1], m[2].trim().replace(/^['"]|['"]$/g, '')])
  );
  const stale = table('afwijkingen')
    .map((r) => stripCode(r[0]))
    .filter((n) => {
      if (!(n in schema) || !commented.has(n)) return false;
      return String(schema[n].default).trim() === commented.get(n).trim();
    })
    .sort();
  assert.deepEqual(stale, [],
    `The "afwijkingen" table in ${REGISTRY} still excuses defaults that now agree. ` +
    'Remove the rows so the next real disagreement is visible.');
});

// ── K4: nginx ────────────────────────────────────────────────────────────────
// The setting that is absent is the dangerous one. nginx does not warn when
// client_max_body_size is missing, it silently uses its own built-in 1m. The
// registry therefore records an absence as a value in its own right, spelled
// "afwezig", and this test fails on a file that gains one, loses one, or
// changes what it says.
const WATCHED = ['client_max_body_size', 'limit_req_zone', 'limit_conn', 'proxy_read_timeout', 'client_body_timeout'];

function nginxConfs() {
  return walk('.', /\.conf$/).map((p) => p.replace(/^\.\//, '')).sort();
}

function directiveValues(file, directive) {
  const src = readFileSync(join(ROOT, file), 'utf8');
  const re = new RegExp(`^\\s*${directive}\\s+([^;]+);`, 'gm');
  return [...src.matchAll(re)].map((m) => m[1].trim().replace(/\s+/g, ' '));
}

test('K4 every nginx conf file in the repo is in the registry', () => {
  const registered = new Set(table('nginx').map((r) => stripCode(r[0])));
  const onDisk = nginxConfs();
  const missing = onDisk.filter((f) => !registered.has(f));
  const gone = [...registered].filter((f) => !onDisk.includes(f));
  assert.deepEqual({ missing, gone }, { missing: [], gone: [] },
    `The "nginx" table in ${REGISTRY} must list exactly the .conf files in the repo. ` +
    'A new conf file is a new set of knobs and needs its row.');
});

test('K4b every watched nginx directive matches what the registry records', () => {
  // Row shape: | file | directive | value |, where value is either the literal
  // the file declares, several separated by " / ", or the word "afwezig".
  const wrong = [];
  for (const row of table('nginx')) {
    const [file, directive, recorded] = row.map(stripCode);
    if (!WATCHED.includes(directive)) {
      wrong.push(`${file}: "${directive}" is not one of the watched directives (${WATCHED.join(', ')})`);
      continue;
    }
    const actual = directiveValues(file, directive);
    const want = recorded === 'afwezig' ? [] : recorded.split(' / ').map((s) => s.trim());
    const got = actual.length === 0 ? [] : actual;
    if (JSON.stringify(want) !== JSON.stringify(got)) {
      wrong.push(
        `${file} ${directive}: registry says ${recorded === 'afwezig' ? 'afwezig' : JSON.stringify(want)}, ` +
        `the file says ${got.length === 0 ? 'afwezig' : JSON.stringify(got)}`
      );
    }
  }
  assert.deepEqual(wrong, [],
    `${REGISTRY} and the nginx conf files have come apart. An absent ` +
    'client_max_body_size is recorded as "afwezig" on purpose: nginx falls back to its ' +
    'own 1m without saying so, and that silence is what this row is here to break.');
});

test('K4c every watched directive present in a conf file has a row', () => {
  // The reverse of K4b: a directive that appears in a file the registry does not
  // account for is exactly the knob that goes unnoticed.
  const rows = new Set(table('nginx').map((r) => `${stripCode(r[0])} ${stripCode(r[1])}`));
  const unrecorded = [];
  for (const f of nginxConfs()) {
    for (const d of WATCHED) {
      if (directiveValues(f, d).length > 0 && !rows.has(`${f} ${d}`)) {
        unrecorded.push(`${f}: ${d}`);
      }
    }
  }
  assert.deepEqual(unrecorded.sort(), [],
    `These nginx directives are set in a conf file and the "nginx" table in ${REGISTRY} ` +
    'does not mention them.');
});

// ── K5: constants that are settings ──────────────────────────────────────────
// A number that decides what the product does is a setting whether or not it
// can be changed from the environment. Writing the same 5 MB in nine files is
// how "the limit" and "the padding block" came to look like one thing.
test('K5 every registered constant still holds the value the registry records', () => {
  const wrong = [];
  for (const row of table('constanten')) {
    const [file, name, value] = row.map(stripCode);
    if (!existsSync(join(ROOT, file))) {
      wrong.push(`${file} does not exist (registered for ${name})`);
      continue;
    }
    const src = readFileSync(join(ROOT, file), 'utf8');
    // The name and the value must occur on the same line: that is what pins the
    // constant rather than merely proving both strings live in the file.
    const hit = src.split('\n').some((l) => l.includes(name) && l.includes(value));
    if (!hit) wrong.push(`${file}: no line carries both ${name} and ${value}`);
  }
  assert.deepEqual(wrong, [],
    `A constant the registry pins has moved or changed. Update the row in ${REGISTRY} ` +
    'in the same commit as the value, and check the other rows that carry the same ' +
    'number: several of them are the same figure written down in different files for ' +
    'different reasons.');
});

// ── the registry must stay honest about its own size ─────────────────────────
test('K6 the registry header states how many knobs it accounts for', () => {
  const counted =
    table('env-buiten').length + table('shell').length +
    table('nginx').length + table('constanten').length;
  const header = registryText.match(/^-\s*\*\*(\d+)\s+knoppen\*\*/m);
  assert.ok(header, `${REGISTRY} must state how many knobs it accounts for, as "- **N knoppen**"`);
  assert.equal(Number(header[1]), counted,
    `${REGISTRY} says ${header && header[1]} knobs and its tables hold ${counted}.`);
});
