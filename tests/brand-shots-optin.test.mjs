// The reference screenshots under docs/ are opt-in, and this is what holds it.
//
// scripts/app-shots.mjs used to write 36 PNGs straight into
// docs/brand/assets/app-2026/ on every run. Those files are tracked, so any
// local run of the browser suites left 36 modified files behind and the next
// `git commit -a` shipped them. Two builders hit that in the same week. Nothing
// was broken by it, which is exactly why nobody noticed: a screenshot that
// changed by two pixels of antialiasing still looks like a screenshot.
//
// Three layers, because each catches a different way back to the old
// behaviour:
//
//   1. UNIT: the resolver itself. No flag means a temp dir; the flag means the
//      tracked directory; and an explicit APP_SHOTS_DIR aimed back into docs/
//      is refused without the flag, so the opt-in is not one variable away
//      from meaning nothing.
//   2. DRY RUN: the real scripts/app-shots.mjs, spawned with a scrubbed
//      environment, has to name a directory outside this repo, and the tracked
//      directory must be byte-identical afterwards. This measures the file
//      that does the writing, not a second copy of its rules.
//   3. STATIC: no other suite or script may name the tracked directory unless
//      it goes through the resolver or names the flag. A new browser suite
//      that hardcodes the path is the obvious way this comes back.
//
// Remove the flag check from scripts/brand-shots-dir.mjs and layers 1, 2 and 3
// all go red.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  resolveBrandShotsDir, isUnderDocs, REPO_ROOT, DOCS_ROOT, TRACKED_DIR, FLAG, DIR_VAR, DRY_RUN_VAR,
} from '../scripts/brand-shots-dir.mjs';

// Built from parts so the static scan below does not match its own pattern.
const TRACKED_REL = ['docs', 'brand', 'assets'].join('/');
const SHOTS_SUITE = path.join(REPO_ROOT, 'scripts', 'app-shots.mjs');

function under(parent, child) {
  const rel = path.relative(parent, child);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

// A snapshot of the tracked directory: name, size and mtime of every file. Two
// identical snapshots mean nothing wrote there.
function snapshot(dir) {
  if (!fs.existsSync(dir)) return '(absent)';
  return fs.readdirSync(dir).sort().map((name) => {
    const s = fs.statSync(path.join(dir, name));
    return `${name} ${s.size} ${s.mtimeMs}`;
  }).join('\n');
}

// ── 1. UNIT ───────────────────────────────────────────────────────────────────

// The names are the contract: tests/README.md, the suite header and every
// checklist that says how to refresh the references all spell them out. A
// renamed constant would keep every other assertion here green while the
// documented command silently stopped working.
test('the documented variable names are the ones the resolver reads', () => {
  assert.equal(FLAG, 'PARAMANT_WRITE_BRAND_SHOTS');
  assert.equal(DIR_VAR, 'APP_SHOTS_DIR');
  assert.equal(DRY_RUN_VAR, 'APP_SHOTS_DRY_RUN');
});

test('without the flag the shots go outside the repo', () => {
  const { dir, optIn, source } = resolveBrandShotsDir({});
  assert.equal(optIn, false);
  assert.equal(source, 'default');
  assert.ok(under(os.tmpdir(), dir), `default target must live under the system temp dir, got ${dir}`);
  assert.ok(!under(REPO_ROOT, dir), `default target must not live in the repo, got ${dir}`);
});

test(`${FLAG}=1 is what points the shots at the tracked references`, () => {
  const { dir, optIn, source } = resolveBrandShotsDir({ [FLAG]: '1' });
  assert.equal(optIn, true);
  assert.equal(source, FLAG);
  assert.equal(dir, TRACKED_DIR);
  assert.ok(under(DOCS_ROOT, dir));
});

test(`a value other than 1 in ${FLAG} is not an opt-in`, () => {
  for (const value of ['0', '', 'true', 'yes']) {
    const { dir } = resolveBrandShotsDir({ [FLAG]: value });
    assert.ok(!under(REPO_ROOT, dir), `${FLAG}=${JSON.stringify(value)} must not reach the repo, got ${dir}`);
  }
});

test(`${DIR_VAR} still names an explicit directory outside docs/`, () => {
  const wanted = path.join(os.tmpdir(), 'somewhere-else');
  const { dir, source } = resolveBrandShotsDir({ [DIR_VAR]: wanted });
  assert.equal(dir, wanted);
  assert.equal(source, DIR_VAR);
});

test(`${DIR_VAR} aimed back into docs/ is refused without the flag`, () => {
  assert.throws(() => resolveBrandShotsDir({ [DIR_VAR]: TRACKED_DIR }), /tracked/);
  assert.throws(() => resolveBrandShotsDir({ [DIR_VAR]: DOCS_ROOT }), /tracked/);
  // Relative and dot-walked paths resolve to the same place, so they are the
  // same refusal and not a way round it.
  assert.throws(() => resolveBrandShotsDir({ [DIR_VAR]: `${TRACKED_REL}/app-2026` }), /tracked/);
  assert.throws(() => resolveBrandShotsDir({ [DIR_VAR]: path.join(REPO_ROOT, 'tests', '..', 'docs', 'x') }), /tracked/);
  // With the flag it is allowed: refreshing the references is the point.
  assert.equal(resolveBrandShotsDir({ [DIR_VAR]: TRACKED_DIR, [FLAG]: '1' }).dir, TRACKED_DIR);
});

test('isUnderDocs answers for docs/ itself and for neighbours that merely start the same', () => {
  assert.equal(isUnderDocs(DOCS_ROOT), true);
  assert.equal(isUnderDocs(TRACKED_DIR), true);
  assert.equal(isUnderDocs(path.join(REPO_ROOT, 'tests')), false);
  assert.equal(isUnderDocs(`${DOCS_ROOT}-scratch`), false);
  assert.equal(isUnderDocs(os.tmpdir()), false);
});

// ── 2. DRY RUN ────────────────────────────────────────────────────────────────

test('a dry run of the real suite names a directory outside the repo and writes nothing', () => {
  const before = snapshot(TRACKED_DIR);
  // A scrubbed environment: neither variable inherited from whoever is running
  // the suite, so this measures the default and not the caller's shell.
  const env = { ...process.env };
  delete env[FLAG];
  delete env[DIR_VAR];
  env[DRY_RUN_VAR] = '1';

  const out = execFileSync(process.execPath, [SHOTS_SUITE], { env, encoding: 'utf8', timeout: 60000 });
  const line = out.split('\n').find((l) => l.startsWith('out-dir: '));
  assert.ok(line, `the dry run must print its target, got:\n${out}`);
  const target = line.slice('out-dir: '.length).trim();

  assert.ok(!under(REPO_ROOT, target),
    `scripts/app-shots.mjs would write into the repo without ${FLAG}: ${target}`);
  assert.ok(!isUnderDocs(target),
    `scripts/app-shots.mjs would write under docs/ without ${FLAG}: ${target}`);
  assert.match(out, /opt-in: no/);
  assert.equal(snapshot(TRACKED_DIR), before, 'a dry run must leave the tracked references untouched');
});

test(`the same dry run with ${FLAG}=1 does aim at the tracked references`, () => {
  const before = snapshot(TRACKED_DIR);
  const env = { ...process.env, [FLAG]: '1', [DRY_RUN_VAR]: '1' };
  delete env[DIR_VAR];

  const out = execFileSync(process.execPath, [SHOTS_SUITE], { env, encoding: 'utf8', timeout: 60000 });
  const line = out.split('\n').find((l) => l.startsWith('out-dir: '));
  assert.ok(line, `the dry run must print its target, got:\n${out}`);
  assert.equal(line.slice('out-dir: '.length).trim(), TRACKED_DIR);
  assert.match(out, /opt-in: yes/);
  // Still a dry run: naming the directory is not writing to it.
  assert.equal(snapshot(TRACKED_DIR), before, 'a dry run must leave the tracked references untouched');
});

// ── 3. STATIC ─────────────────────────────────────────────────────────────────

test('nothing else names the tracked screenshot directory without going through the resolver', () => {
  const roots = [path.join(REPO_ROOT, 'tests'), path.join(REPO_ROOT, 'scripts')];
  const self = path.resolve(new URL(import.meta.url).pathname);
  const resolver = path.join(REPO_ROOT, 'scripts', 'brand-shots-dir.mjs');
  const offenders = [];

  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (entry.name !== 'node_modules') walk(full); continue; }
      if (!/\.(mjs|js|sh)$/.test(entry.name)) continue;
      if (full === self || full === resolver) continue;
      const source = fs.readFileSync(full, 'utf8');
      const namesTracked = source.includes(TRACKED_REL)
        || source.includes(["'docs'", "'brand'", "'assets'"].join(', '));
      if (!namesTracked) continue;
      const guarded = source.includes(FLAG) || source.includes('brand-shots-dir.mjs');
      if (!guarded) offenders.push(path.relative(REPO_ROOT, full));
    }
  };
  for (const root of roots) walk(root);

  assert.deepEqual(offenders, [],
    `these name ${TRACKED_REL}/ but neither import the resolver nor mention ${FLAG}. ` +
    'The reference images are tracked: write to a temp directory by default and ' +
    'let the flag opt in, the way scripts/app-shots.mjs does.');
});
