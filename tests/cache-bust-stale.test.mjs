// scripts/check-cache-bust.sh check 3 (STALE): an asset whose content changed
// against the base ref must ship under a higher ?v=. Merge 1638daa1 resolved a
// conflict back to developer.js?v=9 while developer.js had changed; the guard
// only checked that a ?v= was present and consistent, so it stayed green and
// prod kept serving the old immutable-cached file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'check-cache-bust.sh');
// Built at run time: tests/frontend-loading-contract.test.mjs reads every
// literal asset url with a ?v= in the repo, and these are fixtures, not pages.
const tag = (v) => `<script src="/js/a.js?${'v'}=${v}"></script>\n`;

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8',
    env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com',
      GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' } });
}

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'cachebust-'));
  mkdirSync(join(dir, 'scripts'));
  mkdirSync(join(dir, 'frontend', 'js'), { recursive: true });
  copyFileSync(SCRIPT, join(dir, 'scripts', 'check-cache-bust.sh'));
  writeFileSync(join(dir, 'frontend', 'js', 'a.js'), 'console.log(1)\n');
  writeFileSync(join(dir, 'frontend', 'p.html'), tag(9));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'base');
  git(dir, 'tag', 'basis');
  return dir;
}

function run(dir) {
  return spawnSync('bash', [join(dir, 'scripts', 'check-cache-bust.sh')], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, CACHE_BUST_BASE: 'basis' } });
}

test('changed asset under the old ?v= fails the guard', () => {
  const dir = fixture();
  try {
    writeFileSync(join(dir, 'frontend', 'js', 'a.js'), 'console.log(2)\n');
    const r = run(dir);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /\/js\/a\.js\s+v9 \(base basis has v9/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('changed asset with a raised ?v= passes, unchanged asset needs no bump', () => {
  const dir = fixture();
  try {
    assert.equal(run(dir).status, 0);
    writeFileSync(join(dir, 'frontend', 'js', 'a.js'), 'console.log(2)\n');
    writeFileSync(join(dir, 'frontend', 'p.html'), tag(10));
    const r = run(dir);
    assert.equal(r.status, 0, r.stdout + r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('missing base ref is a visible skip, not a silent pass', () => {
  const dir = fixture();
  try {
    const r = spawnSync('bash', [join(dir, 'scripts', 'check-cache-bust.sh')], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, CACHE_BUST_BASE: 'bestaat-niet' } });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /NOTICE - base ref bestaat-niet not available/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('this tree: every asset changed against origin/main carries a raised ?v=', (t) => {
  const has = spawnSync('git', ['rev-parse', '--verify', '--quiet', 'origin/main^{commit}'], { cwd: ROOT });
  if (has.status !== 0) { t.skip('origin/main not fetched here; the CI job fetches it'); return; }
  const r = spawnSync('bash', [SCRIPT], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
