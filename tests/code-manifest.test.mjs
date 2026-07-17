// The code-transparency manifest must be deterministic (same tree, same hash)
// and sensitive (any changed byte changes the hash).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const SCRIPT = new URL('../scripts/code-transparency-manifest.mjs', import.meta.url).pathname;

function makeTree() {
  const dir = mkdtempSync(join(tmpdir(), 'ctm-'));
  writeFileSync(join(dir, 'index.html'), '<h1>hoi</h1>');
  mkdirSync(join(dir, 'js'));
  writeFileSync(join(dir, 'js', 'app.js'), 'console.log(1);');
  return dir;
}
const run = (dir) => JSON.parse(execFileSync('node', [SCRIPT, dir, 'abc123']).toString());

test('M1 same tree yields the same manifest_hash', () => {
  const dir = makeTree();
  const a = run(dir);
  const b = run(dir);
  assert.equal(a.manifest_hash, b.manifest_hash);
  assert.equal(a.file_count, 2);
  assert.ok(a.files['js/app.js']);
});

test('M2 any changed byte changes the manifest_hash', () => {
  const dir = makeTree();
  const before = run(dir).manifest_hash;
  writeFileSync(join(dir, 'js', 'app.js'), 'console.log(2);');
  assert.notEqual(run(dir).manifest_hash, before);
});

test('M3 two identical trees in different places agree', () => {
  assert.equal(run(makeTree()).manifest_hash, run(makeTree()).manifest_hash);
});
