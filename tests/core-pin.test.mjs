// Guard: exactly one @paramant/core pin, declared in relay/Dockerfile.
// Any other file that names a paramant-core commit must match it, so CI and
// the production image can never build against different crypto engines.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function dockerfilePin() {
  const src = readFileSync(join(root, 'relay', 'Dockerfile'), 'utf8');
  const m = src.match(/^ARG PARAMANT_CORE_COMMIT=([0-9a-f]{40})$/m);
  return m && m[1];
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

test('relay/Dockerfile declares the core pin', () => {
  const pin = dockerfilePin();
  assert.ok(pin, 'ARG PARAMANT_CORE_COMMIT=<40-hex> missing from relay/Dockerfile');
});

test('no other file pins paramant-core to a different commit', () => {
  const pin = dockerfilePin();
  // Scan the places a second pin could do damage. Docs and CHANGELOG may cite
  // historic commits and are deliberately out of scope.
  const candidates = [
    ...walk(join(root, '.github')),
    join(root, 'relay', 'Dockerfile'),
    join(root, 'admin', 'Dockerfile'),
  ];
  const offenders = [];
  for (const file of candidates) {
    let src;
    try { src = readFileSync(file, 'utf8'); } catch { continue; }
    for (const [i, line] of src.split('\n').entries()) {
      if (!/paramant[-_]core|PARAMANT_CORE/i.test(line)) continue;
      for (const sha of line.match(/\b[0-9a-f]{40}\b/g) || []) {
        if (sha !== pin) offenders.push(`${file.slice(root.length + 1)}:${i + 1} pins ${sha}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `core-pin drift:\n${offenders.join('\n')}`);
});
