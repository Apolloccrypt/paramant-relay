// Fase-1-herrun P02: zonder Idempotency-Key sleutelde de admin op de body, dus
// hetzelfde document naar dezelfde mensen binnen 120 s gaf het VORIGE verzoek
// terug (ook ingetrokken of geweigerd) en overschreef het document. De pagina
// stuurt nu per verzending een eigen sleutel.
// Run: node --test tests/envelope-idempotency-key.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'js', 'parasign-signer.js'), 'utf8');

test('createSigningEnvelope stuurt per aanroep een eigen Idempotency-Key', () => {
  const start = src.indexOf('export function createSigningEnvelope(');
  const body = src.slice(start, src.indexOf('\n}\n', start));
  assert.match(body, /randomUUID|getRandomValues/);
  assert.match(body, /_postJSON\('\/api\/user\/envelopes', body, idem \? \{ 'Idempotency-Key': idem \}/);
});

test('_postJSON geeft extra koppen door', () => {
  assert.match(src, /async function _postJSON\(url, body, extraHeaders\)/);
  assert.match(src, /\.\.\.\(extraHeaders \|\| \{\}\)/);
});
