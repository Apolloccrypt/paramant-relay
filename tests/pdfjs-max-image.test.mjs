// Review #555, LAAG: pdf.js was called without maxImageSize, so one image of
// 40000 x 40000 pixels in a pdf (a decompression bomb) was decoded at full
// size in the worker and crashed the tab of whoever opened it, also a
// co-signer opening somebody else's pdf. Every getDocument call in the
// hand-written frontend sets a cap.
// Run: node --test tests/pdfjs-max-image.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
function files(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'vendor' || e.name === 'node_modules') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...files(p));
    else if (e.name.endsWith('.js') && !e.name.endsWith('.min.js')) out.push(p);
  }
  return out;
}

test('every pdf.js getDocument call caps the image size', () => {
  let calls = 0;
  for (const f of files(ROOT)) {
    const src = fs.readFileSync(f, 'utf8');
    for (const m of src.matchAll(/getDocument\(\{([^}]*)\}\)/g)) {
      calls++;
      assert.match(m[1], /maxImageSize:\s*1 << 26/, `${path.relative(ROOT, f)}: getDocument without maxImageSize`);
    }
  }
  assert.ok(calls >= 5, 'found only ' + calls + ' getDocument calls; this check is looking at nothing');
});
