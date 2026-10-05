// The PDF previews in sign-flow.js: no blank raster from a mid-transition
// width, and no page twice when two renders of the same pane overlap.
// See frontend/js/preview-render.js for the two failures this pins.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { previewTargetWidth, viewportTargetWidth, renderGeneration } from '../frontend/js/preview-render.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const flow = fs.readFileSync(path.join(ROOT, 'frontend/sign-flow.js'), 'utf8');

test('a pane width of 1px no longer yields a 1px canvas', () => {
  // The old expression, Math.min(340, Math.floor(w || 340)), gave 1 here.
  assert.equal(previewTargetWidth(1, 340, 280), 280);
  assert.equal(previewTargetWidth(0, 340, 280), 340);
  assert.equal(previewTargetWidth(undefined, 340, 280), 340);
  assert.equal(previewTargetWidth(NaN, 340, 280), 340);
  assert.equal(previewTargetWidth(310.7, 340, 280), 310);
  assert.equal(previewTargetWidth(900, 340, 280), 340);
});

test('the full-width target stays between 280 and 820', () => {
  assert.equal(viewportTargetWidth(0), 820);
  assert.equal(viewportTargetWidth(undefined), 820);
  assert.equal(viewportTargetWidth(10), 280);
  assert.equal(viewportTargetWidth(390), Math.floor(390 * 0.88));
  assert.equal(viewportTargetWidth(1920), 820);
});

test('overlapping renders of one pane: only the newest appends pages', async () => {
  const gen = renderGeneration();
  const pane = [];
  const tick = () => new Promise((r) => setTimeout(r, 0));
  async function render(label, pages) {
    const ticket = gen.start();
    pane.length = 0;                       // pane.innerHTML = ''
    await tick();                          // waitForPdfjs / getDocument
    for (let p = 1; p <= pages; p++) {
      if (!gen.current(ticket)) return;
      pane.push(`${label}${p}`);
      await tick();                        // page.render()
    }
  }
  const first = render('a', 3);
  const second = render('b', 3);           // the seal drag with "every page" on
  await Promise.all([first, second]);
  assert.deepEqual(pane, ['b1', 'b2', 'b3']);
});

test('sign-flow.js uses the guards on every PDF preview surface', () => {
  assert.match(flow, /from '\/js\/preview-render\.js\?v=\d+'/);
  assert.doesNotMatch(flow, /clientWidth \|\| 340/, 'the old review width fallback is back');
  assert.doesNotMatch(flow, /window\.innerWidth \* 0\.88/, 'an unclamped full-width target is back');
  const body = (name) => {
    const at = flow.indexOf(`async function ${name}(`);
    assert.ok(at >= 0, `${name} not found`);
    return flow.slice(at, flow.indexOf('\n}\n', at));
  };
  const doc = body('renderDocPreview');
  assert.match(doc, /docPreviewGen\.start\(\)/);
  assert.match(doc, /previewTargetWidth\(pane\.clientWidth, 340, 280\)/);
  assert.match(doc, /await page\.render\([^\n]*\n\s*\/\/[^\n]*\n\s*if \(stale\(\)\) return;/);
  const signed = body('renderSignedPreview');
  assert.match(signed, /signedPreviewGen\.start\(\)/);
  assert.match(signed, /viewportTargetWidth\(window\.innerWidth\)/);
  assert.match(signed, /await page\.render\([^\n]*\n\s*if \(stale\(\)\) return;/);
});
