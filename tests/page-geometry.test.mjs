// The view-space to PDF-space mapping in frontend/js/paraaf-place.js, pure.
// tests/sign-geometry.test.mjs holds the real bake to it in Chromium; this
// holds the maths, without a browser.
// Run: node --test tests/page-geometry.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normaliseRotation, viewSize, viewToUserMatrix, viewToUserPoint, userToViewPoint, userBoxesToView, isIdentityGeom, geomFromBoxes } from '../frontend/js/paraaf-place.js';

const A4 = [0, 0, 595.28, 841.89];

test('rotation is read the way pdf.js reads it', () => {
  assert.deepEqual([0, 90, 180, 270, 360, 450, -90, 45, 'x'].map(normaliseRotation), [0, 90, 180, 270, 0, 90, 270, 0, 0]);
});

test('a turned page is shown with width and height swapped', () => {
  assert.deepEqual(viewSize({ view: A4, rotate: 90 }), { width: 841.89, height: 595.28 });
  assert.deepEqual(viewSize({ view: A4, rotate: 180 }), { width: 595.28, height: 841.89 });
});

test('the visible corners map onto the right corners of the PDF box', () => {
  const view = [50, 80, 500, 730];   // a CropBox at 50,80
  // [rotation, view bottom-left maps to, view top-right maps to]
  const want = {
    0: [[50, 80], [500, 730]],
    90: [[500, 80], [50, 730]],     // clockwise: the visible bottom left is the box's bottom right
    180: [[500, 730], [50, 80]],
    270: [[50, 730], [500, 80]],
  };
  for (const r of [0, 90, 180, 270]) {
    const g = { view, rotate: r };
    const { width, height } = viewSize(g);
    const bl = viewToUserPoint(g, 0, 0), tr = viewToUserPoint(g, width, height);
    assert.deepEqual([[bl.x, bl.y], [tr.x, tr.y]].map((p) => p.map((n) => Math.round(n))), want[r], `rotate ${r}`);
  }
});

test('user to view is the exact inverse', () => {
  for (const r of [0, 90, 180, 270]) {
    const g = { view: [-100, -100, 495.28, 741.89], rotate: r };
    const p = viewToUserPoint(g, 123.4, 56.7);
    const q = userToViewPoint(g, p.x, p.y);
    assert.ok(Math.abs(q.u - 123.4) < 1e-9 && Math.abs(q.v - 56.7) < 1e-9);
  }
});

test('the matrix turns content counter-clockwise for a clockwise /Rotate (upright in the view)', () => {
  assert.deepEqual(viewToUserMatrix({ view: A4, rotate: 90 }).slice(0, 4), [0, 1, -1, 0]);
  assert.deepEqual(viewToUserMatrix({ view: A4, rotate: 270 }).slice(0, 4), [0, -1, 1, 0]);
});

test('an ordinary page is the identity: the bake draws exactly as before', () => {
  assert.equal(isIdentityGeom({ view: A4, rotate: 0 }), true);
  assert.equal(isIdentityGeom({ view: A4, rotate: 90 }), false);
  assert.equal(isIdentityGeom({ view: [50, 80, 500, 730], rotate: 0 }), false);
  const boxes = [{ x: 1, y: 2, w: 3, h: 4 }];
  assert.equal(userBoxesToView(boxes, { view: A4, rotate: 0 }), boxes);
});

test('text boxes follow the page into view space', () => {
  // A line at the bottom left of the paper, on a page turned 90 clockwise:
  // it shows at the top left of the (595 high) view, running downwards.
  const [b] = userBoxesToView([{ x: 0, y: 0, w: 100, h: 10 }], { view: A4, rotate: 90 });
  assert.deepEqual([b.x, b.y, b.w, b.h].map((n) => Math.round(n)), [0, 495, 10, 100]);
});

test('geometry from pdf-lib boxes: CropBox clipped to the MediaBox, else the MediaBox', () => {
  assert.deepEqual(geomFromBoxes([0, 0, 600, 800], [50, 80, 700, 900], 450), { view: [50, 80, 600, 800], rotate: 90 });
  assert.deepEqual(geomFromBoxes([0, 0, 600, 800], [700, 900, 800, 1000], 0), { view: [0, 0, 600, 800], rotate: 0 });
  assert.deepEqual(geomFromBoxes([0, 0, 600, 800], null, 0).view, [0, 0, 600, 800]);
});
