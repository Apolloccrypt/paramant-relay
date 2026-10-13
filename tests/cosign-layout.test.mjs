// Every party its own spot (js/cosign-layout.js) and the handwriting that
// travels encrypted between them (js/parasign-ink.js). Pure node, no browser.
//
// The customer case of 2026-10-04: two or more people sign one document, each
// a paraaf on every page and a signature on the last. Before, every party got
// the same box and the last signature covered the others.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  partySignatureSpot, partyParaafSpot, partyRequest, requestsForParties, signatureGrid,
  freeAnchor, textBoxesToFractions, strokesToInk, cleanInk, cleanInkPath, PARAAF_FR,
} from '../frontend/js/cosign-layout.js';
import { sealInk, openInk, splitKey, joinKey, parseKeyShareFragment, keyShareFragment } from '../frontend/js/parasign-ink.js';

const overlap = (a, b) => a.x < b.x + b.w - 1e-9 && b.x < a.x + a.w - 1e-9 && a.y < b.y + b.h - 1e-9 && b.y < a.y + a.h - 1e-9;
const inside = (a) => a.x >= 0 && a.y >= 0 && a.x + a.w <= 1.000001 && a.y + a.h <= 1.000001;

test('no two parties ever get the same or an overlapping signature spot, 1 to 30 parties', () => {
  const anchors = [null, { x: 0.55, y: 0.8, w: 0.36, h: 0.105 }, { x: 0.05, y: 0.1, w: 0.3, h: 0.08 }, { x: 0.6, y: 0.95, w: 0.36, h: 0.05 }];
  for (const anchor of anchors) {
    for (let count = 1; count <= 30; count++) {
      const spots = Array.from({ length: count }, (_, i) => partySignatureSpot({ anchor, index: i, count }));
      for (const s of spots) assert.ok(inside(s), `on the page: ${JSON.stringify(s)} (${count} parties)`);
      for (let i = 0; i < count; i++) for (let j = i + 1; j < count; j++) {
        assert.ok(!overlap(spots[i], spots[j]), `parties ${i} and ${j} of ${count} overlap: ${JSON.stringify([spots[i], spots[j]])}`);
      }
    }
  }
});

test('one party still signs on the spot the sender chose', () => {
  const anchor = { x: 0.55, y: 0.8, w: 0.36, h: 0.105 };
  const spots = [0, 1].map((i) => partySignatureSpot({ anchor, index: i, count: 2 }));
  assert.ok(spots.some((s) => Math.abs(s.x - anchor.x) < 1e-6 && Math.abs(s.y - anchor.y) < 1e-6), JSON.stringify(spots));
  const solo = partySignatureSpot({ anchor, index: 0, count: 1 });
  assert.equal(solo.x, 0.55);
  assert.equal(solo.y, 0.8);
});

test('the paraafs of all parties stand side by side in the margin, never on each other', () => {
  for (const corner of ['rechtsonder', 'linksonder', 'rechtsboven', 'linksboven']) {
    const box = { x: corner.startsWith('rechts') ? 0.845 : 0.035, y: corner.endsWith('onder') ? 0.937 : 0.025, w: PARAAF_FR.w, h: PARAAF_FR.h, corner };
    for (let count = 1; count <= 30; count++) {
      const spots = Array.from({ length: count }, (_, i) => partyParaafSpot({ corner: box, index: i, count }));
      for (const s of spots) assert.ok(inside(s), `on the page: ${JSON.stringify(s)}`);
      for (let i = 0; i < count; i++) for (let j = i + 1; j < count; j++) assert.ok(!overlap(spots[i], spots[j]), `${corner}: paraafs ${i} and ${j} of ${count} overlap`);
    }
    // Five fit in one row: the margin, not a column into the text.
    const five = Array.from({ length: 5 }, (_, i) => partyParaafSpot({ corner: box, index: i, count: 5 }));
    assert.equal(new Set(five.map((s) => s.y)).size, 1, `${corner}: five paraafs share one row`);
  }
});

test('a paraaf never touches a signature of another party when the sender asked for both', () => {
  const reqs = requestsForParties({ anchor: { x: 0.1, y: 0.75, w: 0.36, h: 0.1 }, signPage: 3, count: 5, withParaaf: true, pages: [], textBoxesPerPage: null });
  assert.equal(reqs.length, 5);
  const all = reqs.flatMap((r) => r.fields);
  for (const r of reqs) {
    assert.equal(r.version, 2, 'a manifest with a repeated mark is version 2');
    assert.equal(r.fields.length, 2);
    assert.equal(r.fields[0].page_index, 3, 'the signature on the page the sender chose');
    assert.equal(r.fields[1].all_pages, true, 'and a paraaf on every page');
    assert.equal(r.fields[1].page_index, 0, 'anchored on page 0, as the manifest requires');
  }
  for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) {
    const a = all[i], b = all[j];
    const samePage = a.all_pages || b.all_pages || a.page_index === b.page_index;
    if (samePage) assert.ok(!overlap(a, b), `fields ${i} and ${j} overlap`);
  }
  const plain = partyRequest({ index: 0, count: 2, signPage: 1, anchor: null, withParaaf: false });
  assert.equal(plain.version, 1, 'without a paraaf the manifest stays version 1, byte-compatible');
});

test('without an anchor the signatures go where the text is not', () => {
  const pageW = 595, pageH = 842;
  // Text from the top down to y=300pt (from the bottom), nothing below.
  const boxes = [];
  for (let y = 780; y >= 300; y -= 14) boxes.push({ x: 56, y, w: 480, h: 13 });
  const fr = textBoxesToFractions(boxes, pageW, pageH);
  const grid = signatureGrid(3);
  const anchor = freeAnchor(grid, fr);
  const spots = [0, 1, 2].map((i) => partySignatureSpot({ anchor: null, index: i, count: 3, textBoxes: fr }));
  for (const s of spots) for (const t of fr) assert.ok(!overlap(s, t), `spot ${JSON.stringify(s)} covers text`);
  assert.ok(anchor.y > 0.5, 'under the text, not above it');
});

test('a drawn signature becomes a compact vector path, and junk is refused', () => {
  const strokes = [[{ x: 10, y: 50 }, { x: 60, y: 10 }, { x: 110, y: 60 }], [{ x: 130, y: 30 }]];
  const ink = strokesToInk(strokes);
  assert.ok(/^M\d+ \d+( L\d+ \d+)+/.test(ink.path), ink.path);
  assert.ok(ink.w > 0 && ink.w <= 1000);
  assert.ok(ink.h > 0 && ink.h <= 400);
  assert.deepEqual(cleanInk({ kind: 'draw', ...ink }), { kind: 'draw', ...ink });
  assert.equal(cleanInkPath('M0 0 L10 10 Z" onload="x'), '', 'anything but M/L and digits is dropped');
  assert.equal(cleanInk({ kind: 'draw', path: 'M0 0', w: 5000, h: 10 }), null);
  assert.deepEqual(cleanInk({ kind: 'type', text: '  Sandeep\nPrasad ' }), { kind: 'type', text: 'Sandeep Prasad' });
  assert.equal(strokesToInk([]), null);
});

test('the ink opens for whoever holds the document key, for that slot only', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const ink = { kind: 'type', text: 'Sandeep G. Prasad' };
  const sealed = await sealInk({ ink, documentKey: key, envelopeId: 'env_abcdefghijklmnopqrst', partyIndex: 1 });
  assert.match(sealed, /^[A-Za-z0-9_-]+$/);
  assert.ok(!sealed.includes('Sandeep'));
  assert.deepEqual(await openInk({ sealed, documentKey: key, envelopeId: 'env_abcdefghijklmnopqrst', partyIndex: 1 }), ink);
  assert.equal(await openInk({ sealed, documentKey: key, envelopeId: 'env_abcdefghijklmnopqrst', partyIndex: 0 }), null, 'moved to another slot: refused');
  const other = crypto.getRandomValues(new Uint8Array(32));
  assert.equal(await openInk({ sealed, documentKey: other, envelopeId: 'env_abcdefghijklmnopqrst', partyIndex: 1 }), null, 'another key: refused');
  assert.equal(await sealInk({ ink: null, documentKey: key, envelopeId: 'e', partyIndex: 0 }), '');
});

test('the split document key: either half alone is not the key, both together are', () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const { a, b } = splitKey(key);
  assert.notDeepEqual(Array.from(a), Array.from(key));
  assert.notDeepEqual(Array.from(b), Array.from(key));
  assert.deepEqual(Array.from(joinKey(a, b)), Array.from(key));
  const frag = keyShareFragment(a);
  assert.match(frag, /^#ks=v1\.[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(Array.from(parseKeyShareFragment(frag)), Array.from(a));
  assert.equal(parseKeyShareFragment('#doc=v1.' + 'k'.repeat(43)), null, 'a whole key is not a share');
});
