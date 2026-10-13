// The paraaf on "sign every page" lands in a free margin corner, never on text.
//
// Customer report 2026-10-04 (the paying customer): "die functie werkt niet
// hoor. Het plaatst de paraaf random op de tekst." /sign copied the full seal to
// every other page at the spot the signer chose on the signing page. That spot
// is the free signature line there and running text everywhere else.
//
// These tests pin the pure placement (frontend/js/paraaf-place.js), which the
// preview and the baked PDF both call. The browser half, the real
// buildStampedPdf on a real three-page PDF, is tests/paraaf-margin.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import {
  initialsFrom, paraafSize, pickParaafSpot, planParaafs, textBoxesFromItems, paraafFooter, pickSharedSpot, PARAAF_CORNERS,
} from '../frontend/js/paraaf-place.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const A4 = { width: 595.28, height: 841.89 };
const SEAL = { w: 240, h: 100 };   // STAMP_PDF_W x STAMP_PDF_H in sign-flow.js

const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

// A page of body text: 11pt lines from the top margin to the bottom margin,
// 56pt left and right, which is where the seal sat on the signing page.
function bodyText(fromY = 56, toY = 786) {
  const items = [];
  for (let y = toY; y >= fromY; y -= 14) {
    items.push({ str: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.', transform: [11, 0, 0, 11, 56, y], width: 483, height: 11 });
  }
  return items;
}

test('initials come from the signer name, at most four letters', () => {
  assert.equal(initialsFrom('Sandeep G. Prasad'), 'S.G.P.');
  assert.equal(initialsFrom('jan de vries'), 'J.D.V.');
  assert.equal(initialsFrom('Anne-Marie Jansen'), 'A.M.J.');
  assert.equal(initialsFrom('Émile Zola'), 'É.Z.');
  assert.equal(initialsFrom('a b c d e f'), 'A.B.C.D.');
  assert.equal(initialsFrom(''), '');
  assert.equal(initialsFrom(null), '');
});

test('the footer is date plus short fingerprint', () => {
  assert.equal(paraafFooter('2026-10-04T12:00:00Z', '0123456789abcdef'), '2026-10-04 · PQ 01234567');
  assert.equal(paraafFooter('2026-10-04T12:00:00Z', ''), '2026-10-04');
});

test('(b) the paraaf is smaller than the seal, and never larger even for a tiny seal', () => {
  const size = paraafSize(A4.width, A4.height, SEAL);
  assert.ok(size.w < SEAL.w && size.h < SEAL.h, `paraaf ${size.w}x${size.h} must be smaller than seal ${SEAL.w}x${SEAL.h}`);
  assert.ok(size.w / A4.width > 0.14 && size.w / A4.width < 0.21, 'about 15-20% of the page width');
  assert.ok(size.h / A4.height > 0.03 && size.h / A4.height < 0.05, 'about 4% of the page height');
  const tiny = paraafSize(A4.width, A4.height, { w: 60, h: 20 });
  assert.ok(tiny.w <= 60 && tiny.h <= 20, 'capped by a seal smaller than the default paraaf');
});

test('text items become boxes in PDF points, rotated text included', () => {
  const [box] = textBoxesFromItems([{ str: 'Hallo', transform: [10, 0, 0, 10, 100, 200], width: 30, height: 10 }]);
  assert.deepEqual(box, { x: 100, y: 197.5, w: 30, h: 12.5 });
  const [rot] = textBoxesFromItems([{ str: 'Zij', transform: [0, 10, -10, 0, 50, 100], width: 40, height: 10 }]);
  assert.ok(rot.x < 50 && rot.x + rot.w > 49 && rot.y <= 100 && rot.y + rot.h >= 140, 'vertical text gets a vertical box');
  assert.equal(textBoxesFromItems([{ str: '   ', transform: [10, 0, 0, 10, 0, 0], width: 5 }]).length, 0, 'whitespace is not an obstacle');
});

test('(a) with text where the seal sat, the paraaf goes to a free margin corner, not on the text', () => {
  const text = textBoxesFromItems(bodyText());
  // The seal's spot on the signing page, mapped onto this page: in the middle of the text.
  const sealSpot = { x: 300, y: 120, w: SEAL.w, h: SEAL.h };
  assert.ok(text.some((t) => overlaps(t, sealSpot)), 'precondition: the old behaviour would hit text');
  const spot = pickParaafSpot(A4.width, A4.height, paraafSize(A4.width, A4.height, SEAL), text);
  assert.equal(spot.free, true);
  assert.equal(spot.corner, 'rechtsonder');
  for (const t of text) assert.ok(!overlaps(spot, t), 'the paraaf overlaps a line of text');
  assert.ok(spot.x >= 0 && spot.y >= 0 && spot.x + spot.w <= A4.width && spot.y + spot.h <= A4.height, 'on the page');
});

test('a page number in the bottom right sends the paraaf to the next free corner', () => {
  const items = bodyText().concat([{ str: '1', transform: [9, 0, 0, 9, 520, 28], width: 5, height: 9 }]);
  const text = textBoxesFromItems(items);
  const spot = pickParaafSpot(A4.width, A4.height, paraafSize(A4.width, A4.height, SEAL), text);
  assert.equal(spot.corner, 'linksonder');
  for (const t of text) assert.ok(!overlaps(spot, t));
});

test('a page full to the edges falls back to bottom right, at the smallest size', () => {
  const items = [];
  for (let y = 4; y < A4.height; y += 10) items.push({ str: 'x'.repeat(200), transform: [9, 0, 0, 9, 2, y], width: 590, height: 9 });
  const full = pickParaafSpot(A4.width, A4.height, paraafSize(A4.width, A4.height, SEAL), textBoxesFromItems(items));
  const normal = paraafSize(A4.width, A4.height, SEAL);
  assert.equal(full.free, false);
  assert.equal(full.corner, 'rechtsonder');
  assert.ok(full.w < normal.w && full.h < normal.h, 'as small as it gets');
});

test('an unreadable text layer (scanned pdf) means bottom right', () => {
  const spot = pickParaafSpot(A4.width, A4.height, paraafSize(A4.width, A4.height, SEAL), null);
  assert.equal(spot.corner, 'rechtsonder');
  assert.equal(spot.textLayer, false);
  assert.ok(spot.x > A4.width / 2 && spot.y < A4.height / 4);
});

test('the plan skips the seal page and covers every other page', () => {
  const pages = [A4, A4, A4];
  const text = [textBoxesFromItems(bodyText()), textBoxesFromItems(bodyText()), textBoxesFromItems(bodyText(450, 786))];
  const plan = planParaafs(pages, 2, SEAL, text);
  assert.deepEqual(plan.map((b) => b.pageIndex), [0, 1]);
  for (const b of plan) {
    assert.ok(PARAAF_CORNERS.includes(b.corner));
    for (const t of text[b.pageIndex]) assert.ok(!overlaps(b, t));
  }
});

test('co-sign: one shared corner, the one free on the most pages', () => {
  const pages = [A4, A4];
  const plain = [textBoxesFromItems(bodyText(90)), textBoxesFromItems(bodyText(90))];   // a 3 cm bottom margin
  const spot = pickSharedSpot(pages, plain, 0.2, 0.05);
  assert.equal(spot.corner, 'rechtsonder');
  assert.equal(spot.freeOn, 2);
  assert.ok(spot.x > 0.5 && spot.y > 0.9 && spot.w === 0.2 && spot.h === 0.05, JSON.stringify(spot));
  // Page numbers bottom right on both pages: bottom left wins.
  const numbered = pages.map(() => textBoxesFromItems(bodyText().concat([{ str: '2', transform: [9, 0, 0, 9, 520, 28], width: 5, height: 9 }])));
  assert.equal(pickSharedSpot(pages, numbered, 0.2, 0.05).corner, 'linksonder');
  assert.equal(pickSharedSpot([], null, 0.2, 0.05).corner, 'rechtsonder', 'no text layer: bottom right');
});

// (c) Nothing in this change may move a byte of an existing .psign proof. The
// /sign flow signs stamped_hash with an EMPTY appearance manifest; co-sign
// signs its manifest. Pin both canonical forms and pin that this change did
// not reach into the three normalisers.
test('(c) the appearance bytes of existing proofs are unchanged', () => {
  const envelope = require(path.join(ROOT, 'relay/envelope.js'));
  const canonical = envelope.canonicalAppearance || envelope.__test__?.canonicalAppearance;
  assert.ok(canonical, 'relay/envelope.js exposes the canonical appearance');
  assert.equal(canonical({ version: 1, fields: [] }), '{"version":1,"fields":[]}');
  assert.equal(canonical({ version: 1, fields: [{ type: 'seal', page_index: 0, x: 0.1, y: 0.8, w: 0.36, h: 0.105 }] }),
    '{"version":1,"fields":[{"type":"seal","page_index":0,"x":0.1,"y":0.8,"w":0.36,"h":0.105}]}');
  assert.equal(canonical({ version: 2, fields: [{ type: 'seal', page_index: 0, x: 0.1, y: 0.8, w: 0.36, h: 0.105, all_pages: true }] }),
    '{"version":2,"fields":[{"type":"seal","page_index":0,"x":0.1,"y":0.8,"w":0.36,"h":0.105,"all_pages":true}]}');
  const flow = fs.readFileSync(path.join(ROOT, 'frontend/sign-flow.js'), 'utf8');
  assert.match(flow, /const appearance = \{ version: 1, fields: \[\] \};/, '/sign still signs an empty manifest: the paraaf is in the stamped bytes, not in the signed manifest');
  for (const f of ['relay/envelope.js', 'frontend/js/parasign-signer.js', 'frontend/parasign-verify.js']) {
    assert.doesNotMatch(fs.readFileSync(path.join(ROOT, f), 'utf8'), /paraaf-place|other_pages/, `${f} must not learn about the paraaf`);
  }
});
