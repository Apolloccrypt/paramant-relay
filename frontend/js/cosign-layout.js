// Where each party signs on a document that several people sign.
//
// The complaint (2026-10-04, a paying customer): with two or more signers every
// signature landed on exactly the same spot, and the last one covered the rest.
// The sender asked for one box, /co-sign gave that one box to every party, and
// nothing moved it. Here every party gets a spot of its own:
//
//   - the signature: the sender's box for party 1, and for every next party the
//     next free slot beside it, then on the row below (or above, when the page
//     runs out), never on top of another party;
//   - the paraaf on every page: one small mark per party, side by side along
//     the page margin, in the corner that is free of text on the most pages.
//
// Pure functions, no DOM and no pdf.js, so /sign (the sender), /co-sign (each
// signer) and tests/cosign-layout.test.mjs compute the very same spots.
//
// Units: page fractions 0..1 with y measured from the TOP, the convention of the
// signed appearance manifest (relay/envelope.js normaliseAppearance).

import { pickSharedSpot } from './paraaf-place.js?v=1';

// A signature box: wide enough for a written name and a caption under it.
export const SIGNATURE_FR = { w: 0.3, h: 0.085 };
// A paraaf: initials, small. Five side by side still fit in one margin row.
export const PARAAF_FR = { w: 0.12, h: 0.038 };
// Breathing room between two parties' marks, and the page edge we keep clear.
const GAP_X = 0.02;
const GAP_Y = 0.018;
const EDGE = 0.04;

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
const round6 = (n) => Math.round(n * 1000000) / 1000000;

function overlapArea(a, b) {
  const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
  const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
  return w > 0 && h > 0 ? w * h : 0;
}

// pdf.js text boxes in PDF points (bottom-left origin, as js/paraaf-place.js
// returns them) -> page fractions with y from the top.
export function textBoxesToFractions(boxes, pageW, pageH) {
  if (!Array.isArray(boxes) || !(pageW > 0) || !(pageH > 0)) return null;
  return boxes.map((b) => ({ x: b.x / pageW, y: 1 - (b.y + b.h) / pageH, w: b.w / pageW, h: b.h / pageH }));
}

// How the signature slots of `count` parties are laid out: columns per row and
// the box size. Up to two parties keep the full size; more parties get a
// slightly smaller box so a row holds three.
export function signatureGrid(count, base) {
  const n = Math.max(1, Math.min(30, Number(count) || 1));
  const w0 = base && base.w > 0 ? base.w : SIGNATURE_FR.w;
  const h0 = base && base.h > 0 ? base.h : SIGNATURE_FR.h;
  const w = n > 2 ? Math.min(w0, 0.28) : Math.min(w0, 0.44);
  const h = n > 2 ? Math.min(h0, 0.08) : Math.min(h0, 0.12);
  const cols = Math.max(1, Math.min(n, Math.floor((1 - 2 * EDGE + GAP_X) / (w + GAP_X))));
  const rows = Math.ceil(n / cols);
  return { w, h, cols, rows, count: n };
}

// The block of all slots, its top-left corner chosen so it starts at the
// anchor (the sender's box) and stays on the page: shifted left when the row
// runs off the right edge, moved up when the rows run off the bottom.
function blockOrigin(anchor, grid) {
  const blockW = grid.cols * grid.w + (grid.cols - 1) * GAP_X;
  const blockH = grid.rows * grid.h + (grid.rows - 1) * GAP_Y;
  // Off the right edge: the block ends where the sender's box ended, so one
  // party still signs on exactly the spot the sender chose.
  let x0 = anchor.x;
  if (x0 + blockW > 1 - EDGE) x0 = anchor.x + (anchor.w > 0 ? anchor.w : grid.w) - blockW;
  const x = clamp(x0, EDGE, Math.max(EDGE, 1 - EDGE - blockW));
  let y = anchor.y;
  if (y + blockH > 1 - EDGE / 2) y = anchor.y + grid.h - blockH;   // grow upwards from the anchor row
  y = clamp(y, EDGE / 2, Math.max(EDGE / 2, 1 - EDGE / 2 - blockH));
  return { x, y, blockW, blockH };
}

function slotAt(origin, grid, index) {
  const i = Math.max(0, Math.min(grid.count - 1, index));
  const col = i % grid.cols;
  const row = Math.floor(i / grid.cols);
  return {
    x: round6(origin.x + col * (grid.w + GAP_X)),
    y: round6(origin.y + row * (grid.h + GAP_Y)),
    w: round6(grid.w),
    h: round6(grid.h),
  };
}

// Without an anchor from the sender: the place on the page where the whole
// block of slots covers the least text, searched from the bottom of the page
// up (a signature belongs under the text, not above it). textBoxes are
// fractions (textBoxesToFractions), or null when the page has no text layer.
export function freeAnchor(grid, textBoxes) {
  const blockW = grid.cols * grid.w + (grid.cols - 1) * GAP_X;
  const blockH = grid.rows * grid.h + (grid.rows - 1) * GAP_Y;
  const x = EDGE + 0.02;
  const boxes = Array.isArray(textBoxes) ? textBoxes : [];
  let best = null;
  for (let y = 1 - EDGE - blockH; y >= EDGE; y -= 0.01) {
    const block = { x, y, w: blockW, h: blockH };
    const cover = boxes.reduce((sum, t) => sum + overlapArea(block, t), 0);
    if (!best || cover < best.cover - 1e-9) best = { x, y, cover };
    if (cover === 0) break;
  }
  return best ? { x: best.x, y: best.y, w: grid.w, h: grid.h } : { x, y: 1 - EDGE - blockH, w: grid.w, h: grid.h };
}

// The signature spot of party `index` out of `count`. anchor: the sender's
// box as a fraction box, or null to find a free place (then textBoxes count).
export function partySignatureSpot({ anchor, index, count, textBoxes }) {
  const grid = signatureGrid(count, anchor);
  const start = anchor && Number.isFinite(anchor.x) && Number.isFinite(anchor.y)
    ? anchor
    : freeAnchor(grid, textBoxes);
  return slotAt(blockOrigin(start, grid), grid, index);
}

// The paraaf of party `index`: side by side along the margin, from the corner
// js/paraaf-place.js pickSharedSpot found. corner: { x, y, w, h, corner } as
// pickSharedSpot returns it (fractions, y from the top). A right-hand corner
// grows to the left, a left-hand corner to the right; a full row continues on
// the next row inwards (up from a bottom corner, down from a top corner).
export function partyParaafSpot({ corner, index, count }) {
  const n = Math.max(1, Math.min(30, Number(count) || 1));
  const i = Math.max(0, Math.min(n - 1, Number(index) || 0));
  const c = corner && Number.isFinite(corner.x) ? corner : { x: 1 - EDGE - PARAAF_FR.w, y: 1 - EDGE / 2 - PARAAF_FR.h, w: PARAAF_FR.w, h: PARAAF_FR.h, corner: 'rechtsonder' };
  const w = Math.min(c.w || PARAAF_FR.w, PARAAF_FR.w);
  const h = Math.min(c.h || PARAAF_FR.h, PARAAF_FR.h);
  const name = String(c.corner || 'rechtsonder');
  const right = !name.startsWith('links');
  const bottom = !name.endsWith('boven');
  const perRow = Math.max(1, Math.floor((1 - 2 * EDGE + GAP_X) / (w + GAP_X)));
  const col = i % perRow;
  const row = Math.floor(i / perRow);
  // The anchor edge of the corner box: its right edge for a right corner.
  const edgeX = right ? c.x + c.w : c.x;
  let x = right ? edgeX - w - col * (w + GAP_X) : edgeX + col * (w + GAP_X);
  let y = bottom ? (c.y + c.h - h) - row * (h + GAP_Y / 2) : c.y + row * (h + GAP_Y / 2);
  x = clamp(x, 0.005, 1 - w - 0.005);
  y = clamp(y, 0.005, 1 - h - 0.005);
  return { x: round6(x), y: round6(y), w: round6(w), h: round6(h) };
}

// Everything one party is asked for: a signature on `signPage` and, when the
// sender wants it, a paraaf on every page. Returns a manifest-shaped object
// ({ version, fields }) for normaliseSigningAppearance.
export function partyRequest({ index, count, signPage, anchor, textBoxes, paraafCorner, withParaaf }) {
  const fields = [];
  const sig = partySignatureSpot({ anchor, index, count, textBoxes });
  fields.push({ type: 'seal', page_index: Math.max(0, Number(signPage) || 0), ...sig });
  if (withParaaf) {
    const p = partyParaafSpot({ corner: paraafCorner, index, count });
    fields.push({ type: 'seal', page_index: 0, ...p, all_pages: true });
  }
  return { version: withParaaf ? 2 : 1, fields };
}

// The sender's side (/sign, invite mode): one request per party from the one
// box the sender placed. anchor: the sender's box as a manifest field
// (requestedAppearanceFromStamp), signPage its page. withParaaf: the sender
// ticked "every page". pages: [{width,height}] in PDF points and
// textBoxesPerPage as js/paraaf-place.js reads them, for the margin corner
// that is free of text on the most pages. Returns one manifest per party.
export function requestsForParties({ anchor, signPage, count, withParaaf, pages, textBoxesPerPage }) {
  const n = Math.max(1, Math.min(30, Number(count) || 1));
  const corner = withParaaf
    ? pickSharedSpot(pages && pages.length ? pages : null, Array.isArray(textBoxesPerPage) ? textBoxesPerPage : null, PARAAF_FR.w, PARAAF_FR.h)
    : null;
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(partyRequest({ index: i, count: n, signPage, anchor, paraafCorner: corner, withParaaf: !!withParaaf }));
  }
  return out;
}

// ── The visible handwriting ("ink") ─────────────────────────────────────────
// A drawn signature is kept as vector strokes, not as a picture: it stays
// sharp at every size in the PDF and is a few kilobytes. Coordinates are
// quantised to a 1000-wide box, with the height following the drawing.

// strokes: [[{x,y}, ...], ...] in any unit. Returns { path, w, h } with path an
// SVG path ("M x y L x y ...") in a box of w x h (w = 1000), or null when there
// is no ink at all.
export function strokesToInk(strokes) {
  const pts = (strokes || []).flat().filter((p) => p && Number.isFinite(p.x) && Number.isFinite(p.y));
  if (!pts.length) return null;
  const minX = Math.min(...pts.map((p) => p.x)), maxX = Math.max(...pts.map((p) => p.x));
  const minY = Math.min(...pts.map((p) => p.y)), maxY = Math.max(...pts.map((p) => p.y));
  const spanX = Math.max(1, maxX - minX), spanY = Math.max(1, maxY - minY);
  const k = 1000 / Math.max(spanX, spanY * 2.5);
  const parts = [];
  for (const stroke of strokes) {
    const s = (stroke || []).filter((p) => p && Number.isFinite(p.x) && Number.isFinite(p.y));
    if (!s.length) continue;
    s.forEach((p, j) => {
      const x = Math.round((p.x - minX) * k);
      const y = Math.round((p.y - minY) * k);
      parts.push((j === 0 ? 'M' : 'L') + x + ' ' + y);
    });
    if (s.length === 1) parts.push('L' + (Math.round((s[0].x - minX) * k) + 1) + ' ' + Math.round((s[0].y - minY) * k));
  }
  return { path: parts.join(' '), w: Math.max(1, Math.round(spanX * k)), h: Math.max(1, Math.round(spanY * k)) };
}

// A stored path is untrusted (it comes back from the relay, decrypted). Only
// M/L commands with integer coordinates in range survive.
export function cleanInkPath(path) {
  const s = String(path || '');
  if (s.length > 30000 || !/^[ML0-9 ]*$/.test(s)) return '';
  return s.replace(/\s+/g, ' ').trim();
}

export function cleanInk(value) {
  if (!value || typeof value !== 'object') return null;
  if (value.kind === 'type') {
    const text = String(value.text || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 80);
    return text ? { kind: 'type', text } : null;
  }
  if (value.kind === 'draw') {
    const path = cleanInkPath(value.path);
    const w = Math.round(Number(value.w)), h = Math.round(Number(value.h));
    if (!path || !(w > 0 && w <= 1000) || !(h > 0 && h <= 1000)) return null;
    return { kind: 'draw', path, w, h };
  }
  return null;
}
