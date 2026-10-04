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

// A free place for the whole block of signatures, or null when the page has
// none. Unlike freeAnchor this never settles for "the least text": the
// acceptance test of 2026-10-04 found every signature on top of the title and
// the first articles of a last page that was text from top to bottom, because
// the least-covered spot was the top. Searched from the bottom up (under the
// last text first), each row from the left margin to the right, with a little
// room kept around every line. textBoxes: fractions, y from the top.
const TEXT_ROOM = 0.006;
export function freeSignatureBlock(grid, textBoxes) {
  const blockW = grid.cols * grid.w + (grid.cols - 1) * GAP_X;
  const blockH = grid.rows * grid.h + (grid.rows - 1) * GAP_Y;
  const boxes = (Array.isArray(textBoxes) ? textBoxes : []).map((t) => ({ x: t.x - TEXT_ROOM, y: t.y - TEXT_ROOM, w: t.w + 2 * TEXT_ROOM, h: t.h + 2 * TEXT_ROOM }));
  for (let y = 1 - EDGE - blockH; y >= EDGE; y -= 0.005) {
    for (let x = EDGE + 0.02; x + blockW <= 1 - EDGE + 1e-9; x += 0.02) {
      const block = { x, y, w: blockW, h: blockH };
      if (!boxes.some((t) => overlapArea(block, t) > 0)) return { x: round6(x), y: round6(y), w: grid.w, h: grid.h };
    }
  }
  return null;
}

// Where the signatures go when nobody pointed at a spot: under the text of the
// last page when there is room for all of them, else on a signature sheet
// after the last page (page index = pageCount), never over text.
// Returns { page_index, spot } for party `index`.
export function autoSignaturePlace({ index, count, pageCount, textBoxes }) {
  const grid = signatureGrid(count);
  const last = Math.max(0, (Number(pageCount) || 1) - 1);
  const free = freeSignatureBlock(grid, textBoxes);
  if (free) return { page_index: last, spot: slotAt(blockOrigin(free, grid), grid, index) };
  const sheetAnchor = { x: EDGE + 0.02, y: 0.16, w: grid.w, h: grid.h };
  return { page_index: last + 1, spot: slotAt(blockOrigin(sheetAnchor, grid), grid, index) };
}

// The signature spot of party `index` out of `count`. anchor: the sender's
// box as a fraction box, or null to find a free place (then textBoxes count).
export function partySignatureSpot({ anchor, index, count, textBoxes }) {
  let grid = signatureGrid(count, anchor);
  // The sender's box stays where the sender put it: the other parties go to
  // its right as far as the page allows and then on the next row, instead of
  // the whole row sliding left off the chosen spot (acceptance test
  // 2026-10-04: a box placed at x 0.5 came out at x 0.04).
  if (anchor && Number.isFinite(anchor.x)) {
    const fit = Math.floor((1 - EDGE - anchor.x + GAP_X + 1e-9) / (grid.w + GAP_X));
    const rows = fit >= 1 ? Math.ceil(grid.count / fit) : 0;
    if (fit >= 1 && fit < grid.cols && rows * grid.h + (rows - 1) * GAP_Y <= 1 - EDGE) grid = { ...grid, cols: fit, rows };
  }
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

// ── Every party's paraaf, free of text (the retest of 2026-10-04) ──────────
// partyParaafSpot above lines the parafen up from ONE free corner without ever
// looking at the text again: with three or more parties on a full page the
// third, fourth and fifth paraaf slid over the last line of text. Here every
// paraaf is placed against the text itself:
//
//   - the text of ALL pages is laid on one fine grid (a paraaf sits on the same
//     spot on every page, so a cell is taken when ANY page has text there), and
//     the signature boxes of the parties count as taken too;
//   - candidate spots run through the page margins: the bottom margin first,
//     then the top margin, then the side margins;
//   - the first paraaf takes the free spot nearest the bottom right, every next
//     one the free spot nearest the parafen already placed (preferring the
//     same row), never on another party's paraaf;
//   - when the margins cannot hold every paraaf free of text at full size, all
//     parafen get a step smaller, down to 55%, and only then does the spot with
//     the least text under it win.
//
// Pure and deterministic: /sign (the sender) and /co-sign (every signer) feed
// it the same pdf.js text and get the same spots.
//
// pages: [{width,height}] in PDF points (view space); textBoxesPerPage: the
// same length, each [{x,y,w,h}] in points with a bottom-left origin
// (js/paraaf-place.js textBoxesFromItems), or null for a page without a text
// layer. avoid: [{ x, y, w, h }] in fractions with y from the top (signature
// boxes). Returns `count` boxes in fractions with y from the top.
const GRID_COLS = 300;
const GRID_ROWS = 400;
const PARAAF_SCALES = [1, 0.85, 0.7, 0.55];
const PARAAF_PAD_PT = 3;          // breathing room kept between a paraaf and text
const MIN_EDGE_X = 0.02;          // never closer to the paper edge than this
const MIN_EDGE_Y = 0.012;
const BAND = 0.16;                // how deep into the page a margin reaches

function buildOccupancy(pages, textBoxesPerPage, avoid) {
  const list = Array.isArray(pages) && pages.length ? pages : [{ width: 595.28, height: 841.89 }];
  // Every box is added in O(1) to a 2D difference grid and the grid is summed
  // once: a pdf with 50.000 page-sized text boxes used to mark 120k cells per
  // box on the main thread and froze the tab for 20 s (security review r2 (g)).
  // The cell values are the same as marking cell by cell.
  const DW = GRID_COLS + 1;
  const diff = new Float64Array(DW * (GRID_ROWS + 1));
  const mark = (fx0, fy0, fx1, fy1, weight) => {
    if (!(fx1 > 0 && fy1 > 0 && fx0 < 1 && fy0 < 1)) return;
    const c0 = clamp(Math.floor(fx0 * GRID_COLS), 0, GRID_COLS - 1);
    const c1 = clamp(Math.ceil(fx1 * GRID_COLS) - 1, 0, GRID_COLS - 1);
    const r0 = clamp(Math.floor(fy0 * GRID_ROWS), 0, GRID_ROWS - 1);
    const r1 = clamp(Math.ceil(fy1 * GRID_ROWS) - 1, 0, GRID_ROWS - 1);
    if (c1 < c0 || r1 < r0) return;
    diff[r0 * DW + c0] += weight;
    diff[r0 * DW + c1 + 1] -= weight;
    diff[(r1 + 1) * DW + c0] -= weight;
    diff[(r1 + 1) * DW + c1 + 1] += weight;
  };
  list.forEach((pg, i) => {
    const boxes = Array.isArray(textBoxesPerPage) ? textBoxesPerPage[i] : null;
    if (!Array.isArray(boxes) || !(pg && pg.width > 0 && pg.height > 0)) return;
    const px = PARAAF_PAD_PT / pg.width, py = PARAAF_PAD_PT / pg.height;
    for (const b of boxes) {
      if (!b || ![b.x, b.y, b.w, b.h].every(Number.isFinite)) continue;
      mark(b.x / pg.width - px, 1 - (b.y + b.h) / pg.height - py, (b.x + b.w) / pg.width + px, 1 - b.y / pg.height + py, 1);
    }
  });
  // A signature box is never covered: weigh it above every page of text together.
  for (const a of Array.isArray(avoid) ? avoid : []) {
    if (!a || ![a.x, a.y, a.w, a.h].every(Number.isFinite)) continue;
    mark(a.x - 0.006, a.y - 0.004, a.x + a.w + 0.006, a.y + a.h + 0.004, list.length + 1);
  }
  // Integrate the difference grid: raw = the weight covering each cell.
  const raw = new Float64Array(GRID_COLS * GRID_ROWS);
  const occ = new Float64Array(GRID_COLS * GRID_ROWS);
  for (let r = 0; r < GRID_ROWS; r++) {
    let run = 0;
    for (let c = 0; c < GRID_COLS; c++) {
      run += diff[r * DW + c];
      const v = (r ? raw[(r - 1) * GRID_COLS + c] : 0) + run;
      raw[r * GRID_COLS + c] = v;
      occ[r * GRID_COLS + c] = Math.min(65000, v);
    }
  }
  // 2D prefix sums: the text under any rectangle in O(1).
  const W = GRID_COLS + 1;
  const sum = new Float64Array(W * (GRID_ROWS + 1));
  for (let r = 0; r < GRID_ROWS; r++) {
    let row = 0;
    for (let c = 0; c < GRID_COLS; c++) {
      row += occ[r * GRID_COLS + c];
      sum[(r + 1) * W + c + 1] = sum[r * W + c + 1] + row;
    }
  }
  return (x, y, w, h) => {
    const c0 = clamp(Math.floor(x * GRID_COLS + 1e-9), 0, GRID_COLS), c1 = clamp(Math.ceil((x + w) * GRID_COLS - 1e-9), 0, GRID_COLS);
    const r0 = clamp(Math.floor(y * GRID_ROWS + 1e-9), 0, GRID_ROWS), r1 = clamp(Math.ceil((y + h) * GRID_ROWS - 1e-9), 0, GRID_ROWS);
    return sum[r1 * W + c1] - sum[r0 * W + c1] - sum[r1 * W + c0] + sum[r0 * W + c0];
  };
}

// Every candidate spot of a w x h paraaf, with the margin it lies in:
// 0 bottom, 1 top, 2 side. Steps of one grid cell.
function paraafCandidates(w, h) {
  const out = [];
  const xMax = 1 - MIN_EDGE_X - w, yMax = 1 - MIN_EDGE_Y - h;
  const c0 = Math.ceil(MIN_EDGE_X * GRID_COLS), c1 = Math.floor(xMax * GRID_COLS);
  const r0 = Math.ceil(MIN_EDGE_Y * GRID_ROWS), r1 = Math.floor(yMax * GRID_ROWS);
  for (let r = r0; r <= r1; r++) {
    const y = r / GRID_ROWS;
    const inBottom = y + h >= 1 - BAND;
    const inTop = y <= BAND;
    for (let c = c0; c <= c1; c++) {
      const x = c / GRID_COLS;
      const inSide = x <= BAND || x + w >= 1 - BAND;
      const band = inBottom ? 0 : inTop ? 1 : inSide ? 2 : -1;
      if (band >= 0) out.push({ x, y, band });
    }
  }
  return out;
}

export function paraafSpotsForParties({ pages, textBoxesPerPage, count, avoid }) {
  const n = Math.max(1, Math.min(30, Number(count) || 1));
  const cover = buildOccupancy(pages, textBoxesPerPage, avoid);
  // The spot a single paraaf has always had: bottom right, inside the margin.
  const homeOf = (w, h) => ({ x: 1 - 0.035 - w, y: 1 - 0.025 - h });
  const clash = (a, picked, w, h) => picked.some((p) =>
    a.x < p.x + w + GAP_X / 2 && p.x < a.x + w + GAP_X / 2 && a.y < p.y + h + GAP_Y / 3 && p.y < a.y + h + GAP_Y / 3);
  const cost = (c, picked, w, h) => {
    const bandCost = c.band * 2;
    if (!picked.length) {
      const home = homeOf(w, h);
      return bandCost + Math.abs(c.x - home.x) + 3 * Math.abs(c.y - home.y);
    }
    let best = Infinity;
    for (const p of picked) best = Math.min(best, Math.abs(c.x - p.x) + 3 * Math.abs(c.y - p.y));
    return bandCost + best;
  };
  const choose = (cands, w, h, keyOf) => {
    const picked = [];
    while (picked.length < n) {
      let best = null, bestKey = Infinity;
      for (const c of cands) {
        if (clash(c, picked, w, h)) continue;
        const k = keyOf(c, picked);
        if (k < bestKey - 1e-12) { best = c; bestKey = k; }
      }
      if (!best) break;
      picked.push(best);
    }
    return picked;
  };
  const out = (picked, w, h) => picked.map((p) => ({ x: round6(p.x), y: round6(p.y), w: round6(w), h: round6(h) }));
  for (const s of PARAAF_SCALES) {
    const w = PARAAF_FR.w * s, h = PARAAF_FR.h * s;
    const free = paraafCandidates(w, h).filter((c) => cover(c.x, c.y, w, h) === 0);
    const picked = choose(free, w, h, (c, p) => cost(c, p, w, h));
    if (picked.length === n) return out(picked, w, h);
  }
  // Nothing fits free of text even at the smallest size (text from edge to
  // edge): the least covered spots, still never on top of each other.
  const s = PARAAF_SCALES[PARAAF_SCALES.length - 1];
  const w = PARAAF_FR.w * s, h = PARAAF_FR.h * s;
  const all = paraafCandidates(w, h).map((c) => ({ ...c, cover: cover(c.x, c.y, w, h) }));
  const picked = choose(all, w, h, (c, p) => c.cover * 1000 + cost(c, p, w, h));
  while (picked.length < n) picked.push(picked[picked.length - 1] || homeOf(w, h));
  return out(picked, w, h);
}

// Everything one party is asked for: a signature on `signPage` and, when the
// sender wants it, a paraaf on every page. Returns a manifest-shaped object
// ({ version, fields }) for normaliseSigningAppearance.
export function partyRequest({ index, count, signPage, anchor, textBoxes, paraafCorner, paraafSpot, withParaaf }) {
  const fields = [];
  const sig = partySignatureSpot({ anchor, index, count, textBoxes });
  fields.push({ type: 'seal', page_index: Math.max(0, Number(signPage) || 0), ...sig });
  if (withParaaf) {
    const p = paraafSpot && Number.isFinite(paraafSpot.x) ? paraafSpot : partyParaafSpot({ corner: paraafCorner, index, count });
    fields.push({ type: 'seal', page_index: 0, x: p.x, y: p.y, w: p.w, h: p.h, all_pages: true });
  }
  return { version: withParaaf ? 2 : 1, fields };
}

// The sender's side (/sign, invite mode): one request per party from the one
// box the sender placed. anchor: the sender's box as a manifest field
// (requestedAppearanceFromStamp), signPage its page. withParaaf: the sender
// ticked "every page". pages: [{width,height}] in PDF points and
// textBoxesPerPage as js/paraaf-place.js reads them. The parafen are placed
// against the text of every page and clear of every party's signature
// (paraafSpotsForParties). Returns one manifest per party.
export function requestsForParties({ anchor, signPage, count, withParaaf, pages, textBoxesPerPage }) {
  const n = Math.max(1, Math.min(30, Number(count) || 1));
  // Without a box from the sender every party signs where /co-sign puts it
  // (autoSignaturePlace on the last page, or the signature sheet): the parafen
  // keep clear of exactly those spots.
  const lastIdx = Math.max(0, (pages && pages.length ? pages.length : 1) - 1);
  const lastBoxes = !anchor && pages && pages.length && Array.isArray(textBoxesPerPage) && textBoxesPerPage[lastIdx]
    ? textBoxesToFractions(textBoxesPerPage[lastIdx], pages[lastIdx].width, pages[lastIdx].height) : null;
  const sigs = anchor
    ? Array.from({ length: n }, (_, i) => partySignatureSpot({ anchor, index: i, count: n }))
    : Array.from({ length: n }, (_, i) => autoSignaturePlace({ index: i, count: n, pageCount: lastIdx + 1, textBoxes: lastBoxes }))
      .filter((p) => p.page_index <= lastIdx).map((p) => p.spot);
  const spots = withParaaf
    ? paraafSpotsForParties({ pages: pages && pages.length ? pages : null, textBoxesPerPage: Array.isArray(textBoxesPerPage) ? textBoxesPerPage : null, count: n, avoid: sigs })
    : null;
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(partyRequest({ index: i, count: n, signPage, anchor, paraafSpot: spots ? spots[i] : null, withParaaf: !!withParaaf }));
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
