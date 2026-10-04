// Where the paraaf goes on the pages the signer did not place the seal on.
//
// The complaint (2026-10-04, a paying customer): "Het plaatst de paraaf random
// op de tekst." With "sign every page" on, /sign used to copy the FULL seal onto
// every other page at the same relative spot as on the signing page. On the
// signing page that spot is the free signature line; on the other pages it is
// running text. A paraaf is also not a seal: it is a small mark with initials.
//
// So: on every other page a small paraaf (initials, date, short fingerprint),
// in a free corner of the page margin. The text positions come from pdf.js
// (page.getTextContent), the same library the preview already loads.
//
// Pure functions only, no DOM and no pdf.js: sign-flow.js calls the SAME
// functions for the on-screen preview and for the baked PDF, so the signer sees
// exactly what gets signed (WYSIWYS), and tests/paraaf-place.test.mjs runs them
// in node.
//
// Units: PDF points, bottom-left origin (the pdf-lib convention).

// Order matters: the first free corner wins.
export const PARAAF_CORNERS = ['rechtsonder', 'linksonder', 'rechtsboven', 'linksboven'];

// Size relative to the page: about 17% of the width and 4.5% of the height,
// which on A4 is roughly 101 x 38 pt. Big enough for legible initials, small
// enough to fit in a normal page margin.
const W_FR = 0.17;
const H_FR = 0.045;
// Tried in this order before giving up: full size anywhere beats a smaller one.
const SHRINK = [1, 0.8, 0.65];
// Breathing room kept between the paraaf and any text.
const TEXT_PAD = 3;

// "Sandeep G. Prasad" -> "S.G.P."; "jan de vries" -> "J.D.V."; "" -> "".
// At most four letters: a paraaf is not a name.
export function initialsFrom(name) {
  const parts = String(name || '')
    .replace(/[\r\n\t]+/g, ' ')
    .split(/[\s\-]+/)
    .map((p) => p.replace(/[^\p{L}\p{N}]/gu, ''))
    .filter(Boolean);
  if (!parts.length) return '';
  return parts.slice(0, 4).map((p) => p[0].toUpperCase() + '.').join('');
}

// The paraaf box size on a page of pageW x pageH. Never larger than the seal
// in either direction: the paraaf is the small mark, the seal the big one.
export function paraafSize(pageW, pageH, seal) {
  let w = pageW * W_FR;
  let h = pageH * H_FR;
  if (seal && seal.w > 0 && seal.h > 0) {
    w = Math.min(w, seal.w);
    h = Math.min(h, seal.h);
  }
  return { w, h };
}

// The inset from the page edge: inside the margin, not glued to the edge.
export function paraafInset(pageW, pageH) {
  return { x: Math.max(12, pageW * 0.035), y: Math.max(12, pageH * 0.025) };
}

function cornerBox(corner, pageW, pageH, w, h) {
  const m = paraafInset(pageW, pageH);
  const right = corner.startsWith('rechts');
  const bottom = corner.endsWith('onder');
  return {
    x: right ? pageW - m.x - w : m.x,
    y: bottom ? m.y : pageH - m.y - h,
    w,
    h,
  };
}

function overlaps(a, b, pad) {
  return a.x < b.x + b.w + pad && b.x < a.x + a.w + pad
    && a.y < b.y + b.h + pad && b.y < a.y + a.h + pad;
}

// Pick the spot for one page. textBoxes: [{x,y,w,h}] in PDF points, or null
// when the text layer could not be read (a scanned PDF, a pdf.js failure).
// Returns { x, y, w, h, corner, free }: free is false only for the last-resort
// fallback, where nothing was free and the paraaf goes bottom right, smallest.
export function pickParaafSpot(pageW, pageH, size, textBoxes) {
  const boxes = Array.isArray(textBoxes) ? textBoxes : null;
  if (!boxes) {
    return { ...cornerBox('rechtsonder', pageW, pageH, size.w, size.h), corner: 'rechtsonder', free: true, textLayer: false };
  }
  for (const k of SHRINK) {
    const w = size.w * k, h = size.h * k;
    for (const corner of PARAAF_CORNERS) {
      const box = cornerBox(corner, pageW, pageH, w, h);
      if (!boxes.some((t) => overlaps(box, t, TEXT_PAD))) return { ...box, corner, free: true, textLayer: true };
    }
  }
  const k = SHRINK[SHRINK.length - 1];
  return { ...cornerBox('rechtsonder', pageW, pageH, size.w * k, size.h * k), corner: 'rechtsonder', free: false, textLayer: true };
}

// pdf.js textContent.items -> boxes in PDF user space. Each item carries its
// text matrix in transform [a,b,c,d,e,f] and its advance in width; the box runs
// from a quarter font size below the baseline (descenders) to one font size
// above it. Rotated text gets the bounding box of its rotated rectangle.
export function textBoxesFromItems(items) {
  const out = [];
  for (const it of items || []) {
    if (!it || typeof it.str !== 'string' || !it.str.trim()) continue;
    const t = it.transform;
    if (!Array.isArray(t) || t.length < 6) continue;
    const [a, b, c, d, e, f] = t;
    const fs = Math.hypot(c, d) || Math.hypot(a, b) || Number(it.height) || 0;
    const len = Math.hypot(a, b) || 1;
    const ux = a / len, uy = b / len;            // text direction
    const vx = -uy, vy = ux;                      // up, perpendicular
    const width = Number(it.width) || 0;
    const lo = -0.25 * fs, hi = fs;
    const pts = [
      [e + vx * lo, f + vy * lo],
      [e + vx * hi, f + vy * hi],
      [e + ux * width + vx * lo, f + uy * width + vy * lo],
      [e + ux * width + vx * hi, f + uy * width + vy * hi],
    ];
    const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
    const x = Math.min(...xs), y = Math.min(...ys);
    const box = { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y };
    if ([box.x, box.y, box.w, box.h].every(Number.isFinite)) out.push(box);
  }
  return out;
}

// One placement for every page except the seal page. pages: [{width,height}],
// textBoxesPerPage: same length, each an array or null. Returns a sparse list
// [{ pageIndex, x, y, w, h, corner, free }] for the pages that get a paraaf.
export function planParaafs(pages, sealPageIndex, seal, textBoxesPerPage) {
  const plan = [];
  const src = pages[sealPageIndex];
  for (let i = 0; i < pages.length; i++) {
    if (i === sealPageIndex) continue;
    const { width, height } = pages[i];
    // The seal is measured on its own page; scale it to this page before it
    // caps the paraaf, so a mixed-size document still keeps paraaf < seal.
    const sx = src ? width / src.width : 1, sy = src ? height / src.height : 1;
    const size = paraafSize(width, height, seal ? { w: seal.w * sx, h: seal.h * sy } : null);
    const boxes = textBoxesPerPage ? textBoxesPerPage[i] : null;
    plan.push({ pageIndex: i, ...pickParaafSpot(width, height, size, boxes) });
  }
  return plan;
}

// For co-sign, where one signed field (all_pages) sits at the SAME normalised
// spot on every page: the corner that is free on the most pages, as page
// fractions with y from the TOP (the co-sign manifest's convention). w and h
// are fractions of the page too. pages: [{width,height}], textBoxesPerPage as
// in planParaafs. Ties go to the earlier corner, so no text layer at all means
// bottom right.
export function pickSharedSpot(pages, textBoxesPerPage, w, h) {
  const list = pages && pages.length ? pages : [{ width: 595.28, height: 841.89 }];
  let best = null;
  for (const k of SHRINK) {
    for (const corner of PARAAF_CORNERS) {
      let free = 0;
      let fr = null;
      list.forEach((pg, i) => {
        const box = cornerBox(corner, pg.width, pg.height, w * k * pg.width, h * k * pg.height);
        if (!fr) fr = { x: box.x / pg.width, y: 1 - (box.y + box.h) / pg.height, w: w * k, h: h * k };
        const boxes = textBoxesPerPage ? textBoxesPerPage[i] : null;
        if (!Array.isArray(boxes) || !boxes.some((t) => overlaps(box, t, TEXT_PAD))) free++;
      });
      if (!best || free > best.freeOn) best = { ...fr, corner, freeOn: free, pages: list.length };
      if (free === list.length) return best;
    }
  }
  return best;
}

// The one-line footer of the paraaf: "2026-10-04 · PQ 0a1b2c3d".
export function paraafFooter(dateStr, fingerprint8) {
  const date = String(dateStr || '').slice(0, 10);
  const fp = String(fingerprint8 || '').slice(0, 8);
  return [date, fp ? 'PQ ' + fp : ''].filter(Boolean).join(' · ');
}
