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

// ── Page geometry: the view the signer sees vs. the space the PDF draws in ──
//
// pdf.js shows a page in its VIEW space: the visible box (CropBox clipped to
// the MediaBox) turned by the page's /Rotate, origin at the visible bottom
// left. pdf-lib draws in USER space: unturned, with the box wherever the file
// put it (a CropBox at 50,80 or a MediaBox at -100,-100 is not at 0,0). Every
// position the signer makes on screen (seal, paraaf, text, date, highlight,
// note, pen) is in view space, so the bake maps view space onto user space with
// one matrix and draws upright in the view. Test report 2026-10-04: on
// /Rotate 90/180/270 pages everything landed 50-77% off and sideways, and a
// CropBox offset shifted it 10-17%.
//
// geom: { view: [x0, y0, x1, y1] (pdf.js page.view, user space), rotate: 0|90|180|270 }.

// The rotation the way pdf.js reads it: multiples of 90 only, normalised into
// 0..270; anything else is shown unrotated, so it is treated as 0 here too.
export function normaliseRotation(r) {
  let n = Number(r) || 0;
  if (n % 90 !== 0) return 0;
  n %= 360;
  if (n < 0) n += 360;
  return n;
}

// The size of the page as the signer sees it (pdf.js getViewport({scale:1})).
export function viewSize(geom) {
  const [x0, y0, x1, y1] = geom.view;
  const W = Math.abs(x1 - x0), H = Math.abs(y1 - y0);
  const r = normaliseRotation(geom.rotate);
  return (r === 90 || r === 270) ? { width: H, height: W } : { width: W, height: H };
}

// [a, b, c, d, e, f] with x = a*u + c*v + e, y = b*u + d*v + f: view point
// (u, v), bottom-left origin, to user space. /Rotate turns the page CLOCKWISE
// for display, so drawing upright in the view means turning counter-clockwise
// in user space; that is what this matrix does when used as a PDF `cm`.
export function viewToUserMatrix(geom) {
  const x0 = Math.min(geom.view[0], geom.view[2]), y0 = Math.min(geom.view[1], geom.view[3]);
  const W = Math.abs(geom.view[2] - geom.view[0]), H = Math.abs(geom.view[3] - geom.view[1]);
  switch (normaliseRotation(geom.rotate)) {
    case 90:  return [0, 1, -1, 0, x0 + W, y0];
    case 180: return [-1, 0, 0, -1, x0 + W, y0 + H];
    case 270: return [0, -1, 1, 0, x0, y0 + H];
    default:  return [1, 0, 0, 1, x0, y0];
  }
}

// True when view space IS user space (no rotation, box at the origin): the bake
// then draws exactly as it always did, byte for byte.
export function isIdentityGeom(geom) {
  const m = viewToUserMatrix(geom);
  return m[0] === 1 && m[1] === 0 && m[2] === 0 && m[3] === 1 && m[4] === 0 && m[5] === 0;
}

export function viewToUserPoint(geom, u, v) {
  const [a, b, c, d, e, f] = viewToUserMatrix(geom);
  return { x: a * u + c * v + e, y: b * u + d * v + f };
}

export function userToViewPoint(geom, x, y) {
  const [a, b, c, d, e, f] = viewToUserMatrix(geom);
  const det = a * d - b * c;
  const dx = x - e, dy = y - f;
  return { u: (d * dx - c * dy) / det, v: (a * dy - b * dx) / det };
}

// Boxes in user space (textBoxesFromItems) -> boxes in view space, so the
// paraaf corners are judged on the page as the signer sees it: "bottom right"
// is the visible bottom right, also on a turned or cropped page.
export function userBoxesToView(boxes, geom) {
  if (!Array.isArray(boxes)) return boxes;
  if (!geom || isIdentityGeom(geom)) return boxes;
  return boxes.map((b) => {
    const pts = [[b.x, b.y], [b.x + b.w, b.y], [b.x, b.y + b.h], [b.x + b.w, b.y + b.h]]
      .map(([x, y]) => userToViewPoint(geom, x, y));
    const us = pts.map((p) => p.u), vs = pts.map((p) => p.v);
    const x = Math.min(...us), y = Math.min(...vs);
    return { x, y, w: Math.max(...us) - x, h: Math.max(...vs) - y };
  });
}

// The page geometry from pdf-lib, for when pdf.js could not read a page: the
// same rule pdf.js applies (CropBox clipped to the MediaBox, else the
// MediaBox; /Rotate in multiples of 90).
export function geomFromBoxes(mediaBox, cropBox, rotate) {
  const norm = (b) => b && [Math.min(b[0], b[2]), Math.min(b[1], b[3]), Math.max(b[0], b[2]), Math.max(b[1], b[3])];
  const m = norm(mediaBox) || [0, 0, 612, 792];
  let view = m;
  const c = norm(cropBox);
  if (c) {
    const box = [Math.max(c[0], m[0]), Math.max(c[1], m[1]), Math.min(c[2], m[2]), Math.min(c[3], m[3])];
    if (box[2] - box[0] > 0 && box[3] - box[1] > 0) view = box;
  }
  return { view, rotate: normaliseRotation(rotate) };
}

// ── A page without a text layer (a scan) ────────────────────────────────────
// pdf.js gives no text for a scanned page, and "no text" used to mean "free
// everywhere": the paraaf landed on the page number of a scan (acceptance test
// 2026-10-04). So the rendered page is looked at instead: every cell of a
// coarse grid that holds dark pixels counts as taken, exactly like a text box.
// data: RGBA bytes of a canvas w x h showing the whole page (view space).
// Returns boxes in PDF points with a bottom-left origin, as textBoxesFromItems.
export function inkBoxesFromImageData(data, w, h, pageW, pageH, cell = 4) {
  const out = [];
  if (!data || !(w > 0) || !(h > 0)) return out;
  for (let cy = 0; cy < h; cy += cell) {
    for (let cx = 0; cx < w; cx += cell) {
      let dark = 0;
      for (let y = cy; y < Math.min(h, cy + cell); y++) {
        for (let x = cx; x < Math.min(w, cx + cell); x++) {
          const o = (y * w + x) * 4;
          // Ink: clearly darker than paper (scans are rarely pure white).
          if (data[o + 3] > 0 && (data[o] + data[o + 1] + data[o + 2]) < 3 * 170) dark++;
        }
      }
      if (dark >= 2) {
        const x0 = (cx / w) * pageW, x1 = (Math.min(w, cx + cell) / w) * pageW;
        const yTop = (cy / h) * pageH, yBot = (Math.min(h, cy + cell) / h) * pageH;
        out.push({ x: x0, y: pageH - yBot, w: x1 - x0, h: yBot - yTop });
      }
    }
  }
  return out;
}
