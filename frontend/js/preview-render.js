// Preview-render guards for the PDF previews in sign-flow.js. Pure functions,
// no DOM at load time, so tests/preview-render.test.mjs runs them in node.
//
// Two failures these close, both first diagnosed on feat/parasign-pdf-preview
// (June 2026) and never landed:
//
// 1. A width read while a pane is display:none or mid-transition. iOS Safari
//    then reports clientWidth 1 (or innerWidth 0), the old `|| 340` fallback
//    only rescued an exact 0, and the result was a 1px canvas: a blank preview
//    and a seal that lands in the wrong place, because the canvas width feeds
//    the click-to-points ratio.
//
// 2. Two renders of the same pane at once. renderDocPreview clears the pane,
//    then awaits pdf.js per page. A second call (the seal drag with "every
//    page" on calls it again) clears the pane too, and both loops then append
//    their pages: the review shows every page twice. A generation ticket per
//    pane lets the older render stop as soon as a newer one has started.

// Clamp a measured width to [min, max]. A missing or zero measurement falls
// back to max; anything that is not a finite number counts as missing.
export function previewTargetWidth(measured, max, min) {
  const n = Number(measured);
  const w = Number.isFinite(n) && n > 0 ? Math.floor(n) : max;
  return Math.min(max, Math.max(min, w));
}

// The full-width preview target: 88% of the viewport, between 280 and 820 px.
export function viewportTargetWidth(innerWidth) {
  const n = Number(innerWidth);
  const vw = Number.isFinite(n) && n > 0 ? n : 820 / 0.88;
  return previewTargetWidth(Math.floor(vw * 0.88), 820, 280);
}

// One counter per surface. start() hands out a ticket and makes every older
// ticket stale; current(ticket) says whether that render may still touch the
// DOM.
export function renderGeneration() {
  let gen = 0;
  return {
    start() { return ++gen; },
    current(ticket) { return ticket === gen; },
  };
}
