// PDF.js loader (ESM -> global). Same-origin only, no CDN. Worker is
// self-hosted at /vendor/pdfjs/pdf.worker.min.js so worker-src 'self'
// suffices (no CSP relax required).
//
// Exposes window.__pdfjsLib and dispatches the 'pdfjs:ready' event so
// non-module scripts can await it.
//
// Also exports renderPageToCanvas(): the ONE robust PDF.js page-render
// helper shared by /sign (sign-flow.js) and /co-sign (co-sign.js). It fixes
// the iOS Safari "blank page with only a floating seal" bug — see below.
import * as pdfjsLib from './pdf.min.js';

pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/pdf.worker.min.js';

window.__pdfjsLib = pdfjsLib;

// ====================================================================
// Robust canvas page render (iOS Safari blank-seal fix)
// ====================================================================
//
// Root cause of the iOS bug: WebKit silently caps a canvas backing store at
// ~16.7 Mpx (and ~4096px per dimension). Past the cap it does NOT throw — it
// returns a blank (transparent) bitmap, so page.render().promise resolves
// "successfully" over nothing. The Paramant seal is a separate absolutely
// positioned DOM overlay, so it always paints — giving the classic "white page
// with only the floating POST-QUANTUM SIGNED seal". Compounding: no
// devicePixelRatio handling (soft/blank at retina), recycled GPU buffers
// showing stale content, and up to ~30 live canvases tipping over WebKit's
// per-tab canvas budget.
//
// Fix, all gated behind a real-WebKit feature-detect so desktop Chrome/Firefox
// rendering is byte-for-byte unchanged:
//   - cap the canvas pixel area (~4 Mpx, <=4096px/dim), scaling the viewport DOWN;
//   - clamp devicePixelRatio to 2 for sharpness;
//   - reset the canvas (canvas.width = canvas.width + ctx.reset?.()) before paint
//     to kill recycled GPU buffers;
//   - after render, VERIFY the bitmap is non-blank (sample pixels; all-transparent
//     == blank, NOT all-white — PDF.js paints white pages opaque). Retry once at a
//     lower scale; if still blank, render a graceful placeholder instead of a
//     blank canvas;
//   - optional IntersectionObserver lazy render so all ~30 pages are not live at
//     once (render on scroll-into-view; release offscreen canvases via width = 0).

// True Apple WebKit only. Chrome/Edge/Brave/Opera put "Safari" in their UA, so
// match Safari/WebKit and EXCLUDE the Chromium tokens. We additionally treat any
// iOS/iPadOS device as WebKit because every browser on iOS is WebKit under the
// hood (and iPadOS Safari reports a desktop "Macintosh" UA, so also sniff touch).
function detectWebKit() {
  try {
    const ua = (navigator.userAgent || '');
    const isChromium = /\b(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPiOS|SamsungBrowser)\b/.test(ua);
    const looksSafari = /\b(Safari|AppleWebKit)\b/.test(ua) && !isChromium;
    const iOS = /iP(hone|ad|od)/.test(ua) ||
      (navigator.platform === 'MacIntel' && (navigator.maxTouchPoints || 0) > 1); // iPadOS desktop UA
    return looksSafari || iOS;
  } catch { return false; }
}
const IS_WEBKIT = detectWebKit();

// Conservative caps. WebKit's real ceiling is ~16.7 Mpx / 4096px-per-dim; we aim
// well under it because the *device-pixel* area (CSS px * dpr^2) is what counts.
const WK_MAX_CANVAS_AREA = 4 * 1024 * 1024;   // ~4.2 Mpx device pixels
const WK_MAX_CANVAS_DIM = 4096;               // px per dimension
const DPR_CAP = 2;

function clampedDpr() {
  const d = (typeof window !== 'undefined' && window.devicePixelRatio) ? window.devicePixelRatio : 1;
  return Math.max(1, Math.min(DPR_CAP, d || 1));
}

// Sample a handful of pixels and report whether the bitmap is effectively blank.
// "Blank" means every sampled pixel is fully transparent (alpha === 0). We do NOT
// treat all-white as blank: PDF.js fills page backgrounds with opaque white, so a
// legitimately rendered page is opaque. A silently-capped WebKit canvas, by
// contrast, stays transparent. Any getImageData failure (e.g. tainted canvas)
// is treated as NON-blank so we never hide a page we merely failed to inspect.
function isCanvasBlank(canvas) {
  try {
    const ctx = canvas.getContext('2d');
    if (!ctx) return false;
    const w = canvas.width, h = canvas.height;
    if (w === 0 || h === 0) return true;
    const pts = [
      [w >> 1, h >> 1],
      [w >> 2, h >> 2],
      [(w * 3) >> 2, h >> 2],
      [w >> 2, (h * 3) >> 2],
      [(w * 3) >> 2, (h * 3) >> 2],
      [w >> 1, h >> 3],
      [w >> 1, (h * 7) >> 3],
    ];
    for (const [x, y] of pts) {
      const px = Math.min(w - 1, Math.max(0, x));
      const py = Math.min(h - 1, Math.max(0, y));
      const d = ctx.getImageData(px, py, 1, 1).data;
      if (d[3] !== 0) return false;   // found an opaque pixel -> not blank
    }
    return true;   // every sample fully transparent -> blank raster
  } catch {
    return false;   // could not inspect -> assume it rendered
  }
}

// Compute a render scale that respects the WebKit caps. `scale` is the caller's
// desired CSS-pixel scale; on WebKit we may shrink it so width*height*dpr^2 stays
// under the area/dim caps. Returns { scale, dpr } — dpr is 1 off-WebKit so the
// backing store equals the CSS box exactly (unchanged desktop behaviour).
function fitScaleToCaps(page, scale) {
  if (!IS_WEBKIT) return { scale, dpr: 1 };
  const dpr = clampedDpr();
  let s = scale;
  // Iterate down until the device-pixel backing store fits both caps. A few
  // passes converge; cap the loop defensively.
  for (let i = 0; i < 24; i++) {
    const vp = page.getViewport({ scale: s });
    const wDev = vp.width * dpr;
    const hDev = vp.height * dpr;
    const overDim = Math.max(wDev, hDev) > WK_MAX_CANVAS_DIM;
    const overArea = wDev * hDev > WK_MAX_CANVAS_AREA;
    if (!overDim && !overArea) break;
    let shrink = 1;
    if (overDim) shrink = Math.min(shrink, WK_MAX_CANVAS_DIM / Math.max(wDev, hDev));
    if (overArea) shrink = Math.min(shrink, Math.sqrt(WK_MAX_CANVAS_AREA / (wDev * hDev)));
    s = s * shrink * 0.98;   // 0.98 guards against rounding back over the cap
    if (s < 0.02) { s = 0.02; break; }
  }
  return { scale: s, dpr };
}

// Paint `page` into `canvas` at `scale` (CSS px) using `dpr` for the backing
// store. Resets the canvas first to drop any recycled GPU buffer. Returns the
// CSS-pixel viewport width/height the canvas should *display* at.
async function paintOnce(page, canvas, scale, dpr) {
  const cssVp = page.getViewport({ scale });
  const cssW = Math.max(1, Math.floor(cssVp.width));
  const cssH = Math.max(1, Math.floor(cssVp.height));
  // Reset: setting width (even to the same value) clears the backing store and
  // forces WebKit to drop the previous (possibly recycled/stale) GPU buffer.
  canvas.width = Math.max(1, Math.floor(cssW * dpr));
  canvas.height = Math.max(1, Math.floor(cssH * dpr));
  const ctx = canvas.getContext('2d');
  if (ctx && typeof ctx.reset === 'function') { try { ctx.reset(); } catch { /* noop */ } }
  // Render at device resolution; the page is laid out at dpr*scale.
  const renderVp = page.getViewport({ scale: scale * dpr });
  await page.render({ canvasContext: ctx, viewport: renderVp }).promise;
  return { cssW, cssH };
}

function placeholderHtml(canvas, cssW, cssH) {
  // Replace a doomed canvas with a same-sized "preview unavailable" tile rather
  // than leaving a blank (which would invite the floating-seal bug to recur).
  const ph = document.createElement('div');
  ph.className = 'ds-preview-unavailable';
  ph.setAttribute('role', 'img');
  ph.setAttribute('aria-label', 'Page preview unavailable on this device');
  ph.style.cssText =
    'width:100%;aspect-ratio:' + Math.max(1, cssW) + ' / ' + Math.max(1, cssH) + ';' +
    'display:flex;align-items:center;justify-content:center;text-align:center;' +
    'box-sizing:border-box;padding:16px;border:1px solid var(--ink-hair,#d8d8d8);' +
    'background:#fafafa;color:var(--ink-dim,#666);font:500 12px/1.4 Inter,system-ui,sans-serif';
  ph.textContent = 'Preview unavailable on this device. The document hash and signature are unaffected.';
  if (canvas && canvas.parentNode) canvas.parentNode.replaceChild(ph, canvas);
  return ph;
}

/**
 * Render a PDF.js page into a freshly-created <canvas> appended to `container`.
 *
 * @param {PDFPageProxy} page    a pdf.js page (await pdf.getPage(n))
 * @param {HTMLElement}  container element the canvas (or its wrap) is appended to
 * @param {object} [opts]
 *   @param {number}  [opts.scale=1]        desired CSS-pixel render scale
 *   @param {boolean} [opts.lazy=false]     defer paint until scrolled into view
 *     (releases offscreen canvases) — use when rendering many pages at once
 *   @param {Element} [opts.wrap]           wrapper to append/observe instead of
 *     the bare canvas (the canvas is appended inside it)
 *   @param {Element} [opts.root=null]      IntersectionObserver root (scroll box)
 * @returns {Promise<{canvas:HTMLCanvasElement, ok:boolean, lazy:boolean,
 *                     blank:boolean, render:Function}>}
 *   `ok` is true once a non-blank raster is on the canvas. For lazy tiles `ok`
 *   is false until the tile scrolls into view and `render()` resolves; callers
 *   that need to gate UI (e.g. a seal overlay) on a real raster should `await
 *   result.render()`.
 */
export async function renderPageToCanvas(page, container, opts) {
  opts = opts || {};
  const scale = opts.scale || 1;
  const wrap = opts.wrap || null;
  const host = wrap || container;
  const canvas = document.createElement('canvas');
  // CSS sizing is handled by the page stylesheet (canvas{width:100%;height:auto}),
  // so the backing store can exceed the CSS box (that is exactly the dpr win).
  // Reserve the page's height up front via CSS aspect-ratio. An unpainted canvas
  // has zero intrinsic size and would collapse — which, in lazy mode, stacks every
  // tile at the same scroll offset and makes the IntersectionObserver fire for all
  // of them at once (defeating the point). Reserving height keeps the scroll
  // geometry right so tiles paint progressively as they near the viewport.
  try {
    const av = page.getViewport({ scale: 1 });
    if (av && av.width > 0 && av.height > 0) canvas.style.aspectRatio = av.width + ' / ' + av.height;
  } catch { /* noop */ }
  host.appendChild(canvas);
  if (wrap && wrap.parentNode == null) container.appendChild(wrap);

  // The actual paint+verify+retry+fallback, run now (eager) or on first
  // intersection (lazy). Idempotent-guarded so the observer can't double-fire.
  let done = false;
  let okState = false;
  let settle;
  const settled = new Promise((res) => { settle = res; });

  async function doRender() {
    if (done) return okState;
    done = true;
    try {
      const fit1 = fitScaleToCaps(page, scale);
      let painted = await paintOnce(page, canvas, fit1.scale, fit1.dpr);
      let blank = IS_WEBKIT && isCanvasBlank(canvas);
      if (blank) {
        // Retry ONCE at half the (already capped) scale — a smaller backing store
        // is the single most reliable way out of the WebKit silent-cap.
        const fit2 = fitScaleToCaps(page, scale * 0.5);
        painted = await paintOnce(page, canvas, Math.min(fit2.scale, fit1.scale * 0.5), fit2.dpr);
        blank = isCanvasBlank(canvas);
      }
      if (blank) {
        placeholderHtml(canvas, painted.cssW, painted.cssH);
        okState = false;
      } else {
        okState = true;
      }
    } catch (e) {
      // A hard render failure also gets the graceful placeholder (never a blank).
      try {
        const cssVp = page.getViewport({ scale });
        placeholderHtml(canvas, Math.floor(cssVp.width), Math.floor(cssVp.height));
      } catch { /* noop */ }
      okState = false;
    }
    settle(okState);
    return okState;
  }

  if (!opts.lazy) {
    await doRender();
    return { canvas, ok: okState, lazy: false, blank: !okState, render: () => settled };
  }

  // Lazy: paint on first scroll-into-view; release the backing store when the
  // tile scrolls away (canvas.width = 0 frees the GPU buffer on WebKit). Pages
  // already in view at setup time fire immediately via the observer callback.
  if (typeof IntersectionObserver === 'function') {
    const io = new IntersectionObserver((entries) => {
      for (const en of entries) {
        if (en.isIntersecting) {
          doRender().then(() => { /* settled */ });
        } else if (done && okState && canvas.isConnected) {
          // Offscreen: drop the backing store to stay under WebKit's canvas budget.
          // Re-enter the lazy state so it repaints when scrolled back.
          canvas.width = 0; canvas.height = 0;
          done = false; okState = false;
        }
      }
    }, { root: opts.root || null, rootMargin: '600px 0px' });
    io.observe(host);
  } else {
    // No IntersectionObserver: just render eagerly.
    await doRender();
  }
  return { canvas, ok: okState, lazy: true, get blank() { return !okState; }, render: () => settled };
}

// Expose for any non-module consumer (parity with window.__pdfjsLib).
window.__pdfjsRenderPage = renderPageToCanvas;
window.__pdfjsIsWebKit = IS_WEBKIT;

window.dispatchEvent(new CustomEvent('pdfjs:ready'));
