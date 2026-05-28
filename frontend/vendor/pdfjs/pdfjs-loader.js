// PDF.js loader (ESM -> global). Same-origin only, no CDN. Worker is
// self-hosted at /vendor/pdfjs/pdf.worker.min.mjs so worker-src 'self'
// suffices (no CSP relax required).
//
// Surfaces load errors via a pdfjs:error event so callers can show what
// actually went wrong instead of a generic 'PDF.js failed to load'.
//
// Cache-buster on the pdf.min.mjs and worker URLs: nginx ships these
// with max-age=31536000 immutable, so a once-corrupted cached copy
// would stick for a year. Bumping PDFJS_V forces a fresh fetch of both.
const PDFJS_V = '3';

// .js extension on purpose: PDF.js 4.x ships ESM-only files as .mjs, but
// nginx /etc/nginx/mime.types only maps .js to application/javascript.
// .mjs falls through to application/octet-stream, which strict browsers
// (Firefox, Chrome with nosniff) refuse to load as a module. Renaming to
// .js fixes the MIME issue without touching nginx config. ESM-ness is
// determined by the `import`/`export` syntax in the file content, not by
// the extension.
(async () => {
  try {
    const pdfjsLib = await import('./pdf.min.js?v=' + PDFJS_V);
    pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/pdf.worker.min.js?v=' + PDFJS_V;
    window.__pdfjsLib = pdfjsLib;
    window.dispatchEvent(new CustomEvent('pdfjs:ready'));
  } catch (err) {
    window.__pdfjsLoadError = err;
    window.dispatchEvent(new CustomEvent('pdfjs:error', { detail: err }));
    console.error('[pdfjs-loader] import failed:', err);
  }
})();
