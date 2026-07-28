// PDF.js loader (ESM -> global). Same-origin only, no CDN. Worker is
// self-hosted at /vendor/pdfjs/pdf.worker.min.js so worker-src 'self'
// suffices (no CSP relax required).
//
// Exposes window.__pdfjsLib and signals 'pdfjs' so non-module scripts can await
// it with `ready.when('pdfjs')`, whether they run before or after this file.
// The old 'pdfjs:ready' event is gone: consumers happened to guard it with an
// `if (window.__pdfjsLib)` pre-check, so it never bit here, but the identical
// pattern without that guard is what killed /ontvang. See js/ready.js.
import * as pdfjsLib from '/vendor/pdfjs/pdf.min.js';

pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/pdf.worker.min.js';

window.__pdfjsLib = pdfjsLib;
window.ready.signal('pdfjs', pdfjsLib);
