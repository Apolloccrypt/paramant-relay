// PDF.js loader (ESM -> global). Same-origin only, no CDN. Worker is
// self-hosted at /vendor/pdfjs/pdf.worker.min.js so worker-src 'self'
// suffices (no CSP relax required).
//
// Exposes window.__pdfjsLib and dispatches the 'pdfjs:ready' event so
// non-module scripts can await it.
import * as pdfjsLib from './pdf.min.js';

pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/pdf.worker.min.js';

window.__pdfjsLib = pdfjsLib;
window.dispatchEvent(new CustomEvent('pdfjs:ready'));
