// /sign loads pdf-lib and PDF.js on demand, when a document is picked
// (frontend/sign-flow.js, preloadPdfLibs). The suites build their test PDF with
// the page's own window.PDFLib BEFORE they pick anything, so they ask for the
// libraries first, exactly the way the page does. The urls are read out of
// sign-flow.js, so a cache-bust there needs no edit here.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FLOW = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'frontend', 'sign-flow.js'), 'utf8');
const PDFJS = FLOW.match(/const PDFJS_LOADER = '([^']+)'/)[1];
const PDFLIB = FLOW.match(/const PDFLIB_SRC = '([^']+)'/)[1];

export async function loadPdfLibs(page) {
  await page.evaluate(([pdfjs, pdflib]) => {
    for (const [src, isModule] of [[pdfjs, true], [pdflib, false]]) {
      if (document.querySelector('script[src="' + src + '"]')) continue;
      const el = document.createElement('script');
      if (isModule) el.type = 'module';
      el.src = src;
      document.head.appendChild(el);
    }
  }, [PDFJS, PDFLIB]);
}
