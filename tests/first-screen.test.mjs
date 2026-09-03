// What a phone sees first, on every page a buyer lands on.
//
// Every copper pin in this repo reads markup: the text is in the HTML, so the
// assertion is green. None of them looks at where that text ends up. A single
// CSS line moves it. `margin-top: 400px` on `.about-byline` leaves /about with
// the same words, the same DOM and the same passing suite, and pushes the name
// of the person behind the product 400px below a 390x844 phone screen. The
// reviewers who read these pages on 2026-09-02 measured them; this file keeps
// the measurements.
//
// tests/pricing-fold.test.mjs does exactly this for /pricing and this file is
// the same instrument pointed at the other nine pages. Two rules carried over
// from it:
//
//   1. THE BOTTOM EDGE, NOT THE TOP. A line whose top is at 830 is on screen
//      and unreadable. Every claim below is pinned by getBoundingClientRect().
//      bottom against 844, and the failure message names the measured value, so
//      a red run says how far it moved rather than that it moved.
//
//   2. NO HORIZONTAL SCROLL. scrollWidth must equal clientWidth must equal 390
//      on every page. A card that overflows its grid is invisible in the HTML
//      and obvious on a laid-out page; /pricing shipped that defect.
//
// The one claim measured on a text range rather than an element is the SES
// scope note on /parasign. Its paragraph runs from y=753 to y=950, so the block
// does not fit and never was meant to: what has to be readable before a buyer
// signs is the sentence that says the signature is a Simple Electronic
// Signature, and that is measured on its own line boxes.
//
// Selectors are the ids and classes the pages already carry. Nothing here
// changes a word of copy.
//
// THE FONT IS FORCED, and it has to be. design-system.css resolves --sans and
// --mono to system stacks with no @font-face anywhere, so the same page is a
// different height on every machine. The first run of this file was green on
// Fedora, where ui-sans-serif resolves to Cantarell, and red on ubuntu-latest,
// where it resolves to DejaVu Sans: /parasign moved 63px and /help 41px. A gate
// whose numbers depend on the runner is not a gate. So every page is measured
// in DejaVu Sans, which is what CI renders anyway and the widest of the faces in
// play, and a developer now reads the same numbers the gate does. DejaVu is
// installed by `playwright install --with-deps`; the resolved family is named in
// every failure message, so a run on a machine without it says so.
//
// Two claims used to hang over the edge in DejaVu and were pinned in place
// rather than at the fold: the SES sentence on /parasign at y=863 and the third
// answer on /help at y=860. Both are fixed in the CSS of those two pages, in
// their mobile media queries and without touching a word of the copy, so every
// claim in this file now holds the same line: bottom <= 844. `at` records the
// position each one was pulled back to, and a failure names it alongside the
// value it drifted to.
//
// Run: node --test tests/first-screen.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2', '.json':'application/json' };
const FOLD = { width: 390, height: 844 };
// The widest face any of these runners has. Forced so the numbers below mean the
// same thing on a laptop and in CI.
const FONT = ':root{--sans:"DejaVu Sans",sans-serif;--mono:"DejaVu Sans Mono",monospace}';

// The routes nginx serves, so the test walks the same URLs a visitor does.
// deploy/nginx-paramant-live.conf:105 maps /help onto a directory index.
const aliases = {
  '/': '/index.html',
  '/parasign': '/parasign.html',
  '/parasend': '/parasend.html',
  '/about': '/about.html',
  '/security': '/security.html',
  '/trust': '/trust.html',
  '/docs': '/docs.html',
  '/help': '/help/index.html',
  '/download': '/download.html',
};

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = aliases[pathname] || pathname;
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

// Every page is measured signed out. The homepage keeps a second hero for the
// signed-in state and would otherwise resolve into whichever one the session
// call decides, which is not the state a visitor arrives in.
async function open(slug) {
  const page = await browser.newPage({ viewport: { width: FOLD.width, height: FOLD.height } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
  await page.goto(ORIGIN + slug, { waitUntil: 'networkidle' });
  // Appended last, so it wins over the :root block in design-system.css on equal
  // specificity. Layout is flushed by the first getBoundingClientRect below.
  await page.addStyleTag({ content: FONT });
  return page;
}

// One measurement per claim. `css` plus `nth` picks the element; `phrase` narrows
// the measurement to a run of text inside it. Returns the measured geometry and
// the text and href actually found, so an assertion can check it read the thing
// it meant to read rather than a same-classed element elsewhere on the page.
const measure = (page, claims) => page.evaluate((specs) => {
  const found = [];
  for (const spec of specs) {
    const element = document.querySelectorAll(spec.css)[spec.nth || 0];
    if (!element) { found.push({ name: spec.name, missing: 'element' }); continue; }
    let rect = element.getBoundingClientRect();
    if (spec.phrase) {
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      let range = null;
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const at = node.nodeValue.indexOf(spec.phrase);
        if (at < 0) continue;
        range = document.createRange();
        range.setStart(node, at);
        range.setEnd(node, at + spec.phrase.length);
        break;
      }
      if (!range) { found.push({ name: spec.name, missing: 'phrase' }); continue; }
      rect = range.getBoundingClientRect();
    }
    found.push({
      name: spec.name,
      top: Math.round(rect.top + window.scrollY),
      bottom: Math.round(rect.bottom + window.scrollY),
      href: element.getAttribute('href'),
      text: (element.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160),
      // System font stack, so a run on another machine can render taller. Named
      // here because a failure that is only a font difference has to be legible
      // as one instead of read as a layout regression.
      font: getComputedStyle(element).fontFamily.split(',')[0].replace(/"/g, ''),
    });
  }
  return found;
}, claims);

// What the reviewers read on each page, in the order they read it. `text` is the
// proof the right element was measured; the geometry is the assertion.
const PAGES = [
  {
    slug: '/',
    claims: [
      { name: 'the H1', css: '[data-home="out"] h1', text: 'Get documents signed and send files safely' },
      { name: 'the line that says who it is for', css: '[data-home="out"] p.lede', text: 'small professional firms' },
      // The split the whole homepage argues from. It has to be readable as a
      // split, so both halves are checked in one line: free tier named, paid
      // tier named, on the first screen.
      { name: 'the Community and business plans split', css: '[data-home="out"] p.hero-note', text: 'Community plan', also: ['business plans from'] },
      { name: 'the first action', css: '[data-home="out"] .home-actions a', href: '/sign' },
      // Mick, 4 September: one note is enough. The founder line left both hero
      // states; the letter signature further down the page is the one place the
      // homepage still names him, and tests/ui-truthfulness pins that block.
      { name: 'the heading of the five facts, which now come before the gift (panel of 4 September: facts convince, the letter can wait)', css: '#check-h', text: 'Five things you can check' },
    ],
  },
  {
    slug: '/parasign',
    claims: [
      { name: 'the line that says who it is for', css: 'p.ps-who', text: 'For legal, finance and healthcare practices' },
      { name: 'the first action', css: '.ps-actions a.btn-primary', href: '/sign' },
      // Not the paragraph, which runs to y=950 by design. The sentence.
      // It ended at 863 in DejaVu, 19px over the edge, so on a wide face a buyer
      // scrolled to find out that a ParaSign signature is not a qualified one.
      // parasign.html now closes the gap under the section rule and above the
      // buttons on a phone, which lifts it to 815. The sentence itself is
      // untouched and still matches about.html:254 word for word.
      { name: 'the SES scope statement', css: '.scope-note p', phrase: 'Simple Electronic Signature (SES)', at: 815 },
      { name: 'the free limit', css: 'p.ps-fine', text: '2 signatures a month' },
    ],
  },
  {
    slug: '/parasend',
    claims: [
      { name: 'the line that says who it is for', css: 'p.ps-who', text: 'For offices that email client documents' },
      { name: 'the first action', css: '.ps-actions a.btn-primary', href: '/parashare' },
      { name: 'the free limit', css: 'p.ps-sub', text: '10 transfers a month' },
    ],
  },
  {
    slug: '/about',
    // The case this whole file exists for: two lines, no id of their own until
    // now, and the only place on the site that names the person behind it.
    claims: [
      { name: 'the name of the person behind it', css: '.about-byline .n', text: 'Mick Beer' },
      { name: 'his title', css: '.about-byline .t', text: 'Privacy and security researcher' },
      { name: 'the first action', css: '.hero-cta a.btn-primary', href: '/pricing' },
      { name: 'the second action', css: '.hero-cta a.btn-secondary', href: '/security' },
    ],
  },
  {
    slug: '/security',
    claims: [
      // Bounded on purpose: what breaking in still does not get you. A promise
      // with its limit attached is worth nothing if the limit scrolls away.
      { name: 'the bounded promise', css: '.page-hero .lede', text: 'Break into our own server and you still cannot read' },
      { name: 'who is behind it', css: '.hero-by', text: 'Paramantis Solutions B.V.' },
      { name: 'the first action', css: '.hero-cta a.btn-primary', href: '/pricing' },
      { name: 'the second action', css: '.hero-cta a.btn-secondary', href: '/verify' },
    ],
  },
  {
    slug: '/trust',
    claims: [
      { name: 'the lede', css: '.page-hero .lede', text: 'For organisations that run Paramant on their own server' },
      { name: 'the first action', css: '.hero-cta a.btn-primary', href: '/security' },
      { name: 'the second action', css: '.hero-cta a.btn-secondary', href: '/pricing' },
    ],
  },
  {
    slug: '/docs',
    claims: [
      // The one line on a reference page written for the person who decides
      // rather than the person who integrates.
      { name: 'the line for the buyer', css: 'p.docs-buyer', text: 'Evaluating Paramant?' },
      { name: 'the first button', css: '.docs-hero-actions a.docs-hero-btn', nth: 0, href: '#quickstart' },
      { name: 'the second button', css: '.docs-hero-actions a.docs-hero-btn', nth: 1, href: '/pricing' },
    ],
  },
  {
    slug: '/help',
    // Three questions, three answers, no scrolling. An answer whose last line
    // is cut off is a page that has not answered.
    claims: [
      { name: 'the first answer', css: '.buyer-qa-item p.buyer-qa-a', nth: 0, text: 'Signing a document needs an account' },
      { name: 'the second answer', css: '.buyer-qa-item p.buyer-qa-a', nth: 1, text: 'ParaSign Community is free' },
      // The third answer is where the page says the documents live in Germany,
      // which is the answer the buyer this page was rewritten for came to read.
      // It ended at 860 in DejaVu; the Q&A block, its heading and the space
      // between a question and its answer are tighter on a phone, which lifts it
      // to 822 with all three answers intact.
      { name: 'the third answer', css: '.buyer-qa-item p.buyer-qa-a', nth: 2, text: 'Hetzner Nuremberg', at: 822 },
    ],
  },
  {
    slug: '/download',
    claims: [
      { name: 'the status sentence', css: 'header.dl-lead h1', text: 'no longer maintained' },
      { name: 'the sentence under it', css: 'header.dl-lead p.dl-sub', text: 'The last build is from March 2026' },
      { name: 'the first button', css: '.dl-actions a.btn-primary', href: '/' },
      { name: 'the second button', css: '.dl-actions a.btn-outline', href: '/pricing' },
    ],
  },
];

for (const spec of PAGES) {
  test(`${spec.slug} carries its first screen inside 390x844`, async (t) => {
    const page = await open(spec.slug);
    const measured = await measure(page, spec.claims);
    const width = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
      innerWidth: window.innerWidth,
    }));
    await page.close();

    for (const [index, hit] of measured.entries()) {
      const claim = spec.claims[index];
      assert.ok(!hit.missing,
        `${spec.slug} has no ${hit.name}: ${hit.missing === 'phrase' ? `the text "${claim.phrase}" is not inside ${claim.css}` : `nothing matches ${claim.css}${claim.nth ? ` at index ${claim.nth}` : ''}`}`);
      if (claim.text) {
        assert.ok(hit.text.includes(claim.text),
          `${spec.slug}: ${hit.name} was expected to read "${claim.text}"; the element at ${claim.css} reads "${hit.text}". Fix the selector or the copy, do not loosen this.`);
      }
      if (claim.also) {
        for (const extra of claim.also) {
          assert.ok(hit.text.includes(extra),
            `${spec.slug}: ${hit.name} must also name "${extra}"; it reads "${hit.text}"`);
        }
      }
      if (claim.href) {
        assert.equal(hit.href, claim.href,
          `${spec.slug}: ${hit.name} points at ${hit.href}, not ${claim.href}`);
      }
      assert.ok(hit.bottom <= FOLD.height,
        `${spec.slug}: ${hit.name} ends at y=${hit.bottom}, ${hit.bottom - FOLD.height}px past the ${FOLD.height}px first screen (top y=${hit.top}, font ${hit.font})${claim.at ? `. It was measured at y=${claim.at} when the CSS that pulled it onto the screen was written, so it moved ${hit.bottom - claim.at}px down since` : ''}. A phone reader has to scroll for it.`);
      t.diagnostic(`${spec.slug} ${hit.name}: top ${hit.top}, bottom ${hit.bottom}${claim.at ? ` (was ${claim.at} when pulled onto the screen)` : ''}`);
    }

    // Equal to the viewport, not merely no wider than it: a page narrower than
    // the screen is the same layout bug seen from the other side.
    assert.equal(width.scrollWidth, width.clientWidth,
      `${spec.slug} scrolls sideways on a phone: scrollWidth ${width.scrollWidth} against clientWidth ${width.clientWidth}`);
    assert.equal(width.clientWidth, FOLD.width,
      `${spec.slug} lays out at ${width.clientWidth}px in a ${FOLD.width}px viewport (window.innerWidth ${width.innerWidth})`);
  });
}

test.after(async () => { await browser.close(); server.close(); });
