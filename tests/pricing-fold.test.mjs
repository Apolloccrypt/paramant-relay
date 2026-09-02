// What a phone actually sees on /pricing, measured on a laid-out page.
//
// Three things this file holds, all measured rather than read out of the
// markup, because all three were wrong on a page whose HTML read fine.
//
// 1. THE FOLD, BY POSITION. The design target is 390x844. An earlier version of
//    this test asked only whether an element intersected the viewport, which a
//    half-visible line at y=840 satisfies and a reader does not. Every claim
//    below is pinned by its bottom edge: the first amount, the line that says
//    who the page is for, the line that says who is behind it, and the first
//    action must be READABLE on the first screen, not clipped by it. The
//    founder line stood at 1128px on the branch this replaces, a screen and a
//    half down, on the page where a buyer decides whether to hand over client
//    files.
//
// 2. NO JARGON IN THE FOLD. "post-quantum signatures", "public proof log",
//    "relay", "API": none of them mean anything to the lawyer this page sells
//    to, and the same facts stand under the tables where they belong. The text
//    is collected from TEXT NODES, not from a list of block tags: the previous
//    version queried "main p, section p, h1, h2, h3" and so read straight past
//    the kicker <span> under the h1, which is the second thing on the page.
//
// 3. THE CARDS. Grid items default to min-width:auto, and design-system.css
//    sets white-space:nowrap on .btn. Together they let the longest CTA on the
//    page ("Get ParaSign Business -> ... incl.") set the min-content width of
//    the whole grid track. Measured on origin/main at 390px: the container was
//    342px wide and every tier card was 471px, so the right-hand third of each
//    card was clipped. The same defect pushed the entire ParaSign Enterprise
//    card off the right edge at 1280px. Nothing in the HTML shows this; only a
//    laid-out page does.
//
// Run: node --test tests/pricing-fold.test.mjs
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
const aliases = { '/pricing':'/pricing.html', '/signup':'/signup.html' };
const FOLD = { width: 390, height: 844 };

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

async function open(width, height, slug = 'pricing') {
  const page = await browser.newPage({ viewport: { width, height } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
  await page.goto(`${ORIGIN}/${slug}`, { waitUntil: 'networkidle' });
  return page;
}

// The bottom edge of the first element whose own text matches, in CSS pixels
// from the top of the document. Text nodes, not tags: the kicker under the h1
// is a span, and the amount in the promise sits inside a <strong>.
//
// A pattern may ask for the enclosing BLOCK instead of the element holding the
// matched text. The founder claim is the case that needs it: "Mick Beer" is a
// <strong> that ends at y=726, but the claim a reader has to be able to read is
// the whole line, title and KvK number included, and that ends 40px lower. An
// earlier version measured the <strong> and would have called the line visible
// with its registration clipped off the bottom of the screen.
const measure = (page, needles) => page.evaluate((patterns) => {
  const out = {};
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const text = n.nodeValue.replace(/\s+/g, ' ').trim();
    if (!text) continue;
    const el = n.parentElement;
    if (!el || ['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(el.tagName)) continue;
    const rect = el.getBoundingClientRect();
    if (!rect.height) continue;
    nodes.push({ text, el, top: rect.top + window.scrollY, bottom: rect.bottom + window.scrollY });
  }
  for (const [name, source, block] of patterns) {
    const rx = new RegExp(source);
    const hit = nodes.find((n) => rx.test(n.text));
    if (!hit) { out[name] = null; continue; }
    const el = block ? (hit.el.closest('p, li, h1, h2, h3, figcaption') || hit.el) : hit.el;
    const rect = el.getBoundingClientRect();
    out[name] = {
      top: Math.round(rect.top + window.scrollY),
      bottom: Math.round(rect.bottom + window.scrollY),
      // A block claim is reported whole enough to assert on: the founder line
      // runs past 100 characters before it reaches the registration number.
      text: (block ? el.textContent : hit.text).replace(/\s+/g, ' ').trim().slice(0, block ? 240 : 100),
    };
  }
  // Everything a reader can see without scrolling, for the jargon check.
  out.foldText = nodes
    .filter((n) => n.bottom <= window.innerHeight + 1 && n.top >= 0)
    .map((n) => n.text).join(' ');
  return out;
}, needles);

test('the first screen at 390px carries the amount, the audience, the founder and an action', async () => {
  const page = await open(FOLD.width, FOLD.height);
  const seen = await measure(page, [
    ['h1', '^Pricing$'],
    ['what', 'Sign documents and send files that vanish after one read'],
    ['amount', '€0 a month, forever'],
    ['limit', '2 signatures a month, 10 transfers a month, 5 MB per file'],
    // Both paid amounts, because they buy different products and a buyer who
    // only sees €15 has been told the price of the other one.
    ['sending', '€15 a month'],
    ['signing', '€49 a month'],
    ['audience', 'one-person practice, a volunteer board or a household'],
    // Whole line: the name, the title /about gives him, and the registration.
    ['founder', 'Mick Beer', true],
  ]);
  const cta = await page.evaluate(() => {
    // The hero's own action, not the nav's: the nav carries a /signup link on
    // every page and would make this check pass on a page with no CTA at all.
    const link = [...document.querySelectorAll('#main-content a[href="/signup"]')][0];
    if (!link) return null;
    const rect = link.getBoundingClientRect();
    return { top: Math.round(rect.top + window.scrollY), bottom: Math.round(rect.bottom + window.scrollY) };
  });
  await page.close();

  const required = { ...seen, cta };
  delete required.foldText;
  for (const [name, hit] of Object.entries(required)) {
    assert.ok(hit, `/pricing must carry the ${name} line; it is missing entirely`);
    assert.ok(hit.bottom <= FOLD.height,
      `the ${name} line ends at y=${hit.bottom}, past the ${FOLD.height}px first screen: a buyer has to scroll for it`);
  }
  // Order is the argument: what it does, then what it costs, then who it is
  // for, then who is behind it, and only then the button.
  assert.ok(seen.what.top < seen.amount.top, 'what the product does stands above what it costs');
  assert.ok(seen.amount.top <= seen.audience.top, 'the amount stands above the audience line');
  assert.ok(seen.audience.top < cta.top, 'the audience line stands above the first action');
  assert.match(seen.founder.text, /privacy and security researcher.*KvK 42115132/,
    'the measured founder line must be the whole claim, not just the name in bold');
});

test('the first screen at 390px spends no words on jargon', async () => {
  const page = await open(FOLD.width, FOLD.height);
  const { foldText } = await measure(page, []);
  await page.close();
  // Words with no meaning to the buyer this page sells to. Every one of them
  // still stands under the tables, where a reader has asked for detail.
  const JARGON = [
    /post-quantum signatures/i,
    /public proof log/i,
    /\bdedicated relay\b/i,
    /\bthe relay\b/i,
    /\ban API\b/,
    /\bML-DSA\b/i,
    /\bAES-256\b/i,
    /\bciphertext\b/i,
  ];
  const hits = JARGON.filter((rx) => rx.test(foldText)).map((rx) => String(rx));
  assert.deepEqual(hits, [], `the first screen at 390px reads: "${foldText}"\n  jargon found: ${hits.join(', ')}`);
});

test('pricing and signup use one term for what a free account gives', async () => {
  const pricing = await open(FOLD.width, FOLD.height);
  const signup = await open(FOLD.width, FOLD.height, 'signup');
  const text = async (page) => page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
  const [pricingText, signupText] = [await text(pricing), await text(signup)];
  await pricing.close();
  await signup.close();
  const TERM = '2 signatures a month';
  assert.ok(pricingText.includes(TERM), `/pricing must say "${TERM}"`);
  assert.ok(signupText.includes(TERM), `/signup must use the same words as /pricing: "${TERM}"`);
  for (const [label, body] of [['pricing', pricingText], ['signup', signupText]]) {
    assert.doesNotMatch(body, /\d+ documents a month/,
      `/${label} says "documents a month" where the rest of the site says "${TERM}"; one term, one product`);
  }
});

test('no tier card is wider than the grid that holds it', async () => {
  const widths = [320, 390, 768, 1024, 1280];
  const problems = [];
  for (const width of widths) {
    const page = await open(width, 900);
    const rows = await page.evaluate(() => [...document.querySelectorAll('.tier-grid')].map((grid) => ({
      grid: Math.round(grid.getBoundingClientRect().width),
      cards: [...grid.querySelectorAll('.tier-card')].map((card) => Math.round(card.getBoundingClientRect().width)),
      right: Math.max(...[...grid.querySelectorAll('.tier-card')].map((card) => Math.round(card.getBoundingClientRect().right))),
    })));
    await page.close();
    for (const row of rows) {
      // One card may be exactly as wide as a single-column grid; wider than the
      // grid means the page is cutting content off, in every layout.
      const tooWide = row.cards.filter((card) => card > row.grid);
      if (tooWide.length) problems.push(`${width}px: cards ${tooWide.join(', ')} in a ${row.grid}px grid`);
      if (row.right > width) problems.push(`${width}px: a card reaches ${row.right}px, past the ${width}px viewport`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test.after(async () => { await browser.close(); server.close(); });
