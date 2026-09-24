// Nothing sticks out, at any width and any browser zoom.
//
// Why this file exists. On 2026-09-24 a reader who zooms in and out of the
// browser found three faults on /auth/login in the dark edition, at about 933
// CSS pixels: the second of two side-by-side buttons ran out of the card, the
// e-mail field turned olive-yellow when the browser filled it in, and the
// "This page in English" line floated unstyled between the page and the legal
// strip. Every other layout gate here measures two sizes, 390 and 1440, and a
// zoomed desktop window is neither: it is a desktop layout squeezed into a
// width no phone and no monitor has.
//
// HOW BROWSER ZOOM IS EMULATED. Zooming a desktop browser to 150% does two
// things: the layout viewport shrinks to window width / 1.5 CSS pixels, and
// devicePixelRatio grows by 1.5. Media queries, grids and wrapping only see
// the first, so the faithful emulation is a context with deviceScaleFactor =
// zoom and a viewport of round(window / zoom) CSS pixels. That is what this
// suite does. CSS `zoom` on <html> was rejected: it rescales lengths inside an
// unchanged viewport, so media queries keep firing at the unzoomed width,
// which is exactly the case where the real fault hides. The effective width
// is floored at 320 CSS px, the WCAG 1.4.10 reflow floor; below that (a 320
// window at 200%) no browser window lives and no page is required to reflow.
//
// WHAT IS MEASURED, in light and dark, per page and per size:
//
//   scroll    the page scrolls sideways (window.scrollTo(big, y) moves scrollX)
//   escape    a visible a, button, input, select or textarea runs past its
//             nearest card or section, or past the viewport. An element inside
//             a sideways scroller (overflow-x auto/scroll) is in reach by
//             design and is not counted.
//   nav       two items of the top bar overlap, or a bar item's text spills
//             out of its own box.
//   autofill  the :-webkit-autofill rules, applied to each text field, must
//             paint the field in its own background colour (an inset box-shadow
//             over the browser's fill) and its own ink. Without such a rule the
//             browser paints its own colour, light blue or yellow, which on
//             the dark edition is a light slab with light text on it.
//
// SCOPE. Every page under frontend/, NL and /en, on 390, 933 and 1440 at zoom
// 1. The twelve pages a reader meets first, in both languages, on every width
// in WIDTHS at every zoom in ZOOMS. Left out: admin.html (its own app), the
// printable briefs under docs/, and three pages that redirect on load
// (iot, billing/checkout) or a few seconds later (request-key).
//
//   ROF_JSON=/tmp/rof.json node --test tests/responsive-overflow.test.mjs
// writes every finding to that file for a before-and-after count.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.env.PARAMANT_FRONTEND
  ? path.resolve(process.env.PARAMANT_FRONTEND)
  : path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const THEME_KEY = 'paramant.theme.v1';
const MIME = {
  '.js':'text/javascript', '.mjs':'text/javascript', '.css':'text/css', '.html':'text/html',
  '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg', '.webp':'image/webp',
  '.woff2':'font/woff2', '.json':'application/json', '.ico':'image/x-icon', '.wasm':'application/wasm',
};

const WIDTHS = [320, 390, 600, 768, 933, 1024, 1280, 1440, 1920];
const ZOOMS = [0.67, 1, 1.5, 2];
const BROAD_WIDTHS = [390, 933, 1440];
const THEMES = ['light', 'dark'];
const FLOOR = 320;
const WINDOW_HEIGHT = 900;

const SKIP = new Set([
  'admin.html', 'docs/paramant-ot-brief.html', 'en/docs/paramant-ot-brief.html',
  'iot.html', 'en/iot.html', 'billing/checkout.html', 'en/billing/checkout.html',
  'request-key.html', 'en/request-key.html',
]);
// Signed-in screens get the stubbed session the other app suites use, so they
// render their real furniture instead of a redirect to /auth/login.
const SIGNED_IN = new Set(['/dashboard', '/account', '/parashare', '/vault', '/developer',
  '/audit-log-export', '/redeem', '/claim', '/sign']);
const KEY_PAGES = ['/', '/pricing', '/parasend', '/parasign', '/sign', '/signup', '/auth/login',
  '/dashboard', '/account', '/parashare', '/security', '/help'];

function routeOf(rel) {
  let r = '/' + rel.replace(/\.html$/, '');
  r = r.replace(/\/index$/, '') || '/';
  return r === '/en' ? '/en/' : r;
}
function listPages(dir = ROOT, base = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes:true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (['vendor', 'pkg', 'node_modules', 'assets', 'images'].includes(entry.name)) continue;
      out.push(...listPages(path.join(dir, entry.name), rel));
    } else if (entry.name.endsWith('.html') && !SKIP.has(rel)) out.push(rel);
  }
  return out.sort();
}
const ALL = listPages().map(routeOf);
const baseRoute = (r) => r.replace(/^\/en(?=\/|$)/, '') || '/';

function serve() {
  return http.createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const tries = path.extname(pathname)
      ? [pathname]
      : [pathname.replace(/\/$/, '') + '.html', pathname.replace(/\/$/, '') + '/index.html'];
    const next = () => {
      const p = tries.shift();
      if (!p) { res.writeHead(404); return res.end(); }
      const file = path.join(ROOT, p);
      if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
      fs.readFile(file, (error, body) => {
        if (error) return next();
        res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
        res.end(body);
      });
    };
    next();
  });
}

const future = new Date(Date.now() + 30 * 86400000).toISOString();
const ME = {
  email:'demo@example.com', label:'Demo', plan:'community', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:future, usage_purpose:'organisation',
  api_key_masked:'pgp_****', sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};
const DOCS = { documents:[
  { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement 2026.pdf', status:'sent', created_at:'2026-08-21T10:00:00.000Z', party_count:3, signed_count:0 },
  { id:'env_complete_abcdefghijklmnop', original_filename:'Consultancy contract.pdf', status:'complete', created_at:'2026-08-19T10:00:00.000Z', party_count:2, signed_count:2 },
] };

// Playwright tries handlers newest-first, so the catch-alls go on first.
async function stub(page, signedIn) {
  const json = (body, status = 200) => (r) => r.fulfill({ status, contentType:'application/json', body: typeof body === 'string' ? body : JSON.stringify(body) });
  await page.route((url) => !/^https?:\/\/localhost(:\d+)?\//.test(url.href), (r) => r.abort());
  await page.route('**/api/**', json('{}'));
  await page.route('**/api/user/session/verify', json(signedIn ? { authenticated:true, email:'demo@example.com' } : { authenticated:false }, signedIn ? 200 : 401));
  if (!signedIn) return;
  await page.route('**/api/user/me', json(ME));
  await page.route('**/api/user/account', json(ME));
  await page.route('**/api/user/billing/status', json({ current_plan:'community', ...ME }));
  await page.route('**/api/user/billing/history', json({ history:[] }));
  await page.route('**/api/user/documents**', json(DOCS));
  await page.route('**/api/user/dashboard/overview', (r) => r.fulfill({ status:500, body:'' }));
  await page.route('**/api/user/account/**', json({ keys:[{ label:'Signing key' }], passkeys:[{ label:'Passkey' }] }));
}

// Runs in the page. Returns the findings for the current size and theme.
const PROBE = () => {
  const out = [];
  const W = document.documentElement.clientWidth;
  const label = (el) => {
    const t = (el.getAttribute('aria-label') || el.textContent || el.value || el.name || el.id || '').replace(/\s+/g, ' ').trim().slice(0, 40);
    const cls = typeof el.className === 'string' && el.className.trim() ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
    return `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${cls} "${t}"`;
  };
  const shown = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) return false;
      if (cs.clip && cs.clip !== 'auto') return false;
      if (cs.clipPath && cs.clipPath !== 'none') return false;
    }
    return true;
  };

  // scroll
  const x0 = window.scrollX, y0 = window.scrollY;
  window.scrollTo(100000, y0);
  if (window.scrollX > 1) out.push({ kind:'scroll', what:`page scrolls ${Math.round(window.scrollX)}px sideways` });
  window.scrollTo(x0, y0);

  // escape
  const CONTAINER = 'section, form, footer, header, nav, aside, dialog, main, article, [class*="card"], [class*="panel"], [class*="modal"]';
  for (const el of document.querySelectorAll('a[href], button, input:not([type="hidden"]), select, textarea')) {
    if (el.classList.contains('skip-link') || !shown(el)) continue;
    if (getComputedStyle(el).position === 'fixed') continue;
    const r = el.getBoundingClientRect();
    let scroller = false, box = null;
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
      const ox = getComputedStyle(n).overflowX;
      if ((ox === 'auto' || ox === 'scroll') && n.scrollWidth > n.clientWidth + 1) { scroller = true; break; }
      if (n.matches(CONTAINER)) { box = n; break; }
    }
    if (scroller) continue;
    if (r.right > W + 1 || r.left < -1) {
      out.push({ kind:'escape', what:`${label(el)} leaves the viewport (${Math.round(r.left)}..${Math.round(r.right)} of ${W})` });
      continue;
    }
    if (box) {
      const b = box.getBoundingClientRect();
      if (b.width > 2 && (r.right > b.right + 1 || r.left < b.left - 1)) {
        out.push({ kind:'escape', what:`${label(el)} runs out of ${label(box).split(' ')[0]} (${Math.round(r.left)}..${Math.round(r.right)} vs ${Math.round(b.left)}..${Math.round(b.right)})` });
      }
    }
  }

  // nav
  const nav = document.querySelector('nav.nav');
  if (nav && shown(nav)) {
    const items = [...nav.querySelectorAll('a, button')].filter(shown).filter((el) => !el.closest('.nav-mobile'));
    const boxes = items.map((el) => {
      const r = el.getBoundingClientRect();
      return { el, l:r.left, r:r.right, t:r.top, b:r.bottom };
    });
    for (let i = 0; i < boxes.length; i++) {
      const a = boxes[i];
      if (a.el.scrollWidth > a.el.clientWidth + 1 && getComputedStyle(a.el).overflowX === 'visible' && getComputedStyle(a.el).display !== 'inline') {
        out.push({ kind:'nav', what:`${label(a.el)} text spills out of its box` });
      }
      for (let j = i + 1; j < boxes.length; j++) {
        const b = boxes[j];
        if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
        const w = Math.min(a.r, b.r) - Math.max(a.l, b.l);
        const h = Math.min(a.b, b.b) - Math.max(a.t, b.t);
        if (w > 1 && h > 1) out.push({ kind:'nav', what:`${label(a.el)} overlaps ${label(b.el)}` });
      }
    }
  }

  // autofill
  const rules = [];
  const walk = (list, wrap) => {
    for (const rule of list) {
      if (rule.cssRules && !rule.selectorText) {
        const cond = rule.conditionText != null ? `@media ${rule.conditionText}` : null;
        walk(rule.cssRules, cond ? (s) => wrap(`${cond}{${s}}`) : wrap);
      } else if (rule.selectorText && /:(-webkit-)?autofill/.test(rule.selectorText)) {
        rules.push(wrap(rule.cssText.replace(/:-webkit-autofill|:autofill/g, '[data-rof-autofill]')));
      }
    }
  };
  for (const sheet of document.styleSheets) {
    try { walk(sheet.cssRules, (s) => s); } catch { /* cross-origin */ }
  }
  const parse = (s) => { const m = String(s).match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number); return { r:p[0], g:p[1], b:p[2], a:p.length > 3 ? p[3] : 1 }; };
  const near = (x, y) => x && y && Math.abs(x.r - y.r) <= 10 && Math.abs(x.g - y.g) <= 10 && Math.abs(x.b - y.b) <= 10;
  const fields = [...document.querySelectorAll('input:not([type]), input[type="text"], input[type="email"], input[type="password"], input[type="tel"], input[type="search"], input[type="url"], input[type="number"], textarea')].filter(shown).slice(0, 4);
  if (fields.length) {
    // What the browser does to a filled field, with !important as it does it
    // in its own stylesheet: its colour for the ground and its own text colour.
    // The page's rules are then applied on top, so what is measured is what
    // wins in a real autofill.
    const style = document.createElement('style');
    style.textContent = '[data-rof-autofill]{background-color:rgb(250,255,189)!important;color:rgb(0,0,0)!important}\n' + rules.join('\n');
    document.head.appendChild(style);
    for (const f of fields) {
      const before = getComputedStyle(f);
      const ground = parse(before.backgroundColor);
      const ink = parse(before.color);
      f.setAttribute('data-rof-autofill', '');
      const cs = getComputedStyle(f);
      const shadow = cs.boxShadow || '';
      const inset = shadow.split(/,(?![^(]*\))/).find((s) => /inset/.test(s) && /\b(\d{3,})px/.test(s));
      const paint = inset ? parse(inset) : null;
      const fill = parse(cs.webkitTextFillColor && !/currentcolor/i.test(cs.webkitTextFillColor) ? cs.webkitTextFillColor : cs.color);
      f.removeAttribute('data-rof-autofill');
      if (!paint) out.push({ kind:'autofill', what:`${label(f)} has no inset fill over the browser's autofill colour` });
      else if (ground && ground.a > 0 && !near(paint, ground)) out.push({ kind:'autofill', what:`${label(f)} autofill paints ${inset.trim()} over a ${before.backgroundColor} field` });
      else if (ink && !near(fill, ink)) out.push({ kind:'autofill', what:`${label(f)} autofill ink ${cs.webkitTextFillColor} is not the field ink ${before.color}` });
    }
    style.remove();
  }
  return out;
};

function sizesFor(route) {
  const key = KEY_PAGES.includes(baseRoute(route));
  if (!key) return [{ zoom:1, widths:BROAD_WIDTHS }];
  return ZOOMS.map((zoom) => ({ zoom, widths:[...new Set(WIDTHS.map((w) => Math.max(FLOOR, Math.round(w / zoom))))] }));
}

const server = serve();
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

const jobs = [];
for (const route of ALL) for (const { zoom, widths } of sizesFor(route)) jobs.push({ route, zoom, widths });

async function run(job) {
  const { route, zoom, widths } = job;
  const context = await browser.newContext({
    viewport:{ width:widths[0], height:Math.round(WINDOW_HEIGHT / zoom) },
    deviceScaleFactor:zoom, reducedMotion:'reduce',
  });
  await context.addInitScript((k) => { try { localStorage.setItem(k, 'light'); } catch {} }, THEME_KEY);
  const page = await context.newPage();
  const found = [];
  try {
    await stub(page, SIGNED_IN.has(baseRoute(route)));
    await page.goto(ORIGIN + route, { waitUntil:'load', timeout:20000 });
    await page.waitForTimeout(300);
    for (const theme of THEMES) {
      await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);
      for (const width of widths) {
        await page.setViewportSize({ width, height:Math.round(WINDOW_HEIGHT / zoom) });
        await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
        // A fault counts when it is still there after the page has had time
        // to settle: resize handlers and fonts can land a frame late, and a
        // one-frame glimpse of a half-laid-out bar is not what a reader sees.
        let rows = await page.evaluate(PROBE);
        if (rows.length) { await page.waitForTimeout(150); rows = await page.evaluate(PROBE); }
        for (const f of rows) found.push({ route, theme, zoom, width, ...f });
      }
    }
  } catch (error) {
    found.push({ route, zoom, kind:'load', what:String(error.message).split('\n')[0] });
  } finally {
    await context.close();
  }
  return found;
}

const findings = [];
const POOL = Number(process.env.ROF_POOL || 6);
let cursor = 0;
await Promise.all(Array.from({ length:POOL }, async () => {
  while (cursor < jobs.length) findings.push(...await run(jobs[cursor++]));
}));
await browser.close();
server.close();

if (process.env.ROF_JSON) fs.writeFileSync(process.env.ROF_JSON, JSON.stringify(findings, null, 1));

// One line per distinct fault, with the sizes it shows at, so a report reads
// as a list of things to fix rather than a thousand rows of the same button.
function summary(kind) {
  const rows = findings.filter((f) => f.kind === kind);
  const byWhat = new Map();
  for (const f of rows) {
    const what = f.what.replace(/\(.*\)$/, '').trim();
    const k = `${f.route}  ${what}`;
    if (!byWhat.has(k)) byWhat.set(k, new Set());
    byWhat.get(k).add(`${f.theme ?? ''}@${f.width ?? ''}x${f.zoom}`);
  }
  return [...byWhat].map(([k, at]) => `${k}  [${[...at].slice(0, 4).join(' ')}${at.size > 4 ? ` +${at.size - 4}` : ''}]`);
}

test(`coverage: ${ALL.length} pages, ${jobs.length} page loads, ${KEY_PAGES.length * 2} pages at every width and zoom`, () => {
  assert.ok(ALL.length > 100, `only ${ALL.length} pages found under ${ROOT}`);
  assert.ok(ALL.includes('/auth/login') && ALL.includes('/en/auth/login'));
  assert.deepEqual(summary('load'), [], 'pages that did not load');
});

test('no page scrolls sideways', () => {
  assert.deepEqual(summary('scroll'), []);
});

test('no visible control runs out of its card, its section or the viewport', () => {
  assert.deepEqual(summary('escape'), []);
});

test('the items of the top bar never overlap', () => {
  assert.deepEqual(summary('nav'), []);
});

test('autofill keeps the field its own colour in light and dark', () => {
  assert.deepEqual(summary('autofill'), []);
});
