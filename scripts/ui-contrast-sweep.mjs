// The non-text sweep. What tests/theme-contrast.test.mjs cannot see.
//
// Why this file exists. The contrast gate we already had walks TEXT nodes: it
// takes a text colour, flattens it onto the first opaque background above it,
// and scores the pair. That gate is green. It was green on the day a phone
// review found icons, rules and chips that had simply vanished, because none
// of what vanished was text. design-system.css v5 moved the whole site onto a
// warm dark ground; every colour that came from a token followed. Every colour
// that was written as a hex in a page, a script or an SVG did not. A navy
// stroke that read fine on bone is invisible on #15191C, and no test that only
// looks at text will ever say so.
//
// WCAG 2.1 SC 1.4.11 Non-text Contrast asks 3:1 for the visual information
// needed to identify user interface components and states, and for the parts
// of a graphic that carry its meaning. That is the bar used here.
//
// WHAT IS MEASURED, and why each one is in the list:
//
//   svg      Every leaf shape (path, rect, circle, ellipse, line, polyline,
//            polygon, use) and its fill AND its stroke, separately. An icon is
//            a graphic whose meaning is its shape, so it is held to 3:1 in
//            both directions of the theme.
//   img      Raster and <img>-loaded SVG cannot be read from the cascade, so
//            the image is drawn to a canvas and its mean colour over the
//            non-transparent pixels is scored against the ground behind it.
//            This is the check that catches a dark logo on a dark page, which
//            no style rule would ever reveal.
//   pseudo   ::before and ::after with a real content string. Checkmarks,
//            chevrons, bullets and rule glyphs are drawn this way and they are
//            not in the DOM's text, so the text gate steps straight over them.
//   fill     An element with an opaque-ish background (alpha >= .5) and no
//            text of its own: a badge, a pill, a dot, a swatch, a progress
//            bar. A solid mark is deliberate, so it is held to 3:1.
//   line     Borders, outlines and <hr>. These are held to 3:1 ONLY when they
//            run against the grain of the theme, and that needs a word.
//
// THE GRAIN RULE, for lines and washes. A deliberate hairline on a dark ground
// is LIGHTER than the ground; on cream paper it is DARKER. It sits on the same
// side of its background as the page's own ink does. That is what a divider
// is: a whisper in the direction of the writing. A line that sits on the WRONG
// side of its background is not a whisper, it is a leftover from another
// theme: navy on night, bone on paper. So a line under 3:1 that runs with the
// grain is reported as decorative and not gated, and a line under 3:1 that
// runs against it is a finding. This is the exact shape of the bug this sweep
// was written for and it keeps the gate free of the hundreds of intentional
// 16%-cream hairlines the design system paints on every card.
//
// Reused by tests/ui-elements-contrast.test.mjs, which turns the result into a
// gate with a known-defects list. Run it by hand for the report and the
// screenshots:
//
//   node scripts/ui-contrast-sweep.mjs                     report only
//   node scripts/ui-contrast-sweep.mjs --shots /some/dir   report + screenshots
//   node scripts/ui-contrast-sweep.mjs --json out.json     report + raw rows
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// The tree to serve. Overridable so the same sweep can be pointed at a clean
// checkout and give a before-and-after that differs only in the code.
export const ROOT = process.env.PARAMANT_FRONTEND
  ? path.resolve(process.env.PARAMANT_FRONTEND)
  : path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = {
  '.js':'text/javascript', '.mjs':'text/javascript', '.css':'text/css', '.html':'text/html',
  '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
  '.webp':'image/webp', '.gif':'image/gif', '.woff2':'font/woff2', '.json':'application/json',
  '.ico':'image/x-icon', '.txt':'text/plain', '.wasm':'application/wasm',
};

// The routes nginx serves. The first sixteen are the public list of
// tests/theme-contrast.test.mjs, unchanged, so both gates walk the same site.
// The three after it are the pages that carry the drawn work: the architecture
// diagrams, the agility table and the co-sign explainer. They were not in the
// text gate because they have no colour of their own to give text; they are in
// this one because almost everything on them is a graphic.
const ALIAS = {
  '/':'/index.html', '/pricing':'/pricing.html', '/dashboard':'/dashboard.html',
  '/parasign':'/parasign.html', '/parasend':'/parasend.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/account':'/account.html',
  '/security':'/security.html', '/trust':'/trust.html', '/docs':'/docs.html',
  '/about':'/about.html', '/help':'/help/index.html', '/download':'/download.html',
  '/login':'/auth/login.html', '/verify':'/verify.html',
  '/gereedschap':'/gereedschap.html',
  '/architecture':'/architecture.html', '/crypto-agility':'/crypto-agility.html',
  '/co-sign':'/co-sign.html',
  '/developer':'/developer.html',
  '/signup/verified':'/signup/verified.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html',
  '/auth/backup':'/auth/backup.html', '/auth/request-reset':'/auth/request-reset.html',
  '/auth/reset-confirm':'/auth/reset-confirm.html',
};

export const PUBLIC_PAGES = [
  '/', '/pricing', '/parasign', '/parasend', '/sign', '/signup', '/security',
  '/trust', '/docs', '/about', '/help', '/download', '/login', '/verify',
  '/architecture', '/crypto-agility', '/co-sign', '/developer', '/gereedschap',
];

// The signed-in screens, with the same stubs as tests/navigation-shell.test.mjs
// and tests/app-contrast.test.mjs so the app renders its real furniture.
export const APP_PAGES = [
  { slug:'/dashboard', ready:'#dh-root:not([hidden]) .dh-document' },
  { slug:'/account',   ready:'#state-account:not(.hidden)' },
  { slug:'/parashare', ready:'main' },
  { slug:'/sign',      ready:'main' },
  { slug:'/signup',    ready:'main' },
  { slug:'/signup/verified', ready:'main', signedIn:false },
  { slug:'/auth/login', ready:'form' },
  { slug:'/auth/setup', ready:'main' },
  { slug:'/auth/backup', ready:'main' },
  { slug:'/auth/request-reset', ready:'main' },
  { slug:'/auth/reset-confirm', ready:'main' },
];

export const SIZES = [[390, 844], [1440, 900]];
export const THEMES = ['dark', 'light'];
const THEME_KEY = 'paramant.theme.v1';

const future = new Date(Date.now() + 30 * 86400000).toISOString();
const ME = {
  email:'demo@example.com', label:'Demo', plan:'community', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:future, usage_purpose:'organisation',
  api_key_masked:'pgp_****', sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};
const DOCS = { documents:[
  { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement 2026.pdf', status:'sent', created_at:'2026-08-21T10:00:00.000Z', party_count:3, signed_count:0 },
  { id:'env_progress_abcdefghijklmnop', original_filename:'Service order.pdf', status:'sent', created_at:'2026-08-20T10:00:00.000Z', party_count:4, signed_count:2 },
  { id:'env_complete_abcdefghijklmnop', original_filename:'Consultancy contract.pdf', status:'complete', created_at:'2026-08-19T10:00:00.000Z', party_count:2, signed_count:2 },
  { id:'env_void_abcdefghijklmnop', original_filename:'Draft NDA.pdf', status:'void', created_at:'2026-08-18T10:00:00.000Z', party_count:1, signed_count:0 },
] };

// Playwright tries handlers newest-first, so the catch-all goes on FIRST.
async function stubSignedIn(page, signedIn) {
  await page.route('**/api/user/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json',
    body: signedIn ? '{"authenticated":true,"email":"demo@example.com"}' : '{"authenticated":false}' }));
  await page.route('**/api/user/me', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/account', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/billing/status', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ current_plan:'community', ...ME }) }));
  await page.route('**/api/user/billing/history', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"history":[]}' }));
  await page.route('**/api/user/documents**', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(DOCS) }));
  await page.route('**/api/user/dashboard/overview', (r) => r.fulfill({ status:500, body:'' }));
  await page.route('**/api/user/account/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"keys":[{"label":"Signing key"}],"passkeys":[{"label":"Passkey"}]}' }));
}

export function serve() {
  const server = http.createServer((req, res) => {
    let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    pathname = ALIAS[pathname] || pathname;
    const file = path.join(ROOT, pathname);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (error, body) => {
      if (error) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return server;
}

// ── the probe ────────────────────────────────────────────────────────────────
// Runs inside the page. Returns every non-text thing it can see, with the
// colour it is painted in, the ground it sits on and the ratio between them.
const PROBE = async () => {
  const parse = (value) => {
    const s = String(value || '');
    const m = s.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    if (parts.length < 3 || parts.some(Number.isNaN)) return null;
    return { r:parts[0], g:parts[1], b:parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const over = (top, bottom) => ({
    r: top.r * top.a + bottom.r * (1 - top.a),
    g: top.g * top.a + bottom.g * (1 - top.a),
    b: top.b * top.a + bottom.b * (1 - top.a),
    a: 1,
  });
  const lum = (c) => {
    const f = (v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const hex = (c) => '#' + [c.r, c.g, c.b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('');

  // The ground under an element: every background above it composited down to
  // the first opaque one, exactly as the browser paints it.
  const groundOf = (node, { skipSelf = false } = {}) => {
    const stack = [];
    for (let el = skipSelf ? node.parentElement : node; el; el = el.parentElement) {
      const bg = parse(getComputedStyle(el).backgroundColor);
      if (bg && bg.a > 0) { stack.push(bg); if (bg.a >= 1) break; }
    }
    const html = parse(getComputedStyle(document.documentElement).backgroundColor);
    let base = html && html.a >= 1 ? html : { r:255, g:255, b:255, a:1 };
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };

  const visible = (el) => {
    if (typeof el.checkVisibility === 'function'
        && !el.checkVisibility({ checkOpacity:true, checkVisibilityCSS:true })) return false;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) return false;
    // aria-hidden is deliberately NOT a reason to skip. Nearly every icon on
    // this site is aria-hidden, because its meaning is carried by the label
    // next to it, and an icon nobody can see is still an icon nobody can see.
    // The first version of this probe skipped them and found four pages'
    // worth of nothing while the homepage skyline went unmeasured.
    if (el.closest('[hidden], template, script, style, noscript')) return false;
    const box = el.getBoundingClientRect();
    return box.width >= 1 && box.height >= 1;
  };

  const where = (el) => {
    const tag = el.tagName.toLowerCase();
    const id = el.id ? '#' + el.id : '';
    const cls = (typeof el.className === 'string' && el.className.trim())
      ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.')
      : (el.className && el.className.baseVal ? '.' + String(el.className.baseVal).trim().split(/\s+/).slice(0, 2).join('.') : '');
    // A bare <path> says nothing; the box it lives in says where to look.
    const host = el.closest('svg') ? (el.closest('svg').parentElement || el) : el;
    const hostBit = host !== el
      ? ' in ' + host.tagName.toLowerCase() + (host.id ? '#' + host.id : '')
        + (typeof host.className === 'string' && host.className.trim() ? '.' + host.className.trim().split(/\s+/)[0] : '')
      : '';
    return tag + id + cls + hostBit;
  };

  // Which way the ink leans off its ground, HERE, at this element. A hairline
  // that leans the same way as the text beside it is the system whispering;
  // one that leans the other way is a colour from a theme this page no longer
  // wears. Measured locally and not once for the page, because the night has
  // one inverted surface in it: a cream paper panel on a dark page reads its
  // ink downwards while everything around it reads upwards, and a page-wide
  // grain would call every correct border on that panel a defect.
  const grainAt = (el, ground) => {
    const ink = parse(getComputedStyle(el.closest ? (el.closest('*') || el) : el).color);
    if (!ink) return 1;
    return Math.sign(lum(over(ink, ground)) - lum(ground)) || 1;
  };
  const pageGround = groundOf(document.body);

  const rows = [];
  const add = (kind, el, colour, ground, extra = {}) => {
    if (!colour || colour.a <= 0.02) return;
    const flat = over(colour, ground);
    const r = ratio(flat, ground);
    const leans = Math.sign(lum(flat) - lum(ground)) || 0;
    rows.push({
      kind, sel: where(el), ratio: Math.round(r * 100) / 100,
      colour: hex(flat), raw: `rgba(${[colour.r, colour.g, colour.b].map(Math.round).join(',')},${colour.a})`,
      ground: hex(ground), againstGrain: leans !== 0 && leans !== grainAt(el, ground),
      ...extra,
    });
  };

  const SHAPES = 'path, rect, circle, ellipse, line, polyline, polygon, use, text, tspan';
  const own = (el) => Array.from(el.childNodes).some((n) => n.nodeType === 3 && n.nodeValue.trim());

  // 1. SVG shapes, fill and stroke apart.
  for (const el of document.querySelectorAll('svg')) {
    if (!visible(el)) continue;
    // A drawing that declares itself decorative is exempt from 1.4.11, and it
    // has to be: the homepage skyline is cream clouds on a cream sky, which is
    // what a drawing looks like, not what a broken icon looks like. The claim
    // has to be made in the markup, on the svg itself, where a reviewer can
    // see it. An icon in an aria-hidden WRAPPER is not covered by this: its
    // svg says nothing, so it is held to the bar like any other icon.
    const role = (el.getAttribute('role') || '').toLowerCase();
    const art = role === 'presentation' || role === 'none' || el.getAttribute('aria-hidden') === 'true';
    const shapes = el.querySelectorAll(SHAPES);
    const targets = shapes.length ? shapes : [el];
    const svgGround = groundOf(el, { skipSelf:true });
    // A drawing stacks. The label inside a filled box does not sit on the page,
    // it sits on the box, and scoring it against the page is how a sweep
    // reports a perfectly readable diagram as broken. So the shapes are walked
    // in paint order and every opaque area fill is remembered with its
    // rectangle; whatever is drawn inside that rectangle afterwards is scored
    // against it. A shape that ends up holding something is a PANEL, which is
    // a ground and not a mark, and a shape that holds nothing is a mark.
    const painted = [];
    const rowsFor = [];
    const holds = (outer, inner) => inner.left >= outer.left - 1 && inner.right <= outer.right + 1
      && inner.top >= outer.top - 1 && inner.bottom <= outer.bottom + 1;
    for (const shape of targets) {
      const cs = getComputedStyle(shape);
      const box = shape.getBoundingClientRect ? shape.getBoundingClientRect() : null;
      if (!box || (box.width < 1 && box.height < 1)) continue;
      if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) continue;
      // A shape inside <defs>, <clipPath> or <mask> is never painted.
      if (shape.closest('defs, clipPath, mask, symbol')) continue;
      let ground = svgGround;
      let under = null;
      for (let i = painted.length - 1; i >= 0; i--) {
        if (holds(painted[i].box, box)) { ground = painted[i].colour; under = painted[i]; break; }
      }
      if (under) under.holding = true;
      const fillOpacity = Number(cs.fillOpacity === '' ? 1 : cs.fillOpacity);
      const strokeOpacity = Number(cs.strokeOpacity === '' ? 1 : cs.strokeOpacity);
      // <line> and <polyline> have no interior: a fill on them paints nothing.
      const fillable = !['line', 'polyline'].includes(shape.tagName.toLowerCase());
      let entry = null;
      if (fillable && cs.fill && cs.fill !== 'none' && !cs.fill.startsWith('url')) {
        const c = parse(cs.fill);
        if (c && fillOpacity > 0) {
          const colour = { ...c, a: c.a * fillOpacity };
          entry = { box, colour: over(colour, ground), holding:false, shape, ground };
          if (colour.a >= 0.95) painted.push(entry);
          rowsFor.push({ entry, kind:'fill', shape, colour, ground });
        }
      }
      if (cs.stroke && cs.stroke !== 'none' && !cs.stroke.startsWith('url') && parseFloat(cs.strokeWidth) > 0) {
        const c = parse(cs.stroke);
        if (c && strokeOpacity > 0) rowsFor.push({ entry:null, kind:'stroke', shape, colour:{ ...c, a: c.a * strokeOpacity }, ground });
      }
    }
    for (const row of rowsFor) {
      const panel = row.kind === 'fill' && row.entry && row.entry.holding;
      const kind = (art || panel ? 'art-' : 'svg-') + row.kind;
      add(kind, row.shape, row.colour, row.ground, panel ? { panel:true } : {});
    }
  }

  // 2. Images. Drawn to a canvas and averaged over what is actually opaque,
  //    because there is no other way to know whether a logo is dark.
  for (const el of document.querySelectorAll('img')) {
    if (!visible(el)) continue;
    const ground = groundOf(el, { skipSelf:true });
    let mean = null;
    try {
      // A lazy image inside a panel that never opens never loads, and decode()
      // on it never settles. It also paints nothing, so it is not a defect:
      // wait a beat, then move on. This one line is why the sweep used to hang
      // forever on the app's /parashare.
      if (!el.complete) {
        await Promise.race([el.decode().catch(() => {}), new Promise((r) => setTimeout(r, 750))]);
      }
      if (!el.complete || !el.naturalWidth) continue;
      const w = Math.min(64, Math.max(1, el.naturalWidth || Math.round(el.getBoundingClientRect().width)));
      const h = Math.min(64, Math.max(1, el.naturalHeight || Math.round(el.getBoundingClientRect().height)));
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d', { willReadFrequently:true });
      ctx.drawImage(el, 0, 0, w, h);
      const data = ctx.getImageData(0, 0, w, h).data;
      let r = 0, g = 0, b = 0, n = 0;
      for (let i = 0; i < data.length; i += 4) {
        if (data[i + 3] < 24) continue;
        const a = data[i + 3] / 255;
        r += data[i] * a; g += data[i + 1] * a; b += data[i + 2] * a; n += a;
      }
      if (n > 0) mean = { r: r / n, g: g / n, b: b / n, a: Math.min(1, n / (w * h) + 0.0) };
    } catch { mean = null; }
    if (!mean) { rows.push({ kind:'img-unreadable', sel: where(el), ratio: null, src: el.getAttribute('src') }); continue; }
    add('img', el, { ...mean, a:1 }, ground, { src: el.getAttribute('src'), coverage: Math.round(mean.a * 100) / 100 });
  }

  // 3. Pseudo-elements that draw a glyph, and the ones that draw a block.
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el)) continue;
    for (const pseudo of ['::before', '::after']) {
      const cs = getComputedStyle(el, pseudo);
      if (!cs || cs.content === 'none' || cs.content === 'normal') continue;
      if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) continue;
      const ground = groundOf(el);
      const hasGlyph = /^"/.test(cs.content) && cs.content.replace(/^"|"$/g, '').trim() !== '';
      if (hasGlyph) add('pseudo-glyph', el, parse(cs.color), ground, { at: pseudo, content: cs.content.slice(0, 16) });
      const bg = parse(cs.backgroundColor);
      const w = parseFloat(cs.width), h = parseFloat(cs.height);
      if (bg && bg.a >= 0.5 && (w > 0 || h > 0)) add('pseudo-fill', el, bg, ground, { at: pseudo });
    }
  }

  // 4. Solid marks with no text of their own: badges, pills, dots, bars.
  //    And 5. lines: borders, outlines, <hr>.
  //
  //    A mark is a shape that carries meaning on its own. A card, a nav bar, a
  //    hero band and a form field all have a background too, and none of them
  //    is a mark: the card is a surface its text sits on, and a form field is
  //    identified by its border and its label, not by its filling. So the fill
  //    rule asks for three things at once: nothing anywhere inside it reads as
  //    text, it is not a form control, and it is small enough to be an object
  //    rather than a ground. Without the first of those this sweep reported
  //    every nav and every card on the site as a defect, which is how you get
  //    a gate nobody trusts.
  const MARK_AREA = 40000;
  const CONTROL = new Set(['INPUT', 'SELECT', 'TEXTAREA', 'BUTTON', 'PROGRESS', 'METER']);
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('svg')) continue;
    if (!visible(el)) continue;
    const cs = getComputedStyle(el);
    const ground = groundOf(el, { skipSelf:true });
    const bg = parse(cs.backgroundColor);
    const box = el.getBoundingClientRect();
    const isMark = !el.textContent.trim() && !CONTROL.has(el.tagName) && box.width * box.height <= MARK_AREA;
    if (bg && bg.a > 0 && !own(el)) {
      add(isMark && bg.a >= 0.5 ? 'fill' : 'wash', el, bg, ground);
    }
    for (const side of ['Top', 'Right', 'Bottom', 'Left']) {
      const width = parseFloat(cs[`border${side}Width`]);
      const style = cs[`border${side}Style`];
      if (!(width > 0) || style === 'none' || style === 'hidden') continue;
      const c = parse(cs[`border${side}Color`]);
      if (!c || c.a <= 0.02) continue;
      // One row per distinct border colour on an element, not four.
      add('line', el, c, bg && bg.a >= 1 ? bg : ground, { side });
      break;
    }
    if (parseFloat(cs.outlineWidth) > 0 && cs.outlineStyle !== 'none') {
      add('line', el, parse(cs.outlineColor), ground, { side:'outline' });
    }
  }

  return { ground: hex(pageGround), rows };
};

// The static server and the browser are opened here and closed in the finally,
// and that is the whole point of splitting this from measure() below.
//
// It used to open both at the top of one long function and close them at the
// bottom, on the happy path only. On 2026-09-04 that took the "Root integration
// suites (no browser)" job on main from a 20-minute run to a job that never
// ended: tests/ui-elements-contrast.test.mjs had landed in that job (see
// scripts/browser-suites.mjs for why), the job installs no Chromium, so
// chromium.launch() rejected. The rejection is the correct outcome and would
// have been a red test in seconds, except the listening http server was already
// up and nothing closed it. `node --test` waits for the event loop to drain, an
// open listener never drains, and the child process sat there with the failure
// it had already decided on. Three runs on main and one pull request hung on
// exactly that.
//
// So: anything that opens a handle in here is closed on the way out, whichever
// way out it is.
export async function sweep(options = {}) {
  const server = serve();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser = null;
  try {
    browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
    return await measure(server, browser, options);
  } finally {
    if (browser) await browser.close().catch(() => { /* closing over a crash */ });
    // A keep-alive socket the browser left behind holds the process open long
    // after the last page is measured. Node 18 gave us the hammer for that.
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close();
  }
}

async function measure(server, browser, { shotDir = null, pages = PUBLIC_PAGES, appPages = APP_PAGES, themes = THEMES, sizes = SIZES, keepAll = false } = {}) {
  const origin = `http://localhost:${server.address().port}`;
  const findings = [];
  const decorative = [];
  const everything = [];
  let measured = 0;
  if (shotDir) fs.mkdirSync(shotDir, { recursive:true });

  const visit = async (name, slug, theme, width, height, opts) => {
    const context = await browser.newContext({ viewport:{ width, height }, colorScheme: theme });
    if (opts.app) {
      await context.addInitScript(([key, value]) => {
        try { window.localStorage.setItem(key, value); } catch { /* storage off */ }
      }, [THEME_KEY, theme]);
    }
    const page = await context.newPage();
    if (opts.app) await stubSignedIn(page, opts.signedIn !== false);
    else await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
    await page.goto(origin + slug, { waitUntil:'domcontentloaded' });
    if (opts.ready) { try { await page.locator(opts.ready).first().waitFor({ timeout:6000 }); } catch { /* audit what rendered */ } }
    // A transition still running yields a colour that was never the intent.
    await page.addStyleTag({ content: '*,*::before,*::after{transition:none !important;animation:none !important}' });
    // A lazy image below the fold has no pixels to average, so it has to be
    // fetched before the probe can say anything about it. The obvious way is
    // to scroll the page to the bottom and back, and that is what this did
    // first: it also woke the WebGL globe on the app's /parashare, which in a
    // headless renderer with no GPU under it never gave the main thread back
    // and hung the whole sweep. Asking for the images directly costs nothing
    // and wakes nothing. An image inside a closed panel is not fetched by
    // this and does not need to be: it is not on screen either.
    await page.evaluate(async () => {
      for (const img of document.images) if (img.loading === 'lazy') img.loading = 'eager';
      await Promise.all(Array.from(document.images).map((i) => (i.complete ? null
        : Promise.race([i.decode().catch(() => {}), new Promise((r) => setTimeout(r, 750))]))));
    });
    await page.waitForTimeout(400);
    const result = await page.evaluate(PROBE);
    measured += result.rows.length;
    if (process.env.PARAMANT_SWEEP_PROGRESS) process.stderr.write(`  ${name} ${theme} ${width}: ${result.rows.length}\n`);
    for (const row of result.rows) {
      const at = { page:name, theme, width, ...row };
      if (keepAll) everything.push(at);
      if (row.ratio === null) { findings.push({ ...at, ratio:0, why:'image could not be read' }); continue; }
      if (row.ratio >= 3 - 0.005) continue;
      // What is held to 3:1 and what is only written down.
      //   gated      icons, images, CSS glyphs and solid marks, always; and a
      //              line that runs against the grain, which is the leftover
      //              from the light theme this sweep exists to find.
      //   written    a wash is a ground and not a mark, so a footer cut a
      //              shade deeper than the page is not a defect; a line with
      //              the grain is the system's own hairline; and a shape
      //              inside a graphic the markup calls decorative is a tone in
      //              a drawing.
      const GROUND = row.kind === 'wash' || row.kind.startsWith('art-');
      const gated = GROUND ? false : (row.kind === 'line' ? row.againstGrain : true);
      (gated ? findings : decorative).push(at);
    }
    if (shotDir) {
      const file = path.join(shotDir, `${name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'home'}--${theme}--${width}.png`);
      try { await page.screenshot({ path:file, fullPage:true, timeout:60000, animations:'disabled' }); } catch { /* a shot is never a gate */ }
    }
    await context.close();
  };

  // One page must not be able to take the sweep down with it. The app's
  // /parashare boots a WebGL globe, and a headless renderer that runs out of
  // room under it takes the whole context with it: the run either hangs on a
  // dead target or throws. So every visit is capped and caught, and a visit
  // that does not come back is written down as unmeasured instead of silently
  // becoming a clean page.
  const unmeasured = [];
  const guarded = async (name, ...rest) => {
    let timer;
    try {
      await Promise.race([
        visit(name, ...rest),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timed out after 90s')), 90000); }),
      ]);
    } catch (error) {
      unmeasured.push(`${name} ${rest[1]} ${rest[2]}: ${String(error.message || error).split('\n')[0]}`);
    } finally {
      clearTimeout(timer);
    }
  };
  for (const slug of pages) {
    for (const theme of themes) for (const [w, h] of sizes) await guarded(slug, slug, theme, w, h, { app:false });
  }
  for (const screen of appPages) {
    for (const theme of themes) for (const [w, h] of sizes) {
      await guarded('app ' + screen.slug, screen.slug, theme, w, h, { app:true, ready:screen.ready, signedIn:screen.signedIn });
    }
  }
  // One row per place and colour pair; 390 and 1440 see the same defect twice.
  const key = (r) => `${r.page}|${r.theme}|${r.kind}|${r.sel}|${r.colour}|${r.ground}`;
  const uniq = (list) => [...new Map(list.map((r) => [key(r), r])).values()];
  return { measured, unmeasured, findings: uniq(findings), decorative: uniq(decorative), all: keepAll ? everything : [] };
}

export const line = (r) => `${r.page} [${r.theme}] ${r.kind} ${r.sel}: ${r.ratio}:1 ${r.colour} on ${r.ground}${r.src ? ' <' + r.src + '>' : ''}${r.at ? ' ' + r.at : ''}`;

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const shotAt = process.argv.indexOf('--shots');
  const jsonAt = process.argv.indexOf('--json');
  const result = await sweep({ shotDir: shotAt > -1 ? process.argv[shotAt + 1] : null });
  console.log(`measured ${result.measured} non-text paints`);
  for (const one of result.unmeasured) console.log(`  NOT MEASURED: ${one}`);
  console.log(`under 3:1 and gated: ${result.findings.length}`);
  for (const r of result.findings.sort((a, b) => a.ratio - b.ratio)) console.log('  ' + line(r));
  console.log(`under 3:1 but running with the grain (decorative): ${result.decorative.length}`);
  for (const r of result.decorative.sort((a, b) => a.ratio - b.ratio).slice(0, 40)) console.log('  ~ ' + line(r));
  if (jsonAt > -1) fs.writeFileSync(process.argv[jsonAt + 1], JSON.stringify(result, null, 2));
}
