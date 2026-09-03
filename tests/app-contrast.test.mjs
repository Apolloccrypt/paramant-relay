// The app screens carry a dark mode, and a dark mode is where contrast quietly
// dies: one hard-coded hex left behind in a page's own <style> block is enough
// to put white text on a light-blue button, and nothing else in the suite would
// notice. So this walks every app screen in Chromium at two widths, in light
// and in dark, reads the COMPUTED colour of every visible text node, flattens
// it against the first opaque background behind it, and fails on anything under
// WCAG AA. It also checks that a coarse pointer gets a real tap target.
//
// Why computed and not source: the whole point of the token layer in
// frontend/app-2026.css is that a rule written years ago against --ink now
// resolves to a different value per theme. Only the browser knows the answer.
//
// Contract, from docs/brand/design-direction.md section 6:
//   - 4.5:1 for normal text, 3:1 for large text (>=24px, or >=18.66px bold)
//   - 44px tap target for every control under (pointer: coarse), with one
//     deliberate exception: a text link inside a running paragraph, which
//     lives under the reading rule with its underline.

import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.woff2':'font/woff2' };
const ALIAS = {
  '/dashboard':'/dashboard.html', '/account':'/account.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html',
  '/auth/backup':'/auth/backup.html', '/auth/request-reset':'/auth/request-reset.html',
  '/auth/reset-confirm':'/auth/reset-confirm.html',
};

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (ALIAS[pathname]) pathname = ALIAS[pathname];
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
async function stub(page) {
  await page.route('**/api/user/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
  await page.route('**/api/user/me', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/account', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/billing/status', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ current_plan:'community', ...ME }) }));
  await page.route('**/api/user/billing/history', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"history":[]}' }));
  await page.route('**/api/user/documents**', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(DOCS) }));
  await page.route('**/api/user/dashboard/overview', (r) => r.fulfill({ status:500, body:'' }));
  await page.route('**/api/user/account/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"keys":[{"label":"Signing key"}],"passkeys":[{"label":"Passkey"}]}' }));
}

// Runs inside the page: read every visible text node's own colour, flatten it
// onto the first ancestor with an opaque background, and score the pair.
const AUDIT = () => {
  const parse = (value) => {
    const match = String(value).match(/rgba?\(([^)]+)\)/);
    if (!match) return null;
    const parts = match[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
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
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

  const backdrop = (node) => {
    let stack = [];
    for (let el = node; el && el !== document.documentElement.parentNode; el = el.parentElement) {
      const style = getComputedStyle(el);
      const bg = parse(style.backgroundColor);
      if (bg && bg.a > 0) { stack.push(bg); if (bg.a >= 1) break; }
    }
    const page = parse(getComputedStyle(document.documentElement).backgroundColor);
    let base = page && page.a >= 1 ? page : { r: 255, g: 255, b: 255, a: 1 };
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };

  const findings = [];
  const seen = new Set();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.textContent.trim();
    if (!text) continue;
    const el = node.parentElement;
    if (!el || el.closest('[hidden], [aria-hidden="true"], script, style, noscript, template')) continue;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity) === 0) continue;
    const box = el.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) continue;

    const fg = parse(style.color);
    if (!fg) continue;
    const bg = backdrop(el);
    const flat = fg.a < 1 ? over(fg, bg) : fg;
    const size = parseFloat(style.fontSize);
    const weight = Number(style.fontWeight) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3 : 4.5;
    const got = ratio(flat, bg);

    const key = style.color + '|' + [bg.r, bg.g, bg.b].map(Math.round).join(',') + '|' + Math.round(size) + '|' + large;
    if (seen.has(key)) continue;
    seen.add(key);
    if (got + 0.005 < need) {
      findings.push({
        ratio: Number(got.toFixed(2)), need, size: Math.round(size), weight,
        color: style.color, on: `rgb(${[bg.r, bg.g, bg.b].map(Math.round).join(',')})`,
        where: (el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '')),
        sample: text.slice(0, 48),
      });
    }
  }
  return { pairs: seen.size, findings };
};

const TAPS = () => {
  const small = [];
  const controls = document.querySelectorAll('a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]:not([tabindex="-1"])');
  for (const el of controls) {
    if (el.closest('[hidden], [aria-hidden="true"]')) continue;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    const box = el.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) continue;
    // A text link inside a running paragraph is exempt: it is read, not tapped
    // at a button's size, and it carries an underline instead.
    if (el.tagName === 'A' && style.display.startsWith('inline') && el.parentElement
        && ['P', 'LI', 'DD', 'SPAN', 'STRONG', 'EM', 'SMALL', 'LABEL'].includes(el.parentElement.tagName)) continue;
    if (box.height < 43.5) {
      small.push({ where: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/)[0] : ''), height: Math.round(box.height), text: (el.textContent || '').trim().slice(0, 32) });
    }
  }
  return small;
};

const SCREENS = [
  { name:'/dashboard', url:'/dashboard', ready:'#dh-root:not([hidden]) .dh-document' },
  { name:'/sign',      url:'/sign',      ready:'main' },
  { name:'/parashare', url:'/parashare', ready:'main' },
  { name:'/signup',    url:'/signup',    ready:'main' },
  { name:'/account',   url:'/account',   ready:'#state-account:not(.hidden)' },
  { name:'/auth/login', url:'/auth/login', ready:'form' },
  { name:'/auth/setup', url:'/auth/setup', ready:'main' },
  { name:'/auth/backup', url:'/auth/backup', ready:'main' },
  { name:'/auth/request-reset', url:'/auth/request-reset', ready:'main' },
  { name:'/auth/reset-confirm', url:'/auth/reset-confirm', ready:'main' },
];
const VIEWPORTS = [{ w:390, h:844 }, { w:1440, h:900 }];
const THEMES = ['light', 'dark'];

const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

test('every app screen keeps its text above AA in light and dark, at 390 and 1440', async () => {
  const failures = [];
  let pairs = 0;
  for (const screen of SCREENS) {
    for (const vp of VIEWPORTS) {
      for (const theme of THEMES) {
        const context = await browser.newContext({ viewport:{ width:vp.w, height:vp.h }, colorScheme:theme });
        const page = await context.newPage();
        await stub(page);
        await page.goto(ORIGIN + screen.url, { waitUntil:'domcontentloaded' });
        try { await page.locator(screen.ready).first().waitFor({ timeout:6000 }); } catch { /* audit what rendered */ }
        await page.waitForTimeout(250);
        const result = await page.evaluate(AUDIT);
        pairs += result.pairs;
        for (const finding of result.findings) {
          failures.push(`${screen.name} ${vp.w}x${vp.h} ${theme}: ${finding.ratio}:1 (needs ${finding.need}) :: ${finding.where} ${finding.size}px/${finding.weight} ${finding.color} on ${finding.on} :: "${finding.sample}"`);
        }
        await context.close();
      }
    }
  }
  console.log(`contrast: ${pairs} distinct colour pairs measured over ${SCREENS.length} screens x 2 widths x 2 themes`);
  assert.deepEqual(failures, [], `\n${failures.join('\n')}\n`);
});

test('a coarse pointer gets a 44px target on every app control', async () => {
  const failures = [];
  for (const screen of SCREENS) {
    const context = await browser.newContext({ viewport:{ width:390, height:844 }, hasTouch:true, isMobile:true });
    const page = await context.newPage();
    await stub(page);
    await page.goto(ORIGIN + screen.url, { waitUntil:'domcontentloaded' });
    try { await page.locator(screen.ready).first().waitFor({ timeout:6000 }); } catch { /* audit what rendered */ }
    await page.waitForTimeout(250);
    for (const small of await page.evaluate(TAPS)) {
      failures.push(`${screen.name}: ${small.where} is ${small.height}px high :: "${small.text}"`);
    }
    await context.close();
  }
  assert.deepEqual(failures, [], `\n${failures.join('\n')}\n`);
});

test.after(async () => { await browser.close(); server.close(); });
