/* Screenshot helper for the signed-in surfaces at 390px.
 *
 * Serves frontend/ over a throwaway http server, stubs the session and account
 * endpoints so the signed-in view renders without a live relay, and writes
 * full-page PNGs. Used to produce the before/after images on a pull request.
 *
 *   node scripts/shot-dashboard.mjs <out-dir> [plan] [parasign] [parasend]
 */
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const OUT = process.argv[2] || '/tmp/shots';
// plan = the unified account plan. parasign / parasend = the per-product tiers
// a self-serve purchase moves, which is how a paying customer can hold the
// unified plan 'community' and still owe no upgrade band.
const PLAN = process.argv[3] || 'community';
const PARASIGN = process.argv[4] || 'free';
const PARASEND = process.argv[5] || 'free';
const LABEL = process.env.SHOT_LABEL || PLAN;
const PAID_UNTIL = new Date(Date.now() + 30 * 86400000).toISOString();
const productFields = {
  plan_parasign: PARASIGN,
  plan_parasend: PARASEND,
  paid_until_parasign: PARASIGN === 'free' ? null : PAID_UNTIL,
  paid_until_parasend: PARASEND === 'free' ? null : PAID_UNTIL,
};
const EMAIL = 'mickbr@protonmail.com';
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const aliases = { '/': '/index.html', '/dashboard': '/dashboard.html', '/account': '/account.html', '/developer': '/developer.html' };

fs.mkdirSync(OUT, { recursive: true });

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

const json = (body) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 });

// Playwright tries handlers newest-first, so the catch-alls go on FIRST and the
// specific stubs on top of them. The other way round the catch-all answers {}
// to every call and the page renders a signed-out shell.
await page.route('**/api/**', (r) => r.fulfill(json({})));
await page.route('**/api/user/**', (r) => r.fulfill(json({})));
await page.route('**/api/user/billing/history', (r) => r.fulfill(json({ history: [] })));
await page.route('**/api/user/billing/status', (r) => r.fulfill(json({ current_plan: PLAN, ...productFields })));
await page.route('**/api/user/documents**', (r) => r.fulfill(json({ documents: [] })));
await page.route('**/api/user/account', (r) => r.fulfill(json({
  email: EMAIL, plan: PLAN, api_key_masked: 'pk_live_****', label: 'primary',
  created_at: '2026-03-04T10:00:00Z', backup_codes_remaining: 8, sessions: [],
  ...productFields,
})));
await page.route('**/api/user/me', (r) => r.fulfill(json({
  email: EMAIL, plan: PLAN, created_at: '2026-03-04T10:00:00Z',
  backup_codes_remaining: 8, session_expires_at: new Date(Date.now() + 42 * 60000).toISOString(),
  usage_purpose: 'personal', api_key: 'pk_live_demo', label: 'primary',
  ...productFields,
})));
await page.route('**/api/user/session/verify', (r) => r.fulfill(json({ authenticated: true, email: EMAIL })));

// JPEG, because these go straight into a pull request body and a full-page PNG
// of a long dashboard runs to several hundred kB. One step, one extension: the
// body used to link .jpg files a PNG-only script had never written.
const measured = {};
for (const [name, route] of [['dashboard', '/dashboard'], ['account', '/account']]) {
  await page.goto(ORIGIN + route, { waitUntil: 'networkidle' });
  await page.waitForTimeout(700);
  const file = path.join(OUT, `390-${name}-${LABEL}.jpg`);
  await page.screenshot({ path: file, fullPage: true, type: 'jpeg', quality: 82 });
  console.log('wrote', file);
  // What the customer can actually see without scrolling. Point 9 of the
  // review was measured this way: the first action sat at y=677 on a 844px
  // screen, half out of view, because the plan band came before it.
  measured[name] = await page.evaluate(() => {
    const top = (sel) => {
      const el = document.querySelector(sel);
      if (!el || el.hidden || !el.getClientRects().length) return null;
      return Math.round(el.getBoundingClientRect().top + window.scrollY);
    };
    return {
      firstAction: top('.dh-start-card'),
      secondAction: top('.dh-start-card:nth-child(2)'),
      planBand: top('#dh-community') ?? top('#dh-plan-paid') ?? top('#billing-community') ?? top('#billing-paid'),
      upgradeLink: top('.dh-community-cta') ?? top('.acct-plan-cta'),
      planChip: top('.dh-plan') ?? top('.acct-plan'),
      viewport: window.innerHeight,
    };
  });
}
console.log('offsets(px from top of page):', JSON.stringify(measured));

await browser.close();
server.close();
