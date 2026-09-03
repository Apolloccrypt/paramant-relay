// The signed-in pages do not fetch the account key when they load.
//
// WHAT THIS PINS, AND WHY IT IS ITS OWN SUITE. /pricing and /dashboard used to
// call GET /api/user/account/key and authenticate to the relay with the pgp_
// key itself; /account printed the masked key on load. An api-key has no expiry
// and no scope, so every one of those visits put a full data-plane credential
// (or the shape of one) into the tab, for people who had come to read a price
// or check a quota. They now run on a short-lived scoped pst_ session token
// (relay/lib/session-token.js, purpose `app`), and /account fetches the key only
// when someone opens its "Advanced account key" fold.
//
// A grep would have been cheaper and would have measured the wrong thing. What
// matters is what the PAGE does when a browser loads it: a fetch reintroduced
// through a helper, a shared module or an event that fires on load would pass a
// grep of the three page scripts and fail here. So this drives real Chromium
// over the real static frontend and watches the network.
//
// Verified by sabotage:
//   * put the /api/user/account/key fetch back at the top of
//     account.inline1.js, or render data.api_key_masked on load, and the
//     /account cases go red;
//   * make pricing-billing.js or dashboard-history.js fetch the key again and
//     the matching page goes red;
//   * take the toggle listener out of account.inline1.js and the "opening the
//     fold is what asks" case goes red, which is the half that proves the key
//     is still reachable where it is supposed to be.
//
// Run: node --test tests/app-pages-no-api-key.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/account':'/account.html', '/pricing':'/pricing.html' };

// The endpoint this whole suite is about. Named once, so a rename cannot make
// the assertions silently vacuous.
const KEY_URL = '/api/user/account/key';
const FAKE_KEY = 'pgp_live_testkey000000000000cafe';

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
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
const checks = [];
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

// Every /api/** answer a signed-in page can ask for, so nothing fails for a
// reason other than the one under test, plus the recorder. The key endpoint is
// answered too: a 404 would make "no request was made" true for the wrong
// reason on the case where the request IS expected.
const BODIES = {
  '/api/user/session/verify': { authenticated: true, email: 'demo@example.com' },
  '/api/user/account': {
    email: 'demo@example.com', api_key_masked: 'pgp_live...cafe', plan: 'pro', label: 'Demo',
    created_at: '2026-06-01T10:00:00.000Z', backup_codes_remaining: 8,
    session_expires_at: '2099-01-01T00:00:00.000Z', sessions: [],
  },
  [KEY_URL]: { api_key: FAKE_KEY, revealable: true },
  '/api/user/me': { email: 'demo@example.com', plan: 'pro', usage_purpose: 'organisation' },
  '/api/user/documents': { documents: [] },
  '/api/user/dashboard/overview': { plan: 'pro', quota: { transfers: 1, signs: 1, caps: {} }, audit: [] },
  '/api/user/app/token': { token: 'pst_' + 'ab12cd34'.repeat(8), expires_in_s: 900 },
};

async function openPage(route) {
  const page = await browser.newPage({ viewport:{ width:1280, height:900 } });
  const asked = [];
  await page.route('**/api/**', (r) => {
    const pathname = new URL(r.request().url()).pathname;
    asked.push(pathname);
    r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(BODIES[pathname] || {}) });
  });
  await page.goto(ORIGIN + route, { waitUntil:'networkidle' });
  return { page, asked };
}

// ── 1. Loading any of the three asks for no key ──────────────────────────────
for (const route of ['/account', '/pricing', '/dashboard']) {
  const { page, asked } = await openPage(route);
  ok(`${route} asks for no account key when it loads`,
    !asked.includes(KEY_URL), asked.join(', ') || 'no /api call at all');
  // And nothing of the key is IN the page either: a masked key rendered from the
  // account payload is still the page telling you it holds one. textContent, not
  // innerText: the /account key sits inside a closed <details>, and innerText
  // skips what is not laid out, which would make this pass for the wrong reason.
  const body = await page.evaluate(() => document.body.textContent);
  ok(`${route} shows nothing shaped like an account key on load`,
    !/pgp_/.test(body) && !body.includes(FAKE_KEY), (body.match(/pgp_\S*/g) || []).join(', '));
  await page.close();
}

// ── 2. But the key is still reachable, behind the fold on /account ───────────
{
  const { page, asked } = await openPage('/account');
  ok('/account has the Advanced fold, closed', await page.locator('#acct-advanced').count() === 1 &&
    await page.locator('#acct-advanced').evaluate((node) => !node.open));
  const before = asked.filter((u) => u === KEY_URL).length;

  await page.locator('#acct-advanced > summary').click();
  // The placeholder the HTML ships with, written as an escape: the style guard
  // bans the literal character from added lines.
  await page.waitForFunction(() => document.getElementById('api-key').textContent.trim() !== '\u2014');
  const after = asked.filter((u) => u === KEY_URL).length;
  ok('opening the fold is what asks for the key, exactly once', before === 0 && after === 1, `${before} -> ${after}`);

  // Masked, not whole: opening the fold says "show me the row", and Show says
  // "show me the key". Two different acts.
  const shown = (await page.locator('#api-key').innerText()).trim();
  ok('the fold shows the key masked, not in full', shown.startsWith('pgp_live') && shown.includes('...') &&
    shown !== FAKE_KEY, shown);

  await page.locator('#show-key').click();
  await page.waitForFunction((key) => document.getElementById('api-key').textContent.trim() === key, FAKE_KEY);
  ok('Show reveals the whole key without asking the server again',
    asked.filter((u) => u === KEY_URL).length === 1, asked.filter((u) => u === KEY_URL).length);
  await page.close();
}

// ── 3. And the token is what the other two use instead ───────────────────────
// Not on load -- nothing is minted for a visitor who only reads -- but the page
// must carry the helper that mints one, or "no key" would just mean "no
// credential at all" and the checkout would be broken rather than fixed.
{
  const { page, asked } = await openPage('/pricing');
  ok('/pricing mints no session token on load either',
    !asked.includes('/api/user/app/token'), asked.join(', '));
  ok('/pricing loads the app session-token helper',
    await page.evaluate(() => typeof window.paAppToken?.get === 'function'));

  // And the click really runs on the token. This is the half that makes "no key
  // on load" mean something: without it, a page that fetched the key on the
  // click instead would pass every case above.
  const relayCalls = [];
  await page.route('**/v2/billing/checkout', (r) => {
    relayCalls.push(r.request().headers());
    r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ ok:true, checkout_url:'about:blank' }) });
  });
  const button = page.locator('a[data-billing-product]').first();
  ok('/pricing still has a price button to press', await button.count() === 1);
  await button.click();
  // The click is three awaits deep: mint the token, post the checkout, then
  // navigate to the payment page. Poll for the checkout call rather than
  // sleeping a fixed number of milliseconds, which is the difference between a
  // test and a flake.
  const deadline = Date.now() + 5000;
  while (!relayCalls.length && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));

  ok('pressing a price button mints a session token', asked.includes('/api/user/app/token'), asked.join(', '));
  ok('and never asks for the account key on the way', !asked.includes(KEY_URL), asked.join(', '));
  const sent = relayCalls[0] || {};
  ok('the checkout call carries a pst_ bearer and no api-key header',
    /^Bearer pst_[0-9a-f]{8}/i.test(sent.authorization || '') && !('x-api-key' in sent),
    JSON.stringify({ authorization: sent.authorization, 'x-api-key': sent['x-api-key'] }));
  await page.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\napp-pages-no-api-key: ${checks.length} checks passed`);
