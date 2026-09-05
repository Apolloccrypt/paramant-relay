// Nothing on /redeem may run to its last request and fail there.
//
// THE COMPLAINT THIS COMES FROM. The code field lived on /pricing, under the
// whole price table, and on /account, behind a sign-in. Both are pages you
// reach by already having an account. The hundred people /redeem was built for
// have none: they were mailed a code and a link. On those two pages a
// signed-out press is answered by a 401 from POST /v2/billing/redeem and
// js/redeem-code.js sends them to the sign-in, which is the same shape #442
// took off /sign: walk the whole screen, find out at the last request.
//
// So this walks /redeem signed out and asserts:
//
//   1. The one button says what it will do before it is pressed, and pressing
//      it goes to the sign-up with the code still attached.
//   2. Nothing along that route asks /api/user/ anything except the one session
//      probe, and nothing reaches /v2/ at all. A request answered with a 401 IS
//      the dead end whether or not the page shows it; counting requests catches
//      the next one too, wherever a later step puts it.
//   3. The code survives the detour both ways: in the link for the sign-in,
//      which auth-login.js honours, and in this browser for the sign-up, which
//      finishes through an emailed link and carries no next.
//
// It also holds what must not be traded away: /redeem stays a public 200 with
// no redirect and no noindex, the ?code= parameter is treated as somebody
// else's text, and signed in the page still prints the relay's own sentences
// and nothing of its own. The four refusals are read out of
// relay/lib/coupon.js, so a sentence changed there and not here is a failure.
//
// Real Chromium, the real page, same-origin APIs stubbed the way
// tests/sign-signed-out-dead-end.test.mjs stubs them. No relay, no redis.
//
// Run: node tests/redeem-signed-out-dead-end.test.mjs

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
  '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2' };
const ALIAS = {
  '/': '/index.html', '/redeem': '/redeem.html', '/pricing': '/pricing.html',
  '/signup': '/signup.html', '/auth/login': '/auth/login.html', '/dashboard': '/dashboard.html',
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const rel = ALIAS[decodeURIComponent(url.pathname)] || decodeURIComponent(url.pathname);
  const file = path.join(ROOT, rel);
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

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

// ── the relay's own sentences, read from the relay ───────────────────────────
// The page is not allowed an opinion about what a code did, so the strings this
// suite expects are the ones relay/lib/coupon.js actually sends.
const couponSource = fs.readFileSync(path.join(HERE, '..', 'relay', 'lib', 'coupon.js'), 'utf8');
function relaySentence(key) {
  const hit = new RegExp(`^\\s*${key}:\\s*'([^']+)'`, 'm').exec(couponSource);
  if (!hit) throw new Error(`relay/lib/coupon.js no longer has a MESSAGES.${key}`);
  return hit[1];
}
const RELAY_CODE_RE = /const CODE_RE = (\/\^\[A-Z0-9-\]\{3,32\}\$\/)/.exec(couponSource);

// The four a supporter actually meets, with the status the route answers them
// with (relay/relay.js, POST /v2/billing/redeem: 404 for a code we never heard
// of, 409 for one that exists and cannot be spent).
const REFUSALS = [
  { name: 'a code that does not exist', status: 404, error: 'unknown', message: relaySentence('unknown') },
  { name: 'a code that has expired', status: 409, error: 'expired', message: relaySentence('expired') },
  { name: 'a code that has run out', status: 409, error: 'exhausted', message: relaySentence('exhausted') },
  { name: 'a code this account already used', status: 409, error: 'already_used', message: relaySentence('already_used') },
];

const GRANTED = {
  ok: true,
  code: 'COFFEE',
  granted: [
    { product: 'parasign', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00.000Z' },
    { product: 'parasend', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00.000Z' },
  ],
  message: 'Your code is redeemed. You now have ParaSign Pro until 3 December 2026 and ParaSend Pro until 3 December 2026. Nothing was charged.',
};

const json = (route, body, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// Every request that needs an account. The session probe is the one call that
// is supposed to happen and the one that answers the question; everything else
// on /api/user/ needs a session by definition, and /v2/ is the relay itself.
function privileged(page) {
  const seen = [];
  page.on('request', (req) => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/user/') && p !== '/api/user/session/verify') seen.push(req.method() + ' ' + p);
    else if (p.startsWith('/v2/')) seen.push(req.method() + ' ' + p);
  });
  return seen;
}

async function openRedeem(authenticated, { search = '', redeem = null, context = null } = {}) {
  const ctx = context || await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/session/verify', (route) => json(route,
    authenticated ? { authenticated: true, email: 'demo@example.com' } : { authenticated: false }));
  await page.route('**/api/user/app/token', (route) =>
    json(route, { ok: true, token: 'pst_stub_token', expires_in_s: 900 }));
  if (redeem) await page.route('**/v2/billing/redeem', redeem);
  const calls = privileged(page);
  const response = await page.goto(ORIGIN + '/redeem' + search, { waitUntil: 'domcontentloaded' });
  await page.locator('#rd-submit:not([disabled])').waitFor({ timeout: 15000 });
  return { page, ctx, calls, response };
}

async function messageAfterSubmit(page) {
  await page.click('#rd-submit');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-redeem-message]');
    return el && el.textContent && !/Checking your code/.test(el.textContent);
  }, null, { timeout: 15000 });
  return (await page.textContent('[data-redeem-message]')).trim();
}

// ── signed out: the button keeps its promise ─────────────────────────────────
{
  const { page, ctx, calls } = await openRedeem(false, { search: '?code=coffee' });

  ok('signed out, the page says an account is needed before anything is typed',
    await page.locator('#rd-signedout').isVisible(), '#rd-signedout');
  const label = (await page.locator('#rd-submit').textContent()).trim();
  ok('signed out, the one button says it makes an account', label === 'Create a free account', label);
  ok('signed out, the button is not disabled once the session is known',
    !(await page.locator('#rd-submit').isDisabled()));

  // The code from the link, uppercased, in the box and nowhere else.
  ok('the code in the link fills the box', await page.inputValue('#rd-code') === 'COFFEE',
    await page.inputValue('#rd-code'));

  // The sign-in route carries the code, and auth-login.js's own rule accepts it.
  const signinHref = await page.locator('#rd-signin-link').getAttribute('href');
  const next = new URLSearchParams(signinHref.split('?')[1]).get('next');
  ok('the sign-in link comes back here with the code', next === '/redeem?code=COFFEE', String(next));
  ok('and auth-login.js would honour that next', /^\/(?![/\\])/.test(next), String(next));

  // The gate proper: nothing on the route asked for anything that needs an
  // account, so no 401 was raised, because no request was made that could.
  ok('signed out, nothing on the route needs a session', calls.length === 0, calls.join(', ') || 'none');

  // Pressing it goes to the sign-up, with the code kept both ways.
  await page.click('#rd-submit');
  await page.waitForURL(/\/signup\?next=/, { timeout: 15000 }).catch(() => {});
  ok('pressing it goes to the sign-up and back to here', /\/signup\?next=%2Fredeem%3Fcode%3DCOFFEE$/.test(page.url()), page.url());
  ok('and still nothing needed a session', calls.length === 0, calls.join(', ') || 'none');
  const kept = await page.evaluate(() => { try { return window.localStorage.getItem('paramant.redeem.code'); } catch { return null; } });
  ok('the code is kept in this browser for the way back', kept === 'COFFEE', String(kept));

  // Signup does not carry next, so the browser is the carrier: land back here
  // with a bare /redeem and the box is filled in again.
  const back = await ctx.newPage();
  await back.route('**/api/**', (route) => json(route, {}));
  await back.route('**/api/user/session/verify', (route) => json(route, { authenticated: false }));
  await back.goto(ORIGIN + '/redeem', { waitUntil: 'domcontentloaded' });
  await back.locator('#rd-submit:not([disabled])').waitFor({ timeout: 15000 });
  ok('coming back with a bare link, the code is typed in again',
    await back.inputValue('#rd-code') === 'COFFEE', await back.inputValue('#rd-code'));
  await ctx.close();
}

// ── the ?code= parameter is somebody else's text ─────────────────────────────
for (const [label, raw] of [
  ['a script tag', '<script>alert(1)</script>'],
  ['a code with a space in it', 'COF FEE'],
  ['a code longer than the relay allows', 'A'.repeat(64)],
  ['a path', '../../etc/passwd'],
]) {
  const { page, ctx } = await openRedeem(false, { search: '?code=' + encodeURIComponent(raw) });
  const value = await page.inputValue('#rd-code');
  ok(`${label} in the link is refused rather than repaired`, value === '', value);
  const html = await page.content();
  ok(`${label} never reaches the page`, !html.includes(raw), label);
  await ctx.close();
}

// The rule the page applies is the rule the relay applies.
{
  const pageSource = fs.readFileSync(path.join(ROOT, 'js', 'redeem.page.js'), 'utf8');
  ok('the page and the relay agree on what a code looks like',
    !!RELAY_CODE_RE && pageSource.includes(RELAY_CODE_RE[1]),
    RELAY_CODE_RE ? RELAY_CODE_RE[1] : 'relay/lib/coupon.js CODE_RE not found');
}

// ── the guarantees the fix may not trade away ────────────────────────────────
{
  const { page, ctx, response } = await openRedeem(false);
  ok('signed out, /redeem answers 200', response.status() === 200, String(response.status()));
  ok('signed out, /redeem does not redirect',
    new URL(page.url()).pathname === '/redeem' && response.request().redirectedFrom() === null, page.url());
  const robots = await page.locator('meta[name="robots"]').count();
  const content = robots ? await page.locator('meta[name="robots"]').first().getAttribute('content') : '';
  ok('signed out, /redeem is not marked noindex', !/noindex/i.test(content || ''), content || '(no robots meta)');
  ok('there is exactly one h1', await page.locator('h1').count() === 1);
  // One box and one button, on the screen a phone gives you, without scrolling
  // for either. The page is nothing but this, so if it does not fit here it
  // does not fit anywhere.
  const buttonBottom = await page.evaluate(() =>
    Math.round(document.getElementById('rd-submit').getBoundingClientRect().bottom));
  ok('the box and the button are on the first screen of a phone',
    buttonBottom > 0 && buttonBottom <= 844, `${buttonBottom}px`);
  ok('and the page does not scroll sideways',
    await page.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));
  await ctx.close();
}

// ── signed in: the four refusals, in the relay's own words ───────────────────
for (const refusal of REFUSALS) {
  const { page, ctx, calls } = await openRedeem(true, {
    search: '?code=COFFEE',
    redeem: (route) => json(route, { error: refusal.error, message: refusal.message }, refusal.status),
  });
  const label = (await page.locator('#rd-submit').textContent()).trim();
  ok(`${refusal.name}: signed in, the button is the real one`, label === 'Redeem code', label);

  const message = await messageAfterSubmit(page);
  ok(`${refusal.name}: the page prints the relay's sentence`, message === refusal.message, message);
  ok(`${refusal.name}: and no machine string reaches the reader`,
    !/\b[45]\d\d\b/.test(message) && !/_/.test(message) && !/\berror\b/i.test(message), message);
  ok(`${refusal.name}: the code stays in the box so a typo is corrected, not retyped`,
    await page.inputValue('#rd-code') === 'COFFEE', await page.inputValue('#rd-code'));
  ok(`${refusal.name}: the end screen is not shown`, await page.locator('#rd-done').isHidden());
  ok(`${refusal.name}: the button works again afterwards`, !(await page.locator('#rd-submit').isDisabled()));
  ok(`${refusal.name}: exactly one credential was minted, and one code sent`,
    calls.filter((c) => c.endsWith('/api/user/app/token')).length === 1
    && calls.filter((c) => c.endsWith('/v2/billing/redeem')).length === 1, calls.join(', '));
  await ctx.close();
}

// ── signed in: the ending ────────────────────────────────────────────────────
{
  const { page, ctx, calls } = await openRedeem(true, {
    search: '?code=COFFEE',
    redeem: (route) => json(route, GRANTED),
  });
  ok('nothing is asked for before the button is pressed',
    calls.length === 0, calls.join(', ') || 'none');

  await messageAfterSubmit(page);
  await page.locator('#rd-done:not([hidden])').waitFor({ timeout: 15000 });
  ok('the form is gone once the code is spent', await page.locator('#rd-panel').isHidden());

  const title = (await page.locator('#rd-done-title').innerText()).trim();
  const line = (await page.locator('#rd-done-line').innerText()).trim();
  ok('the ending says it in the relay words, both halves',
    GRANTED.message === title + ' ' + line, `${title} | ${line}`);
  ok('the ending names what you have and until when',
    /ParaSign Pro until 3 December 2026/.test(line) && /Nothing was charged/.test(line), line);
  ok('the ending has exactly one primary button',
    await page.locator('#rd-done .done-actions .done-primary').count() === 1);
  // The two rules done-state.css is for, held here because the four flows
  // tests/end-screen-calm.test.mjs walks cannot reach this page: the answer
  // fits one phone screen with the fold shut, and it is not written in
  // algorithm. Same measurement, same vocabulary.
  const doneHeight = await page.evaluate(() => {
    const root = document.getElementById('rd-done');
    let h = root.getBoundingClientRect().height;
    root.querySelectorAll('details').forEach((d) => { h -= d.getBoundingClientRect().height; });
    return Math.round(h);
  });
  ok('the ending fits one phone screen with the fold shut', doneHeight > 0 && doneHeight <= 844, `${doneHeight}px`);
  const face = await page.evaluate(() => {
    const clone = document.getElementById('rd-done').cloneNode(true);
    clone.querySelectorAll('details, script, style').forEach((n) => n.remove());
    return (clone.textContent || '').replace(/\s+/g, ' ').trim();
  });
  const jargon = face.match(/\bML-KEM\b|\bML-DSA\b|\bFIPS\b|\bSHA-?3\b|\bfingerprint\b|\brelay\b/i);
  ok('no algorithm name on the face of the ending', !jargon, jargon ? jargon[0] : '');
  ok('and the technical account starts folded away',
    await page.evaluate(() => [...document.querySelectorAll('#rd-done details')].every((d) => !d.open)));
  const left = await page.evaluate(() => { try { return window.localStorage.getItem('paramant.redeem.code'); } catch { return null; } });
  ok('a spent code is not kept in the browser', left === null, String(left));
  await ctx.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nredeem-signed-out-dead-end: ${checks.length} checks passed`);
