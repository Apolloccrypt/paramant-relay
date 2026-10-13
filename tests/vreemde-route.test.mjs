// Een vreemde moet er zonder hulp doorheen (test op productie bb9b7192,
// 13-10-2026). Deze suite loopt de weg die toen brak, met een gestubde backend:
//
//   1. /pricing uitgelogd: "Kies Firm" stuurde naar /auth/login ("Welkom
//      terug"). Nu naar /signup, met de weg terug naar het gekozen plan.
//   2. /signup las geen ?next=, en de inlogpagina linkte naar een kale
//      /signup. Nu houdt de aanmelding de weg terug vast over de twee mails
//      heen (localStorage, alleen een pad op deze site), en het welkomscherm
//      na het instellen stuurt erheen.
//   5. Na verzenden stond "stap 1 van 5" boven "stap 2 van 5".
//
// Elk blok is rood op bb9b7192.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.woff2': 'font/woff2' };
const ALIAS = {
  '/pricing': '/pricing.html', '/en/pricing': '/en/pricing.html',
  '/signup': '/signup.html', '/en/signup': '/en/signup.html',
  '/auth/login': '/auth/login.html', '/en/auth/login': '/en/auth/login.html',
};
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (ALIAS[p]) p = ALIAS[p];
  else if (p.startsWith('/auth/setup/')) p = '/auth/setup.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const json = (route, status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// A visitor without a session: every API answers 401, the signup itself 200.
async function stranger() {
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } });
  const page = await ctx.newPage();
  const checkouts = [];
  await page.route('**/api/**', (r) => json(r, 401, { error: 'unauthorized' }));
  await page.route('**/v2/**', (r) => { if (r.request().url().includes('/v2/billing/checkout')) checkouts.push(r.request().url()); return json(r, 401, { error: 'unauthorized' }); });
  await page.route('**/api/user/session/verify', (r) => json(r, 200, { authenticated: false }));
  await page.route('**/api/user/signup', (r) => json(r, 200, { ok: true }));
  await page.route('**/js/pow-captcha.js*', (r) => r.fulfill({ status: 200, contentType: 'text/javascript',
    body: 'window.ParamantCaptcha = { getCaptchaProof: async () => ({ challenge_id: "c", nonce: "1" }) };' }));
  return { ctx, page, checkouts };
}

// ── 1 + 2 + 5, Dutch: price button -> signup -> mail -> setup -> back to the plan
const nl = {};
{
  const { ctx, page, checkouts } = await stranger();
  await page.goto(`${ORIGIN}/pricing`, { waitUntil: 'load' });
  nl.noJsHref = await page.locator('a[data-billing-product="firm"][data-billing-interval="monthly"]').first().getAttribute('href');
  await page.locator('a[data-billing-product="firm"][data-billing-interval="monthly"]').first().click();
  await page.waitForURL(/\/(signup|auth\/login)/, { timeout: 15000 }).catch(() => {});
  nl.afterBuy = page.url().slice(ORIGIN.length);
  await page.waitForTimeout(400);
  nl.note = await page.locator('#signup-next-note').isVisible().catch(() => false)
    ? await page.locator('#signup-next-note').innerText() : '';
  nl.loginLink = await page.locator('a[data-signup-login]').getAttribute('href').catch(() => null);
  await page.locator('#email').fill('demo@example.com').catch(() => {});
  await page.locator('#submit-btn').click().catch(() => {});
  await page.locator('#step2:not([hidden])').waitFor({ timeout: 10000 }).catch(() => {});
  nl.stepsShown = await page.evaluate(() => [...document.querySelectorAll('.eyebrow')]
    .filter((e) => /stap \d van 5/i.test(e.textContent) && e.offsetParent !== null).map((e) => e.textContent.trim()));
  nl.stored = await page.evaluate(() => { try { return JSON.parse(localStorage.getItem('paramant:signup-next') || 'null'); } catch { return null; } });

  // The setup link from the second mail opens in a new tab: sessionStorage is gone.
  const tab = await ctx.newPage();
  await tab.route('**/api/**', (r) => json(r, 404, { error: 'not_found' }));
  await tab.goto(`${ORIGIN}/auth/setup/demo-token`, { waitUntil: 'load' });
  await tab.waitForTimeout(300);
  await tab.evaluate(() => { document.querySelectorAll('section[id^="state-"]').forEach((s) => s.classList.add('hidden')); document.getElementById('state-welcome').classList.remove('hidden'); });
  await tab.waitForTimeout(200);
  nl.welcome = await tab.evaluate(() => ({
    shown: !document.getElementById('welcome-doc-return').hidden,
    text: document.getElementById('welcome-doc-return').innerText,
    href: document.getElementById('welcome-doc-link').getAttribute('href'),
  }));
  await tab.waitForURL(/\/pricing/, { timeout: 8000 }).catch(() => {});
  await tab.waitForTimeout(600);
  nl.landed = tab.url().slice(ORIGIN.length);
  nl.resume = await tab.locator('#billing-resume-note').innerText().catch(() => '');
  nl.leftover = await tab.evaluate(() => localStorage.getItem('paramant:signup-next'));
  nl.checkouts = checkouts.length;
  await ctx.close();
}

// ── English: the same road stays English
const en = {};
{
  const { ctx, page } = await stranger();
  await page.goto(`${ORIGIN}/en/pricing`, { waitUntil: 'load' });
  await page.locator('a[data-billing-product="firm"][data-billing-interval="monthly"]').first().click();
  await page.waitForURL(/\/(signup|auth\/login)/, { timeout: 15000 }).catch(() => {});
  en.afterBuy = page.url().slice(ORIGIN.length);
  await page.waitForTimeout(400);
  en.note = await page.locator('#signup-next-note').innerText().catch(() => '');
  en.loginLink = await page.locator('a[data-signup-login]').getAttribute('href').catch(() => null);
  await ctx.close();
}

// ── The sign-in page hands its way back to "Account maken", and a first
// sign-in without ?next= takes the way back this browser kept.
const login = {};
{
  const { ctx, page } = await stranger();
  await page.goto(`${ORIGIN}/auth/login?next=${encodeURIComponent('/sign?herstel=1')}`, { waitUntil: 'load' });
  login.signupLinks = await page.evaluate(() => [...document.querySelectorAll('a')].map((a) => a.getAttribute('href')).filter((h) => /^\/signup/.test(h || '')));
  await page.goto(`${ORIGIN}/en/auth/login?next=${encodeURIComponent('/en/sign?herstel=1')}`, { waitUntil: 'load' });
  login.enSignupLinks = await page.evaluate(() => [...document.querySelectorAll('a')].map((a) => a.getAttribute('href')).filter((h) => /^\/en\/signup/.test(h || '')));
  await page.evaluate(() => localStorage.setItem('paramant:signup-next', JSON.stringify({ path: '/pricing?koop=firm.firm.monthly', exp: Date.now() + 3600e3 })));
  await page.goto(`${ORIGIN}/auth/login`, { waitUntil: 'load' });
  login.firstUrl = page.url().slice(ORIGIN.length);
  login.leftover = await page.evaluate(() => localStorage.getItem('paramant:signup-next'));
  await ctx.close();
}

// ── No open redirect: only a path on this site is ever kept.
const guard = {};
{
  const { ctx, page } = await stranger();
  await page.goto(`${ORIGIN}/signup?next=${encodeURIComponent('//evil.example/x')}`, { waitUntil: 'load' });
  await page.waitForTimeout(300);
  guard.noteShown = await page.locator('#signup-next-note').isVisible();
  await page.locator('#email').fill('demo@example.com');
  await page.locator('#submit-btn').click();
  await page.locator('#step2:not([hidden])').waitFor({ timeout: 10000 }).catch(() => {});
  guard.stored = await page.evaluate(() => localStorage.getItem('paramant:signup-next'));
  guard.unit = await page.evaluate(async () => {
    const m = await import('/js/signup-next.js?v=1');
    return ['//evil.example', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', '/ok\n', '/pricing?koop=firm.firm.monthly', '/sign?herstel=1']
      .map((p) => m.safeLocalPath(p));
  });
  await ctx.close();
}

test('1: uitgelogd op /pricing leidt Kies Firm naar een gratis account, met het plan in de weg terug', () => {
  assert.equal(nl.afterBuy, '/signup?next=' + encodeURIComponent('/pricing?koop=firm.firm.monthly'));
  assert.match(nl.note, /Eerst maakt u een gratis account\. Daarna rekent u af/);
  assert.match(nl.noJsHref, /^\/signup\?next=\/pricing$/, 'zonder JS gaat de knop ook naar de aanmelding');
  assert.equal(en.afterBuy, '/en/signup?next=' + encodeURIComponent('/en/pricing?koop=firm.firm.monthly'));
  assert.match(en.note, /First you make a free account\. Then you pay/);
});

test('2: de aanmelding houdt de weg terug vast en stuurt na het instellen terug naar het plan', () => {
  assert.equal(nl.loginLink, '/auth/login?next=' + encodeURIComponent('/pricing?koop=firm.firm.monthly'));
  assert.equal(en.loginLink, '/en/auth/login?next=' + encodeURIComponent('/en/pricing?koop=firm.firm.monthly'));
  assert.equal(nl.stored && nl.stored.path, '/pricing?koop=firm.firm.monthly');
  assert.ok(nl.welcome.shown, 'het welkomscherm biedt de weg terug');
  assert.match(nl.welcome.text, /terug naar het plan dat u koos/);
  assert.equal(nl.welcome.href, '/pricing?koop=firm.firm.monthly');
  assert.equal(nl.landed, '/pricing', 'terug op /pricing, de keuze uit het adres gehaald');
  assert.match(nl.resume, /Klik op de knop hierboven om dit plan af te rekenen/);
  assert.equal(nl.leftover, null, 'de weg terug is gebruikt en weg');
  assert.equal(nl.checkouts, 0, 'een link alleen start nooit een betaling');
});

test('2: de inlogpagina geeft next door aan Account maken, en een eerste inlog zonder next neemt de bewaarde weg', () => {
  assert.ok(login.signupLinks.length >= 2, JSON.stringify(login.signupLinks));
  for (const h of login.signupLinks) assert.equal(h, '/signup?next=' + encodeURIComponent('/sign?herstel=1'));
  assert.ok(login.enSignupLinks.length >= 2, JSON.stringify(login.enSignupLinks));
  for (const h of login.enSignupLinks) assert.equal(h, '/en/signup?next=' + encodeURIComponent('/en/sign?herstel=1'));
  assert.equal(login.firstUrl, '/auth/login?next=' + encodeURIComponent('/pricing?koop=firm.firm.monthly'));
  assert.equal(login.leftover, null);
});

test('2: alleen een pad op deze site wordt bewaard, nooit een open redirect', () => {
  assert.equal(guard.noteShown, false);
  assert.equal(guard.stored, null);
  assert.deepEqual(guard.unit, [null, null, null, null, null, '/pricing?koop=firm.firm.monthly', '/sign?herstel=1']);
});

test('5: na verzenden staat alleen de actuele stap op het scherm', () => {
  assert.deepEqual(nl.stepsShown, ['stap 2 van 5']);
});
