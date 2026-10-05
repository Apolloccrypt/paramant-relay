// The sun | moon switch beside NL | EN.
//
// Mick, 23-09-2026: "net als EN en NL taal, ook een toggle die dark mode
// maakt. Zelfde style als nu maar extra dark mode / tegenhanger." What that
// asks of the code, and what this file measures in a browser:
//
//   1. every page with the shared nav carries the switch, in the bar from
//      701px up and in the strip under the drawer on a phone, with
//      aria-label "Thema" (English pages: "Theme") and aria-pressed;
//   2. a press flips the page to the other edition, aria-pressed follows,
//      and the choice is written to the same key /account uses;
//   3. the choice survives a reload and another page, on /en and on the app
//      screens as well;
//   4. no flash: on a reload in the dark edition <html> already carries
//      data-theme="dark" and the dark ground at the moment <body> is created,
//      before anything can be painted;
//   5. the colour fade runs only on a press, never on load, and not at all
//      under prefers-reduced-motion.
//
// Run: node --test tests/theme-toggle.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const KEY = 'paramant.theme.v1';
const LIGHT = 'rgb(255, 255, 255)';
const DARK = 'rgb(14, 20, 27)';
const TYPES = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.webp':'image/webp','.jpg':'image/jpeg' };

// Routes as nginx serves them: /x is /x.html, a directory is its index.
const host = http.createServer((req, res) => {
  const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  let file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  else if (!path.extname(file)) file += '.html';
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => host.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${host.address().port}`;
// Wait until the colour fade of a press is over (html.theme-fade gone, then
// one more frame), rather than for a fixed time a loaded CI runner may miss.
async function settle(page) {
  await page.waitForFunction(() => !document.documentElement.classList.contains('theme-fade'), null, { timeout:3000 });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

// Signed out everywhere: the bar and the strip are what a visitor sees.
async function signedOut(page) {
  await page.route('**/api/**', (r) => r.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
}

// Signed in, for the app screens that send a visitor to the login otherwise.
const SESSION = {
  email:'demo@example.com', label:'Demo', plan:'community', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:new Date(Date.now() + 30 * 86400000).toISOString(),
  usage_purpose:'organisation', api_key_masked:'pgp_****', sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};
async function signedIn(page) {
  await page.route('**/api/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
  await page.route('**/api/user/me', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(SESSION) }));
  await page.route('**/api/user/account', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(SESSION) }));
  await page.route('**/api/user/documents**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
}

// The page's ground: <body>, or <html> when the body paints a gradient.
const groundOf = () => {
  const b = getComputedStyle(document.body).backgroundColor;
  return b === 'rgba(0, 0, 0, 0)' ? getComputedStyle(document.documentElement).backgroundColor : b;
};

const PAGES = [
  { url:'/', label:'Thema' },
  { url:'/pricing', label:'Thema' },
  { url:'/partners', label:'Thema' },
  { url:'/en/', label:'Theme' },
  { url:'/en/pricing', label:'Theme' },
  { url:'/auth/login', label:'Thema' },
  { url:'/sign', label:'Thema' },
  { url:'/en/sign', label:'Theme' },
];

test('the switch sits beside NL | EN on every page, and a press flips the page and is remembered', async () => {
  const wrong = [];
  for (const { url, label } of PAGES) {
    const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:'light' });
    const page = await context.newPage();
    await signedOut(page);
    await page.goto(ORIGIN + url, { waitUntil:'load' });

    const button = page.locator('nav.nav [data-theme-toggle]');
    if (await button.count() !== 1) { wrong.push(`${url}: ${await button.count()} switches in the bar, expected 1`); await context.close(); continue; }
    if (await button.getAttribute('aria-label') !== label) wrong.push(`${url}: aria-label is "${await button.getAttribute('aria-label')}", expected "${label}"`);
    if (await button.getAttribute('aria-pressed') !== 'false') wrong.push(`${url}: aria-pressed is not "false" on a light page`);
    if (!await button.isVisible()) wrong.push(`${url}: the switch is not visible at 1280px`);
    // Beside the language switch: the element right before it is NL | EN.
    const beside = await button.evaluate((el) => el.previousElementSibling && el.previousElementSibling.classList.contains('nav-lang'));
    if (!beside) wrong.push(`${url}: the switch is not directly after NL | EN`);
    // Inline SVG, no emoji, no text of its own beyond the bar between the halves.
    const svgs = await button.locator('svg').count();
    if (svgs !== 2) wrong.push(`${url}: ${svgs} icons in the switch, expected a sun and a moon`);

    await button.click();
    await settle(page);
    if (await page.evaluate(groundOf) !== DARK) wrong.push(`${url}: a press did not make the page dark (${await page.evaluate(groundOf)})`);
    if (await button.getAttribute('aria-pressed') !== 'true') wrong.push(`${url}: aria-pressed did not follow to "true"`);
    if (await page.evaluate((k) => localStorage.getItem(k), KEY) !== 'dark') wrong.push(`${url}: the choice was not stored under ${KEY}`);

    await page.reload({ waitUntil:'load' });
    if (await page.evaluate(groundOf) !== DARK) wrong.push(`${url}: the dark choice did not survive a reload`);
    if (await page.locator('nav.nav [data-theme-toggle]').getAttribute('aria-pressed') !== 'true') wrong.push(`${url}: aria-pressed is not "true" after the reload`);

    await page.locator('nav.nav [data-theme-toggle]').click();
    await settle(page);
    if (await page.evaluate(groundOf) !== LIGHT) wrong.push(`${url}: a second press did not bring the light back`);
    if (await page.evaluate((k) => localStorage.getItem(k), KEY) !== 'light') wrong.push(`${url}: the light choice was not stored`);
    await context.close();
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('the choice carries from a public page to /en and into the app', async () => {
  const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:'light' });
  const page = await context.newPage();
  await signedIn(page);
  await page.goto(ORIGIN + '/pricing', { waitUntil:'load' });
  await page.locator('nav.nav [data-theme-toggle]').click();
  const wrong = [];
  for (const url of ['/en/', '/en/pricing', '/sign', '/en/sign', '/account', '/dashboard']) {
    await page.goto(ORIGIN + url, { waitUntil:'load' });
    const seen = await page.evaluate(groundOf);
    if (seen !== DARK) wrong.push(`${url}: ground is ${seen}, expected ${DARK}`);
  }
  await context.close();
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('on a phone the switch sits in the strip under the drawer, next to NL | EN', async () => {
  const wrong = [];
  for (const url of ['/', '/pricing', '/en/', '/auth/login']) {
    const context = await browser.newContext({ viewport:{ width:390, height:844 }, colorScheme:'light', hasTouch:true, isMobile:true });
    const page = await context.newPage();
    await signedOut(page);
    await page.goto(ORIGIN + url, { waitUntil:'load' });
    if (await page.locator('nav.nav [data-theme-toggle]').isVisible()) wrong.push(`${url}: the bar still shows the switch at 390px`);
    await page.locator('#nav-hamburger').click();
    const strip = page.locator('#nav-mobile-tail [data-theme-toggle]');
    if (!await strip.isVisible()) { wrong.push(`${url}: no switch in the open strip`); await context.close(); continue; }
    const row = await strip.evaluate((el) => !!el.parentElement.querySelector('.nav-lang'));
    if (!row) wrong.push(`${url}: the switch is not in the same row as NL | EN`);
    const box = await strip.boundingBox();
    if (!box || box.height < 44) wrong.push(`${url}: the switch is ${box && Math.round(box.height)}px high, under the 44px target`);
    await strip.tap();
    await settle(page);
    if (await page.evaluate(groundOf) !== DARK) wrong.push(`${url}: a tap in the strip did not make the page dark`);
    await context.close();
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('no flash: a reload in the dark edition has the dark ground before <body> exists', async () => {
  const wrong = [];
  for (const url of ['/', '/pricing', '/en/pricing', '/auth/login', '/sign', '/dashboard', '/partners']) {
    const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:'light' });
    await context.addInitScript((key) => {
      try { localStorage.setItem(key, 'dark'); } catch { /* storage off */ }
      // Record the state of <html> at the moment the parser creates <body>:
      // nothing can have been painted before that.
      window.__atBody = null;
      new MutationObserver((records, observer) => {
        if (!document.body) return;
        const html = document.documentElement;
        window.__atBody = { theme: html.getAttribute('data-theme'), ground: getComputedStyle(html).backgroundColor,
          fading: html.classList.contains('theme-fade') };
        observer.disconnect();
      }).observe(document, { childList:true, subtree:true });
    }, KEY);
    const page = await context.newPage();
    await signedIn(page);
    await page.goto(ORIGIN + url, { waitUntil:'load' });
    const at = await page.evaluate(() => window.__atBody);
    if (!at) wrong.push(`${url}: the moment <body> appeared was not observed`);
    else {
      if (at.theme !== 'dark') wrong.push(`${url}: <html data-theme="${at.theme}"> when <body> was created, expected "dark"`);
      if (at.ground !== DARK) wrong.push(`${url}: <html> ground was ${at.ground} when <body> was created, expected ${DARK}`);
      if (at.fading) wrong.push(`${url}: the colour fade ran on load`);
    }
    const fadingAfterLoad = await page.evaluate(() => document.documentElement.classList.contains('theme-fade'));
    if (fadingAfterLoad) wrong.push(`${url}: html.theme-fade is set after load; the fade belongs to a press only`);
    await context.close();
  }
  assert.deepEqual(wrong, [],
    '\n  The dark edition has to be in place before the first paint, or a reader\n' +
    '  who chose it sees a white flash on every page.\n\n  ' + wrong.join('\n  ') + '\n');
});

test('the fade runs on a press, and not under prefers-reduced-motion', async () => {
  const wrong = [];
  for (const reducedMotion of ['no-preference', 'reduce']) {
    const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:'light', reducedMotion });
    const page = await context.newPage();
    await signedOut(page);
    await page.goto(ORIGIN + '/pricing', { waitUntil:'load' });
    const during = await page.evaluate(() => {
      document.querySelector('nav.nav [data-theme-toggle]').click();
      const html = document.documentElement;
      return { fading: html.classList.contains('theme-fade'), transition: getComputedStyle(document.body).transitionDuration };
    });
    if (reducedMotion === 'reduce') {
      if (during.fading && during.transition !== '0s') wrong.push(`reduce: the body still transitions (${during.transition})`);
    } else {
      if (!during.fading) wrong.push('no-preference: html.theme-fade was not set on a press');
      const ms = Math.max(...during.transition.split(',').map((d) => parseFloat(d) * (d.includes('ms') ? 1 : 1000)));
      if (!(ms >= 150 && ms <= 200)) wrong.push(`no-preference: the fade is ${during.transition}, expected 150 to 200ms`);
    }
    await page.waitForTimeout(400);
    if (await page.evaluate(() => document.documentElement.classList.contains('theme-fade'))) wrong.push(`${reducedMotion}: html.theme-fade stayed on after the fade`);
    await context.close();
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test.after(async () => { await browser.close(); host.close(); });
