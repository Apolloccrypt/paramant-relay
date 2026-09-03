// The night is the ground. The paper is a choice, never a jump.
//
// What this file measured before the night edition was the opposite case: with
// prefers-color-scheme: dark and nobody having chosen anything, the app screens
// went to rgb(10, 15, 22) while the marketing pages stayed creme, so signing in
// threw a reader from creme to black. The site now stands on one ground on
// every page, so that jump cannot happen at all: /index, /pricing, /dashboard,
// /sign, /parashare, /account and /auth/login all come up on the same warm
// night. What is left to guard is the mirror image of the old rule, and the
// switch on /account that carries it.
//
// The rule it measures:
//
//   no choice   -> the night, whatever the operating system says
//   'dark'      -> the night, whatever the operating system says
//   'light'     -> the cream paper, whatever the operating system says
//   'auto'      -> the operating system decides, because someone asked it to
//
// and the marketing pages stay on the night in every one of those cases, which
// is what the text next to the switch on /account says.
//
// It has to be a browser. The gate is a media query scoped to an attribute that
// a script writes during head parsing, so the answer is a cascade over a DOM
// state, and only the browser can flatten those into one background colour.
//
// The last test in the file takes the gate out and checks the screens go light
// again on a light system. Without that, a suite like this one passes just as
// happily against a site that has no second theme at all.

import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const THEME_KEY = 'paramant.theme.v1';

// The two page grounds, from --paper in frontend/app-2026.css.
const LIGHT = 'rgb(241, 234, 214)';
const DARK = 'rgb(21, 25, 28)';

const TYPES = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.woff2':'font/woff2' };
const ROUTES = {
  '/dashboard':'/dashboard.html', '/account':'/account.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/':'/index.html',
  '/pricing':'/pricing.html', '/signup/verified':'/signup/verified.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html',
  '/auth/backup':'/auth/backup.html', '/auth/request-reset':'/auth/request-reset.html',
  '/auth/reset-confirm':'/auth/reset-confirm.html',
};

const host = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (ROUTES[pathname]) pathname = ROUTES[pathname];
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => host.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${host.address().port}`;

// Enough of the API for the signed-in screens to render something. The ground
// colour does not depend on any of it; this only keeps the pages from sitting
// in a spinner and timing out.
const SESSION = {
  email:'demo@example.com', label:'Demo', plan:'community', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:new Date(Date.now() + 30 * 86400000).toISOString(),
  usage_purpose:'organisation', api_key_masked:'pgp_****', sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};

async function stubApi(page) {
  await page.route('**/api/user/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
  await page.route('**/api/user/me', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(SESSION) }));
  await page.route('**/api/user/account', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(SESSION) }));
  await page.route('**/api/user/documents**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
}

// Serve the pages back with the gate taken out: [data-theme="auto"] becomes a
// :not([data-theme="dark"]), in the stylesheet and in every page's critical
// <style>. That is a site whose second theme follows the operating system on
// its own, and under a light system with no choice made it must go light.
async function withoutTheGate(page) {
  await page.route('**/*', async (route) => {
    const response = await route.fetch();
    const type = response.headers()['content-type'] || '';
    if (!/html|css/.test(type)) return route.fulfill({ response });
    const body = (await response.text()).split('[data-theme="auto"]').join(':not([data-theme="dark"])');
    return route.fulfill({ response, body });
  });
}

// One measurement: open `url` with the operating system set to `system`, having
// stored `choice` (null = the reader never touched the switch), and report the
// flattened background of <body> plus what <html> ended up carrying.
async function ground(browser, { url, system, choice, sabotage = false }) {
  const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:system });
  if (choice !== null) {
    await context.addInitScript(([key, value]) => {
      try { window.localStorage.setItem(key, value); } catch { /* storage off */ }
    }, [THEME_KEY, choice]);
  }
  const page = await context.newPage();
  if (sabotage) await withoutTheGate(page);   // catch-all first: newest handler wins
  await stubApi(page);
  await page.goto(ORIGIN + url, { waitUntil:'load' });
  await page.waitForTimeout(120);
  const seen = await page.evaluate(() => ({
    body: getComputedStyle(document.body).backgroundColor,
    attribute: document.documentElement.getAttribute('data-theme'),
    chrome: (document.querySelector('meta[name="theme-color"]') || {}).content || null,
  }));
  await context.close();
  return seen;
}

// The five screens the measurement of 2026-09-03 named, plus /signup/verified,
// which you land on straight from the mail link and which loads the same app
// stylesheet. Together that is every surface a reader meets after signing up.
const APP = ['/dashboard', '/sign', '/parashare', '/account', '/auth/login', '/signup/verified'];
const MARKETING = ['/', '/pricing'];

const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

test('a light system with no choice made leaves every app screen on the night', async () => {
  const wrong = [];
  for (const url of APP) {
    const seen = await ground(browser, { url, system:'light', choice:null });
    if (seen.body !== DARK) wrong.push(`${url}: body is ${seen.body}, expected ${DARK}`);
    if (seen.attribute !== null) wrong.push(`${url}: <html data-theme="${seen.attribute}"> without anyone choosing it`);
    if (seen.chrome !== '#15191C') wrong.push(`${url}: theme-color is ${seen.chrome}, expected #15191C`);
  }
  assert.deepEqual(wrong, [],
    '\n  A light operating system must not lift the app off the night on its own.\n' +
    '  The night is the ground of the whole site; the paper is asked for.\n\n  ' +
    wrong.join('\n  ') + '\n');
});

test('the choice "light" holds against a dark system', async () => {
  const wrong = [];
  for (const url of APP) {
    const seen = await ground(browser, { url, system:'dark', choice:'light' });
    if (seen.body !== LIGHT) wrong.push(`${url}: body is ${seen.body}, expected ${LIGHT}`);
    if (seen.attribute !== 'light') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "light"`);
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('the choice "dark" darkens every app screen, on a light system too', async () => {
  const wrong = [];
  for (const url of APP) {
    const seen = await ground(browser, { url, system:'light', choice:'dark' });
    if (seen.body !== DARK) wrong.push(`${url}: body is ${seen.body}, expected ${DARK}`);
    if (seen.attribute !== 'dark') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "dark"`);
    if (seen.chrome !== '#15191C') wrong.push(`${url}: theme-color is ${seen.chrome}, expected #15191C`);
  }
  assert.deepEqual(wrong, [],
    '\n  A choice nobody can make is not a choice.\n\n  ' + wrong.join('\n  ') + '\n');
});

test('the choice "auto" hands the decision back to the operating system', async () => {
  const wrong = [];
  for (const url of APP) {
    const dark = await ground(browser, { url, system:'dark', choice:'auto' });
    if (dark.body !== DARK) wrong.push(`${url} on a dark system: body is ${dark.body}, expected ${DARK}`);
    const light = await ground(browser, { url, system:'light', choice:'auto' });
    if (light.body !== LIGHT) wrong.push(`${url} on a light system: body is ${light.body}, expected ${LIGHT}`);
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('the marketing pages stay on the night in every case, which is what /account promises', async () => {
  const wrong = [];
  for (const url of MARKETING) {
    for (const choice of [null, 'auto', 'light']) {
      const seen = await ground(browser, { url, system:'light', choice });
      // The homepage paints its ground with a gradient, so its computed
      // backgroundColor is transparent and never equals a hex. What matters is
      // that it never becomes the paper.
      if (seen.body === LIGHT) wrong.push(`${url} with choice ${choice}: body is ${seen.body}, which is the paper`);
    }
  }
  assert.deepEqual(wrong, [],
    '\n  The switch on /account says the public pages stay on the night. Either the\n' +
    '  pages changed or the sentence has to.\n\n  ' + wrong.join('\n  ') + '\n');
});

// ── the switch itself ────────────────────────────────────────────────────────

test('/account offers the three choices and picking one repaints the page', async () => {
  const context = await browser.newContext({ viewport:{ width:1280, height:800 }, colorScheme:'light' });
  const page = await context.newPage();
  await stubApi(page);
  await page.goto(ORIGIN + '/account', { waitUntil:'load' });
  await page.locator('#theme-choice').waitFor({ timeout:6000 });

  const values = await page.locator('#theme-choice input[name="appearance"]').evaluateAll(
    (nodes) => nodes.map((node) => node.value));
  assert.deepEqual(values, ['auto', 'light', 'dark'], 'the switch must offer exactly Systeem / Licht / Donker');

  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), DARK,
    'a fresh browser starts on the night');

  // Click the label, the way a reader does: the radio itself is 0x0 by design
  // and the <span> is the 44px target (see .theme-choice in app-2026.css).
  await page.locator('#theme-choice input[value="light"] + span').click();
  await page.waitForTimeout(120);
  assert.equal(await page.locator('#theme-choice input[value="light"]').isChecked(), true,
    'clicking the label must select the radio it belongs to');
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), LIGHT,
    'picking Light must repaint the page you are standing on');
  assert.equal(await page.evaluate((key) => window.localStorage.getItem(key), THEME_KEY), 'light',
    'the choice must survive the next page load');

  // And it comes back on the next screen, not just this one.
  await page.goto(ORIGIN + '/dashboard', { waitUntil:'load' });
  await page.waitForTimeout(120);
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), LIGHT,
    'the choice must carry to the other app screens');

  await context.close();
});

// ── every app page carries the script, so a new one cannot forget it ─────────

test('every page that loads app-2026.css also loads the theme script', () => {
  const pages = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes:true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (entry.name !== 'node_modules' && entry.name !== 'vendor') walk(full); }
      else if (entry.name.endsWith('.html')) pages.push(full);
    }
  };
  walk(ROOT);

  const missing = [];
  for (const page of pages) {
    const html = fs.readFileSync(page, 'utf8');
    if (!html.includes('/app-2026.css')) continue;
    if (!/<script src="\/js\/theme\.js\?v=\d+"><\/script>/.test(html)) {
      missing.push(`${path.relative(ROOT, page)} loads the app stylesheet but not /js/theme.js`);
    }
  }
  assert.deepEqual(missing, [],
    '\n  Without the script the page cannot honour a choice, and a reader who\n' +
    '  picked dark lands on one light screen in the middle of the app.\n\n  ' +
    missing.join('\n  ') + '\n');
});

// ── the sabotage ─────────────────────────────────────────────────────────────

test('sabotage: with the [data-theme="auto"] gate removed the screens go light again', async () => {
  const stillNight = [];
  for (const url of APP) {
    const seen = await ground(browser, { url, system:'light', choice:null, sabotage:true });
    if (seen.body !== LIGHT) stillNight.push(`${url}: body is ${seen.body}, expected ${LIGHT} without the gate`);
  }
  assert.deepEqual(stillNight, [],
    '\n  The gate was taken out and the screens stayed on the night anyway, so the\n' +
    '  four tests above are not measuring the thing they claim to measure. Either\n' +
    '  the paper tokens moved somewhere this rewrite no longer reaches, or the\n' +
    '  second theme is gone.\n\n  ' + stillNight.join('\n  ') + '\n');
});

test.after(async () => { await browser.close(); host.close(); });
