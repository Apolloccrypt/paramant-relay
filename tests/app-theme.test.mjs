// One theme in two editions, and who decides which one you get.
//
// History. On 2026-09-03 a dark operating system pulled the app screens into
// the night while the public pages stayed light, so a reader went from light
// to black by signing in. The gate that fixed it kept the whole site light
// unless someone chose dark on /account. Since 2026-09-23 (Mick: "net als EN
// en NL taal, ook een toggle die dark mode maakt") there is ONE dark set of
// tokens in design-system.css that every page follows, public and app alike,
// and a sun | moon switch beside NL | EN. The jump cannot come back, because
// there is no page left that stays light while another goes dark.
//
// The rule it measures, on every page:
//
//   no choice   -> the operating system decides (light unless it asks for dark)
//   'auto'      -> the same, chosen explicitly on /account
//   'light'     -> light, whatever the operating system says
//   'dark'      -> dark,  whatever the operating system says
//
// It has to be a browser: the answer is a cascade over a DOM state a script
// writes during head parsing. The last test takes the dark token block out and
// checks the screens stay light, so the suite cannot pass against a site that
// has no dark edition at all.

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

// The two page grounds, --ground in frontend/design-system.css.
const LIGHT = 'rgb(255, 255, 255)';
const DARK = 'rgb(14, 20, 27)';   // #0E141B, the dark edition

const TYPES = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.woff2':'font/woff2' };
const ROUTES = {
  '/dashboard':'/dashboard.html', '/account':'/account.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/':'/index.html',
  '/pricing':'/pricing.html', '/signup/verified':'/signup/verified.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html',
  '/auth/backup':'/auth/backup.html', '/auth/request-reset':'/auth/request-reset.html',
  '/auth/reset-confirm':'/auth/reset-confirm.html',
  '/en/':'/en/index.html', '/en/pricing':'/en/pricing.html', '/partners':'/partners.html',
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

// Serve the pages back with the dark token block renamed out of reach: the
// selector :root[data-theme="dark"] becomes one that never matches. With the
// choice 'dark' stored, the screens must then stay light, or the tests above
// are measuring something other than the tokens.
async function withoutTheDarkSet(page) {
  await page.route('**/*', async (route) => {
    const response = await route.fetch();
    const type = response.headers()['content-type'] || '';
    if (!/html|css/.test(type)) return route.fulfill({ response });
    const body = (await response.text())
      .split(':root[data-theme="dark"]').join(':root[data-theme="never"]')
      .split('html[data-theme="dark"]').join('html[data-theme="never"]');
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
  if (sabotage) await withoutTheDarkSet(page);   // catch-all first: newest handler wins
  await stubApi(page);
  await page.goto(ORIGIN + url, { waitUntil:'load' });
  await page.waitForTimeout(120);
  const seen = await page.evaluate(() => ({
    // The homepage paints its body with a gradient; its ground is then <html>.
    body: (() => { const b = getComputedStyle(document.body).backgroundColor;
      return b === 'rgba(0, 0, 0, 0)' ? getComputedStyle(document.documentElement).backgroundColor : b; })(),
    attribute: document.documentElement.getAttribute('data-theme'),
    chrome: (document.querySelector('meta[name="theme-color"]') || {}).content || null,
  }));
  await context.close();
  return seen;
}

// Every surface a reader meets after signing up, and the public pages with
// their English copies: since the one dark set, all of them follow the rule.
const APP = ['/dashboard', '/sign', '/parashare', '/account', '/auth/login', '/signup/verified'];
const MARKETING = ['/', '/pricing', '/en/', '/en/pricing', '/partners'];
const ALL = [...APP, ...MARKETING];

// Wait until the colour fade of a press is over (html.theme-fade gone, then
// one more frame), rather than for a fixed time a loaded CI runner may miss.
async function settle(page) {
  await page.waitForFunction(() => !document.documentElement.classList.contains('theme-fade'), null, { timeout:3000 });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });

test('no choice and a light system: every page is light', async () => {
  const wrong = [];
  for (const url of ALL) {
    const seen = await ground(browser, { url, system:'light', choice:null });
    if (seen.body !== LIGHT) wrong.push(`${url}: body is ${seen.body}, expected ${LIGHT}`);
    if (seen.attribute !== 'light') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "light"`);
  }
  assert.deepEqual(wrong, [], '\n  Light is the default.\n\n  ' + wrong.join('\n  ') + '\n');
});

test('no choice and a dark system: every page is dark, public and app alike', async () => {
  const wrong = [];
  for (const url of ALL) {
    const seen = await ground(browser, { url, system:'dark', choice:null });
    if (seen.body !== DARK) wrong.push(`${url}: body is ${seen.body}, expected ${DARK}`);
    if (seen.attribute !== 'dark') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "dark"`);
    if (seen.chrome !== '#0E141B') wrong.push(`${url}: theme-color is ${seen.chrome}, expected #0E141B`);
  }
  assert.deepEqual(wrong, [],
    '\n  A reader who never chose follows the system, and every page does it the same\n' +
    '  way, so signing in is never a jump from one edition to the other.\n\n  ' + wrong.join('\n  ') + '\n');
});

test('the choice "light" holds against a dark system', async () => {
  const wrong = [];
  for (const url of ALL) {
    const seen = await ground(browser, { url, system:'dark', choice:'light' });
    if (seen.body !== LIGHT) wrong.push(`${url}: body is ${seen.body}, expected ${LIGHT}`);
    if (seen.attribute !== 'light') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "light"`);
  }
  assert.deepEqual(wrong, [], '\n  ' + wrong.join('\n  ') + '\n');
});

test('the choice "dark" darkens every page, on a light system too', async () => {
  const wrong = [];
  for (const url of ALL) {
    const seen = await ground(browser, { url, system:'light', choice:'dark' });
    if (seen.body !== DARK) wrong.push(`${url}: body is ${seen.body}, expected ${DARK}`);
    if (seen.attribute !== 'dark') wrong.push(`${url}: <html data-theme="${seen.attribute}">, expected "dark"`);
    if (seen.chrome !== '#0E141B') wrong.push(`${url}: theme-color is ${seen.chrome}, expected #0E141B`);
  }
  assert.deepEqual(wrong, [],
    '\n  A dark mode nobody can switch on is not a dark mode.\n\n  ' + wrong.join('\n  ') + '\n');
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

  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), LIGHT,
    'a fresh browser starts light');

  // Click the label, the way a reader does: the radio itself is 0x0 by design
  // and the <span> is the 44px target (see .theme-choice in app-2026.css).
  await page.locator('#theme-choice input[value="dark"] + span').click();
  await settle(page);
  assert.equal(await page.locator('#theme-choice input[value="dark"]').isChecked(), true,
    'clicking the label must select the radio it belongs to');
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), DARK,
    'picking Dark must darken the page you are standing on');
  assert.equal(await page.evaluate((key) => window.localStorage.getItem(key), THEME_KEY), 'dark',
    'the choice must survive the next page load');

  // The sun | moon switch in the nav is the same mechanism: pressing it flips
  // the page back to light and the radios follow.
  await page.evaluate(() => { const b = document.querySelector('[data-theme-toggle]'); if (b) b.click(); });
  await settle(page);
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), LIGHT,
    'the nav switch must flip the page on /account too');
  assert.equal(await page.locator('#theme-choice input[value="light"]').isChecked(), true,
    'the radios on /account must follow the nav switch: one mechanism, two doors');
  await page.locator('#theme-choice input[value="dark"] + span').click();
  await settle(page);

  // And it comes back on the next screen, not just this one.
  await page.goto(ORIGIN + '/dashboard', { waitUntil:'load' });
  await settle(page);
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), DARK,
    'the choice must carry to the other app screens');

  await context.close();
});

// ── every app page carries the script, so a new one cannot forget it ─────────

test('every page that loads the shared stylesheets also loads the theme script', () => {
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
    if (!html.includes('/app-2026.css') && !html.includes('/design-system.css')) continue;
    const head = html.slice(0, html.indexOf('</head>'));
    if (!/<script src="\/js\/theme\.js\?v=\d+"><\/script>/.test(head)) {
      missing.push(`${path.relative(ROOT, page)} loads the shared stylesheets but not /js/theme.js in its <head>`);
    }
  }
  assert.deepEqual(missing, [],
    '\n  Without the script in the head the page cannot honour a choice before the\n' +
    '  first paint, and a reader who picked dark gets a light page or a flash.\n\n  ' +
    missing.join('\n  ') + '\n');
});

// ── the sabotage ─────────────────────────────────────────────────────────────

test('sabotage: with the dark token block out of reach the choice "dark" does nothing', async () => {
  const stillDark = [];
  for (const url of ALL) {
    const seen = await ground(browser, { url, system:'light', choice:'dark', sabotage:true });
    if (seen.body === DARK) stillDark.push(`${url}: body is ${seen.body} without the dark set`);
  }
  assert.deepEqual(stillDark, [],
    '\n  The dark token block was renamed out of reach and the page went dark anyway,\n' +
    '  so the tests above are not measuring the one dark set. A second dark palette\n' +
    '  lives somewhere else.\n\n  ' + stillDark.join('\n  ') + '\n');
});

test.after(async () => { await browser.close(); host.close(); });
