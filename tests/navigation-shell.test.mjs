import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/account':'/account.html', '/developer':'/developer.html' };
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

const publicPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await publicPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await publicPage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await publicPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Product,Security,Pricing,Docs');
const publicDesktop = await publicPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('public navigation has four clear destinations', JSON.stringify(publicDesktop) === JSON.stringify(['Product','Security','Pricing','Docs']), publicDesktop.join(', '));
// The signed-out hero now offers ONE primary action and one secondary, not
// three. Three equal buttons is three decisions before the visitor knows what
// the product is; ParaSend keeps its own call to action further down the page,
// where it is next to the three lines that explain it.
ok('public homepage leads with one primary action and one secondary', JSON.stringify(await publicPage.locator('[data-home="out"] .home-actions a').evaluateAll((nodes) => nodes.map((node) => node.getAttribute('href')))) === JSON.stringify(['/sign','/pricing']), await publicPage.locator('[data-home="out"] .home-actions').innerText());
// Both product PAGES have to be reachable from the homepage, not just the two
// apps. /parasend shipped with no inbound link anywhere on the site and
// /parasign had exactly one, from /sign: a product page nothing links to is a
// page a buyer never sees. So the two-products section now leads with the page
// that explains the product and keeps the app as the second action, and this
// pins the order: explain first, app second, per card.
await (async () => {
  const ctas = await publicPage.locator('#products .prod-cta a').evaluateAll((nodes) => nodes.map((node) => node.getAttribute('href')));
  ok('the homepage leads to both product pages, with the apps as the second action', JSON.stringify(ctas) === JSON.stringify(['/parasign','/sign','/parasend','/parashare']), await publicPage.locator('#products').innerText());
  ok('the homepage still routes to ParaSend from its own section', ctas.includes('/parashare'), await publicPage.locator('#products').innerText());
})();
// The guarantee is that the bar is OPAQUE and unblurred on a phone: on iOS
// Safari a backdrop-filter over the dark hero renders see-through and the hero
// showed through the top of the open menu. This used to be pinned to the
// literal rgb(248, 250, 252), which is one palette's page colour and not the
// property that matters; a theme change then reads as a nav regression, and a
// dark theme could never satisfy it at all. Pinned to the page's own surface
// token instead: fully opaque (alpha 1), no blur, and the same colour the page
// itself is painted in, so a bar that stops matching its own page still fails.
const publicMobilePaint = await publicPage.locator('nav.nav').evaluate((node) => {
  const surface = getComputedStyle(document.documentElement).getPropertyValue('--paper').trim()
    || getComputedStyle(document.documentElement).getPropertyValue('--bone').trim();
  const probe = document.createElement('span');
  probe.style.cssText = `position:absolute;visibility:hidden;background:${surface}`;
  document.body.appendChild(probe);
  const pageSurface = getComputedStyle(probe).backgroundColor;
  probe.remove();
  return {
    background: getComputedStyle(node).backgroundColor,
    pageSurface,
    backdropFilter: getComputedStyle(node).backdropFilter,
    webkitBackdropFilter: getComputedStyle(node).getPropertyValue('-webkit-backdrop-filter'),
  };
});
ok('mobile navigation is opaque before opening the menu',
  /^rgb\(\d+, \d+, \d+\)$/.test(publicMobilePaint.background)
  && publicMobilePaint.background === publicMobilePaint.pageSurface
  && publicMobilePaint.backdropFilter === 'none'
  && (!publicMobilePaint.webkitBackdropFilter || publicMobilePaint.webkitBackdropFilter === 'none'),
  JSON.stringify(publicMobilePaint));
await publicPage.locator('#nav-hamburger').click();
await publicPage.waitForFunction(() => {
  const nav = document.querySelector('nav.nav')?.getBoundingClientRect();
  const menu = document.querySelector('#nav-mobile')?.getBoundingClientRect();
  return nav && menu && Math.abs(menu.top - nav.bottom) < 0.5;
});
const publicMobile = await publicPage.locator('#nav-mobile a').allInnerTexts();
const publicMobileGeometry = await publicPage.evaluate(() => {
  const meta = document.querySelector('.meta-bar');
  const nav = document.querySelector('nav.nav').getBoundingClientRect();
  const menu = document.querySelector('#nav-mobile').getBoundingClientRect();
  return {
    metaDisplay: meta ? getComputedStyle(meta).display : 'absent',
    navTop: nav.top,
    navBottom: nav.bottom,
    menuTop: menu.top,
  };
});
ok('mobile menu has no technical strip or gap above it', publicMobileGeometry.metaDisplay === 'none' && publicMobileGeometry.navTop === 0 && Math.abs(publicMobileGeometry.menuTop - publicMobileGeometry.navBottom) < 0.5, JSON.stringify(publicMobileGeometry));
ok('public mobile menu matches desktop without legacy groups', publicMobile.map((item) => item.toLowerCase()).join(',') === publicDesktop.map((item) => item.toLowerCase()).join(',') && await publicPage.locator('#nav-mobile .nav-mobile-group').count() === 0, publicMobile.join(', '));
ok('public mobile menu fits the phone viewport', await publicPage.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), await publicPage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
await publicPage.locator('#nav-hamburger').click();
await publicPage.evaluate(() => {
  document.documentElement.style.scrollBehavior = 'auto';
  window.scrollTo(0, 450);
});
await publicPage.waitForFunction(() => window.scrollY === 450);
await publicPage.evaluate(() => document.querySelector('#nav-hamburger').click());
await publicPage.waitForFunction(() => {
  const nav = document.querySelector('nav.nav')?.getBoundingClientRect();
  const menu = document.querySelector('#nav-mobile')?.getBoundingClientRect();
  return getComputedStyle(document.body).position === 'fixed' && nav && menu && Math.abs(menu.top - nav.bottom) < 0.5;
});
const scrolledMenuGeometry = await publicPage.evaluate(() => {
  const nav = document.querySelector('nav.nav').getBoundingClientRect();
  const menu = document.querySelector('#nav-mobile').getBoundingClientRect();
  return {
    navTop: nav.top,
    navBottom: nav.bottom,
    menuTop: menu.top,
    bodyPosition: getComputedStyle(document.body).position,
    bodyTop: getComputedStyle(document.body).top,
  };
});
ok('mobile menu stays attached when opened after scrolling', scrolledMenuGeometry.navTop === 0 && Math.abs(scrolledMenuGeometry.menuTop - scrolledMenuGeometry.navBottom) < 0.5 && scrolledMenuGeometry.bodyPosition === 'fixed' && scrolledMenuGeometry.bodyTop === '-450px', JSON.stringify(scrolledMenuGeometry));
await publicPage.evaluate(() => document.querySelector('#nav-hamburger').click());
ok('closing the mobile menu restores the page position', await publicPage.evaluate(() => window.scrollY === 450 && getComputedStyle(document.body).position !== 'fixed'), await publicPage.evaluate(() => JSON.stringify({ scrollY:window.scrollY, bodyPosition:getComputedStyle(document.body).position })));
const phoneHelp = await publicPage.evaluate(() => {
  const link = document.querySelector('nav.nav a[href="/help"]');
  if (!link) return { found:false };
  const box = link.getBoundingClientRect();
  return { found:true, display:getComputedStyle(link).display, width:box.width, height:box.height };
});
ok('support is reachable on a phone', phoneHelp.found && phoneHelp.display !== 'none' && phoneHelp.width > 0 && phoneHelp.height > 0, JSON.stringify(phoneHelp));
await publicPage.close();

const tabletPage = await browser.newPage({ viewport:{ width:820, height:1180 } });
await tabletPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await tabletPage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await tabletPage.waitForSelector('nav.nav a[href="/help"]');
const tabletHelp = await tabletPage.evaluate(() => {
  const link = document.querySelector('nav.nav a[href="/help"]');
  const box = link.getBoundingClientRect();
  return { display:getComputedStyle(link).display, width:box.width, height:box.height };
});
ok('support is reachable on a tablet', tabletHelp.display !== 'none' && tabletHelp.width > 0 && tabletHelp.height > 0, JSON.stringify(tabletHelp));
await tabletPage.close();

// Static contract, no browser needed. The mobile drawer mirrors the four nav
// links and carries no Help entry, so every stamped page must keep the /help
// link in the bar itself. Pages without a footer must still name the three
// legal documents; apply-nav.py stamps a legal strip there.
// Application shells keep their own narrower nav and reach Help through the
// signed-in user menu; apply-nav.py names them and this test reads that list
// rather than repeating it.
const generatorSource = fs.readFileSync(path.join(ROOT, 'apply-nav.py'), 'utf8');
const keepOwnNav = new Set(Array.from((generatorSource.match(/KEEP_OWN_NAV = \{([^}]*)\}/) || [null, ''])[1].matchAll(/'([^']+)'/g), (match) => match[1]));
const stamped = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes:true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.html')) {
      const html = fs.readFileSync(full, 'utf8');
      const name = path.relative(ROOT, full).split(path.sep).join('/');
      if (html.includes('<nav class="nav">') && html.includes('id="nav-auth"') && !keepOwnNav.has(name)) stamped.push([name, html]);
    }
  }
})(ROOT);
const withoutHelp = stamped.filter(([, html]) => !/<a href="\/help"/.test(html)).map(([name]) => name);
ok('every stamped page links support', stamped.length > 0 && withoutHelp.length === 0, withoutHelp.join(', ') || `${stamped.length} pages`);
const withoutLegal = stamped.filter(([, html]) => !['/privacy', '/dpa', '/terms'].every((href) => html.includes(`href="${href}"`))).map(([name]) => name);
ok('every stamped page names privacy, dpa and terms', withoutLegal.length === 0, withoutLegal.join(', ') || `${stamped.length} pages`);

const homePage = await browser.newPage({ viewport:{ width:390, height:844 } });
await homePage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await homePage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await homePage.locator('[data-home="in"]:not([hidden])').waitFor();
await homePage.locator('.nav-user').waitFor();
ok('signed-in homepage leads to the document workspace', JSON.stringify(await homePage.locator('[data-home="in"] .home-actions a').evaluateAll((nodes) => nodes.map((node) => node.getAttribute('href')))) === JSON.stringify(['/dashboard','/sign','/parashare']), await homePage.locator('[data-home="in"] .home-actions').innerText());
if (process.env.PARAMANT_HOME_SCREENSHOT_PATH) await homePage.screenshot({ path:process.env.PARAMANT_HOME_SCREENSHOT_PATH });
await homePage.close();

const appPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appPage.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","label":"Demo","plan":"pro","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","usage_purpose":"organisation"}' }));
await appPage.route('**/api/user/documents', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
await appPage.route('**/api/user/account/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
await appPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Documents,Send,Sign,Verify,Settings');
const appDesktop = await appPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('signed-in navigation follows document work', JSON.stringify(appDesktop) === JSON.stringify(['Documents','Send','Sign','Verify','Settings']), appDesktop.join(', '));
ok('dashboard removes its duplicate marketing drawer', await appPage.locator('#nav-mobile-marketing').count() === 0 && await appPage.locator('nav.nav .nav-links').count() === 1, await appPage.locator('nav.nav .nav-links').count());
await appPage.locator('#nav-hamburger').click();
const appMobile = await appPage.locator('#nav-mobile a').allInnerTexts();
ok('signed-in mobile menu matches the workspace', appMobile.map((item) => item.toLowerCase()).join(',') === appDesktop.map((item) => item.toLowerCase()).join(','), appMobile.join(', '));
ok('developer tools are settings, not a sixth product', await appPage.locator('.nav-user-menu a', { hasText:'Developer settings' }).count() === 1 && !appMobile.includes('Developer settings'), appMobile.join(', '));
await appPage.close();

const accountPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await accountPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await accountPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await accountPage.route('**/api/user/account', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","api_key_masked":"pgp_demo...","plan":"pro","label":"Demo","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","sessions":[]}' }));
await accountPage.route('**/api/user/billing/status', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"current_plan":"pro"}' }));
await accountPage.goto(ORIGIN + '/account', { waitUntil:'domcontentloaded' });
await accountPage.locator('#state-account:not(.hidden)').waitFor();
await accountPage.locator('.nav-user').waitFor();
ok('account, billing and developer are one settings hierarchy', JSON.stringify(await accountPage.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account & security','Plan & billing','Developer settings']) && await accountPage.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/account', await accountPage.locator('.settings-tabs').innerText());
ok('legacy account key is advanced instead of the first task', await accountPage.locator('details.acct-advanced:not([open])').count() === 1 && await accountPage.locator('.acct-card:not(.acct-advanced)').first().locator('h2').innerText() === 'Security.', await accountPage.locator('main').innerText());
ok('billing settings do not claim live checkout is a stub', !/stub mode|no real payments/i.test(await accountPage.locator('#billing-section').innerText()), await accountPage.locator('#billing-section').innerText());
ok('account action describes deactivation instead of erasure', /account record is retained/i.test(await accountPage.locator('.acct-card.danger').innerText()) && !/permanent|delete account/i.test(await accountPage.locator('.acct-card.danger').innerText()), await accountPage.locator('.acct-card.danger').innerText());
ok('settings fit the phone viewport', await accountPage.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), await accountPage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
if (process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH) await accountPage.screenshot({ path:process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH, fullPage:true });
await accountPage.close();

const developerPage = await browser.newPage({ viewport:{ width:1280, height:900 } });
await developerPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await developerPage.route('**/api/developer/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await developerPage.goto(ORIGIN + '/developer', { waitUntil:'domcontentloaded' });
await developerPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Documents,Send,Sign,Verify,Settings');
const developerNav = await developerPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('developer page is presented as settings inside the same shell', await developerPage.title() === 'Developer settings · Paramant' && developerNav.map((item) => item.toLowerCase()).join(',') === 'documents,send,sign,verify,settings', await developerPage.title());
ok('developer page shares the settings hierarchy', JSON.stringify(await developerPage.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account & security','Plan & billing','Developer settings']) && await developerPage.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/developer', await developerPage.locator('.settings-tabs').innerText());
await developerPage.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nnavigation-shell: ${checks.length} checks passed`);
