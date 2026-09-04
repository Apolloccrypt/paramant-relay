import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/account':'/account.html', '/developer':'/developer.html', '/pricing':'/pricing.html', '/parashare':'/parashare.html', '/help':'/help/index.html' };
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
await publicPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Product,Gereedschap,Security,Pricing,Docs');
const publicDesktop = await publicPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
// The bar carries the free tools as their own destination. Everything a
// visitor can use without an account lived one level down, behind /pricing or
// a body link, so the page that collects it was the least reachable thing on
// the site. It is the front door of the ladder, so it sits next to Product.
ok('public navigation names its destinations, including the free tools', JSON.stringify(publicDesktop) === JSON.stringify(['Product','Gereedschap','Security','Pricing','Docs']), publicDesktop.join(', '));
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
const publicMobilePaint = await publicPage.locator('nav.nav').evaluate((node) => ({
  background: getComputedStyle(node).backgroundColor,
  backdropFilter: getComputedStyle(node).backdropFilter,
  webkitBackdropFilter: getComputedStyle(node).getPropertyValue('-webkit-backdrop-filter'),
  paper: getComputedStyle(document.body).backgroundColor,
}));
// The pin was loosened to "any opaque rgb" while the homepage painted the bar
// itself and the rest of the site was still bone. The night is the design
// system now, so the bar has one colour on every page again and the hex can be
// named: nav.css paints it with --bone under 1024px, and --bone is the night.
ok('mobile navigation is opaque before opening the menu', publicMobilePaint.background === 'rgb(21, 25, 28)' && publicMobilePaint.backdropFilter === 'none' && (!publicMobilePaint.webkitBackdropFilter || publicMobilePaint.webkitBackdropFilter === 'none'), JSON.stringify(publicMobilePaint));
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
// What this asks is "no technical strip above the nav", and there are two ways
// to satisfy it: the strip is styled away, or it is not in the page at all.
// Only the first was accepted, so the homepage had to keep an empty
// <div class="meta-bar" hidden></div> purely to keep this green, which is a
// test dictating markup rather than describing the result. The strip itself is
// gone from every page now, so 'absent' is the normal answer and 'none' stays
// valid for a page that still carries one and hides it. What is NOT optional is
// the geometry: the nav starts at the top of the viewport and the drawer hangs
// off its bottom with no gap, which is what turns red if a visible strip
// returns.
ok('mobile menu has no technical strip or gap above it', (publicMobileGeometry.metaDisplay === 'absent' || publicMobileGeometry.metaDisplay === 'none') && publicMobileGeometry.navTop === 0 && Math.abs(publicMobileGeometry.menuTop - publicMobileGeometry.navBottom) < 0.5, JSON.stringify(publicMobileGeometry));
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
// Support on a phone. This used to demand a visible /help link in the closed
// bar, which is why Help was the fifth element up there, shrunk to 9px type to
// make it fit. The requirement is that a visitor looking for support finds a
// working route, not that the route lives on one particular surface: it is now
// the first thing under the four destinations when the menu is open, at 48px
// tall instead of 9px wide. The static contract below still demands the link
// in the stamped markup of every page, so it can never quietly disappear.
await publicPage.locator('#nav-hamburger').click();
await publicPage.waitForFunction(() => document.querySelector('#nav-mobile')?.classList.contains('open'));
const phoneHelp = await publicPage.evaluate(() => {
  const links = Array.from(document.querySelectorAll('nav.nav a[href="/help"], .nav-mobile-tail a[href="/help"]'));
  return links.map((link) => {
    const box = link.getBoundingClientRect();
    return { display:getComputedStyle(link).display, width:Math.round(box.width), height:Math.round(box.height) };
  });
});
ok('support is reachable on a phone', phoneHelp.some((link) => link.display !== 'none' && link.width > 0 && link.height >= 44), JSON.stringify(phoneHelp));
await publicPage.locator('#nav-hamburger').click();
await publicPage.close();

// Two reviews of the phone, a week apart, named the same thing: the bar was
// full. Logo, Help, Sign in, Create account and the hamburger, five elements
// on 390px, with the button and the hamburger both starting at x=330 and no
// air between them. So the bar is measured now, and not by eye: what is in it,
// how far apart, and how big a thumb's worth of it there is.
//
// It is measured on three pages, not on the homepage alone. The bar is shared,
// but not every page gets it from the generator: developer.html keeps its own
// (KEEP_OWN_NAV in frontend/apply-nav.py) and is stamped by hand, which is
// exactly where the first round of this went wrong. A check that only ever
// looks at / cannot see that.
for (const route of ['/', '/pricing', '/developer']) {
  const barPage = await browser.newPage({ viewport:{ width:390, height:844 } });
  await barPage.route('**/api/user/session/verify', (call) => call.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
  await barPage.goto(ORIGIN + route, { waitUntil:'domcontentloaded' });
  await barPage.locator('nav.nav .nav-cta').waitFor();
  const bar = await barPage.evaluate(() => {
    const items = Array.from(document.querySelectorAll('nav.nav a, nav.nav button'))
      .filter((node) => {
        const box = node.getBoundingClientRect();
        return getComputedStyle(node).display !== 'none' && box.width > 0 && box.height > 0;
      })
      .map((node) => {
        const box = node.getBoundingClientRect();
        return { label:node.textContent.trim().slice(0, 24) || node.getAttribute('aria-label'), left:Math.round(box.left), right:Math.round(box.right), height:Math.round(box.height) };
      })
      .sort((first, second) => first.left - second.left);
    return { items, gaps:items.slice(1).map((item, index) => Math.round(item.left - items[index].right)) };
  });
  ok(`the phone bar of ${route} carries one action beside the menu button`, bar.items.length <= 3, JSON.stringify(bar.items));
  ok(`nothing in the phone bar of ${route} touches its neighbour`, bar.gaps.length > 0 && bar.gaps.every((gap) => gap >= 12), JSON.stringify(bar));
  ok(`every target in the phone bar of ${route} is finger-sized`, bar.items.every((item) => item.height >= 44), JSON.stringify(bar.items));

  // And what the bar handed over has somewhere to land. Sign in and Help leave
  // the bar below 700px, so on these pages the drawer strip is the only route
  // to either, and both must be a real tap target.
  await barPage.locator('#nav-hamburger').click();
  await barPage.waitForFunction(() => document.querySelector('#nav-mobile-tail')?.classList.contains('open'));
  const handover = await barPage.evaluate(() => Array.from(document.querySelectorAll('#nav-mobile-tail a')).map((link) => {
    const box = link.getBoundingClientRect();
    return { href:link.getAttribute('href'), height:Math.round(box.height), width:Math.round(box.width) };
  }));
  ok(`${route} keeps sign in and support one tap away`, ['/auth/login', '/help'].every((href) => handover.some((link) => link.href === href && link.height >= 44 && link.width > 0)), JSON.stringify(handover));
  await barPage.close();
}

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
// links and carries no Help entry of its own; the link lives in the bar and,
// on a phone, in the strip under the drawer. Either way it must be in the
// stamped markup of every page. Pages without a footer must still name the three
// legal documents; apply-nav.py stamps a legal strip there.
// Application shells keep their own narrower nav and reach Help through the
// signed-in user menu; apply-nav.py names them and this test reads that list
// rather than repeating it.
const generatorSource = fs.readFileSync(path.join(ROOT, 'apply-nav.py'), 'utf8');
const keepOwnNav = new Set(Array.from((generatorSource.match(/KEEP_OWN_NAV = \{([^}]*)\}/) || [null, ''])[1].matchAll(/'([^']+)'/g), (match) => match[1]));
const stamped = [];
const everyPage = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes:true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.html')) {
      const html = fs.readFileSync(full, 'utf8');
      const name = path.relative(ROOT, full).split(path.sep).join('/');
      everyPage.push([name, html]);
      if (html.includes('<nav class="nav">') && html.includes('id="nav-auth"') && !keepOwnNav.has(name)) stamped.push([name, html]);
    }
  }
})(ROOT);

// A hamburger is a promise: below 700px Sign in and Help leave the bar, and the
// strip under the drawer is where they land. A page with the button and without
// the strip has no route to either, and that is not hypothetical. developer.html
// keeps its own nav, is stamped by hand, and shipped exactly like that: on a
// 390px screen both links measured 0x0. This runs over every page in frontend/,
// not only the generated ones, because the generated ones were never the
// problem.
const hamburgerWithoutTail = everyPage
  .filter(([, html]) => html.includes('id="nav-hamburger"') && !html.includes('id="nav-mobile-tail"'))
  .map(([name]) => name);
ok('no page carries a menu button without the strip that catches what it takes away', hamburgerWithoutTail.length === 0, hamburgerWithoutTail.join(', ') || `${everyPage.filter(([, html]) => html.includes('id="nav-hamburger"')).length} pages with a menu button`);
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
// And the hero is where the signed-in homepage ENDS. Under it sat the whole
// sales page -- why half of it is free, the two products, the price table, the
// founder letter -- so a customer who had already bought got three actions and
// then eight screens of pitch on a phone. js/home-auth.js stamps
// data-session="in" on <html> and the page hides the rest off that one
// attribute in CSS; this measures what is on screen rather than the attribute,
// because the attribute being set is not the thing anyone cares about.
const homeSections = await homePage.evaluate(() => {
  const visible = Array.from(document.querySelectorAll('main > section'))
    .filter((section) => getComputedStyle(section).display !== 'none')
    .map((section) => section.className || section.id || section.tagName);
  return {
    session: document.documentElement.getAttribute('data-session'),
    visible,
    total: document.querySelectorAll('main > section').length,
    scrollHeight: document.documentElement.scrollHeight,
  };
});
ok('the signed-in homepage stops after the hero', homeSections.total > 1 && JSON.stringify(homeSections.visible) === JSON.stringify(['home-hero']), JSON.stringify(homeSections));
// Mick, 4 September: one note is enough. The founder line left both hero states,
// so what the signed-in hero has to carry is the workspace a customer came for.
ok('the signed-in hero opens on the documents', (await homePage.locator('[data-home="in"]').innerText()).includes('Your documents'), await homePage.locator('[data-home="in"]').innerText());
if (process.env.PARAMANT_HOME_SCREENSHOT_PATH) await stableScreenshot(homePage, { path:process.env.PARAMANT_HOME_SCREENSHOT_PATH });
await homePage.close();

// Signed OUT, nothing above applies and the page is the page it was: the whole
// pitch, in order, with no attribute on <html>.
const homeOutPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await homeOutPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await homeOutPage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await homeOutPage.locator('[data-home="out"]:not([hidden])').waitFor();
const homeOutSections = await homeOutPage.evaluate(() => ({
  session: document.documentElement.getAttribute('data-session'),
  visible: Array.from(document.querySelectorAll('main > section')).filter((section) => getComputedStyle(section).display !== 'none').length,
  total: document.querySelectorAll('main > section').length,
}));
ok('the signed-out homepage still shows the whole pitch', homeOutSections.session === null && homeOutSections.visible === homeOutSections.total && homeOutSections.total > 1, JSON.stringify(homeOutSections));
await homeOutPage.close();

// The hero art, on a desktop, measured against the edge that actually cuts.
//
// index.html gives <main> overflow:hidden, and .hp-doc inside .hp-art is
// absolutely positioned: it draws roughly 120px BELOW the 380px box .hp-art
// reserves for it. Signed out that overhang lands on the section underneath and
// nobody sees it. Signed in the hero is the last thing in <main>, so main's box
// ends where the hero ends and the overhang is simply cut off: the first review
// of this change measured a 472px hero at 1440 with the document, the receipt
// and the signature sliced through. That is the whole reason the art is retired
// signed in rather than the hero being trimmed to fit around it.
//
// So this measures every box the art actually draws against main's own
// rectangle, which is the clip. One exclusion, by name and with a reason:
// .hp-art-glow is a blurred radial gradient with inset:-40% -20%, so it is
// BUILT to bleed past its own box and has no edge that can read as cut. It has
// hung 13px over the top of main since the art shipped. Everything else in
// there has an outline someone can see the knife go through.
async function artInsideTheClip(authenticated) {
  const page = await browser.newPage({ viewport:{ width:1440, height:900 } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({
    status: authenticated ? 200 : 401,
    contentType: 'application/json',
    body: authenticated ? '{"authenticated":true,"email":"demo@example.com"}' : '{"authenticated":false}',
  }));
  await page.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
  await page.locator(authenticated ? '[data-home="in"]:not([hidden])' : '[data-home="out"]:not([hidden])').waitFor();
  const measured = await page.evaluate(() => {
    const main = document.querySelector('main').getBoundingClientRect();
    const hero = document.querySelector('.home-hero').getBoundingClientRect();
    const art = document.querySelector('.hp-art');
    const nodes = art ? [art, ...art.querySelectorAll('*')] : [];
    const drawn = nodes
      .filter((node) => !node.classList || !node.classList.contains('hp-art-glow'))
      .map((node) => {
        const box = node.getBoundingClientRect();
        const name = (typeof node.className === 'string' && node.className) || node.tagName.toLowerCase();
        return { name, top:Math.round(box.top), bottom:Math.round(box.bottom), width:Math.round(box.width), height:Math.round(box.height) };
      })
      .filter((box) => box.width > 0 && box.height > 0);
    return {
      heroHeight: Math.round(hero.height),
      mainTop: Math.round(main.top),
      mainBottom: Math.round(main.bottom),
      drawn: drawn.length,
      cut: drawn.filter((box) => box.bottom > Math.round(main.bottom) || box.top < Math.round(main.top))
        .map((box) => `${box.name} ${box.top}..${box.bottom} outside main ${Math.round(main.top)}..${Math.round(main.bottom)}`),
    };
  });
  await page.close();
  return measured;
}
const artIn = await artInsideTheClip(true);
ok('signed in at 1440, no part of the hero art is cut off by the clip', artIn.cut.length === 0, JSON.stringify(artIn));
// And the measurement above is capable of finding a box, which a vacuous pass
// on an empty node list would not prove. Signed out the art is drawn, in full.
const artOut = await artInsideTheClip(false);
ok('signed out at 1440, the hero art is drawn and drawn whole', artOut.drawn > 0 && artOut.cut.length === 0, JSON.stringify(artOut));

const appPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appPage.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","label":"Demo","plan":"pro","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","usage_purpose":"organisation"}' }));
await appPage.route('**/api/user/documents', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
await appPage.route('**/api/user/account/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
// The workspace bar is pinned item by item, in order, because the order is the
// claim: Documents is where the work lands, then the three verbs you came to
// do, then Verify and Settings. It went from five entries to six when /vault
// joined Send and Sign as the third verb ("Lock a file"), so this list and
// APP_NAV in frontend/js/nav-auth.js are updated together or not at all.
const WORKSPACE_NAV = ['Documents','Send','Sign','Lock a file','Verify','Settings'];
await appPage.waitForFunction((expected) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === expected, WORKSPACE_NAV.join(','));
const appDesktop = await appPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('signed-in navigation follows document work', JSON.stringify(appDesktop) === JSON.stringify(WORKSPACE_NAV), appDesktop.join(', '));
ok('locking a file is a verb in the bar, next to the other two', appDesktop.indexOf('Lock a file') === appDesktop.indexOf('Sign') + 1 && await appPage.locator('nav.nav .nav-links a[href="/vault"]').count() === 1, appDesktop.join(', '));
ok('dashboard removes its duplicate marketing drawer', await appPage.locator('#nav-mobile-marketing').count() === 0 && await appPage.locator('nav.nav .nav-links').count() === 1, await appPage.locator('nav.nav .nav-links').count());
await appPage.locator('#nav-hamburger').click();
const appMobile = await appPage.locator('#nav-mobile a').allInnerTexts();
ok('signed-in mobile menu matches the workspace', appMobile.map((item) => item.toLowerCase()).join(',') === appDesktop.map((item) => item.toLowerCase()).join(','), appMobile.join(', '));
ok('developer tools are settings, not a sixth product', await appPage.locator('.nav-user-menu a', { hasText:'Developer settings' }).count() === 1 && !appMobile.includes('Developer settings'), appMobile.join(', '));

// Support survives signing in, and it is measured in TAPS.
//
// Signed out, a phone reaches /help in two: the menu button, then the strip
// under the drawer. Signed in, js/nav-auth.js used to delete that strip, on the
// reasoning that the user menu carries Help from then on. What that left on a
// 390px screen was no Help at all in the two places anyone looks: the bar sheds
// .nav-help below 700px, and the drawer is pinned to the workspace links
// by the check above. The only route was the menu behind the email address,
// which is where you go to sign out, not where you go when a signature is
// stuck. A customer had to type the url.
//
// So the strip stays and carries Help alone. The drawer is open at this point
// (one tap), so anything found here is the second tap and no deeper. Anything
// inside .nav-user-menu is explicitly NOT counted: that menu is closed, so it
// costs a tap of its own and would make three.
const signedInHelp = await appPage.evaluate(() => {
  const inClosedMenu = (node) => !!node.closest('.nav-user-menu');
  return Array.from(document.querySelectorAll('a[href="/help"]'))
    .filter((link) => !inClosedMenu(link))
    .map((link) => {
      const box = link.getBoundingClientRect();
      return {
        where: link.closest('#nav-mobile-tail') ? 'drawer strip' : (link.closest('nav.nav') ? 'bar' : 'page'),
        display: getComputedStyle(link).display,
        width: Math.round(box.width),
        height: Math.round(box.height),
      };
    });
});
ok('signed in, support is two taps away on a phone', signedInHelp.some((link) => link.display !== 'none' && link.width > 0 && link.height >= 44), JSON.stringify(signedInHelp));
ok('signed in, the strip under the drawer is what carries support', signedInHelp.some((link) => link.where === 'drawer strip' && link.height >= 44), JSON.stringify(signedInHelp));
// Sign in is not an action you still need, so the strip may not keep offering
// it. Read without a locator wait: when the strip is gone entirely (the bug
// this replaces) the answer is "no strip", reported in a line, not a 30-second
// timeout that buries every check under it.
const tailState = await appPage.evaluate(() => {
  const tail = document.getElementById('nav-mobile-tail');
  if (!tail) return { present:false, hrefs:[] };
  return { present:true, hrefs:Array.from(tail.querySelectorAll('a')).map((link) => link.getAttribute('href')) };
});
ok('the signed-in drawer keeps its strip', tailState.present, JSON.stringify(tailState));
ok('the signed-in drawer strip drops sign in', tailState.present && !tailState.hrefs.includes('/auth/login'), JSON.stringify(tailState));
// And the second tap goes somewhere. A 44px target on a dead link is worse
// than no target: it looks like support and answers nothing.
if (tailState.hrefs.includes('/help')) {
  await appPage.locator('#nav-mobile-tail a[href="/help"]').click();
  await appPage.waitForURL('**/help');
}
ok('the second tap actually opens the help centre', new URL(appPage.url()).pathname === '/help', appPage.url());
await appPage.close();

// The signed-in bar itself, on the same phone. Adding Help back to the nav is
// only right if it does not put a fifth thing in a bar that two reviews already
// called full: nav.css hides the text link below 700px and the strip takes over.
const appBarPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appBarPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appBarPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appBarPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
await appBarPage.locator('.nav-user').waitFor();
const appBar = await appBarPage.evaluate(() => {
  const items = Array.from(document.querySelectorAll('nav.nav a, nav.nav button'))
    .filter((node) => {
      const box = node.getBoundingClientRect();
      return getComputedStyle(node).display !== 'none' && box.width > 0 && box.height > 0 && !node.closest('.nav-user-menu');
    })
    .map((node) => {
      const box = node.getBoundingClientRect();
      return { label:node.textContent.trim().slice(0, 24) || node.getAttribute('aria-label'), left:Math.round(box.left), right:Math.round(box.right), height:Math.round(box.height) };
    })
    .sort((first, second) => first.left - second.left);
  return { items, gaps:items.slice(1).map((item, index) => Math.round(item.left - items[index].right)) };
});
ok('the signed-in phone bar carries one account control beside the menu button', appBar.items.length <= 3, JSON.stringify(appBar.items));
ok('nothing in the signed-in phone bar touches its neighbour', appBar.gaps.length > 0 && appBar.gaps.every((gap) => gap >= 12), JSON.stringify(appBar));
ok('every target in the signed-in phone bar is finger-sized', appBar.items.every((item) => item.height >= 44), JSON.stringify(appBar.items));
await appBarPage.close();

// The same measurement as the signed-out bar above, on an app screen. It is a
// second check and not a second route in that loop because the answer is a
// different colour: /parashare, /dashboard, /sign, /account and the auth pages
// load app-2026.css AFTER nav.css, and that file paints the bar in the app's
// own paper rather than the marketing bone. What must be identical is the
// opacity. nav.css turns the bar opaque under 1024px on purpose, because at .92
// with no backdrop-filter behind it the page scrolls through the letters; the
// later stylesheet had quietly put the translucent token back, and a review of
// /parashare on a 390 phone read it off the screen as spook letters. So this
// pins the alpha and the absent filter and lets the theme own the hex.
const appPaintPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appPaintPage.route('**/api/**', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await appPaintPage.goto(ORIGIN + '/parashare', { waitUntil:'domcontentloaded' });
await appPaintPage.locator('nav.nav').waitFor();
const appPaint = await appPaintPage.locator('nav.nav').evaluate((node) => ({
  background: getComputedStyle(node).backgroundColor,
  backdropFilter: getComputedStyle(node).backdropFilter,
  webkitBackdropFilter: getComputedStyle(node).getPropertyValue('-webkit-backdrop-filter'),
}));
ok('the /parashare navigation is opaque on a phone', /^rgb\(\d+, \d+, \d+\)$/.test(appPaint.background)
  && appPaint.backdropFilter === 'none'
  && (!appPaint.webkitBackdropFilter || appPaint.webkitBackdropFilter === 'none'), JSON.stringify(appPaint));
await appPaintPage.close();

// A signed-in tablet has the room the phone does not, so Help is a text link in
// the bar there, exactly as it is signed out. One tap, and the same place the
// same person used before he had an account.
const appTabletPage = await browser.newPage({ viewport:{ width:820, height:1180 } });
await appTabletPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appTabletPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appTabletPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
await appTabletPage.locator('.nav-user').waitFor();
// Bounded, and the failure is swallowed on purpose: when the link is gone this
// check has to report "no Help in the bar" in one line, not stall for the
// default thirty seconds and then throw away every result collected above it.
await appTabletPage.waitForSelector('nav.nav .nav-auth a[href="/help"]', { timeout:5000 }).catch(() => {});
const appTabletHelp = await appTabletPage.evaluate(() => {
  const link = document.querySelector('nav.nav .nav-auth a[href="/help"]');
  if (!link) return null;
  const box = link.getBoundingClientRect();
  return { display:getComputedStyle(link).display, width:Math.round(box.width), height:Math.round(box.height) };
});
ok('signed in, support is one tap in the bar on a tablet', !!appTabletHelp && appTabletHelp.display !== 'none' && appTabletHelp.width > 0 && appTabletHelp.height >= 44, JSON.stringify(appTabletHelp));
await appTabletPage.close();

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
if (process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH) await stableScreenshot(accountPage, { path:process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH, fullPage:true });
await accountPage.close();

const developerPage = await browser.newPage({ viewport:{ width:1280, height:900 } });
await developerPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await developerPage.route('**/api/developer/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await developerPage.goto(ORIGIN + '/developer', { waitUntil:'domcontentloaded' });
await developerPage.waitForFunction((expected) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === expected, WORKSPACE_NAV.join(','));
const developerNav = await developerPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('developer page is presented as settings inside the same shell', await developerPage.title() === 'Developer settings · Paramant' && developerNav.map((item) => item.toLowerCase()).join(',') === WORKSPACE_NAV.map((item) => item.toLowerCase()).join(','), await developerPage.title());
ok('developer page shares the settings hierarchy', JSON.stringify(await developerPage.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account & security','Plan & billing','Developer settings']) && await developerPage.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/developer', await developerPage.locator('.settings-tabs').innerText());
await developerPage.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nnavigation-shell: ${checks.length} checks passed`);
