import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/security':'/security.html', '/sign':'/sign.html', '/en/dashboard':'/en/dashboard.html', '/account':'/account.html', '/en/account':'/en/account.html', '/developer':'/developer.html', '/pricing':'/pricing.html', '/parashare':'/parashare.html', '/help':'/help/index.html', '/en':'/en/index.html', '/en/docs':'/en/docs.html', '/en/pricing':'/en/pricing.html' };
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
// The public checks below were written for the English homepage. Since
// 25 October 2026 neither homepage carries the shared bar (they have their own
// header: the word mark and Inloggen), so the shared bar is measured on the
// English /pricing, which carries it, and the homepages get their own checks.
await publicPage.goto(ORIGIN + '/en/pricing', { waitUntil:'domcontentloaded' });
await publicPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Send,Sign,Tools,Security,Pricing');
const publicDesktop = await publicPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
// The bar carries the free tools as their own destination. Everything a
// visitor can use without an account lived one level down, behind /pricing or
// a body link, so the page that collects it was the least reachable thing on
// the site. It is the front door of the ladder, so it sits next to Product.
// The label is "Tools" and the route is /gereedschap: the page behind it is
// Dutch because the paid work behind it is, and this is the one word that
// reads the same in both languages, so the bar stays English on the 42 English
// pages that also carry it.
ok('public navigation names its destinations, including the free tools', JSON.stringify(publicDesktop) === JSON.stringify(['Send','Sign','Tools','Security','Pricing']), publicDesktop.join(', '));
// The homepages, signed out (the approved picture of 25 October 2026): a
// header with the word mark and one way to sign in, ONE button to a free
// account, and both product pages reachable from the page (in the footer).
for (const [slug, lp, button, signIn] of [['/en', '/en', 'Try it free', 'Sign in'], ['/', '', 'Probeer het gratis', 'Inloggen']]) {
  const home = await browser.newPage({ viewport:{ width:390, height:844 } });
  await home.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
  await home.goto(ORIGIN + slug, { waitUntil:'domcontentloaded' });
  await home.locator('.h-hero h1').waitFor();
  const actions = await home.locator('main a.h-cta').evaluateAll((nodes) => nodes.map((n) => [n.getAttribute('href'), n.textContent.trim()]));
  ok(`${slug}: the homepage leads with one button, to a free account`, JSON.stringify(actions) === JSON.stringify([[lp + '/signup', button]]), JSON.stringify(actions));
  const header = await home.locator('header.h-top a').evaluateAll((nodes) => nodes.map((n) => [n.getAttribute('href'), n.textContent.trim()]));
  ok(`${slug}: the header carries the word mark and one way to sign in`, header.length === 2 && header[1][0] === lp + '/auth/login' && header[1][1] === signIn, JSON.stringify(header));
  const hrefs = await home.locator('a').evaluateAll((nodes) => nodes.map((n) => n.getAttribute('href')));
  ok(`${slug}: the homepage leads to both product pages`, hrefs.includes(lp + '/parasend') && hrefs.includes(lp + '/parasign'), JSON.stringify(hrefs));
  ok(`${slug}: the homepage fits the phone viewport`, await home.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), '');
  await home.close();
}
// The Dutch bar: the same bar in Dutch, with the two outward product names,
// re-rendered identically by js/nav-auth.js after the session check. Measured
// on /pricing, which carries it.
await (async () => {
  const nl = await browser.newPage({ viewport:{ width:390, height:844 } });
  await nl.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
  await nl.goto(ORIGIN + '/pricing', { waitUntil:'domcontentloaded' });
  const want = 'Versturen,Ondertekenen,Gereedschap,Beveiliging,Prijzen';
  const got = await nl.waitForFunction((w) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((n) => n.textContent).join(',') === w, want, { timeout:10000 }).then(() => true, () => false);
  ok('the Dutch bar names its destinations in Dutch, with Versturen and Ondertekenen', got, (await nl.locator('nav.nav .nav-links .nav-link').allInnerTexts()).join(', '));
  const authText = await nl.locator('#nav-auth').evaluate((n) => n.textContent);
  ok('the Dutch bar says Hulp, Inloggen and Account maken after the session check', /Hulp/.test(authText) && /Inloggen/.test(authText) && /Account maken/.test(authText), authText);
  await nl.close();
})();
const publicMobilePaint = await publicPage.locator('nav.nav').evaluate((node) => ({
  background: getComputedStyle(node).backgroundColor,
  backdropFilter: getComputedStyle(node).backdropFilter,
  webkitBackdropFilter: getComputedStyle(node).getPropertyValue('-webkit-backdrop-filter'),
  paper: getComputedStyle(document.body).backgroundColor,
}));
// Pinned to the bone hex until 4 September 2026, then to "fully opaque, no
// blur". What it guards is that no sharp letter of the page reads through the
// bar. Since design-system.css v6.1 the bar may be translucent, but only with a
// real frost behind it (blur of 12px or more): a letter under 20px of blur is a
// smudge, not spook text. A see-through bar without a blur stays red.
function barHidesThePage(paint) {
  if (/^rgb\(/.test(paint.background)) return true;
  const filter = [paint.backdropFilter, paint.webkitBackdropFilter].filter(Boolean).join(' ');
  const blur = /blur\((\d+(?:\.\d+)?)px\)/.exec(filter);
  return !!blur && Number(blur[1]) >= 12;
}
ok('mobile navigation is opaque, or frosted, before opening the menu', barHidesThePage(publicMobilePaint), JSON.stringify(publicMobilePaint));
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
  const links = Array.from(document.querySelectorAll('nav.nav a[href="/help"], .nav-mobile-tail a[href="/help"], nav.nav a[href="/en/help"], .nav-mobile-tail a[href="/en/help"]'));
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
// It is measured on three pages. The homepage left this list on 25 October
// 2026: it no longer carries the shared bar (its own header is measured below). The bar is shared,
// but not every page gets it from the generator: developer.html keeps its own
// (KEEP_OWN_NAV in frontend/apply-nav.py) and is stamped by hand, which is
// exactly where the first round of this went wrong. A check that only ever
// looks at / cannot see that.
for (const route of ['/security', '/pricing', '/developer']) {
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

// The homepage header, on the same phone: two things, apart, and the one that
// is a button big enough for a thumb.
{
  const homeBar = await browser.newPage({ viewport:{ width:390, height:844 } });
  await homeBar.route('**/api/user/session/verify', (call) => call.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
  await homeBar.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
  await homeBar.locator('header.h-top').waitFor();
  const bar = await homeBar.evaluate(() => {
    const items = Array.from(document.querySelectorAll('header.h-top a')).map((node) => {
      const box = node.getBoundingClientRect();
      return { label:node.textContent.trim(), left:Math.round(box.left), right:Math.round(box.right), height:Math.round(box.height) };
    }).sort((a, b) => a.left - b.left);
    return { items, gaps:items.slice(1).map((item, index) => Math.round(item.left - items[index].right)) };
  });
  ok('the homepage header carries the word mark and one action', bar.items.length === 2, JSON.stringify(bar.items));
  ok('nothing in the homepage header touches its neighbour', bar.gaps.every((gap) => gap >= 12), JSON.stringify(bar));
  ok('the sign-in target in the homepage header is finger-sized', bar.items[1] && bar.items[1].height >= 44, JSON.stringify(bar.items));
  await homeBar.close();
}

const tabletPage = await browser.newPage({ viewport:{ width:820, height:1180 } });
await tabletPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await tabletPage.goto(ORIGIN + '/pricing', { waitUntil:'domcontentloaded' });
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
// An English page links the English help centre (fase 2 SITE-03-F*).
const withoutHelp = stamped.filter(([name, html]) => !(/^en\//.test(name) ? /<a href="\/en\/help"/ : /<a href="\/help"/).test(html)).map(([name]) => name);
ok('every stamped page links support', stamped.length > 0 && withoutHelp.length === 0, withoutHelp.join(', ') || `${stamped.length} pages`);
// A page that declares lang="en" names the English legal texts, under /en.
const withoutLegal = stamped.filter(([, html]) => !['/privacy', '/dpa', '/terms'].every((href) => html.includes(`href="${/<html\b[^>]*\blang="en/i.test(html) ? '/en' + href : href}"`))).map(([name]) => name);
ok('every stamped page names privacy, dpa and terms', withoutLegal.length === 0, withoutLegal.join(', ') || `${stamped.length} pages`);

// Signed in, the homepage is not a second overview: js/home-auth.js sends the
// visitor on to "Je documenten" on /dashboard before the pitch is painted.
const homePage = await browser.newPage({ viewport:{ width:390, height:844 } });
await homePage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await homePage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await homePage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await homePage.waitForURL(ORIGIN + '/dashboard', { timeout:10000, waitUntil:'commit' }).catch(() => {});
ok('signed-in homepage leads to the document workspace', new URL(homePage.url()).pathname === '/dashboard', homePage.url());
await homePage.locator('#dh-root:not([hidden])').waitFor({ timeout:10000 }).catch(() => {});
ok('the signed-in screen opens on the documents', /Je documenten/.test(await homePage.locator('#dh-h1').innerText().catch(() => '')), '');
if (process.env.PARAMANT_HOME_SCREENSHOT_PATH) await stableScreenshot(homePage, { path:process.env.PARAMANT_HOME_SCREENSHOT_PATH });
await homePage.close();

// Signed OUT, the page is the whole pitch, in order, with no attribute on <html>.
const homeOutPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await homeOutPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await homeOutPage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await homeOutPage.waitForTimeout(500);
const homeOutSections = await homeOutPage.evaluate(() => ({
  session: document.documentElement.getAttribute('data-session'),
  visible: Array.from(document.querySelectorAll('main > section')).filter((section) => getComputedStyle(section).display !== 'none' && getComputedStyle(section).visibility !== 'hidden').length,
  total: document.querySelectorAll('main > section').length,
}));
ok('the signed-out homepage still shows the whole pitch', homeOutSections.session === null && homeOutSections.visible === homeOutSections.total && homeOutSections.total > 1, JSON.stringify(homeOutSections));
await homeOutPage.close();

// The product screen in the hero, measured against its own panel: on a
// desktop it used to run past the right edge of its panel in the first
// picture, and the approved one keeps it inside. Every box the drawing draws
// has to sit inside .h-art, at 1440 and at 390, and the three steps under it
// draw whole inside <main>.
for (const width of [1440, 390]) {
  const page = await browser.newPage({ viewport:{ width, height:900 } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
  await page.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
  await page.locator('.h-art').waitFor();
  const art = await page.evaluate(() => {
    const panel = document.querySelector('.h-art').getBoundingClientRect();
    const main = document.querySelector('main').getBoundingClientRect();
    const drawn = Array.from(document.querySelectorAll('.h-art *')).map((node) => node.getBoundingClientRect()).filter((b) => b.width > 0 && b.height > 0);
    const steps = Array.from(document.querySelectorAll('.h-step')).map((n) => n.getBoundingClientRect());
    return {
      drawn: drawn.length,
      cut: drawn.filter((b) => b.left < panel.left - 0.5 || b.right > panel.right + 0.5 || b.top < panel.top - 0.5 || b.bottom > panel.bottom + 0.5).length,
      steps: steps.filter((b) => b.width > 0 && b.height > 0).length,
      stepsCut: steps.filter((b) => b.left < main.left || b.right > main.right).length,
    };
  });
  ok(`at ${width}, the product screen stays inside its panel`, art.drawn > 10 && art.cut === 0, JSON.stringify(art));
  ok(`at ${width}, the three steps draw whole`, art.steps === 3 && art.stepsCut === 0, JSON.stringify(art));
  await page.close();
}

// "Je documenten" itself, on a phone: the bar at the bottom carries the four
// places in order, each a thumb's worth, and the account sits behind the
// initials. On a desktop the bar goes and one button Nieuw takes its place.
{
  const dash = await browser.newPage({ viewport:{ width:390, height:844 } });
  await dash.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await dash.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
  await dash.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","label":"Demo","plan":"pro"}' }));
  await dash.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
  await dash.locator('#dh-root:not([hidden])').waitFor();
  const tabs = await dash.locator('.pa-tabbar a').evaluateAll((nodes) => nodes.map((n) => {
    const b = n.getBoundingClientRect();
    return { text:n.textContent.trim(), href:n.getAttribute('href'), height:Math.round(b.height), width:Math.round(b.width) };
  }));
  ok('the phone bar of Je documenten is Documenten, Versturen, Ondertekenen, Opvragen', JSON.stringify(tabs.map((t) => [t.text, t.href])) === JSON.stringify([['Documenten','/dashboard'],['Versturen','/parashare'],['Ondertekenen','/sign'],['Opvragen','/opvragen']]), JSON.stringify(tabs));
  ok('every place in that bar is finger-sized', tabs.length === 4 && tabs.every((t) => t.height >= 44 && t.width >= 44), JSON.stringify(tabs));
  ok('the current place is marked', await dash.locator('.pa-tabbar a[aria-current="page"]').getAttribute('href') === '/dashboard', '');
  const avatar = await dash.locator('#pa-avatar').evaluate((n) => ({ text:n.textContent.trim(), label:n.getAttribute('aria-label'), popup:n.getAttribute('aria-haspopup') }));
  await dash.locator('#pa-avatar').click();
  const acct = await dash.locator('#pa-acct-menu').evaluate((m) => ({ hidden:m.hidden, account:(m.querySelector('a[role="menuitem"]') || {}).getAttribute?.('href'),
    langs:[...m.querySelectorAll('a[role="menuitemradio"]')].map((a) => [a.getAttribute('href'), a.getAttribute('aria-checked')]) }));
  ok('the account sits behind the initials, with the language', avatar.text === 'DE' && /account/i.test(avatar.label) && avatar.popup === 'menu'
    && !acct.hidden && acct.account === '/account' && JSON.stringify(acct.langs) === JSON.stringify([['/dashboard','true'],['/en/dashboard','false']]), JSON.stringify([avatar, acct]));
  ok('no language line at the foot of Je documenten', !(await dash.locator('.pa-lang').count()), '');
  await dash.keyboard.press('Escape');
  ok('Nieuw is not on the phone; the bar carries the starts', !(await dash.locator('#pa-new').isVisible()), '');
  ok('Je documenten fits the phone viewport', await dash.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), '');
  await dash.setViewportSize({ width:1280, height:900 });
  ok('on a desktop the bar goes and Nieuw is there', !(await dash.locator('.pa-tabbar').isVisible()) && await dash.locator('#pa-new').isVisible(), '');
  await dash.close();
}

const appPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appPage.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","label":"Demo","plan":"pro","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","usage_purpose":"organisation"}' }));
await appPage.route('**/api/user/documents', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
await appPage.route('**/api/user/account/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
// Since 25 October 2026 /dashboard ("Je documenten") has its own header and
// bottom bar (checked above); the shared workspace bar is measured on /sign,
// a signed-in page that still carries it.
await appPage.goto(ORIGIN + '/sign', { waitUntil:'domcontentloaded' });
// The workspace bar is pinned item by item, in order, because the order is the
// claim: Documents is where the work lands, then the three verbs you came to
// do, then Verify and Settings. It went from five entries to six when /vault
// joined Send and Sign as the third verb ("Lock a file"), so this list and
// APP_NAV in frontend/js/nav-auth.js are updated together or not at all.
// Since 23 September 2026 the bar speaks the page's own <html lang>: Dutch by
// default, English on a page that declares lang="en". Same six, same order.
const WORKSPACE = {
  nl: ['Documenten','Versturen','Ondertekenen','Bestand vergrendelen','Controleren','Instellingen'],
  en: ['Documents','Send','Sign','Lock a file','Verify','Settings'],
};
const DEV_SETTINGS = { nl: 'Ontwikkelaarsinstellingen', en: 'Developer settings' };
const appLang = await appPage.evaluate(() => (/^en/i.test(document.documentElement.lang) ? 'en' : 'nl'));
const WORKSPACE_NAV = WORKSPACE[appLang];
const WORKSPACE_NAV_EN = WORKSPACE.en;
await appPage.waitForFunction((expected) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === expected, WORKSPACE_NAV.join(','));
const appDesktop = await appPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('signed-in navigation follows document work', JSON.stringify(appDesktop) === JSON.stringify(WORKSPACE_NAV), appDesktop.join(', '));
ok('locking a file is a verb in the bar, next to the other two', appDesktop.indexOf(WORKSPACE_NAV[3]) === appDesktop.indexOf(WORKSPACE_NAV[2]) + 1 && await appPage.locator('nav.nav .nav-links a[href="/vault"]').count() === 1, appDesktop.join(', '));
ok('the workspace page carries no duplicate marketing drawer', await appPage.locator('#nav-mobile-marketing').count() === 0 && await appPage.locator('nav.nav .nav-links').count() === 1, await appPage.locator('nav.nav .nav-links').count());
await appPage.locator('#nav-hamburger').click();
const appMobile = await appPage.locator('#nav-mobile a').allInnerTexts();
ok('signed-in mobile menu matches the workspace', appMobile.map((item) => item.toLowerCase()).join(',') === appDesktop.map((item) => item.toLowerCase()).join(','), appMobile.join(', '));
ok('developer tools are settings, not a sixth product', await appPage.locator('.nav-user-menu a', { hasText:DEV_SETTINGS[appLang] }).count() === 1 && !appMobile.includes(DEV_SETTINGS[appLang]), appMobile.join(', '));

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
await appBarPage.goto(ORIGIN + '/sign', { waitUntil:'domcontentloaded' });
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
// opacity, or since v6.1 the frost. A bar at .92 with no backdrop-filter, because at .92
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
ok('the /parashare navigation is opaque, or frosted, on a phone', barHidesThePage(appPaint), JSON.stringify(appPaint));
await appPaintPage.close();

// A signed-in tablet has the room the phone does not, so Help is a text link in
// the bar there, exactly as it is signed out. One tap, and the same place the
// same person used before he had an account.
const appTabletPage = await browser.newPage({ viewport:{ width:820, height:1180 } });
await appTabletPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appTabletPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appTabletPage.goto(ORIGIN + '/sign', { waitUntil:'domcontentloaded' });
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
ok('account, billing and developer are one settings hierarchy', JSON.stringify(await accountPage.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account en beveiliging','Plan en betalingen','Instellingen voor ontwikkelaars']) && await accountPage.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/account', await accountPage.locator('.settings-tabs').innerText());
ok('legacy account key is advanced instead of the first task', await accountPage.locator('details.acct-advanced:not([open])').count() === 1 && await accountPage.locator('.acct-card:not(.acct-advanced)').first().locator('h2').innerText() === 'Beveiliging.', await accountPage.locator('main').innerText());
ok('billing settings do not claim live checkout is a stub', !/stub mode|no real payments/i.test(await accountPage.locator('#billing-section').innerText()), await accountPage.locator('#billing-section').innerText());
ok('account action describes deactivation instead of erasure', /persoonsgegevens wissen we/i.test(await accountPage.locator('.acct-card.danger').innerText()) && !/permanent|delete account|definitief|account verwijderen/i.test(await accountPage.locator('.acct-card.danger').innerText()), await accountPage.locator('.acct-card.danger').innerText());
ok('settings fit the phone viewport', await accountPage.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), await accountPage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
if (process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH) await stableScreenshot(accountPage, { path:process.env.PARAMANT_SETTINGS_SCREENSHOT_PATH, fullPage:true });
await accountPage.close();
// /account is Dutch since 23 September 2026; its English copy under /en/ is held
// to the same settings shape, in English.
const accountPageEn = await browser.newPage({ viewport:{ width:390, height:844 } });
await accountPageEn.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await accountPageEn.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await accountPageEn.route('**/api/user/account', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","api_key_masked":"pgp_demo...","plan":"pro","label":"Demo","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","sessions":[]}' }));
await accountPageEn.route('**/api/user/billing/status', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"current_plan":"pro"}' }));
await accountPageEn.goto(ORIGIN + '/en/account', { waitUntil:'domcontentloaded' });
await accountPageEn.locator('#state-account:not(.hidden)').waitFor();
await accountPageEn.locator('.nav-user').waitFor();
ok('en: account, billing and developer are one settings hierarchy', JSON.stringify(await accountPageEn.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account & security','Plan & billing','Developer settings (in Dutch)']) && await accountPageEn.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/en/account', await accountPageEn.locator('.settings-tabs').innerText());
ok('en: legacy account key is advanced instead of the first task', await accountPageEn.locator('details.acct-advanced:not([open])').count() === 1 && await accountPageEn.locator('.acct-card:not(.acct-advanced)').first().locator('h2').innerText() === 'Security.', await accountPageEn.locator('main').innerText());
ok('en: billing settings do not claim live checkout is a stub', !/stub mode|no real payments/i.test(await accountPageEn.locator('#billing-section').innerText()), await accountPageEn.locator('#billing-section').innerText());
ok('en: account action describes deactivation instead of erasure', /erase your email address and other personal data/i.test(await accountPageEn.locator('.acct-card.danger').innerText()) && !/permanent|delete account/i.test(await accountPageEn.locator('.acct-card.danger').innerText()), await accountPageEn.locator('.acct-card.danger').innerText());
ok('en: settings fit the phone viewport', await accountPageEn.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), await accountPageEn.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
await accountPageEn.close();

const developerPage = await browser.newPage({ viewport:{ width:1280, height:900 } });
await developerPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await developerPage.route('**/api/developer/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await developerPage.goto(ORIGIN + '/developer', { waitUntil:'domcontentloaded' });
await developerPage.waitForFunction((expected) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === expected, WORKSPACE.nl.join(','));
const developerNav = await developerPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('developer page is presented as settings inside the same shell', await developerPage.title() === 'Ontwikkelaarsinstellingen · Paramant' && developerNav.map((item) => item.toLowerCase()).join(',') === WORKSPACE.nl.map((item) => item.toLowerCase()).join(','), await developerPage.title());
ok('developer page shares the settings hierarchy', JSON.stringify(await developerPage.locator('.settings-tabs a').allInnerTexts()) === JSON.stringify(['Account en beveiliging','Abonnement en betaling','Ontwikkelaarsinstellingen']) && await developerPage.locator('.settings-tabs a[aria-current="page"]').getAttribute('href') === '/developer', await developerPage.locator('.settings-tabs').innerText());
await developerPage.close();

// The English pages keep the English workspace bar and account menu, signed in.
const enAppPage = await browser.newPage({ viewport:{ width:1280, height:900 } });
await enAppPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await enAppPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await enAppPage.goto(ORIGIN + '/en/docs', { waitUntil:'domcontentloaded' });
await enAppPage.waitForFunction((expected) => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === expected, WORKSPACE_NAV_EN.join(','));
ok('an English page keeps the English workspace bar', JSON.stringify(await enAppPage.locator('nav.nav .nav-links .nav-link').allInnerTexts()) === JSON.stringify(WORKSPACE_NAV_EN));
ok('and the English account menu', await enAppPage.locator('.nav-user-menu a', { hasText:'Developer settings' }).count() === 1 && await enAppPage.locator('#nav-signout').innerText() === 'Sign out', await enAppPage.locator('.nav-user-menu').innerText());
await enAppPage.close();

// The language switch. On a desktop it sits in the bar and takes you to the
// same page in the other language; on a phone the bar keeps its one action and
// the switch is in the strip under the drawer, next to Sign in and Help.
const langDesk = await browser.newPage({ viewport:{ width:1280, height:900 } });
await langDesk.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await langDesk.goto(ORIGIN + '/pricing', { waitUntil:'domcontentloaded' });
const deskSwitch = langDesk.locator('nav.nav .nav-lang');
ok('the desktop bar shows NL | EN with Dutch marked current', await deskSwitch.isVisible() && await deskSwitch.getAttribute('aria-label') === 'Taal / Language' && await deskSwitch.locator('a[aria-current]').innerText() === 'NL', await deskSwitch.innerText());
await Promise.all([langDesk.waitForURL(ORIGIN + '/en/pricing'), deskSwitch.locator('a', { hasText:'EN' }).click()]);
ok('EN goes to the same page in English, and marks EN current there', await langDesk.evaluate(() => document.documentElement.lang) === 'en' && await langDesk.locator('nav.nav .nav-lang a[aria-current]').innerText() === 'EN', langDesk.url());
await langDesk.close();
const langPhone = await browser.newPage({ viewport:{ width:390, height:844 } });
await langPhone.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await langPhone.goto(ORIGIN + '/pricing', { waitUntil:'domcontentloaded' });
ok('the phone bar leaves the switch to the drawer', !(await langPhone.locator('nav.nav .nav-lang').isVisible()));
await langPhone.locator('#nav-hamburger').click();
const tailSwitch = langPhone.locator('#nav-mobile-tail .nav-lang');
const tailBox = await tailSwitch.boundingBox();
ok('the drawer strip carries NL | EN, 44px tall', await tailSwitch.isVisible() && tailBox && tailBox.height >= 44 && await tailSwitch.locator('a[href="/en/pricing"]').count() === 1, JSON.stringify(tailBox));
await langPhone.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nnavigation-shell: ${checks.length} checks passed`);
