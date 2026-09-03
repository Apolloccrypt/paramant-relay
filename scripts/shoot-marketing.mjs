// Playwright evidence for the marketing rebuild. Every changed screen at
// 390x844 and 1440x900, light and dark, plus one reduced-motion pass.
// Run: node scripts/shoot-marketing.mjs [outdir]
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const OUT = process.argv[2] || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'brand', 'assets', 'droom-marketing');
fs.mkdirSync(OUT, { recursive: true });

const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon', '.json':'application/json', '.txt':'text/plain' };
const aliases = { '/':'/index.html', '/pricing':'/pricing.html', '/parasign':'/parasign.html', '/parasend':'/parasend.html', '/about':'/about.html', '/security':'/security.html' };

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
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true });

const PAGES = [['index','/'], ['pricing','/pricing'], ['parasign','/parasign'], ['parasend','/parasend'], ['about','/about'], ['security','/security']];
const SIZES = [[390,844], [1440,900]];

async function shoot(name, slug, w, h, scheme, extra = {}) {
  const { fullPage = false, ...ctxExtra } = extra;
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: fullPage ? 1 : 2, colorScheme: scheme, ...ctxExtra });
  const page = await ctx.newPage();
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
  await page.goto(ORIGIN + slug, { waitUntil: 'networkidle' });
  const suffix = extra.reducedMotion ? '-reduced-motion' : (fullPage ? '-full' : '');
  await page.screenshot({ path: path.join(OUT, `${name}-${w}x${h}-${scheme}${suffix}.png`), fullPage });
  await ctx.close();
}

for (const [name, slug] of PAGES) {
  for (const [w, h] of SIZES) {
    for (const scheme of ['light', 'dark']) await shoot(name, slug, w, h, scheme);
  }
}
// The whole page, not just the first screen: the fold shots above prove the
// geometry, these prove the design.
for (const [name, slug] of PAGES) {
  for (const scheme of ['light', 'dark']) await shoot(name, slug, 1440, 900, scheme, { fullPage: true });
}
// The proof that prefers-reduced-motion takes everything out and leaves every
// state of the screen intact: this must be byte-identical to its twin. Shot on
// /pricing rather than the homepage, because the homepage hero carries an
// animation of its own from #377 and a frozen frame of a running animation is
// not the same picture as a frame of it. Every hover lift, press and arrow
// shift in this round is on /pricing too.
await shoot('pricing', '/pricing', 1440, 900, 'light', { reducedMotion: 'reduce' });

await browser.close();
server.close();
console.log('shots in', OUT);
