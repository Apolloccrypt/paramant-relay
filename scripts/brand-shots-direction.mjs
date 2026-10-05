// The two images in docs/brand/design-direction.md, shot from the real site.
//
// The direction document used to carry eleven pictures of three prototypes that
// no longer exist. What a direction document has to show is the state that was
// merged, so this renders frontend/index.html itself: the phone first screen
// (#377, #382, #392) and the whole desktop page (#377, #382, #386, #389).
//
// Marketing is light only. #380 pulled the dark layer off these pages because
// it sat behind a media query with no switch on them, so a dark shot of /index
// would be a picture of something a reader cannot reach.
//
// Where the images land follows the rule from #393: a temp directory by
// default, the tracked directory only with PARAMANT_WRITE_BRAND_SHOTS=1. The
// resolver in scripts/brand-shots-dir.mjs owns that rule; this file reuses its
// flag and its docs/ check rather than keeping a second copy of either.
//
//   node scripts/brand-shots-direction.mjs                              temp dir
//   PARAMANT_WRITE_BRAND_SHOTS=1 node scripts/brand-shots-direction.mjs  references
//   BRAND_SHOTS_DRY_RUN=1 node scripts/brand-shots-direction.mjs         say where
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, DOCS_ROOT, FLAG, isUnderDocs } from './brand-shots-dir.mjs';

const ROOT = path.join(REPO_ROOT, 'frontend');
const TRACKED = path.join(DOCS_ROOT, 'brand', 'assets', 'design-direction-2026');
const DRY_RUN = 'BRAND_SHOTS_DRY_RUN';

// Same shape as resolveBrandShotsDir, aimed at this document's directory.
const optIn = process.env[FLAG] === '1';
const OUT = optIn ? TRACKED : path.join(os.tmpdir(), 'paramant-direction-shots');
if (isUnderDocs(OUT) && !optIn) throw new Error(`refusing to write under docs/ without ${FLAG}=1`);

if (process.env[DRY_RUN] === '1') {
  console.log(`out-dir: ${OUT}`);
  console.log(`opt-in: ${optIn ? 'yes' : 'no'} (${FLAG})`);
  process.exit(0);
}
fs.mkdirSync(OUT, { recursive: true });

const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.woff2':'font/woff2','.json':'application/json','.wasm':'application/wasm' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/' || pathname.endsWith('/')) pathname += 'index.html';
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;

// Signed out, which is the state a buyer arrives in and the state the nav
// round (#392) was designed for.
async function stub(page) {
  await page.route('**/api/user/session/verify', (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: '{"authenticated":false}' }));
}

// The phone shot is the first screen, at deviceScaleFactor 2: that is the
// frame the geometry gate pins and the one a buyer arrives in. The desktop
// shot is the whole page, so it has to carry the sections below the fold; at
// 2x that is a 12578px image of 2 MB in a tracked directory, so it goes in at
// 1x. Legibility is not the point of a 6000px page shot; the order of the
// sections is.
const SHOTS = [
  { name: 'home-390x844-light.png',  w: 390,  h: 844, fullPage: false, scale: 2 },
  { name: 'home-1440x900-light.png', w: 1440, h: 900, fullPage: true,  scale: 1 },
];

const browser = await chromium.launch({ headless: true });
for (const shot of SHOTS) {
  const context = await browser.newContext({
    viewport: { width: shot.w, height: shot.h },
    deviceScaleFactor: shot.scale,
    colorScheme: 'light',
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  await stub(page);
  await page.goto(`${ORIGIN}/`, { waitUntil: 'domcontentloaded' });
  await page.locator('main').first().waitFor({ timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(OUT, shot.name), fullPage: shot.fullPage });
  console.log(`  ${shot.name}`);
  await context.close();
}
await browser.close();
server.close();
console.log(`2 images in ${OUT}`);
if (!optIn) console.log(`Not the tracked references: set ${FLAG}=1 to refresh them.`);
