// Screenshot harness for the app screens. Not a gate: it renders every app
// screen at 390x844 and 1440x900, in light and dark, with the same API stubs
// the dashboard suite uses, and writes the images to the directory given in
// APP_SHOTS_DIR (default docs/brand/assets/app-2026/).
//
// Run: node tests/app-shots.mjs
// One screen only: APP_SHOTS_ONLY=dashboard node tests/app-shots.mjs

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const OUT = process.env.APP_SHOTS_DIR
  || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'brand', 'assets', 'app-2026');
fs.mkdirSync(OUT, { recursive: true });

const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.woff2':'font/woff2','.json':'application/json','.wasm':'application/wasm' };
const ALIAS = { '/dashboard':'/dashboard.html', '/account':'/account.html', '/sign':'/sign.html',
  '/parashare':'/parashare.html', '/signup':'/signup.html', '/pricing':'/pricing.html',
  '/signup/verified':'/signup/verified.html',
  '/auth/login':'/auth/login.html', '/auth/setup':'/auth/setup.html', '/auth/backup':'/auth/backup.html',
  '/auth/request-reset':'/auth/request-reset.html', '/auth/reset-confirm':'/auth/reset-confirm.html' };

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (ALIAS[pathname]) pathname = ALIAS[pathname];
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

const future = new Date(Date.now() + 30 * 86400000).toISOString();
const ME = {
  email:'demo@example.com', label:'Demo', plan:'community', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:future, usage_purpose:'organisation',
  api_key_masked:'pgp_live_****9f21', sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
};
const DOCS = { documents:[
  { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement 2026.pdf', status:'sent', created_at:'2026-08-21T10:00:00.000Z', expires_at:'2026-09-21T10:00:00.000Z', party_count:3, signed_count:0 },
  { id:'env_progress_abcdefghijklmnop', original_filename:'Service order Nuremberg.pdf', status:'sent', created_at:'2026-08-20T10:00:00.000Z', expires_at:'2026-09-20T10:00:00.000Z', party_count:4, signed_count:2 },
  { id:'env_complete_abcdefghijklmnop', original_filename:'Consultancy contract.pdf', status:'complete', created_at:'2026-08-19T10:00:00.000Z', expires_at:'2026-09-19T10:00:00.000Z', party_count:2, signed_count:2 },
  { id:'env_void_abcdefghijklmnop', original_filename:'Draft NDA.pdf', status:'void', created_at:'2026-08-18T10:00:00.000Z', expires_at:'2026-09-18T10:00:00.000Z', party_count:1, signed_count:0 },
] };

async function stub(page, { signedIn = true } = {}) {
  // Playwright tries handlers newest-first, so the catch-all is registered
  // FIRST and every specific stub lands on top of it.
  await page.route('**/api/user/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json',
    body: signedIn ? '{"authenticated":true,"email":"demo@example.com"}' : '{"authenticated":false}' }));
  await page.route('**/api/user/me', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/account', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(ME) }));
  await page.route('**/api/user/billing/status', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ current_plan:'community', ...ME }) }));
  await page.route('**/api/user/billing/history', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"history":[]}' }));
  await page.route('**/api/user/documents**', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(DOCS) }));
  await page.route('**/api/user/dashboard/overview', (r) => r.fulfill({ status:500, body:'' }));
  await page.route('**/api/user/account/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{"keys":[{"label":"Signing key"}],"passkeys":[{"label":"Passkey"}]}' }));
}

const SCREENS = [
  { name:'dashboard', url:'/dashboard', ready:'#dh-root:not([hidden]) .dh-document' },
  { name:'sign',      url:'/sign',      ready:'main' },
  { name:'parashare', url:'/parashare', ready:'main' },
  { name:'signup',    url:'/signup',    ready:'main' },
  { name:'account',   url:'/account',   ready:'#state-account:not(.hidden)' },
  { name:'login',     url:'/auth/login', ready:'main, .auth-card, form' },
  { name:'setup',     url:'/auth/setup', ready:'main, .auth-card, form' },
  // Straight from the mail link, so this one is shot signed out.
  { name:'verified',  url:'/signup/verified', ready:'main', signedIn:false },
];
const VIEWPORTS = [{ w:390, h:844 }, { w:1440, h:900 }];
const THEMES = ['light', 'dark'];
const only = process.env.APP_SHOTS_ONLY ? process.env.APP_SHOTS_ONLY.split(',') : null;

const browser = await chromium.launch({ headless:true });
const written = [];
for (const screen of SCREENS) {
  if (only && !only.includes(screen.name)) continue;
  for (const vp of VIEWPORTS) {
    for (const theme of THEMES) {
      const context = await browser.newContext({ viewport:{ width:vp.w, height:vp.h }, deviceScaleFactor:2, colorScheme:theme });
      const page = await context.newPage();
      await stub(page, { signedIn: screen.signedIn !== false });
      await page.goto(ORIGIN + screen.url, { waitUntil:'domcontentloaded' });
      try { await page.locator(screen.ready).first().waitFor({ timeout:6000 }); } catch { /* render what there is */ }
      await page.waitForTimeout(500);
      const file = path.join(OUT, `${screen.name}-${vp.w}x${vp.h}-${theme}.png`);
      await page.screenshot({ path:file, fullPage:true });
      written.push(path.basename(file));
      await context.close();
    }
  }
}

// The loading state, held open on purpose: /api/user/me never answers, so the
// silhouette stays on screen long enough to be photographed. This is the shape
// that took CLS from 0.236 to 0.005.
if (!only || only.includes('dashboard')) {
  for (const theme of THEMES) {
    const context = await browser.newContext({ viewport:{ width:1440, height:900 }, deviceScaleFactor:2, colorScheme:theme });
    const page = await context.newPage();
    await stub(page);
    await page.route('**/api/user/me', () => { /* never resolves: hold the placeholder */ });
    await page.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
    await page.waitForTimeout(700);
    const file = path.join(OUT, `dashboard-1440x900-${theme}-loading.png`);
    await page.screenshot({ path:file });
    written.push(path.basename(file));
    await context.close();
  }
}

// One reduced-motion pair, to prove nothing disappears when motion is off.
if (!only || only.includes('dashboard')) {
  for (const theme of THEMES) {
    const context = await browser.newContext({ viewport:{ width:1440, height:900 }, deviceScaleFactor:2, colorScheme:theme, reducedMotion:'reduce' });
    const page = await context.newPage();
    await stub(page);
    await page.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
    try { await page.locator('#dh-root:not([hidden]) .dh-document').first().waitFor({ timeout:6000 }); } catch { /* */ }
    await page.waitForTimeout(400);
    const file = path.join(OUT, `dashboard-1440x900-${theme}-reduced-motion.png`);
    await page.screenshot({ path:file, fullPage:true });
    written.push(path.basename(file));
    await context.close();
  }
}

await browser.close();
server.close();
console.log(`${written.length} images in ${OUT}`);
for (const name of written) console.log('  ' + name);
