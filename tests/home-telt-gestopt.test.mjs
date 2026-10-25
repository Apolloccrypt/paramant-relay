// The homepage and /dashboard count one document the same way.
//
// On 25 October 2026 the owner's phone showed, for one request sent on 27
// September: "Nog open: 1 verzoek wacht op een handtekening" on the homepage,
// and one tap later "Lopend 0, Gestopt 1, Er loopt nu niets" on /dashboard.
// The homepage kept its own copy of the state rule and that copy did not know
// that a request past its signing window (sign_expires_at, 7 days) is expired.
// Both pages now read js/document-state.js.
//
// Second, the big figure on the homepage was a number you could not tap. It
// now links to the list it counts (/dashboard?filter=open), and that list has
// to open on the same filter.
//
// PARAMANT_HOME_IN_SCREENSHOT_DIR=<dir> writes home-telt-gestopt-390.png, the
// fixed homepage at phone width, into that directory.
//
// Run: node --test tests/home-telt-gestopt.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const SHOTS = process.env.PARAMANT_HOME_IN_SCREENSHOT_DIR || '';
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2', '.ico':'image/x-icon' };
const ALIASES = { '/':'/index.html', '/en':'/en/index.html', '/en/':'/en/index.html', '/dashboard':'/dashboard.html', '/en/dashboard':'/en/dashboard.html' };

const DAY = 86400000;
const now = Date.now();
const iso = (ms) => new Date(ms).toISOString();

// Sent 28 days ago, email-bound: the signing window closed 21 days ago, the
// record is kept two more days. The relay still stores status 'sent'.
const STOPPED = { id:'env_stopped_abcdefghijklmnop', original_filename:'Demo verzoek.pdf', status:'sent',
  created_at:iso(now - 28 * DAY), expires_at:iso(now + 2 * DAY), sign_expires_at:iso(now - 21 * DAY),
  party_count:2, signed_count:0, parties:[{ index:0, label:'Signer Demo', status:'pending' }, { index:1, label:'Acme', status:'pending' }] };
// An open envelope without a signing window whose record time ran out.
const STOPPED_OPEN = { id:'env_stopped_open_abcdefghijk', original_filename:'Demo open.pdf', status:'pending',
  created_at:iso(now - 31 * DAY), expires_at:iso(now - DAY), sign_expires_at:null,
  party_count:1, signed_count:0, parties:[{ index:0, label:'Signer Demo', status:'pending' }] };
const LIVE = { id:'env_live_abcdefghijklmnopqr', original_filename:'Demo lopend.pdf', status:'sent',
  created_at:iso(now - DAY), expires_at:iso(now + 29 * DAY), sign_expires_at:iso(now + 6 * DAY),
  party_count:2, signed_count:1, parties:[{ index:0, label:'Signer Demo', status:'signed' }, { index:1, label:'Acme', status:'pending' }] };

function serve() {
  const server = http.createServer((req, res) => {
    let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    pathname = ALIASES[pathname] || pathname;
    const file = path.join(ROOT, pathname);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (error, body) => {
      if (error) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function stub(page, documents) {
  const json = (body) => (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(body) });
  await page.route('**/api/user/session/verify', json({ authenticated:true, email:'demo@example.com' }));
  await page.route('**/api/user/me', json({ email:'demo@example.com', label:'', plan:'community',
    created_at:'2026-06-01T10:00:00.000Z', backup_codes_remaining:8, session_expires_at:iso(now + DAY), usage_purpose:'organisation' }));
  await page.route('**/api/user/dashboard/overview', json({ tiers:{ parasend:'community', parasign:'free' }, quota:{ transfers:0, signs:0, caps:{ transfers:10, signs:2 } }, audit:[] }));
  await page.route('**/api/user/billing/status', json({ current_plan:'community', plan_parasign:'free', plan_parasend:'community', paid_until_parasign:null, paid_until_parasend:null, auto_renews:false, access_until:null }));
  await page.route('**/api/user/account/signing-key', json({ keys:[{ label:'Signing key' }] }));
  await page.route('**/api/user/account/webauthn/credentials', json({ passkeys:[{ label:'Passkey' }] }));
  await page.route('**/api/user/documents', json({ ok:true, count:documents.length, documents }));
  await page.route('**/api/user/parasign/inbox', json({ ok:true, count:0, documents:[] }));
}

async function openHome(documents, home = '/') {
  const page = await browser.newPage({ viewport:{ width:390, height:844 } });
  await stub(page, documents);
  await page.goto(ORIGIN + home, { waitUntil:'domcontentloaded' });
  await page.locator('[data-home="in"]:not([hidden])').waitFor();
  await page.waitForFunction(() => {
    const fig = document.querySelector('[data-hw-read]');
    const rec = document.querySelector('[data-hw-recent]');
    const wait = document.querySelector('[data-hw-waiting]');
    return fig && !fig.hidden && ((rec && !rec.hidden) || (wait && !wait.hidden));
  });
  return page;
}

async function dashboardCounts(page) {
  await page.locator('#dh-root:not([hidden])').waitFor();
  await page.waitForFunction(() => document.querySelector('[data-doc-count="all"]').textContent !== '0');
  const out = {};
  for (const key of ['open', 'completed', 'cancelled', 'all']) out[key] = await page.locator(`[data-doc-count="${key}"]`).innerText();
  return out;
}

const server = await serve();
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
test.after(async () => { await browser.close(); server.close(); });

test('a request past its signing window is not "Nog open" on the homepage and is Gestopt on /dashboard', async () => {
  const page = await openHome([STOPPED, STOPPED_OPEN]);
  const home = await page.evaluate(() => ({
    kicker: document.querySelector('[data-hw-kicker]').textContent,
    num: document.querySelector('[data-hw-num]').textContent,
    cap: document.querySelector('[data-hw-cap]').textContent,
    waiting: !document.querySelector('[data-hw-waiting]').hidden,
    recent: Array.from(document.querySelectorAll('[data-hw-recent-list] .hw-row')).map((r) => r.innerText.replace(/\s+/g, ' ')),
    text: document.querySelector('[data-home="in"]').innerText,
  }));
  assert.notEqual(home.kicker, 'Nog open', 'the figure does not call a stopped request open: ' + JSON.stringify(home));
  assert.doesNotMatch(home.cap, /wacht op een handtekening|wachten op een handtekening/, home.cap);
  assert.equal(home.waiting, false, 'no "Wacht op een handtekening" card for stopped requests');
  assert.doesNotMatch(home.text, /Open\s+[1-9]/, 'the strip does not count them as open: ' + home.text);
  assert.equal(home.recent.length, 2, 'both stopped requests are listed under Recent');
  for (const r of home.recent) assert.match(r, /Verlopen/, 'a stopped request reads Verlopen on the homepage: ' + r);
  if (SHOTS) {
    fs.mkdirSync(SHOTS, { recursive:true });
    await page.emulateMedia({ reducedMotion:'reduce' });
    await stableScreenshot(page, { path:path.join(SHOTS, 'home-telt-gestopt-390.png'), fullPage:false });
  }
  await page.close();

  const dash = await browser.newPage({ viewport:{ width:390, height:844 } });
  await stub(dash, [STOPPED, STOPPED_OPEN]);
  await dash.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
  const counts = await dashboardCounts(dash);
  assert.deepEqual(counts, { open:'0', completed:'0', cancelled:'2', all:'2' }, 'dashboard: Lopend 0, Gestopt 2');
  await dash.close();
});

test('the English homepage applies the same rule', async () => {
  const page = await openHome([STOPPED], '/en');
  const kicker = await page.locator('[data-hw-kicker]').innerText();
  assert.notEqual(kicker, 'Still open');
  assert.match(await page.locator('[data-hw-recent-list]').innerText(), /Expired/);
  await page.close();
});

test('the big figure links to the list it counts, and that list opens on the same filter', async () => {
  const page = await openHome([LIVE, STOPPED]);
  assert.equal(await page.locator('[data-hw-num]').innerText(), '1', 'one live request, the stopped one is not counted');
  const go = page.locator('[data-hw-go]');
  assert.equal(await go.getAttribute('href'), '/dashboard?filter=open#documenten');
  // The tap target is the whole card, not only the digit.
  const card = await page.locator('.hw-figure').boundingBox();
  await page.mouse.click(card.x + card.width - 12, card.y + card.height - 12);
  await page.waitForURL(/\/dashboard\?filter=open/);
  const counts = await dashboardCounts(page);
  assert.equal(counts.open, '1');
  assert.equal(counts.cancelled, '1');
  assert.equal(await page.locator('[data-doc-filter="open"]').getAttribute('aria-pressed'), 'true');
  await page.waitForFunction(() => document.querySelectorAll('#dh-documents .dh-document').length >= 1);
  const list = await page.locator('#dh-documents').innerText();
  assert.match(list, /Demo lopend/);
  assert.doesNotMatch(list, /Demo verzoek/);
  await page.close();
});

test('/dashboard?filter=cancelled opens on Gestopt', async () => {
  const page = await browser.newPage({ viewport:{ width:1280, height:900 } });
  await stub(page, [LIVE, STOPPED]);
  await page.goto(ORIGIN + '/dashboard?filter=cancelled', { waitUntil:'domcontentloaded' });
  await dashboardCounts(page);
  assert.equal(await page.locator('[data-doc-filter="cancelled"]').getAttribute('aria-pressed'), 'true');
  assert.equal(await page.locator('[data-doc-filter="open"]').getAttribute('aria-pressed'), 'false');
  await page.waitForFunction(() => document.querySelectorAll('#dh-documents .dh-document').length >= 1);
  const list = await page.locator('#dh-documents').innerText();
  assert.match(list, /Demo verzoek/);
  assert.doesNotMatch(list, /Demo lopend/);
  await page.close();
});

test('with nothing to count the figure is plain text, not a link', async () => {
  const page = await openHome([STOPPED]);
  assert.equal(await page.locator('[data-hw-go]').getAttribute('href'), null, 'quota figure has no page to link to');
  await page.close();
});
