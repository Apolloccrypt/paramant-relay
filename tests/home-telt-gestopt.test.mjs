// One count for one document, on the one signed-in screen.
//
// On 25 October 2026 the owner's phone showed, for one request sent on 27
// September: "Nog open: 1 verzoek wacht op een handtekening" on the homepage,
// and one tap later "Lopend 0, Gestopt 1, Er loopt nu niets" on /dashboard.
// The homepage kept its own copy of the state rule and that copy did not know
// that a request past its signing window (sign_expires_at, 7 days) is expired.
// Both pages now read js/document-state.js.
//
// Since "Je documenten" (25 October 2026) the homepage no longer draws its
// own count: a signed-in visitor is sent on to /dashboard, and that screen
// counts with js/document-state.js tally(). This file holds the same facts
// against it: a stopped request is never Open, it reads Verlopen under Klaar,
// the number on each tab is the number of cards under it, and an old link
// with ?filter=cancelled lands on Klaar.
//
// PARAMANT_HOME_IN_SCREENSHOT_DIR=<dir> writes home-telt-gestopt-390.png, the
// screen at phone width, into that directory.
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

async function openDash(documents, at = '/dashboard', width = 390) {
  const page = await browser.newPage({ viewport:{ width, height:844 } });
  await stub(page, documents);
  await page.route('**/api/user/sends', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ ok:true, sends:[] }) }));
  await page.route('**/api/user/opvragen', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ requests:[] }) }));
  await page.goto(ORIGIN + at, { waitUntil:'domcontentloaded' });
  await page.locator('#dh-root:not([hidden])').waitFor();
  await page.waitForFunction(() => {
    const o = document.querySelector('[data-doc-count="open"]');
    const k = document.querySelector('[data-doc-count="klaar"]');
    return o && k && (o.textContent !== '0' || k.textContent !== '0');
  });
  return page;
}

async function counts(page) {
  return {
    open: await page.locator('[data-doc-count="open"]').innerText(),
    klaar: await page.locator('[data-doc-count="klaar"]').innerText(),
    openCards: await page.locator('#pa-open .pa-card').count(),
    klaarRows: await page.locator('#pa-klaar .pa-mini').count(),
  };
}

const server = await serve();
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
test.after(async () => { await browser.close(); server.close(); });

test('a signed-in visitor of the homepage lands on the one screen that counts', async () => {
  const page = await browser.newPage({ viewport:{ width:390, height:844 } });
  await stub(page, [STOPPED]);
  await page.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
  await page.waitForURL(/\/dashboard$/);
  await page.close();
});

test('a request past its signing window is not Open and reads Verlopen under Klaar', async () => {
  const page = await openDash([STOPPED, STOPPED_OPEN]);
  assert.deepEqual(await counts(page), { open:'0', klaar:'2', openCards:0, klaarRows:2 }, 'Open 0, Klaar 2, and the tabs count the cards');
  assert.doesNotMatch(await page.locator('#pa-open').innerText(), /Demo verzoek|Demo open/);
  await page.locator('#pa-tab-klaar').click();
  const klaar = await page.locator('#pa-klaar').innerText();
  assert.match(klaar, /Demo verzoek/);
  for (const r of await page.locator('#pa-klaar .pa-mini').allInnerTexts()) assert.match(r, /Verlopen/, 'a stopped request reads Verlopen: ' + r);
  if (SHOTS) {
    fs.mkdirSync(SHOTS, { recursive:true });
    await page.emulateMedia({ reducedMotion:'reduce' });
    await stableScreenshot(page, { path:path.join(SHOTS, 'home-telt-gestopt-390.png'), fullPage:false });
  }
  await page.close();
});

test('the English screen applies the same rule', async () => {
  const page = await openDash([STOPPED], '/en/dashboard');
  assert.equal((await counts(page)).open, '0');
  await page.locator('#pa-tab-klaar').click();
  assert.match(await page.locator('#pa-klaar').innerText(), /Expired/);
  await page.close();
});

test('a live request is the one card under Open, the stopped one is not counted there', async () => {
  const page = await openDash([LIVE, STOPPED]);
  const c = await counts(page);
  assert.equal(c.open, '1');
  assert.equal(c.klaar, '1');
  assert.equal(c.openCards, 1);
  const list = await page.locator('#pa-open').innerText();
  assert.match(list, /Demo lopend/);
  assert.doesNotMatch(list, /Demo verzoek/);
  assert.equal(await page.locator('#pa-tab-open').getAttribute('aria-selected'), 'true');
  await page.close();
});

test('/dashboard?filter=cancelled, the old link for Gestopt, opens on Klaar', async () => {
  const page = await openDash([LIVE, STOPPED], '/dashboard?filter=cancelled', 1280);
  assert.equal(await page.locator('#pa-tab-klaar').getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#pa-tab-open').getAttribute('aria-selected'), 'false');
  const list = await page.locator('#pa-klaar').innerText();
  assert.match(list, /Demo verzoek/);
  assert.doesNotMatch(list, /Demo lopend/);
  await page.close();
});
