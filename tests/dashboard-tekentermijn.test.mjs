// Acceptatie r4, A2: a request past its signing window is "Verlopen" on the
// dashboard, not "Wacht op handtekeningen" with an Intrekken button.
//
// The dashboard judged expiry on expires_at, which is how long the record is
// kept (30 days). Signing stops after 7 days (sign_expires_at, the date
// /co-sign shows as "Tekenen kan tot"). Between day 7 and day 30 the sender
// saw a request nobody could sign as waiting, with a withdraw button. The
// dialog has to show the same date /co-sign shows, and the status chip must
// not run off the right edge of the row on a desktop screen.
//
// Run: node --test tests/dashboard-tekentermijn.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };

const DAY = 86400000;
const now = Date.now();
const iso = (ms) => new Date(ms).toISOString();
// Created ten days ago: the 7-day signing window closed three days ago, the
// 30-day record is still kept for twenty more.
const EXPIRED = { id:'env_expired_abcdefghijklmnop', original_filename:'Huurcontract.pdf', status:'sent',
  created_at:iso(now - 10 * DAY), expires_at:iso(now + 20 * DAY), sign_expires_at:iso(now - 3 * DAY),
  party_count:2, signed_count:1, parties:[{ index:0, label:'Anna', status:'signed' }, { index:1, label:'Bram', status:'pending' }] };
const WAITING = { id:'env_waiting_abcdefghijklmnop', original_filename:'Opdracht.pdf', status:'sent',
  created_at:iso(now - DAY), expires_at:iso(now + 29 * DAY), sign_expires_at:iso(now + 6 * DAY),
  party_count:2, signed_count:0, parties:[{ index:0, label:'Anna', status:'pending' }, { index:1, label:'Bram', status:'pending' }] };

function serve() {
  const server = http.createServer((req, res) => {
    let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    if (pathname === '/dashboard') pathname = '/dashboard.html';
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

async function stub(page) {
  const json = (body) => (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(body) });
  await page.route('**/api/user/session/verify', json({ authenticated:true, email:'afzender@example.com' }));
  await page.route('**/api/user/me', json({ email:'afzender@example.com', label:'Afzender', plan:'pro',
    created_at:'2026-06-01T10:00:00.000Z', backup_codes_remaining:8, session_expires_at:iso(now + DAY), usage_purpose:'organisation' }));
  await page.route('**/api/user/dashboard/overview', (route) => route.fulfill({ status:500, body:'' }));
  await page.route('**/api/user/account/signing-key', json({ keys:[{ label:'Signing key' }] }));
  await page.route('**/api/user/account/webauthn/credentials', json({ passkeys:[{ label:'Passkey' }] }));
  await page.route('**/api/user/documents', json({ documents:[EXPIRED, WAITING] }));
  await page.route('**/api/user/parasign/inbox', json({ ok:true, count:0, documents:[] }));
}

const server = await serve();
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
test.after(async () => { await browser.close(); server.close(); });

test('a request past its 7-day signing window is Verlopen, without Intrekken, and the dialog shows the co-sign date', async () => {
  const page = await browser.newPage({ viewport:{ width:1280, height:900 } });
  await stub(page);
  await page.goto(ORIGIN + '/dashboard', { waitUntil:'networkidle' });
  await page.locator('#dh-root:not([hidden])').waitFor();
  // Lopend holds only the request that can still be signed.
  await page.waitForFunction(() => document.querySelectorAll('.dh-document').length >= 1);
  assert.equal(await page.locator('[data-doc-count="open"]').innerText(), '1', 'only the live request counts as Lopend');
  assert.equal(await page.locator('[data-doc-count="cancelled"]').innerText(), '1', 'the expired request is under Gestopt');
  const openText = await page.locator('#dh-documents').innerText();
  assert.ok(!/Huurcontract/.test(openText), 'the expired request is not under Lopend: ' + openText);

  await page.locator('[data-doc-filter="cancelled"]').click();
  const row = page.locator('.dh-document[data-document-id="' + EXPIRED.id + '"]');
  await row.waitFor();
  assert.match(await row.locator('.dh-status').innerText(), /Verlopen/);
  assert.equal(await row.locator('[data-pa-action="document-withdraw-ask"]').count(), 0, 'nothing to withdraw on an expired request');

  await row.locator('.dh-document-open').click();
  const body = await page.locator('#dh-document-dialog-body').innerText();
  const coSignDate = await page.evaluate((d) => window.paramantDate.day(d), EXPIRED.sign_expires_at);
  const keptDate = await page.evaluate((d) => window.paramantDate.day(d), EXPIRED.expires_at);
  assert.match(body, /Tekenen kan tot/i, body);
  assert.ok(body.includes(coSignDate), 'dialog shows the signing window ' + coSignDate + ': ' + body);
  assert.ok(!body.includes(keptDate), 'dialog does not present the 30-day record date as the deadline: ' + body);
  assert.equal(await page.locator('#dh-document-dialog [data-pa-action="document-cancel"]').count(), 0, 'no cancel in the dialog either');
  await page.close();
});

test('the status chip fits inside the row on a desktop screen', async () => {
  for (const width of [1280, 1024]) {
    const page = await browser.newPage({ viewport:{ width, height:900 } });
    await stub(page);
    await page.goto(ORIGIN + '/dashboard', { waitUntil:'networkidle' });
    await page.locator('#dh-root:not([hidden])').waitFor();
    const chip = page.locator('.dh-document[data-document-id="' + WAITING.id + '"] .dh-status');
    await chip.waitFor();
    assert.match(await chip.innerText(), /Wacht op handtekeningen/);
    const m = await chip.evaluate((el) => {
      const row = el.closest('.dh-document-open');
      const pad = parseFloat(getComputedStyle(row).paddingRight) || 0;
      return { chipRight:el.getBoundingClientRect().right, rowRight:row.getBoundingClientRect().right - pad,
        scroll:el.scrollWidth, client:el.clientWidth };
    });
    assert.ok(m.chipRight <= m.rowRight + 0.5, `chip ends inside the row at ${width}px: ` + JSON.stringify(m));
    assert.ok(m.scroll <= m.client + 1, `chip text is not clipped at ${width}px: ` + JSON.stringify(m));
    await page.close();
  }
});
