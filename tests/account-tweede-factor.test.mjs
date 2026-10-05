// /account: acties die het account veranderen vragen een verse tweede factor
// en zeggen in woorden wat er misging (matrix ACCT-32, sweep-acct punt 2).
//   - een passkey heeft een knop Verwijderen (DELETE
//     /api/user/account/webauthn/credentials/:credId met { totp } of { backup_code });
//   - Alle codes vernieuwen, Nieuwe authenticator-app en Account deactiveren
//     sturen de code mee en zijn bij een fout niet meer stil;
//   - /auth/request-reset vraagt een back-upcode en meldt 401 in woorden.
// Echte pagina's, API nagebootst. Ook in WebKit: ~/bin/pw-webkit.sh tests/account-tweede-factor.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/account': '/account.html', '/en/account': '/en/account.html', '/auth/request-reset': '/auth/request-reset.html', '/en/auth/request-reset': '/en/auth/request-reset.html' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  p = aliases[p] || p;
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });
const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const CRED = 'cred_abcdefghijklmnopqrstuvwxyz012345';

async function openAccount(route, handlers = {}) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  const seen = [];
  const dialogs = [];
  page.on('dialog', async (d) => { dialogs.push(d.message()); if (d.type() === 'prompt') await d.accept(handlers.promptAnswer || ''); else await d.accept(); });
  await page.route('**/api/**', (r) => json(r, {}));
  await page.route('**/api/user/account', (r) => {
    const req = r.request();
    if (req.method() === 'DELETE') { seen.push({ url: req.url(), method: 'DELETE', body: req.postDataJSON() }); return handlers.deleteAccount ? handlers.deleteAccount(r) : json(r, { success: true }); }
    return json(r, { email: 'sandeep@example.com', plan: 'pro', created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 9 });
  });
  await page.route('**/api/user/account/webauthn/credentials', (r) => json(r, { passkeys: handlers.passkeys || [{ credId: CRED, label: 'Telefoon', created_at: '2026-09-01T10:00:00.000Z' }], total: 1 }));
  await page.route('**/api/user/account/webauthn/credentials/*', (r) => {
    const req = r.request();
    seen.push({ url: req.url(), method: req.method(), body: req.postDataJSON() });
    return handlers.removePasskey ? handlers.removePasskey(r) : json(r, { ok: true, remaining_active: 0 });
  });
  await page.route('**/api/user/account/backup-codes/regenerate', (r) => {
    seen.push({ url: r.request().url(), method: 'POST', body: r.request().postDataJSON() });
    return handlers.regen ? handlers.regen(r) : json(r, { backup_codes: ['AAAA-BBBB-CCCC'] });
  });
  await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
  await page.locator('#state-account').waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
  return { page, seen, dialogs };
}

test('ACCT-32: een passkey heeft een knop Verwijderen die de route met de code aanroept', async () => {
  const { page, seen } = await openAccount('/account');
  const btn = page.locator(`[data-remove-passkey="${CRED}"]`);
  await btn.waitFor({ timeout: 15000 });
  assert.equal((await btn.textContent()).trim(), 'Verwijderen');
  await btn.click();
  await page.locator('#sf-code').fill('123456');
  await page.locator('#sf-confirm').click();
  await page.waitForFunction(() => /Passkey verwijderd/.test(document.getElementById('account-passkey-status')?.textContent || ''), null, { timeout: 10000 });
  const del = seen.find((s) => s.method === 'DELETE' && s.url.includes('/webauthn/credentials/'));
  assert.ok(del, 'DELETE verstuurd');
  assert.ok(del.url.endsWith('/api/user/account/webauthn/credentials/' + CRED), del.url);
  assert.deepEqual(del.body, { totp: '123456' });
  await page.close();
});

test('ACCT-32: een foute code zegt dat er niets veranderde', async () => {
  const { page } = await openAccount('/en/account', { removePasskey: (r) => json(r, { error: 'invalid_second_factor' }, 403) });
  await page.locator(`[data-remove-passkey="${CRED}"]`).click({ timeout: 15000 });
  await page.locator('#sf-code').fill('aaaa-bbbb-cccc');
  await page.locator('#sf-confirm').click();
  await page.waitForFunction(() => /did not match/.test(document.getElementById('account-passkey-status')?.textContent || ''), null, { timeout: 10000 });
  await page.close();
});

test('back-upcodes vernieuwen stuurt de code mee en is bij een fout niet stil', async () => {
  const { page, seen, dialogs } = await openAccount('/account', { regen: (r) => json(r, { error: 'invalid_second_factor' }, 403) });
  await page.locator('#regen-backup').click();
  await page.locator('#sf-code').fill('654321');
  await page.locator('#sf-confirm').click();
  await page.waitForFunction(() => !document.getElementById('sf-panel'), null, { timeout: 5000 });
  await page.waitForTimeout(300);
  const call = seen.find((s) => s.url.includes('backup-codes/regenerate'));
  assert.deepEqual(call && call.body, { totp: '654321' });
  assert.ok(dialogs.some((d) => /Die code klopt niet/.test(d)), dialogs.join(' | '));
  await page.close();
});

test('account deactiveren vraagt na DEACTIVEREN ook de code', async () => {
  const { page, seen } = await openAccount('/account', { promptAnswer: 'DEACTIVEREN', deleteAccount: (r) => json(r, { error: 'second_factor_required' }, 400) });
  await page.locator('#delete-account').click();
  await page.locator('#sf-code').fill('AAAA-BBBB-CCCC');
  await page.locator('#sf-confirm').click();
  await page.waitForTimeout(500);
  const call = seen.find((s) => s.method === 'DELETE' && /\/api\/user\/account$/.test(s.url));
  assert.deepEqual(call && call.body, { backup_code: 'AAAA-BBBB-CCCC' });
  assert.ok(page.url().endsWith('/account'), 'bij een fout blijft de klant op de pagina');
  await page.close();
});

for (const [route, want] of [['/auth/request-reset', /horen niet bij elkaar/], ['/en/auth/request-reset', /do not match/]]) {
  test(`${route}: back-upcode verplicht en 401 in woorden`, async () => {
    const page = await browser.newPage();
    let body = null;
    await page.route('**/js/pow-captcha.js*', (r) => r.fulfill({ status: 200, contentType: 'text/javascript', body: 'window.ParamantCaptcha={getCaptchaProof:async()=>({challenge_id:"c",nonce:"n"})};' }));
    await page.route('**/api/user/auth/request-totp-reset', (r) => { body = r.request().postDataJSON(); return json(r, { error: 'invalid_credentials' }, 401); });
    await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
    assert.equal(await page.locator('#backup-code').getAttribute('required'), '');
    await page.fill('#email', 'sandeep@example.com');
    await page.fill('#backup-code', 'aaaa-bbbb-cccc');
    await page.click('#submit-btn');
    await page.waitForFunction(() => document.getElementById('error').classList.contains('visible'), null, { timeout: 10000 });
    assert.deepEqual(body, { email: 'sandeep@example.com', backup_code: 'AAAA-BBBB-CCCC', challenge_id: 'c', nonce: 'n' });
    assert.match(await page.locator('#error').textContent(), want);
    await page.close();
  });
}
