// Acceptatie ronde 3 op cc931c2f, de punten die zakten:
//   A1  "Samen ondertekenen": wie later met het oorspronkelijke bestand
//       controleert, kreeg rood zonder dat ergens stond welk bestand het is
//   A2  dashboard: de rij was de oude knop terwijl de CSS een nieuwe opbouw
//       verwachtte (teksten liepen in elkaar), en een verlopen verzoek stond
//       als "Wacht op handtekeningen" bij Lopend, met een annuleerknop
//   A3  "link opnieuw": de mail stuurde de afzender naar het dashboard, waar
//       de volledige link nergens stond
//   A4  tegenstrijdige teksten op /sign
// Run: node --test tests/acceptatie-r3.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FE = path.join(ROOT, 'frontend');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png' };
const LINK = 'http://localhost/co-sign?env=env_open_000000000000000001&p=1&t=tok#ks=v1.' + 'A'.repeat(43);

const docs = [
  { id: 'env_open_000000000000000001', original_filename: 'lopend-contract.pdf', status: 'sent', created_at: '2026-10-01T10:00:00Z', expires_at: '2099-01-01T10:00:00Z', parties: [{ index: 0, label: 'Signer Demo', status: 'pending' }], signed_count: 0, party_count: 1 },
  { id: 'env_old_0000000000000000002', original_filename: 'verlopen-contract.pdf', status: 'sent', created_at: '2026-09-01T10:00:00Z', expires_at: '2026-09-08T10:00:00Z', parties: [{ index: 0, label: 'Signer Demo', status: 'pending' }], signed_count: 0, party_count: 1 },
];

let server, browser, ORIGIN;
before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const send = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/api/user/me') return send(200, { email: 'demo@example.com', plan: 'pro', created_at: null, backup_codes_remaining: 10 });
    if (u.pathname === '/api/user/session/verify') return send(200, { authenticated: true, email: 'demo@example.com' });
    if (u.pathname === '/api/user/documents') return send(200, { documents: docs });
    if (u.pathname === '/api/user/sends') return send(200, { sends: [] });
    if (u.pathname === '/api/user/account/webauthn/credentials') return send(200, { passkeys: [] });
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/v2/')) return send(200, {});
    const file = path.join(FE, u.pathname === '/dashboard' ? 'dashboard.html' : u.pathname);
    if (!file.startsWith(FE)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, b) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' }); res.end(b); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  ORIGIN = `http://localhost:${server.address().port}`;
  browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
});
after(async () => { if (browser) await browser.close(); if (server) server.close(); });

async function dashboard() {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await ctx.addInitScript((link) => {
    try {
      localStorage.setItem('paramant.keysetup.dismissed.v1', '1');
      localStorage.setItem('paramant.cosign.links.v1:env_open_000000000000000001', JSON.stringify({ exp: Date.now() + 864e5, links: [{ i: 0, label: 'Signer Demo', url: link }] }));
    } catch (_) {}
  }, LINK);
  const page = await ctx.newPage();
  await page.goto(ORIGIN + '/dashboard');
  await page.waitForSelector('#dh-documents .dh-document', { timeout: 15000 });
  return { ctx, page };
}

test('A2: a row is the container the CSS expects, with three columns on desktop', async () => {
  const { ctx, page } = await dashboard();
  const row = page.locator('.dh-document[data-document-id="env_open_000000000000000001"]');
  assert.equal(await row.locator('.dh-document-open').count(), 1, 'the row has its open button');
  assert.equal(await row.locator('.dh-document-foot').count(), 1, 'the row has its strip');
  const cols = await row.locator('.dh-document-open').evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(' ').length);
  assert.equal(cols, 3);
  // Withdraw asks in the row; it does not open the dialog.
  await row.locator('[data-pa-action="document-withdraw-ask"]').click();
  await page.waitForSelector('.dh-rowask');
  assert.equal(await page.locator('#dh-document-dialog').isHidden(), true);
  await ctx.close();
});

test('A2: an expired request is "Verlopen", not open, and has nothing to withdraw', async () => {
  const { ctx, page } = await dashboard();
  assert.equal(await page.locator('[data-doc-count="open"]').innerText(), '1');
  await page.locator('[data-doc-filter="all"]').click();
  const row = page.locator('.dh-document[data-document-id="env_old_0000000000000000002"]');
  await row.waitFor();
  assert.match(await row.innerText(), /Verlopen/);
  assert.doesNotMatch(await row.innerText(), /Wacht op handtekeningen|Intrekken/);
  await ctx.close();
});

test('A3: the dialog of an open request hands over the full link kept in this browser, or says it is not here', async () => {
  const { ctx, page } = await dashboard();
  await page.locator('.dh-document[data-document-id="env_open_000000000000000001"] .dh-document-open').click();
  await page.waitForSelector('#dh-document-dialog:not([hidden])');
  const btn = page.locator('[data-pa-action="document-copy-link"]');
  assert.equal(await btn.count(), 1);
  assert.equal(await btn.getAttribute('data-link'), LINK);
  await page.evaluate(() => localStorage.removeItem('paramant.cosign.links.v1:env_open_000000000000000001'));
  await page.evaluate(() => document.querySelector('[data-pa-action="document-close"]')?.click());
  await page.locator('.dh-document[data-document-id="env_open_000000000000000001"] .dh-document-open').click();
  await page.waitForSelector('#dh-document-dialog:not([hidden])');
  assert.match(await page.locator('#dh-document-dialog').innerText(), /niet in deze browser[\s\S]*nieuw verzoek/);
  await ctx.close();
  const relay = read('relay/relay.js');
  assert.match(relay, /Open uw dashboard in de browser waarmee u het verzoek verstuurde/, 'the mail to the sender points at that exact place');
  assert.doesNotMatch(relay, /uit uw dashboard of uit uw eigen verzonden bericht/);
  assert.match(read('frontend/sign-flow.js'), /rememberSignerLinks\(envelope\.id/);
});

test('A1 and A4: the texts say what is true', () => {
  const flow = read('frontend/sign-flow.js');
  assert.doesNotMatch(flow, /Klik nogmaals op Versturen|Click Send again/, 'no "send anyway" the server refuses');
  assert.doesNotMatch(flow, /Latere medeondertekenaars staan in de envelop, niet op deze pagina/);
  assert.match(flow, /De medeondertekenaars tekenen precies dit bestand\. Controleer het eindbewijs later op \/verify met /, 'together mode names the file to verify');
  const noKey = flow.slice(flow.indexOf("e.code === 'no_signing_passkey'"), flow.indexOf("e.code === 'no_signing_passkey'") + 1200);
  assert.match(noKey, /webauthn\/credentials/, 'no passkey on the account: the code, not Face ID');
  assert.match(noKey, /U ondertekent met de code uit uw authenticator-app\./);
  assert.doesNotMatch(read('frontend/sign.html'), /dan bevestigt u met Face ID, Touch ID of uw beveiligingssleutel\./);
  assert.match(read('frontend/co-sign.js'), /samen met het bestand dat iedereen tekende/);
});
