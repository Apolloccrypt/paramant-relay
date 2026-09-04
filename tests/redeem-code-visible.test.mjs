/* "Have a code?" on the two pages that carry it, in a real browser.
 *
 * WHAT THIS IS FOR. The relay suites prove that a code grants a term. They
 * cannot prove that anybody can reach the box, that pressing the button says
 * what happened, or that a refusal reads as a sentence rather than as a machine
 * string. Those are the parts a supporter actually meets, and they live in
 * markup and in one small script.
 *
 * Four things are pinned:
 *   1. the field is on /pricing and on /account, and it is the SAME markup
 *      contract on both (js/redeem-code.js finds it by data-redeem-form);
 *   2. a success prints the relay's own sentence, which names the plans and the
 *      dates and says nothing was charged;
 *   3. a refusal prints the relay's own sentence too, and never an error code;
 *   4. nothing is fetched until the button is pressed. The credential these
 *      pages run on is minted by the click, not by the page opening, and a code
 *      field that mints a token on load would undo that.
 *
 * The API is mocked, on purpose: this asks what the browser does with an
 * answer, not what the relay answers. What the relay answers is
 * relay/test/route-coupon.test.js.
 *
 * Run: PLAYWRIGHT_CHROMIUM_PATH=/usr/bin/google-chrome node --test tests/redeem-code-visible.test.mjs
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2',
};
const aliases = { '/': '/index.html', '/account': '/account.html', '/pricing': '/pricing.html' };

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
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const json = (route, body, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const GRANTED = {
  ok: true,
  code: 'COFFEE',
  granted: [
    { product: 'parasign', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00.000Z' },
    { product: 'parasend', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00.000Z' },
  ],
  message: 'Your code is redeemed. You now have ParaSign Pro until 3 December 2026 and ParaSend Pro until 3 December 2026. Nothing was charged.',
};

// Everything the two pages fetch on load, so the redeem field is the only thing
// under test and a missing stub cannot look like a failure of it.
async function stubPage(page, redeemHandler) {
  const calls = { token: 0, redeem: 0 };
  // Playwright tries the most recently added route FIRST, so the catch-all goes
  // in before the specific ones, not after.
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'community', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0,
  }));
  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'community', plan_parasign: 'free', plan_parasend: 'community',
    paid_until_parasign: null, paid_until_parasend: null,
    period: null, amount_eur: null, access_until: null, next_billing_date: null,
    auto_renews: false, cancellation_scheduled_at: null,
  }));
  await page.route('**/api/user/billing/history', (route) => json(route, { history: [] }));
  await page.route('**/api/user/billing/invoices', (route) => json(route, { invoices: [] }));
  await page.route('**/api/user/app/token', (route) => {
    calls.token++;
    return json(route, { ok: true, token: 'pst_stub_token', expires_in_s: 900 });
  });
  await page.route('**/v2/billing/redeem', (route) => {
    calls.redeem++;
    return redeemHandler(route);
  });
  return calls;
}

async function open(slug, redeemHandler) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  const calls = await stubPage(page, redeemHandler);
  await page.goto(ORIGIN + slug, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('[data-redeem-form]', { timeout: 10000 });
  return { page, calls };
}

async function typeAndSubmit(page, code) {
  await page.fill('[data-redeem-form] [data-redeem-input]', code);
  await page.click('[data-redeem-form] [data-redeem-submit]');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-redeem-form] [data-redeem-message]');
    return el && !el.hidden && el.textContent && !/Checking your code/.test(el.textContent);
  }, null, { timeout: 10000 });
  return page.textContent('[data-redeem-form] [data-redeem-message]');
}

for (const slug of ['/pricing', '/account']) {
  test(`${slug} carries the code field, and asks for no credential until it is used`, async () => {
    const { page, calls } = await open(slug, (route) => json(route, GRANTED));
    // 4. Nothing on load. The whole point of the app token is that reading a
    // page costs no credential; a field that mints one on load would undo it.
    assert.equal(calls.token, 0, `${slug} minted a session token before anybody pressed anything`);
    assert.equal(calls.redeem, 0);

    const input = await page.$('[data-redeem-form] [data-redeem-input]');
    const button = await page.$('[data-redeem-form] [data-redeem-submit]');
    assert.ok(input, `${slug} has no input inside the redeem form`);
    assert.ok(button, `${slug} has no submit button inside the redeem form`);
    // The claim that made this field allowed on a page about prices.
    const text = await page.textContent('[data-redeem-form]');
    assert.match(text, /nothing is charged, now or later/i,
      `${slug}: the field must say a code charges nothing, which is what the relay does`);
    await page.close();
  });

  test(`${slug} prints what was granted, in the relay's own words`, async () => {
    const { page, calls } = await open(slug, (route) => json(route, GRANTED));
    const msg = await typeAndSubmit(page, 'coffee');
    assert.equal(calls.token, 1, `${slug} did not mint the token on the click`);
    assert.equal(calls.redeem, 1);
    assert.equal(msg.trim(), GRANTED.message,
      `${slug}: the page must print the sentence the relay sent, not one of its own`);
    // The box is cleared, so a second press cannot re-send the same code by
    // accident.
    assert.equal(await page.inputValue('[data-redeem-form] [data-redeem-input]'), '');
    await page.close();
  });

  test(`${slug} prints a refusal as a sentence, never as an error code`, async () => {
    const refusal = { error: 'exhausted', message: 'That code has been fully claimed. It has run out.' };
    const { page } = await open(slug, (route) => json(route, refusal, 409));
    const msg = await typeAndSubmit(page, 'COFFEE');
    assert.equal(msg.trim(), refusal.message, `${slug}: the refusal must be the relay's sentence`);
    assert.doesNotMatch(msg, /exhausted|409|error/i,
      `${slug}: a machine string reached the reader: ${msg}`);
    // The code stays in the box on a refusal: a typo is corrected, not retyped.
    assert.equal(await page.inputValue('[data-redeem-form] [data-redeem-input]'), 'COFFEE');
    await page.close();
  });

  test(`${slug} says something useful when the code field is empty or the server is down`, async () => {
    const { page, calls } = await open(slug, (route) => route.abort());
    // Empty: refused before any request goes out.
    await page.click('[data-redeem-form] [data-redeem-submit]');
    await page.waitForFunction(() => {
      const el = document.querySelector('[data-redeem-form] [data-redeem-message]');
      return el && !el.hidden && el.textContent;
    }, null, { timeout: 10000 });
    assert.equal((await page.textContent('[data-redeem-form] [data-redeem-message]')).trim(),
      'Enter your code first.');
    assert.equal(calls.redeem, 0, 'an empty box must not reach the relay');

    // Server unreachable: one sentence, and the button works again afterwards.
    const msg = await typeAndSubmit(page, 'COFFEE');
    assert.match(msg, /try again in a minute/i, msg);
    assert.equal(await page.isDisabled('[data-redeem-form] [data-redeem-submit]'), false,
      'a failed attempt must not leave the button stuck');
    await page.close();
  });
}

test('a redeemed code refreshes the plan block on /account', async () => {
  // The plan and the term on that page are exactly what the code changed, so
  // leaving them saying what was true before the click is the one thing this
  // field must not do.
  const { page } = await open('/account', (route) => json(route, GRANTED));
  // The page loaded on the Community answer from stubPage. From here on the
  // account holds the `pro` tier, which /account and /pricing both name Firm
  // since 6 September 2026, so the block can only say so if it was read again.
  await page.waitForFunction(() => {
    const el = document.getElementById('billing-plan');
    return el && el.textContent && el.textContent.trim() !== '\u2014';
  }, null, { timeout: 10000 });
  assert.doesNotMatch(await page.textContent('#billing-plan'), /Firm/,
    'the account has to start on Community, or this test cannot tell a refresh from the first read');

  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'pro', plan_parasign: 'pro', plan_parasend: 'pro',
    paid_until_parasign: '2026-12-03T00:00:00.000Z',
    paid_until_parasend: '2026-12-03T00:00:00.000Z',
    period: null, amount_eur: null, access_until: '2026-12-03T00:00:00.000Z',
    next_billing_date: null, auto_renews: false, cancellation_scheduled_at: null,
  }));

  await typeAndSubmit(page, 'COFFEE');
  await page.waitForFunction(() => {
    const el = document.getElementById('billing-plan');
    return el && /Firm/.test(el.textContent || '');
  }, null, { timeout: 10000 });
  const plan = await page.textContent('#billing-plan');
  assert.match(plan, /Firm/, `the plan block still says ${plan} after a code was redeemed`);
  await page.close();
});

test.after(async () => {
  await browser.close();
  server.close();
});
