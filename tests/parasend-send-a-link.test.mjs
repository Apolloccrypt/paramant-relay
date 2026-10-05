// parasend-send-a-link.test.mjs: the asynchronous stand on /parashare, driven
// in a real browser from the chooser to the receiver's saved file.
//
// WHY THIS SUITE EXISTS. The ParaSend web app was a live handshake and nothing
// else: both sides online, a short code compared out loud, then the file moves.
// An administratiekantoor that wants to mail a payslip to somebody who is not
// at a desk right now cannot use that, and said so. The "Send a link" stand is
// the answer, and it is a chain of five things that each have to hold or the
// feature is a link that does not open:
//
//   1. the chooser really switches the page to the other stand
//   2. the file is sealed IN THE BROWSER, so what reaches /v2/inbound is
//      ciphertext and the key is not in the request at all
//   3. the link carries the key after the '#', where no server sees it
//   4. /get takes that link, with no account, and gives the file back BYTE FOR
//      BYTE. This is the assertion that would catch a wire-format drift
//      between the sender and the receiver, which is the failure that turns a
//      shipped link in somebody's mailbox into a permanent error page
//   5. opening it a second time fails, and says why
//
// Everything the relay would do is stubbed at the network edge, so this suite
// is about the two browser halves agreeing with each other. That the relay
// really burns a token on the second fetch is the other half of the pair, and
// it is measured against a real relay in relay/test/route-dl-share-link.test.js.
//
// Run: node tests/parasend-send-a-link.test.mjs
//      (PLAYWRIGHT_CHROMIUM_PATH=... to pick a browser)
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json' };
const aliases = { '/': '/index.html', '/parashare': '/parashare.html', '/get': '/get.html',
  '/en/parashare': '/en/parashare.html', '/en/get': '/en/get.html' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const rel = aliases[url.pathname] || url.pathname;
  const file = path.join(ROOT, rel);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end('no'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

// The file the office is sending. Deliberately not text: a payslip is a PDF,
// and a byte-for-byte comparison of arbitrary bytes is what catches an encoding
// bug that a string round-trip would hide.
const PAYLOAD_BYTES = Array.from({ length: 777 }, (_, i) => (i * 37 + 11) % 256);
const FILE_NAME = 'loonstrook-2026-09.bin';
const TTL_MS = 3_600_000;
const DL_TOKEN = 'a'.repeat(48);

// What the stubbed relay was handed. The whole point of half the assertions
// below is what is NOT in here.
let uploaded = null;

async function stubRelay(page) {
  // Broad first, specific after: Playwright tries the LAST registered handler
  // first, so registering the catch-all second would swallow the token mint and
  // the page would sit on "Account session could not be started" forever.
  await page.route('**/api/user/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }),
  }));
  // Only the health sector answers, which is also how the page picks a sector.
  for (const host of ['legal', 'finance', 'iot']) {
    await page.route(`https://${host}.paramant.app/**`, (route) => route.abort());
  }
  await page.route('https://health.paramant.app/v2/check-key', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({
      valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 },
    }),
  }));
  await page.route('https://health.paramant.app/v2/inbound', async (route) => {
    uploaded = JSON.parse(route.request().postData() || '{}');
    await route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ ok: true, hash: uploaded.hash, ttl_ms: TTL_MS, size: 0, download_token: DL_TOKEN }),
    });
  });
  await page.route('https://health.paramant.app/v2/dl/**', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, enc_meta: null, file_size: 0, ttl_left_s: 3600, used: false }),
  }));
}

// Both languages walk the same path. /parashare and /get are Dutch; the English
// text they carried before lives on at /en/parashare and /en/get, and every
// English pin below still holds there.
const MONTH = '(January|February|March|April|May|June|July|August|September|October|November|December)';
const MAAND = '(januari|februari|maart|april|mei|juni|juli|augustus|september|oktober|november|december)';
const LANGS = [
  {
    tag: 'en', sendPath: '/en/parashare', getPrefix: '/en', markupFile: 'en/parashare.html',
    limit: /A link stays open for up to 24 hours\./,
    planInMarkup: /\d+ (hours?|days?) on (Community|Firm|Pro|Enterprise)|up to \d+ (hours?|days?)/,
    until: new RegExp('until \\d{1,2} ' + MONTH + ' \\d{4}, \\d{2}:\\d{2} UTC'),
    worksOnce: /Works once/, waiting: /Waiting for the receiver/,
    noReceipt: /no signed delivery receipt/i,
    gone: /permanently destroyed/i,
    burned: /already been downloaded and burned/i, singleUse: /single-use/i,
  },
  {
    tag: 'nl', sendPath: '/parashare', getPrefix: '', markupFile: 'parashare.html',
    limit: /Een link blijft maximaal 24 uur open\./,
    planInMarkup: /\d+ (uur|dagen) bij (Community|Firm|Pro|Enterprise)|maximaal \d+ (uur|dagen)/,
    // The Dutch page writes the month in Dutch: format-date.js reads <html lang>.
    until: new RegExp('tot \\d{1,2} ' + MAAND + ' \\d{4}, \\d{2}:\\d{2} UTC'),
    worksOnce: /Werkt één keer/, waiting: /Wacht op de ontvanger/,
    noReceipt: /geen ondertekend ontvangstbewijs/i,
    gone: /voorgoed vernietigd/i,
    burned: /al gedownload en daarna gewist/i, singleUse: /werkt maar één keer/i,
  },
];
for (const L of LANGS) {
uploaded = null;
// ── The sender ───────────────────────────────────────────────────────────────
const sender = await browser.newPage();
await stubRelay(sender);
await sender.goto(`${ORIGIN}${L.sendPath}`, { waitUntil: 'domcontentloaded' });

// The chooser is on the page before anything is picked, which is the whole
// complaint this feature answers: the buyer must not have to reach step 2 to
// find out which stands exist.
ok(L.tag + ': ' + 'the chooser offers both choices above step 1',
  await sender.locator('#ps-mode-link').isVisible() && await sender.locator('#ps-mode-group').isVisible());
// Since 24 September 2026 the link is the default: "To one person", with
// Extra safe (the live hand-over) unticked.
ok(L.tag + ': ' + '"To one person" is the choice selected on arrival, as a link',
  await sender.locator('#ps-mode-link').getAttribute('aria-checked') === 'true'
  && !(await sender.isChecked('#ps-extra-safe')));

// The expiry in the limit line comes from the plan API, not from the markup.
// The stub answered with link_ttl_ms for a Firm account (the tiers.js 'pro'
// row, 24 hours); the page must have written that in. Until the answer
// arrives the line is hidden rather than guessed.
await sender.waitForSelector('#ps-plan:not([hidden])', { timeout: 15000 });
const limitLine = await sender.locator('#ps-limit').textContent();
ok(L.tag + ': ' + 'the limit line names the expiry this plan really gets, from the plan API',
  L.limit.test(limitLine), limitLine);
// No hour written into the markup a visitor sees. Developer comments are
// stripped first: this checks the page, not the file.
const markup = fs.readFileSync(path.join(ROOT, L.markupFile), 'utf8').replace(/<!--[\s\S]*?-->/g, ' ');
ok(L.tag + ': ' + 'no per-plan link lifetime is hardcoded in the markup',
  !L.planInMarkup.test(markup),
  'the times must come from tiers.js through the plan API, never from the page');
ok(L.tag + ': ' + 'the live stepper is hidden on the link',
  !(await sender.locator('#ps-stepper').isVisible()));

await sender.locator('#file-input').setInputFiles({
  name: FILE_NAME, mimeType: 'application/octet-stream', buffer: Buffer.from(PAYLOAD_BYTES),
});
await sender.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
await sender.locator('#btn-create-session').click();
sender.on('console', (m) => { if (m.type() === 'error') console.error('[console]', m.text()); });
sender.on('pageerror', (e) => console.error('[pageerror]', String(e).slice(0, 200)));
try {
  await sender.waitForSelector('#step-link.active', { timeout: 20000 });
} catch (e) {
  const zichtbaar = await sender.evaluate(() => {
    const st = [...document.querySelectorAll('.step')].filter(s => s.classList.contains('active')).map(s => s.id);
    const f = document.getElementById('create-status') || document.getElementById('seal-status');
    return { actief: st, melding: f ? f.textContent : '(geen)' };
  });
  console.error('[stand]', JSON.stringify(zichtbaar));
  throw e;
}

// What the relay was handed. It is base64, it is not the file, and there is no
// key anywhere in the request body.
ok(L.tag + ': ' + 'the upload carries a payload and a hash', !!uploaded && !!uploaded.payload && /^[a-f0-9]{64}$/.test(uploaded.hash || ''));
const sentBytes = Buffer.from(uploaded.payload, 'base64');
ok(L.tag + ': ' + 'what reached the relay is not the file',
  Buffer.compare(sentBytes.subarray(0, PAYLOAD_BYTES.length), Buffer.from(PAYLOAD_BYTES)) !== 0,
  'the bytes on the wire equal the plaintext, so nothing was encrypted');
ok(L.tag + ': ' + 'the file name never reaches the relay',
  !JSON.stringify(uploaded).includes(FILE_NAME),
  'the name is inside the sealed bytes and must not be in the request');
ok(L.tag + ': ' + 'no key material is in the request body',
  !('key' in uploaded) && !('iv' in uploaded) && !JSON.stringify(uploaded.meta || {}).includes('key'));

const shownLink = (await sender.locator('#ps-link-list .ps-link-url').first().textContent()).trim();
ok(L.tag + ': ' + 'the link points at /get with the token', shownLink.includes('/get?t=' + DL_TOKEN), shownLink);
ok(L.tag + ': ' + 'the link names the relay sector', /[?&]r=health/.test(shownLink), shownLink);
const fragment = shownLink.split('#')[1] || '';
ok(L.tag + ': ' + 'the key travels in the URL fragment', fragment.length >= 58 && !shownLink.split('#')[0].includes(fragment),
  'fragment: ' + fragment.slice(0, 12) + '...');
ok(L.tag + ': ' + 'the fragment is unpadded base64url', /^[A-Za-z0-9_-]+$/.test(fragment), fragment.slice(0, 12));

const metaText = (await sender.locator('#ps-link-list .ps-link-row').first().textContent()).replace(/\s+/g, ' ');
// One date format for the whole site (#424): a month written out, a year, and a
// named zone. A slashed date here is the exact ambiguity that rule exists for.
// The two things a sender needs about a link, how often it opens and when it
// stops, are now one sentence rather than two badges: "Works once, until
// 6 September 2026, 14:10 UTC".
ok(L.tag + ': ' + 'the expiry is written in the one site date format',
  L.until.test(metaText),
  metaText);
ok(L.tag + ': ' + 'the row warns the link works once', L.worksOnce.test(metaText), metaText);
ok(L.tag + ': ' + 'the row starts out waiting for the receiver', L.waiting.test(metaText), metaText);
ok(L.tag + ': ' + 'the page says there is no signed receipt for this path',
  L.noReceipt.test(await sender.locator('#ps-link-receipt-note').textContent()));
ok(L.tag + ': ' + 'a copy button sits on the row', await sender.locator('#ps-link-list button[data-click="copySentLink"]').first().isVisible());

// ── The receiver ─────────────────────────────────────────────────────────────
// A different browser context: no account, no session, nothing carried over
// from the sender but the link itself.
const receiverCtx = await browser.newContext({ acceptDownloads: true });
const receiver = await receiverCtx.newPage();
let dlServed = 0;
await receiver.route('https://health.paramant.app/v2/dl/**/get', async (route) => {
  dlServed++;
  if (dlServed > 1) {
    return route.fulfill({ status: 410, contentType: 'text/html', body: '<h1>burned</h1>' });
  }
  await route.fulfill({ status: 200, contentType: 'application/octet-stream', body: sentBytes });
});

const receiveUrl = ORIGIN + L.getPrefix + shownLink.slice(shownLink.indexOf('/get'));
const downloadPromise = receiver.waitForEvent('download', { timeout: 30000 });
await receiver.goto(receiveUrl, { waitUntil: 'domcontentloaded' });
const download = await downloadPromise;
const saved = path.join(process.env.TMPDIR || '/tmp', 'parasend-link-' + process.pid + '.bin');
await download.saveAs(saved);
const back = fs.readFileSync(saved);
fs.unlinkSync(saved);

ok(L.tag + ': ' + 'the receiver needs no account: the link opens straight onto the file', dlServed === 1);
ok(L.tag + ': ' + 'the saved file has the sender\'s name back', download.suggestedFilename() === FILE_NAME, download.suggestedFilename());
ok(L.tag + ': ' + 'the file comes back byte for byte', Buffer.compare(back, Buffer.from(PAYLOAD_BYTES)) === 0,
  `got ${back.length} bytes, sent ${PAYLOAD_BYTES.length}`);

await receiver.waitForSelector('#step-done.active', { timeout: 15000 });
ok(L.tag + ': ' + 'the receiver is told the relay copy is gone',
  L.gone.test(await receiver.locator('#step-done .done-line').textContent()));

// ── The second open ──────────────────────────────────────────────────────────
const second = await receiverCtx.newPage();
await second.route('https://health.paramant.app/v2/dl/**/get', (route) =>
  route.fulfill({ status: 410, contentType: 'text/html', body: '<h1>burned</h1>' }));
await second.goto(receiveUrl, { waitUntil: 'domcontentloaded' });
await second.waitForSelector('#step-burned.active', { timeout: 15000 });
const burned = (await second.locator('#step-burned').textContent()).replace(/\s+/g, ' ');
ok(L.tag + ': ' + 'a second open says the file has already been downloaded and burned',
  L.burned.test(burned), burned.slice(0, 120));
ok(L.tag + ': ' + 'a second open says why: the links are single-use',
  L.singleUse.test(burned), burned.slice(0, 200));

}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((c) => !c.pass)) process.exit(1);
console.log(`\nparasend-send-a-link: ${checks.length} checks passed`);
