// /parashare, Send a link to named people, against a stubbed relay.
//
// Three faults reproduced on 57b0fdf9:
//   - a Community sender with two addresses sealed and uploaded the file, and
//     only then heard "Your plan allows 1 recipients per send", stuck on
//     "Sealing 0%". The list is now checked first (POST /v2/sends/precheck)
//     and nothing is uploaded when it does not fit;
//   - the stand cards stayed clickable while a session ran, and switching
//     flipped the mode under it without going back to step 1;
//   - a failed upload left the sender on a progress bar with no way back.
//
// Run: node --test tests/parashare-group-precheck.test.mjs
//      (PLAYWRIGHT_CHROMIUM_PATH=... to pick a browser)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GP_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const GP_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const GP_MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json' };
const GP_ALIASES = { '/': '/index.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html' };

let gpServer;
let gpBrowser;
let GP_ORIGIN;

before(async () => {
  gpServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const file = path.join(GP_ROOT, GP_ALIASES[url.pathname] || url.pathname);
    if (!file.startsWith(GP_ROOT)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': GP_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => gpServer.listen(0, '127.0.0.1', r));
  GP_ORIGIN = `http://localhost:${gpServer.address().port}`;
  gpBrowser = await chromium.launch({ headless: true, ...(GP_EXE ? { executablePath: GP_EXE } : {}) });
});

after(async () => {
  if (gpBrowser) await gpBrowser.close();
  if (gpServer) await new Promise((r) => gpServer.close(r));
});

// opts.precheck:  (recipients) => { status, body }
// opts.inbound:   'ok' | 'fail' | 'hang'
// opts.plan:      what GET /v2/check-key answers: { plan, ttl, max } where a
//                 missing `max` is a relay from before max_recipients was
//                 served, and the page falls back to asking the precheck.
// opts.group:     choose "To several people" before the file is picked.
const TTL_BY_PLAN = { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 };
const MAX_BY_PLAN = { community: 1, pro: 30, business: 30, enterprise: 30 };
const COMMUNITY = { plan: 'community', ttl: 3600000, max: 1 };
const FIRM = { plan: 'pro', ttl: 86400000, max: 30 };

async function openSender(opts) {
  // precheck counts only the calls that carry a list: an empty one is the
  // fallback question "what is my ceiling", asked of an older relay.
  const calls = { inbound: 0, sends: 0, precheck: 0, precheckEmpty: 0 };
  const plan = opts.plan || { plan: 'community', ttl: 3600000 };
  const page = await gpBrowser.newPage({ viewport: { width: opts.width || 1280, height: 900 } });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ authenticated: true, email: 'demo@example.com' }),
  }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }),
  }));
  for (const host of ['legal', 'finance', 'iot']) {
    await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  }
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify(Object.assign({ valid: true, plan: plan.plan, link_ttl_ms: plan.ttl,
      link_ttl_ms_by_plan: TTL_BY_PLAN },
      plan.max ? { max_recipients: plan.max, max_recipients_by_plan: MAX_BY_PLAN } : {})),
  }));
  await page.route('https://health.paramant.app/v2/sends/precheck', async (r) => {
    const body = JSON.parse(r.request().postData() || '{}');
    const list = body.recipients || [];
    if (list.length) calls.precheck++; else calls.precheckEmpty++;
    const out = opts.precheck(list);
    await r.fulfill({ status: out.status, contentType: 'application/json', body: JSON.stringify(out.body) });
  });
  await page.route('https://health.paramant.app/v2/sends', (r) => { calls.sends++; return r.fulfill({ status: 500, body: '{}' }); });
  await page.route('https://health.paramant.app/v2/inbound', async (r) => {
    calls.inbound++;
    if (opts.inbound === 'hang') return; // never answered
    if (opts.inbound === 'fail') return r.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"boom"}' });
    const up = JSON.parse(r.request().postData() || '{}');
    return r.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ ok: true, hash: up.hash, ttl_ms: 3600000, size: 0, download_token: 'a'.repeat(48) }) });
  });
  // De Engelse pins hieronder gelden voor /en/parashare; de Nederlandse
  // tests onderaan openen /parashare.
  await page.goto(`${GP_ORIGIN}${opts.path || '/en/parashare'}`, { waitUntil: 'domcontentloaded' });
  // The plan has answered once the limit line is on screen.
  await page.waitForSelector('#ps-plan:not([hidden])', { timeout: 15000 });
  if (opts.group) await page.locator('#ps-mode-group').click();
  if (opts.file !== false) {
    await page.locator('#file-input').setInputFiles({ name: 'doc.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(600, 7) });
  }
  return { page, calls };
}

const activeStep = (page) => page.evaluate(() => (document.querySelector('.step.active') || {}).id);
const ready = (page) => page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
const list = (n, prefix = 'r') => Array.from({ length: n }, (_, i) => `${prefix}${i}@example.com`).join('\n');

// ── The precheck still decides when the page does not know the ceiling ─────
// An older relay serves no max_recipients and its precheck names no limit for
// an empty list. The page then locks nothing, and the refusal comes from the
// relay, before anything is sealed or uploaded.
test('with no ceiling known, the precheck refuses before anything is uploaded, with /pricing and a way back', async () => {
  const { page, calls } = await openSender({
    group: true,
    precheck: (l) => l.length > 1
      ? { status: 403, body: { error: 'over_limit', dimension: 'max_recipients', plan: 'community', limit: 1, asked: l.length } }
      : { status: 200, body: { ok: true } },
    inbound: 'ok',
  });
  try {
    await page.fill('#recipients-input', 'a@example.com\nb@example.com');
    await ready(page);
    assert.equal(await page.textContent('#btn-create-session'), 'Send to 2 people');
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 10000 });
    const line = await page.textContent('#over-limit-line');
    assert.match(line, /Your plan sends to 1 person at a time\. You listed 2\./);
    assert.equal(await page.getAttribute('#step-over-limit a.btn', 'href'), '/pricing');
    assert.equal(calls.precheck, 1);
    assert.equal(calls.inbound, 0, 'nothing was uploaded');
    assert.equal(calls.sends, 0);
    await page.click('#step-over-limit [data-click="backToSetup"]');
    assert.equal(await activeStep(page), 'step-setup');
    assert.equal(await page.inputValue('#recipients-input'), 'a@example.com\nb@example.com', 'the list is still there to trim');
    assert.equal(await page.locator('#ps-mode-link').isDisabled(), false, 'the cards are usable again on step 1');
  } finally { await page.close(); }
});

// ── Firm: the list, the counter, the red addresses ───────────────────────────
test('Firm sees the address field and a counter, and 31 of 30 stops the button with a reason', async () => {
  const { page, calls } = await openSender({ plan: FIRM, group: true, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    assert.equal(await page.locator('#recipients-input').isVisible(), true, 'the address field is on screen');
    assert.equal(await page.locator('#ps-mode-group-lock').isVisible(), false, 'no lock for a plan that can send to a group');
    assert.equal(await page.locator('#ps-upsell').isVisible(), false, 'no sales line for a paying plan');
    await page.fill('#recipients-input', list(12));
    assert.equal(await page.textContent('#ps-count'), '12 of 30');
    await ready(page);
    assert.equal(await page.textContent('#btn-create-session'), 'Send to 12 people');
    await page.fill('#recipients-input', list(31));
    assert.equal(await page.textContent('#ps-count'), '31 of 30');
    assert.equal(await page.locator('#btn-create-session').isDisabled(), true);
    assert.equal(await page.textContent('#ps-go-why'), 'You listed 31 people. Your plan sends to 30 at once.');
    assert.equal(calls.precheck, 0, 'nothing was asked of the relay for a list the page already knows is too long');
    assert.equal(calls.precheckEmpty, 0, 'a relay that serves max_recipients is not asked for it again');
  } finally { await page.close(); }
});

test('addresses that are not addresses are named in red, and the button says why it waits', async () => {
  const { page } = await openSender({ plan: FIRM, group: true, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    await page.fill('#recipients-input', 'a@example.com, b@example.com; not-an-address');
    assert.equal(await page.locator('#recipients-bad').isVisible(), true);
    assert.match(await page.textContent('#recipients-bad'), /not-an-address/);
    assert.equal(await page.getAttribute('#recipients-input', 'aria-invalid'), 'true');
    assert.equal(await page.locator('#btn-create-session').isDisabled(), true);
    assert.equal(await page.textContent('#ps-go-why'), 'Fix the addresses in red first.');
    await page.fill('#recipients-input', 'a@example.com, b@example.com');
    assert.equal(await page.locator('#recipients-bad').isVisible(), false);
    await ready(page);
    assert.equal(await page.textContent('#btn-create-session'), 'Send to 2 people');
  } finally { await page.close(); }
});

// ── Community: a lock and one button, never a dead end ──────────────────────
for (const [naam, plan, precheck] of [
  ['served max_recipients', COMMUNITY, () => ({ status: 200, body: { ok: true } })],
  // An older relay: the ceiling comes from the precheck's answer to an empty list.
  ['precheck fallback', { plan: 'community', ttl: 3600000 }, () => ({ status: 400, body: { error: 'empty', limit: 1 } })],
]) {
  test(`Community sees a lock on "To several people" and one upgrade button, not a stuck form (${naam})`, async () => {
    const { page, calls } = await openSender({ plan, precheck, inbound: 'ok' });
    try {
      await page.waitForSelector('#ps-mode-group-lock:not([hidden])', { timeout: 10000 });
      assert.match(await page.textContent('#ps-mode-group'), /With Firm/);
      await page.locator('#ps-mode-group').click();
      assert.equal(await page.getAttribute('#ps-mode-group', 'aria-checked'), 'true', 'the card can be chosen, to read what it is');
      assert.equal(await page.locator('#recipients-input').isVisible(), false, 'no address field that could only be refused');
      assert.equal(await page.locator('#ps-group-locked').isVisible(), true, 'a calm sentence instead');
      assert.equal(await page.locator('#ps-drop').isVisible(), false, 'and no file picker for a send that cannot happen');
      assert.equal(await page.locator('#ps-upsell').isVisible(), true);
      assert.equal(await page.getAttribute('#ps-upsell-btn', 'href'), '/en/pricing');
      assert.equal(await page.textContent('#ps-upsell-btn'), 'See Firm');
      assert.equal(await page.locator('#btn-create-session').isDisabled(), true);
      assert.equal(await page.textContent('#ps-go-why'), 'Choose "To one person" to send now.');
      // And the way back is one click.
      await page.locator('#ps-mode-link').click();
      await ready(page);
      assert.equal(await page.textContent('#btn-create-session'), 'Send');
      assert.equal(calls.precheck, 0);
    } finally { await page.close(); }
  });
}

// ── One limit line, and it is the plan's ────────────────────────────────────
test('the limit line says what this plan does, and only Community gets the Firm line', async () => {
  const cases = [
    [COMMUNITY, 'You send to 1 person. A link stays open for up to 1 hour. A file can be up to 5 MB.', true],
    [FIRM, 'You send to up to 30 people at once. A link stays open for up to 24 hours. A file can be up to 5 MB.', false],
    [{ plan: 'enterprise', ttl: 604800000, max: 30 }, 'You send to up to 30 people at once. A link stays open for up to 7 days. A file can be up to 5 MB.', false],
  ];
  for (const [plan, line, upsell] of cases) {
    const { page } = await openSender({ plan, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok', file: false });
    try {
      assert.equal(await page.textContent('#ps-limit'), line, `${plan.plan}: the limit line`);
      assert.equal(await page.locator('#ps-upsell').isVisible(), upsell, `${plan.plan}: the Firm line`);
      if (upsell) {
        assert.equal(await page.textContent('#ps-upsell-line'),
          'With Firm you send to up to 30 people at once, a link stays open for 24 hours, and you see who has opened it.');
      }
      // The expiry picker offers nothing the plan does not honour.
      const offered = await page.$$eval('#ttl-select option', (os) => os.filter((o) => !o.disabled).map((o) => Number(o.value)));
      assert.ok(offered.length && offered.every((v) => v <= plan.ttl), `${plan.plan}: offered ${offered.join(',')}`);
      // The contradictory sentences of the old page are gone.
      const text = await page.evaluate(() => document.getElementById('step-setup').innerText);
      assert.doesNotMatch(text, /on Community, .* on Firm and .* on Enterprise/);
    } finally { await page.close(); }
  }
});

test('no session token is ever on screen, and the row says who is signed in', async () => {
  const { page } = await openSender({ plan: FIRM, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    await page.waitForFunction(() => /demo@example\.com/.test(document.getElementById('ps-key-slim-label').textContent), null, { timeout: 10000 });
    assert.equal(await page.textContent('#ps-key-slim-label'), 'Signed in as demo@example.com');
    const text = await page.evaluate(() => document.body.innerText);
    assert.doesNotMatch(text, /pst_/, 'the token is a credential, not something to read');
  } finally { await page.close(); }
});

test('Extra safe is the live hand-over: one person, no address, its own button and steps', async () => {
  const { page } = await openSender({ plan: FIRM, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    assert.equal(await page.isChecked('#ps-extra-safe'), false, 'the plain link is the default');
    assert.equal(await page.locator('#ps-stepper').isVisible(), false);
    await page.locator('#ps-extra-safe').check();
    assert.equal(await page.evaluate(() => sendMode), 'live');
    assert.equal(await page.locator('#recipient-one').isVisible(), false, 'no address: the other person is at their screen');
    assert.equal(await page.locator('#ps-stepper').isVisible(), true);
    assert.equal(await page.textContent('#btn-create-session'), 'Start and wait for the other person');
    assert.match(await page.textContent('#ps-limit'), /With Extra safe it can be up to 500 MB, and nothing is stored\./);
    await page.locator('#ps-mode-group').click();
    assert.equal(await page.locator('#ps-safe').isVisible(), false, 'Extra safe belongs to one person');
    assert.equal(await page.evaluate(() => sendMode), 'link');
  } finally { await page.close(); }
});

test('while sealing, the choices are locked and the mode does not change', async () => {
  const { page } = await openSender({ plan: FIRM, group: true, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'hang' });
  try {
    await page.fill('#recipients-input', 'a@example.com');
    await ready(page);
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-sealing.active', { timeout: 10000 });
    assert.equal(await page.locator('#ps-mode-link').isDisabled(), true);
    await page.locator('#ps-mode-link').click({ force: true }).catch(() => {});
    assert.equal(await page.getAttribute('#ps-mode-group', 'aria-checked'), 'true');
    assert.equal(await page.getAttribute('#ps-mode-link', 'aria-checked'), 'false');
    assert.equal(await activeStep(page), 'step-sealing');
  } finally { await page.close(); }
});

test('a failed upload shows a Back button instead of a bar that never moves', async () => {
  const { page } = await openSender({ precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'fail' });
  try {
    await ready(page);
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#seal-back:not([hidden])', { timeout: 10000 });
    await page.click('#seal-back');
    assert.equal(await activeStep(page), 'step-setup');
  } finally { await page.close(); }
});

// ── The file picker ─────────────────────────────────────────────────────────
test('the file picker is a big button in the page language, and says what was taken', async () => {
  const { page } = await openSender({ path: '/parashare', plan: FIRM, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok', file: false });
  try {
    assert.equal(await page.textContent('#ps-drop-btn'), 'Kies een bestand');
    assert.equal(await page.$eval('#file-input', (i) => getComputedStyle(i).opacity), '0', 'the native "Browse..." control is out of sight');
    // Still reachable: its label is the zone, and it keeps its accessible name.
    const name = await page.evaluate(() => { const i = document.getElementById('file-input'); return i.labels && i.labels[0] && i.labels[0].id; });
    assert.equal(name, 'ps-drop');
    await page.locator('#file-input').setInputFiles({ name: 'loonstrook.pdf', mimeType: 'application/pdf', buffer: Buffer.alloc(2048, 1) });
    assert.equal(await page.textContent('#file-status'), '✓ loonstrook.pdf (2 KB)');
    assert.equal(await page.textContent('#ps-drop-btn'), 'Ander bestand kiezen');
    assert.equal(await page.textContent('#ps-go-why'), '');
  } finally { await page.close(); }
});

// ── Two choices, both themes, phone and desktop ─────────────────────────────
for (const width of [390, 1280]) {
  for (const theme of ['light', 'dark']) {
    for (const pad of ['/parashare', '/en/parashare']) {
      test(`${pad} at ${width}px, ${theme}: two equal choices, no sideways scroll`, async () => {
        const ctx = await gpBrowser.newContext({ viewport: { width, height: 900 }, colorScheme: theme });
        await ctx.addInitScript((th) => { try { localStorage.setItem('paramant.theme.v1', th); } catch (_) {} }, theme);
        const page = await ctx.newPage();
        await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
        await page.route('https://*.paramant.app/**', (r) => r.abort());
        try {
          await page.goto(`${GP_ORIGIN}${pad}`, { waitUntil: 'domcontentloaded' });
          assert.equal(await page.evaluate(() => document.documentElement.getAttribute('data-theme')), theme);
          const boxes = await page.$$eval('#ps-mode .ps-mode-card', (cs) => cs.map((c) => { const r = c.getBoundingClientRect(); return { w: r.width, h: r.height, top: r.top, vis: r.width > 0 && r.height > 0 }; }));
          assert.equal(boxes.length, 2, 'two choices');
          assert.ok(boxes.every((b) => b.vis), 'both on screen');
          assert.ok(Math.abs(boxes[0].w - boxes[1].w) < 2 && Math.abs(boxes[0].h - boxes[1].h) < 2, `equal size: ${JSON.stringify(boxes)}`);
          assert.ok(Math.abs(boxes[0].top - boxes[1].top) < 2, 'side by side, also on a phone');
          const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
          assert.ok(over <= 0, `no sideways scroll (${over}px)`);
          const mono = await page.$$eval('.ps-mode-title, .ps-field-label, .ps-how summary, .ps-step-label', (els) =>
            els.filter((e) => /mono/i.test(getComputedStyle(e).fontFamily) || getComputedStyle(e).textTransform === 'uppercase').map((e) => e.textContent.trim()));
          assert.deepEqual(mono, [], 'plain labels are plain text');
        } finally { await ctx.close(); }
      });
    }
  }
}

// ── De Nederlandse /parashare ───────────────────────────────────────────────
test('zonder bekend plafond weigert de precheck in het Nederlands, voor er iets is geüpload', async () => {
  const { page, calls } = await openSender({
    path: '/parashare',
    group: true,
    precheck: (l) => l.length > 1
      ? { status: 403, body: { error: 'over_limit', dimension: 'max_recipients', plan: 'community', limit: 1, asked: l.length } }
      : { status: 200, body: { ok: true } },
    inbound: 'ok',
  });
  try {
    await page.fill('#recipients-input', 'a@example.com\nb@example.com');
    await ready(page);
    assert.equal(await page.textContent('#btn-create-session'), 'Verstuur naar 2 mensen');
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 15000 });
    const line = await page.textContent('#over-limit-line');
    assert.match(line, /Uw abonnement verstuurt naar 1 ontvanger tegelijk\. U noemde er 2\./);
    assert.equal(await page.getAttribute('#step-over-limit a.btn', 'href'), '/pricing');
    assert.equal(calls.inbound, 0, 'er is niets geüpload');
    assert.equal(calls.sends, 0);
  } finally { await page.close(); }
});

test('Firm ziet het adresveld en de teller, in het Nederlands', async () => {
  const { page } = await openSender({ path: '/parashare', plan: FIRM, group: true, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    await page.fill('#recipients-input', list(12, 'p'));
    assert.equal(await page.textContent('#ps-count'), '12 van 30');
    await ready(page);
    assert.equal(await page.textContent('#btn-create-session'), 'Verstuur naar 12 mensen');
    assert.equal(await page.textContent('#ps-limit'), 'U stuurt naar maximaal 30 mensen tegelijk. Een link blijft maximaal 24 uur open. Een bestand mag tot 25 MB zijn.');
  } finally { await page.close(); }
});

test('Community ziet een slot en één knop naar Firm, in het Nederlands', async () => {
  const { page } = await openSender({ path: '/parashare', plan: COMMUNITY, precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    assert.equal(await page.textContent('#ps-limit'), 'U stuurt naar 1 persoon. Een link blijft maximaal 1 uur open. Een bestand mag tot 5 MB zijn.');
    assert.equal(await page.textContent('#ps-upsell-line'),
      'Met Firm stuurt u naar maximaal 30 mensen tegelijk, blijft een link 24 uur open en ziet u wie het heeft geopend.');
    assert.equal(await page.textContent('#ps-upsell-btn'), 'Bekijk Firm');
    await page.locator('#ps-mode-group').click();
    assert.equal(await page.locator('#recipients-input').isVisible(), false);
    assert.equal(await page.textContent('#ps-go-why'), 'Kies Naar één persoon om nu te versturen.');
    const text = await page.evaluate(() => document.body.innerText);
    assert.doesNotMatch(text, /pst_/);
  } finally { await page.close(); }
});
