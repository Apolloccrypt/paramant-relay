'use strict';
// The gift-code block, in the admin screen that is actually served.
//
// WHY THIS FILE EXISTS. The coupon UI was built once already, in
// frontend/js/admin.page.js, and it was invisible. Nginx sends /admin/ to the
// admin container and never to the docroot (deploy/nginx-paramant-public.conf
// to 127.0.0.1:4200, deploy/nginx-paramant-live.conf:313 to 127.0.0.1:3002),
// and that container serves admin/public/index.html plus admin/public/app.js.
// The file the block was written in is on no route an admin uses. Everything
// passed anyway: the relay routes had
// tests, the panel's three proxy hops had tests (coupons.test.js), and the
// screen an admin opens had no Gift codes card on it at all.
//
// So this suite asserts the one thing none of those did: that the block is in
// the SERVED file, that it is rendered by the Billing tab, and that the button
// on it reaches the panel's own /admin/coupons route with the session header
// the rest of that screen uses. A test that read admin.page.js would have gone
// green through the whole outage, which is exactly the failure being closed.
//
// HOW. app.js is a plain browser script with no module system and no framework,
// so it is run in a vm on a hand-built document: getElementById hands back
// stub nodes, fetch records what it was called with, and the real functions do
// the rest. Nothing about the coupon path is reimplemented here; if
// doCreateCoupon stops sending X-Session, or starts calling the relay directly,
// this fails.
//
// Run: node --test admin/test/admin-ui-coupons.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const PUBLIC = path.join(__dirname, '..', 'public');
const APP_JS = fs.readFileSync(path.join(PUBLIC, 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');

// ── A document just large enough for app.js to load and for the Billing tab
// to render into. Anything the script asks for exists; nothing pretends to lay
// out or to bubble an event.
function makeNode(id) {
  return {
    id,
    value: '',
    innerHTML: '',
    textContent: '',
    disabled: false,
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener() {},
    removeEventListener() {},
    setAttribute() {},
    getAttribute() { return null; },
    focus() {},
    closest() { return null; },
    querySelectorAll() { return []; },
    appendChild() {},
    remove() {},
  };
}

function boot({ session = '', fetchImpl } = {}) {
  const nodes = new Map();
  const calls = [];
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, makeNode(id));
      return nodes.get(id);
    },
    createElement: (tag) => makeNode(tag),
    querySelectorAll: () => [],
    addEventListener() {},
    body: makeNode('body'),
  };
  const sandbox = {
    document,
    sessionStorage: { getItem: () => session, setItem() {}, removeItem() {} },
    location: { hash: '', href: '' },
    console,
    setTimeout,
    clearTimeout,
    setInterval: () => 0,
    clearInterval: () => {},
    requestAnimationFrame: (fn) => fn(),
    Date,
    JSON,
    URLSearchParams,
    Number,
    Math,
    String,
    Array,
    Object,
    parseInt,
    parseFloat,
    isNaN,
    encodeURIComponent,
    decodeURIComponent,
    fetch: async (url, opts) => {
      calls.push({ url, opts: opts || {} });
      return fetchImpl ? fetchImpl(url, opts || {}, calls.length) : jsonResponse(200, {});
    },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  const context = vm.createContext(sandbox);
  vm.runInContext(APP_JS, context, { filename: 'app.js' });
  return { context, nodes, calls, run: (src) => vm.runInContext(src, context) };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: async () => body,
  };
}

const COUPON = {
  code: 'COFFEE',
  grants: [{ product: 'parasign', tier: 'pro', days: 90 }],
  max_redemptions: 100,
  used: 0,
  remaining: 100,
  valid_until: null,
  revoked_at: null,
  describes: '3 months of ParaSign Pro and ParaSend Pro',
};

// ── 1. The block is in the served file and on the Billing tab ────────────────

test('the served screen is admin/public, and admin/public/app.js holds the coupon block', () => {
  // The pair that is actually served together. A block in frontend/ is not on
  // this screen, whatever it looks like in a diff.
  assert.match(INDEX_HTML, /<script src="app\.js"/, 'index.html must load app.js');
  assert.ok(APP_JS.includes('renderCouponsShell'),
    'admin/public/app.js has no coupon block; the one in frontend/js/admin.page.js is served by nothing');
  for (const fn of ['fetchCoupons', 'doCreateCoupon', 'doRevokeCoupon']) {
    assert.ok(APP_JS.includes('function ' + fn), `${fn} is missing from the served app.js`);
  }
});

test('the three coupon actions are registered on the delegated click registry', () => {
  // index.html carries no inline handlers (CSP drops unsafe-inline), so a
  // button that is not in the registry is a button that does nothing.
  const { context } = boot();
  const clicks = vm.runInContext('Object.keys(ACTIONS.click)', context);
  for (const name of ['doCreateCoupon', 'doRevokeCoupon', 'fetchCoupons']) {
    assert.ok(clicks.includes(name), `data-click="${name}" has no registered action`);
  }
});

test('opening the Billing tab renders the gift-code card with its four fields', async () => {
  const { context, nodes, run } = boot({
    fetchImpl: (url) => (String(url).includes('/admin/coupons')
      ? jsonResponse(200, { ok: true, coupons: [COUPON] })
      : jsonResponse(200, { plan_distribution: { pro: 2 }, recent_checkouts: [] })),
  });
  await run('loadBilling()');
  const html = nodes.get('tab-billing').innerHTML;
  assert.match(html, /Gift codes/, 'the Billing tab renders no gift-code card');
  assert.match(html, /id="c-code"/, 'no code field');
  assert.match(html, /id="c-max"[^>]*value="100"/, 'no maximum redemptions field defaulting to 100');
  assert.match(html, /id="c-days"[^>]*value="90"/, 'no days field defaulting to 90');
  assert.match(html, /id="c-until"[^>]*type="date"/, 'no valid-until date field');
  assert.match(html, /data-click="doCreateCoupon"/, 'no create button');
  // And the table under it, filled from the list route.
  await new Promise((r) => setTimeout(r, 0));
  const rows = nodes.get('c-results').innerHTML;
  assert.match(rows, /COFFEE/);
  assert.match(rows, /0 of 100/, 'the table must show used of maximum');
  assert.match(rows, /no end date/);
  assert.match(rows, /data-click="doRevokeCoupon"/, 'an open code needs a withdraw button');
  assert.ok(vm.runInContext('true', context));
});

// ── 2. The button reaches the panel's own route, with the session ────────────

test('Create code posts to the panel route /admin/api/admin/coupons with X-Session', async () => {
  const { nodes, calls, run } = boot({
    session: 'sess-abc',
    fetchImpl: (url, opts) => (opts.method === 'POST'
      ? jsonResponse(201, { ok: true, coupon: COUPON })
      : jsonResponse(200, { ok: true, coupons: [COUPON] })),
  });
  nodes.set('c-code', Object.assign(makeNode('c-code'), { value: 'coffee' }));
  nodes.set('c-max', Object.assign(makeNode('c-max'), { value: '50' }));
  nodes.set('c-days', Object.assign(makeNode('c-days'), { value: '30' }));
  nodes.set('c-until', Object.assign(makeNode('c-until'), { value: '2026-12-31' }));
  await run('doCreateCoupon()');

  const post = calls.find((c) => c.opts.method === 'POST');
  assert.ok(post, 'the create button sent no request');
  assert.strictEqual(post.url, '/admin/api/admin/coupons',
    'the create button must go through the admin panel, which swaps the session for ADMIN_TOKEN; the browser never holds that token and cannot call the relay directly');
  assert.strictEqual(post.opts.headers['X-Session'], 'sess-abc',
    'the create request carries no admin session');
  const body = JSON.parse(post.opts.body);
  assert.strictEqual(body.code, 'COFFEE', 'the code must be normalised to upper case, as coupon.js does');
  assert.strictEqual(body.max_redemptions, 50);
  assert.deepStrictEqual(body.grants.map((g) => g.days), [30, 30], 'every grant on one code runs the same number of days');
  assert.strictEqual(body.valid_until, '2026-12-31T23:59:59Z', 'a date field means the end of that day');
  assert.match(nodes.get('c-msg').textContent, /Created COFFEE/);
});

test('Withdraw sends a DELETE with the code in the path and no body', async () => {
  const { nodes, calls, run } = boot({
    session: 'sess-abc',
    fetchImpl: () => jsonResponse(200, { ok: true, coupon: { ...COUPON, revoked_at: '2026-09-04T10:00:00Z' } }),
  });
  // The registry hands doRevokeCoupon the button itself, so the code travels in
  // its dataset and never in a body.
  await run('doRevokeCoupon({dataset:{code:"COFFEE"}})');
  const del = calls.find((c) => c.opts.method === 'DELETE');
  assert.ok(del, 'the withdraw button sent no request');
  assert.strictEqual(del.url, '/admin/api/admin/coupons/COFFEE',
    'the code belongs in the path, on the panel route, not in a body and not on the relay');
  assert.strictEqual(del.opts.headers['X-Session'], 'sess-abc');
  assert.strictEqual(del.opts.body, undefined,
    'the withdraw must send no body; a DELETE body the relay refuses before reading desynchronises a kept-alive connection');
  assert.match(nodes.get('c-msg').textContent, /withdrawn/);
});

// ── 3. The failures say what happened, in words ──────────────────────────────

test('a rejected code is explained in a sentence, not in a relay error word', async () => {
  const cases = [
    [409, { error: 'code_exists' }, /already exists/i],
    [400, { error: 'bad_valid_until' }, /not a date/i],
    [503, { error: 'coupons_unavailable' }, /not reachable/i],
  ];
  for (const [status, body, expect] of cases) {
    const { nodes, run } = boot({ fetchImpl: () => jsonResponse(status, body) });
    nodes.set('c-code', Object.assign(makeNode('c-code'), { value: 'COFFEE' }));
    nodes.set('c-max', Object.assign(makeNode('c-max'), { value: '100' }));
    nodes.set('c-days', Object.assign(makeNode('c-days'), { value: '90' }));
    await run('doCreateCoupon()');
    const msg = nodes.get('c-msg').textContent;
    assert.match(msg, expect, `${body.error} was shown as: ${msg}`);
    assert.doesNotMatch(msg, new RegExp(body.error), `${body.error} was shown raw to the admin`);
  }
});

test('an unreachable relay is said out loud instead of dying in an unhandled rejection', async () => {
  const { nodes, run } = boot({ fetchImpl: () => { throw new TypeError('fetch failed'); } });
  nodes.set('c-code', Object.assign(makeNode('c-code'), { value: 'COFFEE' }));
  nodes.set('c-max', Object.assign(makeNode('c-max'), { value: '100' }));
  nodes.set('c-days', Object.assign(makeNode('c-days'), { value: '90' }));
  await run('doCreateCoupon()');
  assert.match(nodes.get('c-msg').textContent, /could not be reached/i);
});

test('a code that cannot be a code never leaves the browser', async () => {
  const { nodes, calls, run } = boot();
  nodes.set('c-code', Object.assign(makeNode('c-code'), { value: 'A B' }));
  nodes.set('c-max', Object.assign(makeNode('c-max'), { value: '100' }));
  nodes.set('c-days', Object.assign(makeNode('c-days'), { value: '90' }));
  await run('doCreateCoupon()');
  assert.strictEqual(calls.length, 0, 'a malformed code was sent to the relay anyway');
  assert.match(nodes.get('c-msg').textContent, /letters, digits and dashes/i);
});

// ── 4. The banner over it is no longer a lie ─────────────────────────────────

test('the Billing tab no longer calls itself a beta stub', async () => {
  const { nodes, run } = boot({
    fetchImpl: (url) => (String(url).includes('/admin/coupons')
      ? jsonResponse(200, { ok: true, coupons: [] })
      : jsonResponse(200, { plan_distribution: {}, recent_checkouts: [] })),
  });
  await run('loadBilling()');
  const html = nodes.get('tab-billing').innerHTML;
  assert.doesNotMatch(html, /Beta billing/,
    'payments run through Mollie today: relay.js POST /v2/billing/checkout calls mollie.createPayment unconditionally');
  assert.doesNotMatch(html, /stub only|manually invoiced|in integration/i,
    'invoices and credit notes are drawn automatically from the payment webhook (relay/lib/invoice.js, relay/lib/credit-note.js)');
  assert.match(html, /Mollie payments are live/,
    'the tab should say what is true rather than nothing');
  assert.match(html, /no subscription and no direct debit/i,
    'BILLING_MODE is empty in production, which leaves the recurring layer off (relay/lib/mollie.js billingStance)');
});
