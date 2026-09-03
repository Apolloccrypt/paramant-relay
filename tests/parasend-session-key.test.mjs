// ParaSend takes its API key from the session and from nowhere else.
//
// The bug a buyer walked into: Send in the signed-in navigation opened
// /parashare on a card headed "Your API key" with an empty box in it, and the
// key he typed there was not the key of the account he was signed in with. The
// page had two sources of truth. GET /api/user/account/key was one; a
// localStorage entry written by any earlier visit, on any account, was the
// other, and the second outlived the first. A stale or hand-typed key sails
// past the format check, fails at the relay, and the only thing the sender sees
// is a button that will not light up.
//
// So: one source. frontend/js/parashare.page.js reads the account key from the
// session on every load, keeps it in memory, and never writes it to
// localStorage. This suite runs that page script for real, in a vm context
// with a hand-built DOM and a stubbed fetch, node builtins only, so it runs in
// the "Root integration suites" job next to the other tests/*.mjs, and it
// measures the three answers the endpoint can give.
//
// Verified by sabotage, both directions:
//   • put `localStorage.setItem('paramant_api_key', apiKey)` back into
//     onKeyInput and the "never persists" case goes red (and so does row 28 of
//     site-claims.test.mjs);
//   • drop the 429 retry, or make the 500 path silent instead of showing the
//     banner, and the matching case goes red;
//   • make keyValid depend on discoverRelay again and "a dead sector does not
//     disable the button" goes red;
//   • and each case was run against an unpatched parashare.page.js, where the
//     slim-row, banner and retry cases fail and only the happy path passes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const PS_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PS_JS = fs.readFileSync(path.join(PS_ROOT, 'frontend/js/parashare.page.js'), 'utf8');
const PS_HTML = fs.readFileSync(path.join(PS_ROOT, 'frontend/parashare.html'), 'utf8');
const KEY_URL = '/api/user/account/key';
const FAKE_KEY = 'pgp_livetestkey0000000000abcd';

// ── A DOM small enough to read, big enough to run the page script ────────────
function makeElement(id) {
  const classes = new Set();
  const el = {
    id, value: '', textContent: '', innerHTML: '', className: '',
    hidden: false, disabled: false, files: [], style: {},
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, on) => (on === undefined ? (classes.has(c) ? classes.delete(c) : classes.add(c)) : (on ? classes.add(c) : classes.delete(c))),
      contains: (c) => classes.has(c),
    },
    focus() {}, blur() {}, setAttribute() {}, getAttribute: () => null,
    addEventListener() {}, appendChild() {}, closest: () => null,
  };
  return el;
}

// A run of the page: the vm context, the DOM it saw, and what it asked for.
function runPage({ keyResponses, sectorOk = true }) {
  const elements = new Map();
  const getElementById = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const listeners = new Map();
  const calls = { key: 0, sector: 0, urls: [], timeouts: [], storage: [] };
  let keyTurn = 0;

  const respond = (spec) => ({
    ok: spec.status < 400,
    status: spec.status,
    json: async () => spec.body,
  });

  const context = {
    console,
    URLSearchParams,
    AbortSignal: { timeout: () => null },
    crypto: globalThis.crypto,
    navigator: { clipboard: { writeText: async () => {} } },
    location: { search: '', hash: '', origin: 'https://paramant.app', pathname: '/parashare', reload() {} },
    localStorage: {
      getItem: (k) => { calls.storage.push(['get', k]); return null; },
      setItem: (k, v) => { calls.storage.push(['set', k, v]); },
      removeItem: (k) => { calls.storage.push(['remove', k]); },
    },
    document: {
      getElementById,
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => makeElement('created'),
      head: { appendChild() {} },
      body: { appendChild() {} },
      addEventListener: (type, fn) => { listeners.set(type, (listeners.get(type) || []).concat(fn)); },
    },
    // Every timer resolves on the next microtask; the delay asked for is
    // recorded instead, which is how the 2 s retry is measured without waiting.
    setTimeout: (fn, ms) => { calls.timeouts.push(ms); queueMicrotask(() => { try { fn(); } catch (_) {} }); return 0; },
    clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    queueMicrotask,
    act: () => {},
    fetch: async (url) => {
      calls.urls.push(url);
      if (String(url).endsWith(KEY_URL)) {
        calls.key += 1;
        const spec = keyResponses[Math.min(keyTurn++, keyResponses.length - 1)];
        return respond(spec);
      }
      calls.sector += 1;
      if (!sectorOk) throw new Error('sector unreachable');
      return respond({ status: 200, body: { valid: true, plan: 'pro' } });
    },
  };
  context.window = context;
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(PS_JS, context, { filename: 'parashare.page.js' });
  return { context, elements, calls, listeners, getElementById };
}

// Fire DOMContentLoaded and let every pending microtask drain.
async function loadPage(opts) {
  const run = runPage(opts);
  for (const fn of run.listeners.get('DOMContentLoaded') || []) fn();
  for (let i = 0; i < 60; i += 1) await new Promise((r) => setImmediate(r));
  return run;
}

// `let keyValid` at the top of a script is a lexical binding, not a property of
// the context object, so the page's state is read back through the context
// rather than off it.
const evalIn = (run, expr) => vm.runInContext(expr, run.context);

function pickAFile(run) {
  run.getElementById('file-input').files = [{ name: 'contract.pdf', size: 4096 }];
  evalIn(run, 'updateBtn()');
  return !run.getElementById('btn-create-session').disabled;
}

const wroteTheKey = (run) => run.calls.storage.some(([op, k]) => op === 'set' && k === 'paramant_api_key');

// ── 1. The endpoint answers ─────────────────────────────────────────────────
test('a 200 from /api/user/account/key gives the slim row, a usable button, and nothing in localStorage', async () => {
  const run = await loadPage({ keyResponses: [{ status: 200, body: { api_key: FAKE_KEY, revealable: true } }] });

  assert.equal(run.calls.key, 1, 'the account key is fetched exactly once when the endpoint answers');
  assert.equal(run.getElementById('api-key').value, FAKE_KEY, 'the session key is the key the page holds');

  // The slim row is the state the sender lands in: no empty "API key" box.
  const slim = run.getElementById('ps-key-slim');
  assert.equal(slim.hidden, false, 'the slim row is shown');
  assert.equal(slim.classList.contains('is-loading'), false, 'the slim row stops claiming to be loading');
  assert.equal(run.getElementById('ps-key-slim-label').textContent, 'Using your account key');
  assert.equal(run.getElementById('ps-key-mask').hidden, false, 'the masked key is revealed next to the label');
  assert.match(run.getElementById('ps-key-mask').textContent, /^pgp_.*\.\.\..{4}$/, 'the row shows a masked key, not the whole one');
  assert.equal(run.getElementById('step-setup').classList.contains('manual-key'), false,
    'the manual card stays closed: #step-setup only carries .manual-key when the user asks for the box');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'no banner on the happy path');

  assert.equal(evalIn(run, 'keyValid'), true, 'the key is usable');
  assert.equal(pickAFile(run), true, 'pick a file and "Create secure session" is live');
  assert.equal(wroteTheKey(run), false, 'the account key is never written to localStorage');
});

// ── 2. nginx throttles the page ─────────────────────────────────────────────
// /api/user/ sits in the relay_auth zone (deploy/nginx-paramant-live.conf:146,
// burst 5). /parashare loads next to nav-auth's session check and the quota
// call, so a 429 here is the page arriving in its own crowd, not a broken
// account. One retry, 2 s later, and then it gives up.
test('a 429 on the account key is retried once, two seconds later, and then succeeds', async () => {
  const run = await loadPage({
    keyResponses: [
      { status: 429, body: {} },
      { status: 200, body: { api_key: FAKE_KEY, revealable: true } },
    ],
  });

  assert.equal(run.calls.key, 2, 'exactly one retry: the rate limiter must not be hammered');
  assert.ok(run.calls.timeouts.includes(2000), `the retry waits 2000 ms; delays asked for were ${run.calls.timeouts.join(', ')}`);
  assert.equal(run.getElementById('api-key').value, FAKE_KEY, 'the retry is what delivers the key');
  assert.equal(run.getElementById('ps-key-slim').hidden, false, 'the slim row is reached through the retry');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'a throttled first try is not an error to the user');
  assert.equal(evalIn(run, 'keyValid'), true);
  assert.equal(wroteTheKey(run), false, 'the account key is never written to localStorage');
});

// ── 3. The endpoint is broken ───────────────────────────────────────────────
test('a 500 on the account key shows the banner, hides the slim row, and offers a key by hand', async () => {
  const run = await loadPage({ keyResponses: [{ status: 500, body: {} }] });

  assert.equal(run.calls.key, 1, 'a 500 is not a rate limit: no retry');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), true, 'the failure is stated, not swallowed');
  assert.equal(run.getElementById('ps-key-slim').hidden, true,
    'the slim row may not say "using your account key" when there is no account key');
  assert.equal(evalIn(run, 'keyValid'), false);
  assert.equal(pickAFile(run), false, 'without a key the button stays disabled, and the banner says why');
  assert.equal(wroteTheKey(run), false, 'the account key is never written to localStorage');

  // The way out for a self-host whose deployment has no such endpoint.
  evalIn(run, 'expandApiKeyCard()');
  assert.equal(run.getElementById('step-setup').classList.contains('manual-key'), true, 'the manual card opens on request');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'and the banner steps aside');
});

// ── 4. The banner's words, and the default state of the markup ──────────────
test('/parashare ships the banner copy and opens on the slim row, not the manual card', () => {
  assert.ok(PS_HTML.includes('Your account key could not be loaded. Sign in again; if it keeps happening, mail <a href="mailto:privacy@paramant.app">privacy@paramant.app</a>.'),
    'the banner must name the one thing to do and the one address to write to');
  assert.match(PS_HTML, /data-click="expandApiKeyCard">Use a key by hand</, 'the banner must carry the manual way out');

  // The class logic, the other way round from what shipped: the slim row is the
  // default and the card is the exception.
  assert.match(PS_HTML, /\.ps-key-slim\{display:flex/, 'the slim row is the default');
  assert.match(PS_HTML, /\.ps-key-card\{display:none\}/, 'the manual card is hidden by default');
  assert.match(PS_HTML, /#step-setup\.manual-key \.ps-key-card\{display:block\}/, '.manual-key opens the card');
  assert.match(PS_HTML, /#step-setup\.manual-key \.ps-key-slim\{display:none\}/, '.manual-key closes the slim row');
  assert.ok(!/has-saved-key/.test(PS_HTML) && !/has-saved-key/.test(PS_JS),
    'has-saved-key was the old inverted class; nothing may still reference it');
  assert.ok(!/localStorage\.setItem\(\s*['"]paramant_api_key/.test(PS_JS),
    'parashare.page.js must not persist the account key');
  assert.ok(!/localStorage\.getItem\(\s*['"]paramant_api_key/.test(PS_JS),
    'parashare.page.js must not read a key back out of localStorage: the session is the only source');
});

// ── 5. A dead sector is an error, not a dead button ─────────────────────────
// discoverRelay races four sector hosts. When none of them answers, that says
// nothing about the key, and it used to leave the button greyed out with no
// reason on screen. The key and the sector are now separate questions.
test('a sector that will not answer leaves the button live and reports itself at the press', async () => {
  const run = await loadPage({ keyResponses: [{ status: 200, body: { api_key: FAKE_KEY, revealable: true } }], sectorOk: false });

  assert.ok(run.calls.sector >= 4, 'all four sectors were tried');
  assert.equal(evalIn(run, 'keyValid'), true, 'the session key is good; only the sector is unreachable');
  assert.equal(evalIn(run, 'relayReady'), false);
  assert.equal(pickAFile(run), true, 'the button is usable: a silent disabled button explains nothing');

  await evalIn(run, 'createSession()');
  const status = run.getElementById('create-status');
  assert.match(status.textContent, /No relay sector answered/, 'pressing the button states the sector failure');
  assert.equal(status.className, 'status-line err');
  assert.equal(run.getElementById('session-link').textContent, '', 'and no session is created on a dead sector');
});

// ── 6. Sign-out clears what an older build stored ───────────────────────────
test('signing out removes a paramant_api_key left behind by an earlier build', () => {
  const nav = fs.readFileSync(path.join(PS_ROOT, 'frontend/js/nav-auth.js'), 'utf8');
  const signout = nav.slice(nav.indexOf("signout.addEventListener('click'"));
  assert.ok(signout.length > 0, 'nav-auth.js must still wire a sign-out handler');
  assert.match(signout.slice(0, 700), /localStorage\.removeItem\('paramant_api_key'\)/,
    '/privacy said this key was "removed when you sign out" and nothing removed it. The page no longer writes it, and sign-out now clears an old one.');
});
