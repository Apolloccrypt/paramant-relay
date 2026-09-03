// ParaSend runs on a session token, and the account key never reaches the
// browser at all.
//
// TWO FINDINGS, ONE PAGE. The first was a buyer's: Send in the signed-in
// navigation opened /parashare on a card headed "Your API key" with an empty box
// in it, and the key he typed there was not the key of the account he was signed
// in with. The page had two sources of truth, GET /api/user/account/key and a
// localStorage entry any earlier visit could have written, and the second
// outlived the first. That was closed by making the session the only source.
//
// The second was the security review of #397, and it is about what that single
// source hands over. An account API key has no expiry and no scope: fetched into
// a variable, it stays a full data-plane credential for the life of the tab, and
// anything that gets to run on the page can read it and keep it. So the page now
// asks POST /api/user/parasend/token and is handed a pst_ session token instead:
// fifteen minutes, and scoped by the relay to the five routes a transfer walks.
// The key stays on the server.
//
// This suite runs the page script for real, in a vm context with a hand-built
// DOM and a stubbed fetch, node builtins only, so it runs in the "Root
// integration suites" job next to the other tests/*.mjs. What it measures is
// what the page holds, what it sends, and what it does when the token runs out.
//
// Verified by sabotage, in both directions:
//   * put `localStorage.setItem('paramant_api_key', apiKey)` back into
//     onKeyInput and the "never persists" case goes red (and so does row 28 of
//     site-claims.test.mjs);
//   * send X-Api-Key instead of the Bearer on any of the five relay calls and
//     the header case goes red by name;
//   * drop the 401 refresh, or the proactive one, and the expiry cases go red;
//   * drop the 429 retry, or make the 500 path silent instead of showing the
//     banner, and the matching case goes red;
//   * make keyValid depend on discoverRelay again and "a dead sector does not
//     disable the button" goes red;
//   * and each case was run against an unpatched parashare.page.js, where every
//     token case fails and only the shape of the old key flow passes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const PS_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PS_JS = fs.readFileSync(path.join(PS_ROOT, 'frontend/js/parashare.page.js'), 'utf8');
const PS_HTML = fs.readFileSync(path.join(PS_ROOT, 'frontend/parashare.html'), 'utf8');
// The real error module, run INSIDE the context the way the page loads it: as a
// plain script that assigns self.paramantErrors. Requiring it here instead would
// close it over this process's console, and half of what this suite measures is
// what the page does or does not write to the browser's.
const PS_ERRORS_JS = fs.readFileSync(path.join(PS_ROOT, 'frontend/js/error-message.js'), 'utf8');
const TOKEN_URL = '/api/user/parasend/token';
const FAKE_TOKEN = 'pst_' + 'ab12cd34'.repeat(8);
const FAKE_KEY = 'pgp_livetestkey0000000000abcd';

// ── A DOM small enough to read, big enough to run the page script ────────────
function makeElement(id) {
  const classes = new Set();
  // Attributes are read back now: step 2 marks its session card aria-disabled
  // when the relay connection is gone, and a stub that swallowed setAttribute
  // and answered null could not tell that apart from doing nothing.
  const attributes = new Map();
  const el = {
    id, value: '', textContent: '', innerHTML: '', className: '',
    hidden: false, disabled: false, files: [], style: {},
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, on) => (on === undefined ? (classes.has(c) ? classes.delete(c) : classes.add(c)) : (on ? classes.add(c) : classes.delete(c))),
      contains: (c) => classes.has(c),
    },
    focus() {}, blur() {},
    setAttribute: (name, value) => { attributes.set(name, String(value)); },
    getAttribute: (name) => (attributes.has(name) ? attributes.get(name) : null),
    addEventListener() {}, appendChild() {}, closest: () => null,
  };
  return el;
}

// A run of the page: the vm context, the DOM it saw, and what it asked for.
function runPage({ keyResponses, sectorOk = true, relayStatus = null }) {
  const elements = new Map();
  const getElementById = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const listeners = new Map();
  const sockets = [];
  // `relay` records every relay call with the headers it carried, which is the
  // only way to see which credential the page presented.
  const calls = { key: 0, sector: 0, urls: [], timeouts: [], storage: [], copied: [], relay: [] };
  let keyTurn = 0;

  const respond = (spec) => ({
    ok: spec.status < 400,
    status: spec.status,
    json: async () => spec.body,
  });

  const consoleErrors = [];
  const context = {
    console: Object.assign(Object.create(console), {
      error: (...args) => { consoleErrors.push(args.map(String).join(' ')); },
    }),
    URLSearchParams,
    AbortSignal: { timeout: () => null },
    crypto: globalThis.crypto,
    navigator: { clipboard: { writeText: async (text) => { calls.copied.push(text); } } },
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
    // A socket the test can drive: step 2 has to be measurable when the relay
    // connection dies, which is the case that used to print "Disconnected".
    WebSocket: class {
      constructor(url) { this.url = url; sockets.push(this); }
      send() {}
      close() { this.closed = true; }
    },
    fetch: async (url, opts) => {
      calls.urls.push(url);
      if (String(url).endsWith(TOKEN_URL)) {
        calls.key += 1;
        const spec = keyResponses[Math.min(keyTurn++, keyResponses.length - 1)];
        return respond(spec);
      }
      const headers = (opts && opts.headers) || {};
      calls.relay.push({ url: String(url), method: (opts && opts.method) || 'GET', headers });
      calls.sector += 1;
      if (!sectorOk) throw new Error('sector unreachable');
      // A test can make the relay refuse, which is how the mid-session expiry
      // is driven: the page has to notice a 401 and mint a replacement.
      const forced = relayStatus && relayStatus(String(url), calls.relay.length);
      if (forced) return respond(forced);
      return respond({ status: 200, body: { valid: true, plan: 'pro', ok: true, ticket: 'wst_x', download_token: 'dl_x' } });
    },
  };
  context.window = context;
  context.globalThis = context;
  context.self = context;
  vm.createContext(context);
  // Script order matters and the page ships it that way: the reporter first,
  // then the page code that reads window.paramantErrors at call time.
  vm.runInContext(PS_ERRORS_JS, context, { filename: 'error-message.js' });
  vm.runInContext(PS_JS, context, { filename: 'parashare.page.js' });
  return { context, elements, calls, listeners, getElementById, sockets, consoleErrors };
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
// The credential every relay call carried, in order. This is the assertion the
// whole feature rests on: a Bearer, and never an X-Api-Key.
const relayAuth = (run) => run.calls.relay.map((c) => c.headers.Authorization || c.headers['X-Api-Key'] || null);
const ok200 = { status: 200, body: { token: FAKE_TOKEN, expires_in_s: 900 } };

// Press Copy link the way the page does, and let the clipboard promise settle.
async function copyLinkIn(run) {
  await evalIn(run, 'copyLink()');
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
}

// ── 1. The endpoint answers ─────────────────────────────────────────────────
test('a 200 from /api/user/parasend/token gives the slim row, a usable button, and no key anywhere', async () => {
  const run = await loadPage({ keyResponses: [ok200] });

  assert.equal(run.calls.key, 1, 'the session token is fetched exactly once when the endpoint answers');
  assert.equal(evalIn(run, 'sessionAuth'), FAKE_TOKEN, 'the token is the credential the page holds');
  assert.equal(evalIn(run, 'apiKey'), '', 'THE POINT: no API key is held in the page at all');
  assert.equal(run.getElementById('api-key').value, '',
    'and the manual box stays empty, so the two credentials cannot be confused');

  // The slim row is the state the sender lands in: no empty "API key" box.
  const slim = run.getElementById('ps-key-slim');
  assert.equal(slim.hidden, false, 'the slim row is shown');
  assert.equal(slim.classList.contains('is-loading'), false, 'the slim row stops claiming to be loading');
  assert.equal(run.getElementById('ps-key-slim-label').textContent, 'Using your account');
  assert.equal(run.getElementById('ps-key-mask').hidden, false, 'the masked credential is shown next to the label');
  assert.match(run.getElementById('ps-key-mask').textContent, /^pst_.*\.\.\..{4}$/,
    'the row shows a masked session token, and it says pst_ because that is what the page is holding');
  assert.equal(run.getElementById('step-setup').classList.contains('manual-key'), false,
    'the manual card stays closed: #step-setup only carries .manual-key when the user asks for the box');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'no banner on the happy path');

  assert.equal(evalIn(run, 'keyValid'), true, 'the credential is usable');
  assert.equal(pickAFile(run), true, 'pick a file and "Create secure session" is live');
  assert.equal(wroteTheKey(run), false, 'nothing is written to localStorage');

  // Sector discovery is the first thing the token is spent on, and it goes out
  // as a Bearer. An X-Api-Key here would mean the page still had a key to send.
  assert.ok(run.calls.relay.length >= 4, 'all four sectors were asked');
  assert.deepEqual([...new Set(relayAuth(run))], [`Bearer ${FAKE_TOKEN}`],
    'every relay call must carry the session token as a Bearer, and nothing must carry X-Api-Key');
});

// ── 2. nginx throttles the page ─────────────────────────────────────────────
// /api/user/ sits in the relay_auth zone (deploy/nginx-paramant-live.conf:146,
// burst 5). /parashare loads next to nav-auth's session check and the quota
// call, so a 429 here is the page arriving in its own crowd, not a broken
// account. One retry, 2 s later, and then it gives up.
test('a 429 on the session token is retried once, two seconds later, and then succeeds', async () => {
  const run = await loadPage({ keyResponses: [{ status: 429, body: {} }, ok200] });

  assert.equal(run.calls.key, 2, 'exactly one retry: the rate limiter must not be hammered');
  assert.ok(run.calls.timeouts.includes(2000), `the retry waits 2000 ms; delays asked for were ${run.calls.timeouts.join(', ')}`);
  assert.equal(evalIn(run, 'sessionAuth'), FAKE_TOKEN, 'the retry is what delivers the token');
  assert.equal(run.getElementById('ps-key-slim').hidden, false, 'the slim row is reached through the retry');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'a throttled first try is not an error to the user');
  assert.equal(evalIn(run, 'keyValid'), true);
  assert.equal(wroteTheKey(run), false, 'nothing is written to localStorage');
});

// ── 3. The endpoint is broken ───────────────────────────────────────────────
test('a 500 on the session token shows the banner, hides the slim row, and offers a key by hand', async () => {
  const run = await loadPage({ keyResponses: [{ status: 500, body: {} }] });

  assert.equal(run.calls.key, 1, 'a 500 is not a rate limit: no retry');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), true, 'the failure is stated, not swallowed');
  assert.equal(run.getElementById('ps-key-slim').hidden, true,
    'the slim row may not say "using your account" when there is no session credential');
  assert.equal(evalIn(run, 'keyValid'), false);
  assert.equal(pickAFile(run), false, 'without a credential the button stays disabled, and the banner says why');
  assert.equal(wroteTheKey(run), false, 'nothing is written to localStorage');

  // The way out for a self-host whose deployment has no such endpoint.
  evalIn(run, 'expandApiKeyCard()');
  assert.equal(run.getElementById('step-setup').classList.contains('manual-key'), true, 'the manual card opens on request');
  assert.equal(run.getElementById('ps-key-error').classList.contains('is-shown'), false, 'and the banner steps aside');
});

// ── 4. The banner's words, and the default state of the markup ──────────────
test('/parashare ships the banner copy and opens on the slim row, not the manual card', () => {
  assert.ok(PS_HTML.includes('Your account session could not be started. Sign in again; if it keeps happening, mail <a href="mailto:privacy@paramant.app">privacy@paramant.app</a>.'),
    'the banner must name the one thing to do and the one address to write to');
  assert.match(PS_HTML, /data-click="expandApiKeyCard">Use a key by hand</, 'the banner must carry the manual way out');
  // error-message.js is a plain script and parashare.page.js reads
  // window.paramantErrors at call time, so the order of these two tags is what
  // decides whether this page speaks the shared failure sentence or its own
  // fallback copy of it.
  assert.ok(PS_HTML.indexOf('/js/error-message.js') < PS_HTML.indexOf('/js/parashare.page.js'),
    'error-message.js must load before parashare.page.js, or the page falls back to its own copy of the sentence');

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

  // The reveal route is not what this page runs on any more. It still exists,
  // for the account page and for a self-hoster, but a call to it from here
  // would put the key back in the browser through the door this PR closed.
  assert.ok(!PS_JS.includes('/api/user/account/key'),
    'parashare.page.js must not fetch the account key: it asks for a session token');
  assert.ok(PS_JS.includes('/api/user/parasend/token'), 'and it must ask for the token');

  // One place decides which header goes on a relay call. Five copies is how one
  // of them eventually ships without the refresh, or with the wrong header.
  const xApiKey = [...PS_JS.matchAll(/X-Api-Key/g)].length;
  assert.equal(xApiKey, 1,
    `X-Api-Key appears ${xApiKey} times in parashare.page.js; it belongs only in relayAuthHeaders, which is the manual self-host path`);
});

// ── 5. A dead sector is an error, not a dead button ─────────────────────────
// discoverRelay races four sector hosts. When none of them answers, that says
// nothing about the key, and it used to leave the button greyed out with no
// reason on screen. The key and the sector are now separate questions.
test('a sector that will not answer leaves the button live and reports itself at the press', async () => {
  const run = await loadPage({ keyResponses: [ok200], sectorOk: false });

  assert.ok(run.calls.sector >= 4, 'all four sectors were tried');
  assert.equal(evalIn(run, 'keyValid'), true, 'the session token is good; only the sector is unreachable');
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

// ── 7. The banner points at the door that actually opens ────────────────────
// The first version of this banner offered one way out, "use a key by hand",
// and on paramant.app that is not a way out at all: the hosted relay mints the
// key, the sender has never seen it, and typing one is only meaningful on a
// self-hosted deployment. The action that helps a hosted customer is signing in
// again, so that is the button, and the other one says who it is for.
// Verified by sabotage: swap the two, or drop the self-host note, and this
// fails by name.
test('the key banner leads with signing in again, and says who the manual key is for', () => {
  const bannerAt = PS_HTML.indexOf('id="ps-key-error"');
  assert.ok(bannerAt > 0, 'the banner markup must still be findable by its id');
  const banner = PS_HTML.slice(bannerAt, bannerAt + 900);
  assert.match(banner, /class="ps-alert-primary" href="\/auth\/login">Sign in again</,
    'signing in again is the action that works on the hosted relay, so it is the primary');
  assert.match(banner, /data-click="expandApiKeyCard">Use a key by hand</,
    'the manual card must stay reachable for a self-host with no /api/user/account/key');
  assert.match(banner, /for self-hosted relays/,
    'a hosted customer must be told the manual key is not meant for them');
  // Compared inside the action row, not the whole banner: the sentence above it
  // also says "Sign in again", and matching that would pass whatever the buttons
  // do.
  const actionsAt = banner.indexOf('class="ps-alert-actions"');
  assert.ok(actionsAt > 0, 'the banner must group its actions, so their order is a fact and not an accident of wrapping');
  const actions = banner.slice(actionsAt);
  assert.ok(actions.indexOf('href="/auth/login"') < actions.indexOf('data-click="expandApiKeyCard"'),
    'the primary action must come first in the markup, which is the order a screen reader and a phone both follow');
});

// ── 8. An empty box is not a mistake ────────────────────────────────────────
// "Change" clears the field and calls onKeyInput, and the field it just emptied
// was told its format was invalid. A verdict on a field the user has not filled
// in yet. Verified by sabotage: make the empty case take the malformed branch
// and this goes red on both the wording and the error class.
test('an empty manual key field is asked to be filled in, not called invalid', async () => {
  const run = await loadPage({ keyResponses: [{ status: 500, body: {} }] });
  evalIn(run, 'expandApiKeyCard()');
  const status = run.getElementById('key-status');
  assert.equal(status.textContent, 'Enter your API key to continue',
    'an empty field gets an invitation, not a verdict');
  assert.equal(status.className, 'status-line',
    'and no error styling: nothing has gone wrong yet');

  // A key that really is malformed still says so, otherwise the case above is
  // just silence.
  run.getElementById('api-key').value = 'not-a-key';
  await evalIn(run, 'onKeyInput()');
  assert.match(run.getElementById('key-status').textContent, /starts with pgp_/,
    'a typed value that cannot be a key must say what a key looks like');
  assert.equal(run.getElementById('key-status').className, 'status-line err',
    'that one is an error and is allowed to look like one');
});

// ── 9. A dropped relay connection on step 2 ─────────────────────────────────
// The sender has just handed over a file and made a link. When the socket died
// the page wrote the single word "Disconnected" into a status line, which
// answers none of the three questions a sender has: what happened, where is my
// file, and what do I do now. Same treatment as the key banner.
//
// And the alarm is not the whole screen. A live review found the card still
// under it: green beacon, "Waiting for receiver...", the dead link, the blue
// Copy link. The page said the session was gone and offered to share it in the
// same sentence. The card is switched off with the alarm now, and this measures
// that as well as the words.
//
// Verified by sabotage: put the bare setStatus back, or drop the reopen action,
// and this goes red; drop the setSessionCardStale call out of setLinkError, or
// leave the copy button enabled, and the card half goes red by name.
test('a relay connection that drops before the receiver arrives says so, and offers a way back', async () => {
  // The grey itself is CSS, so the class the script toggles has to have a rule
  // behind it or the card would be marked stale and look exactly as live.
  assert.match(PS_HTML, /<div class="card" id="ps-session-card">/,
    'the step 2 session card must be findable by id, or nothing can switch it off');
  assert.match(PS_HTML, /\.card\.is-stale\{opacity:[^;]+;pointer-events:none\}/,
    '.is-stale must both grey the card and stop it taking taps');
  assert.match(PS_HTML, /#ps-session-card\.is-stale #waiting-dot\{background:var\(--ink-3\);animation:none\}/,
    'the beacon has an id rule of its own, so stopping it needs an id rule too');

  const run = await loadPage({ keyResponses: [ok200] });
  pickAFile(run);
  await evalIn(run, 'createSession()');
  for (let i = 0; i < 10; i += 1) await new Promise((r) => setImmediate(r));

  assert.equal(run.sockets.length, 1, 'creating a session opens exactly one relay socket');
  const firstLink = run.getElementById('session-link').textContent;
  assert.match(firstLink, /\/ontvang\?s=inv_/, 'the sender gets a one-time receiver link');
  assert.equal(run.getElementById('ps-link-error').classList.contains('is-shown'), false,
    'no alarm while the socket is healthy');

  run.sockets[0].onclose();
  const box = run.getElementById('ps-link-error');
  assert.equal(box.classList.contains('is-shown'), true, 'a dropped socket is stated, not whispered into a status line');
  const said = run.getElementById('ps-link-error-text').textContent;
  assert.match(said, /dropped before your receiver arrived/, 'it says what happened');
  assert.match(said, /Nothing was uploaded/, 'it says the file did not go anywhere');
  assert.match(said, /still here in this browser/, 'it says where the file is');
  assert.ok(!/to the relay/.test(said), 'and it says it without naming the plumbing: the sender lost a connection, not a relay');

  // The card under the alarm. It kept a beating beacon, "Waiting for
  // receiver...", the dead link and a blue Copy link, so the screen said the
  // session was gone and offered to share it in the same breath. Copying that
  // link sends the receiver to a session that no longer exists.
  const card = run.getElementById('ps-session-card');
  assert.equal(card.classList.contains('is-stale'), true,
    'the session card must grey out with the alarm; the stylesheet keys the grey and the dead beacon off .is-stale');
  assert.equal(card.getAttribute('aria-disabled'), 'true',
    'a reader who cannot see the grey has to be told the card is off');
  assert.equal(run.getElementById('ps-copy-btn').disabled, true, 'the copy button is really disabled, not only dimmed');
  assert.equal(run.getElementById('session-link').getAttribute('aria-disabled'), 'true',
    'the link box is a click target of its own, so it is marked off as well');
  await copyLinkIn(run);
  assert.deepEqual(run.calls.copied, [], 'and pressing copy on a dead session puts nothing on the clipboard');

  // The way back: a fresh session, a new link, and the alarm cleared.
  await evalIn(run, 'reopenSession()');
  for (let i = 0; i < 10; i += 1) await new Promise((r) => setImmediate(r));
  assert.equal(run.sockets.length, 2, 'reopening makes a new relay connection');
  assert.notEqual(run.getElementById('session-link').textContent, firstLink,
    'and a new one-time link: the old token died with the old socket');
  assert.equal(box.classList.contains('is-shown'), false, 'the alarm clears once the session is back');
  assert.equal(card.classList.contains('is-stale'), false, 'and the card comes back to life with it');
  assert.equal(card.getAttribute('aria-disabled'), 'false');
  assert.equal(run.getElementById('ps-copy-btn').disabled, false, 'the new link is copyable');
  await copyLinkIn(run);
  assert.deepEqual(run.calls.copied, [run.getElementById('session-link').textContent],
    'and copy hands over the new link, not the dead one');

  // A socket that closes after the receiver is already known is the normal end
  // of the handshake, not a failure.
  run.sockets[1].onopen();
  await evalIn(run, "showReceiverConnected('aa'.repeat(16), 'bb'.repeat(16))");
  run.sockets[1].onclose();
  assert.equal(box.classList.contains('is-shown'), false,
    'closing after the receiver has been seen is not an error and must not raise the banner');
});

// ── 10. The words a buyer reads on steps 1 and 2 ────────────────────────────
// The page opened on "Encrypted file relay" and explained itself with keypair,
// fingerprint, plaintext and relay. Every one of those is accurate and none of
// them tells a small firm what the tool does. The jargon is not deleted, it is
// moved: a "How this works" panel holds it, and the flow above it is written
// for someone who wants to send a file. Verified by sabotage: put any of the
// four words back into the flow, or drop the panel, and this fails by word.
test('steps 1 and 2 are written for the sender, with the jargon moved into "How this works"', () => {
  assert.match(PS_HTML, /<h1>Send a file that deletes itself<\/h1>/,
    'the heading says what the tool does for the reader, not what it is made of');
  assert.match(PS_HTML, /<details class="ps-how">[\s\S]*?<summary>How this works<\/summary>/,
    'the technical account must still be on the page, one click away');
  assert.match(PS_HTML, /ML-KEM-768[\s\S]{0,400}ML-DSA-65/,
    'the panel must keep the real names: moving the jargon may not mean losing it');
  assert.match(PS_HTML, /Choose a file \(or several\)/,
    'the file label must ask for a file, not announce vault mode');

  // The flow itself, steps 1 and 2 only, with the panel cut out.
  // Visible words only: the ids and handler names below (fp-display,
  // confirmFingerprint) are code, and renaming those buys the reader nothing.
  const flowText = PS_HTML
    .slice(PS_HTML.indexOf('id="step-setup"'), PS_HTML.indexOf('id="step-encrypting"'))
    .replace(/<details class="ps-how">[\s\S]*?<\/details>/, ' ')
    .replace(/<[^>]+>/g, ' ');
  for (const word of ['keypair', 'key pair', 'plaintext', 'ML-KEM', 'ML-DSA', 'AES-256', 'fingerprint', 'vault mode', 'blob']) {
    assert.ok(!new RegExp(word, 'i').test(flowText),
      `steps 1 and 2 still say "${word}" to the reader; that belongs in the How this works panel, not in the path a sender walks`);
  }
  // And the fingerprint step is named after the thing the sender does.
  assert.match(PS_HTML, /<div class="card-head-title">Compare this code together<\/div>/,
    'the verify card must be named for the action, not for the data structure');
  assert.match(PS_HTML, /<span class="ps-step-label">3 &middot; Compare<\/span>/,
    'the stepper must name the same step the same way');
});

// ── 11. Which failures are worth a line in the console ──────────────────────
// The page reports the unplanned case through failureText, which is the shared
// reporter from js/error-message.js. "No key for this session" is not that
// case: a signed-out browser gets 401 or 403 and a self-host that never built
// the endpoint gets 404, and the banner is the whole answer to both. Reporting
// them would put a console error on every signed-out visit, and
// tests/product-heartbeat.test.mjs reads that console: it caught exactly this
// and went red on "session token: HTTP 404". A 500 is a different thing and does
// get reported. Verified by sabotage in both directions: report the expected
// half and the 404 case goes red; stop reporting the 500 and the 500 case does.
test('a missing session token is not a console error, and a broken endpoint is', async () => {
  for (const status of [401, 403, 404]) {
    const quiet = await loadPage({ keyResponses: [{ status, body: {} }] });
    assert.equal(quiet.getElementById('ps-key-error').classList.contains('is-shown'), true,
      `a ${status} must still raise the banner: the sender has to know why there is no credential`);
    assert.deepEqual(quiet.consoleErrors, [],
      `a ${status} is the ordinary "no key here" answer and may not write to the console of every signed-out visit`);
  }

  const broken = await loadPage({ keyResponses: [{ status: 500, body: {} }] });
  assert.equal(broken.getElementById('ps-key-error').classList.contains('is-shown'), true);
  assert.ok(broken.consoleErrors.some((line) => /\[paramant\] session token/.test(line)),
    'a 500 is unplanned, and its detail belongs in the console through the one reporter');

  // A 200 that carries no token is an account the relay would not mint for,
  // which is planned as well: the admin says so with a token_unavailable body.
  const noToken = await loadPage({ keyResponses: [{ status: 200, body: { error: 'token_unavailable' } }] });
  assert.equal(noToken.getElementById('ps-key-error').classList.contains('is-shown'), true);
  assert.deepEqual(noToken.consoleErrors, [],
    'an account the relay will not mint for is a documented state, not a fault to report');
});

// ── 12. The self-host way out still sends a key ─────────────────────────────
// The token endpoint is part of the hosted admin panel. A self-hosted relay may
// not have it, and for that deployment the banner's "Use a key by hand" is the
// whole product. So the manual path must still work, and it must send the
// header a plain relay understands: X-Api-Key, not a Bearer for a token nobody
// minted. Verified by sabotage: make relayAuthHeaders always send the Bearer
// and this fails on the header; drop the sessionAuth reset out of onKeyInput
// and it fails because a dead token is still being presented.
test('a hand-typed key on a self-host sends X-Api-Key, and takes over from the token', async () => {
  // Start on the happy path, so there IS a token to take over from. That is the
  // case that can go wrong quietly: a page that keeps both credentials.
  const run = await loadPage({ keyResponses: [ok200] });
  assert.equal(evalIn(run, 'sessionAuth'), FAKE_TOKEN);

  evalIn(run, 'expandApiKeyCard()');
  assert.equal(evalIn(run, 'sessionAuth'), '',
    'asking for the box drops the token: one credential at a time, or the page has two sources of truth again');

  run.calls.relay.length = 0;
  run.getElementById('api-key').value = FAKE_KEY;
  await evalIn(run, 'onKeyInput()');
  await new Promise((r) => setImmediate(r));

  assert.equal(evalIn(run, 'apiKey'), FAKE_KEY, 'the typed key is the credential now');
  assert.equal(evalIn(run, 'keyValid'), true);
  assert.ok(run.calls.relay.length >= 4, 'the typed key is checked against the sectors');
  assert.deepEqual([...new Set(relayAuth(run))], [FAKE_KEY],
    'the self-host path must send the key as X-Api-Key; a plain relay knows nothing about pst_ tokens');
  for (const c of run.calls.relay) {
    assert.equal(c.headers.Authorization, undefined, 'and it must not still be waving a token it gave up');
  }
});

// ── 13. The token runs out mid-session ──────────────────────────────────────
// Fifteen minutes is short on purpose, and a send is not. A sender can pick a
// 4 GB file, wait for a receiver to open the link, compare a fingerprint on the
// phone and only then press Send, and the upload is the one step that cannot be
// cheaply retried. There are two guards, and this measures both: the page mints
// a replacement before the expiry it knows about, and if it is wrong about that
// it takes one 401 from the relay and mints on the spot.
//
// Verified by sabotage: drop the margin refresh and the first case goes red;
// drop the 401 retry and the second does; make the retry unconditional and the
// last case never returns at all, which is the loop it exists to forbid.
test('a token that expires during a long session is replaced, before and after the fact', async () => {
  const SECOND = 'pst_' + '99887766'.repeat(8);

  // (a) proactively. The page is handed a token that is already inside its
  // refresh margin, so the very next relay call has to mint first.
  const soon = await loadPage({
    keyResponses: [
      { status: 200, body: { token: FAKE_TOKEN, expires_in_s: 30 } },
      { status: 200, body: { token: SECOND, expires_in_s: 900 } },
    ],
  });
  assert.equal(soon.calls.key, 2, 'a token inside the margin is replaced before it is spent again');
  assert.equal(evalIn(soon, 'sessionAuth'), SECOND);

  // (b) after the fact. The token looks healthy, and the relay says otherwise:
  // a restart, a revocation somewhere else, a clock that disagreed. One 401,
  // one mint, one retry, and the call succeeds on the second token.
  let refused = 0;
  const dead = await loadPage({
    keyResponses: [ok200, { status: 200, body: { token: SECOND, expires_in_s: 900 } }],
    // Only the upload is refused, and only while the first token is being used.
    relayStatus: (url) => {
      if (!url.includes('/v2/inbound')) return null;
      refused += 1;
      return refused === 1 ? { status: 401, body: { error: 'Invalid API key' } } : null;
    },
  });
  assert.equal(dead.calls.key, 1, 'nothing is minted until something is actually refused');

  dead.calls.relay.length = 0;
  const r = await evalIn(dead, "relayFetch('https://health.paramant.app/v2/inbound', { method: 'POST' })");
  assert.equal(r.status, 200, 'the retry after a fresh token is what the caller ends up with');
  assert.equal(dead.calls.key, 2, 'exactly one replacement token was minted');
  assert.equal(evalIn(dead, 'sessionAuth'), SECOND);
  assert.deepEqual(dead.calls.relay.map((c) => c.headers.Authorization),
    [`Bearer ${FAKE_TOKEN}`, `Bearer ${SECOND}`],
    'the first attempt carried the dead token and the second carried the new one');

  // And it stops there. A relay that keeps saying 401 must not become a mint
  // loop against a rate-limited endpoint.
  const stubborn = await loadPage({
    keyResponses: [ok200],
    relayStatus: (url) => (url.includes('/v2/inbound') ? { status: 401, body: { error: 'Invalid API key' } } : null),
  });
  const before = stubborn.calls.key;
  const still = await evalIn(stubborn, "relayFetch('https://health.paramant.app/v2/inbound', { method: 'POST' })");
  assert.equal(still.status, 401, 'a 401 that survives a fresh token is a real 401 and is handed to the caller');
  assert.ok(stubborn.calls.key - before <= 1, 'one mint, never a loop');
});
