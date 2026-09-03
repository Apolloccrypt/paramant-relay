'use strict';
// One booted admin/server.js, plus a stub relay for it to talk to.
//
// WHY THIS FILE EXISTS. Every suite in admin/test was, until now, either a pure
// lib test or a source-text assertion: twenty files, and not one of them ever
// started the server. login-ratelimit.test.js is the clearest case. It rebuilds
// the login decision in its own attemptLogin() helper and then reads server.js
// as a string to check the ORDER of three calls. That catches a handler that
// reverts to counting attempts before it authenticates, and it caught nothing
// else, because the handler it tested was one written in the test file.
//
// The reviewer's scenario is a request-level property: ten wrong codes on one
// address from three IP addresses, and then the owner signs in. Whether that
// works depends on the real handler, the real limiter, real redis keys and the
// real order in which express runs them. So this is the admin counterpart of
// relay/test/_relay-server.js: spawn the actual process, talk HTTP to it, and
// let it be wrong if it is wrong.
//
// WHAT IS REAL AND WHAT IS NOT. Redis is real (REDIS_URL, same server the relay
// route suites use). The admin process is real, unmodified, spawned as the
// Dockerfile spawns it. The RELAY is a stub: the admin reaches it over HTTP for
// exactly two things during a login (the account lookup and the TOTP verdict),
// and standing up a whole relay to answer those would make this suite depend on
// the native signing binding for no gain. The stub answers on the same two
// routes with the same shapes, and a test can make it say anything, including
// 503, which is the one relay answer the login handler has a branch for.

const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const path = require('path');

const ADMIN_DIR = path.join(__dirname, '..');
const ADMIN_JS = path.join(ADMIN_DIR, 'server.js');

// Everything this module started, so a suite's after() hook can end the lot.
const _children = new Set();
const _servers = new Set();

// SIGTERM first, same reasoning as _relay-server.js: a killed child writes no
// V8 coverage profile. SIGKILL stays as the backstop.
function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { clearTimeout(t); resolve(); };
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) { /* gone */ } resolve(); }, 3000);
    child.once('exit', done);
    try { child.kill('SIGTERM'); } catch (_) { done(); }
  });
}

async function killAll() {
  const all = [..._children].map(stopChild);
  _children.clear();
  await Promise.all(all);
  for (const s of _servers) { await new Promise((r) => s.close(r)); }
  _servers.clear();
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

// The two relay routes an admin login touches, and nothing else.
//
//   GET  /v2/admin/keys?reveal=1  -- the account table. findUserByEmail pulls
//        the whole thing and matches on email, which is how "does this account
//        exist" is decided.
//   POST /v2/user/verify-totp     -- the verdict on a code.
//
// state.accounts is the table; state.verify decides the verdict and may return
// a status of its own, so a test can hand the admin a 503 and watch what it
// does with it. Every request is recorded in state.calls.
async function stubRelay(state) {
  const port = await freePort();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = null;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (_) { body = null; }
      state.calls.push({ method: req.method, path: url.pathname, body });
      const send = (status, payload) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      if (url.pathname === '/v2/admin/keys') return send(200, { keys: state.accounts });
      if (url.pathname === '/v2/user/verify-totp' || url.pathname === '/v2/user/consume-backup') {
        const backup = url.pathname.endsWith('consume-backup');
        const out = backup
          ? (state.consumeBackup ? state.consumeBackup(body || {}) : { valid: false })
          : state.verify(body || {});
        const throttleMs = relayThrottleMs(state, body || {});
        const reply = () => send(out.status || 200, out.body !== undefined ? out.body : {
          valid: !!out.valid, ...(backup ? {} : { algorithm: 'sha256' }), throttle_ms: throttleMs,
        });
        // A real relay does not answer instantly. Two costs, and they are
        // different in kind: state.verifyDelayMs is the fixed work (a redis read
        // of the encrypted secret, the single-use write), and the throttle below
        // is the per-account delay relay.js charges for previous failures. The
        // second one is the whole finding: it is only ever charged to a request
        // that names an account that exists.
        const wait = (state.verifyDelayMs || 0) + throttleMs;
        if (wait > 0) return setTimeout(reply, wait);
        return reply();
      }
      if (url.pathname === '/health') return send(200, { ok: true });
      return send(404, { error: 'stub_relay_has_no_such_route', path: url.pathname });
    });
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  _servers.add(server);
  return { port, base: `http://127.0.0.1:${port}`, state, close: () => new Promise((r) => { _servers.delete(server); server.close(r); }) };
}

// relay/lib/auth-throttle.js, reproduced: 250 ms per failure past ten, capped at
// two seconds, charged per user_id. The stub keeps the count the way relay.js
// keeps it, in memory, so a suite can drive the throttle from outside.
//
// `throttled_upstream` in the body is the caller declaring it has already
// charged the delay itself. relay.js honours it by counting the failure and
// reporting throttle_ms without sleeping, and so does this.
function relayThrottleMs(state, body) {
  if (!state.throttle) return 0;
  const key = String(body.user_id || '');
  const failures = state.throttleCounts.get(key) || 0;
  const over = failures - 10;
  const owed = over > 0 ? Math.min(over * 250, 2000) : 0;
  const wrong = !(state.verify(body) || {}).valid;
  state.throttleCounts.set(key, wrong ? failures + 1 : 0);
  return body.throttled_upstream ? 0 : owed;
}

// A relay stub with one account on it, ready to be handed to boot().
//
// The code a test types is compared against `secret` here rather than in the
// admin, because the admin does not check codes: it asks the relay. That is the
// whole reason the timing side-channel in the not-found branch existed.
function defaultRelayState(accounts = [], secret = '123456') {
  const state = {
    accounts,
    calls: [],
    verifyDelayMs: 0,
    // Off by default so the suites that do not care about it are not slowed
    // down; login-timing turns it on, because it is the finding.
    throttle: false,
    throttleCounts: new Map(),
    verify: (body) => ({ valid: body && body.totp === secret }),
  };
  return state;
}

// Boot admin/server.js and wait until it answers.
//
// opts.redisUrl   - required; the admin exits at once without one.
// opts.relay      - a stub from stubRelay(); its base becomes RELAY_HEALTH.
// opts.env        - extra environment, wins over everything above.
// opts.serverPath - a different server.js to run, or ADMIN_SERVER_JS in the
//                   environment. This is how a suite is checked against the
//                   code it is supposed to catch: point it at a pre-fix
//                   checkout and the suite has to go red. A test has no reason
//                   to pass it itself.
async function boot(opts = {}) {
  const relay = opts.relay;
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    BASE_PATH: '',
    ADMIN_TOKEN: opts.adminToken || 'admin-token-for-the-admin-http-suite',
    INTERNAL_AUTH_TOKEN: opts.internalToken || 'internal-token-for-the-admin-http-suite',
    REDIS_URL: opts.redisUrl,
    RELAY_HEALTH: relay ? relay.base : 'http://127.0.0.1:1',
    RELAY_MAIN: relay ? relay.base : 'http://127.0.0.1:1',
    SITE_URL: 'http://127.0.0.1',
  };
  // No mail: RESEND_API_KEY unset makes sendSetupEmail throw, and every call
  // site of it is already .catch()ed, so nothing leaves this machine.
  delete env.RESEND_API_KEY;
  Object.assign(env, opts.env || {});

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = await freePort();
    const child = spawn(process.execPath, [opts.serverPath || process.env.ADMIN_SERVER_JS || ADMIN_JS], {
      cwd: ADMIN_DIR,
      env: { ...env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    _children.add(child);

    let out = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { out += d.toString(); });
    let exited = null;
    child.on('exit', (code) => { exited = code; });

    const deadline = Date.now() + 20000;
    let up = false;
    while (Date.now() < deadline && exited === null) {
      // ANY answer means the listener is up. Not r.ok: the admin's own probe
      // route (/api/auth/check) answers 401 when nobody is signed in, which is
      // exactly why a /health that says something true was worth adding.
      try { await fetch(`http://127.0.0.1:${port}/api/auth/check`); up = true; break; }
      catch (_) { /* not listening yet */ }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (up) return makeHandle(child, port, env, () => out, relay);

    _children.delete(child);
    await stopChild(child);
    lastErr = new Error(
      `admin/server.js did not come up on port ${port} (exit=${exited}).\n` +
      `stdout/stderr tail:\n${out.slice(-2000)}`);
    if (!/EADDRINUSE/.test(out)) break;
  }
  throw lastErr || new Error('admin/server.js did not boot');
}

function makeHandle(child, port, env, log, relay) {
  const base = `http://127.0.0.1:${port}`;
  const handle = {
    port, env, child, base, log, relay,
    // One request. Returns { status, headers, text, json, ms }. ms is measured
    // around the socket, which is what the timing suite needs.
    req(method, p, { headers = {}, body } = {}) {
      const hdr = { ...headers };
      let payload = null;
      if (body !== undefined && body !== null) {
        payload = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
        if (!Object.keys(hdr).some((h) => h.toLowerCase() === 'content-type')) {
          hdr['Content-Type'] = 'application/json';
        }
      }
      const t0 = process.hrtime.bigint();
      return new Promise((resolve, reject) => {
        const r = http.request(base + p, { method, headers: hdr }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let json = null;
            try { json = JSON.parse(text); } catch (_) { /* not JSON */ }
            resolve({
              status: res.statusCode, headers: res.headers, text, json,
              ms: Number(process.hrtime.bigint() - t0) / 1e6,
            });
          });
        });
        r.on('error', reject);
        if (payload) r.write(payload);
        r.end();
      });
    },
    get(p, o) { return handle.req('GET', p, o); },
    post(p, o) { return handle.req('POST', p, o); },
    // A login attempt from a named IP. The handler reads x-real-ip and there is
    // no trust-proxy setting, so a test can spend one IP's budget and move on,
    // which is exactly the three-IP attack the reviewer described.
    login({ email, totp, ip, challenge_id, nonce }) {
      const body = { email, totp };
      if (challenge_id !== undefined) body.challenge_id = challenge_id;
      if (nonce !== undefined) body.nonce = nonce;
      return handle.post('/api/user/login', { headers: { 'X-Real-IP': ip || '198.51.100.1' }, body });
    },
    stop() { _children.delete(child); return stopChild(child); },
  };
  return handle;
}

// Solve one proof-of-work challenge: the smallest nonce whose
// sha256(challenge_id + salt + nonce) starts with `difficulty` zero bits. The
// admin issues these at GET /api/captcha/challenge and the login page solves
// them in the browser; a test that wants to get past the threshold has to do
// the same work, about 2^18 hashes.
function solvePow(challengeId, salt, difficulty) {
  const crypto = require('crypto');
  const fullChars = Math.floor(difficulty / 4);
  const rem = difficulty % 4;
  for (let n = 0; ; n++) {
    const h = crypto.createHash('sha256').update(challengeId + salt + String(n)).digest('hex');
    let ok = true;
    for (let i = 0; i < fullChars; i++) { if (h[i] !== '0') { ok = false; break; } }
    if (!ok) continue;
    if (rem === 0) return n;
    if ((parseInt(h[fullChars], 16) & (0xF << (4 - rem))) === 0) return n;
  }
}

// Closing line of a suite, same contract as relay/test/_requires.js: a run that
// asserted nothing says SKIPPED rather than "0 checks passed", because CI greps
// for that phrase and a green tick over nothing is worse than a red one.
// Copied rather than required across the two packages on purpose: admin/ is its
// own npm project and its Dockerfile copies only its own tree.
function summary(name, passed) {
  console.log(passed > 0
    ? `\n${name}: ${passed} checks passed`
    : `\n${name}: SKIPPED - 0 checks ran`);
}

module.exports = { boot, killAll, freePort, stubRelay, defaultRelayState, solvePow, summary, ADMIN_DIR, ADMIN_JS };
