'use strict';
// One booted relay.js, for suites that test the ROUTE layer rather than a lib.
//
// WHY. relay.js is 6488 lines and 68 route comparisons, and until now no unit
// test loaded it: it was only ever started as a black box by inbound-hash-verify,
// deep-health-gate and billing-stance-boot, each of which rolled its own spawn.
// The auth gate, the envelope lifecycle, the transfer burn and the per-tier
// limits all live in that file, so testing them means booting it. This is the
// shared version of the spawn those three suites already do by hand, plus:
//   - a writable scratch dir for every path that otherwise defaults to /data
//     (identity, STH log, peer STHs, code manifest, trial keys, users.json),
//     so a test run neither needs root nor leaves anything behind;
//   - an ephemeral port taken from the OS, so parallel suites never collide;
//   - a small request helper that returns { status, headers, body } with the
//     JSON already parsed.
//
// Nothing here reaches the network: the relay binds 127.0.0.1, redis and NATS
// are switched off by empty URLs, and Mollie is never given a key.

const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RELAY_DIR = path.join(__dirname, '..');
const RELAY_JS = path.join(RELAY_DIR, 'relay.js');

// Every child this module started, so a suite's after() hook can kill the lot.
const _children = new Set();

// SIGTERM, not SIGKILL. relay.js handles SIGTERM (relay.js:6479) by zeroizing
// its blobs, flushing the CT/STH queues and calling process.exit(0) - and a
// clean exit is also what makes the child write its V8 coverage profile when
// the run is wrapped in c8 or NODE_V8_COVERAGE. A SIGKILLed relay contributes
// no coverage at all, which is exactly why relay.js showed up as "not in the
// table" in the 2026-09-02 audit: the three suites that boot it all kill it
// with SIGKILL. SIGKILL stays as the backstop for a child that ignores the ask.
function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { clearTimeout(t); resolve(); };
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} resolve(); }, 3000);
    child.once('exit', done);
    try { child.kill('SIGTERM'); } catch (_) { done(); }
  });
}

// Await this in a suite's after() hook. Waiting is not politeness: a child that
// has not finished exiting has not finished writing its coverage profile
// either, and the parent exiting first loses it.
function killAll() {
  const all = [..._children].map(stopChild);
  _children.clear();
  return Promise.all(all).then(() => {
    for (const d of _dirs) {
      if (!d.startsWith(os.tmpdir())) continue;
      try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
    }
    _dirs.clear();
  });
}

// A port the OS just told us is free. Racy in theory (someone could take it in
// the gap), which is why boot() retries on EADDRINUSE.
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

// Scratch dirs handed out by boot(), removed by killAll() so a test run leaves
// nothing behind. Only ever paths this module made under the OS temp dir.
const _dirs = new Set();

function scratchDir(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `relay-${tag}-`));
  _dirs.add(d);
  return d;
}

// Env that keeps a booted relay entirely inside its own scratch dir. Every
// entry here has a /data default in relay.js; without them the boot logs four
// EACCES warnings and the identity is regenerated per restart, which quietly
// breaks any test that restarts the relay on purpose.
function scratchEnv(dir) {
  return {
    RELAY_IDENTITY_FILE: path.join(dir, 'relay-identity.json'),
    TRIAL_KEYS_FILE: path.join(dir, 'trial-keys.jsonl'),
    STH_FILE: path.join(dir, 'sth-log.jsonl'),
    PEER_STH_DIR: path.join(dir, 'peer-sths'),
    CODE_MANIFEST_FILE: path.join(dir, 'code-manifest.json'),
    USERS_FILE: path.join(dir, 'users.json'),
  };
}

// Boot relay.js and wait until /health answers.
//
// opts.users      – users.json content as an object; goes in USERS_JSON (read
//                   only) unless opts.usersFile is true, in which case it is
//                   written to <dir>/users.json so the relay can write it back.
// opts.env        – extra environment, wins over everything above.
// opts.dir        – reuse a scratch dir (this is how a restart test keeps the
//                   users.json and the relay identity of the previous boot).
// opts.captureLog – keep stdout, exposed as srv.log().
async function boot(opts = {}) {
  const dir = opts.dir || scratchDir(opts.tag || 'test');
  const users = opts.users || { api_keys: [] };
  const env = {
    ...process.env,
    ...scratchEnv(dir),
    NODE_ENV: 'test',
    // No redis, no NATS, no Mollie key: this relay talks to nothing.
    REDIS_URL: '',
    RELAY_REDIS_URL: '',
    NATS_URL: '',
    RELAY_SELF_URL: '',
    RELAY_PRIMARY_URL: '',
    HOST: '127.0.0.1',
  };
  for (const k of ['MOLLIE_API_KEY', 'MOLLIE_TEST_API_KEY', 'BILLING_MODE']) delete env[k];

  if (opts.usersFile) {
    // Only write when the caller supplied users, so a restart keeps whatever
    // the previous boot persisted.
    if (opts.users || !fs.existsSync(env.USERS_FILE)) {
      fs.writeFileSync(env.USERS_FILE, JSON.stringify(users, null, 2));
    }
    delete env.USERS_JSON;
  } else {
    env.USERS_JSON = JSON.stringify(users);
  }
  Object.assign(env, opts.env || {});

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = await freePort();
    const child = spawn(process.execPath, [RELAY_JS], {
      cwd: RELAY_DIR,
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
    let healthy = false;
    while (Date.now() < deadline && exited === null) {
      try {
        const r = await fetch(`http://127.0.0.1:${port}/health`);
        if (r.ok) { healthy = true; break; }
      } catch (_) { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (healthy) {
      return makeHandle(child, port, dir, env, () => out, opts);
    }
    _children.delete(child);
    stopChild(child);
    lastErr = new Error(
      `relay.js did not become healthy on port ${port} (exit=${exited}).\n` +
      `stdout/stderr tail:\n${out.slice(-2000)}`);
    if (!/EADDRINUSE/.test(out)) break; // only a port clash is worth a retry
  }
  throw lastErr || new Error('relay.js did not boot');
}

function makeHandle(child, port, dir, env, log, bootOpts) {
  const base = `http://127.0.0.1:${port}`;
  const handle = {
    port, dir, env, child, base, log,
    // One request. `body` may be a string, a Buffer or a plain object (which is
    // sent as JSON). Returns the parsed JSON when the answer is JSON, and the
    // raw text either way.
    req(method, p, { headers = {}, body } = {}) {
      const hdr = { ...headers };
      let payload = null;
      if (body !== undefined && body !== null) {
        if (Buffer.isBuffer(body) || typeof body === 'string') {
          payload = Buffer.from(body);
        } else {
          payload = Buffer.from(JSON.stringify(body));
          if (!Object.keys(hdr).some((h) => h.toLowerCase() === 'content-type')) {
            hdr['Content-Type'] = 'application/json';
          }
        }
      }
      return new Promise((resolve, reject) => {
        const r = http.request(base + p, {
          method,
          headers: hdr,
          // GET /v2/outbound/:hash answers with an X-Paramant-Receipt header of
          // about 18.5 KB (a base64 ML-DSA-65 signature over the delivery
          // receipt, measured 2026-09-02). Node's own default maxHeaderSize is
          // 16 KB and undici's fetch() caps earlier, so a plain fetch() of a
          // download throws UND_ERR_HEADERS_OVERFLOW. Raised here so the test
          // client is not the thing under test; the size itself is a finding,
          // reported with this PR, not a fixture.
          maxHeaderSize: 96 * 1024,
        }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const buf = Buffer.concat(chunks);
            const text = buf.toString('utf8');
            let json = null;
            try { json = JSON.parse(text); } catch (_) { /* not JSON */ }
            resolve({ status: res.statusCode, headers: res.headers, text, json, buf });
          });
        });
        r.on('error', reject);
        if (payload) r.write(payload);
        r.end();
      });
    },
    get(p, o) { return handle.req('GET', p, o); },
    post(p, o) { return handle.req('POST', p, o); },
    // Read what the relay persisted to its users.json (usersFile mode only).
    readUsersFile() {
      return JSON.parse(fs.readFileSync(env.USERS_FILE, 'utf8'));
    },
    stop() {
      _children.delete(child);
      stopChild(child);
    },
    // Stop and boot again on the SAME scratch dir: same users.json, same relay
    // identity, new process. This is the shape of the #315 regression test.
    async restart(extra = {}) {
      handle.stop();
      await new Promise((r) => setTimeout(r, 150));
      // Same dir, same env, no fresh users payload: the relay must find on disk
      // whatever the previous process wrote there.
      return boot({
        ...bootOpts,
        users: null,
        dir,
        usersFile: true,
        env: { ...(bootOpts.env || {}), ...extra },
      });
    },
  };
  return handle;
}

module.exports = { boot, killAll, freePort, RELAY_DIR };
