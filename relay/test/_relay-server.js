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

// Boot relay.js and wait until OUR relay.js answers.
//
// "OURS" IS THE WHOLE PROBLEM. freePort() asks the OS for a free port, closes
// the listener and hands the number on, so between that close and the child's
// own listen() the port belongs to nobody and anybody may take it. The route
// suites are started as `node --test test/route-*.test.js`, which runs the
// files in PARALLEL processes, and every one of them boots relays through this
// function. Two of them being handed the same number is not exotic, it is
// arithmetic.
//
// The old loop then made it invisible. It probed GET /health on the port and
// took any 200 as "we are up", starting on the very first iteration, long
// before the child could possibly be listening. So when another suite's relay
// held the port, THAT relay answered, this function returned a handle pointing
// at it, and our own child died of EADDRINUSE unnoticed. The test then talked
// to a stranger with a different ADMIN_TOKEN and got
// {"error":"ADMIN_TOKEN required for admin endpoints"} with a 401, which is
// what run 33713795533 saw on route-billing-entitlements #315 after a restart.
// Nothing about that failure looked like a port clash, which is why it read as
// a restart bug.
//
// So the wait has two halves and neither is optional:
//   1. our child's own stdout must carry relay_started for THIS port. Only the
//      process that owns the socket logs that, so it is proof of ownership,
//      not a guess about timing;
//   2. when the caller set an ADMIN_TOKEN, one authenticated admin request must
//      not come back 401, which is the same proof from the other end and the
//      exact symptom the suite hit.
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
    // THE BOOT-TIME BACKGROUND JOBS STAY OUT OF A TEST RUN unless a suite asks
    // for them by name (opts.env wins over this).
    //
    // Both of these reach the SHARED redis, not this relay's scratch dir, and
    // both work on keys with no account in them: the plan-expiry sweep
    // zRem/hDels members of the one global paramant:billing:expiry zset
    // (lib/plan-expiry.js), and the party-index migration takes a global lock
    // and SCANs the whole `env:*` keyspace (lib/parasign-party-backfill.js).
    // CI runs 21 route suites in parallel processes against ONE redis on db 0,
    // so a relay that lives past its own suite's assertions starts sweeping and
    // scanning another suite's rows. The delays are 30-60 s and 15-35 s, which
    // is longer than most suites but not longer than all of them, so it shows
    // up as one suite going red on somebody else's branch.
    //
    // An hour is not a magic number: it is "longer than any suite in this repo
    // stays up". A suite that wants either job sets its own value.
    PLAN_EXPIRY_BOOT_DELAY_MS: String(3600000),
    PARTY_INDEX_BOOT_DELAY_MS: String(3600000),
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

    // relay.js logs one JSON line per event; this is the one server.listen()
    // fires in its callback (relay.js:6972), and it carries the port it is
    // actually bound to.
    const startedOnOurPort = () =>
      new RegExp(`"msg":"relay_started"[^\\n]*"port":${port}\\b`).test(out);

    const deadline = Date.now() + 20000;
    let healthy = false;
    while (Date.now() < deadline && exited === null) {
      // Do not even ask the port a question until our own child says it owns
      // it. Asking earlier is how a stranger's relay gets adopted.
      if (startedOnOurPort()) {
        try {
          const r = await fetch(`http://127.0.0.1:${port}/health`);
          if (r.ok) { healthy = true; break; }
        } catch (_) { /* listening, not serving yet */ }
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (healthy) {
      // Second half: if this suite runs with an admin token, spend one request
      // proving the process on the other end shares it. A 401 here means the
      // answer is coming from a relay that is not ours, and returning the
      // handle anyway is what turned a port clash into a mystery about
      // restarts.
      if (env.ADMIN_TOKEN) {
        const hdr = { 'X-Admin-Token': env.ADMIN_TOKEN };
        if (env.INTERNAL_AUTH_TOKEN) hdr['X-Internal-Auth'] = env.INTERNAL_AUTH_TOKEN;
        // Any account id: an unknown one is a 404 from our own relay and a 401
        // from anyone else's. Only the 401 is disqualifying.
        const probe = await fetch(
          `http://127.0.0.1:${port}/v2/admin/entitlements/acct_boot_probe`, { headers: hdr });
        if (probe.status === 401) {
          throw new Error(
            `the relay answering on port ${port} does not share this suite's ADMIN_TOKEN, so it is\n` +
            '  not the child this boot() started. Our child logged relay_started on that port, which\n' +
            '  should make that impossible; something else is listening on it.\n' +
            `stdout/stderr tail:\n${out.slice(-2000)}`);
        }
      }
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
    req(method, p, { headers = {}, body, maxHeaderSize } = {}) {
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
          // NO maxHeaderSize override by default, on purpose. This client is
          // held to Node's own 16 KB limit, the same one a caller using fetch()
          // has, so any route that grows a header block past it fails here
          // instead of only in production. GET /v2/outbound/:hash used to answer
          // with 19560 bytes of headers and threw UND_ERR_HEADERS_OVERFLOW on
          // every download (PR #341, finding 2). A test that needs the old
          // behaviour asks for the room explicitly.
          ...(maxHeaderSize ? { maxHeaderSize } : {}),
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
    // Returns a promise: await it when what happens next depends on this
    // process being gone. restart() does.
    stop() {
      _children.delete(child);
      return stopChild(child);
    },
    // Stop and boot again on the SAME scratch dir: same users.json, same relay
    // identity, new process. This is the shape of the #315 regression test.
    async restart(extra = {}) {
      // Await the exit instead of sleeping 150 ms at it. relay.js zeroizes its
      // blobs, flushes the CT/STH queues and writes users.json on SIGTERM
      // (relay.js:6479), and the next boot reads that same users.json. 150 ms
      // was a guess at how long that takes, and on a loaded runner it is the
      // wrong guess: the new relay would read a file the old one had not
      // finished writing.
      await handle.stop();
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
