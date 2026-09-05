'use strict';
// The whole buyer-facing stack on one origin, for the gate that walks the whole
// paying customer's path (tests/koper-hele-weg.test.mjs).
//
// One origin matters twice: WebAuthn needs it, and the bug this gate exists for
// was rights landing on one relay and being read from another. So the screens,
// the account API and the relay all sit behind the same dev proxy the local
// passkey flow already uses, and the admin points at the relay the same way.
//
//   relay-main (real relay.js)   <- public /v2: checkout, webhook, redeem
//   relay-health (real relay.js) <- what the admin plane reads for every screen
//   admin (real server.js)       <- /api/user/*, the account screens' backend
//   dev proxy                    <- frontend/ + /api -> admin + /v2 -> relay-main
//   fake Mollie                  <- the far end of the payment wire
//
// TWO relays, not one, and that is the whole point. In production the money
// lands on relay-main (nginx sends public /v2 there) and every screen is served
// off relay-health (admin/server.js SECTORS.health). users.json is per
// container; only redis is shared. A one-relay test cannot see the bug this
// gate exists for, because on one relay every write is trivially readable.
//
// Redis is required (invoices and the entitlement mirror live there) and is
// taken from REDIS_URL. The stack picks its OWN redis database index so a run
// never reads or writes anything a developer already had in db 0.

const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const fakeMollie = require('./fake-mollie.cjs');
const fakeResend = require('./fake-resend.cjs');

const children = new Set();
const dirs = new Set();

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
  });
}

async function waitFor(fn, ms = 25000, every = 150) {
  const deadline = Date.now() + ms;
  let last;
  while (Date.now() < deadline) {
    try { if (await fn()) return true; } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, every));
  }
  throw new Error('timeout waiting for stack' + (last ? ': ' + last.message : ''));
}

function spawnLogged(cmd, args, opts, tag, sink) {
  const child = spawn(cmd, args, opts);
  children.add(child);
  const push = (d) => { sink.push(`[${tag}] ${d.toString()}`); if (sink.length > 4000) sink.shift(); };
  child.stdout.on('data', push);
  child.stderr.on('data', push);
  return child;
}

// A redis database index nobody else in this repo uses, wiped before the run.
const REDIS_DB = parseInt(process.env.KOPER_REDIS_DB || '11', 10);

function redisUrlWithDb(base, db) {
  const u = new URL(base || 'redis://127.0.0.1:6379');
  u.pathname = '/' + db;
  return u.toString();
}

async function start(opts = {}) {
  const logs = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'koper-stack-'));
  dirs.add(dir);

  const redisUrl = redisUrlWithDb(process.env.REDIS_URL || 'redis://127.0.0.1:6379', REDIS_DB);
  // Wipe our own database, never anyone else's.
  const { createClient } = require(path.join(ROOT, 'admin', 'node_modules', 'redis'));
  const rc = createClient({ url: redisUrl });
  await rc.connect();
  await rc.flushDb();

  const mollie = fakeMollie.create();
  const mollieOrigin = await mollie.listen();
  const resend = fakeResend.create();
  const resendOrigin = await resend.listen();

  const relayPort = await freePort();      // relay-main: the public /v2 half
  const healthPort = await freePort();     // relay-health: what the screens read
  const adminPort = await freePort();
  const proxyPort = await freePort();
  const origin = `http://localhost:${proxyPort}`;

  const adminToken = 'dev-admin-' + crypto.randomBytes(8).toString('hex');
  const internalToken = 'dev-internal-' + crypto.randomBytes(8).toString('hex');
  const totpKey = crypto.randomBytes(32).toString('base64');

  const commonEnv = {
    ...process.env,
    NODE_ENV: 'test',
    REDIS_URL: redisUrl,
    RELAY_REDIS_URL: redisUrl,
    ADMIN_TOKEN: adminToken,
    INTERNAL_AUTH_TOKEN: internalToken,
    PARAMANT_TOTP_MASTER_KEY: totpKey,
    NATS_URL: '',
    RESEND_API_KEY: 're_test_key_for_the_sink',
    FAKE_RESEND_URL: resendOrigin,
    NODE_OPTIONS: `--require ${path.join(__dirname, 'mollie-intercept.cjs')}`,
  };

  const relayEnvFor = (tag, port) => ({
    ...commonEnv,
    PORT: String(port),
    HOST: '127.0.0.1',
    SECTOR: tag,
    RELAY_MODE: 'ghost_pipe',
    RELAY_IDENTITY_FILE: path.join(dir, `${tag}-identity.json`),
    TRIAL_KEYS_FILE: path.join(dir, `${tag}-trial-keys.jsonl`),
    STH_FILE: path.join(dir, `${tag}-sth-log.jsonl`),
    PEER_STH_DIR: path.join(dir, `${tag}-peer-sths`),
    CODE_MANIFEST_FILE: path.join(dir, `${tag}-code-manifest.json`),
    // The per-container file. Separate on purpose: this is what makes a grant
    // written on one relay invisible to the other unless redis carries it.
    USERS_FILE: path.join(dir, `${tag}-users.json`),
    MOLLIE_TEST_API_KEY: 'test_dummy_key_for_the_fake',
    BILLING_MODE: 'test',
    FAKE_MOLLIE_URL: mollieOrigin,
    PARASIGN_PUBLIC_ORIGIN: origin,
    SITE_URL: origin,
    ...(opts.relayEnv || {}),
  });

  const relayEnv = relayEnvFor('main', relayPort);
  const healthEnv = relayEnvFor('health', healthPort);
  for (const e of [relayEnv, healthEnv]) fs.writeFileSync(e.USERS_FILE, JSON.stringify({ api_keys: [] }, null, 2));

  let relay = spawnLogged(process.execPath, ['relay.js'], {
    cwd: path.join(ROOT, 'relay'), env: relayEnv, stdio: ['ignore', 'pipe', 'pipe'],
  }, 'main', logs);
  let health = spawnLogged(process.execPath, ['relay.js'], {
    cwd: path.join(ROOT, 'relay'), env: healthEnv, stdio: ['ignore', 'pipe', 'pipe'],
  }, 'health', logs);

  // Restart one relay on the SAME port with its users.json rewritten in
  // between. This is how a test moves the clock: paid_until lives on the
  // account record, and rereading it at boot is what happens on a deploy.
  async function restartRelay(which, mutate, extraEnv) {
    const isMain = which === 'main';
    const env = isMain ? relayEnv : healthEnv;
    const child = isMain ? relay : health;
    try { child.kill('SIGTERM'); } catch (_) {}
    await new Promise((r) => setTimeout(r, 600));
    if (typeof mutate === 'function') {
      const j = JSON.parse(fs.readFileSync(env.USERS_FILE, 'utf8'));
      mutate(j);
      fs.writeFileSync(env.USERS_FILE, JSON.stringify(j, null, 2));
    }
    const next = spawnLogged(process.execPath, ['relay.js'], {
      cwd: path.join(ROOT, 'relay'), env: { ...env, ...(extraEnv || {}) }, stdio: ['ignore', 'pipe', 'pipe'],
    }, which, logs);
    if (isMain) relay = next; else health = next;
    await waitFor(async () => (await fetch(`http://127.0.0.1:${isMain ? relayPort : healthPort}/health`)).ok);
    return next;
  }

  const adminEnv = {
    ...commonEnv,
    PORT: String(adminPort),
    BASE_PATH: '',
    RELAY_MAIN: `http://127.0.0.1:${relayPort}`,
    RELAY_HEALTH: `http://127.0.0.1:${healthPort}`,
    RELAY_LEGAL: `http://127.0.0.1:${healthPort}`,
    RELAY_FINANCE: `http://127.0.0.1:${healthPort}`,
    RELAY_IOT: `http://127.0.0.1:${healthPort}`,
    SITE_URL: origin,
    WEBAUTHN_RP_ID: 'localhost',
    WEBAUTHN_ORIGIN: origin,
    ...(opts.adminEnv || {}),
  };
  const admin = spawnLogged(process.execPath, ['server.js'], {
    cwd: path.join(ROOT, 'admin'), env: adminEnv, stdio: ['ignore', 'pipe', 'pipe'],
  }, 'admin', logs);

  const proxy = spawnLogged(process.execPath, [path.join(ROOT, 'scripts', 'dev-local-proxy.js')], {
    cwd: ROOT,
    env: { ...process.env, DEV_PORT: String(proxyPort), ADMIN_URL: `http://127.0.0.1:${adminPort}`, RELAY_URL: `http://127.0.0.1:${relayPort}` },
    stdio: ['ignore', 'pipe', 'pipe'],
  }, 'proxy', logs);

  await waitFor(async () => (await fetch(`http://127.0.0.1:${relayPort}/health`)).ok);
  await waitFor(async () => (await fetch(`http://127.0.0.1:${healthPort}/health`)).ok);
  await waitFor(async () => (await fetch(`http://127.0.0.1:${adminPort}/api/user/session/verify`)).status !== 0);
  await waitFor(async () => (await fetch(`${origin}/pricing.html`)).ok);

  return {
    origin, relayPort, healthPort, adminPort, proxyPort, adminToken, internalToken,
    redisUrl, redis: rc, mollie, mollieOrigin, resend, resendOrigin, dir, logs,
    totpKey,
    usersFile: relayEnv.USERS_FILE,
    healthUsersFile: healthEnv.USERS_FILE,
    admin, proxy, restartRelay,
    get relay() { return relay; },
    get health() { return health; },
    log: () => logs.join(''),
    async stop() {
      try { await rc.quit(); } catch (_) { /* already gone */ }
      await mollie.close();
      await resend.close();
      for (const c of children) { try { c.kill('SIGTERM'); } catch (_) {} }
      await new Promise((r) => setTimeout(r, 300));
      for (const c of children) { try { c.kill('SIGKILL'); } catch (_) {} }
      children.clear();
      for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {} }
      dirs.clear();
    },
  };
}

module.exports = { start, freePort, waitFor };
