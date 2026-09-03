'use strict';
// The account-existence oracle on /api/user/login, measured.
//
// This is the instrument, not a test. It boots an admin, drives N login
// attempts against an address that exists and N against one that does not, and
// prints the distribution of both. login-timing.test.js is the assertion that
// keeps the result true; this file is what produced the numbers quoted in the
// pull request, and it can be pointed at any checkout:
//
//   node admin/test/login-timing.bench.js
//   ADMIN_SERVER_JS=/path/to/other/admin/server.js node admin/test/login-timing.bench.js
//
// Needs a redis: REDIS_URL, default redis://127.0.0.1:6393.
//
// Every attempt uses a fresh X-Real-IP. The per-IP limiter allows five in
// fifteen minutes and the sixth is a 429, which would be measuring the wrong
// thing entirely.

const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6393';
const SERVER_JS = process.env.ADMIN_SERVER_JS || null;
const N = Number.parseInt(process.env.BENCH_N || '200', 10);
// How long the stub relay takes to answer /v2/user/verify-totp. That call is
// what the existing-account branch does and the absent-account branch does not,
// so it IS the oracle: set it to what a real relay costs on your network.
const RELAY_MS = Number.parseInt(process.env.BENCH_RELAY_DELAY_MS || '0', 10);

const REAL_EMAIL = 'present@example.test';
const ABSENT_EMAIL = 'absent@example.test';
const PRESENT_KEY = 'pgp_present_account_for_the_timing_bench';
// This run's own address space, so its per-IP counters cannot meet another's.
const OCTET = 20 + Math.floor(Math.random() * 200);

// One connection, reused: opening a client per flush was itself several
// milliseconds of noise inside the loop being measured.
let _rc = null;
async function redisClient() {
  if (_rc) return _rc;
  const { createClient } = require('redis');
  _rc = createClient({ url: REDIS_URL });
  _rc.on('error', () => {});
  await _rc.connect();
  return _rc;
}

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return {
    n: s.length,
    mean: s.reduce((a, b) => a + b, 0) / s.length,
    p50: at(0.5), p90: at(0.9), p99: at(0.99),
    min: s[0], max: s[s.length - 1],
  };
}

const f = (x) => x.toFixed(2).padStart(8);

async function run() {
  const relay = await stubRelay(defaultRelayState(
    [{ key: PRESENT_KEY, email: REAL_EMAIL, active: true }],
    '123456'));
  relay.state.verifyDelayMs = RELAY_MS;
  const srv = await boot({ redisUrl: REDIS_URL, relay, serverPath: SERVER_JS });

  // The account has to have TOTP switched ON, or the handler takes the
  // "not configured" branch and answers 401 without ever calling the relay --
  // which would measure two short paths against each other and find nothing.
  // The oracle is the relay call, so the account must be one that reaches it.
  const seed = await redisClient();
  await seed.set(`paramant:user:totp_active:${PRESENT_KEY}`, 'true');

  // Both addresses must be under the proof-of-work threshold for the whole run,
  // or half the samples measure a 428 instead of a credential answer. Ten
  // failures is the threshold and the window is fifteen minutes, so the counter
  // is cleared before each group.
  const wipe = async (pattern) => {
    const c = await redisClient();
    for await (const batch of c.scanIterator({ MATCH: pattern, COUNT: 500 })) {
      for (const k of (Array.isArray(batch) ? batch : [batch])) await c.del(k);
    }
  };
  const flush = () => wipe('paramant:user:loginfail:*');

  // A previous run leaves per-IP counters behind for fifteen minutes, and the
  // sixth attempt from one IP is a 429. Clear them, and give this run its own
  // /8 as well, so two runs in the same window cannot collide.
  await wipe('paramant:user:ratelimit:ip:*');

  const sample = async (email, label) => {
    const out = [];
    for (let i = 0; i < N; i++) {
      if (i % 8 === 0) await flush();
      const r = await srv.login({ email, totp: '000000', ip: `${OCTET}.${(i >> 8) & 255}.${i & 255}.${label}` });
      if (r.status !== 401) throw new Error(`expected 401 for ${email}, got ${r.status} ${r.text}`);
      out.push(r.ms);
    }
    return out;
  };

  // A warm-up that is thrown away: the first requests through a fresh process
  // pay for JIT and for the first redis round trips, and they land in whichever
  // group runs first.
  await sample(REAL_EMAIL, 9);

  // Interleaved rather than one group after the other, so a drift in machine
  // load hits both cases equally.
  const present = [];
  const absent = [];
  for (let i = 0; i < N; i++) {
    if (i % 8 === 0) await flush();
    const a = await srv.login({ email: REAL_EMAIL, totp: '000000', ip: `${OCTET}.100.${i & 255}.${(i >> 8) & 255}` });
    const b = await srv.login({ email: ABSENT_EMAIL, totp: '000000', ip: `${OCTET}.200.${i & 255}.${(i >> 8) & 255}` });
    if (a.status !== 401 || b.status !== 401) throw new Error(`expected two 401s, got ${a.status} and ${b.status}`);
    present.push(a.ms);
    absent.push(b.ms);
  }

  const p = stats(present);
  const q = stats(absent);
  console.log(`\nadmin/server.js: ${SERVER_JS || 'this checkout'}`);
  console.log(`${N} requests per case, interleaved, one X-Real-IP each.`);
  console.log(`stub relay verify-totp cost: ${RELAY_MS} ms\n`);
  console.log('case                  mean     p50     p90     p99     min     max');
  console.log(`account exists    ${f(p.mean)}${f(p.p50)}${f(p.p90)}${f(p.p99)}${f(p.min)}${f(p.max)}`);
  console.log(`account absent    ${f(q.mean)}${f(q.p50)}${f(q.p90)}${f(q.p99)}${f(q.min)}${f(q.max)}`);
  console.log(`\ndelta of means    ${f(p.mean - q.mean)} ms`);
  console.log(`delta of medians  ${f(p.p50 - q.p50)} ms`);

  await srv.stop();
  await relay.close();
  await killAll();
  if (_rc) await _rc.destroy();
}

run().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
