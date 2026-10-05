'use strict';
// The account-existence oracle on /api/user/login, measured.
//
// This is the instrument, not a test. It boots an admin, drives N login
// attempts against an address that exists and N against one that does not, at a
// chosen number of PRIOR FAILURES, and prints both distributions.
// login-timing.test.js is the assertion that keeps the result true; this file is
// what produced the numbers in the pull request, and it can be pointed at any
// checkout:
//
//   node admin/test/login-timing.bench.js
//   ADMIN_SERVER_JS=/other/checkout/admin/server.js node admin/test/login-timing.bench.js
//
// Knobs: BENCH_N (samples per case), BENCH_FAILURES (comma-separated levels),
// BENCH_RELAY_DELAY_MS (fixed relay cost), BENCH_RELAY_THROTTLE (1 to give the
// stub relay the per-account delay relay.js really charges), REDIS_URL.
//
// WHY PRIOR FAILURES ARE A KNOB. The first round of this fix measured only a
// clean address and concluded the oracle was 4 ms wide. It is not. relay.js
// sleeps 250 ms per failure past ten, capped at two seconds, and only a request
// naming an account that EXISTS ever reaches that sleep. At twelve failures the
// gap is half a second; at twenty it is two. Any instrument that only looks at
// zero failures reports a fixed floor as a complete fix, which is exactly what
// happened.
//
// Every attempt uses a fresh X-Real-IP: the per-IP limiter allows five per
// fifteen minutes and the sixth is a 429, which would measure the wrong thing.

const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, solvePow } = require('./_admin-server');

const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6393';
const SERVER_JS = process.env.ADMIN_SERVER_JS || null;
const N = Number.parseInt(process.env.BENCH_N || '100', 10);
const RELAY_MS = Number.parseInt(process.env.BENCH_RELAY_DELAY_MS || '0', 10);
const RELAY_THROTTLE = process.env.BENCH_RELAY_THROTTLE !== '0';
const LEVELS = String(process.env.BENCH_FAILURES || '0,12,20')
  .split(',').map((x) => Number.parseInt(x, 10)).filter(Number.isFinite);

const RUN = crypto.randomBytes(4).toString('hex');
const PRESENT_KEY = `pgp_present_account_for_the_timing_bench_${RUN}`;
const PRESENT_EMAIL = `present_${RUN}@example.com`;
const ABSENT_EMAIL = `absent_${RUN}@example.com`;
const OCTET = 20 + Math.floor(Math.random() * 200);

let _rc = null;
async function redisClient() {
  if (_rc) return _rc;
  const { createClient } = require('redis');
  _rc = createClient({ url: REDIS_URL });
  _rc.on('error', () => {});
  await _rc.connect();
  return _rc;
}

const failKey = (email) =>
  `paramant:user:loginfail:${crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`;

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return { n: s.length, mean: s.reduce((a, b) => a + b, 0) / s.length,
    p50: at(0.5), p90: at(0.9), p99: at(0.99), min: s[0], max: s[s.length - 1] };
}
const f = (x) => x.toFixed(2).padStart(9);

async function run() {
  const relay = await stubRelay(defaultRelayState(
    [{ key: PRESENT_KEY, email: PRESENT_EMAIL, active: true }], '123456'));
  relay.state.verifyDelayMs = RELAY_MS;
  relay.state.throttle = RELAY_THROTTLE;
  const srv = await boot({ redisUrl: REDIS_URL, relay, serverPath: SERVER_JS });

  const rc = await redisClient();
  // TOTP has to be ON, or the handler takes the "not configured" branch and
  // answers 401 without ever calling the relay: two short paths, no finding.
  await rc.set(`paramant:user:totp_active:${PRESENT_KEY}`, 'true');

  // A run's own /8, so the fifteen-minute per-IP counters of the last run
  // cannot refuse the first request of this one.
  let ipN = 0;
  const nextIp = () => { ipN++; return `${OCTET}.${(ipN >> 8) & 255}.${ipN & 255}.5`; };

  // Above ten failures the answer is 428 unless the request carries a solved
  // proof-of-work, so the attack (and this measurement) has to pay for one.
  // Solved BEFORE the timed request, or the hashing shows up in the timing.
  async function proofIfNeeded(failures) {
    if (failures < 10) return {};
    const ch = await srv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': nextIp() } });
    if (ch.status !== 200) throw new Error(`no challenge: ${ch.status} ${ch.text}`);
    return { challenge_id: ch.json.challenge_id, nonce: solvePow(ch.json.challenge_id, ch.json.salt, ch.json.difficulty) };
  }

  const setFailures = async (email, n) => {
    if (n <= 0) await rc.del(failKey(email));
    else await rc.set(failKey(email), String(n), { EX: 900 });
  };

  // Drive the stub relay's per-account counter to the same level, the way real
  // wrong codes would. relay.js counts per user_id in memory.
  const setRelayFailures = (n) => { relay.state.throttleCounts.set(PRESENT_KEY, n); };

  async function sample(email, failures, isPresent) {
    await setFailures(email, failures);
    if (isPresent) setRelayFailures(failures);
    const proof = await proofIfNeeded(failures);
    const r = await srv.login({ email, totp: '000000', ip: nextIp(), ...proof });
    if (r.status !== 401) throw new Error(`expected 401 for ${email} at ${failures} failures, got ${r.status} ${r.text}`);
    return r.ms;
  }

  // Warm-up, thrown away: the first requests pay for JIT and the first redis
  // round trips.
  for (let i = 0; i < 5; i++) await sample(PRESENT_EMAIL, 0, true);

  console.log(`\nadmin/server.js: ${SERVER_JS || 'this checkout'}`);
  console.log(`${N} requests per case, interleaved, one X-Real-IP each.`);
  console.log(`stub relay: fixed cost ${RELAY_MS} ms, per-account throttle ${RELAY_THROTTLE ? 'on (relay/lib/auth-throttle.js)' : 'off'}\n`);
  console.log('prior failures  case                mean      p50      p90      p99      min      max');

  for (const level of LEVELS) {
    const present = [];
    const absent = [];
    for (let i = 0; i < N; i++) {
      present.push(await sample(PRESENT_EMAIL, level, true));
      absent.push(await sample(ABSENT_EMAIL, level, false));
    }
    const p = stats(present);
    const q = stats(absent);
    const lbl = String(level).padStart(4);
    console.log(`${lbl}            exists       ${f(p.mean)}${f(p.p50)}${f(p.p90)}${f(p.p99)}${f(p.min)}${f(p.max)}`);
    console.log(`${lbl}            absent       ${f(q.mean)}${f(q.p50)}${f(q.p90)}${f(q.p99)}${f(q.min)}${f(q.max)}`);
    const overlap = p.min < q.max && q.min < p.max;
    console.log(`${lbl}            delta p50    ${f(p.p50 - q.p50)}   ranges ${overlap ? 'OVERLAP' : 'DO NOT OVERLAP -- one request classifies the address'}\n`);
  }

  await srv.stop();
  await relay.close();
  await killAll();
  if (_rc) await _rc.destroy();
}

run().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
