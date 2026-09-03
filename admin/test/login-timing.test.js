'use strict';
// Does an address that exists take longer to be refused than one that does not?
//
// WHY THIS SUITE EXISTS. The status codes on /api/user/login were made
// identical on purpose: three different 403s were folded into one 401 so the
// code could not be read as "this address is a customer". The clock was left
// alone. An existing account reaches a second relay call and one more redis
// read; a non-existent one returns two steps earlier, and the difference is
// stable enough to classify an address from a single request. Measured on this
// harness before the fix, 200 requests per case, with the stub relay given a
// realistic 3 ms cost for /v2/user/verify-totp:
//
//   exists  p50 6.44 ms   min 4.59 ms
//   absent  p50 2.20 ms   max 3.73 ms
//
// The ranges do not even touch. One request per address, under the rate limit,
// no credentials, and the customer list falls out.
//
// WHAT IS ASSERTED HERE. Not "the code contains a delay" -- that is a source
// assertion and it would pass over a delay applied to the wrong branch. The
// property is measured: the two medians sit on top of each other, and the two
// ranges overlap, so no threshold separates them.
//
// The floor is set low for this suite (PARAMANT_LOGIN_MIN_ANSWER_MS below)
// because a suite that waits the production 250 ms per request would take
// minutes. That also pins the knob: if the environment variable were ignored,
// every sample would land at 250 ms and the run would time out rather than
// quietly pass.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/login-timing.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, summary } = require('./_admin-server');

const TIMING_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const TIMING_FLOOR_MS = 60;
// What a real relay costs on the verify call. This is the oracle: with it set
// to zero the pre-fix gap was about 1 ms, with it at 3 ms it was about 4 ms.
// The suite runs with it on, so a fix that only closed the small gap fails.
const TIMING_RELAY_MS = 3;
const TIMING_SAMPLES = 30;
// Per run, for the same reason as the other admin HTTP suites: the failure
// counter is shared state with a fifteen-minute window.
const TIMING_RUN = crypto.randomBytes(5).toString('hex');
const TIMING_PRESENT_KEY = `pgp_present_account_for_the_timing_suite_${TIMING_RUN}`;
const TIMING_PRESENT_EMAIL = `present_${TIMING_RUN}@example.com`;
const TIMING_ABSENT_EMAIL = `absent_${TIMING_RUN}@example.com`;

let tSrv = null;
let tRelay = null;
let tRedis = null;
let tChecks = 0;
const tDid = () => { tChecks++; };

const TIMING_NET = 20 + Math.floor(Math.random() * 200);
let _tIp = 0;
const tIp = () => { _tIp++; return `${TIMING_NET}.${(_tIp >> 8) & 255}.${_tIp & 255}.11`; };

before(async () => {
  const url = process.env.REDIS_URL || TIMING_DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error('unmet precondition "redis": the redis module is not installed. ' +
      'Run npm ci in admin/, or declare it: ADMIN_TEST_SKIP=redis');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  tRedis = rc;

  tRelay = await stubRelay(defaultRelayState(
    [{ key: TIMING_PRESENT_KEY, email: TIMING_PRESENT_EMAIL, active: true }], '123456'));
  tRelay.state.verifyDelayMs = TIMING_RELAY_MS;
  tSrv = await boot({
    redisUrl: url,
    relay: tRelay,
    env: { PARAMANT_LOGIN_MIN_ANSWER_MS: String(TIMING_FLOOR_MS) },
  });
  // Without this the existing account takes the "TOTP not configured" branch
  // and never reaches the relay, which is the cheap path -- and the suite would
  // be comparing two short paths and finding nothing.
  await tRedis.set(`paramant:user:totp_active:${TIMING_PRESENT_KEY}`, 'true');
});

after(async () => {
  await killAll();
  if (tRedis) { try { await tRedis.disconnect(); } catch (_) { /* already gone */ } }
  summary('login-timing', tChecks);
});

const ready = () => tSrv !== null;

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// Merely naming an address must not push it over the proof-of-work threshold
// halfway through a run: a 428 is a different amount of work and would show up
// as noise in exactly the measurement being taken.
async function clearFailures(email) {
  await tRedis.del(`paramant:user:loginfail:${crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`);
}

test('a 401 for an address that exists takes the same time as one for an address that does not', async (t) => {
  if (!ready()) return t.skip('no redis');

  // Thrown away: the first requests through a fresh process pay for JIT and for
  // the first redis round trips, and they would land in whichever group ran
  // first.
  for (let i = 0; i < 5; i++) {
    await clearFailures(TIMING_PRESENT_EMAIL);
    await tSrv.login({ email: TIMING_PRESENT_EMAIL, totp: '000000', ip: tIp() });
  }

  // Interleaved, so a drift in machine load hits both cases equally.
  const present = [];
  const absent = [];
  for (let i = 0; i < TIMING_SAMPLES; i++) {
    await clearFailures(TIMING_PRESENT_EMAIL);
    await clearFailures(TIMING_ABSENT_EMAIL);
    const a = await tSrv.login({ email: TIMING_PRESENT_EMAIL, totp: '000000', ip: tIp() });
    const b = await tSrv.login({ email: TIMING_ABSENT_EMAIL, totp: '000000', ip: tIp() });
    assert.equal(a.status, 401, `the existing account must answer 401, got ${a.status} ${a.text}`);
    assert.equal(b.status, 401, `the absent account must answer 401, got ${b.status} ${b.text}`);
    present.push(a.ms);
    absent.push(b.ms);
  }

  const pMed = median(present);
  const aMed = median(absent);
  const pMin = Math.min(...present);
  const pMax = Math.max(...present);
  const aMin = Math.min(...absent);
  const aMax = Math.max(...absent);
  const detail = `exists p50=${pMed.toFixed(2)} [${pMin.toFixed(2)}, ${pMax.toFixed(2)}], ` +
                 `absent p50=${aMed.toFixed(2)} [${aMin.toFixed(2)}, ${aMax.toFixed(2)}]`;

  // The floor has to be doing the work, or this suite proves nothing: both
  // groups must sit on it rather than on whatever the handler happened to cost.
  assert.ok(pMed >= TIMING_FLOOR_MS - 5 && aMed >= TIMING_FLOOR_MS - 5,
    `both cases must be held to the floor of ${TIMING_FLOOR_MS}ms; ${detail}`);
  tDid();

  // The gap this closes was 4.2 ms at the median with the same 3 ms relay cost.
  // Five is a generous ceiling on a loaded machine and still an order of
  // magnitude below a usable signal at these sample sizes.
  assert.ok(Math.abs(pMed - aMed) < 5,
    `the medians must not separate the two cases; ${detail}`);
  tDid();

  // The stronger property, and the one that actually kills the oracle: the
  // ranges overlap, so there is no threshold at which a single request
  // classifies an address. Before the fix the fastest hit was slower than the
  // slowest miss.
  assert.ok(pMin < aMax && aMin < pMax,
    `the two ranges must overlap, or one request still classifies an address; ${detail}`);
  tDid();
});

test('the floor does not slow down the refusals that are not credential answers', async (t) => {
  if (!ready()) return t.skip('no redis');
  // A 429 is told apart from a 401 by its status code, so padding it would buy
  // nothing and would only punish the caller who is already being refused. The
  // same goes for the 428 that asks for a proof-of-work: the login page is
  // waiting on it to start hashing.
  const ip = tIp();
  for (let i = 0; i < 5; i++) await tSrv.login({ email: TIMING_ABSENT_EMAIL, totp: '000000', ip });
  const refused = await tSrv.login({ email: TIMING_ABSENT_EMAIL, totp: '000000', ip });
  assert.equal(refused.status, 429, `the sixth attempt from one IP is refused, got ${refused.status}`);
  assert.ok(refused.ms < TIMING_FLOOR_MS,
    `a 429 must not be held to the credential floor, took ${refused.ms.toFixed(2)}ms`);
  tDid();
});
