'use strict';
// Does an address that exists take longer to be refused than one that does not?
//
// WHY THIS SUITE EXISTS, AND WHY IT WAS REWRITTEN. The first version measured
// only a clean address, found the gap was about 4 ms, added a fixed floor, and
// declared the oracle closed. It was not. relay.js charges a per-ACCOUNT
// throttle before it checks a code (relay/lib/auth-throttle.js: 250 ms per
// failure past ten, capped at two seconds), and only a request naming an
// account that exists ever reaches it. Measured through a booted admin with the
// stub relay charging that same throttle, 100 requests per case:
//
//   prior failures   exists p50    absent p50   ranges
//   0                251.87 ms     251.90 ms    overlap
//   12               509.91 ms     251.61 ms    do not overlap
//   20              2010.23 ms     251.82 ms    do not overlap
//
// Twelve wrong codes from rotating source addresses, which nothing refuses
// because the per-address counter deliberately does not refuse, and one request
// classifies the address. So this suite runs at three failure levels, with the
// real floor and the real throttle values, and a level of zero on its own is
// not enough to pass it.
//
// It costs about a minute: at twenty failures every answer is held for 2.25 s
// by design, and each request past the threshold has to carry a real 2^18
// proof-of-work, solved before the clock starts so the hashing is not measured.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/login-timing.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, realRelay, solvePow, summary } = require('./_admin-server');

const TIMING_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
// The production default from deploy/.env.example. Not a smaller number: a
// floor that only holds in the test is not a floor.
const TIMING_FLOOR_MS = 250;
// What a real relay costs on the verify call, on top of the throttle.
const TIMING_RELAY_MS = 3;
// relay/lib/auth-throttle.js, via the stub. This is the finding.
const TIMING_LEVELS = [0, 12, 20];
const TIMING_SAMPLES = 8;
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

const failKey = (email) =>
  `paramant:user:loginfail:${crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`;

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
  tRelay.state.throttle = true;
  // No env override: the suite runs on the shipped default, so a change to that
  // default that reopens the oracle shows up here.
  tSrv = await boot({ redisUrl: url, relay: tRelay });
  // Without this the existing account takes the "TOTP not configured" branch and
  // never reaches the relay, which is the cheap path: the suite would compare
  // two short paths and find nothing.
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

// Put this address on exactly `n` recorded failures. Both the admin's counter
// (keyed on the hashed address) and, for the account that exists, the relay's
// own per-account counter, so the two are in the state twelve wrong codes would
// really have left them in.
async function setFailures(email, n, presentKey) {
  if (n <= 0) await tRedis.del(failKey(email));
  else await tRedis.set(failKey(email), String(n), { EX: 900 });
  if (presentKey) tRelay.state.throttleCounts.set(presentKey, n);
}

// Past ten failures the answer is 428 unless the request carries a solved
// proof-of-work, so the attack has to buy one and so does this. Solved before
// the timed request: 2^18 hashes inside the measurement would drown it.
async function proofIfNeeded(failures) {
  if (failures < 10) return {};
  const ch = await tSrv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': tIp() } });
  assert.equal(ch.status, 200, `a challenge must be issuable: ${ch.status} ${ch.text}`);
  return {
    challenge_id: ch.json.challenge_id,
    nonce: solvePow(ch.json.challenge_id, ch.json.salt, ch.json.difficulty),
  };
}

async function sampleOne(email, failures, presentKey) {
  await setFailures(email, failures, presentKey);
  const proof = await proofIfNeeded(failures);
  const r = await tSrv.login({ email, totp: '000000', ip: tIp(), ...proof });
  assert.equal(r.status, 401,
    `at ${failures} prior failures ${email} must still get a plain 401, got ${r.status} ${r.text}`);
  return r.ms;
}

test('the refusal takes the same time whether the address has an account or not', async (t) => {
  if (!ready()) return t.skip('no redis');

  // Warm-up, thrown away: the first requests pay for JIT and the first redis
  // round trips, and they would land in whichever group ran first.
  for (let i = 0; i < 4; i++) await sampleOne(TIMING_PRESENT_EMAIL, 0, TIMING_PRESENT_KEY);

  for (const level of TIMING_LEVELS) {
    const present = [];
    const absent = [];
    // Interleaved, so a drift in machine load hits both cases equally.
    for (let i = 0; i < TIMING_SAMPLES; i++) {
      present.push(await sampleOne(TIMING_PRESENT_EMAIL, level, TIMING_PRESENT_KEY));
      absent.push(await sampleOne(TIMING_ABSENT_EMAIL, level, null));
    }
    const pMed = median(present);
    const aMed = median(absent);
    const pMin = Math.min(...present), pMax = Math.max(...present);
    const aMin = Math.min(...absent), aMax = Math.max(...absent);
    const detail = `at ${level} prior failures: exists p50=${pMed.toFixed(2)} [${pMin.toFixed(2)}, ${pMax.toFixed(2)}], ` +
                   `absent p50=${aMed.toFixed(2)} [${aMin.toFixed(2)}, ${aMax.toFixed(2)}]`;

    // The floor is doing the work, and it grows with the failure count exactly
    // as the relay's throttle does: 250 ms base, plus 250 ms per failure past
    // ten, capped at two seconds. If the mirror were missing, the absent case
    // would sit at 250 ms while the present one climbed.
    const owed = TIMING_FLOOR_MS + Math.min(Math.max(level - 10, 0) * 250, 2000);
    for (const [label, med] of [['exists', pMed], ['absent', aMed]]) {
      assert.ok(med >= owed - 10,
        `${label} must be held to its floor of ${owed}ms; ${detail}`);
    }
    tDid();

    // The gap this closes was 258 ms at twelve failures and 1758 ms at twenty.
    // Ten is a generous ceiling on a loaded machine and two orders of magnitude
    // below a usable signal.
    assert.ok(Math.abs(pMed - aMed) < 10,
      `the medians must not separate the two cases; ${detail}`);
    tDid();

    // The property that actually kills the oracle: the ranges overlap, so no
    // threshold classifies an address from one request. Before the fix the
    // fastest hit was slower than the slowest miss at both levels above zero.
    assert.ok(pMin < aMax && aMin < pMax,
      `the two ranges must overlap, or one request still classifies an address; ${detail}`);
    tDid();
  }
});

test('the relay is told the delay was already charged, so it is never charged twice', async (t) => {
  if (!ready()) return t.skip('no redis');
  // The floor above only stays constant because relay.js does not ALSO sleep.
  // A change that drops this flag would put the account-keyed delay back on top
  // of the address-keyed one, and the timing test would only notice it on a
  // loaded machine. Pin the flag itself.
  const calls = tRelay.state.calls.filter((c) => c.path === '/v2/user/verify-totp');
  assert.ok(calls.length > 0, 'the suite above must have reached the relay at all');
  const unflagged = calls.filter((c) => !c.body || c.body.throttled_upstream !== true);
  assert.equal(unflagged.length, 0,
    `every verify-totp call must declare the throttle was applied upstream, ${unflagged.length} did not`);
  tDid();
});

// ── /api/user/login-with-backup ──────────────────────────────────────────────
//
// The same question on the other login route, and it needed its own answer.
// consumeBackupCode verifies a code against EVERY stored hash until one
// matches, so a wrong code costs ten full argon2id verifications at 64 MiB:
// measured here, one verification p50 49.7 ms and ten of them p50 494.2 ms with
// a max of 870.9 ms. An address with no account pays none of it. With the
// 250 ms floor this route inherited in the last round, that read as 472.7 ms
// against 251.6 ms with no overlap, and the admin logged "answer overran its
// floor" on every single request, which is the code saying the floor it was
// given was not one.
//
// The floor on this route is PARAMANT_LOGIN_BACKUP_MIN_ANSWER_MS, 1500 ms by
// default, plus the per-address throttle. Nothing is stubbed here: it is a real
// relay doing real argon2 against ten real stored hashes, because the finding
// is the cost of that work and a stub would be measuring the stub.
const BK_SAMPLES = 6;
// The route refuses at five hits per address per window, so the last attempt it
// answers with a verdict is the fifth: four before it. Five before it is a 429
// for BOTH cases, which is not a credential answer and carries no information.
const BK_LEVELS = [0, 4];
const BK_KEY = `pgp_backup_account_for_the_timing_suite_${TIMING_RUN}`;
const BK_PRESENT_EMAIL = `bkpresent_${TIMING_RUN}@example.com`;
const BK_ABSENT_EMAIL = `bkabsent_${TIMING_RUN}@example.com`;
const BK_ADMIN_TOKEN = 'admin-token-for-the-backup-timing-suite';
const BK_INTERNAL_TOKEN = 'internal-token-for-the-backup-timing-suite';
// admin/server.js LOGIN_BACKUP_MIN_ANSWER_MS default.
const BK_FLOOR_MS = 1500;

let bkSrv = null;
let bkRelay = null;

const bkHitKey = (email) =>
  `paramant:webauthn:rl:bk:email:${crypto.createHash('sha256').update(String(email).toLowerCase().trim()).digest('hex')}`;

// The engine the relay refuses to boot without. @paramant/core is a file-link to
// the sibling repo, so a checkout that has not built it cannot start a relay,
// and this case cannot run. Same doctrine as relay/test/_requires.js: that is a
// hard failure unless the runner names it, so the job that lacks the engine has
// to say so and the job that has it cannot quietly stop running this.
function relayEngineAvailable() {
  try { require.resolve('@paramant/core', { paths: [require('path').join(__dirname, '..', '..', 'relay')] }); return true; }
  catch (_) { return false; }
}

test('the backup-code route answers in the same time whether the address has an account or not', async (t) => {
  if (!ready()) return t.skip('no redis');
  const url = process.env.REDIS_URL || TIMING_DEFAULT_REDIS;

  if (!relayEngineAvailable()) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').map((x) => x.trim()).includes('relay')) {
      console.log('  SKIP [relay] - @paramant/core is not built, so relay.js cannot boot ' +
        '(declared via ADMIN_TEST_SKIP). This case runs in the relay-crypto job, which builds it.');
      return;
    }
    throw new Error(
      'unmet precondition "relay": @paramant/core is not built, so relay.js cannot boot and\n' +
      '  the argon2 cost this case measures cannot be produced. Build the binding (see\n' +
      '  .github/workflows/test.yml, job relay-crypto-tests), or, if this job is\n' +
      '  deliberately without it, say so on the runner: ADMIN_TEST_SKIP=relay');
  }

  bkRelay = await realRelay({
    redisUrl: url,
    adminToken: BK_ADMIN_TOKEN,
    internalToken: BK_INTERNAL_TOKEN,
    accounts: [{ key: BK_KEY, plan: 'pro', active: true, email: BK_PRESENT_EMAIL, account_id: 'acct_bk' }],
  });
  bkSrv = await boot({
    redisUrl: url,
    relay: bkRelay,
    adminToken: BK_ADMIN_TOKEN,
    internalToken: BK_INTERNAL_TOKEN,
  });
  t.after(async () => { await bkSrv.stop(); await bkRelay.close(); });

  const codes = await bkRelay.enrol(BK_KEY);
  assert.equal(codes.length, 10, `the account must really have ten backup codes, got ${codes.length}`);
  const stored = await tRedis.sCard(`paramant:user:backup_codes:${BK_KEY}`);
  assert.equal(stored, 10, `and ten argon2 hashes stored, got ${stored}`);
  tDid();

  // A code that is wrong in the right shape: it has to reach argon2 and fail
  // against all ten, which is the worst case and the one that matters.
  const wrong = 'ZZZZ-ZZZZ-ZZZZ';
  assert.ok(!codes.includes(wrong), 'the wrong code must really be wrong');

  const attempt = async (email, priorHits) => {
    // Put the address on exactly `priorHits` attempts. Both cases are driven to
    // the same number, which is the point: the counter is incremented before
    // findUserByEmail, so it cannot know whether the account exists.
    if (priorHits <= 0) await tRedis.del(bkHitKey(email));
    else await tRedis.set(bkHitKey(email), String(priorHits), { EX: 900 });
    const r = await bkSrv.post('/api/user/login-with-backup', {
      headers: { 'X-Real-IP': tIp() },
      body: { email, backup_code: wrong },
    });
    assert.equal(r.status, 401,
      `a wrong backup code is a 401 at ${priorHits} prior attempts, got ${r.status} ${r.text}`);
    return r.ms;
  };

  // Warm-up: the first argon2 call in a fresh process pays for the native
  // module and the first 64 MiB allocation.
  for (let i = 0; i < 2; i++) await attempt(BK_PRESENT_EMAIL, 0);

  for (const level of BK_LEVELS) {
    const present = [];
    const absent = [];
    for (let i = 0; i < BK_SAMPLES; i++) {
      present.push(await attempt(BK_PRESENT_EMAIL, level));
      absent.push(await attempt(BK_ABSENT_EMAIL, level));
    }
    const pMed = median(present), aMed = median(absent);
    const pMin = Math.min(...present), pMax = Math.max(...present);
    const aMin = Math.min(...absent), aMax = Math.max(...absent);
    const detail = `at ${level} prior attempts: exists p50=${pMed.toFixed(2)} [${pMin.toFixed(2)}, ${pMax.toFixed(2)}], ` +
                   `absent p50=${aMed.toFixed(2)} [${aMin.toFixed(2)}, ${aMax.toFixed(2)}]`;

    // The floor must be above the argon2 worst case, or the work shows through
    // it. 250 ms per attempt past the first, same step as the other route.
    const owed = BK_FLOOR_MS + Math.min(Math.max(level - 1, 0) * 250, 2000);
    for (const [label, med] of [['exists', pMed], ['absent', aMed]]) {
      assert.ok(med >= owed - 20, `${label} must be held to its floor of ${owed}ms; ${detail}`);
    }
    tDid();

    assert.ok(Math.abs(pMed - aMed) < 25,
      `the medians must not separate the two cases; ${detail}`);
    tDid();

    assert.ok(pMin < aMax && aMin < pMax,
      `the two ranges must overlap, or one request still classifies an address; ${detail}`);
    tDid();
  }

  // The floor is only a floor while it is above the work. If argon2 on this
  // machine ever costs more than the floor allows, the admin says so, and the
  // suite would rather fail on that than on a timing gap nobody can explain.
  assert.doesNotMatch(bkSrv.log() || '', /answer overran its floor/,
    'no answer may overrun its floor: raise PARAMANT_LOGIN_BACKUP_MIN_ANSWER_MS');
  tDid();
});

test('the answers that are not credential answers are not held back', async (t) => {
  if (!ready()) return t.skip('no redis');
  // A 429 is told apart from a 401 by its status code, so padding it buys
  // nothing and only punishes a caller who is already refused. The same for the
  // 428 that asks for a proof-of-work: the login page is waiting on it to start
  // hashing.
  const ip = tIp();
  await setFailures(TIMING_ABSENT_EMAIL, 0, null);
  for (let i = 0; i < 5; i++) await tSrv.login({ email: TIMING_ABSENT_EMAIL, totp: '000000', ip });
  const refused = await tSrv.login({ email: TIMING_ABSENT_EMAIL, totp: '000000', ip });
  assert.equal(refused.status, 429, `the sixth attempt from one IP is refused, got ${refused.status}`);
  assert.ok(refused.ms < TIMING_FLOOR_MS,
    `a 429 must not be held to the credential floor, took ${refused.ms.toFixed(2)}ms`);
  tDid();
});
