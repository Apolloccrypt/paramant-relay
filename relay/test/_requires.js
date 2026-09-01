'use strict';
// Preconditions for relay tests that need something a bare checkout does not
// have: the native ML-DSA-65 binding (@paramant/core), or a reachable Redis.
//
// WHY THIS FILE EXISTS. Six suites used to swallow the load error, print
// "  skip - ...", and return. Under `node --test` a file that exits 0 is a PASS,
// so the relay unit job (which installs nothing, on purpose) reported "ok 24"
// while five of those suites had run ZERO checks. The one that hurt is
// parasign-sandbox-live-guard.test.js: it is the only thing standing between a
// psk_live_ key and the sandbox auto-signer, and for as long as that job ran
// without @paramant/core it asserted nothing at all. A green tick over nothing
// is worse than a red one, because red gets looked at.
//
// THE RULE NOW: a precondition the test cannot meet is a HARD FAILURE, unless
// the runner names it as deliberately absent:
//
//   RELAY_TEST_SKIP=engine,redis   node --test test/foo.test.js
//
// That moves the decision out of the test and into .github/workflows/test.yml,
// where a reviewer can see which job gave up on what. It also means the fix for
// a skip is to give the job the dependency: nothing else has to change here.

const firstLine = (e) => String((e && e.message) || e).split('\n')[0];

// Named preconditions the runner declared this environment does not provide.
function mayskip(name) {
  return String(process.env.RELAY_TEST_SKIP || '')
    .split(',').map((s) => s.trim()).filter(Boolean).includes(name);
}

// A precondition could not be met. Either the runner said so up front (skip,
// loudly and by name), or this is a real failure and the test goes red.
function unmet(name, reason) {
  if (mayskip(name)) {
    console.log(`  SKIP [${name}] - ${reason} (declared via RELAY_TEST_SKIP)`);
    return null;
  }
  throw new Error(
    `unmet precondition "${name}": ${reason}\n` +
    `  This suite cannot set up its own conditions, so it fails instead of\n` +
    `  reporting a pass over nothing. Give the job the dependency, or, if this\n` +
    `  environment is genuinely not meant to have it, say so on the runner:\n` +
    `    RELAY_TEST_SKIP=${name}`);
}

// The ML-DSA-65 signing engine (algorithm id 0x0002), via @paramant/core.
// Returns the engine, or null when "engine" is a declared skip.
function requireEngine() {
  let reason;
  try {
    require('../crypto/bootstrap').bootstrap();
    const eng = require('../crypto/registry').getSig(0x0002);
    if (eng && typeof eng.generateKeyPair === 'function') return eng;
    reason = 'crypto registry has no usable ML-DSA-65 engine at 0x0002';
  } catch (e) {
    // Almost always "Cannot find module '@paramant/core'", i.e. the job never
    // ran `npm install` (the binding is a file: link to the sibling repo).
    // First line only: node appends a multi-line "Require stack" that turns the
    // one-line SKIP/FAIL message into a wall of paths.
    reason = firstLine(e);
  }
  return unmet('engine', `ML-DSA-65 engine unavailable: ${reason}`);
}

// A connected redis client at REDIS_URL (or the caller's default port), or null
// when "redis" is a declared skip. Callers must disconnect what they get.
async function requireRedis(defaultUrl) {
  const url = process.env.REDIS_URL || defaultUrl;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) { return unmet('redis', `the "redis" module is not installed: ${firstLine(e)}`); }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try {
    await rc.connect();
    await rc.ping();
    return rc;
  } catch (e) {
    try { await rc.disconnect(); } catch (_) {}
    return unmet('redis', `no reachable redis at ${url}: ${firstLine(e)}`);
  }
}

// Closing line of a suite. A run that asserted nothing says SKIPPED, not
// "0 checks passed": that phrase is exactly what made the CI log look fine.
function summary(name, passed) {
  console.log(passed > 0
    ? `\n${name}: ${passed} checks passed`
    : `\n${name}: SKIPPED - 0 checks ran`);
}

module.exports = { mayskip, unmet, requireEngine, requireRedis, summary };
