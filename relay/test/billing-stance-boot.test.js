'use strict';
// The boot line that says which stance billing is in. The brake in
// mollie.billingStance() is only useful if an operator can see, in the first
// seconds of a container's log, whether the relay will bill one-off or open
// subscriptions. So the line itself is pinned here, on a real relay.js, in the
// three stances: BILLING_MODE empty with a live key (production on 2026-09-02),
// BILLING_MODE=test, BILLING_MODE=live. Never the key: only its prefix.
//
// Boots relay.js with stdout captured, four times: the three stances plus an
// explicit mode without its key, which must boot red. Needs the installed relay
// dependencies (relay.js requires redis at load), so this runs in the crypto
// job next to deep-health-gate, not in the no-install unit job.
// Run: node relay/test/billing-stance-boot.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const {
  BOOT_TIMEOUT_MS, freeRelayPort, killSpawnedRelays, spawnRelay,
} = require('./_boot-relay');

after(killSpawnedRelays);

// Boot until the billing_config line appears (it is logged right after
// relay_started), then return it parsed. Fails loudly if it never comes, and
// the message now carries the exit state and both output tails: a boot that
// died on a port someone else had taken used to look exactly like a boot that
// was merely slow.
//
// The port comes from the OS. It used to be 34900 + (pid % 400) + a counter,
// which is the same window deep-health-gate picked from, and test.yml runs the
// two suites as parallel processes out of a single `node --test`.
async function bootForBillingLine(extraEnv) {
  const port = await freeRelayPort();
  return new Promise((resolve, reject) => {
    let settled = false;
    // Whichever of the three outcomes lands first wins; the other two are the
    // consequences of it (killing the child fires 'exit', for one).
    const once = (fn) => (...args) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(...args);
    };
    const done = once((line) => { relay.kill(); resolve(line); });
    const fail = once((what) => {
      reject(new Error(`${what} on port ${relay.port}\n${relay.output()}`));
    });
    // spawnRelay hands over complete stdout lines. The relay logs one JSON
    // object per line, so nothing has to be reassembled here.
    const relay = spawnRelay(port, extraEnv, {
      unset: ['BILLING_MODE', 'MOLLIE_API_KEY', 'MOLLIE_TEST_API_KEY'],
      onLine: (line) => {
        if (settled || !line.includes('"billing_config"')) return;
        let j = null;
        try { j = JSON.parse(line); } catch (_) { return; }
        if (j && j.msg === 'billing_config') done(j);
      },
    });
    relay.child.on('exit', (code, signal) => {
      fail(`relay exited (code=${code} signal=${signal}) before logging billing_config`);
    });
    const timer = setTimeout(
      () => fail(`no billing_config line within ${BOOT_TIMEOUT_MS}ms`),
      BOOT_TIMEOUT_MS);
  });
}

test('stance 1: BILLING_MODE empty with a live key boots one-off only, and says so at warn', async () => {
  const j = await bootForBillingLine({ MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'warn', 'an inferred stance is legitimate but undecided, so it warns');
  assert.strictEqual(j.mode, 'live');
  assert.strictEqual(j.mode_source, 'inferred');
  assert.strictEqual(j.recurring, false);
  assert.strictEqual(j.key_present, true);
  assert.strictEqual(j.key_prefix, 'live_');
  assert.match(j.stance, /^live: one-off payments only/);
  assert.match(j.stance, /BILLING_MODE not set/);
  assert.ok(!JSON.stringify(j).includes('bootcheck'), 'the key itself must never reach the log');
});

test('stance 2: BILLING_MODE=test boots the recurring layer against the test key', async () => {
  const j = await bootForBillingLine({ BILLING_MODE: 'test', MOLLIE_TEST_API_KEY: 'test_bootcheck_0123456789', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'info');
  assert.strictEqual(j.mode, 'test');
  assert.strictEqual(j.mode_source, 'explicit');
  assert.strictEqual(j.recurring, true);
  assert.strictEqual(j.key_present, true);
  assert.strictEqual(j.key_prefix, 'test_', 'a test stance must pick the test key even when a live key is present');
  assert.match(j.stance, /^test: one-off payments plus customers, mandates and subscriptions \(BILLING_MODE=test\)/);
});

test('stance 3: BILLING_MODE=live boots the recurring layer against the live key', async () => {
  const j = await bootForBillingLine({ BILLING_MODE: 'live', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'info');
  assert.strictEqual(j.mode, 'live');
  assert.strictEqual(j.mode_source, 'explicit');
  assert.strictEqual(j.recurring, true);
  assert.strictEqual(j.key_prefix, 'live_');
  assert.match(j.stance, /BILLING_MODE=live\)$/);
});

test('an explicit stance without its key boots red: nothing can bill, and the log says so first', async () => {
  const j = await bootForBillingLine({ BILLING_MODE: 'test', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'error');
  assert.strictEqual(j.mode, 'test');
  assert.strictEqual(j.key_present, false);
  assert.strictEqual(j.key_prefix, null);
});
