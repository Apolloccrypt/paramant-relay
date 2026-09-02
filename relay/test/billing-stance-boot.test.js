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
const { spawn } = require('child_process');
const path = require('path');

const RELAY_DIR = path.join(__dirname, '..');
const children = [];
after(() => { for (const c of children) c.kill('SIGKILL'); });

// Boot until the billing_config line appears (it is logged right after
// relay_started), then return it parsed. Fails loudly if it never comes.
function bootForBillingLine(port, extraEnv) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, PORT: String(port), USERS_JSON: '{"api_keys":[]}', RELAY_REDIS_URL: '', NATS_URL: '' };
    for (const k of ['BILLING_MODE', 'MOLLIE_API_KEY', 'MOLLIE_TEST_API_KEY']) delete env[k];
    Object.assign(env, extraEnv);
    const child = spawn('node', ['relay.js'], { cwd: RELAY_DIR, env, stdio: ['ignore', 'pipe', 'ignore'] });
    children.push(child);
    let buf = '';
    const timer = setTimeout(() => reject(new Error(`no billing_config line within 15s; stdout so far:\n${buf.slice(-2000)}`)), 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      for (const line of buf.split('\n')) {
        if (!line.includes('"billing_config"')) continue;
        let j = null;
        try { j = JSON.parse(line); } catch (_) { continue; }
        if (j && j.msg === 'billing_config') { clearTimeout(timer); child.kill('SIGKILL'); return resolve(j); }
      }
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`relay exited (${code}) before logging billing_config:\n${buf.slice(-2000)}`)); });
  });
}

const port = () => 34900 + (process.pid % 400) + children.length;

test('stance 1: BILLING_MODE empty with a live key boots one-off only, and says so at warn', async () => {
  const j = await bootForBillingLine(port(), { MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
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
  const j = await bootForBillingLine(port(), { BILLING_MODE: 'test', MOLLIE_TEST_API_KEY: 'test_bootcheck_0123456789', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'info');
  assert.strictEqual(j.mode, 'test');
  assert.strictEqual(j.mode_source, 'explicit');
  assert.strictEqual(j.recurring, true);
  assert.strictEqual(j.key_present, true);
  assert.strictEqual(j.key_prefix, 'test_', 'a test stance must pick the test key even when a live key is present');
  assert.match(j.stance, /^test: one-off payments plus customers, mandates and subscriptions \(BILLING_MODE=test\)/);
});

test('stance 3: BILLING_MODE=live boots the recurring layer against the live key', async () => {
  const j = await bootForBillingLine(port(), { BILLING_MODE: 'live', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'info');
  assert.strictEqual(j.mode, 'live');
  assert.strictEqual(j.mode_source, 'explicit');
  assert.strictEqual(j.recurring, true);
  assert.strictEqual(j.key_prefix, 'live_');
  assert.match(j.stance, /BILLING_MODE=live\)$/);
});

test('an explicit stance without its key boots red: nothing can bill, and the log says so first', async () => {
  const j = await bootForBillingLine(port(), { BILLING_MODE: 'test', MOLLIE_API_KEY: 'live_bootcheck_0123456789' });
  assert.strictEqual(j.level, 'error');
  assert.strictEqual(j.mode, 'test');
  assert.strictEqual(j.key_present, false);
  assert.strictEqual(j.key_prefix, null);
});
