'use strict';
// /v2/health/deep across relay modes. The handler aggregates version, loaded
// key count, free disk and cert age. In `full` mode that is deliberately
// public (the setup wizard and /all-systems-go read it); in `ghost_pipe` and
// `iot` the same payload is an information leak, and before this gate existed
// the mode allowlist simply dropped the route ("Not available in this relay
// mode") — so production had NO deep readiness check at all, which is what the
// 2026-09-01 audit found. The fix: the route is mode-allowed everywhere, but
// outside `full` it sits behind the X-Internal-Auth header that already gates
// the user endpoints. Missing token config keeps it closed.
//
// Boots relay.js three times (ghost_pipe+token, ghost_pipe without token,
// full) and asserts: authed internal read works in production mode, the open
// internet gets 401 (not a silent drop, not the old "Not available" error),
// unconfigured token stays closed, and full mode stays public.
// Run: node relay/test/deep-health-gate.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const { bootHealthyRelay, killSpawnedRelays } = require('./_boot-relay');

const TOKEN = 'deephealth-test-token';

async function deep(port, headers) {
  const r = await fetch(`http://127.0.0.1:${port}/v2/health/deep`, { headers: headers || {} });
  let j = null;
  try { j = await r.json(); } catch (_) { /* non-JSON */ }
  return { status: r.status, body: j };
}

after(killSpawnedRelays);

test('ghost_pipe: internal auth reads the deep check, the open internet gets 401', async () => {
  const { port } = await bootHealthyRelay({ RELAY_MODE: 'ghost_pipe', INTERNAL_AUTH_TOKEN: TOKEN });

  // Unauthenticated: closed, and closed the RIGHT way — a 401 from the gate,
  // not the old mode-allowlist drop that said "Not available in this relay
  // mode" and left production without any readiness signal.
  const anon = await deep(port);
  assert.strictEqual(anon.status, 401, 'unauthenticated read must be refused');
  assert.strictEqual(anon.body.error, 'unauthorized');

  // Authenticated: the full aggregated check, same shape full mode serves.
  const authed = await deep(port, { 'X-Internal-Auth': TOKEN });
  assert.strictEqual(authed.status, 200, 'internal-authed read must work in production mode');
  assert.ok(['green', 'yellow', 'red'].includes(authed.body.overall), 'overall verdict present');
  assert.ok(Array.isArray(authed.body.checks) && authed.body.checks.length > 0, 'checks array present');
  const names = authed.body.checks.map((c) => c.name);
  for (const expected of ['relay', 'crypto', 'storage', 'memory']) {
    assert.ok(names.includes(expected), `check "${expected}" present`);
  }

  // ── A check must MEASURE, not just appear ──────────────────────────────────
  // Presence was all this asserted, and presence was all it ever got. From the
  // day /v2/health/deep was written until 2026-09-05 the storage check threw
  // inside its own try and reported "not writable: path.join is not a function"
  // on every relay, healthy disk or not, because `path` was shadowed by the
  // request pathname for the whole handler. Nobody saw it, because the only
  // gate on this route counted names. So the names are still counted, and now
  // the verdicts are read too: on a booted relay with a writable working
  // directory the storage check is green, and no check may report a failure
  // whose text is a JavaScript TypeError. That second half is the general one.
  // Any check that answers with "is not a function", "undefined", "is not
  // defined" or "Cannot read" is reporting on the checker, not on the thing.
  const byName = Object.fromEntries(authed.body.checks.map((c) => [c.name, c]));
  assert.strictEqual(byName.storage.status, 'green',
    `storage must be green on a relay that can write its own working directory, got ` +
    `"${byName.storage.status}: ${byName.storage.detail}". A red here with a JavaScript ` +
    `error in the detail is the checker failing, not the disk.`);
  for (const c of authed.body.checks) {
    assert.doesNotMatch(String(c.detail || ''), /is not a function|is not defined|Cannot read|undefined is not/,
      `check "${c.name}" reports a JavaScript error as its verdict: "${c.detail}". ` +
      `A self-test that measures its own bug reports the same answer forever.`);
  }

  // A wrong token is not a lucky token.
  const wrong = await deep(port, { 'X-Internal-Auth': TOKEN + 'x' });
  assert.strictEqual(wrong.status, 401, 'wrong token must be refused');
});

test('ghost_pipe without INTERNAL_AUTH_TOKEN: stays closed, never open-by-default', async () => {
  const { port } = await bootHealthyRelay({ RELAY_MODE: 'ghost_pipe', INTERNAL_AUTH_TOKEN: '' });
  const anon = await deep(port);
  assert.strictEqual(anon.status, 401, 'missing token config must read as closed');
  // Even presenting the header cannot open a gate with no configured token.
  const tried = await deep(port, { 'X-Internal-Auth': '' });
  assert.strictEqual(tried.status, 401, 'empty token must not match empty config');
});

test('full mode: stays public for the setup wizard', async () => {
  const { port } = await bootHealthyRelay({ RELAY_MODE: 'full' });
  const anon = await deep(port);
  assert.strictEqual(anon.status, 200, 'full mode must keep the public read');
  assert.ok(Array.isArray(anon.body.checks) && anon.body.checks.length > 0);
});
