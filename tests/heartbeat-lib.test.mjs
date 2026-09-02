// The heartbeat's own machinery, pinned.
//
// scripts/heartbeat/ is the thing that watches production, and until this file
// existed nothing watched it. That is not a theoretical gap: while the
// directory was being written, the ML-DSA-65 argument order was wrong and the
// entire suite stayed green, because the only thing exercising it was the
// hourly job that needs secrets nobody has set. The same class of mistake in
// the canary it replaced (verify(publicKey, message, signature) against a
// library that takes verify(signature, message, publicKey)) sat there unnoticed
// for as long as the canary was skipping.
//
// So the load-bearing invariants get a suite that runs on every push:
//
//   1. the ML-DSA-65 argument order round-trips, and a WRONG order is proven to
//      fail rather than assumed to
//   2. the recipe-v4 sign message is stable and actually mixes in the signer's
//      public key, which is the whole reason open-mode slots are signer-bound
//   3. runStep fails a step that recorded no proof, which is the mechanism the
//      whole rewrite rests on
//   4. a dry run can never report itself as green
//
// It needs @noble/post-quantum, so it runs in the job that installs the root
// dependencies. That is deliberate: making it skip when the package is absent
// would reintroduce the exact bug it exists to catch.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { signMessageBytes } = require('../relay/envelope.js');
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

// Every import of the heartbeat lib writes into this, so the suite never
// touches a real evidence directory.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'heartbeat-test-'));
process.env.HEARTBEAT_EVIDENCE_DIR = TMP;

const lib = await import('../scripts/heartbeat/lib.mjs');
const { assertMlDsaWrapper, _mldsa } = await import('../scripts/heartbeat/parasign.mjs');

test.after(() => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* temp dir */ } });

// ── 1. the argument order ───────────────────────────────────────────────────

test('ML-DSA-65 round-trips with the order the heartbeat uses', () => {
  const kp = ml_dsa65.keygen(crypto.randomBytes(32));
  const msg = Buffer.from('paramant heartbeat argument-order pin');
  // The installed library's order, stated here so a major bump that changes it
  // fails this line with a name attached instead of somewhere in an hourly log.
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  assert.equal(sig.length, 3309, 'ML-DSA-65 signatures are 3309 bytes');
  assert.equal(kp.publicKey.length, 1952, 'ML-DSA-65 public keys are 1952 bytes');
  assert.ok(ml_dsa65.verify(sig, msg, kp.publicKey), 'verify(signature, message, publicKey) must hold');
});

test('the wrapper in parasign.mjs uses that order, and says so out loud', () => {
  assert.equal(assertMlDsaWrapper(), true);

  const kp = _mldsa.keygen(crypto.randomBytes(32));
  const msg = Buffer.from('paramant heartbeat wrapper pin');
  const sig = _mldsa.sign(kp.secretKey, msg);
  assert.ok(_mldsa.verify(kp.publicKey, msg, sig));
});

// The negative that makes the positive worth having. The old canary called
// verify(publicKey, message, signature); this proves that does not quietly
// return false but throws, which is why nobody could have mistaken it for a
// failing assertion had it ever run.
test('the order the old canary used throws rather than returning false', () => {
  const kp = ml_dsa65.keygen(crypto.randomBytes(32));
  const msg = Buffer.from('paramant heartbeat wrong-order pin');
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  assert.throws(
    () => ml_dsa65.verify(kp.publicKey, msg, sig),
    /expected Uint8Array of length/,
    'if this ever stops throwing, a swapped argument order becomes silent again',
  );
});

test('a signature over a different message does not verify', () => {
  const kp = ml_dsa65.keygen(crypto.randomBytes(32));
  const sig = ml_dsa65.sign(Buffer.from('one message'), kp.secretKey);
  assert.equal(ml_dsa65.verify(sig, Buffer.from('another message'), kp.publicKey), false);
});

// ── 2. the sign message the public route accepts ────────────────────────────

test('recipe v4 binds the signature to the signer public key', () => {
  const id = 'abcdefghijklmnopqrstuvwx';
  const doc = 'ab'.repeat(32);
  const pkA = Buffer.from(crypto.randomBytes(1952)).toString('base64');
  const pkB = Buffer.from(crypto.randomBytes(1952)).toString('base64');

  const a = signMessageBytes(id, doc, 0, '', 4, pkA, '');
  const again = signMessageBytes(id, doc, 0, '', 4, pkA, '');
  assert.deepEqual(a, again, 'the same inputs must give the same message');

  // The point of v4 over v1: without this, any caller who knew an open
  // envelope's id could fill any slot with a substituted key.
  const b = signMessageBytes(id, doc, 0, '', 4, pkB, '');
  assert.notDeepEqual(a, b, 'v4 must mix in the signer public key');

  const v1 = signMessageBytes(id, doc, 0, '', 1, pkA, '');
  assert.notDeepEqual(a, v1, 'v4 must differ from v1, or the domain separator is not applied');
  assert.equal(a.length, 32, 'the sign message is a sha3-256 digest');

  // Party index and document hash both have to matter, or a signature for one
  // slot would be replayable into another.
  assert.notDeepEqual(a, signMessageBytes(id, doc, 1, '', 4, pkA, ''), 'party index must bind');
  assert.notDeepEqual(a, signMessageBytes(id, 'cd'.repeat(32), 0, '', 4, pkA, ''), 'document hash must bind');
});

test('a real signature over a v4 message verifies, end to end', () => {
  const kp = ml_dsa65.keygen(crypto.randomBytes(32));
  const pub = Buffer.from(kp.publicKey).toString('base64');
  const msg = signMessageBytes('abcdefghijklmnopqrstuvwx', 'ab'.repeat(32), 0, '', 4, pub, '');
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  assert.ok(ml_dsa65.verify(sig, msg, kp.publicKey));
});

// ── 3. no green without evidence ────────────────────────────────────────────

test('runStep fails a step that recorded no proof, even when nothing threw', async () => {
  const r = await lib.runStep('records-nothing', async () => { /* the whole bug, in one line */ });
  assert.equal(r.ok, false, 'a step that observed nothing must not pass');
  assert.match(r.cause, /produced no proofs/);

  const written = JSON.parse(fs.readFileSync(path.join(TMP, 'records-nothing.json'), 'utf8'));
  assert.equal(written.ok, false, 'the evidence file must record the failure too');
  assert.equal(written.proofs.length, 0);
});

test('runStep passes a step that recorded one, and writes the evidence', async () => {
  const r = await lib.runStep('records-something', async (evidence) => {
    lib.proof(evidence, 'something observed', { observed: 42 });
  });
  assert.equal(r.ok, true);
  assert.equal(r.proofs, 1);

  const written = JSON.parse(fs.readFileSync(path.join(TMP, 'records-something.json'), 'utf8'));
  assert.equal(written.ok, true);
  assert.equal(written.proofs[0].name, 'something observed');
  assert.equal(written.proofs[0].observed, 42);
  assert.ok(written.started_at && written.finished_at, 'evidence must be timestamped');
});

test('runStep catches a throw and names the cause instead of escaping', async () => {
  const r = await lib.runStep('throws', async () => {
    throw new lib.HeartbeatError('the short cause', 'the long explanation');
  });
  assert.equal(r.ok, false);
  assert.equal(r.cause, 'the short cause', 'the summary line takes the short form');
  assert.equal(JSON.parse(fs.readFileSync(path.join(TMP, 'throws.json'), 'utf8')).cause, 'the short cause');
});

// ── 4. a missing secret is red, never a skip ────────────────────────────────

test('requireSecret fails by name rather than skipping', () => {
  delete process.env.HEARTBEAT_TEST_SECRET;
  assert.throws(
    () => lib.requireSecret('HEARTBEAT_TEST_SECRET', 'some shape'),
    (e) => e.cause_short === 'secret HEARTBEAT_TEST_SECRET is not set'
      && /gh secret set HEARTBEAT_TEST_SECRET/.test(e.message)
      && /some shape/.test(e.message),
    'the whole rewrite rests on this being a failure that names the secret',
  );

  // Whitespace is not a secret either: a variable set to "" or " " in a
  // workflow is exactly what a missing repository secret expands to.
  process.env.HEARTBEAT_TEST_SECRET = '   ';
  assert.throws(() => lib.requireSecret('HEARTBEAT_TEST_SECRET'), /is not set/,
    'an unset repository secret expands to an empty string, which must not count as set');

  process.env.HEARTBEAT_TEST_SECRET = ' real-value ';
  assert.equal(lib.requireSecret('HEARTBEAT_TEST_SECRET'), 'real-value');
  delete process.env.HEARTBEAT_TEST_SECRET;
});

// ── 5. a dry run is never green ─────────────────────────────────────────────

test('a dry run exits non-zero and does not report itself as green', async () => {
  const { spawnSync } = await import('node:child_process');
  const root = path.join(import.meta.dirname, '..');
  const out = path.join(TMP, 'dry');
  const r = spawnSync(process.execPath, ['scripts/heartbeat/run.mjs'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      HEARTBEAT_DRY_RUN: '1',
      HEARTBEAT_EVIDENCE_DIR: out,
      PARAMANT_CANARY_KEY: 'pgp_dry_run_placeholder',
      PARASIGN_CANARY_KEY: 'psk_test_dry_run_placeholder',
    },
  });
  assert.notEqual(r.status, 0,
    'a dry run contacts nothing, so it must never exit 0 and be read as a green production run');

  const summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8'));
  assert.equal(summary.ok, false, 'summary.ok must be false for a run that proved nothing');
  assert.equal(summary.dry_run, true);
  assert.equal(summary.steps_ok, true, 'the wiring itself must still be reported as sound');
  assert.match(summary.line, /DRY RUN/);
  assert.doesNotMatch(summary.line, /^Heartbeat green/);
  for (const step of summary.steps) {
    assert.equal(JSON.parse(fs.readFileSync(path.join(out, `${step.name}.json`), 'utf8')).dry_run, true,
      `${step.name} evidence must be marked as a dry run`);
  }
});
