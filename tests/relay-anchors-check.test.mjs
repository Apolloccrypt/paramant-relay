// The relay trust anchors and the deploy check that holds production to them.
//
// Hertest 2026-10-04 (deel 3): RETIRED_RELAY_ANCHORS was empty and nothing
// noticed a relay that signs with a key /verify does not pin, so a key
// rotation would quietly turn every new multi-party proof red. The live
// comparison needs the network and runs in the deploy (deploy-3.1.sh phase 6,
// also under --verify-only). What CI can check without a network is here: the
// pin file is consistent with itself, and the judgement the deploy makes is
// right for a pinned key, a rotated key, and a key that was retired.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkFile, judge, fingerprintOf } from '../deploy/check-relay-anchors.mjs';
import { RELAY_TRUST_ANCHORS, RETIRED_RELAY_ANCHORS } from '../frontend/js/relay-trust-anchors.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

test('the pin file is consistent: every fingerprint is the SHA3-256 of its own key', () => {
  assert.deepEqual(checkFile({ anchors: RELAY_TRUST_ANCHORS, retired: RETIRED_RELAY_ANCHORS }), []);
});

const keyA = Buffer.alloc(1952, 1).toString('base64');
const keyB = Buffer.alloc(1952, 2).toString('base64');
const pin = (host, key) => ({ host, key, fingerprint: fingerprintOf(key) });

test('the deploy check: pinned passes, a rotated key fails, a served retired key fails', () => {
  const anchors = [pin('health.example', keyA)];
  assert.equal(judge({ anchors, retired: [], live: [{ host: 'health.example', public_key: keyA }] })[0].state, 'pinned');
  assert.equal(judge({ anchors, retired: [], live: [{ host: 'health.example', public_key: keyB }] })[0].state, 'unpinned',
    'a relay that rotated without a new pin must stop the deploy');
  const after = [pin('health.example', keyB)];
  const retired = [{ ...pin('health.example', keyA), retired_at: '2026-10-04' }];
  assert.equal(judge({ anchors: after, retired, live: [{ host: 'health.example', public_key: keyB }] })[0].state, 'pinned',
    'after the procedure: new key pinned, old key retired');
  assert.equal(judge({ anchors: after, retired, live: [{ host: 'health.example', public_key: keyA }] })[0].state, 'serving-retired');
  assert.equal(judge({ anchors, retired: [], live: [{ host: 'health.example', error: 'timeout' }] })[0].state, 'unreachable',
    'an unreachable host is not proven, never green');
});

test('a retired entry needs retired_at, its own fingerprint, and must not still be pinned', () => {
  const anchors = [pin('h', keyB)];
  assert.match(checkFile({ anchors, retired: [pin('h', keyA)] }).join('\n'), /retired_at/);
  assert.match(checkFile({ anchors, retired: [{ ...pin('h', keyB), retired_at: '2026-10-04' }] }).join('\n'), /still pinned/);
  assert.match(checkFile({ anchors: [{ host: 'h', key: keyA, fingerprint: 'ab'.repeat(32) }], retired: [] }).join('\n'), /not the SHA3-256/);
});

test('the deploy runs the check in phase 6, which --verify-only runs too', () => {
  const sh = fs.readFileSync(path.join(ROOT, 'deploy/deploy-3.1.sh'), 'utf8');
  const p6 = sh.slice(sh.indexOf('phase_6() {'), sh.indexOf('\n}\n', sh.indexOf('phase_6() {')));
  assert.match(p6, /node deploy\/check-relay-anchors\.mjs/, 'phase 6 must compare the live relay keys with the pins');
  const vo = sh.slice(sh.indexOf('if [ "$VERIFY_ONLY" -eq 1 ]; then\n  phase_v'));
  assert.match(vo, /phase_6/, '--verify-only runs phase 6');
  const rb = fs.readFileSync(path.join(ROOT, 'RUNBOOK.md'), 'utf8');
  assert.match(rb, /Relay identity key rotation/);
  assert.match(rb, /RETIRED_RELAY_ANCHORS/);
});
