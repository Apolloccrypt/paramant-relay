// The relay's gossip pins (relay/lib/fleet-pins.js) and the browser's trust
// anchors (frontend/js/relay-trust-anchors.js) name the same five keys.
//
// The relay image does not ship frontend/, so the fingerprints live in two
// files. If a relay rotates its key and only one file is updated, either
// /verify calls genuine receipts forged, or /v2/sth/ingest refuses the real
// relay's heads and keeps mirroring nothing. This suite makes the two move
// together, and checks every fingerprint against the key it claims to hash.
// Run: node --test tests/fleet-pins-match-anchors.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { RELAY_TRUST_ANCHORS } from '../frontend/js/relay-trust-anchors.js';

const require = createRequire(import.meta.url);
const { PARAMANT_FLEET } = require('../relay/lib/fleet-pins.js');

test('every trust anchor is pinned on the relay with the same fingerprint, and nothing else is', () => {
  const fromAnchors = Object.fromEntries(RELAY_TRUST_ANCHORS.map((a) => [a.host, a.fingerprint]));
  assert.deepEqual({ ...PARAMANT_FLEET }, fromAnchors);
});

test('each pinned fingerprint is SHA3-256 of the anchored public key', () => {
  for (const a of RELAY_TRUST_ANCHORS) {
    const fp = createHash('sha3-256').update(Buffer.from(a.key, 'base64')).digest('hex');
    assert.equal(PARAMANT_FLEET[a.host], fp, `${a.host}: pin is not the hash of its key`);
  }
});
