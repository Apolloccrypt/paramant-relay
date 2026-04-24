import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import crypto from 'node:crypto';

import {
  wireEncode, wireDecode, buildAAD, isV1, KEM, SIG,
  fetchCapabilities,
} from '../index.js';

const LIVE_RELAY = process.env.PARAMANT_TEST_RELAY || 'https://paramant.app';

async function liveReachable() {
  try {
    const res = await fetch(LIVE_RELAY + '/v2/capabilities', { signal: AbortSignal.timeout(4000) });
    return res.ok;
  } catch { return false; }
}

test('live: /v2/capabilities advertises ML-KEM-768 + ML-DSA-65', async (t) => {
  if (!(await liveReachable())) return t.skip('live relay unreachable');
  const caps = await fetchCapabilities(LIVE_RELAY, { timeout: 8000 });
  assert.equal(caps.wire_version, 1);
  const loadedKem = caps.kem.filter(k => k.loaded).map(k => k.id);
  const loadedSig = caps.sig.filter(s => s.loaded).map(s => s.id);
  assert.ok(loadedKem.includes(2));
  assert.ok(loadedSig.includes(0));
  assert.ok(loadedSig.includes(2));
});

test('live: POST /v2/anon-inbound with a valid v1 blob returns 200', async (t) => {
  if (!(await liveReachable())) return t.skip('live relay unreachable');

  // Build a valid v1 anon blob (sigId=0x0000). We use a fresh ML-KEM-768 pair
  // for "recipient" (the recipient's real pubkey isn't on file, but the
  // relay's anon-inbound accepts any v1 blob — it just stores bytes).
  const { publicKey } = ml_kem768.keygen();
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

  // Derive AES key.
  const salt = cipherText.slice(0, 32);
  const baseKey = await crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('paramant-v1-aes-key') },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = buildAAD({ kemId: KEM.ML_KEM_768, sigId: SIG.NONE });
  const plaintext = new TextEncoder().encode('sdk-js integration probe');
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext
  ));

  const blob = wireEncode({
    kemId: KEM.ML_KEM_768,
    sigId: SIG.NONE,
    ctKem: cipherText,
    senderPub: publicKey,
    nonce, ciphertext: ct,
  });

  assert.equal(isV1(blob), true);
  const parsed = wireDecode(blob);
  assert.equal(parsed.kemId, KEM.ML_KEM_768);
  assert.equal(parsed.sigId, SIG.NONE);

  const hash = crypto.createHash('sha256').update(blob).digest('hex');
  const b64 = Buffer.from(blob).toString('base64');

  const res = await fetch(LIVE_RELAY + '/v2/anon-inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'paramant-sdk-js-test/3.0.0' },
    body: JSON.stringify({ hash, payload: b64, ttl_ms: 60000, max_views: 1 }),
    signal: AbortSignal.timeout(15000),
  });
  // Accept: 200 (ok), 202 (accepted), 401/403 (anon gated by some deployments).
  assert.ok([200, 202, 401, 403].includes(res.status), `unexpected status ${res.status}`);
  if (res.status === 200) {
    const body = await res.json();
    assert.ok(body.ok === true || typeof body.hash === 'string');
  }
});

test('live: POST /v2/anon-inbound with unsupported kemId returns 415', async (t) => {
  if (!(await liveReachable())) return t.skip('live relay unreachable');
  // Build a structurally valid blob but with an unknown kemId (0x9999 — private range).
  const blob = wireEncode({
    kemId: 0x9999,
    sigId: 0x0000,
    ctKem: crypto.randomBytes(1088),
    senderPub: crypto.randomBytes(1184),
    nonce: crypto.randomBytes(12),
    ciphertext: crypto.randomBytes(64),
  });
  const hash = crypto.createHash('sha256').update(blob).digest('hex');
  const b64 = Buffer.from(blob).toString('base64');

  const res = await fetch(LIVE_RELAY + '/v2/anon-inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'paramant-sdk-js-test/3.0.0' },
    body: JSON.stringify({ hash, payload: b64, ttl_ms: 60000, max_views: 1 }),
    signal: AbortSignal.timeout(15000),
  });
  // 415 = unsupported algorithm per wire-format-v1 spec; allow 400/422 as other reject codes.
  assert.ok([400, 415, 422].includes(res.status), `expected 4xx reject, got ${res.status}`);
});
