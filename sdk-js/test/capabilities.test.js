import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  fetchCapabilities, assertSupported,
  UnsupportedAlgorithmError, UnsupportedWireVersionError,
} from '../src/capabilities.js';

function mockFetch(jsonBody, { ok = true, status = 200 } = {}) {
  return async () => ({
    ok, status,
    async json() { return jsonBody; },
  });
}

test('fetchCapabilities parses a well-formed response', async () => {
  const body = {
    wire_version: 1,
    kem: [{ id: 2, name: 'ML-KEM-768', loaded: true }],
    sig: [{ id: 0, name: 'none', loaded: true }, { id: 2, name: 'ML-DSA-65', loaded: true }],
  };
  const caps = await fetchCapabilities('http://relay', { fetch: mockFetch(body) });
  assert.deepEqual(caps, body);
});

test('fetchCapabilities rejects missing wire_version', async () => {
  await assert.rejects(
    fetchCapabilities('http://relay', { fetch: mockFetch({ kem: [], sig: [] }) }),
    /missing wire_version/
  );
});

test('fetchCapabilities rejects non-2xx', async () => {
  await assert.rejects(
    fetchCapabilities('http://relay', { fetch: mockFetch({}, { ok: false, status: 500 }) }),
    /capabilities fetch failed: HTTP 500/
  );
});

test('assertSupported passes when all IDs loaded', () => {
  const caps = {
    wire_version: 1,
    kem: [{ id: 2, loaded: true }],
    sig: [{ id: 0, loaded: true }, { id: 2, loaded: true }],
  };
  assertSupported(caps, { kemId: 2, sigId: 2 });
  assertSupported(caps, { kemId: 2, sigId: 0 });
});

test('assertSupported throws on wire_version mismatch', () => {
  assert.throws(
    () => assertSupported({ wire_version: 2, kem: [], sig: [] }, { kemId: 2, sigId: 2 }),
    UnsupportedWireVersionError
  );
});

test('assertSupported throws on unloaded kemId', () => {
  const caps = { wire_version: 1, kem: [{ id: 2, loaded: false }], sig: [{ id: 2, loaded: true }] };
  assert.throws(() => assertSupported(caps, { kemId: 2, sigId: 2 }), UnsupportedAlgorithmError);
});

test('assertSupported throws on missing sigId', () => {
  const caps = { wire_version: 1, kem: [{ id: 2, loaded: true }], sig: [{ id: 0, loaded: true }] };
  assert.throws(() => assertSupported(caps, { kemId: 2, sigId: 2 }), UnsupportedAlgorithmError);
});

// Live integration tests — skipped if paramant.app unreachable.

const LIVE_RELAY = process.env.PARAMANT_TEST_RELAY || 'https://paramant.app';

test('live: fetch /v2/capabilities from paramant.app', async () => {
  let caps;
  try {
    caps = await fetchCapabilities(LIVE_RELAY, { timeout: 8000 });
  } catch (e) {
    // Network failure — treat as skip rather than fail.
    console.warn(`skipping live capabilities test: ${e.message}`);
    return;
  }
  assert.equal(caps.wire_version, 1);
  const kemIds = caps.kem.filter(k => k.loaded).map(k => k.id);
  const sigIds = caps.sig.filter(s => s.loaded).map(s => s.id);
  assert.ok(kemIds.includes(2), `relay advertises ML-KEM-768 (got kem IDs: ${kemIds.join(',')})`);
  assert.ok(sigIds.includes(0), `relay advertises anonymous (got sig IDs: ${sigIds.join(',')})`);
  assert.ok(sigIds.includes(2), `relay advertises ML-DSA-65`);
});
