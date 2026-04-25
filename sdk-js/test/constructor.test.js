import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GhostPipe, GhostPipeError } from '../index.js';

const VALID = { apiKey: 'pgp_x', device: 'd1', relay: 'http://x', checkCapabilities: false };

test('constructor: valid options succeed', () => {
  const gp = new GhostPipe(VALID);
  assert.equal(gp.relay, 'http://x');
  assert.equal(gp.device, 'd1');
});

test('constructor: empty options object succeeds (auto-detect path)', () => {
  const gp = new GhostPipe({});
  assert.equal(gp.relay, '');
});

test('constructor: typo "relayUrl" suggests "relay"', () => {
  assert.throws(
    () => new GhostPipe({ relayUrl: 'http://x', device: 'd' }),
    err => err instanceof GhostPipeError &&
           /unknown constructor option/.test(err.message) &&
           /"relayUrl" — did you mean "relay"/.test(err.message)
  );
});

test('constructor: typo "URL" suggests "relay"', () => {
  assert.throws(
    () => new GhostPipe({ URL: 'http://x', device: 'd' }),
    err => err instanceof GhostPipeError &&
           /"URL" — did you mean "relay"/.test(err.message)
  );
});

test('constructor: typo "endpoint" suggests "relay"', () => {
  assert.throws(
    () => new GhostPipe({ endpoint: 'http://x' }),
    err => /"endpoint" — did you mean "relay"/.test(err.message)
  );
});

test('constructor: typo "apikey" suggests "apiKey"', () => {
  assert.throws(
    () => new GhostPipe({ apikey: 'pgp_x', device: 'd' }),
    err => /"apikey" — did you mean "apiKey"/.test(err.message)
  );
});

test('constructor: unknown option without typo hint lists valid options', () => {
  assert.throws(
    () => new GhostPipe({ chairs: 4 }),
    err => err instanceof GhostPipeError &&
           /"chairs"/.test(err.message) &&
           /Valid options:.*relay/.test(err.message)
  );
});

test('constructor: non-object argument throws helpful error', () => {
  assert.throws(
    () => new GhostPipe('http://x'),
    err => err instanceof GhostPipeError &&
           /expects an options object, got string/.test(err.message)
  );
  assert.throws(
    () => new GhostPipe([]),
    err => err instanceof GhostPipeError &&
           /expects an options object, got array/.test(err.message)
  );
  assert.throws(
    () => new GhostPipe(null),
    err => err instanceof GhostPipeError &&
           /expects an options object, got object/.test(err.message)
  );
});
