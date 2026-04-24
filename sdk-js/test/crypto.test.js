import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { GhostPipe, KEM, SIG } from '../index.js';

// Isolate keypair storage away from the real ~/.paramant.
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'paramant-sdk-test-'));
process.env.HOME = TEST_HOME;

test('ML-KEM-768 keygen + encap + decap roundtrip via @noble', () => {
  const { publicKey, secretKey } = ml_kem768.keygen();
  assert.equal(publicKey.length, 1184);
  assert.equal(secretKey.length, 2400);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  assert.equal(cipherText.length, 1088);
  assert.equal(sharedSecret.length, 32);
  const recovered = ml_kem768.decapsulate(cipherText, secretKey);
  assert.deepEqual(recovered, sharedSecret);
});

test('ML-DSA-65 sign + verify via @noble', () => {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  assert.equal(publicKey.length, 1952);
  assert.equal(secretKey.length, 4032);
  const msg = new TextEncoder().encode('paramant-v3-test');
  const sig = ml_dsa65.sign(msg, secretKey);
  assert.equal(sig.length, 3309);
  assert.equal(ml_dsa65.verify(sig, msg, publicKey), true);
});

test('GhostPipe._encrypt produces a v1 blob and _decrypt recovers plaintext (anonymous)', async () => {
  const { publicKey, secretKey } = ml_kem768.keygen();
  const pubHex = Buffer.from(publicKey).toString('hex');

  const sender = new GhostPipe({
    apiKey: 'pgp_test', device: 'sender-a',
    relay: 'http://x', checkCapabilities: false, sigId: SIG.NONE,
  });
  const plaintext = new TextEncoder().encode('quantum hello');
  const { blob, hash } = await sender._encrypt(plaintext, pubHex, { padBlock: 8192, sigId: SIG.NONE });
  assert.equal(blob.length, 8192);
  assert.equal(Buffer.from(blob.slice(0, 10)).toString('hex'), '50514842010002000000');
  assert.equal(hash.length, 64);

  const receiver = new GhostPipe({
    apiKey: 'pgp_test', device: 'receiver-a',
    relay: 'http://x', checkCapabilities: false, sigId: SIG.NONE,
  });
  receiver._keypair = {
    version: 3, device: 'receiver-a',
    kemId: KEM.ML_KEM_768, sigId: SIG.NONE,
    kem_pub: pubHex, kem_priv: Buffer.from(secretKey).toString('hex'),
    sig_pub: '', sig_priv: '',
  };
  const out = await receiver._decrypt(blob);
  assert.deepEqual(out, plaintext);
});

test('GhostPipe._encrypt produces a v1 signed blob (ML-DSA-65) and _decrypt recovers plaintext', async () => {
  const { publicKey, secretKey } = ml_kem768.keygen();
  const pubHex = Buffer.from(publicKey).toString('hex');

  const sender = new GhostPipe({
    apiKey: 'pgp_test', device: 'sender-b',
    relay: 'http://x', checkCapabilities: false,
  });
  await sender._loadKeypair();
  const plaintext = new TextEncoder().encode('signed quantum hello');
  const { blob } = await sender._encrypt(plaintext, pubHex, { padBlock: 16384 });
  assert.equal(blob.length, 16384);
  assert.equal(Buffer.from(blob.slice(0, 10)).toString('hex'), '50514842010002000200');

  const receiver = new GhostPipe({
    apiKey: 'pgp_test', device: 'receiver-b',
    relay: 'http://x', checkCapabilities: false,
  });
  receiver._keypair = {
    version: 3, device: 'receiver-b',
    kemId: KEM.ML_KEM_768, sigId: SIG.ML_DSA_65,
    kem_pub: pubHex, kem_priv: Buffer.from(secretKey).toString('hex'),
    sig_pub: '', sig_priv: '',
  };
  const out = await receiver._decrypt(blob);
  assert.deepEqual(out, plaintext);
});

test('GhostPipe validates algorithm IDs at construction time', () => {
  assert.throws(() => new GhostPipe({
    apiKey: 'pgp_x', device: 'd', relay: 'http://x', checkCapabilities: false,
    kemId: 0x9999,
  }));
});

test('GhostPipe stores v3 keypair with real ML-KEM-768 sizes', async () => {
  const gp = new GhostPipe({ apiKey: 'pgp_x', device: 'keytest', relay: 'http://x', checkCapabilities: false });
  const kp = await gp._loadKeypair();
  assert.equal(kp.version, 3);
  assert.equal(kp.kemId, KEM.ML_KEM_768);
  assert.equal(kp.sigId, SIG.ML_DSA_65);
  assert.equal(kp.kem_pub.length, 1184 * 2); // hex-encoded
  assert.equal(kp.sig_pub.length, 1952 * 2);
});
