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

// Pre-fix, signed blobs were accepted on _decrypt without ever calling
// sig.verify — every "signature" was a no-op. This regression test flips a
// bit in the signature region and asserts decryption now fails loudly.
test('GhostPipe._decrypt rejects a tampered ML-DSA-65 signature (post-quantum auth)', async () => {
  const { decode: wireDecode } = await import('../src/wire-format.js');
  const { publicKey, secretKey } = ml_kem768.keygen();
  const pubHex = Buffer.from(publicKey).toString('hex');

  const sender = new GhostPipe({
    apiKey: 'pgp_test', device: 'sender-tamper',
    relay: 'http://x', checkCapabilities: false,
  });
  await sender._loadKeypair();
  const plaintext = new TextEncoder().encode('do not accept forged sigs');
  const { blob } = await sender._encrypt(plaintext, pubHex, { padBlock: 16384 });

  // Locate the signature region inside the (unpadded prefix of the) blob and
  // flip the first byte. wireDecode walks the same bytes the receiver does.
  const parsed = wireDecode(blob);
  // sig sits after: header(10) + 4+ctKem + 4+senderPub + 4 (sigLen) — flip
  // the first signature byte in-place.
  const sigOffset = 10 + 4 + parsed.ctKem.length + 4 + parsed.senderPub.length + 4;
  blob[sigOffset] ^= 0xFF;

  const receiver = new GhostPipe({
    apiKey: 'pgp_test', device: 'receiver-tamper',
    relay: 'http://x', checkCapabilities: false,
  });
  receiver._keypair = {
    version: 3, device: 'receiver-tamper',
    kemId: KEM.ML_KEM_768, sigId: SIG.ML_DSA_65,
    kem_pub: pubHex, kem_priv: Buffer.from(secretKey).toString('hex'),
    sig_pub: '', sig_priv: '',
  };
  await assert.rejects(
    () => receiver._decrypt(blob),
    (err) => err.name === 'SignatureError'
  );
});

// Wire-format-v1 + Python SDK interop: for sigId != 0x0000 the senderPub
// field MUST carry the sender's signing public key (1952 B for ML-DSA-65),
// not the KEM public key (1184 B). Pre-fix this was the KEM pubkey, which
// made every signed blob un-verifiable.
test('GhostPipe._encrypt: signed blob senderPub is the ML-DSA-65 signing pubkey (1952 bytes)', async () => {
  const { decode: wireDecode } = await import('../src/wire-format.js');
  const { publicKey } = ml_kem768.keygen();
  const pubHex = Buffer.from(publicKey).toString('hex');

  const sender = new GhostPipe({
    apiKey: 'pgp_test', device: 'sender-pubsize',
    relay: 'http://x', checkCapabilities: false,
  });
  await sender._loadKeypair();
  const { blob } = await sender._encrypt(
    new TextEncoder().encode('size check'), pubHex, { padBlock: 16384 }
  );
  const parsed = wireDecode(blob);
  assert.equal(parsed.sigId, SIG.ML_DSA_65);
  assert.equal(parsed.senderPub.length, 1952, 'senderPub must be the ML-DSA-65 signing pubkey');
});

// Pre-fix, _encrypt with padBlock > 65536 threw QuotaExceededError because
// crypto.getRandomValues caps at 65536 bytes per call. fillRandom now chunks.
for (const padBlock of [65536, 131072, 5 * 1024 * 1024]) {
  test(`_encrypt at padBlock=${padBlock} (fillRandom regression)`, async () => {
    const { publicKey } = ml_kem768.keygen();
    const pubHex = Buffer.from(publicKey).toString('hex');
    const sender = new GhostPipe({
      apiKey: 'pgp_test', device: `sender-pad-${padBlock}`,
      relay: 'http://x', checkCapabilities: false, sigId: SIG.NONE,
    });
    const { blob } = await sender._encrypt(
      new TextEncoder().encode('quantum payload — fillRandom regression'),
      pubHex, { padBlock, sigId: SIG.NONE }
    );
    assert.equal(blob.length, padBlock);
  });
}
