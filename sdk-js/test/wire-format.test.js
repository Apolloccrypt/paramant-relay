import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  encode, decode, buildAAD, isV1,
  MAGIC, VERSION_V1, HEADER_FIXED_SIZE, NONCE_SIZE,
  InvalidMagicError, InvalidVersionError, InvalidFlagsError, MalformedBlobError,
} from '../src/wire-format.js';

function repeatHex(hex, n) {
  const pat = Buffer.from(hex, 'hex');
  const out = Buffer.alloc(pat.length * n);
  for (let i = 0; i < n; i++) pat.copy(out, i * pat.length);
  return new Uint8Array(out);
}

function sha256(u8) {
  return crypto.createHash('sha256').update(u8).digest('hex');
}

test('MAGIC is PQHB', () => {
  assert.deepEqual(Array.from(MAGIC), [0x50, 0x51, 0x48, 0x42]);
  assert.equal(Buffer.from(MAGIC).toString('ascii'), 'PQHB');
});

test('header size is 10 bytes, nonce is 12 bytes', () => {
  assert.equal(HEADER_FIXED_SIZE, 10);
  assert.equal(NONCE_SIZE, 12);
  assert.equal(VERSION_V1, 0x01);
});

test('test vector 1 (signed): SHA-256 bit-exact', () => {
  const blob = encode({
    kemId: 0x0002,
    sigId: 0x0002,
    ctKem: repeatHex('00112233445566778899aabbccddeeff', 68),
    senderPub: repeatHex('cafe', 296),
    signature: repeatHex('babe', 1654),
    nonce: Buffer.from('000102030405060708090a0b', 'hex'),
    ciphertext: repeatHex('deadbeef', 16),
  });
  assert.equal(blob.length, 5090, 'total length');
  assert.equal(Buffer.from(blob.slice(0, 10)).toString('hex'), '50514842010002000200');
  assert.equal(
    Buffer.from(blob.slice(0, 64)).toString('hex'),
    '505148420100020002000000044000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011'
  );
  assert.equal(sha256(blob), '002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a');
});

test('test vector 2 (anonymous): SHA-256 bit-exact', () => {
  const blob = encode({
    kemId: 0x0002,
    sigId: 0x0000,
    ctKem: repeatHex('00112233445566778899aabbccddeeff', 68),
    senderPub: repeatHex('cafe', 296),
    nonce: Buffer.from('000102030405060708090a0b', 'hex'),
    ciphertext: repeatHex('deadbeef', 16),
  });
  assert.equal(blob.length, 1778);
  assert.equal(Buffer.from(blob.slice(0, 10)).toString('hex'), '50514842010002000000');
  assert.equal(
    Buffer.from(blob.slice(0, 64)).toString('hex'),
    '505148420100020000000000044000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011'
  );
  assert.equal(sha256(blob), '46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef');
});

test('encode/decode roundtrip (signed)', () => {
  const input = {
    kemId: 0x0002,
    sigId: 0x0002,
    ctKem: crypto.randomBytes(1088),
    senderPub: crypto.randomBytes(1184),
    signature: crypto.randomBytes(3309),
    nonce: crypto.randomBytes(12),
    ciphertext: crypto.randomBytes(512),
  };
  const blob = encode(input);
  const parsed = decode(blob);
  assert.equal(parsed.version, VERSION_V1);
  assert.equal(parsed.kemId, 0x0002);
  assert.equal(parsed.sigId, 0x0002);
  assert.equal(parsed.flags, 0x00);
  assert.deepEqual(parsed.ctKem, new Uint8Array(input.ctKem));
  assert.deepEqual(parsed.senderPub, new Uint8Array(input.senderPub));
  assert.deepEqual(parsed.signature, new Uint8Array(input.signature));
  assert.deepEqual(parsed.nonce, new Uint8Array(input.nonce));
  assert.deepEqual(parsed.ciphertext, new Uint8Array(input.ciphertext));
});

test('encode/decode roundtrip (anonymous, no signature)', () => {
  const input = {
    kemId: 0x0002,
    sigId: 0x0000,
    ctKem: crypto.randomBytes(1088),
    senderPub: crypto.randomBytes(1184),
    nonce: crypto.randomBytes(12),
    ciphertext: crypto.randomBytes(64),
  };
  const blob = encode(input);
  const parsed = decode(blob);
  assert.equal(parsed.sigId, 0x0000);
  assert.equal(parsed.signature, null);
});

test('isV1 correctness', () => {
  assert.equal(isV1(new Uint8Array([0x50, 0x51, 0x48, 0x42, 0x01])), true);
  assert.equal(isV1(new Uint8Array([0x50, 0x51, 0x48, 0x41])), false);
  assert.equal(isV1(new Uint8Array([0x50])), false);
  assert.equal(isV1(null), false);
});

test('encode rejects non-zero flags', () => {
  assert.throws(() => encode({
    kemId: 2, sigId: 2, flags: 0x01,
    ctKem: new Uint8Array(1), senderPub: new Uint8Array(1),
    signature: new Uint8Array(1), nonce: new Uint8Array(12), ciphertext: new Uint8Array(1),
  }), InvalidFlagsError);
});

test('encode requires signature when sigId != 0', () => {
  assert.throws(() => encode({
    kemId: 2, sigId: 2,
    ctKem: new Uint8Array(1), senderPub: new Uint8Array(1),
    nonce: new Uint8Array(12), ciphertext: new Uint8Array(1),
  }));
});

test('encode forbids signature when sigId == 0', () => {
  assert.throws(() => encode({
    kemId: 2, sigId: 0,
    ctKem: new Uint8Array(1), senderPub: new Uint8Array(1),
    signature: new Uint8Array(1),
    nonce: new Uint8Array(12), ciphertext: new Uint8Array(1),
  }));
});

test('decode rejects wrong magic', () => {
  const bad = new Uint8Array(20);
  bad.set([0x41, 0x42, 0x43, 0x44]);
  bad[4] = 0x01;
  assert.throws(() => decode(bad), InvalidMagicError);
});

test('decode rejects unsupported version', () => {
  const blob = encode({
    kemId: 2, sigId: 0,
    ctKem: new Uint8Array(1), senderPub: new Uint8Array(1),
    nonce: new Uint8Array(12), ciphertext: new Uint8Array(1),
  });
  blob[4] = 0x99;
  assert.throws(() => decode(blob), InvalidVersionError);
});

test('decode rejects truncated blob', () => {
  assert.throws(() => decode(new Uint8Array(5)), MalformedBlobError);
});

test('buildAAD is 14 bytes: header + chunk_index', () => {
  const aad = buildAAD({ kemId: 2, sigId: 2, chunkIndex: 0 });
  assert.equal(aad.length, 14);
  assert.equal(Buffer.from(aad).toString('hex'), '5051484201000200020000000000');
});
