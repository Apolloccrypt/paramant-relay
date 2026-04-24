const test = require("node:test");
const assert = require("node:assert");
const mldsa44 = require("./mldsa44");

test("ML-DSA-44 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mldsa44.generateKeyPair();
  assert.strictEqual(publicKey.length, 1312);
  assert.strictEqual(secretKey.length, 2560);
});

test("ML-DSA-44 sign/verify roundtrip", () => {
  const { publicKey, secretKey } = mldsa44.generateKeyPair();
  const message = Buffer.from("test message for ML-DSA-44");
  const signature = mldsa44.sign(message, secretKey);

  assert.strictEqual(mldsa44.verify(signature, message, publicKey), true);
});

test("ML-DSA-44 rejects tampered message", () => {
  const { publicKey, secretKey } = mldsa44.generateKeyPair();
  const message = Buffer.from("original");
  const tampered = Buffer.from("tampered");
  const signature = mldsa44.sign(message, secretKey);

  assert.strictEqual(mldsa44.verify(signature, tampered, publicKey), false);
});

test("ML-DSA-44 rejects wrong public key size", () => {
  const { secretKey } = mldsa44.generateKeyPair();
  const signature = mldsa44.sign(Buffer.from("msg"), secretKey);
  assert.throws(() => mldsa44.verify(signature, Buffer.from("msg"), Buffer.alloc(100)));
});
