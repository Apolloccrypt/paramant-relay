const test = require("node:test");
const assert = require("node:assert");
const mldsa87 = require("./mldsa87");

test("ML-DSA-87 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mldsa87.generateKeyPair();
  assert.strictEqual(publicKey.length, 2592);
  assert.strictEqual(secretKey.length, 4896);
});

test("ML-DSA-87 sign/verify roundtrip", () => {
  const { publicKey, secretKey } = mldsa87.generateKeyPair();
  const message = Buffer.from("test message for ML-DSA-87");
  const signature = mldsa87.sign(message, secretKey);

  assert.strictEqual(mldsa87.verify(signature, message, publicKey), true);
});

test("ML-DSA-87 rejects tampered message", () => {
  const { publicKey, secretKey } = mldsa87.generateKeyPair();
  const message = Buffer.from("original");
  const tampered = Buffer.from("tampered");
  const signature = mldsa87.sign(message, secretKey);

  assert.strictEqual(mldsa87.verify(signature, tampered, publicKey), false);
});

test("ML-DSA-87 rejects wrong public key size", () => {
  const { secretKey } = mldsa87.generateKeyPair();
  const signature = mldsa87.sign(Buffer.from("msg"), secretKey);
  assert.throws(() => mldsa87.verify(signature, Buffer.from("msg"), Buffer.alloc(100)));
});
