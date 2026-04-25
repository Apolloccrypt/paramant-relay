const test = require("node:test");
const assert = require("node:assert");
const mlkem768 = require("./impls/mlkem768");
const mldsa65 = require("./impls/mldsa65");

test("ML-KEM-768 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mlkem768.generateKeyPair();
  assert.strictEqual(publicKey.length, 1184);
  assert.strictEqual(secretKey.length, 2400);
});

test("ML-KEM-768 encapsulate/decapsulate roundtrip", () => {
  const { publicKey, secretKey } = mlkem768.generateKeyPair();
  const { ciphertext, sharedSecret } = mlkem768.encapsulate(publicKey);
  assert.strictEqual(ciphertext.length, 1088);
  assert.strictEqual(sharedSecret.length, 32);

  const recovered = mlkem768.decapsulate(ciphertext, secretKey);
  assert.deepStrictEqual(recovered, sharedSecret);
});

test("ML-KEM-768 rejects wrong public key size", () => {
  assert.throws(() => mlkem768.encapsulate(Buffer.alloc(100)));
});

test("ML-KEM-768 rejects wrong ciphertext size", () => {
  const { secretKey } = mlkem768.generateKeyPair();
  assert.throws(() => mlkem768.decapsulate(Buffer.alloc(100), secretKey));
});

test("ML-DSA-65 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mldsa65.generateKeyPair();
  assert.strictEqual(publicKey.length, 1952);
  assert.strictEqual(secretKey.length, 4032);
});

test("ML-DSA-65 sign/verify roundtrip", () => {
  const { publicKey, secretKey } = mldsa65.generateKeyPair();
  const message = Buffer.from("test message for signing");
  const signature = mldsa65.sign(message, secretKey);

  assert.strictEqual(mldsa65.verify(signature, message, publicKey), true);
});

test("ML-DSA-65 rejects tampered message", () => {
  const { publicKey, secretKey } = mldsa65.generateKeyPair();
  const message = Buffer.from("original");
  const tampered = Buffer.from("tampered");
  const signature = mldsa65.sign(message, secretKey);

  assert.strictEqual(mldsa65.verify(signature, tampered, publicKey), false);
});

test("ML-DSA-65 rejects wrong public key size", () => {
  const { secretKey } = mldsa65.generateKeyPair();
  const signature = mldsa65.sign(Buffer.from("msg"), secretKey);
  assert.throws(() => mldsa65.verify(signature, Buffer.from("msg"), Buffer.alloc(100)));
});
