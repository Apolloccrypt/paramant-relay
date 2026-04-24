const test = require("node:test");
const assert = require("node:assert");
const mlkem512 = require("./mlkem512");

test("ML-KEM-512 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mlkem512.generateKeyPair();
  assert.strictEqual(publicKey.length, 800);
  assert.strictEqual(secretKey.length, 1632);
});

test("ML-KEM-512 encapsulate/decapsulate roundtrip", () => {
  const { publicKey, secretKey } = mlkem512.generateKeyPair();
  const { ciphertext, sharedSecret } = mlkem512.encapsulate(publicKey);
  assert.strictEqual(ciphertext.length, 768);
  assert.strictEqual(sharedSecret.length, 32);

  const recovered = mlkem512.decapsulate(ciphertext, secretKey);
  assert.deepStrictEqual(recovered, sharedSecret);
});

test("ML-KEM-512 rejects wrong public key size", () => {
  assert.throws(() => mlkem512.encapsulate(Buffer.alloc(100)));
});

test("ML-KEM-512 rejects wrong ciphertext size", () => {
  const { secretKey } = mlkem512.generateKeyPair();
  assert.throws(() => mlkem512.decapsulate(Buffer.alloc(100), secretKey));
});
