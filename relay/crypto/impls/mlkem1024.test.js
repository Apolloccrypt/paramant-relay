const test = require("node:test");
const assert = require("node:assert");
const mlkem1024 = require("./mlkem1024");

test("ML-KEM-1024 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = mlkem1024.generateKeyPair();
  assert.strictEqual(publicKey.length, 1568);
  assert.strictEqual(secretKey.length, 3168);
});

test("ML-KEM-1024 encapsulate/decapsulate roundtrip", () => {
  const { publicKey, secretKey } = mlkem1024.generateKeyPair();
  const { ciphertext, sharedSecret } = mlkem1024.encapsulate(publicKey);
  assert.strictEqual(ciphertext.length, 1568);
  assert.strictEqual(sharedSecret.length, 32);

  const recovered = mlkem1024.decapsulate(ciphertext, secretKey);
  assert.deepStrictEqual(recovered, sharedSecret);
});

test("ML-KEM-1024 rejects wrong public key size", () => {
  assert.throws(() => mlkem1024.encapsulate(Buffer.alloc(100)));
});

test("ML-KEM-1024 rejects wrong ciphertext size", () => {
  const { secretKey } = mlkem1024.generateKeyPair();
  assert.throws(() => mlkem1024.decapsulate(Buffer.alloc(100), secretKey));
});
