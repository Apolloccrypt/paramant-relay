const test = require("node:test");
const assert = require("node:assert");
const slh = require("./slhdsa_sha2_128s");

// s-variants are slow-signing. Use ONE sign per file and multiplex assertions
// across it to keep the test suite runtime bounded.
test("SLH-DSA-SHA2-128s keygen + sign + verify (single-sign)", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  assert.strictEqual(publicKey.length, 32);
  assert.strictEqual(secretKey.length, 64);

  const message = Buffer.from("hi");
  const signature = slh.sign(message, secretKey);
  assert.strictEqual(signature.length, 7856);

  assert.strictEqual(slh.verify(signature, message, publicKey), true);
  assert.strictEqual(slh.verify(signature, Buffer.from("no"), publicKey), false);
  assert.throws(() => slh.verify(signature, message, Buffer.alloc(16)));
});

test("SLH-DSA-SHA2-128s carries performance_hint=slow_signing", () => {
  assert.strictEqual(slh.performance_hint, "slow_signing");
});
