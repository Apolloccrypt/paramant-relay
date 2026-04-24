const test = require("node:test");
const assert = require("node:assert");
const slh = require("./slhdsa_shake_256s");

test("SLH-DSA-SHAKE-256s keygen + sign + verify (single-sign, slow ~10s)", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  assert.strictEqual(publicKey.length, 64);
  assert.strictEqual(secretKey.length, 128);

  const message = Buffer.from("hi");
  const signature = slh.sign(message, secretKey);
  assert.strictEqual(signature.length, 29792);

  assert.strictEqual(slh.verify(signature, message, publicKey), true);
  assert.strictEqual(slh.verify(signature, Buffer.from("no"), publicKey), false);
  assert.throws(() => slh.verify(signature, message, Buffer.alloc(32)));
});

test("SLH-DSA-SHAKE-256s carries performance_hint=slow_signing", () => {
  assert.strictEqual(slh.performance_hint, "slow_signing");
});
