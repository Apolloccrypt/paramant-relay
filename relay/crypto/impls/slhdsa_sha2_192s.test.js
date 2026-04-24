const test = require("node:test");
const assert = require("node:assert");
const slh = require("./slhdsa_sha2_192s");

test("SLH-DSA-SHA2-192s keygen + sign + verify (single-sign, slow)", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  assert.strictEqual(publicKey.length, 48);
  assert.strictEqual(secretKey.length, 96);

  const message = Buffer.from("hi");
  const signature = slh.sign(message, secretKey);
  assert.strictEqual(signature.length, 16224);

  assert.strictEqual(slh.verify(signature, message, publicKey), true);
  assert.strictEqual(slh.verify(signature, Buffer.from("no"), publicKey), false);
  assert.throws(() => slh.verify(signature, message, Buffer.alloc(24)));
});

test("SLH-DSA-SHA2-192s carries performance_hint=slow_signing", () => {
  assert.strictEqual(slh.performance_hint, "slow_signing");
});
