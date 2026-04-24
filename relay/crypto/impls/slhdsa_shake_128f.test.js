const test = require("node:test");
const assert = require("node:assert");
const slh = require("./slhdsa_shake_128f");

test("SLH-DSA-SHAKE-128f keygen produces expected sizes", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  assert.strictEqual(publicKey.length, 32);
  assert.strictEqual(secretKey.length, 64);
});

test("SLH-DSA-SHAKE-128f sign/verify roundtrip", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  const message = Buffer.from("test message for SLH-DSA-SHAKE-128f");
  const signature = slh.sign(message, secretKey);
  assert.strictEqual(signature.length, 17088);
  assert.strictEqual(slh.verify(signature, message, publicKey), true);
});

test("SLH-DSA-SHAKE-128f rejects tampered message", () => {
  const { publicKey, secretKey } = slh.generateKeyPair();
  const signature = slh.sign(Buffer.from("original"), secretKey);
  assert.strictEqual(slh.verify(signature, Buffer.from("tampered"), publicKey), false);
});

test("SLH-DSA-SHAKE-128f has no performance_hint (fast variant)", () => {
  assert.strictEqual(slh.performance_hint, undefined);
});
