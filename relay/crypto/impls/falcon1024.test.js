const test = require("node:test");
const assert = require("node:assert");
const falcon1024 = require("./falcon1024");

test("Falcon-1024 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = falcon1024.generateKeyPair();
  assert.strictEqual(publicKey.length, 1793);
  assert.strictEqual(secretKey.length, 2305);
});

test("Falcon-1024 sign/verify roundtrip", () => {
  const { publicKey, secretKey } = falcon1024.generateKeyPair();
  const message = Buffer.from("test message for Falcon-1024");
  const signature = falcon1024.sign(message, secretKey);

  assert.strictEqual(falcon1024.verify(signature, message, publicKey), true);
});

test("Falcon-1024 rejects tampered message", () => {
  const { publicKey, secretKey } = falcon1024.generateKeyPair();
  const message = Buffer.from("original");
  const tampered = Buffer.from("tampered");
  const signature = falcon1024.sign(message, secretKey);

  assert.strictEqual(falcon1024.verify(signature, tampered, publicKey), false);
});

test("Falcon-1024 rejects wrong public key size", () => {
  const { secretKey } = falcon1024.generateKeyPair();
  const signature = falcon1024.sign(Buffer.from("msg"), secretKey);
  assert.throws(() => falcon1024.verify(signature, Buffer.from("msg"), Buffer.alloc(200)));
});
