const test = require("node:test");
const assert = require("node:assert");
const falcon512 = require("./falcon512");

test("Falcon-512 keygen produces expected sizes", () => {
  const { publicKey, secretKey } = falcon512.generateKeyPair();
  assert.strictEqual(publicKey.length, 897);
  assert.strictEqual(secretKey.length, 1281);
});

test("Falcon-512 sign/verify roundtrip", () => {
  const { publicKey, secretKey } = falcon512.generateKeyPair();
  const message = Buffer.from("test message for Falcon-512");
  const signature = falcon512.sign(message, secretKey);

  assert.strictEqual(falcon512.verify(signature, message, publicKey), true);
});

test("Falcon-512 rejects tampered message", () => {
  const { publicKey, secretKey } = falcon512.generateKeyPair();
  const message = Buffer.from("original");
  const tampered = Buffer.from("tampered");
  const signature = falcon512.sign(message, secretKey);

  assert.strictEqual(falcon512.verify(signature, tampered, publicKey), false);
});

test("Falcon-512 rejects wrong public key size", () => {
  const { secretKey } = falcon512.generateKeyPair();
  const signature = falcon512.sign(Buffer.from("msg"), secretKey);
  assert.throws(() => falcon512.verify(signature, Buffer.from("msg"), Buffer.alloc(100)));
});
