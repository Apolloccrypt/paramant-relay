const test = require("node:test");
const assert = require("node:assert");
const { encode, decode, isV1, MAGIC, VERSION_V1 } = require("./wire-format");
const { UnsupportedAlgorithm, InvalidVersion } = require("./errors");
const { registerKEM, registerSig, clearRegistry } = require("./registry");

function setupRegistry() {
  clearRegistry();
  registerKEM(0x0002, {
    name: "ML-KEM-768",
    pubKeySize: 1184,
    ctSize: 1088,
    encapsulate: () => ({ ciphertext: Buffer.alloc(1088), sharedSecret: Buffer.alloc(32) }),
    decapsulate: () => Buffer.alloc(32)
  });
  registerSig(0x0002, {
    name: "ML-DSA-65",
    pubKeySize: 1952,
    sigSize: 3309,
    sign: () => Buffer.alloc(3309),
    verify: () => true
  });
}

const signedInput = () => ({
  kemId: 0x0002,
  sigId: 0x0002,
  ctKem: Buffer.alloc(1088, 0xA1),
  senderPub: Buffer.alloc(1952, 0xB2),
  signature: Buffer.alloc(3309, 0xC3),
  nonce: Buffer.alloc(12, 0xD4),
  ciphertext: Buffer.from("integration test payload — signed blob"),
});

const anonInput = () => ({
  kemId: 0x0002,
  sigId: 0x0000,
  ctKem: Buffer.alloc(1088, 0xE5),
  senderPub: Buffer.alloc(1152, 0xF6),
  signature: null,
  nonce: Buffer.alloc(12, 0x07),
  ciphertext: Buffer.from("integration test payload — anon blob"),
});

test("integration: encode/decode roundtrip preserves every field (signed)", () => {
  setupRegistry();
  const input = signedInput();
  const blob = encode(input);
  const decoded = decode(blob);
  assert.strictEqual(decoded.kemId, input.kemId);
  assert.strictEqual(decoded.sigId, input.sigId);
  assert.strictEqual(decoded.flags, 0x00);
  assert.deepStrictEqual(decoded.ctKem, input.ctKem);
  assert.deepStrictEqual(decoded.senderPub, input.senderPub);
  assert.deepStrictEqual(decoded.signature, input.signature);
  assert.deepStrictEqual(decoded.nonce, input.nonce);
  assert.deepStrictEqual(decoded.ciphertext, input.ciphertext);
});

test("integration: anonymous blob (sigId=0x0000) encodes without signature section, decodes with signature=null", () => {
  setupRegistry();
  const input = anonInput();
  const blob = encode(input);
  const decoded = decode(blob);
  assert.strictEqual(decoded.sigId, 0x0000);
  assert.strictEqual(decoded.signature, null);
  assert.deepStrictEqual(decoded.ciphertext, input.ciphertext);
  // Fixed sizes: 10 header + 4+1088 ctKem + 4+1152 senderPub + 12 nonce + 4+38 ct = 2312
  assert.strictEqual(blob.length, 10 + 4 + 1088 + 4 + 1152 + 12 + 4 + 38);
});

test("integration: isV1 returns true for v1 blob", () => {
  setupRegistry();
  const blob = encode(signedInput());
  assert.strictEqual(isV1(blob), true);
});

test("integration: isV1 returns false for v0 blob", () => {
  const v0ish = Buffer.concat([
    Buffer.alloc(1088, 0xA1),  // ctKem-like bytes, no PQHB magic
    Buffer.alloc(1952, 0xB2),
    Buffer.alloc(12, 0xD4),
    Buffer.from("looks like a v0 payload"),
  ]);
  assert.strictEqual(isV1(v0ish), false);
});

test("integration: isV1 returns false for empty buffer", () => {
  assert.strictEqual(isV1(Buffer.alloc(0)), false);
});

test("integration: isV1 returns false for non-buffer", () => {
  assert.strictEqual(isV1(null), false);
  assert.strictEqual(isV1("PQHB..."), false);
});

test("integration: decode of blob with unknown kemId throws UnsupportedAlgorithm", () => {
  setupRegistry();
  const blob = encode(signedInput());
  blob.writeUInt16BE(0xBEEF, 5);  // clobber kemId → unregistered
  assert.throws(() => decode(blob), (err) => {
    return err instanceof UnsupportedAlgorithm && err.kind === "KEM" && err.id === 0xBEEF;
  });
});

test("integration: decode of blob with unknown sigId throws UnsupportedAlgorithm", () => {
  setupRegistry();
  const blob = encode(signedInput());
  blob.writeUInt16BE(0xBEEF, 7);  // clobber sigId → unregistered
  assert.throws(() => decode(blob), (err) => {
    return err instanceof UnsupportedAlgorithm && err.kind === "SIG" && err.id === 0xBEEF;
  });
});

test("integration: decode of blob with future version throws InvalidVersion listing supported", () => {
  setupRegistry();
  const blob = encode(signedInput());
  blob.writeUInt8(0x02, 4);  // version byte → unsupported
  assert.throws(() => decode(blob), (err) => {
    return err instanceof InvalidVersion
      && err.version === 0x02
      && Array.isArray(err.supported)
      && err.supported.includes(VERSION_V1);
  });
});

test("integration: MAGIC bytes spell 'PQHB' in ASCII", () => {
  assert.strictEqual(MAGIC.toString("ascii"), "PQHB");
  assert.strictEqual(MAGIC.length, 4);
});
