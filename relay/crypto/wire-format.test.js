const test = require("node:test");
const assert = require("node:assert");
const { encode, decode, buildAAD, MAGIC, VERSION_V1, HEADER_FIXED_SIZE } = require("./wire-format");
const {
  InvalidMagic,
  InvalidVersion,
  MalformedBlob,
  InvalidFlags,
  UnsupportedAlgorithm
} = require("./errors");
const {
  registerKEM,
  registerSig,
  clearRegistry
} = require("./registry");

function setupFakeRegistry() {
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

const sampleInput = () => ({
  kemId: 0x0002,
  sigId: 0x0002,
  ctKem: Buffer.alloc(1088, 0xAA),
  senderPub: Buffer.alloc(1952, 0xBB),
  signature: Buffer.alloc(3309, 0xCC),
  nonce: Buffer.alloc(12, 0xDD),
  ciphertext: Buffer.from("hello world")
});

test("encode/decode roundtrip with signature", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  const decoded = decode(blob);

  assert.strictEqual(decoded.version, VERSION_V1);
  assert.strictEqual(decoded.kemId, 0x0002);
  assert.strictEqual(decoded.sigId, 0x0002);
  assert.strictEqual(decoded.flags, 0x00);
  assert.deepStrictEqual(decoded.ctKem, input.ctKem);
  assert.deepStrictEqual(decoded.senderPub, input.senderPub);
  assert.deepStrictEqual(decoded.signature, input.signature);
  assert.deepStrictEqual(decoded.nonce, input.nonce);
  assert.deepStrictEqual(decoded.ciphertext, input.ciphertext);
});

test("encode/decode roundtrip without signature (sigId=0x0000)", () => {
  setupFakeRegistry();
  const input = { ...sampleInput(), sigId: 0x0000, signature: null };
  const blob = encode(input);
  const decoded = decode(blob);

  assert.strictEqual(decoded.sigId, 0x0000);
  assert.strictEqual(decoded.signature, null);
  assert.deepStrictEqual(decoded.ciphertext, input.ciphertext);
});

test("decode rejects invalid magic", () => {
  setupFakeRegistry();
  const bad = Buffer.concat([Buffer.from("XXXX"), Buffer.alloc(100)]);
  assert.throws(() => decode(bad), InvalidMagic);
});

test("decode rejects invalid version", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  blob.writeUInt8(0x99, 4);
  assert.throws(() => decode(blob), InvalidVersion);
});

test("decode rejects invalid flags", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  blob.writeUInt8(0xFF, 9);
  assert.throws(() => decode(blob), InvalidFlags);
});

test("decode rejects unsupported KEM id", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  blob.writeUInt16BE(0xDEAD, 5);
  assert.throws(() => decode(blob), UnsupportedAlgorithm);
});

test("decode rejects unsupported sig id", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  blob.writeUInt16BE(0xDEAD, 7);
  assert.throws(() => decode(blob), UnsupportedAlgorithm);
});

test("decode rejects truncated blob at header", () => {
  setupFakeRegistry();
  const bad = Buffer.concat([MAGIC, Buffer.from([VERSION_V1])]);
  assert.throws(() => decode(bad), MalformedBlob);
});

test("decode rejects truncated blob at ciphertext", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  const truncated = blob.subarray(0, blob.length - 10);
  assert.throws(() => decode(truncated), MalformedBlob);
});

test("encode rejects wrong nonce length", () => {
  const input = sampleInput();
  input.nonce = Buffer.alloc(10);
  assert.throws(() => encode(input));
});

test("encode rejects invalid flags", () => {
  const input = sampleInput();
  input.flags = 0x42;
  assert.throws(() => encode(input), InvalidFlags);
});

test("encode requires signature when sigId != 0x0000", () => {
  const input = { ...sampleInput(), sigId: 0x0002, signature: null };
  assert.throws(() => encode(input));
});

test("encode rejects signature when sigId = 0x0000", () => {
  const input = { ...sampleInput(), sigId: 0x0000 };
  assert.throws(() => encode(input));
});

test("buildAAD produces stable output", () => {
  const aad = buildAAD({ kemId: 0x0002, sigId: 0x0002, flags: 0x00, chunkIndex: 0 });
  assert.strictEqual(aad.length, HEADER_FIXED_SIZE + 4);
  assert.strictEqual(aad.compare(MAGIC, 0, 4, 0, 4), 0);
  assert.strictEqual(aad.readUInt8(4), VERSION_V1);
});

test("buildAAD differs per chunkIndex", () => {
  const a = buildAAD({ kemId: 0x0002, sigId: 0x0002, chunkIndex: 0 });
  const b = buildAAD({ kemId: 0x0002, sigId: 0x0002, chunkIndex: 1 });
  assert.notDeepStrictEqual(a, b);
});

test("aad returned by decode matches first 10 bytes of blob", () => {
  setupFakeRegistry();
  const input = sampleInput();
  const blob = encode(input);
  const decoded = decode(blob);
  assert.deepStrictEqual(decoded.aad, blob.subarray(0, HEADER_FIXED_SIZE));
});
