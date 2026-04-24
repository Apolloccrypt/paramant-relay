const test = require("node:test");
const assert = require("node:assert");
const {
  registerKEM,
  registerSig,
  getKEM,
  getSig,
  hasKEM,
  hasSig,
  listSupported,
  clearRegistry
} = require("./registry");
const { UnsupportedAlgorithm } = require("./errors");

const fakeKEM = {
  name: "TEST-KEM",
  pubKeySize: 32,
  ctSize: 48,
  encapsulate: (pk) => ({ ciphertext: Buffer.alloc(48), sharedSecret: Buffer.alloc(32) }),
  decapsulate: (ct, sk) => Buffer.alloc(32)
};

const fakeSig = {
  name: "TEST-SIG",
  pubKeySize: 32,
  sigSize: 64,
  sign: (msg, sk) => Buffer.alloc(64),
  verify: (sig, msg, pk) => true
};

test("registerKEM adds to registry", () => {
  clearRegistry();
  registerKEM(0x9001, fakeKEM);
  assert.strictEqual(hasKEM(0x9001), true);
  assert.strictEqual(getKEM(0x9001).name, "TEST-KEM");
});

test("registerKEM rejects invalid id", () => {
  clearRegistry();
  assert.throws(() => registerKEM(-1, fakeKEM));
  assert.throws(() => registerKEM(0x10000, fakeKEM));
  assert.throws(() => registerKEM("string", fakeKEM));
});

test("registerKEM rejects incomplete impl", () => {
  clearRegistry();
  assert.throws(() => registerKEM(0x9001, { name: "incomplete" }));
});

test("getKEM throws UnsupportedAlgorithm for unknown id", () => {
  clearRegistry();
  assert.throws(() => getKEM(0xDEAD), UnsupportedAlgorithm);
});

test("registerSig adds to registry", () => {
  clearRegistry();
  registerSig(0x9001, fakeSig);
  assert.strictEqual(hasSig(0x9001), true);
  assert.strictEqual(getSig(0x9001).name, "TEST-SIG");
});

test("registerSig rejects id 0x0000", () => {
  clearRegistry();
  assert.throws(() => registerSig(0x0000, fakeSig));
});

test("getSig returns null for 0x0000 (no-signature)", () => {
  clearRegistry();
  assert.strictEqual(getSig(0x0000), null);
});

test("hasSig returns true for 0x0000", () => {
  clearRegistry();
  assert.strictEqual(hasSig(0x0000), true);
});

test("listSupported returns wire_version + arrays", () => {
  clearRegistry();
  registerKEM(0x9001, fakeKEM);
  registerSig(0x9001, fakeSig);
  const result = listSupported();
  assert.strictEqual(result.wire_version, 1);
  assert.strictEqual(result.kem.length, 1);
  assert.strictEqual(result.sig.length, 2);
  assert.strictEqual(result.sig[0].id, 0x0000);
  assert.strictEqual(result.sig[0].name, "none");
});
