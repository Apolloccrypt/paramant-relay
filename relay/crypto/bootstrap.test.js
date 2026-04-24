const test = require("node:test");
const assert = require("node:assert");
const { bootstrap } = require("./bootstrap");
const { getKEM, getSig, hasKEM, hasSig } = require("./registry");
const { UnsupportedAlgorithm } = require("./errors");

test("bootstrap registers ML-KEM-512 at id 0x0001", () => {
  bootstrap();
  const kem = getKEM(0x0001);
  assert.strictEqual(kem.name, "ML-KEM-512");
  assert.strictEqual(hasKEM(0x0001), true);
});

test("bootstrap registers ML-KEM-768 at id 0x0002", () => {
  bootstrap();
  const kem = getKEM(0x0002);
  assert.strictEqual(kem.name, "ML-KEM-768");
  assert.strictEqual(hasKEM(0x0002), true);
});

test("bootstrap registers ML-KEM-1024 at id 0x0003", () => {
  bootstrap();
  const kem = getKEM(0x0003);
  assert.strictEqual(kem.name, "ML-KEM-1024");
  assert.strictEqual(hasKEM(0x0003), true);
});

test("bootstrap registers ML-DSA-44 at id 0x0001", () => {
  bootstrap();
  const sig = getSig(0x0001);
  assert.strictEqual(sig.name, "ML-DSA-44");
  assert.strictEqual(hasSig(0x0001), true);
});

test("bootstrap registers ML-DSA-65 at id 0x0002", () => {
  bootstrap();
  const sig = getSig(0x0002);
  assert.strictEqual(sig.name, "ML-DSA-65");
  assert.strictEqual(hasSig(0x0002), true);
});

test("bootstrap registers ML-DSA-87 at id 0x0003", () => {
  bootstrap();
  const sig = getSig(0x0003);
  assert.strictEqual(sig.name, "ML-DSA-87");
  assert.strictEqual(hasSig(0x0003), true);
});

test("bootstrap is idempotent — repeated calls do not throw or mutate", () => {
  bootstrap();
  assert.doesNotThrow(() => { bootstrap(); bootstrap(); bootstrap(); });
  // After repeated calls the loaded impls must still be the expected ones
  assert.strictEqual(getKEM(0x0001).name, "ML-KEM-512");
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(getKEM(0x0003).name, "ML-KEM-1024");
  assert.strictEqual(getSig(0x0001).name, "ML-DSA-44");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
  assert.strictEqual(getSig(0x0003).name, "ML-DSA-87");
});

test("unloaded algorithm ids throw UnsupportedAlgorithm", () => {
  bootstrap();
  // 0x0100+ reserved for Falcon, 0x0200+ reserved for SPHINCS+ — not yet loaded
  assert.throws(() => getKEM(0x0100), UnsupportedAlgorithm);
  assert.throws(() => getSig(0x0200), UnsupportedAlgorithm);
});
