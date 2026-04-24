const test = require("node:test");
const assert = require("node:assert");
const { bootstrap } = require("./bootstrap");
const { getKEM, getSig, hasKEM, hasSig } = require("./registry");
const { UnsupportedAlgorithm } = require("./errors");

test("bootstrap registers ML-KEM-768 at id 0x0002", () => {
  bootstrap();
  const kem = getKEM(0x0002);
  assert.strictEqual(kem.name, "ML-KEM-768");
  assert.strictEqual(hasKEM(0x0002), true);
});

test("bootstrap registers ML-DSA-65 at id 0x0002", () => {
  bootstrap();
  const sig = getSig(0x0002);
  assert.strictEqual(sig.name, "ML-DSA-65");
  assert.strictEqual(hasSig(0x0002), true);
});

test("bootstrap is idempotent — repeated calls do not throw or mutate", () => {
  bootstrap();
  assert.doesNotThrow(() => { bootstrap(); bootstrap(); bootstrap(); });
  // After repeated calls the loaded impls must still be the expected ones
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
});

test("unloaded algorithm ids throw UnsupportedAlgorithm", () => {
  bootstrap();
  // 0x0003 = ML-KEM-1024 / ML-DSA-87 slot — intentionally not loaded
  assert.throws(() => getKEM(0x0003), UnsupportedAlgorithm);
  assert.throws(() => getSig(0x0003), UnsupportedAlgorithm);
});
