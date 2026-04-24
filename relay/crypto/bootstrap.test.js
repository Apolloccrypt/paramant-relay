const test = require("node:test");
const assert = require("node:assert");
const { bootstrap } = require("./bootstrap");
const { getKEM, getSig, hasKEM, hasSig, listSupported } = require("./registry");
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

test("bootstrap registers Falcon-512 at id 0x0100", () => {
  bootstrap();
  assert.strictEqual(getSig(0x0100).name, "Falcon-512");
  assert.strictEqual(hasSig(0x0100), true);
});

test("bootstrap registers Falcon-1024 at id 0x0101", () => {
  bootstrap();
  assert.strictEqual(getSig(0x0101).name, "Falcon-1024");
  assert.strictEqual(hasSig(0x0101), true);
});

test("bootstrap registers SLH-DSA SHA-2 family at 0x0200..0x0205", () => {
  bootstrap();
  assert.strictEqual(getSig(0x0200).name, "SLH-DSA-SHA2-128s");
  assert.strictEqual(getSig(0x0201).name, "SLH-DSA-SHA2-128f");
  assert.strictEqual(getSig(0x0202).name, "SLH-DSA-SHA2-192s");
  assert.strictEqual(getSig(0x0203).name, "SLH-DSA-SHA2-192f");
  assert.strictEqual(getSig(0x0204).name, "SLH-DSA-SHA2-256s");
  assert.strictEqual(getSig(0x0205).name, "SLH-DSA-SHA2-256f");
});

test("bootstrap registers SLH-DSA SHAKE family at 0x0206..0x020B", () => {
  bootstrap();
  assert.strictEqual(getSig(0x0206).name, "SLH-DSA-SHAKE-128s");
  assert.strictEqual(getSig(0x0207).name, "SLH-DSA-SHAKE-128f");
  assert.strictEqual(getSig(0x0208).name, "SLH-DSA-SHAKE-192s");
  assert.strictEqual(getSig(0x0209).name, "SLH-DSA-SHAKE-192f");
  assert.strictEqual(getSig(0x020A).name, "SLH-DSA-SHAKE-256s");
  assert.strictEqual(getSig(0x020B).name, "SLH-DSA-SHAKE-256f");
});

test("slow-signing SLH-DSA 's' variants carry performance_hint=slow_signing", () => {
  bootstrap();
  const slowIds = [0x0200, 0x0202, 0x0204, 0x0206, 0x0208, 0x020A];
  for (const id of slowIds) {
    assert.strictEqual(
      getSig(id).performance_hint, "slow_signing",
      `sig 0x${id.toString(16)} should have performance_hint=slow_signing`
    );
  }
});

test("fast SLH-DSA 'f' variants and Falcon have no performance_hint", () => {
  bootstrap();
  const fastIds = [0x0100, 0x0101, 0x0201, 0x0203, 0x0205, 0x0207, 0x0209, 0x020B];
  for (const id of fastIds) {
    assert.strictEqual(
      getSig(id).performance_hint, undefined,
      `sig 0x${id.toString(16)} should not have performance_hint`
    );
  }
});

test("existing ML-DSA entries have no performance_hint", () => {
  bootstrap();
  assert.strictEqual(getSig(0x0001).performance_hint, undefined);
  assert.strictEqual(getSig(0x0002).performance_hint, undefined);
  assert.strictEqual(getSig(0x0003).performance_hint, undefined);
});

test("listSupported emits performance_hint only on slow entries", () => {
  bootstrap();
  const { sig } = listSupported();
  const slowIds = new Set([0x0200, 0x0202, 0x0204, 0x0206, 0x0208, 0x020A]);
  for (const entry of sig) {
    if (slowIds.has(entry.id)) {
      assert.strictEqual(entry.performance_hint, "slow_signing",
        `entry 0x${entry.id.toString(16)} missing slow_signing hint`);
    } else {
      assert.strictEqual("performance_hint" in entry, false,
        `entry 0x${entry.id.toString(16)} should not emit performance_hint field`);
    }
  }
});

test("listSupported includes all expected counts (3 KEM, 18 sig including none)", () => {
  bootstrap();
  const caps = listSupported();
  // 3 KEM: ML-KEM-512, 768, 1024
  // 18 sig: none + 3 ML-DSA + 2 Falcon + 12 SLH-DSA
  assert.strictEqual(caps.kem.length, 3);
  assert.strictEqual(caps.sig.length, 18);
  // none is always first
  assert.strictEqual(caps.sig[0].id, 0x0000);
  assert.strictEqual(caps.sig[0].name, "none");
});

test("bootstrap is idempotent — repeated calls do not throw or mutate", () => {
  bootstrap();
  assert.doesNotThrow(() => { bootstrap(); bootstrap(); bootstrap(); });
  assert.strictEqual(getKEM(0x0001).name, "ML-KEM-512");
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(getKEM(0x0003).name, "ML-KEM-1024");
  assert.strictEqual(getSig(0x0001).name, "ML-DSA-44");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
  assert.strictEqual(getSig(0x0003).name, "ML-DSA-87");
  assert.strictEqual(getSig(0x0100).name, "Falcon-512");
  assert.strictEqual(getSig(0x0200).name, "SLH-DSA-SHA2-128s");
});

test("unloaded algorithm ids throw UnsupportedAlgorithm", () => {
  bootstrap();
  // 0x0100 KEM slot is unused (Falcon is a SIG, not a KEM)
  assert.throws(() => getKEM(0x0100), UnsupportedAlgorithm);
  // 0x0300+ reserved for future algorithms, not yet loaded
  assert.throws(() => getSig(0x0300), UnsupportedAlgorithm);
});
