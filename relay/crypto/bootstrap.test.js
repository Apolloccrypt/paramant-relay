const test = require("node:test");
const assert = require("node:assert");
const { bootstrap, getActiveMode, resetBootstrap } = require("./bootstrap");
const { getKEM, getSig, hasKEM, hasSig, listSupported } = require("./registry");
const { UnsupportedAlgorithm } = require("./errors");

// bootstrap() is mode-aware (ADR R006): 'core' (default) registers only
// ML-KEM-768 + ML-DSA-65; 'extended' registers all 18 algorithms. The impl
// files are always required at startup; only registration is gated by mode.
// Each test resets state and selects the mode it needs, since bootstrap() is
// idempotent within a process.

function boot(mode) {
  resetBootstrap();
  return bootstrap(mode);
}

// --- core mode (default) ----------------------------------------------------

test("default mode is 'core' (no arg, no env)", () => {
  resetBootstrap();
  const prev = process.env.CRYPTO_MODE;
  delete process.env.CRYPTO_MODE;
  try {
    const mode = bootstrap();
    assert.strictEqual(mode, "core");
    assert.strictEqual(getActiveMode(), "core");
  } finally {
    if (prev !== undefined) process.env.CRYPTO_MODE = prev;
  }
});

test("core mode registers ML-KEM-768 + ML-DSA-65 only", () => {
  boot("core");
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
  assert.strictEqual(hasKEM(0x0002), true);
  assert.strictEqual(hasSig(0x0002), true);
});

test("core mode does NOT register the extended algorithms", () => {
  boot("core");
  assert.throws(() => getKEM(0x0001), UnsupportedAlgorithm); // ML-KEM-512
  assert.throws(() => getKEM(0x0003), UnsupportedAlgorithm); // ML-KEM-1024
  assert.throws(() => getSig(0x0001), UnsupportedAlgorithm); // ML-DSA-44
  assert.throws(() => getSig(0x0003), UnsupportedAlgorithm); // ML-DSA-87
  assert.throws(() => getSig(0x0100), UnsupportedAlgorithm); // Falcon-512
  assert.throws(() => getSig(0x0200), UnsupportedAlgorithm); // SLH-DSA-SHA2-128s
});

test("core mode listSupported: 1 KEM, 2 sig (none + ML-DSA-65)", () => {
  boot("core");
  const caps = listSupported();
  assert.strictEqual(caps.kem.length, 1);
  assert.strictEqual(caps.sig.length, 2);
  assert.strictEqual(caps.sig[0].id, 0x0000);
  assert.strictEqual(caps.sig[0].name, "none");
  assert.strictEqual(caps.sig[1].name, "ML-DSA-65");
  assert.strictEqual(caps.kem[0].name, "ML-KEM-768");
});

// --- extended mode ----------------------------------------------------------

test("extended mode registers ML-KEM-512 at id 0x0001", () => {
  boot("extended");
  assert.strictEqual(getKEM(0x0001).name, "ML-KEM-512");
  assert.strictEqual(hasKEM(0x0001), true);
});

test("extended mode registers ML-KEM-768 at id 0x0002", () => {
  boot("extended");
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(hasKEM(0x0002), true);
});

test("extended mode registers ML-KEM-1024 at id 0x0003", () => {
  boot("extended");
  assert.strictEqual(getKEM(0x0003).name, "ML-KEM-1024");
  assert.strictEqual(hasKEM(0x0003), true);
});

test("extended mode registers ML-DSA-44 at id 0x0001", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0001).name, "ML-DSA-44");
  assert.strictEqual(hasSig(0x0001), true);
});

test("extended mode registers ML-DSA-65 at id 0x0002", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
  assert.strictEqual(hasSig(0x0002), true);
});

test("extended mode registers ML-DSA-87 at id 0x0003", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0003).name, "ML-DSA-87");
  assert.strictEqual(hasSig(0x0003), true);
});

test("extended mode registers Falcon-512 at id 0x0100", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0100).name, "Falcon-512");
  assert.strictEqual(hasSig(0x0100), true);
});

test("extended mode registers Falcon-1024 at id 0x0101", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0101).name, "Falcon-1024");
  assert.strictEqual(hasSig(0x0101), true);
});

test("extended mode registers SLH-DSA SHA-2 family at 0x0200..0x0205", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0200).name, "SLH-DSA-SHA2-128s");
  assert.strictEqual(getSig(0x0201).name, "SLH-DSA-SHA2-128f");
  assert.strictEqual(getSig(0x0202).name, "SLH-DSA-SHA2-192s");
  assert.strictEqual(getSig(0x0203).name, "SLH-DSA-SHA2-192f");
  assert.strictEqual(getSig(0x0204).name, "SLH-DSA-SHA2-256s");
  assert.strictEqual(getSig(0x0205).name, "SLH-DSA-SHA2-256f");
});

test("extended mode registers SLH-DSA SHAKE family at 0x0206..0x020B", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0206).name, "SLH-DSA-SHAKE-128s");
  assert.strictEqual(getSig(0x0207).name, "SLH-DSA-SHAKE-128f");
  assert.strictEqual(getSig(0x0208).name, "SLH-DSA-SHAKE-192s");
  assert.strictEqual(getSig(0x0209).name, "SLH-DSA-SHAKE-192f");
  assert.strictEqual(getSig(0x020A).name, "SLH-DSA-SHAKE-256s");
  assert.strictEqual(getSig(0x020B).name, "SLH-DSA-SHAKE-256f");
});

test("slow-signing SLH-DSA 's' variants carry performance_hint=slow_signing", () => {
  boot("extended");
  const slowIds = [0x0200, 0x0202, 0x0204, 0x0206, 0x0208, 0x020A];
  for (const id of slowIds) {
    assert.strictEqual(
      getSig(id).performance_hint, "slow_signing",
      `sig 0x${id.toString(16)} should have performance_hint=slow_signing`
    );
  }
});

test("fast SLH-DSA 'f' variants and Falcon have no performance_hint", () => {
  boot("extended");
  const fastIds = [0x0100, 0x0101, 0x0201, 0x0203, 0x0205, 0x0207, 0x0209, 0x020B];
  for (const id of fastIds) {
    assert.strictEqual(
      getSig(id).performance_hint, undefined,
      `sig 0x${id.toString(16)} should not have performance_hint`
    );
  }
});

test("ML-DSA entries have no performance_hint", () => {
  boot("extended");
  assert.strictEqual(getSig(0x0001).performance_hint, undefined);
  assert.strictEqual(getSig(0x0002).performance_hint, undefined);
  assert.strictEqual(getSig(0x0003).performance_hint, undefined);
});

test("extended listSupported emits performance_hint only on slow entries", () => {
  boot("extended");
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

test("extended listSupported counts (3 KEM, 18 sig including none)", () => {
  boot("extended");
  const caps = listSupported();
  // 3 KEM: ML-KEM-512, 768, 1024
  // 18 sig: none + 3 ML-DSA + 2 Falcon + 12 SLH-DSA
  assert.strictEqual(caps.kem.length, 3);
  assert.strictEqual(caps.sig.length, 18);
  assert.strictEqual(caps.sig[0].id, 0x0000);
  assert.strictEqual(caps.sig[0].name, "none");
});

// --- mode resolution + idempotence -----------------------------------------

test("explicit arg overrides env", () => {
  resetBootstrap();
  const prev = process.env.CRYPTO_MODE;
  process.env.CRYPTO_MODE = "core";
  try {
    assert.strictEqual(bootstrap("extended"), "extended");
    assert.strictEqual(getKEM(0x0001).name, "ML-KEM-512");
  } finally {
    if (prev !== undefined) process.env.CRYPTO_MODE = prev; else delete process.env.CRYPTO_MODE;
  }
});

test("invalid mode throws", () => {
  resetBootstrap();
  assert.throws(() => bootstrap("paranoid"), /Invalid CRYPTO_MODE/);
});

test("bootstrap is idempotent -- repeated calls do not throw or re-register", () => {
  boot("extended");
  assert.doesNotThrow(() => { bootstrap(); bootstrap("core"); });
  // mode stays the first-resolved value; a later call does not switch it
  assert.strictEqual(getActiveMode(), "extended");
  assert.strictEqual(getKEM(0x0002).name, "ML-KEM-768");
  assert.strictEqual(getSig(0x0002).name, "ML-DSA-65");
});

test("unloaded algorithm ids throw UnsupportedAlgorithm", () => {
  boot("extended");
  // 0x0100 KEM slot is unused (Falcon is a SIG, not a KEM)
  assert.throws(() => getKEM(0x0100), UnsupportedAlgorithm);
  // 0x0300+ reserved for future algorithms, not yet loaded
  assert.throws(() => getSig(0x0300), UnsupportedAlgorithm);
});
