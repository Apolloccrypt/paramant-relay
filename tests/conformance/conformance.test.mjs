// SDK ↔ relay cross-implementation conformance suite.
//
// Proves, with the THREE REAL crypto stacks (no mocks, no KAT-only):
//   • noble    = @noble/post-quantum   (sdk-js crypto)
//   • pqcrypto = pqcrypto/PQClean      (sdk-py crypto)
//   • core     = @paramant/core NAPI   (relay crypto)
//
// that the shared wire-format v1, the sign_input order, the canonicalJSON
// receipt form, the HKDF info string, and ML-DSA/ML-KEM interop all agree.
// The spec (docs/wire-format-v1.md) is the oracle — see spec-vectors.mjs.
//
// Run:  node --test tests/conformance/conformance.test.mjs   (from repo root)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import * as cfg from './config.mjs';
import { call, IMPLS } from './lib/bus.mjs';
import {
  VECTOR_SIGNED, VECTOR_ANON, HKDF_INFO,
  buildAAD, buildSignInput,
  CANONICAL_ASCII_CASES, CANONICAL_NONASCII_CASE,
} from './spec-vectors.mjs';

const require = createRequire(import.meta.url);
const hexOf = (u8) => Buffer.from(u8).toString('hex');

// sdk-js canonicalJSON, verbatim from sdk-js/index.js:154 (it is an internal,
// non-exported function — embedded here with citation so the JS form is still
// checked against the spec anchor). See README "Known limitation".
function canonicalJSON_sdkjs(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON_sdkjs).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalJSON_sdkjs(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

// ── Preflight: all three real libs must actually load (else fail loudly) ────
test('preflight: the three real crypto stacks load (no mocks)', () => {
  cfg.requireDep('@noble/post-quantum (sdk-js crypto)', cfg.nobleDir,
    'Set PARAMANT_NOBLE_DIR.');
  cfg.requireDep('@paramant/core NAPI binding (relay crypto)', cfg.coreNode,
    'Set PARAMANT_CORE_NODE to the built index.node.');
  cfg.requireDep('Python+pqcrypto (sdk-py crypto)', cfg.python,
    'Set PARAMANT_PY to a venv python with pqcrypto + cryptography.');
  for (const impl of IMPLS) {
    const r = call(impl, 'kem-keygen');
    assert.equal(Buffer.from(r.pubHex, 'hex').length, 1184, `${impl} ML-KEM-768 pubkey size`);
  }
});

// ── Roundtrip 1: wire-format v1 byte-exact vs docs/wire-format-v1.md ─────────
// Each shipped wire implementation encodes the spec's own test vectors; the
// SHA-256, length and header must match the spec's stated values exactly.
const WIRE_IMPLS = [
  { impl: 'noble', label: 'sdk-js/src/wire-format.js', src: cfg.sdkJsWire },
  { impl: 'pqcrypto', label: 'sdk-py/paramant/wire_format.py', src: cfg.sdkPyDir },
  { impl: 'core', label: 'relay/crypto/wire-format.js', src: cfg.relayWire },
];

for (const { impl, label, src } of WIRE_IMPLS) {
  for (const V of [VECTOR_SIGNED, VECTOR_ANON]) {
    test(`RT1 wire-exact · ${label} · ${V.name}`, { skip: src ? false : `${label} not present in this repo (expected in the other repo)` }, () => {
      const r = call(impl, 'wire-encode', {
        kemId: V.kemId, sigId: V.sigId,
        ctKemHex: hexOf(V.ctKem), senderPubHex: hexOf(V.senderPub),
        signatureHex: V.signature ? hexOf(V.signature) : null,
        nonceHex: hexOf(V.nonce), ciphertextHex: hexOf(V.ciphertext),
      });
      assert.equal(r.len, V.expect.totalLen, `total length (spec: ${V.specSection})`);
      assert.equal(r.blobHex.slice(0, 20), V.expect.header10Hex, 'header[0:10]');
      assert.equal(r.sha256Hex, V.expect.sha256Hex,
        `SHA-256 must match spec exactly — drift here means this impl is NOT wire-conformant (${V.specSection})`);
    });
  }
}

// ── Roundtrip 2: canonicalJSON byte-identical across impls ──────────────────
for (const c of CANONICAL_ASCII_CASES) {
  test(`RT2 canonicalJSON · ${c.name}`, () => {
    const expectBytes = Buffer.from(c.expect, 'utf8').toString('hex');

    // sdk-js form (embedded, cited)
    assert.equal(canonicalJSON_sdkjs(c.input), c.expect, 'sdk-js canonicalJSON');

    // real relay impl (relay/parasign.js) when present
    if (cfg.relayParasign) {
      const { canonicalJSON } = require(cfg.relayParasign);
      assert.equal(canonicalJSON(c.input), c.expect, 'relay parasign.js canonicalJSON');
    }

    // real sdk-py form via adapter
    const py = call('pqcrypto', 'canonical', { value: c.input });
    assert.equal(py.bytesHex, expectBytes, 'sdk-py json.dumps(sort_keys,separators)');
  });
}

// Documented ASCII-only boundary — pin it instead of pretending Unicode interop.
test('RT2 canonicalJSON · non-ASCII divergence boundary (documented)', () => {
  const C = CANONICAL_NONASCII_CASE;
  assert.equal(canonicalJSON_sdkjs(C.input), C.jsExpect, 'sdk-js emits raw UTF-8');
  const py = call('pqcrypto', 'canonical', { value: C.input });
  const pyStr = Buffer.from(py.bytesHex, 'hex').toString('utf8');
  assert.equal(pyStr, C.pyDefaultExpect, 'sdk-py json.dumps escapes non-ASCII (ensure_ascii default)');
  assert.notEqual(canonicalJSON_sdkjs(C.input), pyStr,
    'EXPECTED divergence: sdk-js (raw UTF-8) ≠ sdk-py (\\uXXXX). Receipts MUST stay ASCII ' +
    'or signatures will not verify cross-SDK. sdk-js index.js:153 scopes the equivalence to ASCII.');
});

// ── Roundtrip 3: ML-DSA-65 cross-impl sign/verify (Vlak A + Vlak B) ─────────
// Vlak A: the wire-blob sender signature over
//   ct_kem || sender_pub || nonce || ciphertext || aad   (spec line 92)
// Vlak B: the ParaSign/relay receipt over canonicalJSON(receipt).
// Each impl signs with its OWN freshly generated keypair (mirrors reality:
// every party signs with its own lib); every other impl must verify it.
const aadA = buildAAD({ kemId: VECTOR_SIGNED.kemId, sigId: VECTOR_SIGNED.sigId, chunkIndex: 0 });
const MSG_A = hexOf(buildSignInput({
  ctKem: VECTOR_SIGNED.ctKem, senderPub: VECTOR_SIGNED.senderPub,
  nonce: VECTOR_SIGNED.nonce, ciphertext: VECTOR_SIGNED.ciphertext, aad: aadA,
}));
const MSG_B = Buffer.from(
  canonicalJSON_sdkjs({ alg: 'ML-DSA-65', blob_sha256: 'abc123', relay: 'relay.paramant.app', ts: 1716900000 }),
  'utf8').toString('hex');

for (const signImpl of IMPLS) {
  test(`RT3 ML-DSA-65 · signed by ${signImpl} → verified by all impls`, () => {
    const kp = call(signImpl, 'sig-keygen');
    assert.equal(Buffer.from(kp.pubHex, 'hex').length, 1952, 'ML-DSA-65 pubkey size');

    for (const [label, msgHex] of [['VlakA wire-sign_input', MSG_A], ['VlakB canonicalJSON receipt', MSG_B]]) {
      const sg = call(signImpl, 'sig-sign', { skHex: kp.skHex, msgHex });
      assert.equal(Buffer.from(sg.sigHex, 'hex').length, 3309, 'ML-DSA-65 signature size');
      for (const verifyImpl of IMPLS) {
        const v = call(verifyImpl, 'sig-verify', { pubHex: kp.pubHex, msgHex, sigHex: sg.sigHex });
        assert.equal(v.valid, true,
          `${signImpl}-signed ${label} must verify under ${verifyImpl} — false = cross-impl signature DRIFT`);
      }
      // negative control: a one-byte tamper must be rejected by every verifier
      const tampered = flipFirstByte(msgHex);
      for (const verifyImpl of IMPLS) {
        const v = call(verifyImpl, 'sig-verify', { pubHex: kp.pubHex, msgHex: tampered, sigHex: sg.sigHex });
        assert.equal(v.valid, false, `${verifyImpl} must reject tampered ${label}`);
      }
    }
  });
}
function flipFirstByte(hex) {
  const b = Buffer.from(hex, 'hex');
  b[0] = b[0] ^ 0xff;
  return b.toString('hex');
}

// ── Roundtrip 4a: ML-KEM-768 cross-impl encaps/decaps ───────────────────────
// Recipient keygen+decaps with one impl; sender encaps with another; the
// shared secret derived on each side must be byte-identical.
for (const recipImpl of IMPLS) {
  test(`RT4a ML-KEM-768 · recipient ${recipImpl} ← encaps by all impls`, () => {
    const kp = call(recipImpl, 'kem-keygen');
    for (const sendImpl of IMPLS) {
      const enc = call(sendImpl, 'kem-encaps', { pubHex: kp.pubHex });
      const dec = call(recipImpl, 'kem-decaps', { skHex: kp.skHex, ctHex: enc.ctHex });
      assert.equal(Buffer.from(enc.ssHex, 'hex').length, 32, 'shared secret 32 bytes');
      assert.equal(dec.ssHex, enc.ssHex,
        `shared secret mismatch: ${sendImpl} encaps vs ${recipImpl} decaps — KEM cross-impl DRIFT`);
    }
  });
}

// ── Roundtrip 4b: HKDF(info='paramant-v1-aes-key') + AES-256-GCM envelope ────
// Client-only contract (the relay stores blobs opaquely, never decrypts — so
// 'core' is intentionally absent here). sdk-js (WebCrypto) ⇄ sdk-py (pyca).
test('RT4b envelope · HKDF info + AES-GCM interop (sdk-js ⇄ sdk-py)', () => {
  // Use a real ML-KEM shared secret + salt = ctKem[0:32] (sdk-js index.js:544).
  const kp = call('core', 'kem-keygen');
  const enc = call('noble', 'kem-encaps', { pubHex: kp.pubHex });
  const ss = enc.ssHex;
  const saltHex = enc.ctHex.slice(0, 64); // first 32 bytes
  const aadHex = hexOf(buildAAD({ kemId: VECTOR_SIGNED.kemId, sigId: VECTOR_SIGNED.sigId, chunkIndex: 0 }));
  const nonceHex = '000102030405060708090a0b';
  const ptHex = Buffer.from('the eagle lands at midnight', 'utf8').toString('hex');

  const keyJS = call('noble', 'hkdf', { ssHex: ss, saltHex, info: HKDF_INFO }).keyHex;
  const keyPY = call('pqcrypto', 'hkdf', { ssHex: ss, saltHex, info: HKDF_INFO }).keyHex;
  assert.equal(keyJS, keyPY, `HKDF derived key mismatch — info string '${HKDF_INFO}' or salt convention drifted`);

  // sdk-js encrypts → sdk-py decrypts
  const ctJS = call('noble', 'aead-encrypt', { keyHex: keyJS, nonceHex, ptHex, aadHex }).ctHex;
  const back1 = call('pqcrypto', 'aead-decrypt', { keyHex: keyPY, nonceHex, ctHex: ctJS, aadHex }).ptHex;
  assert.equal(back1, ptHex, 'sdk-js-encrypted blob must decrypt under sdk-py');

  // sdk-py encrypts → sdk-js decrypts
  const ctPY = call('pqcrypto', 'aead-encrypt', { keyHex: keyPY, nonceHex, ptHex, aadHex }).ctHex;
  const back2 = call('noble', 'aead-decrypt', { keyHex: keyJS, nonceHex, ctHex: ctPY, aadHex }).ptHex;
  assert.equal(back2, ptHex, 'sdk-py-encrypted blob must decrypt under sdk-js');

  // negative: wrong AAD must fail GCM tag (spec lines 83/335)
  const wrongAad = flipFirstByte(aadHex);
  assert.throws(() => call('pqcrypto', 'aead-decrypt', { keyHex: keyPY, nonceHex, ctHex: ctJS, aadHex: wrongAad }),
    'GCM must reject a tampered AAD (header integrity binding)');
});

// ── Documentation test: AES/HKDF is off the relay path, not silently skipped ─
test('RT4b note · relay crypto (core) does not implement the AES/HKDF envelope', () => {
  assert.throws(() => call('core', 'hkdf', { ssHex: '00'.repeat(32), saltHex: '00'.repeat(32), info: HKDF_INFO }),
    /off the relay path/i,
    'core must explicitly report AES/HKDF as off-path (relay stores blobs opaquely), not fake a value');
});
