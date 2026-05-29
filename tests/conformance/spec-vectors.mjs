// Spec-anchored constants. Every value here is transcribed from
// docs/wire-format-v1.md — NOT derived from any implementation. The whole
// point of this suite is that the spec is the source of truth and the three
// implementations are checked against it, never against each other-as-oracle.
//
// Citations are to docs/wire-format-v1.md line/section as of origin/main
// (commit 42040e1). If you change the spec, change these and the line refs.

// ── Algorithm IDs (spec §"Algorithm registry", lines 138-150) ───────────────
export const KEM_ML_KEM_768 = 0x0002; // spec line 139
export const SIG_NONE = 0x0000;       // spec line 148
export const SIG_ML_DSA_65 = 0x0002;  // spec line 150

// ── Header constants (spec §"Wire format", lines 32-36 + §encoder 254-258) ──
export const MAGIC_HEX = '50514842';  // 'PQHB'  spec line 32 / 254
export const VERSION = 0x01;          // spec line 33 / 255
export const HEADER_SIZE = 10;        // spec line 31
export const NONCE_SIZE = 12;         // spec line 49 / 268

// ── HKDF / envelope contract (sdk-js index.js:547, sdk-py crypto.py:114) ────
// The info string MUST be byte-identical across SDKs or derived AES keys
// diverge and every cross-SDK message fails to decrypt.
export const HKDF_INFO = 'paramant-v1-aes-key';

// Repeat a hex byte-pattern N times → Uint8Array. Spec line 341 notation:
// "<pattern> × N" means the hex pattern repeated N times.
export function repeatHex(patternHex, times) {
  const unit = Buffer.from(patternHex, 'hex');
  return new Uint8Array(Buffer.concat(Array.from({ length: times }, () => unit)));
}

// ── Test vector 1: signed blob, ML-KEM-768 + ML-DSA-65 (spec §343-362) ──────
export const VECTOR_SIGNED = {
  name: 'spec test vector 1 — signed (ML-KEM-768 + ML-DSA-65)',
  specSection: 'docs/wire-format-v1.md §"Test vector 1" (lines 343-362)',
  kemId: KEM_ML_KEM_768,
  sigId: SIG_ML_DSA_65,
  ctKem: repeatHex('00112233445566778899aabbccddeeff', 68), // 1088 B, spec 351
  senderPub: repeatHex('cafe', 296),                        //  592 B, spec 352
  signature: repeatHex('babe', 1654),                       // 3308 B, spec 353
  nonce: Buffer.from('000102030405060708090a0b', 'hex'),    //   12 B, spec 354
  ciphertext: repeatHex('deadbeef', 16),                    //   64 B, spec 355
  expect: {
    totalLen: 5090,                                         // spec line 359
    header10Hex: '50514842010002000200',                    // spec line 360
    sha256Hex: '002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a', // spec 362
  },
};

// ── Test vector 2: anonymous blob, ML-KEM-768, no signature (spec §364-383) ─
export const VECTOR_ANON = {
  name: 'spec test vector 2 — anonymous (ML-KEM-768, no signature)',
  specSection: 'docs/wire-format-v1.md §"Test vector 2" (lines 364-383)',
  kemId: KEM_ML_KEM_768,
  sigId: SIG_NONE,
  ctKem: repeatHex('00112233445566778899aabbccddeeff', 68), // 1088 B, spec 372
  senderPub: repeatHex('cafe', 296),                        //  592 B, spec 373
  signature: null,                                          // omitted, spec 374
  nonce: Buffer.from('000102030405060708090a0b', 'hex'),    //   12 B, spec 375
  ciphertext: repeatHex('deadbeef', 16),                    //   64 B, spec 376
  expect: {
    totalLen: 1778,                                         // spec line 380
    header10Hex: '50514842010002000000',                    // spec line 381
    sha256Hex: '46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef', // spec 383
  },
};

// ── AAD construction (spec §"GCM AAD", lines 80 + 330) ──────────────────────
// AAD = header_bytes[0:10] || uint32_be(chunk_index)
export function buildAAD({ kemId, sigId, flags = 0x00, chunkIndex = 0 }) {
  const buf = Buffer.alloc(HEADER_SIZE + 4);
  Buffer.from(MAGIC_HEX, 'hex').copy(buf, 0);
  buf.writeUInt8(VERSION, 4);
  buf.writeUInt16BE(kemId, 5);
  buf.writeUInt16BE(sigId, 7);
  buf.writeUInt8(flags, 9);
  buf.writeUInt32BE(chunkIndex, HEADER_SIZE);
  return new Uint8Array(buf);
}

// ── Sender-authentication signature input (spec §"Signature input", line 92) ─
// sign_input = CT_KEM || SENDER_PUB || NONCE || CIPHERTEXT || AAD
// Pins the exact concatenation order. sdk-js index.js:573 and sdk-py
// _canonical_sign_input (paramant_sdk.py:160) MUST both produce these bytes.
export function buildSignInput({ ctKem, senderPub, nonce, ciphertext, aad }) {
  return new Uint8Array(Buffer.concat([
    Buffer.from(ctKem), Buffer.from(senderPub), Buffer.from(nonce),
    Buffer.from(ciphertext), Buffer.from(aad),
  ]));
}

// ── canonicalJSON anchors (sdk-js index.js:154, sdk-py paramant_sdk.py:800,
//    relay parasign.js canonicalJSON) ──────────────────────────────────────
// Contract: recursively sorted keys, no whitespace, JS JSON.stringify scalar
// rules == Python json.dumps(sort_keys=True, separators=(",",":")) FOR ASCII.
// Expected strings below are hand-derived from that documented rule, not from
// running any implementation.
export const CANONICAL_ASCII_CASES = [
  {
    name: 'flat, keys out of order',
    input: { b: 1, a: 2 },
    expect: '{"a":2,"b":1}',
  },
  {
    name: 'nested object + array + null + bool',
    input: { z: [3, 2, 1], a: { y: true, x: null } },
    expect: '{"a":{"x":null,"y":true},"z":[3,2,1]}',
  },
  {
    name: 'realistic ASCII relay receipt (the production shape)',
    input: {
      alg: 'ML-DSA-65',
      blob_sha256: 'abc123',
      relay: 'relay.paramant.app',
      ts: 1716900000,
    },
    expect: '{"alg":"ML-DSA-65","blob_sha256":"abc123","relay":"relay.paramant.app","ts":1716900000}',
  },
];

// Known, documented boundary: sdk-js canonicalJSON uses JSON.stringify (emits
// raw UTF-8 for non-ASCII) while sdk-py json.dumps defaults to ensure_ascii=
// True (emits \uXXXX). sdk-js index.js:153 explicitly scopes the equivalence
// to "ASCII receipts". This suite PINS that boundary so a future change to
// either side is caught, instead of pretending full Unicode interop exists.
export const CANONICAL_NONASCII_CASE = {
  name: 'non-ASCII payload (documented divergence boundary)',
  input: { msg: 'café', lock: '🔒' },
  jsExpect: '{"lock":"🔒","msg":"café"}',                    // JS JSON.stringify
  pyDefaultExpect: '{"lock":"\\ud83d\\udd12","msg":"caf\\u00e9"}', // py ensure_ascii=True
};
