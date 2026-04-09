/**
 * crypto-wasm/test.js — WASM roundtrip smoke test
 *
 * Generates a real ML-KEM-768 + ECDH P-256 keypair (via noble-mlkem-bundle.js),
 * encrypts a test payload using the WASM, decrypts it back, and asserts equality.
 *
 * Usage:
 *   node crypto-wasm/test.js
 *
 * Requires:
 *   - crypto-wasm/pkg/ built (run: cd crypto-wasm && wasm-pack build --target web --out-dir pkg)
 *   - frontend/noble-mlkem-bundle.js (vendored noble/post-quantum)
 *   - Node.js >= 18 (has globalThis.crypto with getRandomValues + subtle)
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const __dir = path.dirname(fileURLToPath(import.meta.url));

// ── Load noble ML-KEM-768 for keygen ────────────────────────────────────────
// noble-mlkem-bundle.js is a browser bundle — we load it via dynamic eval so
// it can use globalThis.crypto which Node 18+ exposes.
const bundleSrc = readFileSync(path.join(__dir, '../frontend/noble-mlkem-bundle.js'), 'utf8');
const bundleExports = {};
const mod = new Function('exports', bundleSrc + '; Object.assign(exports, { ml_kem768 });');
mod(bundleExports);
const { ml_kem768 } = bundleExports;

if (!ml_kem768?.keygen) {
  console.error('FAIL: noble-mlkem-bundle.js did not export ml_kem768.keygen');
  process.exit(1);
}

// ── Load WASM ────────────────────────────────────────────────────────────────
// wasm-pack --target web generates an init() that accepts a WASM buffer.
// We read the binary manually and pass it to init().
const wasmJsPath = path.join(__dir, 'pkg/paramant_crypto.js');
const wasmBinPath = path.join(__dir, 'pkg/paramant_crypto_bg.wasm');

// Patch import.meta.url before importing the generated glue code
// (the glue code uses import.meta.url to locate the WASM file when no arg is given)
const wasmModule = await import(wasmJsPath);
const { default: initWasm, encrypt_blob, decrypt_blob } = wasmModule;

const wasmBin = readFileSync(wasmBinPath);
await initWasm(wasmBin.buffer);

// ── Keygen ───────────────────────────────────────────────────────────────────
console.log('Generating ML-KEM-768 keypair...');
const { publicKey: kemPub, secretKey: kemSec } = ml_kem768.keygen();

console.log('Generating ECDH P-256 keypair...');
const ecdhPair = await globalThis.crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
);
const ecdhPubRaw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', ecdhPair.publicKey));
const ecdhSecJwk = await globalThis.crypto.subtle.exportKey('jwk', ecdhPair.privateKey);
// Extract 32-byte scalar from JWK d (base64url)
const b64urlToU8 = s => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length/4)*4, '=');
  return Uint8Array.from(Buffer.from(b64, 'base64'));
};
const ecdhPrivRaw = b64urlToU8(ecdhSecJwk.d);

// ── Encrypt ──────────────────────────────────────────────────────────────────
const plaintext = new TextEncoder().encode('Hello, post-quantum world! ' + Date.now());
console.log('Encrypting', plaintext.length, 'bytes...');
const encrypted = encrypt_blob(plaintext, kemPub, ecdhPubRaw);
console.log('Encrypted blob size:', encrypted.length, 'bytes (expected 5242880)');

if (encrypted.length !== 5 * 1024 * 1024) {
  console.error('FAIL: unexpected encrypted blob size', encrypted.length);
  process.exit(1);
}
if (encrypted[0] !== 0x02) {
  console.error('FAIL: unexpected magic byte', encrypted[0].toString(16));
  process.exit(1);
}

// ── Decrypt ──────────────────────────────────────────────────────────────────
console.log('Decrypting...');
const decrypted = decrypt_blob(encrypted, kemSec, ecdhPrivRaw);

// The WASM decrypt_blob may return the full 5MB buffer or just the plaintext.
// Compare the first plaintext.length bytes.
const decryptedText = new TextDecoder().decode(decrypted.slice(0, plaintext.length));
const original = new TextDecoder().decode(plaintext);

if (decryptedText !== original) {
  console.error('FAIL: decrypted text does not match original');
  console.error('  original :', original);
  console.error('  decrypted:', decryptedText);
  process.exit(1);
}

console.log('');
console.log('✓ WASM roundtrip OK');
console.log('  plaintext :', original);
console.log('  encrypted : 5 MB padded blob, magic=0x02');
console.log('  decrypted : matches original');
console.log('');
console.log('All checks passed.');
