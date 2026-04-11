/**
 * crypto-bridge.js — wraps the Rust/WASM hybrid KEM (ML-KEM-768 + ECDH P-256 + AES-256-GCM)
 * and re-exports the same API that parashare.html, drop.html, and ontvang.html use.
 *
 * Wire format (produced by WASM, no AAD):
 *   0x02 | u32be(ctKemLen) | ctKem | u32be(senderPubLen) | senderPub | nonce(12) | u32be(ctLen) | ct
 * Padded to 5 MB with random bytes.
 *
 * Self-integrity: on first init, the WASM binary is fetched and its SHA-256 is checked
 * against WASM_SHA256 below. Throws if the hash does not match.
 */

import init, { encrypt_blob, decrypt_blob } from './pkg/paramant_crypto.js';

// SHA-256 of frontend/pkg/paramant_crypto_bg.wasm — update after each wasm-pack build.
const WASM_SHA256 = 'd009869a8e5eb64e8926a7c8527b15964eac2f075f3707504c596fb65067cc2a';

let _ready = null;

async function _verifyAndInit() {
  // Derive the WASM path relative to this module
  const wasmUrl = new URL('./pkg/paramant_crypto_bg.wasm', import.meta.url).href;
  const resp = await fetch(wasmUrl);
  if (!resp.ok) throw new Error('Failed to fetch WASM binary: ' + resp.status);
  const wasmBytes = await resp.arrayBuffer();

  // Compute SHA-256 and compare against hardcoded hash
  const hashBuf = await crypto.subtle.digest('SHA-256', wasmBytes);
  const hashHex = [...new Uint8Array(hashBuf)].map(b => b.toString(16).padStart(2, '0')).join('');
  if (hashHex !== WASM_SHA256) {
    throw new Error(
      'WASM integrity check failed.\n' +
      'Expected: ' + WASM_SHA256 + '\n' +
      'Got:      ' + hashHex + '\n' +
      'Do not proceed — the crypto binary may have been tampered with.'
    );
  }

  // Pass the already-fetched bytes to init() to avoid a second HTTP request
  // wasm-bindgen ≥ 0.2.91 requires object form { module_or_path: ... }
  return init({ module_or_path: wasmBytes });
}

/** Ensure WASM is initialised exactly once (with integrity check). */
export async function initCrypto() {
  if (!_ready) _ready = _verifyAndInit();
  return _ready;
}

/**
 * Encrypt plaintext for a receiver.
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} kemPub   - ML-KEM-768 public key, 1184 bytes
 * @param {Uint8Array} ecdhPub  - P-256 uncompressed public key, 65 bytes
 * @returns {Promise<Uint8Array>} 5 MB padded blob
 */
export async function encryptBlob(plaintext, kemPub, ecdhPub) {
  await initCrypto();
  return encrypt_blob(plaintext, kemPub, ecdhPub);
}

/**
 * Decrypt a blob produced by encryptBlob.
 * @param {Uint8Array} blob       - 5 MB padded ciphertext blob
 * @param {Uint8Array} kemPriv    - ML-KEM-768 secret key (noble format), 2400 bytes
 * @param {Uint8Array} ecdhPriv   - P-256 private key scalar, 32 bytes
 * @returns {Promise<Uint8Array>} plaintext (may include padding — strip trailing zeros)
 */
export async function decryptBlob(blob, kemPriv, ecdhPriv) {
  await initCrypto();
  return decrypt_blob(blob, kemPriv, ecdhPriv);
}
