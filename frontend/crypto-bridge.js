/**
 * crypto-bridge.js — wraps the Rust/WASM hybrid KEM (ML-KEM-768 + ECDH P-256 + AES-256-GCM)
 * and re-exports the same API that parashare.html uses internally.
 *
 * Wire format (matches JS side exactly):
 *   0x02 | u32be(ctKemLen) | ctKem | u32be(senderPubLen) | senderPub | nonce(12) | u32be(ctLen) | ct
 * Padded to 5 MB with random bytes.
 */

import init, { encrypt_blob, decrypt_blob } from './pkg/paramant_crypto.js';

let _ready = null;

/** Ensure WASM is initialised exactly once. */
export async function initCrypto() {
  if (!_ready) _ready = init();
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
 * @returns {Promise<Uint8Array>} plaintext
 */
export async function decryptBlob(blob, kemPriv, ecdhPriv) {
  await initCrypto();
  return decrypt_blob(blob, kemPriv, ecdhPriv);
}
