/**
 * noble-mlkem-loader.js — loads the ML-KEM-768 JavaScript implementation and
 * exposes it as window.ml_kem768 for use in non-module <script> contexts.
 *
 * Only needed for KEY GENERATION (keygen). Encryption and decryption are
 * handled by crypto-bridge.js (WASM), which is faster and does the full
 * ML-KEM-768 + ECDH P-256 + AES-256-GCM hybrid in a single call.
 */
import { ml_kem768 } from './noble-mlkem-bundle.js';
window.ml_kem768 = ml_kem768;
document.dispatchEvent(new Event('mlkem-ready'));
