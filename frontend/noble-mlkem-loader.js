/**
 * noble-mlkem-loader.js — loads the ML-KEM-768 JavaScript implementation and
 * exposes it as window.ml_kem768 for use in non-module <script> contexts.
 *
 * Only needed for KEY GENERATION (keygen). Encryption and decryption are
 * handled by crypto-bridge.js (WASM), which is faster and does the full
 * ML-KEM-768 + ECDH P-256 + AES-256-GCM hybrid in a single call.
 *
 * The import is document-root absolute on purpose. A relative specifier here
 * resolves against this file's URL: correct today, wrong the moment the file
 * moves — which is exactly how the ParaSend crypto bridge broke for three weeks
 * in July 2026. There is also a DIFFERENT, larger bundle at
 * /dist/noble-mlkem-bundle.js, so the leading slash also says which one we mean.
 */
import { ml_kem768 } from '/noble-mlkem-bundle.js';

window.ml_kem768 = ml_kem768;

// Sticky signal: a consumer that runs after this file still learns about it.
// A bare dispatchEvent here left /ontvang stuck on "Generating keypair..."
// from 2026-07-02 to 2026-07-28. See js/ready.js for the full story.
window.ready.signal('mlkem', ml_kem768);
