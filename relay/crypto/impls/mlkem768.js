// ML-KEM-768 via @paramant/core (Rust PQ-crypto core, NAPI binding). Byte-
// compatible with the previous @noble/post-quantum implementation: same 1184/
// 2400/1088/32 sizes and FIPS 203 wire bytes (verified by 149 relay-anchored
// KAT interop checks in paramant-core). Returns Uint8Array to match the prior
// return type exactly. See paramant-core docs/deploy-bridge.md (M5b).
const core = require("@paramant/core");

module.exports = {
  name: "ML-KEM-768",
  pubKeySize: 1184,
  ctSize: 1088,
  secretKeySize: 2400,
  sharedSecretSize: 32,

  generateKeyPair() {
    const { publicKey, secretKey } = core.kemKeygen();
    return { publicKey: new Uint8Array(publicKey), secretKey: new Uint8Array(secretKey) };
  },

  encapsulate(publicKey) {
    if (publicKey.length !== 1184) {
      throw new Error(`ML-KEM-768 public key must be 1184 bytes, got ${publicKey.length}`);
    }
    const { ciphertext, sharedSecret } = core.kemEncaps(Buffer.from(publicKey));
    return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(sharedSecret) };
  },

  decapsulate(ciphertext, secretKey) {
    if (ciphertext.length !== 1088) {
      throw new Error(`ML-KEM-768 ciphertext must be 1088 bytes, got ${ciphertext.length}`);
    }
    // @paramant/core kemDecaps takes (secretKey, ciphertext) -- the reverse of
    // this function's (ciphertext, secretKey) argument order.
    return new Uint8Array(core.kemDecaps(Buffer.from(secretKey), Buffer.from(ciphertext)));
  }
};
