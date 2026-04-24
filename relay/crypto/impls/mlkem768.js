const { ml_kem768 } = require("@noble/post-quantum/ml-kem.js");

module.exports = {
  name: "ML-KEM-768",
  pubKeySize: 1184,
  ctSize: 1088,
  secretKeySize: 2400,
  sharedSecretSize: 32,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_kem768.keygen();
    return { publicKey, secretKey };
  },

  encapsulate(publicKey) {
    if (publicKey.length !== 1184) {
      throw new Error(`ML-KEM-768 public key must be 1184 bytes, got ${publicKey.length}`);
    }
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    return { ciphertext: cipherText, sharedSecret };
  },

  decapsulate(ciphertext, secretKey) {
    if (ciphertext.length !== 1088) {
      throw new Error(`ML-KEM-768 ciphertext must be 1088 bytes, got ${ciphertext.length}`);
    }
    return ml_kem768.decapsulate(ciphertext, secretKey);
  }
};
