const { ml_kem1024 } = require("@noble/post-quantum/ml-kem.js");

module.exports = {
  name: "ML-KEM-1024",
  pubKeySize: 1568,
  ctSize: 1568,
  secretKeySize: 3168,
  sharedSecretSize: 32,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_kem1024.keygen();
    return { publicKey, secretKey };
  },

  encapsulate(publicKey) {
    if (publicKey.length !== 1568) {
      throw new Error(`ML-KEM-1024 public key must be 1568 bytes, got ${publicKey.length}`);
    }
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(publicKey);
    return { ciphertext: cipherText, sharedSecret };
  },

  decapsulate(ciphertext, secretKey) {
    if (ciphertext.length !== 1568) {
      throw new Error(`ML-KEM-1024 ciphertext must be 1568 bytes, got ${ciphertext.length}`);
    }
    return ml_kem1024.decapsulate(ciphertext, secretKey);
  }
};
