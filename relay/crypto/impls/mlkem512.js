const { ml_kem512 } = require("@noble/post-quantum/ml-kem.js");

module.exports = {
  name: "ML-KEM-512",
  pubKeySize: 800,
  ctSize: 768,
  secretKeySize: 1632,
  sharedSecretSize: 32,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_kem512.keygen();
    return { publicKey, secretKey };
  },

  encapsulate(publicKey) {
    if (publicKey.length !== 800) {
      throw new Error(`ML-KEM-512 public key must be 800 bytes, got ${publicKey.length}`);
    }
    const { cipherText, sharedSecret } = ml_kem512.encapsulate(publicKey);
    return { ciphertext: cipherText, sharedSecret };
  },

  decapsulate(ciphertext, secretKey) {
    if (ciphertext.length !== 768) {
      throw new Error(`ML-KEM-512 ciphertext must be 768 bytes, got ${ciphertext.length}`);
    }
    return ml_kem512.decapsulate(ciphertext, secretKey);
  }
};
