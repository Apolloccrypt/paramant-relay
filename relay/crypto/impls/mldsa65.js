const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa.js");

module.exports = {
  name: "ML-DSA-65",
  pubKeySize: 1952,
  secretKeySize: 4032,
  sigSize: 3309,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return ml_dsa65.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 1952) {
      throw new Error(`ML-DSA-65 public key must be 1952 bytes, got ${publicKey.length}`);
    }
    return ml_dsa65.verify(signature, message, publicKey);
  }
};
