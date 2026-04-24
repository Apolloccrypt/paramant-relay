const { ml_dsa87 } = require("@noble/post-quantum/ml-dsa.js");

module.exports = {
  name: "ML-DSA-87",
  pubKeySize: 2592,
  secretKeySize: 4896,
  sigSize: 4627,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_dsa87.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return ml_dsa87.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 2592) {
      throw new Error(`ML-DSA-87 public key must be 2592 bytes, got ${publicKey.length}`);
    }
    return ml_dsa87.verify(signature, message, publicKey);
  }
};
