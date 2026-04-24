const { ml_dsa44 } = require("@noble/post-quantum/ml-dsa.js");

module.exports = {
  name: "ML-DSA-44",
  pubKeySize: 1312,
  secretKeySize: 2560,
  sigSize: 2420,

  generateKeyPair() {
    const { publicKey, secretKey } = ml_dsa44.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return ml_dsa44.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 1312) {
      throw new Error(`ML-DSA-44 public key must be 1312 bytes, got ${publicKey.length}`);
    }
    return ml_dsa44.verify(signature, message, publicKey);
  }
};
