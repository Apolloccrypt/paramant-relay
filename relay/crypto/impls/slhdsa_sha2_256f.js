const { slh_dsa_sha2_256f } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHA2-256f",
  pubKeySize: 64,
  secretKeySize: 128,
  sigSize: 49856,

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_sha2_256f.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_sha2_256f.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 64) {
      throw new Error(`SLH-DSA-SHA2-256f public key must be 64 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_sha2_256f.verify(signature, message, publicKey);
  }
};
