const { slh_dsa_sha2_128s } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHA2-128s",
  pubKeySize: 32,
  secretKeySize: 64,
  sigSize: 7856,
  performance_hint: "slow_signing",

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_sha2_128s.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_sha2_128s.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 32) {
      throw new Error(`SLH-DSA-SHA2-128s public key must be 32 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_sha2_128s.verify(signature, message, publicKey);
  }
};
