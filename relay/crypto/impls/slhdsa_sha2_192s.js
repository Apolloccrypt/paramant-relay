const { slh_dsa_sha2_192s } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHA2-192s",
  pubKeySize: 48,
  secretKeySize: 96,
  sigSize: 16224,
  performance_hint: "slow_signing",

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_sha2_192s.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_sha2_192s.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 48) {
      throw new Error(`SLH-DSA-SHA2-192s public key must be 48 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_sha2_192s.verify(signature, message, publicKey);
  }
};
