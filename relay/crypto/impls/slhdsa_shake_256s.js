const { slh_dsa_shake_256s } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHAKE-256s",
  pubKeySize: 64,
  secretKeySize: 128,
  sigSize: 29792,
  performance_hint: "slow_signing",

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_shake_256s.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_shake_256s.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 64) {
      throw new Error(`SLH-DSA-SHAKE-256s public key must be 64 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_shake_256s.verify(signature, message, publicKey);
  }
};
