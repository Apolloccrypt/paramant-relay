const { slh_dsa_shake_192f } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHAKE-192f",
  pubKeySize: 48,
  secretKeySize: 96,
  sigSize: 35664,

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_shake_192f.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_shake_192f.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 48) {
      throw new Error(`SLH-DSA-SHAKE-192f public key must be 48 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_shake_192f.verify(signature, message, publicKey);
  }
};
