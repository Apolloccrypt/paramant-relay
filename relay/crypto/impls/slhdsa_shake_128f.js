const { slh_dsa_shake_128f } = require("@noble/post-quantum/slh-dsa.js");

module.exports = {
  name: "SLH-DSA-SHAKE-128f",
  pubKeySize: 32,
  secretKeySize: 64,
  sigSize: 17088,

  generateKeyPair() {
    const { publicKey, secretKey } = slh_dsa_shake_128f.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return slh_dsa_shake_128f.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 32) {
      throw new Error(`SLH-DSA-SHAKE-128f public key must be 32 bytes, got ${publicKey.length}`);
    }
    return slh_dsa_shake_128f.verify(signature, message, publicKey);
  }
};
