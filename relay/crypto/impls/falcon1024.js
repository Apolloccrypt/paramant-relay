const { falcon1024 } = require("@noble/post-quantum/falcon.js");

module.exports = {
  name: "Falcon-1024",
  pubKeySize: 1793,
  secretKeySize: 2305,
  // Falcon signatures are variable length (FIPS 206). 1280 is the maximum.
  sigSize: 1280,

  generateKeyPair() {
    const { publicKey, secretKey } = falcon1024.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return falcon1024.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 1793) {
      throw new Error(`Falcon-1024 public key must be 1793 bytes, got ${publicKey.length}`);
    }
    return falcon1024.verify(signature, message, publicKey);
  }
};
