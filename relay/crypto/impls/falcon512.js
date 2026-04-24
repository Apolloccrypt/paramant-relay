const { falcon512 } = require("@noble/post-quantum/falcon.js");

module.exports = {
  name: "Falcon-512",
  pubKeySize: 897,
  secretKeySize: 1281,
  // Falcon signatures are variable length (FIPS 206). 666 is the maximum.
  sigSize: 666,

  generateKeyPair() {
    const { publicKey, secretKey } = falcon512.keygen();
    return { publicKey, secretKey };
  },

  sign(message, secretKey) {
    return falcon512.sign(message, secretKey);
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 897) {
      throw new Error(`Falcon-512 public key must be 897 bytes, got ${publicKey.length}`);
    }
    return falcon512.verify(signature, message, publicKey);
  }
};
