// ML-DSA-65 via @paramant/core (Rust PQ-crypto core, NAPI binding). Byte-
// compatible with the previous @noble/post-quantum implementation: same
// 1952/4032/3309 sizes and FIPS 204 wire bytes (cross-impl byte-equivalence
// proven in paramant-core ADR-0021, 50/50 verify-KAT + seeded-keygen KAT
// against the same @noble-anchored vectors). Returns Uint8Array to match the
// prior return type exactly. Same migration pattern as mlkem768.js (M5b).
const core = require("@paramant/core");

module.exports = {
  name: "ML-DSA-65",
  pubKeySize: 1952,
  secretKeySize: 4032,
  sigSize: 3309,

  generateKeyPair() {
    const { publicKey, secretKey } = core.mldsaKeygen();
    return { publicKey: new Uint8Array(publicKey), secretKey: new Uint8Array(secretKey) };
  },

  sign(message, secretKey) {
    // @paramant/core mldsaSign takes (secretKey, message) -- the reverse of
    // this function's (message, secretKey) argument order.
    return new Uint8Array(core.mldsaSign(Buffer.from(secretKey), Buffer.from(message)));
  },

  verify(signature, message, publicKey) {
    if (publicKey.length !== 1952) {
      throw new Error(`ML-DSA-65 public key must be 1952 bytes, got ${publicKey.length}`);
    }
    // @paramant/core mldsaVerify takes (publicKey, message, signature) -- a
    // different order than this function's (signature, message, publicKey).
    return core.mldsaVerify(Buffer.from(publicKey), Buffer.from(message), Buffer.from(signature));
  }
};
