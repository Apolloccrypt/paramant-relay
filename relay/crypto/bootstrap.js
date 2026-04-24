// relay/crypto/bootstrap.js
// Registers the algorithms this relay supports. Called once at startup.
// To add a new algorithm: write an impl file, import here, register it.

const { registerKEM, registerSig } = require('./registry');
const mlkem768 = require('./impls/mlkem768');
const mldsa65 = require('./impls/mldsa65');
const mlkem512 = require('./impls/mlkem512');
const mlkem1024 = require('./impls/mlkem1024');
const mldsa44 = require('./impls/mldsa44');
const mldsa87 = require('./impls/mldsa87');
const falcon512 = require('./impls/falcon512');
const falcon1024 = require('./impls/falcon1024');
const slhdsa_sha2_128s = require('./impls/slhdsa_sha2_128s');
const slhdsa_sha2_128f = require('./impls/slhdsa_sha2_128f');
const slhdsa_sha2_192s = require('./impls/slhdsa_sha2_192s');
const slhdsa_sha2_192f = require('./impls/slhdsa_sha2_192f');
const slhdsa_sha2_256s = require('./impls/slhdsa_sha2_256s');
const slhdsa_sha2_256f = require('./impls/slhdsa_sha2_256f');
const slhdsa_shake_128s = require('./impls/slhdsa_shake_128s');
const slhdsa_shake_128f = require('./impls/slhdsa_shake_128f');
const slhdsa_shake_192s = require('./impls/slhdsa_shake_192s');
const slhdsa_shake_192f = require('./impls/slhdsa_shake_192f');
const slhdsa_shake_256s = require('./impls/slhdsa_shake_256s');
const slhdsa_shake_256f = require('./impls/slhdsa_shake_256f');

let bootstrapped = false;

function bootstrap() {
  if (bootstrapped) return;

  // KEM 0x0001 = ML-KEM-512  (NIST security category 1)
  // KEM 0x0002 = ML-KEM-768  (default, NIST security category 3)
  // KEM 0x0003 = ML-KEM-1024 (NIST security category 5)
  registerKEM(0x0001, mlkem512);
  registerKEM(0x0002, mlkem768);
  registerKEM(0x0003, mlkem1024);

  // Sig 0x0001 = ML-DSA-44 (NIST security category 2)
  // Sig 0x0002 = ML-DSA-65 (default, NIST security category 3)
  // Sig 0x0003 = ML-DSA-87 (NIST security category 5)
  registerSig(0x0001, mldsa44);
  registerSig(0x0002, mldsa65);
  registerSig(0x0003, mldsa87);

  // Sig 0x0100 = Falcon-512  (FIPS 206, NIST security category 1)
  // Sig 0x0101 = Falcon-1024 (FIPS 206, NIST security category 5)
  registerSig(0x0100, falcon512);
  registerSig(0x0101, falcon1024);

  // Sig 0x0200..0x020B = SLH-DSA / SPHINCS+ (FIPS 205)
  // 's' variants are small-signature/slow-signing; 'f' variants are fast-signing/larger-signature.
  registerSig(0x0200, slhdsa_sha2_128s);
  registerSig(0x0201, slhdsa_sha2_128f);
  registerSig(0x0202, slhdsa_sha2_192s);
  registerSig(0x0203, slhdsa_sha2_192f);
  registerSig(0x0204, slhdsa_sha2_256s);
  registerSig(0x0205, slhdsa_sha2_256f);
  registerSig(0x0206, slhdsa_shake_128s);
  registerSig(0x0207, slhdsa_shake_128f);
  registerSig(0x0208, slhdsa_shake_192s);
  registerSig(0x0209, slhdsa_shake_192f);
  registerSig(0x020A, slhdsa_shake_256s);
  registerSig(0x020B, slhdsa_shake_256f);

  bootstrapped = true;
}

module.exports = { bootstrap };
