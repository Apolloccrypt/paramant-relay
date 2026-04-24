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

  bootstrapped = true;
}

module.exports = { bootstrap };
