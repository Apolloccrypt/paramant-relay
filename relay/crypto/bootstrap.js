// relay/crypto/bootstrap.js
// Registers the algorithms this relay supports. Called once at startup.
// To add a new algorithm: write an impl file, import here, register it.

const { registerKEM, registerSig } = require('./registry');
const mlkem768 = require('./impls/mlkem768');
const mldsa65 = require('./impls/mldsa65');

let bootstrapped = false;

function bootstrap() {
  if (bootstrapped) return;

  // KEM 0x0002 = ML-KEM-768 (default)
  registerKEM(0x0002, mlkem768);

  // Sig 0x0002 = ML-DSA-65 (default)
  registerSig(0x0002, mldsa65);

  bootstrapped = true;
}

module.exports = { bootstrap };
