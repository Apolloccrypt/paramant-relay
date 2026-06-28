// relay/crypto/bootstrap.js
// Registers the algorithms this relay supports. Called once at startup.
//
// CRYPTO_MODE controls which algorithms get registered:
//   'core'     (default) - ML-KEM-768 + ML-DSA-65 only. FIPS 203/204.
//                          Used by all official SDKs (sdk-js, sdk-py,
//                          crypto-wasm). Smallest audit surface.
//   'extended' - all 18 algorithms: ML-KEM-{512,768,1024},
//                ML-DSA-{44,65,87}, Falcon-{512,1024}, all 12 SLH-DSA
//                variants. Crypto-agility for experimental clients
//                using the raw HTTP API.
//
// Backing libraries differ by tier. The two core impls (mlkem768.js, mldsa65.js)
// route to @paramant/core (the Rust PQ-crypto core, NAPI binding). The 16
// extended impls are the only code that requires @noble/post-quantum. So in the
// production default (CRYPTO_MODE=core) @noble runs no crypto: it is dormant on
// the hot path, and the core audit surface is @paramant/core, not @noble. The
// extended impl files are still required eagerly (see below), so @noble is
// loaded into the process even in core mode; it cannot move to a devDependency
// without breaking that eager require. See ADR R006 for the dependency-surface
// rationale.
//
// To enable extended mode: set CRYPTO_MODE=extended in .env. See ADR R006.

const { registerKEM, registerSig } = require('./registry');

// Core impls (always loaded)
const mlkem768 = require('./impls/mlkem768');
const mldsa65 = require('./impls/mldsa65');

// Extended impls (registered only when CRYPTO_MODE=extended). Required eagerly
// so a missing or broken impl file fails at startup, not at first use.
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
let activeMode = null;

function bootstrap(mode) {
  if (bootstrapped) return activeMode;

  // Resolve mode: explicit arg > env > default.
  const resolved = (mode || process.env.CRYPTO_MODE || 'core').toLowerCase();
  if (resolved !== 'core' && resolved !== 'extended') {
    throw new Error(`Invalid CRYPTO_MODE: ${resolved}. Must be 'core' or 'extended'.`);
  }

  // Core algorithms - loaded in both modes.
  // KEM 0x0002 = ML-KEM-768 (FIPS 203, NIST security category 3)
  registerKEM(0x0002, mlkem768);
  // Sig 0x0002 = ML-DSA-65 (FIPS 204, NIST security category 3)
  registerSig(0x0002, mldsa65);

  if (resolved === 'extended') {
    // Additional ML-KEM levels.
    registerKEM(0x0001, mlkem512);
    registerKEM(0x0003, mlkem1024);

    // Additional ML-DSA levels.
    registerSig(0x0001, mldsa44);
    registerSig(0x0003, mldsa87);

    // Falcon (FIPS 206).
    registerSig(0x0100, falcon512);
    registerSig(0x0101, falcon1024);

    // SLH-DSA / SPHINCS+ (FIPS 205). 's' = small-sig/slow, 'f' = fast/larger-sig.
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
  }

  bootstrapped = true;
  activeMode = resolved;
  return resolved;
}

function getActiveMode() {
  return activeMode;
}

// For testing: clear the registry and bootstrap state so a different mode can
// be exercised in the same process.
function resetBootstrap() {
  const { clearRegistry } = require('./registry');
  clearRegistry();
  bootstrapped = false;
  activeMode = null;
}

module.exports = { bootstrap, getActiveMode, resetBootstrap };
