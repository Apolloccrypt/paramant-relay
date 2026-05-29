// Relay crypto adapter. PQ ops via the REAL @paramant/core NAPI binding (the
// crypto the relay actually runs, relay/crypto/impls/{mldsa65,mlkem768}.js);
// wire-format via the REAL relay/crypto/wire-format.js when present.
//
// AES-GCM / HKDF are intentionally OFF the relay path: the relay stores blobs
// opaquely and never decrypts them (docs/wire-format-v1.md lines 108-110). So
// those ops return an explicit "off-path" error rather than a fabricated value.
//
// Reads one JSON request from stdin, writes one JSON response to stdout.
// On a missing real dependency: {"ok":false,"error":...} + exit 3. No mock.

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const H = {
  toBytes: (h) => Buffer.from(h, 'hex'),
  fromBytes: (b) => Buffer.from(b).toString('hex'),
};

async function main() {
  const req = JSON.parse(await readStdin());

  const coreNode = process.env.PARAMANT_CORE_NODE;
  if (!coreNode) fail('PARAMANT_CORE_NODE not set — cannot locate the @paramant/core NAPI binding (relay crypto).');

  let core;
  try {
    core = require(coreNode);
  } catch (e) {
    fail(`could not load real @paramant/core binding from ${coreNode}: ${e.message}`);
  }

  switch (req.op) {
    case 'kem-keygen': {
      const { publicKey, secretKey } = core.kemKeygen();
      return ok({ pubHex: H.fromBytes(publicKey), skHex: H.fromBytes(secretKey) });
    }
    case 'kem-encaps': {
      const { ciphertext, sharedSecret } = core.kemEncaps(H.toBytes(req.pubHex));
      return ok({ ctHex: H.fromBytes(ciphertext), ssHex: H.fromBytes(sharedSecret) });
    }
    case 'kem-decaps': {
      // relay impl: core.kemDecaps(secretKey, ciphertext)
      const ss = core.kemDecaps(H.toBytes(req.skHex), H.toBytes(req.ctHex));
      return ok({ ssHex: H.fromBytes(ss) });
    }
    case 'sig-keygen': {
      const { publicKey, secretKey } = core.mldsaKeygen();
      return ok({ pubHex: H.fromBytes(publicKey), skHex: H.fromBytes(secretKey) });
    }
    case 'sig-sign': {
      // relay impl: core.mldsaSign(secretKey, message)
      const sig = core.mldsaSign(H.toBytes(req.skHex), H.toBytes(req.msgHex));
      return ok({ sigHex: H.fromBytes(sig) });
    }
    case 'sig-verify': {
      // relay impl: core.mldsaVerify(publicKey, message, signature)
      const valid = core.mldsaVerify(H.toBytes(req.pubHex), H.toBytes(req.msgHex), H.toBytes(req.sigHex));
      return ok({ valid: !!valid });
    }
    case 'hkdf':
    case 'aead-encrypt':
    case 'aead-decrypt':
      fail(`op '${req.op}' is OFF the relay path: the relay stores blobs opaquely ` +
           `and never derives keys or decrypts (spec lines 108-110). The AES/HKDF ` +
           `envelope is a client-only contract — test it between sdk-js and sdk-py.`);
      break;
    case 'wire-encode': {
      const wire = loadRelayWire();
      const blob = wire.encode({
        kemId: req.kemId, sigId: req.sigId, flags: 0x00,
        ctKem: H.toBytes(req.ctKemHex),
        senderPub: H.toBytes(req.senderPubHex),
        signature: req.signatureHex ? H.toBytes(req.signatureHex) : undefined,
        nonce: H.toBytes(req.nonceHex),
        ciphertext: H.toBytes(req.ciphertextHex),
      });
      const { createHash } = require('node:crypto');
      const sha = createHash('sha256').update(blob).digest('hex');
      return ok({ blobHex: H.fromBytes(blob), sha256Hex: sha, len: blob.length });
    }
    default:
      fail(`unknown op: ${req.op}`);
  }
}

let _wire;
function loadRelayWire() {
  if (_wire) return _wire;
  const path = process.env.PARAMANT_RELAY_WIRE;
  if (!path) fail('PARAMANT_RELAY_WIRE not set — relay/crypto/wire-format.js not present (expected in SDK repo; required here).');
  try {
    _wire = require(path);
  } catch (e) {
    fail(`could not load real relay wire-format from ${path}: ${e.message}`);
  }
  return _wire;
}

function ok(obj) { process.stdout.write(JSON.stringify({ ok: true, ...obj })); process.exit(0); }
function fail(msg) { process.stdout.write(JSON.stringify({ ok: false, error: msg })); process.exit(3); }
function readStdin() {
  return new Promise((res) => {
    let d = ''; process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => res(d));
  });
}

main().catch((e) => fail(e.message));
