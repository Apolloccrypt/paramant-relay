// sdk-js crypto adapter. PQ ops via the REAL @noble/post-quantum (the library
// sdk-js depends on); wire-format via the REAL sdk-js/src/wire-format.js;
// HKDF + AES-256-GCM via WebCrypto, mirroring sdk-js index.js _encrypt/_decrypt
// (which inline those exact parameters — info='paramant-v1-aes-key').
//
// Reads one JSON request from stdin, writes one JSON response to stdout.
// On a missing real dependency: {"ok":false,"error":...} + exit 3. No mock.

import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const H = {
  toBytes: (h) => new Uint8Array(Buffer.from(h, 'hex')),
  fromBytes: (b) => Buffer.from(b).toString('hex'),
};

async function main() {
  const req = JSON.parse(await readStdin());

  const nobleDir = process.env.PARAMANT_NOBLE_DIR;
  if (!nobleDir) fail('PARAMANT_NOBLE_DIR not set — cannot locate @noble/post-quantum (sdk-js crypto).');

  let ml_kem768, ml_dsa65;
  try {
    ({ ml_kem768 } = await import(pathToFileURL(join(nobleDir, 'ml-kem.js')).href));
    ({ ml_dsa65 } = await import(pathToFileURL(join(nobleDir, 'ml-dsa.js')).href));
  } catch (e) {
    fail(`could not load real @noble/post-quantum from ${nobleDir}: ${e.message}`);
  }

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail('WebCrypto subtle unavailable in this Node — cannot run the sdk-js envelope path.');

  switch (req.op) {
    case 'kem-keygen': {
      const kp = ml_kem768.keygen();
      return ok({ pubHex: H.fromBytes(kp.publicKey), skHex: H.fromBytes(kp.secretKey) });
    }
    case 'kem-encaps': {
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(H.toBytes(req.pubHex));
      return ok({ ctHex: H.fromBytes(cipherText), ssHex: H.fromBytes(sharedSecret) });
    }
    case 'kem-decaps': {
      const ss = ml_kem768.decapsulate(H.toBytes(req.ctHex), H.toBytes(req.skHex));
      return ok({ ssHex: H.fromBytes(ss) });
    }
    case 'sig-keygen': {
      const kp = ml_dsa65.keygen();
      return ok({ pubHex: H.fromBytes(kp.publicKey), skHex: H.fromBytes(kp.secretKey) });
    }
    case 'sig-sign': {
      // sdk-js index.js:274 — ml_dsa65.sign(msg, sk)
      const sig = ml_dsa65.sign(H.toBytes(req.msgHex), H.toBytes(req.skHex));
      return ok({ sigHex: H.fromBytes(sig) });
    }
    case 'sig-verify': {
      // sdk-js index.js:277 — ml_dsa65.verify(sig, msg, pk)
      const valid = ml_dsa65.verify(H.toBytes(req.sigHex), H.toBytes(req.msgHex), H.toBytes(req.pubHex));
      return ok({ valid: !!valid });
    }
    case 'hkdf': {
      const base = await subtle.importKey('raw', H.toBytes(req.ssHex), { name: 'HKDF' }, false, ['deriveBits']);
      const bits = await subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: H.toBytes(req.saltHex), info: new TextEncoder().encode(req.info) },
        base, 256
      );
      return ok({ keyHex: H.fromBytes(new Uint8Array(bits)) });
    }
    case 'aead-encrypt': {
      const key = await subtle.importKey('raw', H.toBytes(req.keyHex), { name: 'AES-GCM' }, false, ['encrypt']);
      const ct = await subtle.encrypt(
        { name: 'AES-GCM', iv: H.toBytes(req.nonceHex), additionalData: H.toBytes(req.aadHex) },
        key, H.toBytes(req.ptHex)
      );
      return ok({ ctHex: H.fromBytes(new Uint8Array(ct)) });
    }
    case 'aead-decrypt': {
      const key = await subtle.importKey('raw', H.toBytes(req.keyHex), { name: 'AES-GCM' }, false, ['decrypt']);
      const pt = await subtle.decrypt(
        { name: 'AES-GCM', iv: H.toBytes(req.nonceHex), additionalData: H.toBytes(req.aadHex) },
        key, H.toBytes(req.ctHex)
      );
      return ok({ ptHex: H.fromBytes(new Uint8Array(pt)) });
    }
    case 'wire-encode': {
      const wire = await loadSdkJsWire();
      const blob = wire.encode({
        kemId: req.kemId, sigId: req.sigId, flags: 0x00,
        ctKem: H.toBytes(req.ctKemHex),
        senderPub: H.toBytes(req.senderPubHex),
        signature: req.signatureHex ? H.toBytes(req.signatureHex) : undefined,
        nonce: H.toBytes(req.nonceHex),
        ciphertext: H.toBytes(req.ciphertextHex),
      });
      const sha = new Uint8Array(await subtle.digest('SHA-256', blob));
      return ok({ blobHex: H.fromBytes(blob), sha256Hex: H.fromBytes(sha), len: blob.length });
    }
    default:
      fail(`unknown op: ${req.op}`);
  }
}

let _wire;
async function loadSdkJsWire() {
  if (_wire) return _wire;
  const path = process.env.PARAMANT_SDK_JS_WIRE
    || join(process.env.PWD || '.', 'sdk-js', 'src', 'wire-format.js');
  try {
    _wire = await import(pathToFileURL(path).href);
  } catch (e) {
    fail(`could not load real sdk-js wire-format from ${path}: ${e.message}`);
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
