/**
 * Paramant Ghost Pipe SDK v3.0.0
 * ===================================
 * Real post-quantum (ML-KEM-768 + ML-DSA-65) zero-plaintext file transport.
 *
 * Wire format: v1 (PQHB, see docs/wire-format-v1.md).
 * Key exchange: ML-KEM-768 via @noble/post-quantum.
 * AEAD: AES-256-GCM with header bound as AAD.
 *
 * Node.js:  import { GhostPipe } from 'paramant-sdk'
 * Browser:  <script type="module"> import { GhostPipe } from 'paramant-sdk/index.js'
 */

'use strict';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { encode as wireEncode, decode as wireDecode, buildAAD, isV1 } from './src/wire-format.js';
import { fetchCapabilities, assertSupported, UnsupportedAlgorithmError } from './src/capabilities.js';

// Node-only CJS interop. Not loaded in browser builds.
const _nodeRequire = (typeof process !== 'undefined' && process.versions?.node)
  ? (await import('node:module')).createRequire(import.meta.url)
  : null;

export const VERSION = '3.0.0';
export const WIRE_VERSION = 1;

// KEM / SIG IDs from docs/wire-format-v1.md registry.
export const KEM = Object.freeze({
  ML_KEM_768: 0x0002,
});
export const SIG = Object.freeze({
  NONE: 0x0000,
  ML_DSA_65: 0x0002,
});

const DEFAULT_KEM_ID = KEM.ML_KEM_768;
const DEFAULT_SIG_ID = SIG.ML_DSA_65;

const SECTOR_RELAYS = {
  health:  'https://health.paramant.app',
  iot:     'https://iot.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  relay:   'https://relay.paramant.app',
};

const UA = `paramant-sdk/${VERSION} js`;

// ── Exceptions ────────────────────────────────────────────────────────────────

export class GhostPipeError extends Error {
  constructor(msg) { super(msg); this.name = 'GhostPipeError'; }
}
export class RelayError extends GhostPipeError {
  constructor(status, body) {
    super(`Relay HTTP ${status}: ${String(body).slice(0, 200)}`);
    this.name = 'RelayError'; this.status = status; this.body = body;
  }
}
export class AuthError extends GhostPipeError {
  constructor(msg) { super(msg); this.name = 'AuthError'; }
}
export class BurnedError extends GhostPipeError {
  constructor(msg) { super(msg); this.name = 'BurnedError'; }
}
export class FingerprintMismatchError extends GhostPipeError {
  constructor(deviceId, stored, received) {
    super(
      `\n  ⚠  FINGERPRINT MISMATCH — device: ${deviceId}\n` +
      `  Stored:   ${stored}\n` +
      `  Received: ${received}\n` +
      `  Call gp.trust('${deviceId}') after out-of-band verification.\n`
    );
    this.name = 'FingerprintMismatchError';
    this.deviceId = deviceId; this.stored = stored; this.received = received;
  }
}
export class LicenseError extends GhostPipeError {
  constructor(msg) { super(msg); this.name = 'LicenseError'; }
}
export class RateLimitError extends GhostPipeError {
  constructor(msg) { super(msg); this.name = 'RateLimitError'; }
}
export class SignatureError extends GhostPipeError {
  constructor(msg) { super(msg); this.name = 'SignatureError'; }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function u8toHex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToU8(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function concat(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// Web Crypto getRandomValues caps at 65536 bytes per call; fill larger buffers in chunks.
function fillRandom(buf) {
  const CHUNK = 65536;
  if (buf.byteLength <= CHUNK) {
    crypto.getRandomValues(buf);
    return buf;
  }
  for (let off = 0; off < buf.byteLength; off += CHUNK) {
    crypto.getRandomValues(buf.subarray(off, Math.min(off + CHUNK, buf.byteLength)));
  }
  return buf;
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function readU32be(u8, off) {
  return new DataView(u8.buffer, u8.byteOffset + off, 4).getUint32(0, false);
}

function toBase64(u8) {
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64');
  let s = '';
  const SZ = 8192;
  for (let i = 0; i < u8.length; i += SZ) s += String.fromCharCode(...u8.slice(i, i + SZ));
  return btoa(s);
}

function fromBase64(str) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(str, 'base64'));
  const raw = atob(str);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

async function sha256Hex(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return u8toHex(new Uint8Array(hash));
}

async function sha256Bytes(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/** SHA-256(kem_pub_bytes || sig_pub_bytes) → 5×4 hex groups. */
async function computeFingerprint(kemPubHex, sigPubHex) {
  const buf = hexToU8((kemPubHex || '') + (sigPubHex || ''));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const h = [...hash.slice(0, 10)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

// ── Known-keys store (TOFU) ───────────────────────────────────────────────────

function _isNode() {
  return typeof process !== 'undefined' && process.versions?.node;
}

function _loadKnownKeysNode() {
  try {
    const fs   = _nodeRequire('fs');
    const path = _nodeRequire('path');
    const p    = path.join(_nodeRequire('os').homedir(), '.paramant', 'known_keys');
    if (!fs.existsSync(p)) return {};
    const result = {};
    for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
      const l = line.trim();
      if (!l || l.startsWith('#')) continue;
      const parts = l.split(/\s+/);
      if (parts.length >= 2) result[parts[0]] = { fingerprint: parts[1], registered_at: parts[2] || '' };
    }
    return result;
  } catch { return {}; }
}

function _saveKnownKeysNode(keys) {
  try {
    const fs   = _nodeRequire('fs');
    const path = _nodeRequire('path');
    const dir  = path.join(_nodeRequire('os').homedir(), '.paramant');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const p = path.join(dir, 'known_keys');
    const tmp = p + '.tmp';
    let content = '# PARAMANT known-keys — Trust On First Use (TOFU)\n# Format: device_id fingerprint registered_at\n';
    for (const [did, v] of Object.entries(keys)) content += `${did} ${v.fingerprint} ${v.registered_at}\n`;
    fs.writeFileSync(tmp, content, { mode: 0o600 });
    fs.renameSync(tmp, p);
  } catch(e) { console.warn('[paramant] known_keys write failed:', e.message); }
}

function loadKnownKeys() {
  if (_isNode()) return _loadKnownKeysNode();
  try {
    return JSON.parse(localStorage.getItem('paramant_known_keys') || '{}');
  } catch { return {}; }
}

function saveKnownKeys(keys) {
  if (_isNode()) { _saveKnownKeysNode(keys); return; }
  try { localStorage.setItem('paramant_known_keys', JSON.stringify(keys)); } catch {}
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

async function httpRequest({ url, method = 'GET', body, headers = {}, timeout = 30000, retries = 3 }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const res = await fetch(url, { method, headers, body, signal: controller.signal });
        clearTimeout(timer);
        const raw = await res.arrayBuffer();
        return { status: res.status, body: new Uint8Array(raw) };
      } catch(e) {
        if (e.name === 'AbortError') throw new RelayError(0, 'Request timed out');
        if (attempt === retries - 1) throw new RelayError(0, e.message);
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
      }
    }
  } finally {
    clearTimeout(timer);
  }
}

// ── KEM / SIG engine ──────────────────────────────────────────────────────────

function kemEngine(kemId) {
  if (kemId === KEM.ML_KEM_768) {
    return {
      name: 'ML-KEM-768', pubKeySize: 1184, ctSize: 1088, sharedSecretSize: 32,
      keygen: () => ml_kem768.keygen(),
      encapsulate: (pub) => {
        if (pub.length !== 1184) throw new GhostPipeError(`ML-KEM-768 public key must be 1184 bytes, got ${pub.length}`);
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(pub);
        return { ciphertext: cipherText, sharedSecret };
      },
      decapsulate: (ct, sk) => {
        if (ct.length !== 1088) throw new GhostPipeError(`ML-KEM-768 ciphertext must be 1088 bytes, got ${ct.length}`);
        return ml_kem768.decapsulate(ct, sk);
      },
    };
  }
  throw new UnsupportedAlgorithmError('kemId', kemId, ['0x0002']);
}

function sigEngine(sigId) {
  if (sigId === SIG.NONE) return null;
  if (sigId === SIG.ML_DSA_65) {
    return {
      name: 'ML-DSA-65', pubKeySize: 1952, sigSize: 3309,
      keygen: () => ml_dsa65.keygen(),
      sign: (msg, sk) => ml_dsa65.sign(msg, sk),
      verify: (sig, msg, pk) => {
        if (pk.length !== 1952) throw new SignatureError(`ML-DSA-65 public key must be 1952 bytes, got ${pk.length}`);
        return ml_dsa65.verify(sig, msg, pk);
      },
    };
  }
  throw new UnsupportedAlgorithmError('sigId', sigId, ['0x0000', '0x0002']);
}

// ── Main SDK class ────────────────────────────────────────────────────────────

const KNOWN_OPTS = new Set([
  'apiKey', 'device', 'relay', 'preSharedSecret',
  'verifyFingerprints', 'timeout',
  'kemId', 'sigId', 'checkCapabilities',
]);

const TYPO_HINTS = {
  relayurl: 'relay', relayUrl: 'relay', relayURL: 'relay',
  url: 'relay', URL: 'relay', endpoint: 'relay', host: 'relay', server: 'relay',
  apikey: 'apiKey', apiToken: 'apiKey', token: 'apiKey', key: 'apiKey',
  deviceId: 'device', deviceID: 'device', device_id: 'device',
};

function validateOpts(opts) {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new GhostPipeError(
      'GhostPipe: constructor expects an options object, got ' +
      (Array.isArray(opts) ? 'array' : typeof opts) + '.\n' +
      'Example: new GhostPipe({ apiKey: "pgp_...", device: "my-laptop" })\n' +
      'See https://paramant.app/docs#sdk-js'
    );
  }
  const unknown = Object.keys(opts).filter(k => !KNOWN_OPTS.has(k));
  if (unknown.length === 0) return;
  const lines = unknown.map(k => {
    const hint = TYPO_HINTS[k] || TYPO_HINTS[k.toLowerCase()];
    return hint ? `  - "${k}" — did you mean "${hint}"?` : `  - "${k}"`;
  });
  throw new GhostPipeError(
    'GhostPipe: unknown constructor option(s):\n' +
    lines.join('\n') + '\n' +
    'Valid options: ' + Array.from(KNOWN_OPTS).join(', ') + '\n' +
    'See https://paramant.app/docs#sdk-js'
  );
}

export class GhostPipe {
  /**
   * Paramant Ghost Pipe client.
   *
   * @param {object} opts
   * @param {string} opts.apiKey
   * @param {string} opts.device
   * @param {string} [opts.relay]
   * @param {string} [opts.preSharedSecret]
   * @param {boolean} [opts.verifyFingerprints]
   * @param {number} [opts.timeout]
   * @param {number} [opts.kemId]  Default: 0x0002 (ML-KEM-768)
   * @param {number} [opts.sigId]  Default: 0x0002 (ML-DSA-65). Pass 0x0000 for anonymous blobs.
   * @param {boolean} [opts.checkCapabilities] Default: true
   */
  constructor(opts = {}) {
    validateOpts(opts);
    const { apiKey, device, relay = '', preSharedSecret = '',
            verifyFingerprints = true, timeout = 30000,
            kemId = DEFAULT_KEM_ID, sigId = DEFAULT_SIG_ID,
            checkCapabilities = true } = opts;
    if (apiKey && !apiKey.startsWith('pgp_')) throw new AuthError('API key must start with pgp_');
    this.apiKey             = apiKey;
    this.device             = device;
    this.relay              = relay;
    this.preSharedSecret    = preSharedSecret;
    this.verifyFingerprints = verifyFingerprints;
    this.timeout            = timeout;
    this.kemId              = kemId;
    this.sigId              = sigId;
    this.checkCapabilities  = checkCapabilities;
    this._keypair           = null;
    this._capabilities      = null;
    // Validate algorithms early — fail fast on unknown IDs.
    kemEngine(kemId);
    sigEngine(sigId);
  }

  async _detectRelay() {
    for (const [, url] of Object.entries(SECTOR_RELAYS)) {
      try {
        const { status, body } = await httpRequest({
          url: `${url}/v2/check-key`,
          headers: { 'User-Agent': UA, 'X-Api-Key': this.apiKey },
          timeout: 4000,
          retries: 1,
        });
        if (status === 200 && JSON.parse(new TextDecoder().decode(body)).valid) return url;
      } catch {}
    }
    return null;
  }

  async _ensureRelay() {
    if (!this.relay) {
      this.relay = await this._detectRelay();
      if (!this.relay) throw new RelayError(0, 'No reachable relay found for this API key. Set relay: option explicitly.');
    }
  }

  async _ensureCapabilities() {
    if (!this.checkCapabilities) return null;
    if (this._capabilities) return this._capabilities;
    await this._ensureRelay();
    const caps = await fetchCapabilities(this.relay, { timeout: this.timeout });
    assertSupported(caps, { wireVersion: WIRE_VERSION, kemId: this.kemId, sigId: this.sigId });
    this._capabilities = caps;
    return caps;
  }

  /** Force-refresh the cached capabilities. */
  async capabilities() {
    await this._ensureRelay();
    const caps = await fetchCapabilities(this.relay, { timeout: this.timeout });
    this._capabilities = caps;
    return caps;
  }

  async _request(method, path, { body, contentType = 'application/json', params, extraHeaders } = {}) {
    await this._ensureRelay();
    let url = this.relay + path;
    if (params) url += '?' + new URLSearchParams(params).toString();
    const headers = { 'User-Agent': UA };
    if (this.apiKey) headers['X-Api-Key'] = this.apiKey;
    if (body) headers['Content-Type'] = contentType;
    if (extraHeaders) Object.assign(headers, extraHeaders);
    const { status, body: respBody } = await httpRequest({
      url, method, body, headers, timeout: this.timeout,
    });
    if (status === 401 || status === 403) throw new AuthError(`HTTP ${status}`);
    if (status === 402) throw new LicenseError(new TextDecoder().decode(respBody).slice(0, 200));
    if (status === 410) throw new BurnedError('Blob burned or expired');
    if (status === 415) throw new GhostPipeError(`Unsupported algorithm: ${new TextDecoder().decode(respBody).slice(0, 200)}`);
    if (status === 429) throw new RateLimitError('Rate limited');
    return { status, body: respBody };
  }

  async _get(path, params) { return this._request('GET', path, { params }); }
  async _post(path, data) {
    return this._request('POST', path, { body: new TextEncoder().encode(JSON.stringify(data)) });
  }
  async _postRaw(path, bytes, contentType = 'application/octet-stream') {
    return this._request('POST', path, { body: bytes, contentType });
  }
  async _delete(path) { return this._request('DELETE', path); }

  _json(r) { return JSON.parse(new TextDecoder().decode(r.body)); }

  // ── Keypair (ML-KEM-768 + optional ML-DSA-65) ──────────────────────────────

  async _loadKeypair() {
    if (this._keypair) return this._keypair;
    const key = `paramant_kp_${this.device}`;
    if (_isNode()) {
      const fs   = _nodeRequire('fs');
      const path = _nodeRequire('path');
      const p = path.join(_nodeRequire('os').homedir(), '.paramant',
                           this.device.replace(/\//g, '_') + '.keypair.json');
      if (fs.existsSync(p)) {
        const stored = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (stored.version === 3) { this._keypair = stored; return stored; }
      }
    } else {
      const stored = localStorage.getItem(key);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.version === 3) { this._keypair = parsed; return parsed; }
      }
    }
    const kp = await this._generateKeypair();
    this._keypair = kp;
    if (_isNode()) {
      const fs   = _nodeRequire('fs');
      const path = _nodeRequire('path');
      const dir  = path.join(_nodeRequire('os').homedir(), '.paramant');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const p = path.join(dir, this.device.replace(/\//g, '_') + '.keypair.json');
      fs.writeFileSync(p, JSON.stringify(kp), { mode: 0o600 });
    } else {
      try { localStorage.setItem(key, JSON.stringify(kp)); } catch {}
    }
    return kp;
  }

  async _generateKeypair() {
    const kem = kemEngine(this.kemId);
    const kemKp = kem.keygen();
    let sigKp = null;
    if (this.sigId !== SIG.NONE) {
      const sig = sigEngine(this.sigId);
      sigKp = sig.keygen();
    }
    return {
      version:    3,
      device:     this.device,
      kemId:      this.kemId,
      sigId:      this.sigId,
      kem_pub:    u8toHex(kemKp.publicKey),
      kem_priv:   u8toHex(kemKp.secretKey),
      sig_pub:    sigKp ? u8toHex(sigKp.publicKey) : '',
      sig_priv:   sigKp ? u8toHex(sigKp.secretKey) : '',
    };
  }

  // ── TOFU ──────────────────────────────────────────────────────────────────

  async _tofuCheck(deviceId, kemPubHex, sigPubHex, registeredAt = '') {
    const fp = await computeFingerprint(kemPubHex, sigPubHex);
    if (!this.verifyFingerprints) return fp;
    const keys = loadKnownKeys();
    if (keys[deviceId]) {
      const stored = keys[deviceId].fingerprint;
      if (stored.replace(/-/g,'').toUpperCase() !== fp.replace(/-/g,'').toUpperCase()) {
        throw new FingerprintMismatchError(deviceId, stored, fp);
      }
    } else {
      keys[deviceId] = { fingerprint: fp, registered_at: registeredAt };
      saveKnownKeys(keys);
      console.log(`[paramant] New device: ${deviceId}`);
      console.log(`           Fingerprint: ${fp}`);
      console.log(`           Verify out-of-band before trusting sensitive transfers.`);
    }
    return fp;
  }

  // ── Encryption (wire-format v1) ────────────────────────────────────────────

  async _fetchPubkeys(deviceId) {
    const { status, body } = await this._get(`/v2/pubkey/${deviceId}`);
    if (status === 404) throw new GhostPipeError(`No pubkeys for device '${deviceId}'. Call registerPubkeys() on receiver first.`);
    return JSON.parse(new TextDecoder().decode(body));
  }

  /**
   * Produce a wire-format v1 blob.
   *
   * @param {Uint8Array} plaintext
   * @param {string} recipientKemPubHex
   * @param {object} [opts]
   * @param {number} [opts.padBlock]
   * @param {string} [opts.pss]
   * @param {number} [opts.kemId]
   * @param {number} [opts.sigId]
   * @returns {Promise<{blob: Uint8Array, hash: string, hashRaw: string}>}
   */
  async _encrypt(plaintext, recipientKemPubHex, {
    padBlock = 5 * 1024 * 1024,
    pss = '',
    kemId = this.kemId,
    sigId = this.sigId,
  } = {}) {
    const kem = kemEngine(kemId);
    const kemPub = hexToU8(recipientKemPubHex);
    const { ciphertext: ctKem, sharedSecret } = kem.encapsulate(kemPub);

    // Derive AES key via HKDF(sharedSecret, salt=ctKem[0:32], info='aes-key' || pss-hash)
    let pssHash = new Uint8Array(0);
    if (pss) pssHash = await sha256Bytes(new TextEncoder().encode(pss));
    const ikm = concat(sharedSecret, pssHash);
    const salt = ctKem.slice(0, 32);
    const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('paramant-v1-aes-key') },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = buildAAD({ kemId, sigId, flags: 0x00, chunkIndex: 0 });
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext
    ));

    // Sender key material and signature.
    // Per docs/wire-format-v1.md: when sigId != 0x0000, senderPub is the
    // sender's *signing* public key so the receiver can verify the embedded
    // signature without an out-of-band lookup. For anonymous blobs we keep
    // the KEM pubkey there as a stable, opaque sender identifier.
    const kp = await this._loadKeypair();
    const senderPubBytes = sigId !== SIG.NONE
      ? hexToU8(kp.sig_pub)
      : hexToU8(kp.kem_pub);

    let signature;
    if (sigId !== SIG.NONE) {
      const sig = sigEngine(sigId);
      if (!kp.sig_priv) throw new SignatureError('sigId != 0x0000 requires a device signing keypair');
      const sigPriv = hexToU8(kp.sig_priv);
      // Sign ctKem || senderPub || nonce || ct || aad — must match _decrypt.
      const msg = concat(ctKem, senderPubBytes, nonce, ct, aad);
      signature = sig.sign(msg, sigPriv);
    }

    const core = wireEncode({
      kemId, sigId, flags: 0x00,
      ctKem, senderPub: senderPubBytes, signature,
      nonce, ciphertext: ct,
    });

    if (core.length > padBlock) throw new GhostPipeError(`Data too large (${plaintext.length} bytes) for block ${padBlock}`);
    const padding = fillRandom(new Uint8Array(padBlock - core.length));
    const blob = concat(core, padding);
    const hash = await sha256Hex(blob);
    return { blob, hash };
  }

  async _decrypt(blob, pss = '') {
    const kp = await this._loadKeypair();
    if (!isV1(blob)) throw new GhostPipeError('blob is not wire-format v1 (missing PQHB magic)');

    const parsed = wireDecode(blob);
    const kem = kemEngine(parsed.kemId);
    if (parsed.kemId !== kp.kemId) {
      throw new GhostPipeError(`blob kemId=0x${parsed.kemId.toString(16)} does not match keypair kemId=0x${kp.kemId.toString(16)}`);
    }

    const sharedSecret = kem.decapsulate(parsed.ctKem, hexToU8(kp.kem_priv));

    let pssHash = new Uint8Array(0);
    if (pss) pssHash = await sha256Bytes(new TextEncoder().encode(pss));
    const ikm = concat(sharedSecret, pssHash);
    const salt = parsed.ctKem.slice(0, 32);
    const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('paramant-v1-aes-key') },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const aad = buildAAD({ kemId: parsed.kemId, sigId: parsed.sigId, flags: parsed.flags, chunkIndex: 0 });

    // Verify signature if present. Sender-key pinning (TOFU) is enforced
    // separately on send() via _tofuCheck — here we only enforce that the
    // signature is cryptographically valid for the senderPub carried in
    // the blob. Pre-fix this branch silently accepted any bytes in the
    // signature field.
    if (parsed.sigId !== SIG.NONE) {
      const sig = sigEngine(parsed.sigId);
      const msg = concat(parsed.ctKem, parsed.senderPub, parsed.nonce, parsed.ciphertext, aad);
      let valid = false;
      try {
        valid = sig.verify(parsed.signature, msg, parsed.senderPub);
      } catch (e) {
        throw new SignatureError(`${sig.name} signature verification raised: ${e.message}`);
      }
      if (!valid) {
        throw new SignatureError(`${sig.name} signature did not verify against senderPub`);
      }
    }

    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: parsed.nonce, additionalData: aad }, aesKey, parsed.ciphertext
    ));
  }

  // ── Pubkey registration ────────────────────────────────────────────────────

  async registerPubkeys() {
    const kp = await this._loadKeypair();
    const { status, body } = await this._post('/v2/pubkey', {
      device_id: this.device,
      kem_id:    kp.kemId,
      sig_id:    kp.sigId,
      kem_pub:   kp.kem_pub,
      sig_pub:   kp.sig_pub || '',
    });
    if (status !== 200 && status !== 409) throw new RelayError(status, new TextDecoder().decode(body));
    return JSON.parse(new TextDecoder().decode(body));
  }

  // ── Core transfer ──────────────────────────────────────────────────────────

  async send(data, { recipient, ttl = 3600, maxViews = 1, padBlock = 5 * 1024 * 1024,
                     preSharedSecret } = {}) {
    await this._ensureCapabilities();
    const target = recipient || this.device;
    const pss    = preSharedSecret ?? this.preSharedSecret;
    const pubkeys = await this._fetchPubkeys(target);
    const recipientKemPub = pubkeys.kem_pub || pubkeys.kyber_pub || '';
    if (!recipientKemPub) throw new GhostPipeError(`No KEM pubkey for device '${target}'`);
    await this._tofuCheck(target, recipientKemPub, pubkeys.sig_pub || '', pubkeys.registered_at || '');
    const { blob, hash } = await this._encrypt(data, recipientKemPub, { padBlock, pss });
    const { status, body } = await this._post('/v2/inbound', {
      hash,
      payload:   toBase64(blob),
      ttl_ms:    ttl * 1000,
      max_views: maxViews,
      meta:      { device_id: this.device },
    });
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body).slice(0, 400));
    return hash;
  }

  async receive(hash_, { preSharedSecret } = {}) {
    const pss = preSharedSecret ?? this.preSharedSecret;
    const { status, body } = await this._get(`/v2/outbound/${hash_}`);
    if (status === 404) throw new BurnedError('Blob not found: expired, already retrieved, or never stored.');
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body));
    return this._decrypt(body, pss);
  }

  async status(hash_) {
    const r = await this._get(`/v2/status/${hash_}`);
    return this._json(r);
  }

  async cancel(hash_) {
    const r = await this._delete(`/v2/inbound/${hash_}`);
    return this._json(r);
  }

  // ── Anonymous inbound (wire-format v1, sigId=0x0000) ───────────────────────

  /**
   * Submit an anonymous v1 blob to /v2/anon-inbound given a recipient's KEM public key.
   *
   * @param {Uint8Array} data
   * @param {string} recipientKemPubHex  Recipient ML-KEM-768 public key (hex, 2368 chars).
   * @param {object} [opts]
   * @param {number} [opts.ttl]          Seconds (default 3600).
   * @param {number} [opts.maxViews]
   * @param {number} [opts.padBlock]
   * @returns {Promise<{hash: string, blob: Uint8Array, response: any}>}
   */
  async sendAnonymous(data, recipientKemPubHex, { ttl = 3600, maxViews = 1, padBlock = 5 * 1024 * 1024 } = {}) {
    await this._ensureCapabilities();
    const { blob, hash } = await this._encrypt(data, recipientKemPubHex, {
      padBlock, kemId: this.kemId, sigId: SIG.NONE,
    });
    const { status, body } = await this._post('/v2/anon-inbound', {
      hash,
      payload:   toBase64(blob),
      ttl_ms:    ttl * 1000,
      max_views: maxViews,
    });
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body).slice(0, 400));
    return { hash, blob, response: JSON.parse(new TextDecoder().decode(body)) };
  }

  // ── Drop (anonymous BIP39) ────────────────────────────────────────────────

  async drop(data, { ttl = 3600 } = {}) {
    const entropy = crypto.getRandomValues(new Uint8Array(16));
    const phrase  = await _bip39Encode(entropy);
    const { aesKey, lookupHash } = await _deriveDropKeys(entropy);
    const nonce  = crypto.getRandomValues(new Uint8Array(12));
    const ct     = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, data));
    const ctLen  = u32be(ct.length);
    const packet = concat(nonce, ctLen, ct);
    const padBlock = 5 * 1024 * 1024;
    if (packet.length > padBlock) throw new GhostPipeError(`Data too large (${data.length} bytes)`);
    const blob = concat(packet, fillRandom(new Uint8Array(padBlock - packet.length)));
    const { status, body } = await this._post('/v2/inbound', {
      hash:      lookupHash,
      payload:   toBase64(blob),
      ttl_ms:    ttl * 1000,
      max_views: 1,
      meta:      { drop: true },
    });
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body).slice(0, 400));
    return phrase;
  }

  async pickup(phrase) {
    const entropy    = await _bip39Decode(phrase.trim());
    const { aesKey, lookupHash } = await _deriveDropKeys(entropy);
    const { status, body } = await this._get(`/v2/outbound/${lookupHash}`);
    if (status === 404) throw new BurnedError('Drop not found: expired, retrieved, or wrong mnemonic.');
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body));
    const nonce = body.slice(0, 12);
    const ctLen = readU32be(body, 12);
    const ct    = body.slice(16, 16 + ctLen);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct));
  }

  // ── Fingerprint & TOFU ────────────────────────────────────────────────────

  async fingerprint(deviceId) {
    const target = deviceId || this.device;
    const { status, body } = await this._get(`/v2/fingerprint/${target}`);
    if (status === 404) throw new GhostPipeError(`No pubkeys for device '${target}'`);
    return JSON.parse(new TextDecoder().decode(body)).fingerprint;
  }

  async verifyFingerprint(deviceId, fingerprint) {
    const { status, body } = await this._post('/v2/pubkey/verify', { device_id: deviceId, fingerprint });
    return JSON.parse(new TextDecoder().decode(body)).match === true;
  }

  async trust(deviceId, fingerprint) {
    if (!fingerprint) fingerprint = await this.fingerprint(deviceId);
    const keys = loadKnownKeys();
    keys[deviceId] = { fingerprint, registered_at: new Date().toISOString() };
    saveKnownKeys(keys);
    return fingerprint;
  }

  untrust(deviceId) {
    const keys = loadKnownKeys();
    delete keys[deviceId];
    saveKnownKeys(keys);
  }

  knownDevices() {
    const keys = loadKnownKeys();
    return Object.entries(keys).map(([deviceId, v]) => ({
      deviceId, fingerprint: v.fingerprint, registeredAt: v.registered_at,
    }));
  }

  // ── Session (PSS) ─────────────────────────────────────────────────────────

  async sessionCreate(pss, ttlMs = 600_000) {
    const commitment = u8toHex(await sha256Bytes(new TextEncoder().encode(pss)));
    const r = await this._post('/v2/session/create', { commitment, ttl_ms: ttlMs });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  async sessionJoin(sessionId, pss) {
    const kp = await this._loadKeypair();
    const r = await this._post('/v2/session/join', {
      session_id: sessionId, pss,
      kem_pub: kp.kem_pub, sig_pub: kp.sig_pub || '',
    });
    if (r.status === 403) throw new AuthError('PSS mismatch');
    return this._json(r);
  }

  async sessionPubkey(sessionId) {
    const r = await this._get(`/v2/session/${sessionId}/pubkey`);
    if (r.status === 202) return null;
    return this._json(r);
  }

  // ── Webhooks ──────────────────────────────────────────────────────────────

  async webhookRegister(callbackUrl, secret = '') {
    const r = await this._post('/v2/webhook', {
      device_id: this.device, url: callbackUrl, secret,
    });
    return this._json(r);
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────

  async getWsTicket() {
    const r = await this._post('/v2/ws-ticket', {});
    return this._json(r).ticket;
  }

  async stream(onBlob) {
    await this._ensureRelay();
    const ticket = await this.getWsTicket();
    const wsUrl  = this.relay.replace('https://', 'wss://').replace('http://', 'ws://') +
                   `/v2/stream?ticket=${ticket}`;
    const WS = typeof WebSocket !== 'undefined' ? WebSocket : _nodeRequire('ws');
    const ws = new WS(wsUrl);
    ws.onmessage = (e) => {
      try {
        const d = JSON.parse(typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data));
        if (d.type === 'blob_ready' && d.hash) onBlob(d.hash);
      } catch {}
    };
    return ws;
  }

  async ack(hash_) {
    return this._json(await this._post('/v2/ack', { hash: hash_, device_id: this.device }));
  }

  // ── Health & monitoring ───────────────────────────────────────────────────

  async health() { return this._json(await this._get('/health')); }
  async monitor() { return this._json(await this._get('/v2/monitor')); }
  async checkKey() { return this._json(await this._get('/v2/check-key')); }
  async keySector() { return this._json(await this._get('/v2/key-sector')); }

  // ── Audit & CT log ─────────────────────────────────────────────────────────

  async audit({ limit = 100, format = 'json' } = {}) {
    const r = await this._get('/v2/audit', { limit, format });
    if (format === 'csv') return new TextDecoder().decode(r.body);
    return this._json(r).entries || [];
  }

  async ctLog(from = 0, limit = 100) {
    return this._json(await this._get('/v2/ct', { from, limit }));
  }

  async ctProof(index) {
    return this._json(await this._get(`/v2/ct/${index}`));
  }

  async verifyReceipt(receipt) {
    const body = typeof receipt === 'string' ? { receipt } : { receipt: JSON.stringify(receipt) };
    const r = await this._post('/v2/verify-receipt', body);
    return this._json(r);
  }

  // ── DID ───────────────────────────────────────────────────────────────────

  async didRegister(dsaPub = '') {
    const kp = await this._loadKeypair();
    const r  = await this._post('/v2/did/register', {
      device_id: this.device,
      kem_pub:   kp.kem_pub,
      sig_pub:   kp.sig_pub || '',
      dsa_pub:   dsaPub || kp.sig_pub || '',
    });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  async didResolve(did) {
    const r = await this._get(`/v2/did/${did}`);
    if (r.status === 404) throw new GhostPipeError(`DID not found: ${did}`);
    return this._json(r);
  }

  async didList() { return this._json(await this._get('/v2/did')).dids || []; }

  // ── Team ──────────────────────────────────────────────────────────────────

  async teamDevices() { return this._json(await this._get('/v2/team/devices')); }

  async teamAddDevice(label) {
    const r = await this._post('/v2/team/add-device', { label });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  // ── Admin ─────────────────────────────────────────────────────────────────

  admin(token) { return new GhostPipeAdmin({ relay: this.relay, token, timeout: this.timeout }); }
}

// ── Admin client ──────────────────────────────────────────────────────────────

export class GhostPipeAdmin {
  constructor({ relay, token, timeout = 30000 }) {
    this.relay   = relay;
    this.token   = token;
    this.timeout = timeout;
  }

  async _request(method, path, body) {
    const headers = { 'User-Agent': UA, 'X-Admin-Token': this.token, 'Authorization': `Bearer ${this.token}` };
    if (body) headers['Content-Type'] = 'application/json';
    const { status, body: respBody } = await httpRequest({
      url: this.relay + path, method,
      body: body ? new TextEncoder().encode(JSON.stringify(body)) : undefined,
      headers, timeout: this.timeout,
    });
    if (status === 401) throw new AuthError('Invalid ADMIN_TOKEN');
    return { status, body: respBody };
  }

  _json(r) { return JSON.parse(new TextDecoder().decode(r.body)); }

  async stats() { return this._json(await this._request('GET', '/health')); }
  async keys() { return this._json(await this._request('GET', '/v2/admin/keys')); }

  async keyAdd({ label = '', plan = 'pro', email = '' } = {}) {
    const r = await this._request('POST', '/v2/admin/keys', { label, plan, email });
    if (r.status === 402) throw new LicenseError(new TextDecoder().decode(r.body));
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  async keyRevoke(key) {
    const r = await this._request('POST', '/v2/admin/keys/revoke', { key });
    return this._json(r);
  }

  async licenseStatus() {
    const d = await this.stats();
    return { edition: d.edition, active_keys: d.active_keys, key_limit: d.key_limit,
             license_expires: d.license_expires, license_issued_to: d.license_issued_to };
  }

  async reload() { return this._json(await this._request('POST', '/v2/reload-users', {})); }

  async sendWelcome(email, key, { plan = 'pro', label = '' } = {}) {
    return this._json(await this._request('POST', '/v2/admin/send-welcome', { email, key, plan, label }));
  }
}

// ── BIP39 helpers (Node.js only) ──────────────────────────────────────────────

async function _bip39Encode(entropy) {
  if (_isNode()) {
    const { entropyToMnemonic } = _nodeRequire('bip39');
    return entropyToMnemonic(Buffer.from(entropy).toString('hex'));
  }
  throw new GhostPipeError('BIP39 mnemonic generation requires Node.js + npm install bip39');
}

async function _bip39Decode(phrase) {
  if (_isNode()) {
    const { mnemonicToEntropy } = _nodeRequire('bip39');
    return new Uint8Array(Buffer.from(mnemonicToEntropy(phrase), 'hex'));
  }
  throw new GhostPipeError('BIP39 mnemonic decoding requires Node.js + npm install bip39');
}

async function _deriveDropKeys(entropy) {
  const subtle = crypto.subtle;
  const salt1  = new TextEncoder().encode('paramant-drop-v1');
  const info1  = new TextEncoder().encode('aes-key');
  const info2  = new TextEncoder().encode('lookup-id');
  const base   = await subtle.importKey('raw', entropy, { name: 'HKDF' }, false, ['deriveKey', 'deriveBits']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt1, info: info1 }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  const idBytes     = new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt1, info: info2 }, base, 256));
  const lookupHash  = await sha256Hex(idBytes);
  return { aesKey, lookupHash };
}

// ── Exports ───────────────────────────────────────────────────────────────────

export { SECTOR_RELAYS, fetchCapabilities, wireEncode, wireDecode, buildAAD, isV1 };
export default GhostPipe;
