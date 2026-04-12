/**
 * PARAMANT Ghost Pipe SDK v2.4.1
 * ==================================
 * JavaScript/TypeScript SDK for Paramant Ghost Pipe — post-quantum encrypted file relay.
 *
 * Zero plaintext. Burn-on-read. EU/DE jurisdiction.
 *
 * Node.js:  import { GhostPipe } from 'paramant-sdk'
 * Browser:  <script type="module"> import { GhostPipe } from './index.js'
 */

'use strict';

const VERSION = '2.4.1';

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

/** SHA-256(kyber_pub_bytes || ecdh_pub_bytes) → 5×4 hex groups.
 * Must match parashare.html genFingerprint() exactly.
 */
async function computeFingerprint(kyberPubHex, ecdhPubHex) {
  const buf = hexToU8((kyberPubHex || '') + (ecdhPubHex || ''));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const h = [...hash.slice(0, 10)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

// ── Known-keys store ──────────────────────────────────────────────────────────
// Node.js: ~/.paramant/known_keys file (same format as Python SDK)
// Browser: localStorage['paramant_known_keys'] as JSON

function _loadKnownKeysNode() {
  try {
    const fs   = require('fs');
    const path = require('path');
    const p    = path.join(require('os').homedir(), '.paramant', 'known_keys');
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
    const fs   = require('fs');
    const path = require('path');
    const dir  = path.join(require('os').homedir(), '.paramant');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const p = path.join(dir, 'known_keys');
    const tmp = p + '.tmp';
    let content = '# PARAMANT known-keys — Trust On First Use (TOFU)\n# Format: device_id fingerprint registered_at\n';
    for (const [did, v] of Object.entries(keys)) content += `${did} ${v.fingerprint} ${v.registered_at}\n`;
    fs.writeFileSync(tmp, content, { mode: 0o600 });
    fs.renameSync(tmp, p);
  } catch(e) { console.warn('[paramant] known_keys write failed:', e.message); }
}

function _isNode() {
  return typeof process !== 'undefined' && process.versions?.node;
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

// ── Main SDK class ────────────────────────────────────────────────────────────

export class GhostPipe {
  /**
   * PARAMANT Ghost Pipe client.
   *
   * @param {object} opts
   * @param {string} opts.apiKey               pgp_... API key
   * @param {string} opts.device               Unique device identifier
   * @param {string} [opts.relay]              Relay URL (auto-detected if omitted)
   * @param {string} [opts.preSharedSecret]    Optional PSS for HKDF
   * @param {boolean} [opts.verifyFingerprints] Enable TOFU (default true)
   * @param {number} [opts.timeout]            HTTP timeout ms (default 30000)
   *
   * @example
   * const gp = new GhostPipe({ apiKey: 'pgp_...', device: 'my-device' })
   * const hash = await gp.send(data)
   * const data = await gp.receive(hash)
   */
  constructor({ apiKey, device, relay = '', preSharedSecret = '',
                verifyFingerprints = true, timeout = 30000 }) {
    if (!apiKey?.startsWith('pgp_')) throw new AuthError('API key must start with pgp_');
    this.apiKey             = apiKey;
    this.device             = device;
    this.relay              = relay;
    this.preSharedSecret    = preSharedSecret;
    this.verifyFingerprints = verifyFingerprints;
    this.timeout            = timeout;
    this._keypair           = null;
  }

  /** Auto-detect relay URL by trying all sector relays. */
  async _detectRelay() {
    for (const [, url] of Object.entries(SECTOR_RELAYS)) {
      try {
        // Fix D: send API key in X-Api-Key header — never in query string
        const { status, body } = await httpRequest({
          url: `${url}/v2/check-key`,
          headers: { 'User-Agent': UA, 'X-Api-Key': this.apiKey },
          timeout: 4000,
          retries: 1,
        });
        if (status === 200 && JSON.parse(new TextDecoder().decode(body)).valid) {
          return url;
        }
      } catch {}
    }
    return null;
  }

  /** Ensure relay URL is set. Call before any API method. */
  async _ensureRelay() {
    if (!this.relay) {
      this.relay = await this._detectRelay();
      // Fix D: fail explicitly — no silent fallback to arbitrary relay
      if (!this.relay) throw new RelayError(0, 'No reachable relay found for this API key. Set relay: option explicitly.');
    }
  }

  // ── HTTP helpers ───────────────────────────────────────────────────────────

  async _request(method, path, { body, contentType = 'application/json', params, extraHeaders } = {}) {
    await this._ensureRelay();
    let url = this.relay + path;
    if (params) url += '?' + new URLSearchParams(params).toString();
    const headers = { 'User-Agent': UA, 'X-Api-Key': this.apiKey };
    if (body) headers['Content-Type'] = contentType;
    if (extraHeaders) Object.assign(headers, extraHeaders);
    const { status, body: respBody } = await httpRequest({
      url, method, body, headers, timeout: this.timeout,
    });
    if (status === 401 || status === 403) throw new AuthError(`HTTP ${status}`);
    if (status === 402) throw new LicenseError(new TextDecoder().decode(respBody).slice(0, 200));
    if (status === 410) throw new BurnedError('Blob burned or expired');
    if (status === 429) throw new RateLimitError('Rate limited');
    return { status, body: respBody };
  }

  async _get(path, params) { return this._request('GET', path, { params }); }
  async _post(path, data) {
    return this._request('POST', path, { body: new TextEncoder().encode(JSON.stringify(data)) });
  }
  async _delete(path) { return this._request('DELETE', path); }

  _json(r) { return JSON.parse(new TextDecoder().decode(r.body)); }

  // ── Keypair ────────────────────────────────────────────────────────────────

  /**
   * Load or generate ECDH P-256 keypair for this device.
   * Keys are stored in localStorage (browser) or ~/.paramant/ (Node).
   */
  async _loadKeypair() {
    if (this._keypair) return this._keypair;
    const key = `paramant_kp_${this.device}`;
    if (_isNode()) {
      const fs   = require('fs');
      const path = require('path');
      const p = path.join(require('os').homedir(), '.paramant',
                           this.device.replace(/\//g, '_') + '.keypair.json');
      if (fs.existsSync(p)) { this._keypair = JSON.parse(fs.readFileSync(p, 'utf8')); return this._keypair; }
    } else {
      const stored = localStorage.getItem(key);
      if (stored) { this._keypair = JSON.parse(stored); return this._keypair; }
    }
    // Generate new keypair
    const kp = await this._generateKeypair();
    this._keypair = kp;
    if (_isNode()) {
      const fs   = require('fs');
      const path = require('path');
      const dir  = path.join(require('os').homedir(), '.paramant');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const p = path.join(dir, this.device.replace(/\//g, '_') + '.keypair.json');
      fs.writeFileSync(p, JSON.stringify(kp), { mode: 0o600 });
    } else {
      try { localStorage.setItem(key, JSON.stringify(kp)); } catch {}
    }
    return kp;
  }

  async _generateKeypair() {
    const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const pubRaw  = await crypto.subtle.exportKey('raw', ecdh.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', ecdh.privateKey);
    return {
      device:       this.device,
      ecdh_pub_raw: u8toHex(new Uint8Array(pubRaw)),
      ecdh_priv_jwk: JSON.stringify(privJwk),
      kyber_pub:    '',
      kyber_priv:   '',
    };
  }

  // ── TOFU ──────────────────────────────────────────────────────────────────

  async _tofuCheck(deviceId, kyberPubHex, ecdhPubHex, registeredAt = '') {
    const fp   = await computeFingerprint(kyberPubHex, ecdhPubHex);
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

  // ── Encryption/decryption ─────────────────────────────────────────────────

  async _fetchPubkeys(deviceId) {
    const { status, body } = await this._get(`/v2/pubkey/${deviceId}`);
    if (status === 404) throw new GhostPipeError(`No pubkeys for device '${deviceId}'. Call registerPubkeys() on receiver first.`);
    return this._json({ body });
  }

  async _encrypt(plaintext, ecdhPubHex, kyberPubHex, padBlock = 5 * 1024 * 1024, pss = '') {
    // ECDH ephemeral key
    const ephKey = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephKey.publicKey));
    // Import receiver ECDH public key
    const rxKey = await crypto.subtle.importKey('raw', hexToU8(ecdhPubHex),
      { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const ecdhSS = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: rxKey }, ephKey.privateKey, 256));

    // PSS hash
    let pssHash = new Uint8Array(0);
    if (pss) {
      const pssBytes = new TextEncoder().encode(pss);
      pssHash = new Uint8Array(await crypto.subtle.digest('SHA-256', pssBytes));
    }

    // KEM placeholder (kyber not available in pure JS — use empty)
    const kct = new Uint8Array(0);
    const kss = new Uint8Array(0);

    // HKDF
    const salt = kct.length >= 32 ? kct.slice(0, 32) : ecdhSS.slice(0, 32);
    const ikm  = concat(ecdhSS, kss, pssHash);
    const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveKey']);
    const aesKey  = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('aes-key') },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad   = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00]);
    const ct    = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext));

    // Bundle: u32(ephPubLen) || ephPub || u32(kctLen) || kct
    const bundle = concat(u32be(ephPubRaw.length), ephPubRaw, u32be(kct.length), kct);
    const packet = concat(u32be(bundle.length), bundle, nonce, u32be(ct.length), ct);
    if (packet.length > padBlock) throw new GhostPipeError(`Data too large (${plaintext.length} bytes) for block ${padBlock}`);
    const padding = crypto.getRandomValues(new Uint8Array(padBlock - packet.length));
    const blob = concat(packet, padding);
    const hash = await sha256Hex(blob);
    return { blob, hash };
  }

  async _decrypt(blob, pss = '') {
    const kp = await this._loadKeypair();
    let o = 0;
    const blen   = readU32be(blob, o); o += 4;
    const bundle = blob.slice(o, o + blen); o += blen;
    let bo = 0;
    const eplen  = readU32be(bundle, bo); bo += 4;
    const ephPub = bundle.slice(bo, bo + eplen); bo += eplen;
    const klen   = readU32be(bundle, bo); bo += 4;
    // kct (unused in JS — no Kyber)
    bo += klen;
    const nonce  = blob.slice(o, o + 12); o += 12;
    const ctlen  = readU32be(blob, o); o += 4;
    const ct     = blob.slice(o, o + ctlen);

    // ECDH
    const privJwk  = JSON.parse(kp.ecdh_priv_jwk);
    const privKey  = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const rxEphPub = await crypto.subtle.importKey('raw', ephPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const ecdhSS   = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: rxEphPub }, privKey, 256));

    let pssHash = new Uint8Array(0);
    if (pss) {
      const pssBytes = new TextEncoder().encode(pss);
      pssHash = new Uint8Array(await crypto.subtle.digest('SHA-256', pssBytes));
    }

    const kss  = new Uint8Array(0);
    const salt = ecdhSS.slice(0, 32);
    const ikm  = concat(ecdhSS, kss, pssHash);
    const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveKey']);
    const aesKey  = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('aes-key') },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const aad = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, ct));
  }

  // ── Pubkey registration ────────────────────────────────────────────────────

  /**
   * Register ECDH P-256 public key with the relay.
   * Call once before a receiver can accept transfers.
   *
   * @returns {Promise<object>} {ok, fingerprint, ct_index}
   *
   * @example
   * await gp.registerPubkeys()
   */
  async registerPubkeys() {
    const kp = await this._loadKeypair();
    const { status, body } = await this._post('/v2/pubkey', {
      device_id: this.device,
      ecdh_pub:  kp.ecdh_pub_raw,
      kyber_pub: kp.kyber_pub || '',
    });
    if (status !== 200 && status !== 409) throw new RelayError(status, new TextDecoder().decode(body));
    return this._json({ body });
  }

  // ── Core transfer ──────────────────────────────────────────────────────────

  /**
   * Encrypt and upload data to the relay. Returns a burn-on-read hash.
   *
   * @param {Uint8Array} data          Data to send.
   * @param {object} [opts]
   * @param {string} [opts.recipient]  Receiver device ID (default: self.device).
   * @param {number} [opts.ttl]        TTL seconds (default 3600).
   * @param {number} [opts.maxViews]   Max downloads before burn (default 1).
   * @param {number} [opts.padBlock]   Padding block size (default 5MB).
   * @param {string} [opts.preSharedSecret] PSS override.
   * @returns {Promise<string>} SHA-256 hash.
   *
   * @example
   * const hash = await gp.send(data, { recipient: 'pacs-001' })
   */
  async send(data, { recipient, ttl = 3600, maxViews = 1, padBlock = 5 * 1024 * 1024,
                     preSharedSecret } = {}) {
    const target = recipient || this.device;
    const pss    = preSharedSecret ?? this.preSharedSecret;
    const pubkeys = await this._fetchPubkeys(target);
    await this._tofuCheck(target, pubkeys.kyber_pub || '', pubkeys.ecdh_pub, pubkeys.registered_at || '');
    const { blob, hash } = await this._encrypt(data, pubkeys.ecdh_pub, pubkeys.kyber_pub || '', padBlock, pss);
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

  /**
   * Download and decrypt a blob. Burn-on-read: works once.
   *
   * @param {string} hash_  SHA-256 hash from sender's send() call.
   * @param {object} [opts]
   * @param {string} [opts.preSharedSecret] Must match what sender used.
   * @returns {Promise<Uint8Array>} Decrypted data.
   *
   * @example
   * const data = await gp.receive('a3f2...')
   */
  async receive(hash_, { preSharedSecret } = {}) {
    const pss = preSharedSecret ?? this.preSharedSecret;
    const { status, body } = await this._get(`/v2/outbound/${hash_}`);
    if (status === 404) throw new BurnedError('Blob not found: expired, already retrieved, or never stored.');
    if (status !== 200) throw new RelayError(status, new TextDecoder().decode(body));
    return this._decrypt(body, pss);
  }

  /**
   * Check if a blob is still available.
   *
   * @param {string} hash_ SHA-256 hash.
   * @returns {Promise<object>} {available, bytes, ttl_remaining_ms}
   */
  async status(hash_) {
    const r = await this._get(`/v2/status/${hash_}`);
    return this._json(r);
  }

  /**
   * Cancel (delete) a blob before it is retrieved.
   *
   * @param {string} hash_ SHA-256 hash.
   * @returns {Promise<object>} {ok: true}
   */
  async cancel(hash_) {
    const r = await this._delete(`/v2/inbound/${hash_}`);
    return this._json(r);
  }

  // ── Drop (anonymous BIP39) ────────────────────────────────────────────────

  /**
   * Send data anonymously using a 12-word BIP39 mnemonic as the key.
   * Requires: npm install bip39 (Node.js)
   *
   * @param {Uint8Array} data
   * @param {object} [opts]
   * @param {number} [opts.ttl] Seconds (default 3600).
   * @returns {Promise<string>} 12-word BIP39 mnemonic.
   *
   * @example
   * const mnemonic = await gp.drop(data)
   */
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
    const blob = concat(packet, crypto.getRandomValues(new Uint8Array(padBlock - packet.length)));
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

  /**
   * Retrieve a BIP39 drop. Burn-on-read: works once.
   *
   * @param {string} phrase 12-word BIP39 mnemonic.
   * @returns {Promise<Uint8Array>} Decrypted data.
   */
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

  /**
   * Fetch and return fingerprint for a device.
   *
   * @param {string} [deviceId] Device to check (default: this.device).
   * @returns {Promise<string>} Fingerprint in XXXX-XXXX-XXXX-XXXX-XXXX format.
   */
  async fingerprint(deviceId) {
    const target = deviceId || this.device;
    const { status, body } = await this._get(`/v2/fingerprint/${target}`);
    if (status === 404) throw new GhostPipeError(`No pubkeys for device '${target}'`);
    const d = this._json({ body });
    return d.fingerprint;
  }

  /**
   * Verify a fingerprint against the relay's stored pubkey.
   *
   * @param {string} deviceId
   * @param {string} fingerprint
   * @returns {Promise<boolean>}
   */
  async verifyFingerprint(deviceId, fingerprint) {
    const { status, body } = await this._post('/v2/pubkey/verify', { device_id: deviceId, fingerprint });
    return this._json({ body }).match === true;
  }

  /**
   * Trust a device: store fingerprint in known_keys.
   *
   * @param {string} deviceId
   * @param {string} [fingerprint] If omitted, fetched from relay.
   * @returns {Promise<string>} Stored fingerprint.
   */
  async trust(deviceId, fingerprint) {
    if (!fingerprint) fingerprint = await this.fingerprint(deviceId);
    const keys = loadKnownKeys();
    keys[deviceId] = { fingerprint, registered_at: new Date().toISOString() };
    saveKnownKeys(keys);
    return fingerprint;
  }

  /**
   * Remove a device from the local known_keys store.
   *
   * @param {string} deviceId
   */
  untrust(deviceId) {
    const keys = loadKnownKeys();
    delete keys[deviceId];
    saveKnownKeys(keys);
  }

  /**
   * List all trusted devices.
   *
   * @returns {Array<{deviceId: string, fingerprint: string, registeredAt: string}>}
   */
  knownDevices() {
    const keys = loadKnownKeys();
    return Object.entries(keys).map(([deviceId, v]) => ({
      deviceId, fingerprint: v.fingerprint, registeredAt: v.registered_at,
    }));
  }

  // ── Session (PSS) ─────────────────────────────────────────────────────────

  /**
   * Create a PSS session. Sender calls this.
   *
   * @param {string} pss Pre-shared secret.
   * @param {number} [ttlMs] Session lifetime ms (default 600000).
   * @returns {Promise<object>} {ok, session_id, expires_ms}
   */
  async sessionCreate(pss, ttlMs = 600_000) {
    const commitment = u8toHex(await sha256Bytes(new TextEncoder().encode(pss)));
    const r = await this._post('/v2/session/create', { commitment, ttl_ms: ttlMs });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  /**
   * Join a PSS session. Receiver calls this.
   *
   * @param {string} sessionId Session ID from sender's sessionCreate().
   * @param {string} pss       Pre-shared secret (must match sender's).
   * @returns {Promise<object>}
   */
  async sessionJoin(sessionId, pss) {
    const kp = await this._loadKeypair();
    const r = await this._post('/v2/session/join', {
      session_id: sessionId, pss,
      ecdh_pub: kp.ecdh_pub_raw, kyber_pub: kp.kyber_pub || '',
    });
    if (r.status === 403) throw new AuthError('PSS mismatch');
    return this._json(r);
  }

  /**
   * Poll for receiver pubkeys in a PSS session. Returns null if not joined yet.
   *
   * @param {string} sessionId
   * @returns {Promise<object|null>}
   */
  async sessionPubkey(sessionId) {
    const r = await this._get(`/v2/session/${sessionId}/pubkey`);
    if (r.status === 202) return null;
    return this._json(r);
  }

  // ── Webhooks ──────────────────────────────────────────────────────────────

  /**
   * Register a webhook for push notifications.
   *
   * @param {string} callbackUrl Public HTTPS URL.
   * @param {string} [secret]    HMAC-SHA256 signing secret.
   * @returns {Promise<object>}
   */
  async webhookRegister(callbackUrl, secret = '') {
    const r = await this._post('/v2/webhook', {
      device_id: this.device, url: callbackUrl, secret,
    });
    return this._json(r);
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────

  /**
   * Get a one-time WebSocket ticket.
   *
   * @returns {Promise<string>} Ticket string.
   */
  async getWsTicket() {
    const r = await this._post('/v2/ws-ticket', {});
    return this._json(r).ticket;
  }

  /**
   * Stream blobs in real-time via WebSocket.
   *
   * @param {function} onBlob  Callback(hash: string) — called for each new blob.
   * @returns {Promise<WebSocket>} WebSocket instance.
   *
   * @example
   * await gp.stream(async hash => {
   *   const data = await gp.receive(hash)
   *   console.log('received', data.length, 'bytes')
   * })
   */
  async stream(onBlob) {
    await this._ensureRelay();
    const ticket = await this.getWsTicket();
    const wsUrl  = this.relay.replace('https://', 'wss://').replace('http://', 'ws://') +
                   `/v2/stream?ticket=${ticket}`;
    const WS = typeof WebSocket !== 'undefined' ? WebSocket : require('ws');
    const ws = new WS(wsUrl);
    ws.onmessage = (e) => {
      try {
        const d = JSON.parse(typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data));
        if (d.type === 'blob_ready' && d.hash) onBlob(d.hash);
      } catch {}
    };
    return ws;
  }

  // ── Ack ───────────────────────────────────────────────────────────────────

  /**
   * Acknowledge receipt of a blob.
   *
   * @param {string} hash_
   * @returns {Promise<object>}
   */
  async ack(hash_) {
    return this._json(await this._post('/v2/ack', { hash: hash_, device_id: this.device }));
  }

  // ── Health & monitoring ───────────────────────────────────────────────────

  /** @returns {Promise<object>} {ok, version, sector, edition} */
  async health() { return this._json(await this._get('/health')); }

  /** @returns {Promise<object>} {ok, plan, blobs_in_flight, delivery} */
  async monitor() { return this._json(await this._get('/v2/monitor')); }

  /** @returns {Promise<object>} {valid, plan} */
  async checkKey() { return this._json(await this._get('/v2/check-key')); }

  /** @returns {Promise<object>} {sector, plan, team_id} */
  async keySector() { return this._json(await this._get('/v2/key-sector')); }

  // ── Audit ─────────────────────────────────────────────────────────────────

  /**
   * Fetch audit log entries.
   *
   * @param {object} [opts]
   * @param {number} [opts.limit]  Max entries (default 100).
   * @param {string} [opts.format] 'json' or 'csv'.
   * @returns {Promise<Array|string>}
   */
  async audit({ limit = 100, format = 'json' } = {}) {
    const r = await this._get('/v2/audit', { limit, format });
    if (format === 'csv') return new TextDecoder().decode(r.body);
    return this._json(r).entries || [];
  }

  // ── CT Log ────────────────────────────────────────────────────────────────

  /**
   * @param {number} [from] Start index.
   * @param {number} [limit] Max entries.
   * @returns {Promise<object>}
   */
  async ctLog(from = 0, limit = 100) {
    return this._json(await this._get('/v2/ct', { from, limit }));
  }

  /**
   * @param {number} index CT log index.
   * @returns {Promise<object>}
   */
  async ctProof(index) {
    return this._json(await this._get(`/v2/ct/${index}`));
  }

  // ── DID ───────────────────────────────────────────────────────────────────

  /**
   * Register a DID for this device.
   *
   * @param {string} [dsaPub] ML-DSA-65 public key hex.
   * @returns {Promise<object>} {ok, did, document, ct_index}
   */
  async didRegister(dsaPub = '') {
    const kp = await this._loadKeypair();
    const r  = await this._post('/v2/did/register', {
      device_id: this.device,
      ecdh_pub:  kp.ecdh_pub_raw,
      kyber_pub: kp.kyber_pub || '',
      dsa_pub:   dsaPub,
    });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  /**
   * Resolve a DID document.
   *
   * @param {string} did
   * @returns {Promise<object>}
   */
  async didResolve(did) {
    const r = await this._get(`/v2/did/${did}`);
    if (r.status === 404) throw new GhostPipeError(`DID not found: ${did}`);
    return this._json(r);
  }

  /** @returns {Promise<Array>} */
  async didList() {
    return this._json(await this._get('/v2/did')).dids || [];
  }

  // ── Team ──────────────────────────────────────────────────────────────────

  /** @returns {Promise<object>} */
  async teamDevices() { return this._json(await this._get('/v2/team/devices')); }

  /**
   * @param {string} label
   * @returns {Promise<object>} {ok, key, label, team_id}
   */
  async teamAddDevice(label) {
    const r = await this._post('/v2/team/add-device', { label });
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  // ── Admin ─────────────────────────────────────────────────────────────────

  /**
   * Return admin client.
   *
   * @param {string} token Admin token.
   * @returns {GhostPipeAdmin}
   */
  admin(token) { return new GhostPipeAdmin({ relay: this.relay, token, timeout: this.timeout }); }
}

// ── Admin client ──────────────────────────────────────────────────────────────

export class GhostPipeAdmin {
  /**
   * @param {object} opts
   * @param {string} opts.relay
   * @param {string} opts.token
   * @param {number} [opts.timeout]
   */
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

  /** @returns {Promise<object>} Full health/stats */
  async stats() { return this._json(await this._request('GET', '/health')); }

  /** @returns {Promise<object>} {ok, count, keys, license} */
  async keys() { return this._json(await this._request('GET', '/v2/admin/keys')); }

  /**
   * @param {object} opts
   * @param {string} [opts.label]
   * @param {string} [opts.plan]
   * @param {string} [opts.email]
   * @returns {Promise<object>} {ok, key, plan, label}
   */
  async keyAdd({ label = '', plan = 'pro', email = '' } = {}) {
    const r = await this._request('POST', '/v2/admin/keys', { label, plan, email });
    if (r.status === 402) throw new LicenseError(new TextDecoder().decode(r.body));
    if (r.status !== 200) throw new RelayError(r.status, new TextDecoder().decode(r.body));
    return this._json(r);
  }

  /**
   * @param {string} key pgp_... key to revoke.
   * @returns {Promise<object>}
   */
  async keyRevoke(key) {
    const r = await this._request('POST', '/v2/admin/keys/revoke', { key });
    return this._json(r);
  }

  /** @returns {Promise<object>} License and edition info */
  async licenseStatus() {
    const d = await this.stats();
    return { edition: d.edition, active_keys: d.active_keys, key_limit: d.key_limit,
             license_expires: d.license_expires, license_issued_to: d.license_issued_to };
  }

  /** @returns {Promise<object>} {ok, loaded} */
  async reload() { return this._json(await this._request('POST', '/v2/reload-users', {})); }

  /**
   * Send welcome email with API key.
   * @param {string} email
   * @param {string} key
   * @param {object} [opts]
   */
  async sendWelcome(email, key, { plan = 'pro', label = '' } = {}) {
    return this._json(await this._request('POST', '/v2/admin/send-welcome', { email, key, plan, label }));
  }
}

// ── BIP39 helpers (Node.js only) ──────────────────────────────────────────────

async function _bip39Encode(entropy) {
  if (_isNode()) {
    const { generateMnemonic, entropyToMnemonic } = require('bip39');
    return entropyToMnemonic(Buffer.from(entropy).toString('hex'));
  }
  throw new GhostPipeError('BIP39 mnemonic generation requires Node.js + npm install bip39');
}

async function _bip39Decode(phrase) {
  if (_isNode()) {
    const { mnemonicToEntropy } = require('bip39');
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

export { VERSION, SECTOR_RELAYS };
export default GhostPipe;
