'use strict';
/**
 * PARAMANT Ghost Pipe SDK — @paramant/connect v1.0.0
 * Post-quantum burn-on-read secure transport.
 *
 * Zero dependencies. Node.js >= 18.
 *
 * Quick start:
 *   const { GhostPipe } = require('@paramant/connect');
 *   const gp = new GhostPipe({ apiKey: 'pk_live_...', device: 'device-001' });
 *   const hash = await gp.send(Buffer.from('hello world'));
 *   const data = await gp.receive(hash);
 */

const crypto = require('crypto');
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const VERSION = '1.0.0';
const UA      = `paramant-sdk-js/${VERSION}`;
const BLOCK   = 5 * 1024 * 1024;

const SECTOR_RELAYS = {
  health:  'https://health.paramant.app',
  iot:     'https://iot.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  relay:   'https://relay.paramant.app',
};

class GhostPipeError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'GhostPipeError';
    this.code = code;
  }
}

/** Low-level HTTP request (no external deps). */
function request(url, { method = 'GET', headers = {}, body = null, timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u    = new URL(url);
    const lib  = u.protocol === 'https:' ? https : http;
    const opts = {
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname + u.search,
      method,
      headers:  { 'User-Agent': UA, ...headers },
    };
    const req = lib.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end',  () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => { req.destroy(); reject(new GhostPipeError('Request timeout', 'TIMEOUT')); });
    if (body) req.write(body);
    req.end();
  });
}

/** Detect best relay by health check. */
async function detectRelay(preferredSector) {
  const candidates = preferredSector && SECTOR_RELAYS[preferredSector]
    ? [SECTOR_RELAYS[preferredSector], SECTOR_RELAYS.relay]
    : [SECTOR_RELAYS.health, SECTOR_RELAYS.relay];

  for (const url of candidates) {
    try {
      const r = await request(url + '/health', { timeout: 4000 });
      if (r.status === 200) return url;
    } catch (_) {}
  }
  return SECTOR_RELAYS.relay;
}

/**
 * GhostPipe — main SDK class.
 *
 * @param {object} opts
 * @param {string} opts.apiKey   — API key (required)
 * @param {string} opts.device   — device identifier (required)
 * @param {string} [opts.relay]  — override relay URL
 * @param {string} [opts.sector] — preferred sector: health|iot|legal|finance
 */
class GhostPipe {
  constructor({ apiKey, device, relay = '', sector = '' } = {}) {
    if (!apiKey) throw new GhostPipeError('apiKey required', 'MISSING_KEY');
    if (!device) throw new GhostPipeError('device required', 'MISSING_DEVICE');
    this.apiKey  = apiKey;
    this.device  = device;
    this._relay  = relay || '';
    this._sector = sector;
    this._keyDir = path.join(os.homedir(), '.paramant', 'keys');
  }

  async _getRelay() {
    if (!this._relay) this._relay = await detectRelay(this._sector);
    return this._relay;
  }

  _headers(extra = {}) {
    return { 'X-API-Key': this.apiKey, 'X-Device-ID': this.device, ...extra };
  }

  async _get(relPath) {
    const base = await this._getRelay();
    const r    = await request(base + relPath, { headers: this._headers() });
    if (r.status === 401) throw new GhostPipeError('Invalid API key', 'UNAUTHORIZED');
    if (r.status === 429) throw new GhostPipeError('Rate limit exceeded', 'RATE_LIMIT');
    return { status: r.status, body: r.body, json: () => JSON.parse(r.body.toString()) };
  }

  async _post(relPath, bodyBuf, contentType = 'application/json') {
    const base = await this._getRelay();
    const r    = await request(base + relPath, {
      method:  'POST',
      headers: this._headers({ 'Content-Type': contentType, 'Content-Length': String(bodyBuf.length) }),
      body:    bodyBuf,
    });
    if (r.status === 401) throw new GhostPipeError('Invalid API key', 'UNAUTHORIZED');
    if (r.status === 429) throw new GhostPipeError('Rate limit exceeded', 'RATE_LIMIT');
    return { status: r.status, body: r.body, json: () => JSON.parse(r.body.toString()) };
  }

  // ── Keypair management ────────────────────────────────────────────────────

  _keyPath(suffix) {
    return path.join(this._keyDir, `${this.device}.${suffix}`);
  }

  _ensureKeyDir() {
    fs.mkdirSync(this._keyDir, { recursive: true, mode: 0o700 });
  }

  _loadOrGenerateECDH() {
    this._ensureKeyDir();
    const privPath = this._keyPath('ecdh.pem');
    const pubPath  = this._keyPath('ecdh.pub.pem');
    if (fs.existsSync(privPath)) {
      const privPem = fs.readFileSync(privPath, 'utf8');
      const kp      = crypto.createPrivateKey(privPem);
      const pub     = crypto.createPublicKey(kp);
      return { privateKey: kp, publicKey: pub };
    }
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    fs.writeFileSync(privPath, kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(pubPath,  kp.publicKey.export({ type: 'spki', format: 'pem' }));
    return kp;
  }

  // ── Core API ──────────────────────────────────────────────────────────────

  /**
   * Send encrypted data through the relay.
   * @param {Buffer|string} data
   * @param {object} [opts]
   * @param {number} [opts.ttl=300]  — seconds until auto-burn
   * @returns {Promise<string>}      — content hash for receiver
   */
  async send(data, { ttl = 300 } = {}) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length > BLOCK) throw new GhostPipeError(`Payload exceeds ${BLOCK} bytes`, 'TOO_LARGE');

    // Fetch receiver's ECDH public key
    const pubR = await this._fetchReceiverPubkey();

    // ECDH key agreement
    const { privateKey: senderPriv } = this._loadOrGenerateECDH();
    const senderPub = crypto.createPublicKey(senderPriv);
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(
      senderPriv.export({ type: 'pkcs8', format: 'der' }).slice(-32)
    );
    const receiverPubRaw = pubR.export({ type: 'spki', format: 'der' }).slice(-65);
    const shared = ecdh.computeSecret(receiverPubRaw);

    // Derive AES-256-GCM key
    const ikm  = crypto.createHash('sha256').update(shared).digest();
    const salt = crypto.randomBytes(16);
    const hkdf = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('paramant-ghost-pipe-v1'), 32);
    const aesKey = Buffer.from(hkdf);
    const iv     = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const enc    = Buffer.concat([cipher.update(buf), cipher.final()]);
    const tag    = cipher.getAuthTag();

    // Encode sender's public key
    const senderPubDer = senderPub.export({ type: 'spki', format: 'der' });

    // Blob layout: [4 magic][2 ver][16 salt][12 iv][16 tag][65 sender_pub][payload]
    const MAGIC = Buffer.from('PQHB');
    const VER   = Buffer.from([0x01, 0x00]);
    const blob  = Buffer.concat([MAGIC, VER, salt, iv, tag, senderPubDer.slice(-65), enc]);

    const r = await this._post(
      `/v2/send?device_id=${encodeURIComponent(this.device)}&ttl=${ttl}`,
      blob,
      'application/octet-stream'
    );
    if (r.status !== 200 && r.status !== 201) {
      throw new GhostPipeError(`Send failed: ${r.status} ${r.body.toString().slice(0,200)}`, 'SEND_FAILED');
    }
    const d = r.json();
    if (!d.hash) throw new GhostPipeError('No hash in response', 'BAD_RESPONSE');
    return d.hash;
  }

  /**
   * Receive and decrypt a blob by hash.
   * @param {string} hash
   * @returns {Promise<Buffer>}
   */
  async receive(hash) {
    const r = await this._get(`/v2/receive?hash=${encodeURIComponent(hash)}&device_id=${encodeURIComponent(this.device)}`);
    if (r.status === 404) throw new GhostPipeError('Blob not found (already burned or expired)', 'NOT_FOUND');
    if (r.status !== 200) throw new GhostPipeError(`Receive failed: ${r.status}`, 'RECEIVE_FAILED');

    const blob = r.body;
    if (blob.length < 4 + 2 + 16 + 12 + 16 + 65) throw new GhostPipeError('Blob too short', 'BAD_BLOB');

    const magic = blob.slice(0, 4);
    if (!magic.equals(Buffer.from('PQHB'))) throw new GhostPipeError('Invalid blob magic', 'BAD_MAGIC');

    let off    = 6;
    const salt = blob.slice(off, off + 16); off += 16;
    const iv   = blob.slice(off, off + 12); off += 12;
    const tag  = blob.slice(off, off + 16); off += 16;
    const senderPubRaw = blob.slice(off, off + 65); off += 65;
    const enc  = blob.slice(off);

    // ECDH key agreement
    const { privateKey: recvPriv } = this._loadOrGenerateECDH();
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(
      recvPriv.export({ type: 'pkcs8', format: 'der' }).slice(-32)
    );
    const shared = ecdh.computeSecret(senderPubRaw);

    const ikm  = crypto.createHash('sha256').update(shared).digest();
    const hkdf = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('paramant-ghost-pipe-v1'), 32);
    const aesKey = Buffer.from(hkdf);

    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(enc), decipher.final()]);
    } catch (_) {
      throw new GhostPipeError('Decryption failed — wrong key or corrupted blob', 'DECRYPT_FAILED');
    }
  }

  /**
   * Check blob status without consuming it.
   * @param {string} hash
   * @returns {Promise<object>}
   */
  async status(hash) {
    const r = await this._get(`/v2/status?hash=${encodeURIComponent(hash)}`);
    return r.json();
  }

  /**
   * Fetch relay health info.
   * @returns {Promise<object>}
   */
  async health() {
    const base = await this._getRelay();
    const r    = await request(base + '/health', { headers: this._headers() });
    return JSON.parse(r.body.toString());
  }

  /**
   * Fetch your audit log.
   * @param {number} [limit=100]
   * @returns {Promise<Array>}
   */
  async audit(limit = 100) {
    const r = await this._get(`/v2/audit?limit=${limit}`);
    const d = r.json();
    return d.entries || d.audit || d.log || [];
  }

  /** Listen for incoming messages (polling). */
  async listen(onReceive, { interval = 3000 } = {}) {
    while (true) {
      try {
        const r = await this._get(`/v2/pending?device_id=${encodeURIComponent(this.device)}`);
        if (r.status === 200) {
          const d = r.json();
          const hashes = d.hashes || d.pending || [];
          for (const hash of hashes) {
            try {
              const data = await this.receive(hash);
              await onReceive(data, { hash });
            } catch (e) {
              if (e.code !== 'NOT_FOUND') throw e;
            }
          }
        }
      } catch (e) {
        if (e.code !== 'TIMEOUT') throw e;
      }
      await new Promise((r) => setTimeout(r, interval));
    }
  }

  async _fetchReceiverPubkey() {
    const r  = await this._get(`/v2/pubkey?device_id=${encodeURIComponent(this.device)}`);
    const d  = r.json();
    const hex = d.ecdh_pub || d.pubkey || d.public_key;
    if (!hex) {
      // No pubkey registered yet — register our own and use it (loopback / same device)
      await this._registerPubkeys();
      const r2  = await this._get(`/v2/pubkey?device_id=${encodeURIComponent(this.device)}`);
      const d2  = r2.json();
      const h2  = d2.ecdh_pub || d2.pubkey || d2.public_key;
      if (!h2) throw new GhostPipeError('Could not register/fetch public key', 'PUBKEY_FAILED');
      return crypto.createPublicKey({ key: Buffer.from(h2, 'hex'), format: 'der', type: 'spki' });
    }
    return crypto.createPublicKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'spki' });
  }

  async _registerPubkeys() {
    const kp     = this._loadOrGenerateECDH();
    const pubHex = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    const body   = JSON.stringify({ device_id: this.device, ecdh_pub: pubHex });
    await this._post('/v2/register', Buffer.from(body));
  }
}

/**
 * GhostPipeCluster — multi-relay failover client.
 *
 * @param {object} opts
 * @param {string} opts.apiKey
 * @param {string} opts.device
 * @param {string[]} [opts.relays]  — override relay list
 */
class GhostPipeCluster {
  constructor({ apiKey, device, relays } = {}) {
    this._relayUrls = relays || Object.values(SECTOR_RELAYS);
    this._clients   = this._relayUrls.map((r) => new GhostPipe({ apiKey, device, relay: r }));
    this._healthy   = new Map(this._relayUrls.map((r) => [r, true]));
    this._startMonitor();
  }

  _startMonitor() {
    const check = async () => {
      for (let i = 0; i < this._relayUrls.length; i++) {
        try {
          const h = await this._clients[i].health();
          this._healthy.set(this._relayUrls[i], !!h.status);
        } catch (_) {
          this._healthy.set(this._relayUrls[i], false);
        }
      }
    };
    check();
    this._timer = setInterval(check, 30000);
    if (this._timer.unref) this._timer.unref();
  }

  _getClient() {
    for (let i = 0; i < this._relayUrls.length; i++) {
      if (this._healthy.get(this._relayUrls[i]) !== false) return this._clients[i];
    }
    return this._clients[0]; // fallback
  }

  async send(data, opts)     { return this._getClient().send(data, opts); }
  async receive(hash)        { return this._getClient().receive(hash); }
  async status(hash)         { return this._getClient().status(hash); }
  async health()             { return this._getClient().health(); }

  destroy() { clearInterval(this._timer); }
}

module.exports = { GhostPipe, GhostPipeCluster, GhostPipeError, SECTOR_RELAYS, VERSION };
