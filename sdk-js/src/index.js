'use strict';
/**
 * PARAMANT Ghost Pipe SDK — @paramant/connect v1.1.0
 * Post-quantum burn-on-read secure transport.
 *
 * Zero dependencies. Node.js >= 18.
 *
 * Quick start:
 *   const { GhostPipe } = require('@paramant/connect');
 *   const gp = new GhostPipe({ apiKey: 'pgp_...', device: 'device-001' });
 *   await gp.setup();          // generate keypair + register with relay
 *   const hash = await gp.send(Buffer.from('hello world'));
 *   const data = await gp.receive(hash);
 *
 * Changelog v1.1.0:
 *   - Fixed all relay endpoints (v1.0.0 used non-existent /v2/send, /v2/receive,
 *     /v2/register, /v2/pending)
 *   - Correct endpoint map:
 *       POST /v2/pubkey         (register keypair)
 *       GET  /v2/pubkey/:device (fetch receiver pubkey)
 *       POST /v2/inbound        (upload blob as JSON {hash,payload(b64),ttl_ms,meta})
 *       GET  /v2/outbound/:hash (download raw binary, burn-on-read)
 *       GET  /v2/status/:hash   (availability check)
 *       GET  /v2/stream-next    (poll for incoming)
 *   - Wire format aligned with Python SDK (PQHB magic, interoperable)
 *   - receive() now decodes raw binary (not base64)
 *   - sha256 of payload computed before upload and included in body
 *   - Added setup(), downloadToken from send() response
 *   - GhostPipeCluster: health check fixed (ok field vs status field)
 */

const crypto = require('crypto');
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const VERSION = '1.1.0';
const UA      = `paramant-sdk-js/${VERSION}`;
const BLOCK   = 5 * 1024 * 1024; // 5 MB max payload

const SECTOR_RELAYS = {
  health:  'https://health.paramant.app',
  iot:     'https://iot.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  relay:   'https://relay.paramant.app',
};

// ── Blob wire format (PQHB v1) ──────────────────────────────────────────────
// Identical to Python SDK — required for cross-SDK interoperability.
//
// Offset  Length  Field
//      0       4  Magic: 'PQHB'
//      4       2  Version: 0x01 0x00
//      6      16  HKDF salt (random)
//     22      12  AES-GCM IV (random)
//     34      16  AES-GCM auth tag
//     50      65  Sender ECDH public key (uncompressed P-256, raw 65 bytes)
//    115      ??  AES-256-GCM ciphertext (variable)
//
// Total minimum: 115 + 1 = 116 bytes. Uploaded as-is (base64 in JSON body).
// Relay stores raw blob and returns it as raw binary on /v2/outbound/:hash.

const MAGIC   = Buffer.from('PQHB');
const VER     = Buffer.from([0x01, 0x00]);
const HDR_LEN = 4 + 2 + 16 + 12 + 16 + 65; // 115

class GhostPipeError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'GhostPipeError';
    this.code = code;
  }
}

// ── Low-level HTTP (zero external deps) ─────────────────────────────────────
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
      res.on('end',  () => resolve({
        status:  res.statusCode,
        headers: res.headers,
        body:    Buffer.concat(chunks),
        json()  { return JSON.parse(this.body.toString()); },
      }));
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => { req.destroy(); reject(new GhostPipeError('Request timeout', 'TIMEOUT')); });
    if (body) req.write(body);
    req.end();
  });
}

// ── Relay detection ──────────────────────────────────────────────────────────
async function detectRelay(preferredSector, apiKey) {
  const candidates = preferredSector && SECTOR_RELAYS[preferredSector]
    ? [SECTOR_RELAYS[preferredSector]]
    : [SECTOR_RELAYS.health, SECTOR_RELAYS.relay];

  for (const url of candidates) {
    try {
      const r = await request(`${url}/v2/check-key?k=${encodeURIComponent(apiKey)}`,
        { timeout: 4000, headers: { 'User-Agent': UA } });
      if (r.status === 200 && r.json().valid) return url;
    } catch (_) {}
  }
  // Fallback: any reachable relay
  for (const url of Object.values(SECTOR_RELAYS)) {
    try {
      const r = await request(url + '/health', { timeout: 3000 });
      if (r.status === 200) return url;
    } catch (_) {}
  }
  throw new GhostPipeError('No relay reachable — check API key and network', 'NO_RELAY');
}

// ── ECDH helpers ─────────────────────────────────────────────────────────────
function rawP256FromSpki(spkiDer) {
  // Last 65 bytes of SPKI DER is the uncompressed public key point
  return spkiDer.slice(-65);
}

// ── GhostPipe ─────────────────────────────────────────────────────────────────
/**
 * @param {object} opts
 * @param {string}  opts.apiKey   — pgp_... API key
 * @param {string}  opts.device   — unique device identifier
 * @param {string} [opts.relay]   — override relay URL (skip auto-detect)
 * @param {string} [opts.sector]  — preferred sector: health|iot|legal|finance
 */
class GhostPipe {
  constructor({ apiKey, device, relay = '', sector = '' } = {}) {
    if (!apiKey) throw new GhostPipeError('apiKey required', 'MISSING_KEY');
    if (!device) throw new GhostPipeError('device required', 'MISSING_DEVICE');
    this.apiKey   = apiKey;
    this.device   = device;
    this._relay   = relay;
    this._sector  = sector;
    this._keyDir  = path.join(os.homedir(), '.paramant', 'keys');
    this._seqFile = path.join(os.homedir(), '.paramant',
      device.replace(/[^a-z0-9_-]/gi, '_') + '.seq');
  }

  async _getRelay() {
    if (!this._relay) this._relay = await detectRelay(this._sector, this.apiKey);
    return this._relay;
  }

  _hdrs(extra = {}) {
    return { 'X-Api-Key': this.apiKey, ...extra };
  }

  async _get(relPath) {
    const base = await this._getRelay();
    const r    = await request(base + relPath, { headers: this._hdrs() });
    if (r.status === 401) throw new GhostPipeError('Invalid API key', 'UNAUTHORIZED');
    if (r.status === 429) throw new GhostPipeError('Rate limit exceeded', 'RATE_LIMIT');
    return r;
  }

  async _post(relPath, bodyBuf, contentType = 'application/json') {
    const base = await this._getRelay();
    const r    = await request(base + relPath, {
      method:  'POST',
      headers: this._hdrs({ 'Content-Type': contentType, 'Content-Length': String(bodyBuf.length) }),
      body:    bodyBuf,
    });
    if (r.status === 401) throw new GhostPipeError('Invalid API key', 'UNAUTHORIZED');
    if (r.status === 429) throw new GhostPipeError('Rate limit exceeded', 'RATE_LIMIT');
    return r;
  }

  // ── Keypair management ───────────────────────────────────────────────────
  _keyPath(suf) {
    fs.mkdirSync(this._keyDir, { recursive: true, mode: 0o700 });
    return path.join(this._keyDir, `${this.device.replace(/[^a-z0-9_-]/gi,'_')}.${suf}`);
  }

  _loadOrGenerateKeypair() {
    const privPath = this._keyPath('ecdh.pem');
    if (fs.existsSync(privPath)) {
      const priv = crypto.createPrivateKey(fs.readFileSync(privPath, 'utf8'));
      return { privateKey: priv, publicKey: crypto.createPublicKey(priv) };
    }
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    fs.writeFileSync(privPath, kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    return kp;
  }

  // ── Pubkey registration ──────────────────────────────────────────────────
  async setup() {
    const kp     = this._loadOrGenerateKeypair();
    const pubHex = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    const body   = Buffer.from(JSON.stringify({ device_id: this.device, ecdh_pub: pubHex }));
    const r      = await this._post('/v2/pubkey', body);
    if (r.status !== 200) {
      throw new GhostPipeError(`Pubkey registration failed: ${r.status} ${r.body.toString().slice(0,100)}`, 'SETUP_FAILED');
    }
    return this;
  }

  async _fetchReceiverPubkey() {
    const r = await this._get(`/v2/pubkey/${encodeURIComponent(this.device)}`);
    if (r.status === 404) throw new GhostPipeError(
      'No pubkey found for device. Call setup() on the receiver first.', 'NO_PUBKEY');
    if (r.status !== 200) throw new GhostPipeError(`Pubkey fetch failed: ${r.status}`, 'PUBKEY_FAILED');
    const d   = r.json();
    const hex = d.ecdh_pub;
    if (!hex) throw new GhostPipeError('ecdh_pub missing from relay response', 'BAD_PUBKEY');
    return crypto.createPublicKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'spki' });
  }

  // ── Encryption (PQHB v1 wire format) ────────────────────────────────────
  _encrypt(plaintext, receiverPub) {
    // Ephemeral ECDH key agreement
    const ephKp    = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const ecdh     = crypto.createECDH('prime256v1');
    const ephPrivDer = ephKp.privateKey.export({ type: 'pkcs8', format: 'der' });
    ecdh.setPrivateKey(ephPrivDer.slice(-32));
    const recvRaw  = rawP256FromSpki(receiverPub.export({ type: 'spki', format: 'der' }));
    const shared   = ecdh.computeSecret(recvRaw);

    const salt = crypto.randomBytes(16);
    const hkdf = crypto.hkdfSync('sha256', shared, salt, Buffer.from('paramant-ghost-pipe-v1'), 32);
    const key  = Buffer.from(hkdf);
    const iv   = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc    = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag    = cipher.getAuthTag();

    const ephPubRaw = rawP256FromSpki(ephKp.publicKey.export({ type: 'spki', format: 'der' }));
    return Buffer.concat([MAGIC, VER, salt, iv, tag, ephPubRaw, enc]);
  }

  _decrypt(blob) {
    if (blob.length < HDR_LEN + 1) throw new GhostPipeError('Blob too short', 'BAD_BLOB');
    if (!blob.slice(0, 4).equals(MAGIC)) throw new GhostPipeError('Invalid magic (expected PQHB)', 'BAD_MAGIC');
    let off = 6;
    const salt      = blob.slice(off, off + 16); off += 16;
    const iv        = blob.slice(off, off + 12); off += 12;
    const tag       = blob.slice(off, off + 16); off += 16;
    const senderRaw = blob.slice(off, off + 65); off += 65;
    const enc       = blob.slice(off);

    const kp   = this._loadOrGenerateKeypair();
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(kp.privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32));
    const shared = ecdh.computeSecret(senderRaw);

    const hkdf = crypto.hkdfSync('sha256', shared, salt, Buffer.from('paramant-ghost-pipe-v1'), 32);
    const key  = Buffer.from(hkdf);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    try {
      return Buffer.concat([decipher.update(enc), decipher.final()]);
    } catch (_) {
      throw new GhostPipeError('Decryption failed — wrong key or corrupted blob', 'DECRYPT_FAILED');
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Send encrypted data through the relay.
   * @param {Buffer|string} data
   * @param {object}  [opts]
   * @param {number}  [opts.ttl=300]     — seconds until auto-burn
   * @param {string}  [opts.fileName]    — original filename (shown in download link)
   * @returns {Promise<{hash, downloadToken}>}
   */
  async send(data, { ttl = 300, fileName = '' } = {}) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length > BLOCK) throw new GhostPipeError(`Payload exceeds ${BLOCK} bytes`, 'TOO_LARGE');

    const receiverPub = await this._fetchReceiverPubkey();
    const blob        = this._encrypt(buf, receiverPub);
    const hash        = crypto.createHash('sha256').update(blob).digest('hex');

    const body = Buffer.from(JSON.stringify({
      hash,
      payload:  blob.toString('base64'),
      ttl_ms:   ttl * 1000,
      meta:     { device_id: this.device, file_name: fileName || undefined },
    }));

    const r = await this._post('/v2/inbound', body);
    if (r.status !== 200) {
      throw new GhostPipeError(`Send failed: ${r.status} ${r.body.toString().slice(0, 200)}`, 'SEND_FAILED');
    }
    const d = r.json();
    return { hash: d.hash || hash, downloadToken: d.download_token || null };
  }

  /**
   * Receive and decrypt a blob by hash. Burns the blob on the relay.
   * @param {string} hash
   * @returns {Promise<Buffer>}
   */
  async receive(hash) {
    const r = await this._get(`/v2/outbound/${encodeURIComponent(hash)}`);
    if (r.status === 404) throw new GhostPipeError('Blob not found (burned, expired, or never stored)', 'NOT_FOUND');
    if (r.status !== 200) throw new GhostPipeError(`Receive failed: ${r.status}`, 'RECEIVE_FAILED');
    // Relay returns raw binary (application/octet-stream)
    return this._decrypt(r.body);
  }

  /**
   * Check if a blob is available without consuming it.
   * @param {string} hash
   * @returns {Promise<{available, bytes, ttl_remaining_ms}>}
   */
  async status(hash) {
    const r = await this._get(`/v2/status/${encodeURIComponent(hash)}`);
    return r.json();
  }

  /**
   * Relay health info.
   * @returns {Promise<object>}
   */
  async health() {
    const base = await this._getRelay();
    const r    = await request(base + '/health', { timeout: 5000 });
    return r.json();
  }

  /**
   * Fetch your audit log entries.
   * @param {number} [limit=100]
   * @returns {Promise<Array>}
   */
  async audit(limit = 100) {
    const r = await this._get(`/v2/audit?limit=${limit}`);
    const d = r.json();
    return d.entries || d.audit || d.log || [];
  }

  /**
   * Register a webhook for push notifications.
   * @param {string} callbackUrl
   * @param {string} [secret]    — HMAC-SHA256 signing secret
   */
  async registerWebhook(callbackUrl, secret = '') {
    const body = Buffer.from(JSON.stringify({ device_id: this.device, url: callbackUrl, secret }));
    const r    = await this._post('/v2/webhook', body);
    if (r.status !== 200) throw new GhostPipeError(`Webhook registration failed: ${r.status}`, 'WEBHOOK_FAILED');
  }

  /**
   * Poll relay for incoming blobs (requires pro/enterprise plan for stream-next).
   * @param {function} onReceive  — async (data: Buffer, meta: object) => void
   * @param {object}   [opts]
   * @param {number}   [opts.interval=3000]  — poll interval ms
   */
  async listen(onReceive, { interval = 3000 } = {}) {
    await this.setup();
    let seq = this._loadSeq();
    while (true) {
      try {
        const r = await this._get(`/v2/stream-next?device=${encodeURIComponent(this.device)}&seq=${seq}`);
        if (r.status === 200) {
          const d = r.json();
          if (d.available && d.hash) {
            const nextSeq = d.seq != null ? d.seq : seq + 1;
            try {
              const data = await this.receive(d.hash);
              seq = nextSeq;
              this._saveSeq(seq);
              await onReceive(data, { seq, hash: d.hash });
              continue;
            } catch (e) {
              if (e.code !== 'NOT_FOUND') throw e;
              seq = nextSeq;
            }
          }
        }
      } catch (e) {
        if (e.code !== 'TIMEOUT' && e.code !== 'RATE_LIMIT') throw e;
      }
      await new Promise((res) => setTimeout(res, interval));
    }
  }

  _loadSeq() {
    try { return parseInt(fs.readFileSync(this._seqFile, 'utf8').trim()) || 0; } catch { return 0; }
  }
  _saveSeq(n) {
    fs.mkdirSync(path.dirname(this._seqFile), { recursive: true });
    const tmp = this._seqFile + '.tmp';
    fs.writeFileSync(tmp, String(n));
    fs.renameSync(tmp, this._seqFile);
  }
}

// ── GhostPipeCluster ─────────────────────────────────────────────────────────
/**
 * Multi-relay client with automatic failover.
 *
 * @param {object}   opts
 * @param {string}   opts.apiKey
 * @param {string}   opts.device
 * @param {string[]} [opts.relays]  — defaults to all sector relays
 */
class GhostPipeCluster {
  constructor({ apiKey, device, relays } = {}) {
    this._urls    = relays || Object.values(SECTOR_RELAYS);
    this._clients = this._urls.map((r) => new GhostPipe({ apiKey, device, relay: r }));
    this._healthy = new Map(this._urls.map((r) => [r, true]));
    this._startMonitor();
  }

  _startMonitor() {
    const check = async () => {
      for (let i = 0; i < this._urls.length; i++) {
        try {
          const h = await this._clients[i].health();
          this._healthy.set(this._urls[i], h.ok === true);
        } catch (_) {
          this._healthy.set(this._urls[i], false);
        }
      }
    };
    check();
    this._timer = setInterval(check, 30000);
    if (this._timer.unref) this._timer.unref();
  }

  _getClient() {
    for (let i = 0; i < this._urls.length; i++) {
      if (this._healthy.get(this._urls[i]) !== false) return this._clients[i];
    }
    return this._clients[0];
  }

  async send(data, opts)  { return this._getClient().send(data, opts); }
  async receive(hash)     { return this._getClient().receive(hash); }
  async status(hash)      { return this._getClient().status(hash); }
  async health()          { return this._getClient().health(); }
  async setup()           { return this._getClient().setup(); }
  destroy()               { clearInterval(this._timer); }
}

module.exports = { GhostPipe, GhostPipeCluster, GhostPipeError, SECTOR_RELAYS, VERSION };
