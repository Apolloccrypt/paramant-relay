/**
 * PARAMANT Ghost Pipe Relay v2.2.1
 * NOTE: This is the canonical relay used by the Docker image (CMD ["node", "relay.js"]).
 * ghost-pipe-relay.js is the development/experimental variant — do not confuse the two.
 *
 * Post-Quantum Transport Protocol
 * "New HTTPS — decentralized, zero-plaintext, quantum-safe"
 * 
 * Crypto stack:
 *   ML-KEM-768  (NIST FIPS 203) — key encapsulation
 *   ML-DSA-65   (NIST FIPS 204) — digital signatures (NEW)
 *   ECDH P-256                  — classical hybrid
 *   AES-256-GCM                 — symmetric encryption
 *   HKDF-SHA256                 — key derivation
 * 
 * Audit:
 *   Merkle hash chain           — tamper-evident log (NEW)
 * 
 * Zero plaintext. Burn-on-read. EU/DE jurisdiction.
 */
'use strict';
const http   = require('http');
const crypto = require('crypto');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const url_   = require('url');

const VERSION    = '2.4.5';
// Per-restart nonce: stream-next hashes non-precomputable even if API key is known
const STREAM_NONCE = crypto.randomBytes(32);

// ── WS ticket store — avoids API key in WebSocket upgrade URL (finding #13) ──
// Client calls POST /v2/ws-ticket → gets 30s one-time ticket → connects with ?ticket=xxx
const wsTickets = new Map(); // ticket → { apiKey, expires }
setInterval(() => { const now = Date.now(); for (const [k, v] of wsTickets) if (now > v.expires) wsTickets.delete(k); }, 10_000);


// ── Drop / Argon2id / BIP39 — optioneel laden ─────────────────────────────────
let argon2Lib = null;
try { argon2Lib = require('argon2'); } catch(e) { /* npm install argon2 */ }
let bip39Lib  = null;
try { bip39Lib  = require('bip39');  } catch(e) { /* npm install bip39  */ }
const PORT       = parseInt(process.env.PORT       || '4000');
const USERS_FILE = process.env.USERS_FILE          || './users.json';
const TTL_MS     = parseInt(process.env.TTL_MS     || '300000');
const MAX_BLOB   = parseInt(process.env.MAX_BLOB   || '5242880');
const MAX_AUDIT  = parseInt(process.env.MAX_AUDIT  || '1000');
const _RAW_MODE  = process.env.RELAY_MODE          || 'full';
const RELAY_MODE = ['ghost_pipe', 'iot', 'full'].includes(_RAW_MODE) ? _RAW_MODE : (() => {
  console.error(`[paramant] Invalid RELAY_MODE="${_RAW_MODE}". Must be ghost_pipe|iot|full. Defaulting to ghost_pipe.`);
  return 'ghost_pipe';
})();
const SECTOR              = process.env.SECTOR              || 'relay';
const RELAY_SELF_URL      = process.env.RELAY_SELF_URL      || null; // e.g. https://relay.paramant.app — this relay's public URL
const RELAY_PRIMARY_URL   = process.env.RELAY_PRIMARY_URL   || null; // e.g. https://health.paramant.app — where to register
const RELAY_IDENTITY_FILE = process.env.RELAY_IDENTITY_FILE || '/data/relay-identity.json';
const TRIAL_KEYS_FILE     = process.env.TRIAL_KEYS_FILE     || '/data/trial-keys.jsonl';

// Probeer @noble/post-quantum te laden voor ML-DSA
let mlDsa = null;
try {
  const { ml_dsa65: mlDsaLib } = require('@noble/post-quantum/ml-dsa.js');
  mlDsa = mlDsaLib || null;
  if (mlDsa) log('info', 'ml_dsa_loaded', { alg: 'ML-DSA-65 NIST FIPS 204' });
} catch(e) { log('warn', 'ml_dsa_not_available', { hint: 'npm install @noble/post-quantum' }); }

const ALLOWED = {
  ghost_pipe: ['/health','/v2/pubkey','/v2/inbound','/v2/anon-inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/drop','/v2/session',
               '/v2/ws-ticket','/v2/fingerprint','/v2/relays','/v2/request-trial','/v2/sign-dpa',
               '/v2/sth','/v2/verify-receipt','/ct','/ct/feed','/v2/auth','/v2/user'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/anon-inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/drop','/v2/session',
               '/v2/relays','/v2/request-trial','/v2/sign-dpa','/v2/sth','/v2/verify-receipt','/ct','/ct/feed','/v2/auth','/v2/user'],
  full:       null,
};

function modeAllows(p) {
  const a = ALLOWED[RELAY_MODE];
  return !a || a.some(x => p === x || p.startsWith(x + '/'));
}

// HTML-escape user-supplied strings before embedding in email templates.
function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── NATS.io JetStream — push transport (vervangt polling) ────────────────────
let natsClient = null;
let natsJs = null;
async function initNats() {
  if (!process.env.NATS_URL) return; // opt-in only — no automatic localhost fallback
  try {
    const { connect } = require('nats');
    const servers = process.env.NATS_URL;
    try {
      const _u = new URL(servers.includes('://') ? servers : 'nats://' + servers);
      if (!servers.startsWith('tls://') && _u.hostname !== 'localhost' && _u.hostname !== '127.0.0.1') {
        log('warn', 'nats_no_tls', { hint: 'NATS_URL does not use tls:// — plaintext NATS on non-localhost exposes transfer metadata' });
      }
    } catch {}
    const opts = { servers };
    if (process.env.NATS_USER)  opts.user  = process.env.NATS_USER;
    if (process.env.NATS_PASS)  opts.pass  = process.env.NATS_PASS;
    if (process.env.NATS_TOKEN) opts.token = process.env.NATS_TOKEN;
    natsClient = await connect(opts);
    natsJs = natsClient.jetstream();
    try {
      const jsm = await natsClient.jetstreamManager();
      await jsm.streams.add({ name: 'PARAMANT', subjects: ['paramant.>'], max_age: 300e9 });
    } catch(e) {}
    log('info', 'nats_connected', { servers });
  } catch(e) {
    log('warn', 'nats_not_available', { hint: 'NATS connection failed — check NATS_URL, credentials, and TLS config', err: e.message });
  }
}
async function natsPush(apiKey, deviceId, hash, size) {
  if (!natsJs) return;
  try {
    const { StringCodec } = require('nats');
    const sc = StringCodec();
    await natsJs.publish(
      // Hash key+device to avoid partial API key exposure in NATS subjects (finding)
      `paramant.${crypto.createHash('sha256').update(apiKey).digest('hex').slice(0,16)}.${crypto.createHash('sha256').update(deviceId).digest('hex').slice(0,16)}`,
      sc.encode(JSON.stringify({ hash, size, ts: new Date().toISOString() }))
    );
  } catch(e) {}
}
initNats();

// Fix B: per-device delivery queue — stream-next returns real blob hashes
// deviceQueues[apiKey:deviceId] = [sha256_hash, ...]
const deviceQueues = new Map(); // `${apiKey}:${deviceId}` → string[]

function deviceQueuePush(apiKey, deviceId, hash) {
  if (!deviceId) return;
  const k = `${apiKey}:${deviceId}`;
  if (!deviceQueues.has(k)) deviceQueues.set(k, []);
  const q = deviceQueues.get(k);
  if (!q.includes(hash)) q.push(hash); // dedup
}

// ── DID — Decentralized Identity (W3C) ───────────────────────────────────────
const didRegistry = new Map();

function generateDid(deviceId, pubKeyHex) {
  const hash = crypto.createHash('sha3-256').update(deviceId + pubKeyHex).digest('hex').slice(0,32);
  return `did:paramant:${hash}`;
}

function createDidDocument(did, deviceId, ecdhPubHex, dsaPubHex) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    created: new Date().toISOString(),
    assertionMethod: [did + '#keys-1'],
    capabilityInvocation: [did + '#keys-1'],
    verificationMethod: [{
      id: `${did}#keys-1`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyHex: ecdhPubHex
    }],
    service: [{
      id: `${did}#ghost-pipe`,
      type: 'GhostPipeRelay',
      serviceEndpoint: `https://${SECTOR}.paramant.app`,
      device: deviceId,
      protocol: 'ghost-pipe-v2',
      encryption: 'ML-KEM-768+ECDH+AES-256-GCM'
    }]
  };
}

// ── Certificate Transparency Log ─────────────────────────────────────────────
const ctLog = [];
const CT_MAX = 10000;
const CT_FILE     = process.env.CT_FILE     || null; // opt-in only — auto-derive disabled to preserve RAM-only default
const CT_MAX_SIZE = parseInt(process.env.CT_MAX_SIZE || String(100 * 1024 * 1024)); // 100 MB default

// Fix 8: async CT write stream with queued writes and log rotation
let _ctStream    = null;
let _ctWriteQueue = [];
let _ctDraining  = false;

function _ctOpenStream() {
  if (!CT_FILE) return;
  _ctStream = fs.createWriteStream(CT_FILE, { flags: 'a' });
  _ctStream.on('error', e => log('warn', 'ct_stream_error', { err: e.message }));
}

async function _ctRotate() {
  if (!CT_FILE) return;
  try {
    const stat = await fs.promises.stat(CT_FILE).catch(() => null);
    if (!stat || stat.size < CT_MAX_SIZE) return;
    if (_ctStream) { await new Promise(r => _ctStream.end(r)); _ctStream = null; }
    await fs.promises.rename(CT_FILE, CT_FILE + '.1').catch(() => {});
    _ctOpenStream();
    log('info', 'ct_log_rotated', { file: CT_FILE });
  } catch(e) { log('warn', 'ct_rotate_error', { err: e.message }); }
}

async function _ctDrain() {
  if (_ctDraining || !_ctStream) return;
  _ctDraining = true;
  while (_ctWriteQueue.length > 0) {
    const line = _ctWriteQueue.shift();
    await new Promise((resolve, reject) => {
      _ctStream.write(line, err => err ? reject(err) : resolve());
    }).catch(e => log('warn', 'ct_write_error', { err: e.message }));
  }
  _ctDraining = false;
  // Check rotation after draining
  _ctRotate().catch(() => {});
}

function ctWrite(entry) {
  if (!CT_FILE || !_ctStream) return;
  _ctWriteQueue.push(JSON.stringify(entry) + '\n');
  setImmediate(_ctDrain);
}

// Flush CT queue on graceful shutdown
function _flushCtOnExit() {
  if (!_ctStream || _ctWriteQueue.length === 0) return;
  for (const line of _ctWriteQueue) { try { _ctStream.write(line); } catch {} }
  _ctWriteQueue = [];
}

// Load persisted CT log on startup (sync read only at startup, not on hot path)
if (CT_FILE) {
  try {
    const lines = fs.readFileSync(CT_FILE, 'utf8').split('\n').filter(l => l.trim());
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (Array.isArray(parsed)) {
          for (const entry of parsed) {
            if (entry && typeof entry === 'object' && !Array.isArray(entry)) ctLog.push(entry);
          }
        } else {
          ctLog.push(parsed);
        }
      } catch {}
    }
    if (ctLog.length) log('info', 'ct_log_loaded', { entries: ctLog.length, file: CT_FILE });
  } catch (e) {
    if (e.code !== 'ENOENT') log('warn', 'ct_log_load_failed', { err: e.message });
  }
  _ctOpenStream();
}

// ── Signed Tree Head (STH) — RFC 6962 style, ML-DSA-65 signed ───────────────
const STH_MAX  = 1000;
const STH_FILE = process.env.STH_FILE || '/data/sth-log.jsonl';
const sthLog   = []; // rolling array of last STH_MAX signed tree heads

let _sthStream    = null;
let _sthWriteQueue = [];
let _sthDraining  = false;

function _sthOpenStream() {
  try {
    fs.mkdirSync(path.dirname(STH_FILE), { recursive: true });
    _sthStream = fs.createWriteStream(STH_FILE, { flags: 'a' });
    _sthStream.on('error', e => log('warn', 'sth_stream_error', { err: e.message }));
  } catch (e) { log('warn', 'sth_stream_open_failed', { err: e.message }); }
}

async function _sthDrain() {
  if (_sthDraining || !_sthStream) return;
  _sthDraining = true;
  while (_sthWriteQueue.length > 0) {
    const line = _sthWriteQueue.shift();
    await new Promise((resolve, reject) => {
      _sthStream.write(line, err => err ? reject(err) : resolve());
    }).catch(e => log('warn', 'sth_write_error', { err: e.message }));
  }
  _sthDraining = false;
}

function sthWrite(entry) {
  _sthWriteQueue.push(JSON.stringify(entry) + '\n');
  setImmediate(_sthDrain);
}

function _flushSthOnExit() {
  if (!_sthStream || _sthWriteQueue.length === 0) return;
  for (const line of _sthWriteQueue) { try { _sthStream.write(line); } catch {} }
  _sthWriteQueue = [];
}

// Load persisted STH log on startup
try {
  const lines = fs.readFileSync(STH_FILE, 'utf8').split('\n').filter(l => l.trim());
  for (const line of lines) {
    try { sthLog.push(JSON.parse(line)); } catch {}
  }
  if (sthLog.length > STH_MAX) sthLog.splice(0, sthLog.length - STH_MAX);
  if (sthLog.length) log('info', 'sth_log_loaded', { entries: sthLog.length });
} catch (e) {
  if (e.code !== 'ENOENT') log('warn', 'sth_log_load_failed', { err: e.message });
}
_sthOpenStream();

// ── Relay identity — ML-DSA-65 keypair for relay authentication ───────────────
let relayIdentity = null; // { sk: Buffer, pk: Buffer, pk_hash: string }

function loadOrCreateRelayIdentity() {
  if (!mlDsa) {
    log('warn', 'relay_identity_skipped', { reason: 'ML-DSA-65 not available — relay registry disabled' });
    return;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(RELAY_IDENTITY_FILE, 'utf8'));
    const sk = Buffer.from(raw.sk, 'base64');
    const pk = Buffer.from(raw.pk, 'base64');
    const pk_hash = crypto.createHash('sha3-256').update(pk).digest('hex');
    relayIdentity = { sk, pk, pk_hash };
    log('info', 'relay_identity_loaded', { pk_hash: pk_hash.slice(0, 16) + '…', file: RELAY_IDENTITY_FILE });
  } catch (e) {
    if (e.code !== 'ENOENT') log('warn', 'relay_identity_load_failed', { err: e.message, file: RELAY_IDENTITY_FILE });
    // Generate new keypair
    try {
      const kp = mlDsa.keygen();
      const sk = Buffer.from(kp.secretKey);
      const pk = Buffer.from(kp.publicKey);
      const pk_hash = crypto.createHash('sha3-256').update(pk).digest('hex');
      relayIdentity = { sk, pk, pk_hash };
      try {
        fs.mkdirSync(path.dirname(RELAY_IDENTITY_FILE), { recursive: true });
        fs.writeFileSync(RELAY_IDENTITY_FILE,
          JSON.stringify({ sk: sk.toString('base64'), pk: pk.toString('base64'), created_at: new Date().toISOString() }),
          { mode: 0o600 });
        log('info', 'relay_identity_created', { pk_hash: pk_hash.slice(0, 16) + '…', file: RELAY_IDENTITY_FILE });
      } catch (we) {
        log('warn', 'relay_identity_not_persisted', { err: we.message, hint: 'Key regenerated on restart — set RELAY_IDENTITY_FILE to a writable path' });
      }
    } catch (ge) {
      log('error', 'relay_identity_keygen_failed', { err: ge.message });
    }
  }
}

// ── Relay registry — in-memory, populated from CT log on startup ──────────────
// key: pk_hash (hex) → { url, sector, version, edition, pk_hash, verified_since, last_seen, ct_index, last_ct_index }
const relayRegistry = new Map();
const MAX_RELAY_REGISTRY = parseInt(process.env.MAX_RELAY_REGISTRY || '10000');

function relayRegistryFromCTLog() {
  for (const entry of ctLog) {
    if (entry.type !== 'relay_reg') continue;
    const key = entry.relay_pk_hash;
    if (!key) continue;
    const existing = relayRegistry.get(key);
    if (!existing) {
      relayRegistry.set(key, {
        url: entry.relay_url, sector: entry.relay_sector,
        version: entry.relay_version, edition: entry.relay_edition || 'community',
        pk_hash: key, verified_since: entry.ts, last_seen: entry.ts,
        ct_index: entry.index, last_ct_index: entry.index
      });
    } else {
      existing.last_seen    = entry.ts;
      existing.last_ct_index = entry.index;
      existing.version      = entry.relay_version;
      existing.edition      = entry.relay_edition || existing.edition;
    }
  }
  if (relayRegistry.size > 0) log('info', 'relay_registry_loaded', { relays: relayRegistry.size });
}

// RFC 6962-style Merkle tree — SHA3-256 with domain separation bytes:
//   leaf node:  SHA3-256(0x00 || leaf_data_bytes)   — prevents second-preimage attacks
//   inner node: SHA3-256(0x01 || left_bytes || right_bytes)
// Odd leaf at end is promoted unchanged (no self-duplication).

function ctLeafHash(deviceIdHash, pubKeyHex, ts) {
  const data = Buffer.concat([
    Buffer.from(deviceIdHash, 'hex'),           // 32 bytes — device identity
    Buffer.from(pubKeyHex.slice(0, 64), 'hex'), // 32 bytes — first half of pubkey
    Buffer.from(ts, 'utf8')                     // ISO timestamp
  ]);
  return crypto.createHash('sha3-256').update(Buffer.from([0x00])).update(data).digest('hex');
}

function ctNodeHash(left, right) {
  return crypto.createHash('sha3-256')
    .update(Buffer.from([0x01]))
    .update(Buffer.from(left, 'hex'))
    .update(Buffer.from(right, 'hex'))
    .digest('hex');
}

function ctTreeHash(entries) {
  if (entries.length === 0) return '0'.repeat(64);
  let hashes = entries.map(e => e.leaf_hash);
  while (hashes.length > 1) {
    const next = [];
    for (let i = 0; i < hashes.length; i += 2) {
      next.push(i + 1 < hashes.length ? ctNodeHash(hashes[i], hashes[i+1]) : hashes[i]);
    }
    hashes = next;
  }
  return hashes[0];
}

// Returns the Merkle audit path for `idx` in the given entries array.
// Each element is { hash, position: 'left'|'right' } so verifiers know how to combine.
// Verification: start with leaf_hash, for each step combine with sibling per position.
function ctInclusionProof(entries, idx) {
  if (entries.length <= 1) return [];
  let hashes = entries.map(e => e.leaf_hash);
  const path = [];
  let i = idx;
  while (hashes.length > 1) {
    const sibling = i % 2 === 0 ? i + 1 : i - 1;
    if (sibling < hashes.length) {
      path.push({ hash: hashes[sibling], position: i % 2 === 0 ? 'right' : 'left' });
    }
    const next = [];
    for (let j = 0; j < hashes.length; j += 2) {
      next.push(j + 1 < hashes.length ? ctNodeHash(hashes[j], hashes[j+1]) : hashes[j]);
    }
    hashes = next;
    i = Math.floor(i / 2);
  }
  return path;
}

// Leaf hash for blob/transfer entries — domain separator 0x02 (0x00=pubkey, 0x01=inner node)
// Commits to transfer hash + sector without exposing payload content.
function blobLeafHash(blobHash, sector, ts) {
  const data = Buffer.concat([
    Buffer.from(blobHash, 'hex'),                                        // 32 bytes — transfer hash
    crypto.createHash('sha3-256').update(sector || 'relay').digest(),    // 32 bytes — sector identity
    Buffer.from(ts, 'utf8')                                              // ISO timestamp
  ]);
  return crypto.createHash('sha3-256').update(Buffer.from([0x02])).update(data).digest('hex');
}

// Recursive canonical JSON (sorted keys, no whitespace) — used for signing receipts + STH.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function ctAppend(deviceId, pubKeyHex, apiKey) {
  const ts = new Date().toISOString();
  const deviceIdHash = crypto.createHash('sha3-256').update(deviceId + apiKey.slice(0,8)).digest('hex');
  const leaf_hash = ctLeafHash(deviceIdHash, pubKeyHex, ts);
  const index = ctLog.length;
  const allEntries = [...ctLog, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, index); // real audit path, not a slice
  const entry = { index, leaf_hash, tree_hash, device_hash: deviceIdHash, ts, proof };
  ctLog.push(entry);
  if (ctLog.length > CT_MAX) ctLog.shift();
  // Fix 8: async write via stream queue instead of appendFileSync
  ctWrite(entry);
  produceSth(entry.index + 1, entry.tree_hash);
  return entry;
}

// Appends a relay registration entry to the CT log.
// Leaf hash: SHA3-256(0x00 || SHA3-256(url|sector) || pk_hash_bytes || ts)
// — commits to relay identity (URL+sector) and public key, auditable without revealing keys.
function ctAppendRelayReg(relayUrl, sector, version, edition, pkHash) {
  const ts = new Date().toISOString();
  const urlSectorHash = crypto.createHash('sha3-256').update(relayUrl + '|' + sector).digest('hex');
  // ctLeafHash(deviceIdHash, pubKeyHex, ts) — reuse with urlSectorHash as identity, pkHash as key
  const leaf_hash = ctLeafHash(urlSectorHash, pkHash, ts);
  const index = ctLog.length;
  const allEntries = [...ctLog, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, index);
  const entry = {
    index, type: 'relay_reg', leaf_hash, tree_hash,
    device_hash: pkHash,          // reused field — relay public key hash
    relay_url: relayUrl, relay_sector: sector,
    relay_version: version, relay_edition: edition,
    relay_pk_hash: pkHash,
    ts, proof
  };
  ctLog.push(entry);
  if (ctLog.length > CT_MAX) ctLog.shift();
  // Fix 8: async write via stream queue
  ctWrite(entry);
  produceSth(entry.index + 1, entry.tree_hash);
  return entry;
}

// Appends a blob transfer entry to the CT log and returns the entry with inclusion proof.
// Leaf hash: SHA3-256(0x02 || SHA3-256(sector) || ts) — commits to transfer identity.
// Called at inbound upload; the entry is stored in blobStore so the outbound handler
// can produce a signed delivery receipt without re-querying the CT log.
function ctAppendTransfer(blobHash, sector) {
  const ts = new Date().toISOString();
  const leaf_hash = blobLeafHash(blobHash, sector, ts);
  const index = ctLog.length;
  const allEntries = [...ctLog, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, index);
  const entry = {
    index, type: 'transfer', leaf_hash, tree_hash,
    blob_hash: blobHash, sector, ts, proof
  };
  ctLog.push(entry);
  if (ctLog.length > CT_MAX) ctLog.shift();
  ctWrite(entry);
  const sth = produceSth(entry.index + 1, entry.tree_hash);
  return { ...entry, sth };
}

// ── Signed Tree Head — produce, sign, and persist an STH for every root change ─
// Canonical JSON: sorted keys, no whitespace, UTF-8 (matches RFC 6962 § 3.5 spirit).
// Signed with the relay's ML-DSA-65 identity key (NIST FIPS 204).
function produceSth(tree_size, sha3_root) {
  if (!mlDsa || !relayIdentity) return null;
  const relay_id = RELAY_SELF_URL || (SECTOR + '.paramant.app');
  const payload  = { relay_id, sha3_root, timestamp: Date.now(), tree_size, version: 1 };
  // Canonical JSON: keys sorted alphabetically
  const sortedKeys = Object.keys(payload).sort();
  const canonical  = JSON.stringify(Object.fromEntries(sortedKeys.map(k => [k, payload[k]])));
  let signature;
  try {
    signature = Buffer.from(mlDsa.sign(Buffer.from(canonical, 'utf8'), relayIdentity.sk)).toString('base64');
  } catch (e) {
    log('warn', 'sth_sign_failed', { err: e.message });
    return null;
  }
  const sth = { ...payload, signature };
  sthLog.push(sth);
  if (sthLog.length > STH_MAX) sthLog.shift();
  sthWrite(sth);
  // Broadcast to peers asynchronously — non-blocking, best-effort
  setImmediate(() => broadcastSTH(sth).catch(() => {}));
  return sth;
}

// ── Peer STH storage — mirrors signed tree heads from other relays ─────────────
const PEER_STH_DIR = process.env.PEER_STH_DIR || '/data/peer-sths';
const PEER_STH_MAX = parseInt(process.env.PEER_STH_MAX || '500'); // per peer
// peerSths: relay pk_hash (hex) → { sths: STH[], pk_b64: string }
const peerSths = new Map();
const _peerSthStreams = new Map(); // pk_hash → fs.WriteStream

function _peerSthStreamFor(pkHash) {
  if (_peerSthStreams.has(pkHash)) return _peerSthStreams.get(pkHash);
  try {
    fs.mkdirSync(PEER_STH_DIR, { recursive: true });
    const safe = pkHash.replace(/[^a-f0-9]/g, '').slice(0, 64);
    const stream = fs.createWriteStream(path.join(PEER_STH_DIR, safe + '.jsonl'), { flags: 'a' });
    stream.on('error', e => log('warn', 'peer_sth_stream_error', { id: pkHash.slice(0, 16), err: e.message }));
    _peerSthStreams.set(pkHash, stream);
    return stream;
  } catch (e) {
    log('warn', 'peer_sth_stream_open_failed', { err: e.message });
    return null;
  }
}

function _peerSthWrite(pkHash, sth) {
  const stream = _peerSthStreamFor(pkHash);
  if (!stream) return;
  try { stream.write(JSON.stringify(sth) + '\n'); } catch {}
}

function loadPeerSths() {
  try {
    fs.mkdirSync(PEER_STH_DIR, { recursive: true });
    const files = fs.readdirSync(PEER_STH_DIR).filter(f => f.endsWith('.jsonl'));
    for (const file of files) {
      const id = file.replace(/\.jsonl$/, '');
      try {
        const lines = fs.readFileSync(path.join(PEER_STH_DIR, file), 'utf8').split('\n').filter(l => l.trim());
        const sths = [];
        for (const line of lines) { try { sths.push(JSON.parse(line)); } catch {} }
        const recent = sths.slice(-PEER_STH_MAX);
        const pk_b64 = recent.length > 0 ? (recent[recent.length - 1].public_key || '') : '';
        peerSths.set(id, { sths: recent, pk_b64 });
      } catch {}
    }
    if (peerSths.size > 0) log('info', 'peer_sths_loaded', { peers: peerSths.size });
  } catch (e) {
    if (e.code !== 'ENOENT') log('warn', 'peer_sths_load_failed', { err: e.message });
  }
}

function _flushPeerSthsOnExit() {
  for (const stream of _peerSthStreams.values()) { try { stream.end(); } catch {} }
}

// ── Gossip — broadcast our latest STH to all registered peers ─────────────────
async function broadcastSTH(sth) {
  if (!sth || !relayIdentity) return;
  const peers = [...relayRegistry.values()].filter(r => r.url && r.url !== RELAY_SELF_URL);
  if (peers.length === 0) return;
  const body = JSON.stringify({
    ...sth,
    public_key: relayIdentity.pk.toString('base64'),
    relay_pk_hash: relayIdentity.pk_hash,
  });
  for (const peer of peers) {
    if (!isSsrfSafeUrl(peer.url)) { log('warn', 'gossip_ssrf_blocked', { url: (peer.url||'').slice(0,60) }); continue; }
    try {
      const target = new URL('/v2/sth/ingest', peer.url);
      const mod = target.protocol === 'https:' ? https : http;
      await new Promise(resolve => {
        const r = mod.request({
          hostname: target.hostname,
          port: target.port || (target.protocol === 'https:' ? 443 : 80),
          path: target.pathname,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, res2 => { res2.resume(); resolve(); });
        r.setTimeout(3000, () => { r.destroy(); resolve(); });
        r.on('error', () => resolve()); // non-blocking, best-effort
        r.write(body);
        r.end();
      });
    } catch {}
  }
}

// ── RFC 6962 consistency proof ─────────────────────────────────────────────────
// Proves the tree at toSize is an append-only extension of the tree at fromSize.
function _merkleRootOf(leafHashes) {
  if (leafHashes.length === 0) return '0'.repeat(64);
  let h = [...leafHashes];
  while (h.length > 1) {
    const next = [];
    for (let i = 0; i < h.length; i += 2)
      next.push(i + 1 < h.length ? ctNodeHash(h[i], h[i + 1]) : h[i]);
    h = next;
  }
  return h[0];
}

function _subproof(m, nodes, b) {
  const n = nodes.length;
  if (m === n) return b ? [] : [_merkleRootOf(nodes)];
  let k = 1;
  while (k * 2 < n) k *= 2; // k = largest power of 2 strictly less than n
  if (m <= k) return _subproof(m, nodes.slice(0, k), b).concat([_merkleRootOf(nodes.slice(k))]);
  return [_merkleRootOf(nodes.slice(0, k))].concat(_subproof(m - k, nodes.slice(k), false));
}

// 0 ≤ fromSize ≤ toSize ≤ ctLog.length
function ctConsistencyProof(fromSize, toSize) {
  if (fromSize < 0 || toSize < fromSize || toSize > ctLog.length) return null;
  if (fromSize === 0 || fromSize === toSize) return [];
  const leaves = ctLog.slice(0, toSize).map(e => e.leaf_hash);
  return _subproof(fromSize, leaves, fromSize === leaves.length);
}

// ── Fingerprint — out-of-band key verification ────────────────────────────────
// SHA-256(kyber_pub_bytes || ecdh_pub_bytes) → first 10 bytes → 5×4 hex groups
// Matches browser genFingerprint() in parashare.html and ontvang.html exactly.
// Both parties compute independently; mismatch = relay MITM detected.
function computeFingerprint(kyberPubHex, ecdhPubHex) {
  const buf = Buffer.concat([
    Buffer.from(kyberPubHex || '', 'hex'),
    Buffer.from(ecdhPubHex  || '', 'hex'),
  ]);
  const h = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 20).toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

// ── Hardware Attestation — TPM / Secure Enclave ───────────────────────────────
const attestations = new Map();

function verifyAttestation(pubKeyHex, deviceId, attestationObj) {
  if (!attestationObj) return { valid: false, reason: 'no_attestation', attested: false };
  const method = attestationObj.method || 'unknown';
  let result;
  if (method === 'tpm2') {
    const fresh = Date.now() - (attestationObj.ts || 0) < 300000;
    result = { valid: fresh, method: 'tpm2', pcr: attestationObj.pcr_values || [] };
  } else if (method === 'apple') {
    result = { valid: !!attestationObj.auth_data, method: 'apple_secure_enclave' };
  } else if (method === 'software') {
    result = { valid: true, method: 'software', warning: 'not_hardware_backed' };
  } else {
    result = { valid: false, reason: 'unknown_method' };
  }
  const deviceHash = crypto.createHash('sha3-256').update(deviceId).digest('hex');
  attestations.set(deviceHash, { ...result, attested: result.valid, verified_ts: new Date().toISOString() });
  log(result.valid ? 'info' : 'warn', 'attestation_result', { device: deviceId.slice(0,8), method, valid: result.valid });
  return result;
}

// ── Prometheus metrics ────────────────────────────────────────────────────────
const metricsCounters = { requests_total:0, requests_authed:0, blobs_stored:0, blobs_burned:0, bytes_in_total:0, bytes_out_total:0, errors_total:0, ack_total:0, did_registrations:0 };
function incMetric(k,v=1){ if(metricsCounters.hasOwnProperty(k)) metricsCounters[k]+=v; }
function renderPrometheus() {
  const L=[];
  for(const [k,v] of Object.entries(metricsCounters)){
    L.push(`# TYPE paramant_${k} counter`);
    L.push(`paramant_${k}{sector="${SECTOR}",v="${VERSION}"} ${v}`);
  }
  for(const [k,v] of [['blobs_in_flight',blobStore.size],['pubkeys',pubkeys.size],['edition',EDITION==='licensed'?1:0],['did_registry',didRegistry.size],['ct_log',ctLog.length],['uptime_s',Math.floor(process.uptime())],['heap_bytes',process.memoryUsage().heapUsed]]){
    L.push(`# TYPE paramant_${k} gauge`);
    L.push(`paramant_${k}{sector="${SECTOR}"} ${v}`);
  }
  const rs = ramStatus();
  for(const [k,v] of [['ram_slots_available',rs.available_slots],['ram_blobs_max',rs.blobs_max],['ram_blob_mb',rs.blob_ram_mb],['ram_rss_mb',rs.rss_mb],['ram_heap_mb',rs.heap_mb]]){
    L.push(`# TYPE paramant_${k} gauge`);
    L.push(`paramant_${k}{sector="${SECTOR}"} ${v}`);
  }
  return L.join('\n')+'\n';
}

// ── TOTP verificatie (RFC 6238) ───────────────────────────────────────────────
const TOTP_SECRET = process.env.TOTP_SECRET || '';
const TOTP_WINDOW = 1;
// Fix 14: validate TOTP_SECRET at startup so misconfiguration is caught early
if (TOTP_SECRET) {
  try { base32Decode(TOTP_SECRET); }
  catch(e) { log('error', 'totp_secret_invalid', { err: e.message, hint: 'TOTP_SECRET must be valid Base32 (A-Z, 2-7)' }); process.exit(1); }
}

function base32Decode(s) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = [];
  s = s.toUpperCase().replace(/=+$/, '');
  for (const c of s) {
    const idx = alpha.indexOf(c);
    // Fix 14: throw on invalid Base32 character instead of silently using -1
    if (idx === -1) throw new Error(`Invalid Base32 character: '${c}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xFF); bits -= 8; }
  }
  return Buffer.from(output);
}

function totpCode(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha256', key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  zeroBuffer(key); zeroBuffer(mac);
  return code.toString().padStart(6, '0');
}

// Fix 5: used-code tracking — window = 30s each side → 3 windows × 30s = 90s expiry
const _usedTotpCodes = new Map(); // code+counter → expiry ms
setInterval(() => { const now = Date.now(); for (const [k, exp] of _usedTotpCodes) if (now > exp) _usedTotpCodes.delete(k); }, 30_000);

function verifyTotp(token) {
  if (!TOTP_SECRET) return false;
  const tokenBuf = Buffer.from(String(token || ''), 'utf8');
  if (tokenBuf.length !== 6) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  // Fix 5a: evaluate ALL windows — never short-circuit (constant-time scan)
  let matched = false;
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const c = counter + i;
    const expected = totpCode(TOTP_SECRET, c);
    const expectedBuf = Buffer.from(expected, 'utf8');
    // Fix 5b: timingSafeEqual (lengths guaranteed equal — both are 6-char strings)
    const eq = tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf);
    if (eq) {
      // Fix 5c: reject reused codes — key = token + counter slot
      const useKey = `${token}:${c}`;
      if (_usedTotpCodes.has(useKey)) { matched = false; continue; }
      _usedTotpCodes.set(useKey, (c + 2) * 30 * 1000); // expire after 2 windows past use
      matched = true;
    }
  }
  return matched;
}

// ── Download tokens — one-time public download links
const downloadTokens = new Map(); // token -> { hash, key, expires_ms, used }

// ── DPA rate limiting — prevents spam/storage churn on the public sign-dpa endpoint
const dpaIpRequests    = new Map(); // ip    → [timestamps]
const dpaEmailRequests = new Map(); // email → timestamp
setInterval(() => {
  const cutoff = Date.now() - 86_400_000;
  for (const [k, times] of dpaIpRequests) { const kept = times.filter(t => t > cutoff); if (kept.length) dpaIpRequests.set(k, kept); else dpaIpRequests.delete(k); }
  for (const [k, t]     of dpaEmailRequests) { if (t < cutoff) dpaEmailRequests.delete(k); }
}, 3_600_000);

// Known link-preview bots — serve safe HTML placeholder, never trigger burn
const PRELOAD_BOTS = /WhatsApp|Telegram(?:Bot)?|Slackbot|Discordbot|facebookexternalhit|Twitterbot|LinkedInBot|Googlebot|bingbot|YandexBot|DuckDuckBot|ia_archiver|python-requests|python-urllib|Go-http-client/i;

function _dlConfirmPage(token, encMeta, sizeStr, ttlStr) {
  // encMeta is ciphertext only — relay never sees plaintext filename (finding #4)
  // If present, embed as data attribute for SDK to decrypt client-side
  const encMetaAttr = encMeta ? ` data-enc-meta="${encMeta.replace(/"/g,'&quot;')}"` : '';
  const name = 'Encrypted file';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PARAMANT — Secure File Ready</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d0d;color:#e0e0e0;font-family:'SF Mono',monospace;display:flex;
  align-items:center;justify-content:center;min-height:100vh;padding:24px}
.card{background:#161616;border:1px solid #2a2a2a;border-radius:12px;
  max-width:440px;width:100%;padding:36px 32px}
.logo{color:#5eead4;font-size:.75rem;letter-spacing:.15em;text-transform:uppercase;
  margin-bottom:28px}
h1{font-size:1.1rem;font-weight:600;margin-bottom:8px}
.sub{color:#888;font-size:.82rem;margin-bottom:28px}
.meta{background:#1e1e1e;border-radius:8px;padding:16px;margin-bottom:24px;
  font-size:.82rem;display:grid;gap:8px}
.meta-row{display:flex;justify-content:space-between;align-items:center}
.meta-label{color:#666}
.meta-val{color:#e0e0e0;text-align:right;max-width:60%;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.warn{color:#f59e0b;font-size:.78rem;margin-bottom:24px;
  padding:10px 14px;background:#1c1700;border-radius:6px;border-left:3px solid #f59e0b}
.btn{display:block;width:100%;padding:14px;background:#5eead4;color:#0d0d0d;
  border:none;border-radius:8px;font-family:inherit;font-size:.9rem;font-weight:700;
  cursor:pointer;text-align:center;text-decoration:none;letter-spacing:.03em;
  transition:opacity .15s}
.btn:hover{opacity:.88}
.footer{margin-top:20px;font-size:.72rem;color:#444;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo">PARAMANT · Post-Quantum Secure Transfer</div>
  <h1>Secure file ready for download</h1>
  <p class="sub">End-to-end encrypted · Burns after reading</p>
  <div class="meta">
    <div class="meta-row"><span class="meta-label">File</span><span class="meta-val" id="fn"${encMetaAttr}>${name}</span></div>
    <div class="meta-row"><span class="meta-label">Size</span><span class="meta-val">${sizeStr}</span></div>
    <div class="meta-row"><span class="meta-label">Expires in</span><span class="meta-val">${ttlStr}</span></div>
  </div>
  <p class="warn">⚠ This file is deleted from the server immediately after download. You get one chance.</p>
  <a class="btn" href="/v2/dl/${token}/get">Download &amp; Burn</a>
  <p class="footer">ML-KEM-768 encrypted · Zero plaintext stored · PARAMANT</p>
</div>
</body></html>`;
}

function _dlBurnedPage(msg) {
  const safe = msg.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PARAMANT — File Burned</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d0d;color:#e0e0e0;font-family:'SF Mono',monospace;display:flex;
  align-items:center;justify-content:center;min-height:100vh;padding:24px}
.card{background:#161616;border:1px solid #2a2a2a;border-radius:12px;
  max-width:440px;width:100%;padding:36px 32px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1rem;font-weight:600;margin-bottom:8px;color:#f87171}
p{color:#666;font-size:.82rem}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔥</div>
  <h1>${safe}</h1>
  <p>Burn-on-read: the file no longer exists on this server.</p>
</div>
</body></html>`;
}

// ── CT Log public web UI ──────────────────────────────────────────────────────
const CT_PAGE = (() => {
  const css = [
    '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}',
    ':root{--bg:#0b1d12;--bg2:#0f2318;--border:#1a3a22;--accent:#3dbe7a;--dim:#4a7a5a;--text:#c0ddc8;--err:#ef4444;--ok:#3dbe7a}',
    'body{background:var(--bg);color:var(--text);font-family:\'Cascadia Code\',\'Fira Mono\',Consolas,monospace;font-size:13px;line-height:1.5;min-height:100vh}',
    '.hdr{border-bottom:1px solid var(--border);padding:10px 16px;display:flex;align-items:center;gap:12px;position:sticky;top:0;background:var(--bg);z-index:10}',
    '.logo{color:var(--accent);font-weight:700;font-size:14px;letter-spacing:.05em}',
    '.badge{color:var(--dim);font-size:11px}',
    '.main{max-width:980px;margin:0 auto;padding:16px}',
    '.sec{margin-bottom:18px}',
    '.sec-title{color:var(--accent);font-size:10px;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)}',
    '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:3px;overflow:hidden}',
    '.cell{background:var(--bg2);padding:9px 12px}',
    '.cell-label{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px}',
    '.cell-value{color:var(--text);word-break:break-all;font-size:12px}',
    '.cell-value.hi{color:var(--accent)}',
    '.root-box{border:1px solid var(--border);border-radius:3px;background:var(--bg2);padding:10px 12px}',
    '.root-label{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}',
    '.root-hash{color:var(--accent);word-break:break-all;font-size:11px;font-family:monospace}',
    '.status-bar{display:flex;align-items:center;gap:12px;padding:8px 0;font-size:11px;flex-wrap:wrap}',
    '.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:4px;flex-shrink:0}',
    '.dot.ok{background:var(--ok);box-shadow:0 0 5px var(--ok)}',
    '.dot.err{background:var(--err)}',
    '.dot.idle{background:var(--dim)}',
    '.btn{background:transparent;border:1px solid var(--accent);color:var(--accent);padding:5px 12px;font-family:inherit;font-size:10px;cursor:pointer;border-radius:2px;letter-spacing:.08em;text-transform:uppercase;transition:background .15s,color .15s}',
    '.btn:hover:not(:disabled){background:var(--accent);color:var(--bg)}',
    '.btn:disabled{opacity:.4;cursor:default}',
    '.refresh-info{color:var(--dim);font-size:10px;margin-left:auto}',
    '.vbox{margin-top:10px;padding:10px 12px;border-radius:2px;font-size:11px;border:1px solid;display:none}',
    '.vbox.ok{border-color:var(--accent);background:rgba(61,190,122,.07);color:var(--accent)}',
    '.vbox.err{border-color:var(--err);background:rgba(239,68,68,.07);color:var(--err)}',
    '.vbox pre{white-space:pre-wrap;font-family:inherit;font-size:11px}',
    'table{width:100%;border-collapse:collapse}',
    'thead th{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.08em;padding:5px 8px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}',
    'tbody tr{border-bottom:1px solid var(--border)}',
    'tbody tr:hover{background:var(--bg2)}',
    'tbody td{padding:4px 8px;font-size:11px;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px}',
    '.ci{color:var(--dim)}.ch{color:var(--accent)}.ct-ts{color:var(--dim)}.ctype{color:#7bbf96}',
    '.empty{text-align:center;padding:28px;color:var(--dim);font-style:italic;max-width:none}',
    '@media(max-width:600px){.grid{grid-template-columns:1fr 1fr}tbody td{font-size:10px;padding:3px 5px}}',
  ].join('\n');

  const js = `
var g=function(i){return document.getElementById(i)};
function fmtId(x){return x?x.slice(0,16)+'...'+x.slice(-8):'N/A'}
function fmtTs(x){return x?x.replace('T',' ').replace(/\\.\\d+Z$/,'Z'):'\u2014'}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
async function load(){
  try{
    var r=await fetch('/ct/feed');
    if(!r.ok)throw new Error('HTTP '+r.status);
    var d=await r.json();
    g('rid').textContent=fmtId(d.relay_id);g('rid').title=d.relay_id||'';
    g('sec').textContent=d.sector||'\u2014';
    g('ver').textContent=d.version||'\u2014';
    g('tsz').textContent=(d.tree_size||0).toLocaleString()+' entries';
    g('rh').textContent=d.root||'\u2014';
    var tb=g('tb');
    if(!d.entries||!d.entries.length){
      tb.innerHTML='<tr><td colspan="5" class="empty">No entries yet \u2014 waiting for first transfer</td></tr>';
    }else{
      tb.innerHTML=d.entries.slice().reverse().map(function(e){
        return '<tr><td class="ci">'+esc(e.i!==undefined?e.i:'?')+'</td>'
          +'<td class="ct-ts">'+esc(fmtTs(e.t))+'</td>'
          +'<td class="ch">'+esc(e.h||'\u2014')+'</td>'
          +'<td class="ctype">'+esc(e.type||'key_reg')+'</td>'
          +'<td>'+esc(e.s||'\u2014')+'</td></tr>';
      }).join('');
    }
    g('sdot').className='dot ok';g('stxt').textContent='Live \u00b7 auto-refresh 10s';
    g('rinfo').textContent='Refreshed '+new Date().toISOString().slice(0,19).replace('T',' ')+'Z';
  }catch(e){g('sdot').className='dot err';g('stxt').textContent='Error: '+e.message;}
}
async function verify(){
  var vb=g('vbox'),btn=g('vbtn');
  btn.disabled=true;btn.textContent='Verifying...';vb.style.display='none';
  try{
    var res=await Promise.all([fetch('/ct/feed'),fetch('/v2/sth')]);
    var feed=await res[0].json();
    var sthResp=await res[1].json();
    var sth=sthResp.sth||sthResp; // /v2/sth returns {ok,sth:{...}}
    var lines=[],ok=true;
    var sthRoot=sth.sha3_root||sth.root;
    var sthSize=sth.tree_size;
    if(feed.root&&sthRoot){
      if(feed.root===sthRoot){
        lines.push('[OK]   Merkle root consistent across /ct/feed and /v2/sth');
        lines.push('       '+feed.root.slice(0,40)+'...');
      }else{ok=false;lines.push('[FAIL] Root mismatch between endpoints!');
        lines.push('  feed: '+feed.root.slice(0,32)+'...');
        lines.push('  sth:  '+sthRoot.slice(0,32)+'...');}
    }else if(!sthRoot){
      lines.push('[INFO] No STH yet — CT log is empty (no transfers recorded)');
    }
    if(sthSize!==undefined&&feed.tree_size!==undefined){
      var diff=Math.abs(sthSize-feed.tree_size);
      if(diff<=1)lines.push('[OK]   Tree size: '+feed.tree_size+' entries'+(diff?' (±1 in-flight write)':''));
      else{ok=false;lines.push('[WARN] Tree size mismatch: feed='+feed.tree_size+' sth='+sthSize);}
    }
    var rid=sth.relay_id||feed.relay_id;
    if(rid){
      lines.push('[OK]   Relay identity: '+rid.slice(0,20)+'...');
      lines.push('       Algorithm: ML-DSA-65 (NIST FIPS 204)');
    }else lines.push('[INFO] Relay identity not configured (RELAY_IDENTITY_FILE not set)');
    var sig=sth.signature||sth.sig;
    if(sig){
      lines.push('[OK]   ML-DSA-65 signature present');
      lines.push('       sig: '+sig.slice(0,24)+'...');
      lines.push('[INFO] Full sig verification requires ML-DSA-65 WASM module');
      lines.push('       Browser WebCrypto does not support post-quantum algorithms yet.');
    }else lines.push('[INFO] No ML-DSA-65 signature (relay identity not configured)');
    vb.className='vbox '+(ok?'ok':'err');vb.style.display='block';
    vb.innerHTML='<pre>'+esc(lines.join('\n'))+'</pre>';
  }catch(e){vb.className='vbox err';vb.style.display='block';vb.textContent='Verification failed: '+e.message;}
  finally{btn.disabled=false;btn.textContent='Verify this relay';}
}
load();setInterval(load,10000);
`.trim();

  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>CT Log \u2014 paramant relay</title>',
    '<style>', css, '</style>',
    '</head>',
    '<body>',
    '<div class="hdr">',
    '  <div class="logo">PARAMANT</div>',
    '  <div class="badge">Certificate Transparency Log \u2014 Public Audit Interface</div>',
    '</div>',
    '<div class="main">',
    '  <div class="sec">',
    '    <div class="sec-title">Relay Identity</div>',
    '    <div class="grid">',
    '      <div class="cell"><div class="cell-label">Relay ID</div><div class="cell-value" id="rid" title="">\u2014</div></div>',
    '      <div class="cell"><div class="cell-label">Sector</div><div class="cell-value hi" id="sec">\u2014</div></div>',
    '      <div class="cell"><div class="cell-label">Version</div><div class="cell-value" id="ver">\u2014</div></div>',
    '      <div class="cell"><div class="cell-label">Tree Size</div><div class="cell-value hi" id="tsz">\u2014</div></div>',
    '    </div>',
    '  </div>',
    '  <div class="sec">',
    '    <div class="sec-title">Current Merkle Root</div>',
    '    <div class="root-box">',
    '      <div class="root-label">SHA3-256 Merkle Tree Head \u2014 tamper-evident hash of all transfers</div>',
    '      <div class="root-hash" id="rh">\u2014</div>',
    '    </div>',
    '  </div>',
    '  <div class="sec">',
    '    <div class="status-bar">',
    '      <div><span class="dot idle" id="sdot"></span><span id="stxt">Connecting...</span></div>',
    '      <button class="btn" id="vbtn" onclick="verify()">Verify this relay</button>',
    '      <div class="refresh-info" id="rinfo"></div>',
    '    </div>',
    '    <div class="vbox" id="vbox"></div>',
    '  </div>',
    '  <div class="sec">',
    '    <div class="sec-title">Last 50 Log Entries <span style="color:var(--dim);font-weight:normal;letter-spacing:0">(newest first)</span></div>',
    '    <div style="overflow-x:auto">',
    '      <table>',
    '        <thead><tr><th>#</th><th>Timestamp (UTC)</th><th>Leaf Hash</th><th>Type</th><th>Sector</th></tr></thead>',
    '        <tbody id="tb"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody>',
    '      </table>',
    '    </div>',
    '  </div>',
    '</div>',
    '<script>', js, '<\/script>',
    '</body></html>',
  ].join('\n');
})();

// Cleanup expired tokens elke 60s
setInterval(() => {
  const now = Date.now();
  for (const [t, d] of downloadTokens.entries()) {
    if (d.used || now > d.expires_ms) downloadTokens.delete(t);
  }
}, 60000);

// ── PSS Sessions — pre-shared-secret commitment scheme (Mattijs Flow 1) ────
// session_id → { commitment: sha256hex, api_key: str, expires_ms: int,
//               joined: bool, ecdh_pub?, kyber_pub?, joined_at? }
const sessions = new Map();

// Cleanup expired sessions elke 60s
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions.entries()) {
    if (now > s.expires_ms) sessions.delete(id);
  }
}, 60000);


// ── RAM guard ────────────────────────────────────────────────────────────────
const RAM_LIMIT_MB    = parseInt(process.env.RAM_LIMIT_MB    || '512');
const RAM_RESERVE_MB  = parseInt(process.env.RAM_RESERVE_MB  || '256');
const BLOB_SIZE_MB    = 5;
const MAX_BLOBS       = Math.floor(RAM_LIMIT_MB / BLOB_SIZE_MB);

function ramStats() {
  const mem    = process.memoryUsage();
  const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
  const rssMB  = Math.round(mem.rss      / 1024 / 1024);
  let blobBytes = 0;
  for (const e of blobStore.values()) blobBytes += (e.size || 0);
  const blobMB  = Math.round(blobBytes / 1024 / 1024);
  return { heapMB, rssMB, blobMB, blobCount: blobStore.size };
}

function ramOk() {
  const { rssMB, blobCount } = ramStats();
  const effective = blobCount + inFlightInbound;
  if (effective >= MAX_BLOBS) return false;
  if (rssMB + BLOB_SIZE_MB * (inFlightInbound + 1) > RAM_LIMIT_MB + RAM_RESERVE_MB) return false;
  return true;
}

function ramStatus() {
  const s = ramStats();
  return {
    blobs_in_flight:  s.blobCount,
    blobs_uploading:  inFlightInbound,
    blobs_max:        MAX_BLOBS,
    blob_ram_mb:      s.blobMB,
    heap_mb:          s.heapMB,
    rss_mb:           s.rssMB,
    ram_limit_mb:     RAM_LIMIT_MB,
    ram_ok:           ramOk(),
    available_slots:  Math.max(0, MAX_BLOBS - s.blobCount - inFlightInbound),
  };
}

setInterval(() => {
  const r = ramStatus();
  if (!r.ram_ok) {
    log('warn', 'ram_pressure', r);
  } else if (r.blobs_in_flight > MAX_BLOBS * 0.7) {
    log('info', 'ram_high', r);
  }
}, 60000);

// ── RAM_GUARD marker
// ── RAM-only stores ───────────────────────────────────────────────────────────
const apiKeys    = new Map();  // key → {plan, active, label, dsa_pub}
const blobStore  = new Map();  // hash → {blob, ts, ttl, size, sig?}

// Trial key request rate limiting (in-memory)
const trialRequests   = new Map(); // email_lc → last_request_ts
const trialIpRequests = new Map(); // ip → [timestamps]  (max 3 per 24h)
const anonInboundIpRequests = new Map(); // ip → [timestamps] for /v2/anon-inbound rate limit

// Team rate limit tracking
const teamRateLimits = new Map(); // team_id → { count, resetAt }
function checkTeamRateLimit(teamId, limit) {
  if (!teamId) return true;
  const now = Date.now();
  const b = teamRateLimits.get(teamId) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= limit) return false;
  b.count++; teamRateLimits.set(teamId, b); return true;
}

// M2: Per-IP rate limit for /v2/admin/verify-mfa (max 5 attempts per minute)
const mfaRateLimits = new Map(); // ip → { count, resetAt }
function checkMfaRateLimit(ip) {
  const now = Date.now();
  const b = mfaRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= 5) return false;
  b.count++; mfaRateLimits.set(ip, b); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of mfaRateLimits) if (now > v.resetAt + 60000) mfaRateLimits.delete(k); }, 120_000);
const pubkeys    = new Map();  // device:key → {ecdh_pub, kyber_pub, dsa_pub, ts}
const webhooks   = new Map();  // device:key → [{url, secret}]
const auditChain = new Map();  // key → Merkle chain [{ts,event,hash,bytes,device,prev_hash,chain_hash}]

function log(level, msg, data = {}) {
  if (typeof msg === 'string')
    console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, v: VERSION, ...data }));
}

function J(o) { return JSON.stringify(o); }

// ── Client IP — prefers CF-Connecting-IP (production), falls back to X-Real-IP set by nginx ──
function getClientIp(req) {
  return req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

// ── HTML escaping for email templates (prevents HTML injection in Resend emails) ──
function escHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Key zeroization ───────────────────────────────────────────────────────────
function zeroBuffer(buf) {
  if (buf && Buffer.isBuffer(buf)) {
    try { crypto.randomFillSync(buf); } catch {}
    try { buf.fill(0); } catch {}
  }
}

// ── HKDF-SHA256 — compatible met Python cryptography library ──────────────────
function hkdf(ikm, salt, info, length) {
  const s = typeof salt === 'string' ? Buffer.from(salt) : salt;
  const i = typeof info === 'string' ? Buffer.from(info) : info;
  try {
    return Buffer.from(crypto.hkdfSync('sha256', ikm, s, i, length));
  } catch(e) {
    // Fallback voor Node < 15 (handmatige HKDF implementatie)
    const prk = crypto.createHmac('sha256', s).update(ikm).digest();
    let t = Buffer.alloc(0), okm = Buffer.alloc(0);
    for (let n = 0; okm.length < length; n++) {
      t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, i, Buffer.from([n + 1])])).digest();
      okm = Buffer.concat([okm, t]);
    }
    return okm.slice(0, length);
  }
}

// Leid relay lookup-hash af van BIP39 mnemonic (zelfde als Python SDK)
function mnemonicToLookupHash(phrase) {
  if (!bip39Lib) throw new Error('bip39 not available (npm install bip39)');
  if (!bip39Lib.validateMnemonic(phrase)) throw new Error('Invalid BIP39 mnemonic (checksum error)');
  const entropy = Buffer.from(bip39Lib.mnemonicToEntropy(phrase), 'hex');
  const idBytes = hkdf(entropy, 'paramant-drop-v1', 'lookup-id', 32);
  const hash    = crypto.createHash('sha3-256').update(idBytes).digest('hex');
  zeroBuffer(entropy);
  return hash;
}

// ── Merkle audit chain ────────────────────────────────────────────────────────
// Elke entry bevat hash van vorige entry — tamper-evident log
function auditAppend(key, event, data = {}) {
  if (!key) return;
  if (!auditChain.has(key)) auditChain.set(key, []);
  const chain    = auditChain.get(key);
  const prevHash = chain.length > 0 ? chain[chain.length - 1].chain_hash : '0'.repeat(64);
  const entry    = { ts: new Date().toISOString(), event, prev_hash: prevHash, ...data };
  const entryStr = JSON.stringify({ ts: entry.ts, event, hash: data.hash||'', bytes: data.bytes||0, prev_hash: prevHash });
  entry.chain_hash = crypto.createHash('sha3-256').update(entryStr).digest('hex');
  chain.push(entry);
  if (chain.length > MAX_AUDIT) chain.shift();
}

function verifyChain(entries) {
  // Verifieer integriteit van de audit chain
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].prev_hash !== entries[i-1].chain_hash) return false;
  }
  return true;
}

// ── ML-DSA handtekening verificatie ──────────────────────────────────────────
function verifyDsaSignature(payload, signature, pubKeyHex) {
  if (!mlDsa || !signature || !pubKeyHex) return { valid: false, reason: 'ML-DSA not available or no sig' };
  try {
    const pub = Buffer.from(pubKeyHex, 'hex');
    const sig = Buffer.from(signature, 'hex');
    const msg = Buffer.from(payload);
    const valid = mlDsa.verify(pub, msg, sig);
    return { valid, alg: 'ML-DSA-65' };
  } catch(e) {
    return { valid: false, reason: e.message };
  }
}

// ── Relay stats ───────────────────────────────────────────────────────────────
let stats = { inbound: 0, outbound: 0, burned: 0, webhooks_sent: 0, bytes_in: 0, bytes_out: 0 };
let inFlightInbound = 0;

// ── Per-key outbound rate limiting (finding #12) ──────────────────────────────
// Limits how fast a key holder can burn blobs via /v2/outbound — reduces
// ability to probe or burn other users' blobs via intercepted download tokens.
const OUTBOUND_RATE = { free: 50, pro: 500, enterprise: Infinity };
const OUTBOUND_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour sliding window
const outboundRateMap = new Map(); // apiKey → { count, resetAt }
function outboundRateOk(apiKey, plan) {
  const max = OUTBOUND_RATE[plan] ?? OUTBOUND_RATE.free;
  if (max === Infinity) return true;
  const now = Date.now();
  let c = outboundRateMap.get(apiKey);
  if (!c || now > c.resetAt) { c = { count: 0, resetAt: now + OUTBOUND_RATE_WINDOW_MS }; }
  if (c.count >= max) return false;
  c.count++; outboundRateMap.set(apiKey, c);
  return true;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of outboundRateMap) if (now > v.resetAt) outboundRateMap.delete(k); }, 3_600_000);

// Serialized async write queue for users.json — prevents lost-update race.
// _writeUsersJson: low-level write (caller must already hold the snapshot).
// _mutateUsersJson: safe read-modify-write inside the queue (use this at call sites).
let _usersWriteQueue = Promise.resolve();
function _writeUsersJson(data) {
  _usersWriteQueue = _usersWriteQueue.then(() =>
    fs.promises.writeFile(USERS_FILE, JSON.stringify(data, null, 2))
  ).catch(e => log('warn', 'users_write_error', { err: e.message }));
  return _usersWriteQueue;
}
function _mutateUsersJson(fn) {
  _usersWriteQueue = _usersWriteQueue.then(async () => {
    const raw = await fs.promises.readFile(USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    fn(data);
    await fs.promises.writeFile(USERS_FILE, JSON.stringify(data, null, 2));
  }).catch(e => log('warn', 'users_write_error', { err: e.message }));
  return _usersWriteQueue;
}

function loadUsers() {
  if (process.env.USERS_JSON) {
    try { const d = JSON.parse(process.env.USERS_JSON); (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||"",active:true}); }); log("info","users_loaded",{count:apiKeys.size,source:"env"}); return; } catch(e) { log("error","users_json_parse",{err:e.message}); }
  }
  try {
    const d = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    (d.api_keys || []).forEach(k => {
      if (k.active) apiKeys.set(k.key, {
        plan: k.plan, label: k.label||'', active: true, dsa_pub: k.dsa_pub||'',
        daily_uploads: 0, daily_reset_ts: Date.now() + 86_400_000,
        is_trial: !!(k.plan === 'community' && k.trial_metadata),
        trial_created: k.created ? new Date(k.created).getTime() : null,
        uploads_today: 0, last_upload_day: '',
      });
    });
    log('info', 'users_loaded', { count: apiKeys.size, sector: SECTOR });
  } catch(e) { log('warn', 'no_users_file'); }
}

function loadTrialKeys() {
  try {
    const lines = fs.readFileSync(TRIAL_KEYS_FILE, 'utf8').split('\n').filter(Boolean);
    let loaded = 0;
    for (const line of lines) {
      try {
        const k = JSON.parse(line);
        if (!k.key || !k.active) continue;
        // Don't overwrite a key already loaded from users.json
        if (!apiKeys.has(k.key)) {
          apiKeys.set(k.key, {
            plan: 'community', label: k.label||'', active: true, dsa_pub: '',
            daily_uploads: 0, daily_reset_ts: Date.now() + 86_400_000,
            is_trial: true, trial_created: k.created || Date.now(),
            uploads_today: 0, last_upload_day: '',
          });
          loaded++;
        }
      } catch {}
    }
    if (loaded > 0) log('info', 'trial_keys_loaded', { count: loaded });
  } catch(e) { /* file may not exist yet */ }
}

// Pubkey plan limits and TTL
const _pubkeyTtl = { free: 7 * 86_400_000, pro: 30 * 86_400_000, enterprise: 365 * 86_400_000 };
const _pubkeyMax = { free: 5, pro: 50, enterprise: Infinity };
const INVITE_PUBKEY_TTL = 3_600_000; // 1 hour

// TTL flush — clean pubkey rate limit map hourly + expired pubkeys
setInterval(() => {
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0,10);
  // Clean expired pubkeys
  const now = Date.now();
  for (const [k, v] of pubkeys.entries()) {
    if (v.expires && now > v.expires) pubkeys.delete(k);
  }
}, 3600000);

setInterval(() => {
  const now = Date.now();
  for (const [h, e] of blobStore.entries()) {
    if (now - e.ts > e.ttl) {
      zeroBuffer(e.blob);
      blobStore.delete(h);
      log('info', 'blob_ttl_expired', { hash: h.slice(0,16) });
    }
  }
}, 30_000);

// ── SSRF guard — only allow public HTTPS webhook URLs ─────────────────────────
// Blocks: RFC1918, loopback, link-local, IPv6 ULA, cloud metadata,
//         and all alternate IP representations (decimal, hex, octal, short-form,
//         IPv4-mapped IPv6) that bypass naive string-based checks.
function isSsrfSafeUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
    // Reject non-hostname forms: pure decimal (2130706433), hex (0x7f000001), short octal
    if (/^\d+$/.test(h)) return false;                  // decimal IP
    if (/^0x[0-9a-f]+$/i.test(h)) return false;          // hex IP
    if (/^(0\d+\.){1,3}\d+$/.test(h)) return false;    // octal octets (0177.0.0.1)
    if (/^\d+\.\d+$/.test(h)) return false;             // short-form (127.1)
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (/^::ffff:/i.test(h)) {
      const v4part = h.replace(/^::ffff:/i, '');
      return isSsrfSafeUrl('https://' + v4part + '/');
    }
    if (h === 'localhost' || h === '0.0.0.0' || h === '0') return false;
    if (/^127\./.test(h)) return false;
    if (/^::1$/.test(h)) return false;
    if (/^169\.254\./.test(h)) return false;
    if (/^fe80/i.test(h)) return false;
    if (/^10\./.test(h)) return false;
    if (/^192\.168\./.test(h)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
    if (/^f[cd]/i.test(h)) return false;                  // IPv6 ULA (fc00::/7)
    if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return false;
    if (h === 'metadata.google.internal' || h === 'metadata.aws.internal') return false;
    // Fix 11: restrict to standard HTTPS ports only
    const ALLOWED_PORTS = new Set(['', '443']);
    if (!ALLOWED_PORTS.has(u.port)) return false;
    return true;
  } catch { return false; }
}

// ── Webhook push ──────────────────────────────────────────────────────────────
async function pushWebhooks(apiKey, deviceId, event, data) {
  const hooks = webhooks.get(`${deviceId}:${apiKey}`) || [];
  for (const hook of hooks) {
    if (!isSsrfSafeUrl(hook.url)) { log('warn', 'webhook_ssrf_blocked', { url: (hook.url||'').slice(0,60) }); continue; }
    // DNS rebinding defense: resolve the hostname and verify the resulting IP
    // Prevents attack where domain resolves to public IP at registration, then DNS
    // TTL expires and is switched to a private/RFC1918 address before firing.
    try {
      const _wu = new URL(hook.url);
      const _resolved = await require('dns').promises.lookup(_wu.hostname);
      if (!isSsrfSafeUrl('https://' + _resolved.address + '/')) {
        log('warn', 'webhook_dns_rebinding_blocked', { url: hook.url.slice(0,60), resolved: _resolved.address });
        continue;
      }
    } catch(e) {
      log('warn', 'webhook_dns_resolve_fail', { url: (hook.url||'').slice(0,60), err: e.message });
      continue;
    }
    const payload = J({ event, device_id: deviceId, ts: new Date().toISOString(), ...data });
    try {
      const sig = hook.secret ? crypto.createHmac('sha256', hook.secret).update(payload).digest('hex') : '';
      const req = https.request(hook.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload),
                   'X-Paramant-Event': event, 'X-Paramant-Sig': sig, 'User-Agent': `paramant-relay/${VERSION}` }
      });
      req.on('error', () => {});
      req.write(payload); req.end();
      stats.webhooks_sent++;
    } catch(e) { log('warn', 'webhook_fail', { url: (hook.url||'').slice(0,60) }); }
  }
}


// ── DID-only authenticatie ────────────────────────────────────────────────────
// Apparaat stuurt x-did + x-did-signature — geen centrale users.json nodig
// DER-SPKI prefix for P-256 uncompressed public key (65 bytes → 91 bytes total).
// publicKeyHex stores raw ECDH P-256 point bytes; crypto.verify requires DER-SPKI.
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

// ── Constant-time token comparison — prevents timing-side-channel on admin token (finding) ──
function safeEqual(a, b) {
  try {
    const ba = Buffer.from(String(a || ''), 'utf8');
    const bb = Buffer.from(String(b || ''), 'utf8');
    if (ba.length !== bb.length) {
      // Still do the compare to avoid length oracle, but result is always false
      const pad = Buffer.alloc(Math.max(ba.length, bb.length));
      crypto.timingSafeEqual(pad, pad);
      return false;
    }
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

function authByDid(didStr, signature, payload) {
  const entry = didRegistry.get(didStr);
  if (!entry) return null;
  const vm = entry.doc.verificationMethod?.[0];
  if (!vm || !vm.publicKeyHex) return null;
  try {
    const rawKey = Buffer.from(vm.publicKeyHex, 'hex');
    // Wrap raw uncompressed P-256 point in DER-SPKI if not already encoded (0x30 = SEQUENCE tag)
    const spkiKey = rawKey[0] === 0x30 ? rawKey : Buffer.concat([P256_SPKI_PREFIX, rawKey]);
    const valid = crypto.verify(
      'SHA256',
      Buffer.from(payload),
      { key: spkiKey, format: 'der', type: 'spki' },
      Buffer.from(signature, 'hex')
    );
    if (valid) return entry;
  } catch(e) {
    log('warn', 'did_auth_verify_error', { err: e.message, did: didStr.slice(0,30) });
  }
  return null;
}

// ── CORS ──────────────────────────────────────────────────────────────────────
function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (origin === 'https://paramant.app' || origin.endsWith('.paramant.app')) return true;
  if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://')) return true;
  if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) return true;
  return false;
}
function setHeaders(res, req) {
  const origin = req?.headers?.origin || '';
  const allowOrigin = isAllowedOrigin(origin) ? origin : 'https://paramant.app';
  res.setHeader('Access-Control-Allow-Origin',  allowOrigin);
  res.setHeader('Vary',                         'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Dsa-Signature, Authorization, X-DID, X-DID-Signature');
  res.setHeader('Cache-Control',                'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options',       'nosniff');
  res.setHeader('Content-Security-Policy',      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
  res.setHeader('Strict-Transport-Security',    'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy',              'no-referrer');
  res.setHeader('Permissions-Policy',           'interest-cohort=()');
  // X-Paramant-Version intentionally omitted — version disclosure via response header removed (security hardening v2.3.3)
  res.setHeader('X-Paramant-Sector',            SECTOR);
  res.setHeader('X-Crypto-Version',             'ML-KEM-768+AES-256-GCM');
  res.setHeader('X-Hybrid-Mode',                'available');
}

function readBody(req, max = MAX_BLOB * 2) {
  return new Promise((res, rej) => {
    const c = []; let n = 0;
    req.on('data', d => { n += d.length; if (n > max) return rej(new Error('Too large')); c.push(d); });
    req.on('end',   () => res(Buffer.concat(c)));
    req.on('error', rej);
  });
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  setHeaders(res, req);
  const parsed  = url_.parse(req.url, true);
  const path    = parsed.pathname;
  const query   = parsed.query;
  const apiKey  = (req.headers['x-api-key'] || '').trim();
  // Reject any request that passes the API key as a query-string parameter.
  // Query strings appear in server logs, browser history, and proxy access logs.
  if (query.k) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'API key must be sent in the X-Api-Key header, not as a query parameter.' }));
  }
  const didHeader = req.headers['x-did'] || '';
  const didSig    = req.headers['x-did-signature'] || '';
  let didAuthEntry = null;
  if (!apiKey && didHeader && didSig) {
    didAuthEntry = authByDid(didHeader, didSig, req.url);
    if (didAuthEntry) log('info', 'did_auth_mode', { did: didHeader.slice(0,30) });
  }
  const dsaSig  = req.headers['x-dsa-signature'] || '';
  const keyData = apiKeys.get(apiKey) || (didAuthEntry ? { plan: 'pro', active: true, label: didAuthEntry.device_id } : null);

  // Community Edition limit: block keys that exceed the 5-key cap
  // /v2/check-key is exempt — it must always return the real key status so
  // clients can discover which relay accepts their key without being gated.
  if (keyData?.over_limit && path !== '/v2/check-key') {
    res.writeHead(402, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      error: 'This relay has reached its user limit. Please contact the relay operator.',
      operator_hint: 'Relay operators: add PARAMANT_LICENSE=plk_... to .env to unlock unlimited users. See https://paramant.app/pricing',
      docs: 'https://github.com/Apolloccrypt/paramant-relay#license--pricing'
    }));
  }

  incMetric('requests_total');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (path === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, relay: SECTOR, version: VERSION, status: 'operational', protocol: 'ghost-pipe-v2', docs: 'https://paramant.app/docs' }));
  }
  if (!modeAllows(path)) { res.writeHead(405); return res.end(J({ error: 'Not available in this relay mode', mode: RELAY_MODE })); }

  // ── GET /health ─────────────────────────────────────────────────────────────
  if (path === '/health') {
    const adminTok = (req.headers['x-admin-token'] || '').trim();
    const adminOk  = adminTok && safeEqual(adminTok, process.env.ADMIN_TOKEN || '');
    const ram = ramStatus();
    const base = { ok: true, version: VERSION, sector: SECTOR, edition: EDITION,
      max_keys: LICENSE_MAX_KEYS === Infinity ? null : LICENSE_MAX_KEYS,
      ...(LICENSE_PAYLOAD ? { license_expires: LICENSE_PAYLOAD.expires_at, license_issued_to: LICENSE_PAYLOAD.issued_to } : {}) };
    const full = { ...base, ...ram, pubkeys: pubkeys.size,
      webhooks: [...webhooks.values()].flat().length, stats,
      quantum_ready: true, protocol: 'ghost-pipe-v2',
      encryption: 'ML-KEM-768 + ECDH P-256 + AES-256-GCM',
      signatures: mlDsa ? 'ML-DSA-65 (NIST FIPS 204)' : 'ECDSA P-256 (ML-DSA fallback)',
      audit: 'Merkle hash chain',
      storage: 'RAM-only, zero plaintext, burn-on-read',
      padding: '5MB fixed (DPI-masking)',
      jurisdiction: 'EU/DE, GDPR, no US CLOUD Act',
      edition: EDITION,
      key_limit: LICENSE_MAX_KEYS === Infinity ? null : LICENSE_MAX_KEYS,
      active_keys: [...apiKeys.values()].filter(k => k.active !== false).length };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J(adminOk ? full : base));
  }

  // ── GET /v2/auth/capabilities — public, no auth ─────────────────────────────
  if (req.method === 'GET' && path === '/v2/auth/capabilities') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      api_key: true,
      user_totp: process.env.ENABLE_USER_TOTP === 'true',
      user_totp_status: process.env.ENABLE_USER_TOTP === 'true'
        ? 'live'
        : 'rolling_out_q2_2026',
      capabilities_version: 1,
    }));
  }

  // ── GET /v2/check-key ───────────────────────────────────────────────────────
  if (path === '/v2/check-key') {
    const kd = apiKeys.get(apiKey);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ valid: !!(kd?.active), plan: kd?.plan || null }));
  }

  // ── POST /v2/request-trial — Self-service trial key request (public, no auth) ──
  if (path === '/v2/request-trial' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());

      // Honeypot: bots fill hidden fields; legitimate browsers leave them empty
      if (d._hp) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(J({ ok: true })); }

      const rawEmail = (d.email || '').toString().trim();
      const name = (d.name || '').toString().trim().slice(0, 128);
      const useCase = ((d.use_case || d.usecase) || '').toString().trim().slice(0, 512);
      if (!name || !rawEmail || !useCase) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'name, email and use_case are required' }));
      }
      if (rawEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'Invalid email address' }));
      }

      const now = Date.now();
      const DAY_MS = 86_400_000;

      // IP rate limit: max 3 per IP per 24h
      // Use CF-Connecting-IP (Cloudflare) or X-Real-IP (nginx $remote_addr) instead of
      // socket address, which collapses to the proxy IP in reverse-proxy deployments.
      const clientIp = getClientIp(req);
      const ipTimes = (trialIpRequests.get(clientIp) || []).filter(t => now - t < DAY_MS);
      if (ipTimes.length >= 3) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '86400' });
        return res.end(J({ error: 'Too many requests' }));
      }

      // Email rate limit: 1 per 7 days — generic 429 (no info disclosure about existing key)
      const emailKey = rawEmail.toLowerCase();
      if (trialRequests.has(emailKey) && now - trialRequests.get(emailKey) < 7 * DAY_MS) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '604800' });
        return res.end(J({ error: 'Too many requests' }));
      }

      // Record rate limit entries
      ipTimes.push(now);
      trialIpRequests.set(clientIp, ipTimes);
      trialRequests.set(emailKey, now);

      const newKey = 'pgp_' + crypto.randomBytes(32).toString('hex');
      const label = `trial:${name.replace(/\s+/g, '_').toLowerCase().slice(0, 40)}`;
      const trialCreated = now;
      apiKeys.set(newKey, {
        plan: 'community', label, active: true, dsa_pub: '',
        daily_uploads: 0, daily_reset_ts: now + DAY_MS,
        is_trial: true, trial_created: trialCreated,
        uploads_today: 0, last_upload_day: '',
      });

      // Persist to JSONL (append-only, survives restarts independently of users.json)
      const trialRecord = JSON.stringify({ key: newKey, label, email: rawEmail, active: true, created: trialCreated, trial_metadata: { name, use_case: useCase } });
      fs.promises.appendFile(TRIAL_KEYS_FILE, trialRecord + '\n').catch(e => log('warn', 'trial_key_jsonl_failed', { err: e.message }));

      // Also persist to users.json (admin visibility) — full read-modify-write inside queue
      _mutateUsersJson(d => {
        d.api_keys.push({ key: newKey, plan: 'community', label, email: rawEmail, active: true, created: new Date(trialCreated).toISOString(), trial_metadata: { name, use_case: useCase } });
        d.updated = new Date().toISOString();
      });

      const RESEND_KEY = process.env.RESEND_API_KEY || '';
      function sendEmail(to, subject, html) {
        if (!RESEND_KEY) return;
        const body = JSON.stringify({ from: 'PARAMANT <privacy@paramant.app>', to: [to], subject, html });
        const r = https.request({ hostname: 'api.resend.com', path: '/emails', method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        }, res2 => { res2.on('data', () => {}); res2.on('end', () => {}); });
        r.on('error', e => log('warn', 'trial_email_failed', { to, err: e.message }));
        r.write(body); r.end();
      }

      // Welcome email to requester
      const welcomeHtml = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:520px">
          <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
          <p style="color:#888;margin-bottom:16px">Hi ${escHtml(name)},</p>
          <p style="color:#888;margin-bottom:24px">Your free trial API key is ready. It gives you access to the community relay — burn-on-read, ML-KEM-768 encryption, EU/DE jurisdiction.</p>
          <div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px">
            <div style="font-size:11px;color:#555;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">API KEY — COMMUNITY TRIAL</div>
            <div style="font-size:14px;color:#ededed;word-break:break-all">${newKey}</div>
          </div>
          <div style="background:#1a1a00;border:1px solid #2a2a00;border-radius:6px;padding:16px;margin-bottom:24px;color:#cccc00;font-size:12px">
            IMPORTANT: Save this key in your password manager immediately. It is generated once and cannot be recovered.
          </div>
          <p style="font-size:12px;color:#555">Limits: 10 uploads/day · 1h TTL · 5MB · 30-day trial</p>
          <pre style="background:#111;border:1px solid #1a1a1a;border-radius:4px;padding:16px;font-size:12px;color:#888;overflow-x:auto">pip install paramant-sdk

from paramant import ParamantClient
client = ParamantClient(api_key='${newKey}')
session = client.create_session('recipient@example.com')</pre>
          <p style="margin-top:24px;font-size:12px;color:#555"><a href="https://paramant.app/docs" style="color:#888">Docs</a> &nbsp;&middot;&nbsp; <a href="https://paramant.app" style="color:#888">Dashboard</a></p>
          <p style="margin-top:32px;font-size:11px;color:#333">ML-KEM-768 &nbsp;&middot;&nbsp; Burn-on-read &nbsp;&middot;&nbsp; EU/DE &nbsp;&middot;&nbsp; BUSL-1.1</p>
        </div>`;
      sendEmail(rawEmail, 'Your PARAMANT trial API key', welcomeHtml);

      // Notification email to operator
      const notifyHtml = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:32px;max-width:480px">
          <div style="font-size:14px;font-weight:600;margin-bottom:16px;letter-spacing:.08em">PARAMANT — new trial key</div>
          <table style="font-size:12px;color:#888;border-collapse:collapse">
            <tr><td style="padding:4px 12px 4px 0;color:#555">Name</td><td>${escHtml(name)}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#555">Email</td><td>${escHtml(rawEmail)}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#555">Use case</td><td>${escHtml(useCase.slice(0, 120))}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#555">Key prefix</td><td>${newKey.slice(0, 12)}…</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#555">Time</td><td>${new Date(now).toISOString()}</td></tr>
          </table>
        </div>`;
      sendEmail('privacy@paramant.app', `New trial key: ${name} <${rawEmail}>`, notifyHtml);

      log('info', 'trial_key_requested', { name, email: rawEmail, use_case: useCase.slice(0, 80) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key: newKey, email: rawEmail,
        message: 'Your API key is ready. Save it now — it cannot be recovered. A copy has also been sent to your email.' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/sign-dpa — Electronic DPA signature (GDPR Art. 28) ──────────────
  if (path === '/v2/sign-dpa' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 8192)).toString());
      const name  = (d.name  || '').toString().trim().slice(0, 256);
      const title = (d.title || '').toString().trim().slice(0, 256);
      const org   = (d.org   || '').toString().trim().slice(0, 256);
      const kvk   = (d.kvk   || '').toString().trim().slice(0, 64);
      const email = (d.email || '').toString().trim();
      const version = (d.version || '2025-01-01').toString().trim().slice(0, 20);

      if (!name || !org || !email) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'name, org, and email are required' }));
      }
      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'Invalid email address' }));
      }

      // Rate limit: max 3 DPA signatures per IP per 24h, max 1 per email per 24h
      const dpaNow = Date.now(), DPA_WIN = 86_400_000;
      const dpaIp = getClientIp(req);
      const dpaIpTimes = (dpaIpRequests.get(dpaIp) || []).filter(t => dpaNow - t < DPA_WIN);
      if (dpaIpTimes.length >= 3) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '86400' });
        return res.end(J({ error: 'Too many requests' }));
      }
      if (dpaEmailRequests.has(email) && dpaNow - dpaEmailRequests.get(email) < DPA_WIN) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '86400' });
        return res.end(J({ error: 'Too many requests' }));
      }
      dpaIpTimes.push(dpaNow);
      dpaIpRequests.set(dpaIp, dpaIpTimes);
      dpaEmailRequests.set(email, dpaNow);

      const ref = 'DPA-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
      const signed_at = new Date().toISOString();

      // Persist DPA signature record (append-only)
      const DPA_FILE = process.env.DPA_FILE || '/etc/paramant/dpa-signatures.jsonl';
      const record = JSON.stringify({ ref, name, title, org, kvk, email, version, signed_at, ip: getClientIp(req) });
      fs.promises.appendFile(DPA_FILE, record + '\n').catch(e => log('warn', 'dpa_persist_failed', { err: e.message }));

      // Send countersigned DPA email
      const RESEND_KEY = process.env.RESEND_API_KEY || '';
      if (RESEND_KEY) {
        const html = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:600px">
          <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
          <p style="color:#888;margin-bottom:16px">Dear ${escHtml(name)},</p>
          <p style="color:#888;margin-bottom:24px">This email confirms that a Data Processing Agreement (GDPR Art. 28) has been signed on behalf of <strong style="color:#ededed">${escHtml(org)}</strong>.</p>
          <div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px;font-size:13px">
            <div style="color:#555;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">Agreement details</div>
            <table style="width:100%;border-collapse:collapse">
              <tr><td style="color:#555;padding:4px 0;width:40%">Reference</td><td style="color:#ededed">${ref}</td></tr>
              <tr><td style="color:#555;padding:4px 0">Organisation</td><td style="color:#ededed">${escHtml(org)}</td></tr>
              <tr><td style="color:#555;padding:4px 0">Signatory</td><td style="color:#ededed">${escHtml(name)}${title ? ' — ' + escHtml(title) : ''}</td></tr>
              <tr><td style="color:#555;padding:4px 0">Signed at</td><td style="color:#ededed">${signed_at}</td></tr>
              <tr><td style="color:#555;padding:4px 0">DPA version</td><td style="color:#ededed">${version}</td></tr>
              <tr><td style="color:#555;padding:4px 0">Processor</td><td style="color:#ededed">PARAMANT — Hetzner DE (FSN1)</td></tr>
            </table>
          </div>
          <p style="color:#888;font-size:13px;margin-bottom:24px">The full agreement text is available at <a href="https://paramant.app/verwerkersovereenkomst" style="color:#888">paramant.app/verwerkersovereenkomst</a>. Keep this email and the reference number for your records.</p>
          <p style="color:#555;font-size:12px">Questions: privacy@paramant.app &nbsp;&middot;&nbsp; EU/DE jurisdiction &nbsp;&middot;&nbsp; GDPR Art. 28 compliant</p>
        </div>`;
        const emailBody = JSON.stringify({
          from: 'PARAMANT <privacy@paramant.app>',
          to: [email],
          cc: ['privacy@paramant.app'],
          subject: `DPA signed — ${org} (${ref})`,
          html,
        });
        const req2 = https.request({ hostname: 'api.resend.com', path: '/emails', method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(emailBody) }
        }, r => { let data = ''; r.on('data', c => data += c); r.on('end', () => { try { const p = JSON.parse(data); log('info', 'dpa_email_sent', { ref, email, id: p.id }); } catch(e) {} }); });
        req2.on('error', e => log('warn', 'dpa_email_failed', { err: e.message }));
        req2.write(emailBody); req2.end();
      }

      log('info', 'dpa_signed', { ref, org, email, version });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, ref, signed_at }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /metrics — Prometheus metrics (voor auth gate, ADMIN_TOKEN vereist) ──
  if (path === '/metrics') {
    const adminToken = process.env.ADMIN_TOKEN || '';
    const reqToken = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (adminToken && !safeEqual(reqToken, adminToken)) {
      res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('Unauthorized');
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
    return res.end(renderPrometheus());
  }

  // ── GET /ct, /ct/ — public CT log web UI (no auth) ─────────────────────────
  if ((path === '/ct' || path === '/ct/') && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(CT_PAGE);
  }

  // ── GET /ct/feed — public JSON feed for CT log UI (no auth, no keys) ─────────
  if (path === '/ct/feed' && req.method === 'GET') {
    const last50 = ctLog.slice(-50);
    const root   = ctLog.length ? ctLog[ctLog.length - 1].tree_hash : '0'.repeat(64);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(J({
      relay_id: relayIdentity ? relayIdentity.pk_hash : null,
      sector:   SECTOR,
      version:  VERSION,
      tree_size: ctLog.length,
      root,
      entries: last50.map(e => ({
        i:    e.index,
        t:    e.ts,
        h:    e.leaf_hash ? e.leaf_hash.slice(0, 16) + '...' : null,
        type: e.type || 'key_reg',
        s:    e.relay_sector || SECTOR,
      })),
    }));
  }

  // ── GET /v2/ct/log + /v2/ct/proof — publiek, geen auth ──────────────────────
  if (path === '/v2/ct/log') {
    const limit = Math.min(parseInt(query.limit || '100'), 1000);
    const from  = parseInt(query.from || '0');
    const entries = ctLog.slice(from, from + limit).map(e => ({ index: e.index, type: e.type, leaf_hash: e.leaf_hash, tree_hash: e.tree_hash, device_hash: e.device_hash, ts: e.ts }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, size: ctLog.length, root: ctLog.length ? ctLog[ctLog.length-1].tree_hash : '0'.repeat(64), entries }));
  }
  const ctpm0 = path.match(/^\/v2\/ct\/proof\/(\d+)$/);
  const ctpq0 = (!ctpm0 && path === '/v2/ct/proof') ? query.index : null;
  if (ctpm0 || (ctpq0 !== null && ctpq0 !== undefined)) {
    const idx = parseInt(ctpm0 ? ctpm0[1] : ctpq0);
    const entry = ctLog[idx];
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Index not found' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, index: idx, leaf_hash: entry.leaf_hash, tree_hash: entry.tree_hash, proof: entry.proof, ts: entry.ts }));
  }

  // ── GET /v2/sth, /v2/sth/history, /v2/sth/:timestamp — Signed Tree Head (public) ──
  if (path === '/v2/sth' && req.method === 'GET') {
    const latest = sthLog.length ? sthLog[sthLog.length - 1] : null;
    if (!latest) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'No STH yet — CT log is empty' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, sth: latest }));
  }
  if (path === '/v2/sth/history' && req.method === 'GET') {
    const limit = Math.min(parseInt(query.limit || '100'), 100);
    const history = sthLog.slice(-limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: history.length, total: sthLog.length, sths: history }));
  }
  const sthTsm = path.match(/^\/v2\/sth\/(\d+)$/);
  if (sthTsm && req.method === 'GET') {
    const ts = parseInt(sthTsm[1]);
    const found = sthLog.find(s => s.timestamp >= ts);
    if (!found) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'No STH at or after this timestamp' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, sth: found }));
  }

  // ── POST /v2/relays/register — relay self-registration, ML-DSA-65 verified ───
  // Public endpoint — no API key required. Requires valid ML-DSA-65 signature.
  if (path === '/v2/relays/register' && req.method === 'POST') {
    if (!mlDsa) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'ML-DSA-65 not available on this relay — relay registry disabled' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 65536)).toString()); } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid JSON body' }));
    }
    const { url: rUrl, sector: rSector, version: rVersion, edition: rEdition,
            public_key, signature, timestamp } = body;
    if (!rUrl || !rSector || !rVersion || !public_key || !signature || !timestamp) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Missing required fields: url, sector, version, public_key, signature, timestamp' }));
    }
    // Fix: validate relay URL before storing — prevents SSRF via gossip broadcastSTH
    if (!isSsrfSafeUrl(rUrl)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'url must be a valid public HTTPS URL (private/loopback addresses not allowed)' }));
    }
    // Timestamp freshness check — reject if older than 5 minutes (replay prevention)
    const ageSec = (Date.now() - new Date(timestamp).getTime()) / 1000;
    if (Math.abs(ageSec) > 300) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Timestamp out of range — must be within 5 minutes of server time', age_sec: Math.round(ageSec) }));
    }
    let pkBytes, sigBytes;
    try { pkBytes = Buffer.from(public_key, 'base64'); sigBytes = Buffer.from(signature, 'base64'); } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid base64 in public_key or signature' }));
    }
    // Verify ML-DSA-65 signature over: url|sector|version|timestamp
    // API in @noble/post-quantum: verify(signature, message, publicKey)
    const msg = Buffer.from(rUrl + '|' + rSector + '|' + rVersion + '|' + timestamp, 'utf8');
    let verified = false;
    try { verified = mlDsa.verify(sigBytes, msg, pkBytes); } catch {}
    if (!verified) {
      log('warn', 'relay_register_bad_sig', { url: rUrl, sector: rSector });
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Signature verification failed' }));
    }
    const pkHash = crypto.createHash('sha3-256').update(pkBytes).digest('hex');
    const existing = relayRegistry.get(pkHash);
    const verified_since = existing?.verified_since || new Date().toISOString();
    const ctEntry = ctAppendRelayReg(rUrl, rSector, rVersion, rEdition || 'community', pkHash);
    // Fix 7: evict oldest entry when registry is at capacity
    if (!existing && relayRegistry.size >= MAX_RELAY_REGISTRY) {
      const oldestKey = relayRegistry.keys().next().value;
      relayRegistry.delete(oldestKey);
      log('warn', 'relay_registry_evict', { evicted: oldestKey?.slice(0,16), size: relayRegistry.size });
    }
    relayRegistry.set(pkHash, {
      url: rUrl, sector: rSector, version: rVersion, edition: rEdition || 'community',
      pk_hash: pkHash, verified_since,
      last_seen: ctEntry.ts,
      ct_index: existing?.ct_index ?? ctEntry.index,
      last_ct_index: ctEntry.index
    });
    log('info', 'relay_registered', { url: rUrl, sector: rSector, pk_hash: pkHash.slice(0,16)+'…', ct_index: ctEntry.index });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, pk_hash: pkHash, ct_index: ctEntry.index, verified_since }));
  }

  // ── GET /v2/relays — public registry of verified relay nodes ─────────────────
  if (path === '/v2/relays' && req.method === 'GET') {
    // Fix 7: paginate response to bound response size
    const limit  = Math.min(parseInt(query.limit  || '50')  || 50,  200);
    const offset = Math.max(parseInt(query.offset || '0')   || 0,   0);
    const all = [...relayRegistry.values()];
    const page = all.slice(offset, offset + limit).map(r => ({
      url: r.url, sector: r.sector, version: r.version, edition: r.edition,
      pk_hash: r.pk_hash, verified_since: r.verified_since, last_seen: r.last_seen,
      ct_index: r.ct_index, last_ct_index: r.last_ct_index
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, relays: page, total: relayRegistry.size, limit, offset }));
  }

  // ── POST /v2/sth/ingest — receive gossip STH from a peer relay ────────────────
  if (path === '/v2/sth/ingest' && req.method === 'POST') {
    if (!mlDsa) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'ML-DSA-65 not available — STH ingestion disabled' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 65536)).toString()); } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid JSON body' }));
    }
    const { relay_id, sha3_root, timestamp, tree_size, version, signature, public_key, relay_pk_hash } = body || {};
    if (!relay_id || sha3_root == null || timestamp == null || tree_size == null || !signature || !public_key) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Missing required fields: relay_id, sha3_root, timestamp, tree_size, signature, public_key' }));
    }
    let pkBytes, sigBytes;
    try { pkBytes = Buffer.from(public_key, 'base64'); sigBytes = Buffer.from(signature, 'base64'); } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid base64 in public_key or signature' }));
    }
    const computedPkHash = crypto.createHash('sha3-256').update(pkBytes).digest('hex');
    if (relay_pk_hash && computedPkHash !== relay_pk_hash) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'public_key does not match relay_pk_hash' }));
    }
    // Verify ML-DSA-65 signature over canonical payload (same as produceSth)
    const payload = { relay_id, sha3_root, timestamp, tree_size, version: version || 1 };
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]])));
    let verified = false;
    try { verified = mlDsa.verify(sigBytes, Buffer.from(canonical, 'utf8'), pkBytes); } catch {}
    if (!verified) {
      log('warn', 'sth_ingest_bad_sig', { relay_id: String(relay_id).slice(0, 32), pk_hash: computedPkHash.slice(0, 16) });
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Signature verification failed' }));
    }
    if (!peerSths.has(computedPkHash)) peerSths.set(computedPkHash, { sths: [], pk_b64: public_key });
    const peer = peerSths.get(computedPkHash);
    peer.pk_b64 = public_key;
    const record = { relay_id, relay_pk_hash: computedPkHash, sha3_root, timestamp, tree_size,
                     version: version || 1, signature, public_key, received_at: new Date().toISOString() };
    peer.sths.push(record);
    if (peer.sths.length > PEER_STH_MAX) peer.sths.shift();
    _peerSthWrite(computedPkHash, record);
    log('info', 'sth_ingested', { relay_id: String(relay_id).slice(0, 32), tree_size, root: String(sha3_root).slice(0, 16) });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, relay_pk_hash: computedPkHash }));
  }

  // ── GET /v2/sth/peers — list peer relays and their latest mirrored STH root ───
  if (path === '/v2/sth/peers' && req.method === 'GET') {
    const result = [];
    for (const [pkHash, peer] of peerSths) {
      const latest = peer.sths.length > 0 ? peer.sths[peer.sths.length - 1] : null;
      result.push({
        relay_pk_hash: pkHash,
        relay_id: latest?.relay_id || null,
        sth_count: peer.sths.length,
        latest_root: latest?.sha3_root || null,
        latest_tree_size: latest?.tree_size ?? null,
        latest_ts: latest?.received_at || null,
      });
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, peers: result, count: result.length }));
  }

  // ── GET /v2/sth/peers/:id — full STH history mirrored from a specific peer ────
  const sthPeerMatch = path.match(/^\/v2\/sth\/peers\/([a-f0-9]{1,64})$/);
  if (sthPeerMatch && req.method === 'GET') {
    const peer = peerSths.get(sthPeerMatch[1]);
    if (!peer) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Peer not found', relay_pk_hash: sthPeerMatch[1] }));
    }
    const lim = Math.min(parseInt(query.limit || '100') || 100, 500);
    const off  = Math.max(parseInt(query.offset || '0') || 0, 0);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, relay_pk_hash: sthPeerMatch[1],
                       sths: peer.sths.slice(off, off + lim), total: peer.sths.length, limit: lim, offset: off }));
  }

  // ── GET /v2/sth/consistency — RFC 6962 consistency proof ──────────────────────
  if (path === '/v2/sth/consistency' && req.method === 'GET') {
    const fromSize = parseInt(query.from);
    const toSize   = query.to !== undefined ? parseInt(query.to) : ctLog.length;
    if (isNaN(fromSize) || isNaN(toSize)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Query params required: from=<integer> (and optionally to=<integer>)' }));
    }
    if (fromSize < 0 || toSize < fromSize || toSize > ctLog.length) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: `Invalid range: 0 ≤ from (${fromSize}) ≤ to (${toSize}) ≤ log size (${ctLog.length})` }));
    }
    const proof = ctConsistencyProof(fromSize, toSize);
    if (proof === null) { res.writeHead(500); return res.end(J({ error: 'Could not compute proof' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, from: fromSize, to: toSize, proof }));
  }

  // ── GET /ct/feed.xml — RSS feed of signed tree heads for external archiving ───
  if (path === '/ct/feed.xml' && req.method === 'GET') {
    const selfUrl = RELAY_SELF_URL || `http://${SECTOR}.paramant.app`;
    const items = sthLog.slice(-20).map(s => {
      const d = new Date(typeof s.timestamp === 'number' ? s.timestamp : Date.parse(s.timestamp));
      const desc = `tree_size=${s.tree_size} root=${s.sha3_root} relay=${s.relay_id} sig=${String(s.signature).slice(0, 24)}…`;
      const esc = t => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `    <item>
      <title>STH #${s.tree_size} — ${String(s.sha3_root).slice(0, 8)}…</title>
      <pubDate>${d.toUTCString()}</pubDate>
      <description>${esc(desc)}</description>
      <guid isPermaLink="true">${selfUrl}/v2/sth?ts=${d.getTime()}</guid>
    </item>`;
    }).join('\n');
    const feed = `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0">\n  <channel>\n    <title>Paramant CT Log — ${selfUrl}</title>\n    <link>${selfUrl}/ct/feed.xml</link>\n    <description>Signed Tree Heads for independent CT log verification. Subscribe to independently archive roots.</description>\n    <language>en</language>\n    <ttl>10</ttl>\n${items}\n  </channel>\n</rss>`;
    res.writeHead(200, { 'Content-Type': 'application/rss+xml; charset=UTF-8', 'Cache-Control': 'public, max-age=60' });
    return res.end(feed);
  }

  // ── GET /v2/did/:did — publiek DID document resolven ─────────────────────────
  const didm0 = path.match(/^\/v2\/did\/([^/]+)$/);
  if (didm0 && req.method === 'GET') {
    let _didParam;
    try { _didParam = decodeURIComponent(didm0[1]); }
    catch { res.writeHead(400); return res.end(J({ error: 'Invalid percent-encoding in path' })); }
    const entry = didRegistry.get(_didParam);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'DID not found' })); }
    res.writeHead(200, { 'Content-Type': 'application/did+json' });
    return res.end(J(entry.doc));
  }

  // ── GET /v2/dl/:token — two-step: HTML confirm page (safe for link preloaders)
  const dlm = path.match(/^\/v2\/dl\/([a-f0-9]{48})$/);
  if (dlm && req.method === 'GET') {
    const token = dlm[1];
    const ua = req.headers['user-agent'] || '';
    // Known preload bots get a safe placeholder — never trigger burn
    if (PRELOAD_BOTS.test(ua)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>PARAMANT — Secure File</title>
<meta name="description" content="A secure encrypted file is waiting for you.">
<meta property="og:title" content="PARAMANT — Secure File Transfer">
<meta property="og:description" content="End-to-end encrypted · Burns after reading · ML-KEM-768">
</head><body>Open this link in your browser to download the secure file.</body></html>`);
    }
    const td = downloadTokens.get(token);
    if (!td || td.used) {
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage(td?.used ? 'This file has already been downloaded and burned' : 'Link not found or already used'));
    }
    if (Date.now() > td.expires_ms) {
      downloadTokens.delete(token);
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('Link expired'));
    }
    const ttl_left = Math.round((td.expires_ms - Date.now()) / 1000);
    const ttlStr = ttl_left > 3600 ? `${Math.round(ttl_left/3600)}h` : ttl_left > 60 ? `${Math.round(ttl_left/60)}m` : `${ttl_left}s`;
    const sizeStr = td.file_size ? (td.file_size > 1048576 ? `${(td.file_size/1048576).toFixed(1)} MB` : td.file_size > 1024 ? `${(td.file_size/1024).toFixed(1)} KB` : `${td.file_size} B`) : 'Unknown';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(_dlConfirmPage(token, td.enc_meta || null, sizeStr, ttlStr));
  }

  // ── GET /v2/dl/:token/get — actual burn + download (human must click confirm)
  const dlgm = path.match(/^\/v2\/dl\/([a-f0-9]{48})\/get$/);
  if (dlgm && req.method === 'GET') {
    const token = dlgm[1];
    const ua = req.headers['user-agent'] || '';
    if (PRELOAD_BOTS.test(ua)) {
      res.writeHead(403); return res.end(J({ error: 'Automated clients not permitted' }));
    }
    const td = downloadTokens.get(token);
    if (!td) {
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('Link not found or already used'));
    }
    if (td.used) {
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('This file has already been downloaded and burned'));
    }
    if (Date.now() > td.expires_ms) {
      downloadTokens.delete(token);
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('Link expired'));
    }
    const entry = blobStore.get(td.hash);
    if (!entry) {
      downloadTokens.delete(token);
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('File not found — already burned'));
    }
    // Fix 4: block concurrent downloads before transfer starts
    if (td.in_progress) {
      res.writeHead(409, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(_dlBurnedPage('Download already in progress'));
    }
    td.in_progress = true;
    const blobHash = td.hash;
    const blob = entry.blob;
    log('info', 'dl_token_used', { token: token.slice(0,8), hash: blobHash.slice(0,16) });
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      // Relay never stores plaintext filename (finding #4) — receiver SDK decrypts enc_meta to recover name
      'Content-Disposition': 'attachment; filename="paramant-encrypted-payload"',
      'Cache-Control': 'no-store',
      'X-Burned': 'true',
      'X-Hash': blobHash,
    });
    // Fix 4: only burn blob after response has fully flushed to the client
    res.on('finish', () => {
      td.used = true;
      blobStore.delete(blobHash);
      try { blob.fill(0); } catch {}
    });
    // Fix 4: on socket error before finish, allow retry
    res.on('close', () => {
      if (!td.used) {
        td.in_progress = false;
        log('warn', 'dl_aborted_before_finish', { token: token.slice(0,8), hash: blobHash.slice(0,16) });
      }
    });
    return res.end(blob);
  }

  // ── GET /v2/dl/:token/info — check token zonder te branden ──────────────
  const dlim = path.match(/^\/v2\/dl\/([a-f0-9]{48})\/info$/);
  if (dlim && req.method === 'GET') {
    const token = dlim[1];
    const td = downloadTokens.get(token);
    if (!td || td.used || Date.now() > td.expires_ms) {
      res.writeHead(404); return res.end(J({ ok: false, error: 'Link not found, used, or expired' }));
    }
    const ttl_left = Math.round((td.expires_ms - Date.now()) / 1000);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, enc_meta: td.enc_meta || null, file_size: td.file_size, ttl_left_s: ttl_left, used: false }));
  }

  // ── POST /v2/session/join — Receiver bewijst kennis van PSS + bindt pubkeys ─
  // Geen API key nodig — PSS is de authenticatie
  // Relay verifieert: SHA-256(pss) == commitment  (relay kan dit NIET vervalsen)
  // Na join: pubkeys gebonden aan sessie, niet overschrijfbaar
  if (path === '/v2/session/join' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.session_id || !d.pss || !d.ecdh_pub) {
        res.writeHead(400);
        return res.end(J({ error: 'session_id, pss, and ecdh_pub required' }));
      }
      const sess = sessions.get(d.session_id);
      if (!sess)                    { res.writeHead(404); return res.end(J({ error: 'Session not found or expired' })); }
      if (Date.now() > sess.expires_ms) {
        sessions.delete(d.session_id);
        res.writeHead(410); return res.end(J({ error: 'Session expired' }));
      }
      if (sess.joined)              { res.writeHead(409); return res.end(J({ error: 'Session already joined — first join wins' })); }

      // Verifieer PSS commitment: SHA-256(pss) moet overeenkomen
      const pssHash = crypto.createHash('sha3-256').update(d.pss).digest('hex');
      if (pssHash !== sess.commitment) {
        log('warn', 'session_join_bad_pss', { sid: d.session_id.slice(0, 12) });
        res.writeHead(403); return res.end(J({ error: 'Pre-shared secret does not match commitment' }));
      }

      // PSS verified — bind pubkeys (first-join-wins, onveranderbaar)
      sess.joined    = true;
      sess.ecdh_pub  = d.ecdh_pub;
      sess.kyber_pub = d.kyber_pub || '';
      sess.joined_at = new Date().toISOString();

      log('info', 'session_joined', { sid: d.session_id.slice(0, 12), kyber: !!d.kyber_pub });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, session_id: d.session_id, joined_at: sess.joined_at }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/reload-users — Zero-downtime API key reload ─────────────────
  if (path === '/v2/reload-users' && req.method === 'POST') {
    const tok = (req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ','')||'').trim();
    if (!tok || !safeEqual(tok, process.env.ADMIN_TOKEN || '')) {
      res.writeHead(401); return res.end(J({ error: 'unauthorized' }));
    }
    if (process.env.USERS_JSON) {
      res.writeHead(400); return res.end(J({ error: 'USERS_JSON env in gebruik — bestand reload niet van toepassing' }));
    }
    const prevCount = apiKeys.size;
    apiKeys.clear();
    loadUsers();

    applyKeyLimitEnforcement();
    log('info', 'reload_users', { prev: prevCount, now: apiKeys.size });
    res.writeHead(200); return res.end(J({ ok: true, loaded: apiKeys.size }));
  }

  // ── Ghost Pipe invite rendezvous — pubkey exchange without API key ───────────
  // inv_ session tokens bypass API key auth for pubkey endpoints only.
  // Public keys are not sensitive; security comes from fingerprint verification.
  const INVITE_RE = /^inv_[a-zA-Z0-9]{32}(_ready)?$/;

  // ── GET /v2/pubkey — relay's ML-DSA-65 identity public key (for STH verification) ─
  if (path === '/v2/pubkey' && req.method === 'GET') {
    if (!relayIdentity) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'ML-DSA-65 not available on this relay' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, alg: 'ML-DSA-65', public_key: relayIdentity.pk.toString('base64'), pk_hash: relayIdentity.pk_hash }));
  }

  // ── POST /v2/pubkey — Registreer pubkeys (ML-KEM + ECDH + ML-DSA optioneel) ─
  if (path === '/v2/pubkey' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({ error: 'device_id and ecdh_pub required' })); }
      // M3: reject oversized device_id to prevent memory exhaustion / map-key attacks
      if (typeof d.device_id !== 'string' || d.device_id.length > 256) { res.writeHead(400); return res.end(J({ error: 'device_id must be a string of at most 256 characters' })); }
      if (INVITE_RE.test(d.device_id)) {
        // Store without API key suffix — readable by any party who knows the session token
        const invFp = computeFingerprint(d.kyber_pub || '', d.ecdh_pub);
        pubkeys.set(d.device_id, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', fingerprint: invFp, ts: new Date().toISOString(), registered_at: new Date().toISOString(), expires: Date.now() + INVITE_PUBKEY_TTL });
        log('info', 'pubkey_registered_invite', { device: d.device_id.slice(0, 12), fp: invFp });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, fingerprint: invFp }));
      }
      // Non-invite: require valid API key
      if (!keyData?.active) { res.writeHead(401); return res.end(J({ error: 'Invalid API key' })); }
      const plan = keyData.plan || 'pro';
      // Per-plan total device limit
      const maxDevices = _pubkeyMax[plan] ?? _pubkeyMax.free;
      if (maxDevices !== Infinity) {
        const keyPrefix = `:${apiKey}`;
        let deviceCount = 0;
        for (const k of pubkeys.keys()) { if (k.endsWith(keyPrefix)) deviceCount++; }
        if (deviceCount >= maxDevices) {
          res.writeHead(429); return res.end(J({ error: `Device limit reached. Max ${maxDevices} devices on ${plan} plan.`, limit: maxDevices, plan }));
        }
      }
      const ttl = _pubkeyTtl[plan] ?? _pubkeyTtl.free;
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      const attestResult = verifyAttestation(d.ecdh_pub, d.device_id, d.attestation || null);
      const existingPubkey = pubkeys.get(`${d.device_id}:${apiKey}`);
      if (existingPubkey && (!existingPubkey.expires || Date.now() < existingPubkey.expires)) {
        res.writeHead(409); return res.end(J({ error: 'Pubkey already registered for this session — first registration wins' }));
      }
      const fp = computeFingerprint(d.kyber_pub || '', d.ecdh_pub);
      const regAt = new Date().toISOString();
      pubkeys.set(`${d.device_id}:${apiKey}`, {
        ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '',
        dsa_pub:  d.dsa_pub  || '',
        fingerprint: fp, ct_index: ctEntry.index,
        ts: regAt, registered_at: regAt,
        expires: Date.now() + ttl,
      });
      log('info', 'pubkey_registered', { device: d.device_id, kyber: !!d.kyber_pub, dsa: !!d.dsa_pub, plan, ttl_days: Math.round(ttl/86400000), fp });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, fingerprint: fp, dsa_supported: !!mlDsa, ct_index: ctEntry.index, ct_tree_hash: ctEntry.tree_hash, attested: attestResult.valid, attestation_method: attestResult.method || null }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/pubkey/:device ───────────────────────────────────────────────────
  const pkm = path.match(/^\/v2\/pubkey\/([^/]+)$/);
  if (pkm && req.method === 'GET') {
    let deviceId;
    try { deviceId = decodeURIComponent(pkm[1]); }
    catch { res.writeHead(400); return res.end(J({ error: 'Invalid percent-encoding in path' })); }
    // Invite sessions: stored and retrieved without API key
    const _pkKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${apiKey}`;
    const entry = pubkeys.get(_pkKey);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'No pubkeys for this device. Start receiver first.' })); }
    if (entry.expires && Date.now() > entry.expires) {
      pubkeys.delete(_pkKey);
      res.writeHead(404); return res.end(J({ error: 'Pubkey registration expired. Re-register the device.' }));
    }
    // Compute fingerprint on the fly if not stored (backcompat with pre-fingerprint entries)
    const fp = entry.fingerprint || computeFingerprint(entry.kyber_pub || '', entry.ecdh_pub);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, ecdh_pub: entry.ecdh_pub, kyber_pub: entry.kyber_pub, dsa_pub: entry.dsa_pub || '', ts: entry.ts, fingerprint: fp, registered_at: entry.registered_at || entry.ts, ct_index: entry.ct_index ?? null }));
  }

  // ── GET /v2/fingerprint/:device — Return just the fingerprint for out-of-band verification
  const fpm = path.match(/^\/v2\/fingerprint\/([^/]+)$/);
  if (fpm && req.method === 'GET') {
    let deviceId;
    try { deviceId = decodeURIComponent(fpm[1]); }
    catch { res.writeHead(400); return res.end(J({ error: 'Invalid percent-encoding in path' })); }
    const _fKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${apiKey}`;
    const entry = pubkeys.get(_fKey);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'No pubkeys for this device.' })); }
    if (entry.expires && Date.now() > entry.expires) {
      pubkeys.delete(_fKey);
      res.writeHead(404); return res.end(J({ error: 'Pubkey registration expired.' }));
    }
    const fp = entry.fingerprint || computeFingerprint(entry.kyber_pub || '', entry.ecdh_pub);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, device_id: deviceId, fingerprint: fp, registered_at: entry.registered_at || entry.ts, ct_index: entry.ct_index ?? null }));
  }

  // ── POST /v2/pubkey/verify — Verify a fingerprint matches stored pubkey ───────
  if (path === '/v2/pubkey/verify' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.device_id || !d.fingerprint) { res.writeHead(400); return res.end(J({ error: 'device_id and fingerprint required' })); }
      const _vKey = INVITE_RE.test(d.device_id) ? d.device_id : `${d.device_id}:${apiKey}`;
      const entry = pubkeys.get(_vKey);
      if (!entry) { res.writeHead(404); return res.end(J({ error: 'No pubkeys for this device.' })); }
      const storedFp = entry.fingerprint || computeFingerprint(entry.kyber_pub || '', entry.ecdh_pub);
      const match = storedFp.toUpperCase() === d.fingerprint.toUpperCase().replace(/[^A-F0-9]/g,'').replace(/(.{4})/g,'$1-').slice(0,-1);
      // Normalised comparison: strip dashes, uppercase
      const normStored  = storedFp.replace(/-/g,'').toUpperCase();
      const normProvided = d.fingerprint.replace(/-/g,'').toUpperCase();
      const verified = normStored === normProvided;
      res.writeHead(verified ? 200 : 409, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: verified, match: verified, stored: storedFp, provided: d.fingerprint, registered_at: entry.registered_at || entry.ts }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/anon-inbound — Keyless upload for magic-link flow ───────────────
  // No API key required. Rate limited by IP. Sender encrypts AES-256-GCM client-side;
  // the decryption key travels in the URL fragment only — relay never sees it.
  if (path === '/v2/anon-inbound' && req.method === 'POST') {
    const ANON_MAX = 5 * 1024 * 1024;
    const ANON_RPH = parseInt(process.env.ANON_RATE_PER_HOUR || '10');
    const HOUR_MS  = 3_600_000;
    const ip       = getClientIp(req);
    const now      = Date.now();
    const ipTimes  = (anonInboundIpRequests.get(ip) || []).filter(t => now - t < HOUR_MS);
    if (ipTimes.length >= ANON_RPH) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' });
      return res.end(J({ error: 'Rate limit: max ' + ANON_RPH + ' uploads per hour. Try again later.' }));
    }
    if (!ramOk()) {
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '10' });
      return res.end(J({ error: 'Relay at capacity. Retry in 10 seconds.' }));
    }
    inFlightInbound++;
    try {
      const body = await readBody(req, ANON_MAX * 2);
      const d    = JSON.parse(body.toString());
      const { hash, payload, ttl_ms, enc_meta } = d;
      if (!hash || !payload)            { res.writeHead(400); return res.end(J({ error: 'hash and payload required' })); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({ error: 'hash must be SHA-256 hex' })); }
      if (blobStore.has(hash))           { res.writeHead(409); return res.end(J({ error: 'Hash already in use' })); }
      const blob = Buffer.from(payload, 'base64');
      if (blob.length > ANON_MAX)        { res.writeHead(413); return res.end(J({ error: 'Max 5MB on anonymous uploads' })); }
      let safeEncMeta = null;
      if (enc_meta !== undefined && enc_meta !== null) {
        const em = String(enc_meta);
        if (em.length > 2048 || !/^[A-Za-z0-9+/=]+$/.test(em)) { res.writeHead(400); return res.end(J({ error: 'enc_meta must be base64, max 2048 chars' })); }
        safeEncMeta = em;
      }
      const ttl     = Math.min(parseInt(ttl_ms || TTL_MS), 86_400_000); // max 24h for anon
      const ctEntry = ctAppendTransfer(hash, SECTOR);
      blobStore.set(hash, {
        blob, ts: now, ttl, size: blob.length,
        apiKey: null, max_views: 1, views_remaining: 1, sector: SECTOR,
        ct_entry: { index: ctEntry.index, leaf_hash: ctEntry.leaf_hash, tree_hash: ctEntry.tree_hash,
                    tree_size: ctEntry.index + 1, audit_path: ctEntry.proof, sth: ctEntry.sth || null },
      });
      setTimeout(() => { const e = blobStore.get(hash); if (e) { zeroBuffer(e.blob); blobStore.delete(hash); } }, ttl);
      ipTimes.push(now);
      anonInboundIpRequests.set(ip, ipTimes);
      const dlToken = require('crypto').randomBytes(24).toString('hex');
      downloadTokens.set(dlToken, { hash, key: null, expires_ms: now + ttl, used: false, enc_meta: safeEncMeta, file_size: blob.length });
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      log('info', 'anon_blob_stored', { hash: hash.slice(0, 16), size: blob.length });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash, download_token: dlToken, ttl_ms: ttl, size: blob.length }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
    finally { inFlightInbound--; }
  }

  // Admin paths: ONLY ADMIN_TOKEN is accepted — no enterprise keys, no pgp_ keys
  // All other paths: require a valid X-Api-Key (pgp_ key in users.json)
  const isAdminPath = path.startsWith('/v2/admin');
  if (isAdminPath) {
    const adminHeader = (req.headers['x-admin-token'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '') || '').trim();
    const validAdmin = !!adminHeader && !!process.env.ADMIN_TOKEN && safeEqual(adminHeader, process.env.ADMIN_TOKEN);
    if (!validAdmin) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'ADMIN_TOKEN required for admin endpoints' }));
    }
    // Fall through to admin endpoint handlers below
  } else if (!keyData?.active) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
  }

  // ── POST /v2/session/create — Sender maakt PSS-gebonden sessie ─────────────
  // Vereist: geldige API key, commitment = SHA-256(pss) als hex
  // Geeft: session_id (pss_<32hex>), expires_ms
  // Relay ziet alleen de hash — kan PSS niet reconstrueren
  if (path === '/v2/session/create' && req.method === 'POST') {
    if (!keyData) { res.writeHead(401); return res.end(J({ error: 'Valid API key required' })); }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.commitment || !/^[a-f0-9]{64}$/.test(d.commitment)) {
        res.writeHead(400);
        return res.end(J({ error: 'commitment must be SHA-256 hex (64 chars) of your pre-shared secret' }));
      }
      const ttl  = Math.min(Math.max(parseInt(d.ttl_ms) || 600000, 60000), 3600000); // 1min–1h, default 10min
      const sid  = 'pss_' + crypto.randomBytes(24).toString('hex');
      sessions.set(sid, {
        commitment:  d.commitment,
        api_key:     apiKey,
        expires_ms:  Date.now() + ttl,
        joined:      false,
        ecdh_pub:    null,
        kyber_pub:   null,
        joined_at:   null,
      });
      log('info', 'session_created', { sid: sid.slice(0, 12), ttl });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, session_id: sid, expires_ms: Date.now() + ttl, ttl_ms: ttl }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/session/:id/pubkey — Sender haalt PSS-gebonden pubkeys op ───────
  // Vereist: geldige API key die de sessie aangemaakt heeft
  // Geeft: ecdh_pub + kyber_pub van receiver — alleen na succesvolle join
  // Relay KAN NIET vervalsen: pubkeys zijn gebonden aan PSS-verificatie
  const sessPkm = path.match(/^\/v2\/session\/(pss_[a-f0-9]{48})\/pubkey$/);
  if (sessPkm && req.method === 'GET') {
    if (!keyData) { res.writeHead(401); return res.end(J({ error: 'Valid API key required' })); }
    const sess = sessions.get(sessPkm[1]);
    if (!sess)               { res.writeHead(404); return res.end(J({ error: 'Session not found or expired' })); }
    if (sess.api_key !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Session belongs to a different API key' })); }
    if (!sess.joined)        { res.writeHead(202); return res.end(J({ ok: false, joined: false, message: 'Receiver has not joined yet — poll again' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true, joined: true,
      ecdh_pub:  sess.ecdh_pub,
      kyber_pub: sess.kyber_pub,
      joined_at: sess.joined_at,
      expires_ms: sess.expires_ms,
    }));
  }

  // ── GET /v2/session/:id/status — Poll of receiver al gejoind is ─────────────
  const sessSm = path.match(/^\/v2\/session\/(pss_[a-f0-9]{48})\/status$/);
  if (sessSm && req.method === 'GET') {
    if (!keyData) { res.writeHead(401); return res.end(J({ error: 'Valid API key required' })); }
    const sess = sessions.get(sessSm[1]);
    if (!sess)               { res.writeHead(404); return res.end(J({ error: 'Session not found or expired' })); }
    if (sess.api_key !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Session belongs to a different API key' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, joined: sess.joined, expires_ms: sess.expires_ms }));
  }

  // ── POST /v2/inbound — Upload versleuteld blok + optioneel ML-DSA handtekening
  if (path === '/v2/inbound' && req.method === 'POST') {
    if (!ramOk()) {
      const r = ramStatus();
      res.writeHead(503, {
        'Content-Type': 'application/json',
        'Retry-After': '10',
        'X-Ram-Slots': String(r.available_slots),
      });
      log('warn', 'inbound_rejected_ram', r);
      return res.end(J({
        ok: false,
        error: 'Relay at capacity. Retry in 10 seconds.',
        retry_after_s: 10,
        slots_available: r.available_slots,
        blobs_in_flight: r.blobs_in_flight,
      }));
    }
    inFlightInbound++;
    try {
      const body = await readBody(req);
      const d    = JSON.parse(body.toString());
      const { hash, payload, ttl_ms, meta, dsa_signature, max_views: reqMaxViews, password, enc_meta } = d;

      if (!hash || !payload) { res.writeHead(400); return res.end(J({ error: 'hash and payload required' })); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({ error: 'hash must be SHA-256 hex' })); }
      if (blobStore.has(hash)) { res.writeHead(409); return res.end(J({ error: 'Hash already in use' })); }

      // Trial key enforcement
      if (keyData?.is_trial) {
        const TRIAL_MAX_SIZE = 5 * 1024 * 1024;
        const TRIAL_MAX_TTL  = 3_600_000; // 1h
        const TRIAL_EXPIRY   = 30 * 86_400_000;
        const TRIAL_DAILY    = 10;
        const OT_TRIAL_MAX   = 1000; // OT eval: 1000 transfers total, no daily cap
        if (keyData.trial_created && Date.now() - keyData.trial_created > TRIAL_EXPIRY) {
          apiKeys.delete(apiKey);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'Trial key expired' }));
        }
        if (RELAY_MODE === 'iot') {
          // OT evaluation mode: total budget instead of daily cap
          if ((keyData.total_transfers || 0) >= OT_TRIAL_MAX) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            return res.end(J({ error: 'OT trial limit reached (1000 transfers). Contact us to upgrade.' }));
          }
          keyData.total_transfers = (keyData.total_transfers || 0) + 1;
        } else {
          const today = new Date().toDateString();
          if (keyData.last_upload_day !== today) { keyData.uploads_today = 0; keyData.last_upload_day = today; }
          if (keyData.uploads_today >= TRIAL_DAILY) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            return res.end(J({ error: 'Daily upload limit reached (trial: 10/day)' }));
          }
          keyData.uploads_today++;
        }
        const blobPreview = Buffer.byteLength(payload, 'base64');
        if (blobPreview > TRIAL_MAX_SIZE) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'Max 5MB on trial' }));
        }
        if (ttl_ms && parseInt(ttl_ms) > TRIAL_MAX_TTL) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'Max TTL 1h on trial' }));
        }
      }

      // enc_meta: sender-encrypted filename/metadata (relay stores ciphertext only — finding #4)
      // Max 2048 bytes base64; relay never decrypts it.
      let safeEncMeta = null;
      if (enc_meta !== undefined && enc_meta !== null) {
        const em = String(enc_meta);
        if (em.length > 2048) { res.writeHead(400); return res.end(J({ error: 'enc_meta too large (max 2048 chars)' })); }
        if (!/^[A-Za-z0-9+/=]+$/.test(em)) { res.writeHead(400); return res.end(J({ error: 'enc_meta must be base64' })); }
        safeEncMeta = em;
      }

      const blob = Buffer.from(payload, 'base64');
      const planMaxSize = MAX_BLOB;
      if (blob.length > planMaxSize) { res.writeHead(413); return res.end(J({ error: `Max ${Math.round(planMaxSize/1048576)}MB` })); }

      // ML-DSA handtekening verificatie (optioneel maar gelogd)
      let sigResult = { valid: false, reason: 'not provided' };
      if (dsa_signature && keyData.dsa_pub) {
        sigResult = verifyDsaSignature(hash, dsa_signature, keyData.dsa_pub);
      }

      const _planMaxTtl = { dev: 3_600_000, pro: 86_400_000, enterprise: 604_800_000 };
      const _plan = keyData?.plan || 'dev';
      const _maxTtl = _planMaxTtl[_plan] || _planMaxTtl.dev;
      const ttl = Math.min(parseInt(ttl_ms || TTL_MS), _maxTtl);
      // Access policies: max_views (default 1 = burn-on-read) + Argon2id password
      const _planMaxViews = { free: 1, pro: 10, enterprise: 100 };
      const maxViews = Math.max(1, Math.min(parseInt(reqMaxViews || 1) || 1, _planMaxViews[keyData?.plan || 'pro'] || 1));
      let pw_hash = null;
      if (password) {
        if (!argon2Lib) { res.writeHead(501); return res.end(J({ error: 'Argon2id not available on this relay' })); }
        pw_hash = await argon2Lib.hash(password, { type: argon2Lib.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
      }
      // Append transfer to CT log before storing — so proof is available at outbound time
      const ctEntry = ctAppendTransfer(hash, SECTOR);
      blobStore.set(hash, { blob, ts: Date.now(), ttl, size: blob.length,
        sig_valid: sigResult.valid, apiKey, max_views: maxViews, views_remaining: maxViews, pw_hash,
        sector: SECTOR,
        ct_entry: {
          index:     ctEntry.index,
          leaf_hash: ctEntry.leaf_hash,
          tree_hash: ctEntry.tree_hash,
          tree_size: ctEntry.index + 1,
          audit_path: ctEntry.proof,
          sth:       ctEntry.sth || null,
        }
      });
      setTimeout(() => {
        const e = blobStore.get(hash);
        if (e) { zeroBuffer(e.blob); blobStore.delete(hash); }
      }, ttl);

      const deviceId = meta?.device_id;
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      auditAppend(apiKey, 'inbound', { hash: hash.slice(0,16)+'...', bytes: blob.length, device: deviceId, sig: sigResult.valid ? 'ML-DSA-OK' : 'unsigned' });
      log('info', 'blob_stored', { hash: hash.slice(0,16), size: blob.length, sig: sigResult.valid });

      if (deviceId) {
        pushWebhooks(apiKey, deviceId, 'blob_ready', { hash, size: blob.length, ttl_ms: ttl, sig_valid: sigResult.valid });
        // Fix B: push real hash to recipient device queue for stream-next
        deviceQueuePush(apiKey, deviceId, hash);
      }
      if (global.wsPush) global.wsPush(apiKey, { hash, size: blob.length, device: deviceId, sig_valid: sigResult.valid });
      natsPush(apiKey, deviceId || 'unknown', hash, blob.length);

      // Genereer one-time download token
      const dlToken = require('crypto').randomBytes(24).toString('hex');
      downloadTokens.set(dlToken, {
        hash,
        key: apiKey,
        expires_ms: Date.now() + ttl,
        used: false,
        enc_meta: safeEncMeta,  // encrypted filename/metadata (ciphertext only) — finding #4 closed
        file_size: blob.length,
      });
      const merkleProof = {
        leaf_hash:  ctEntry.leaf_hash,
        leaf_index: ctEntry.index,
        tree_size:  ctEntry.index + 1,
        audit_path: ctEntry.proof,
        root:       ctEntry.tree_hash,
        sth:        ctEntry.sth || null,
        sth_signature: ctEntry.sth ? ctEntry.sth.signature : null,
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash, ttl_ms: ttl, size: blob.length, sig_verified: sigResult.valid, download_token: dlToken, merkle_proof: merkleProof }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
    finally { inFlightInbound--; }
  }

  // ── DELETE /v2/inbound/:hash — Caller-initiated abort (orphan cleanup) ────────
  const delm = path.match(/^\/v2\/inbound\/([a-f0-9]{64})$/);
  if (delm && req.method === 'DELETE') {
    const entry = blobStore.get(delm[1]);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Not found' })); }
    if (entry.apiKey && entry.apiKey !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Forbidden' })); }
    zeroBuffer(entry.blob);
    blobStore.delete(delm[1]);
    // Remove associated download token if present
    for (const [t, d] of downloadTokens.entries()) { if (d.hash === delm[1]) { downloadTokens.delete(t); break; } }
    auditAppend(apiKey, 'inbound_aborted', { hash: delm[1].slice(0,16)+'...' });
    log('info', 'blob_aborted', { hash: delm[1].slice(0,16) });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true }));
  }

  // ── GET /v2/outbound/:hash — Burn-on-read ────────────────────────────────────
  const outm = path.match(/^\/v2\/outbound\/([a-f0-9]{64})$/);
  if (outm && req.method === 'GET') {
    const entry = blobStore.get(outm[1]);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Not found. Expired, burned, or never stored.' })); }
    if (entry.apiKey && entry.apiKey !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Forbidden' })); }
    // Per-key outbound rate limit (finding #12)
    if (!outboundRateOk(apiKey, keyData?.plan)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Outbound rate limit exceeded. Retry after the hourly window resets.' }));
    }
    // Argon2id password verification (if set)
    if (entry.pw_hash) {
      const reqPw = (req.headers['x-blob-password'] || '').trim();
      if (!reqPw) { res.writeHead(401, { 'WWW-Authenticate': 'X-Blob-Password' }); return res.end(J({ error: 'Password required (X-Blob-Password header)' })); }
      if (!argon2Lib) { res.writeHead(503); return res.end(J({ error: 'Argon2id not available' })); }
      // Guard against Argon2 async race: two concurrent requests could both
      // read the same entry before the first one deletes it (pentest #1)
      if (entry._verifying) { res.writeHead(429); return res.end(J({ error: 'Already being retrieved' })); }
      entry._verifying = true;
      let pwOk = false;
      try {
        pwOk = await argon2Lib.verify(entry.pw_hash, reqPw);
        // Keep _verifying = true through views decrement so a second concurrent
        // request cannot slip in after verify() resolves but before burn/decrement.
        // Reset only after the decision is made (below).
      } catch(e) {
        entry._verifying = false;
        res.writeHead(500); return res.end(J({ error: 'Password verification failed' }));
      }
      if (!pwOk) { entry._verifying = false; res.writeHead(403); return res.end(J({ error: 'Incorrect password' })); }
    }
    // Access policies: max_views — decrement, burn wanneer 0
    entry.views_remaining = (entry.views_remaining ?? 1) - 1;
    const burned = entry.views_remaining <= 0;
    const blob = entry.blob;
    if (entry.pw_hash) entry._verifying = false; // release lock now that decision is finalized
    if (burned) {
      blobStore.delete(outm[1]);
      incMetric('blobs_burned'); stats.burned++;
    }
    incMetric('bytes_out_total', blob.length);
    stats.outbound++; stats.bytes_out += blob.length;
    auditAppend(apiKey, burned ? 'outbound_burn' : 'outbound_view',
      { hash: outm[1].slice(0,16)+'...', bytes: blob.length, views_left: entry.views_remaining });
    log('info', burned ? 'blob_burned' : 'blob_served',
      { hash: outm[1].slice(0,16), views_left: entry.views_remaining });

    // ── Build signed delivery receipt ────────────────────────────────────────
    let receiptHeader = null;
    const ctData = entry.ct_entry || null;
    if (ctData) {
      const inclusionProof = {
        leaf_hash:     ctData.leaf_hash,
        leaf_index:    ctData.index,
        tree_size:     ctData.tree_size,
        audit_path:    ctData.audit_path,
        root:          ctData.tree_hash,
        sth:           ctData.sth || null,
        sth_signature: ctData.sth ? ctData.sth.signature : null,
      };
      const receiptPayload = {
        blob_hash:              outm[1],
        retrieved_at:           Date.now(),
        sector:                 entry.sector || SECTOR,
        relay_id:               RELAY_SELF_URL || (SECTOR + '.paramant.app'),
        tree_size_at_retrieval: ctLog.length,
        inclusion_proof:        inclusionProof,
        burn_confirmed:         burned,
      };
      let signature = null;
      if (mlDsa && relayIdentity) {
        try {
          const canonical = canonicalJSON(receiptPayload);
          signature = Buffer.from(mlDsa.sign(Buffer.from(canonical, 'utf8'), relayIdentity.sk)).toString('base64');
        } catch(e) { log('warn', 'receipt_sign_failed', { err: e.message }); }
      }
      const receipt = { ...receiptPayload, signature };
      receiptHeader = Buffer.from(JSON.stringify(receipt)).toString('base64url');
    }

    const outHeaders = {
      'Content-Type':       'application/octet-stream',
      'Content-Length':     blob.length,
      'X-Paramant-Burned':  burned ? 'true' : 'false',
      'X-Paramant-Hash':    outm[1],
    };
    if (receiptHeader) outHeaders['X-Paramant-Receipt'] = receiptHeader;
    res.writeHead(200, outHeaders);
    if (burned) return res.end(blob, () => { try { blob.fill(0); } catch {} });
    return res.end(blob);
  }

  // ── GET /v2/status/:hash ─────────────────────────────────────────────────────
  const stm = path.match(/^\/v2\/status\/([a-f0-9]{64})$/);
  if (stm && req.method === 'GET') {
    const e = blobStore.get(stm[1]);
    if (!e) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(J({ available: false })); }
    if (e.apiKey && e.apiKey !== apiKey) { res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Forbidden' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ available: true, bytes: e.size, ttl_remaining_ms: Math.max(0, e.ttl - (Date.now() - e.ts)), sig_valid: e.sig_valid }));
  }

  // ── POST /v2/webhook ─────────────────────────────────────────────────────────
  if (path === '/v2/webhook' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.device_id || !d.url) { res.writeHead(400); return res.end(J({ error: 'device_id and url required' })); }
      if (!isSsrfSafeUrl(d.url)) { res.writeHead(400); return res.end(J({ error: 'url must be a valid public HTTPS URL (private/loopback addresses not allowed)' })); }
      const k = `${d.device_id}:${apiKey}`;
      if (!webhooks.has(k)) webhooks.set(k, []);
      webhooks.get(k).push({ url: d.url, secret: d.secret || '' });
      log('info', 'webhook_registered', { device: d.device_id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/ws-ticket — short-lived ticket for WS upgrade (finding #13) ───────
  // Client fetches ticket via authenticated HTTP, then connects WS with ?ticket=xxx
  // so the API key never appears in the WebSocket URL (which lands in nginx access logs).
  if (path === '/v2/ws-ticket' && req.method === 'POST') {
    const ticket = 'wst_' + crypto.randomBytes(24).toString('hex');
    wsTickets.set(ticket, { apiKey, expires: Date.now() + 30_000 }); // 30s one-time use
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, ticket, expires_in: 30 }));
  }

  // ── GET /v2/stream-next ──────────────────────────────────────────────────────
  if (path === '/v2/stream-next') {
    const device = query.device || '';
    // Fix B: return next real blob hash from per-device delivery queue
    const qKey = `${apiKey}:${device}`;
    const queue = deviceQueues.get(qKey) || [];
    // Pop only hashes whose blob is still in store (TTL may have expired)
    let hash = null;
    while (queue.length > 0) {
      const candidate = queue[0];
      if (blobStore.has(candidate)) { hash = candidate; break; }
      queue.shift(); // discard expired/burned entries
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, device, hash, available: hash !== null }));
  }

  // ── GET /v2/audit — Merkle chain audit log ───────────────────────────────────
  if (path === '/v2/audit') {
    if (!apiKey || !apiKeys.has(apiKey) || apiKeys.get(apiKey)?.active === false) {
      res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required' }));
    }
    const limit   = Math.max(1, Math.min(parseInt(query.limit || '100') || 1, MAX_AUDIT));
    const entries = (auditChain.get(apiKey) || []).slice(-limit).reverse();
    const valid   = verifyChain([...(auditChain.get(apiKey) || [])]);

    if (query.format === 'csv') {
        res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="paramant_audit.csv"' });
      return res.end('ts,event,hash,bytes,device,chain_hash\n' +
        entries.map(e => `${e.ts},${e.event},${e.hash||''},${e.bytes||0},${e.device||''},${e.chain_hash}`).join('\n'));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: entries.length, chain_valid: valid, entries }));
  }

  // ── POST /v2/did/register ────────────────────────────────────────────────────
  if (path === '/v2/did/register' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({ error: 'device_id and ecdh_pub required' })); }
      // Receiver sessions (device_id 'inv_*') gebruiken transfer key als session scope — geen API key nodig
      // Alle overige pubkey registraties vereisen een geldige API key
      const isReceiverSession = typeof d.device_id === 'string' && d.device_id.startsWith('inv_');
      if (!keyData && !isReceiverSession) {
        res.writeHead(401); return res.end(J({ error: 'Valid API key required for pubkey registration' }));
      }
      // Rate limit: max 500 DIDs per API key to prevent RAM DoS
      const MAX_DID_PER_KEY = 500;
      if (apiKey) {
        let keyDidCount = 0;
        for (const e of didRegistry.values()) { if (e.key === apiKey) keyDidCount++; }
        if (keyDidCount >= MAX_DID_PER_KEY) {
          res.writeHead(429); return res.end(J({ error: `DID limit reached. Max ${MAX_DID_PER_KEY} DIDs per API key.` }));
        }
      }
      const did = generateDid(d.device_id, d.ecdh_pub);
      const doc = createDidDocument(did, d.device_id, d.ecdh_pub, d.dsa_pub || '');
      didRegistry.set(did, { device_id: d.device_id, key: apiKey, doc, ts: new Date().toISOString() });
      const _didPlan = keyData?.plan || 'pro';
      pubkeys.set(`${d.device_id}:${apiKey}`, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', dsa_pub: d.dsa_pub || '', ts: new Date().toISOString(), expires: Date.now() + (_pubkeyTtl[_didPlan] ?? _pubkeyTtl.free) });
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      incMetric('did_registrations');
      auditAppend(apiKey, 'did_registered', { did, device: d.device_id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, did, document: doc, ct_index: ctEntry.index }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/did ──────────────────────────────────────────────────────────────
  if (path === '/v2/did' && req.method === 'GET') {
    const dids = [...didRegistry.values()].filter(e => e.key === apiKey).map(e => ({ did: e.doc.id, device: e.device_id, ts: e.ts }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: dids.length, dids }));
  }

  // ── POST /v2/attest ──────────────────────────────────────────────────────────
  if (path === '/v2/attest' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.device_id || !d.attestation) { res.writeHead(400); return res.end(J({ error: 'device_id and attestation required' })); }
      const pk = pubkeys.get(`${d.device_id}:${apiKey}`);
      if (!pk) { res.writeHead(404); return res.end(J({ error: 'Device not registered' })); }
      const result = verifyAttestation(pk.ecdh_pub, d.device_id, d.attestation);
      auditAppend(apiKey, 'attestation', { device: d.device_id, method: d.attestation.method, valid: result.valid });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, ...result, device: d.device_id }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/attest/:device ───────────────────────────────────────────────────
  const attm = path.match(/^\/v2\/attest\/([^/]+)$/);
  if (attm && req.method === 'GET') {
    let _attParam;
    try { _attParam = decodeURIComponent(attm[1]); }
    catch { res.writeHead(400); return res.end(J({ error: 'Invalid percent-encoding in path' })); }
    const deviceHash = crypto.createHash('sha3-256').update(_attParam).digest('hex');
    const att = attestations.get(deviceHash);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, device_hash: deviceHash, attestation: att || { attested: false, reason: 'never_attested' } }));
  }

  // ── POST /v2/ack — ACK bevestiging van ontvangst ─────────────────────────────
  if (path === '/v2/ack' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.hash) { res.writeHead(400); return res.end(J({ error: 'hash required' })); }
      incMetric('ack_total');
      auditAppend(apiKey, 'ack_received', { hash: d.hash.slice(0,16)+'...', device: d.device_id || '' });
      log('info', 'ack_received', { hash: d.hash.slice(0,16) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash: d.hash }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/verify-mfa ─────────────────────────────────────────────
  if (path === '/v2/admin/verify-mfa' && req.method === 'POST') {
    // M2: rate limit — max 5 attempts per IP per minute
    const clientIp = getClientIp(req);
    if (!checkMfaRateLimit(clientIp)) {
      log('warn', 'mfa_rate_limited', { ip: clientIp });
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(J({ error: 'Too many MFA attempts — try again in 60 seconds' }));
    }
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const valid = verifyTotp(d.totp_code || '');
      log(valid ? 'info' : 'warn', 'mfa_attempt', { valid, ip: clientIp });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: valid, error: valid ? null : 'Invalid TOTP code' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys — Key aanmaken ────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'POST') {
    // Enforce key limit (community = 5 hard cap; licensed = LICENSE_MAX_KEYS or Infinity)
    if (LICENSE_MAX_KEYS !== Infinity) {
      const activeCount = [...apiKeys.values()].filter(v => v.active !== false).length;
      if (activeCount >= LICENSE_MAX_KEYS) {
        res.writeHead(402, { 'Content-Type': 'application/json' });
        return res.end(J({
          error: EDITION === 'community'
            ? `Community Edition limit reached (${COMMUNITY_KEY_LIMIT} keys). Add a plk_ license key to unlock unlimited users.`
            : `License limit reached (${LICENSE_MAX_KEYS} keys). Contact Paramant to upgrade your license.`,
          current_keys: activeCount,
          max_keys: LICENSE_MAX_KEYS,
          upgrade_url: 'https://paramant.app/pricing'
        }));
      }
    }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      const newKey = (d.key && /^pgp_[0-9a-f]{32,64}$/.test(d.key)) ? d.key : 'pgp_' + crypto.randomBytes(32).toString('hex');
      // Fix 13: validate plan against allowlist
      const VALID_PLANS = new Set(['community', 'dev', 'pro', 'licensed', 'enterprise']);
      const plan = VALID_PLANS.has(d.plan) ? d.plan : 'community';
      const label = typeof d.label === 'string' ? d.label.slice(0, 128) : '';
      // L4: validate email format and length before storing/sending
      const rawEmail = (d.email || '').toString().trim();
      if (rawEmail && (rawEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail))) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'Invalid email address' }));
      }
      const email = rawEmail;
      apiKeys.set(newKey, { plan, label, active: true });
      _mutateUsersJson(d => {
        d.api_keys.push({ key: newKey, plan, label, email, active: true, created: new Date().toISOString() });
        d.updated = new Date().toISOString();
      }).then(() => log('info', 'key_created_via_admin', { label, plan, persisted: true }))
        .catch(we => log('warn', 'key_persist_failed', { err: we.message, label }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key: newKey, plan, label }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/admin/keys ────────────────────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'GET') {
    const keys = [...apiKeys.entries()].map(([k, v]) => ({
      key: k, plan: v.plan, label: v.label, active: v.active, over_limit: v.over_limit || false
    }));
    const licenseInfo = { edition: EDITION, active_keys: keys.length, key_limit: LICENSE_MAX_KEYS === Infinity ? null : LICENSE_MAX_KEYS, ...(LICENSE_PAYLOAD ? { license_expires: LICENSE_PAYLOAD.expires_at } : {}) };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: keys.length, keys, license: licenseInfo }));
  }

  // ── POST /v2/admin/keys/revoke ────────────────────────────────────────────
  if (path === '/v2/admin/keys/revoke' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      if (!apiKeys.has(d.key)) { res.writeHead(404); return res.end(J({ error: 'Key not found' })); }
      apiKeys.get(d.key).active = false;
      const revokedKey = d.key;
      _mutateUsersJson(ud => {
        const ue = ud.api_keys.find(k => k.key === revokedKey);
        if (ue) { ue.active = false; ue.revoked_at = new Date().toISOString(); }
        ud.updated = new Date().toISOString();
      }).then(() => log('info', 'key_revoked_via_admin', { key: revokedKey.slice(0,16), persisted: true }))
        .catch(we => log('warn', 'key_revoke_persist_failed', { err: we.message }));
      // Fix 12: close active WebSocket connections for the revoked key
      const revokedWsClients = wsClients.get(revokedKey);
      if (revokedWsClients) {
        for (const ws of revokedWsClients) {
          try { ws.close(4401, 'Key revoked'); } catch {}
        }
        wsClients.delete(revokedKey);
      }
      res.writeHead(200); return res.end(J({ ok: true }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys/update-plan ─────────────────────────────────────────
  if (path === '/v2/admin/keys/update-plan' && req.method === 'POST') {
    if (!_internalOk()) return _internalReject();
    try {
      const { key, plan } = JSON.parse((await readBody(req, 1024)).toString());
      const VALID_PLANS = new Set(['community','dev','pro','licensed','enterprise']);
      if (!key || !VALID_PLANS.has(plan)) { res.writeHead(400); return res.end(J({ error: 'invalid_params' })); }
      if (!apiKeys.has(key)) { res.writeHead(404); return res.end(J({ error: 'key_not_found' })); }
      apiKeys.get(key).plan = plan;
      _mutateUsersJson(ud => {
        const entry = ud.api_keys.find(k => k.key === key);
        if (entry) { entry.plan = plan; entry.plan_updated = new Date().toISOString(); }
        ud.updated = new Date().toISOString();
      }).catch(e => log('warn', 'plan_update_persist_failed', { err: e.message }));
      res.writeHead(200); return res.end(J({ ok: true, key, plan }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/send-welcome ──────────────────────────────────────────────
  if (path === '/v2/admin/send-welcome' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.email || !d.key) { res.writeHead(400); return res.end(J({ error: 'email and key required' })); }
      const RESEND_KEY = process.env.RESEND_API_KEY || '';
      if (!RESEND_KEY) { res.writeHead(503); return res.end(J({ error: 'RESEND_API_KEY not configured' })); }
      const html = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:520px">
        <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
        <div style="background:#1a1a00;border:1px solid #2a2a00;border-radius:6px;padding:16px;margin-bottom:24px;color:#cccc00;font-size:12px">
          IMPORTANT: Save this API key in your password manager immediately. It is generated once and cannot be recovered. If you lose it, you need to purchase a new subscription.
        </div>
        <p style="color:#888;margin-bottom:24px">Your API key is ready.</p>
        <div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px">
          <div style="font-size:11px;color:#555;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">API KEY — ${(d.plan||'').toUpperCase()}</div>
          <div style="font-size:14px;color:#ededed;word-break:break-all">${d.key}</div>
        </div>
        <pre style="background:#111;border:1px solid #1a1a1a;border-radius:4px;padding:16px;font-size:12px;color:#888;overflow-x:auto">pip install cryptography

python3 paramant-receiver.py \\
  --key ${d.key} \\
  --device my-device \\
  --output /tmp/received/</pre>
        <p style="margin-top:24px;font-size:12px;color:#555"><a href="https://paramant.app/docs" style="color:#888">Docs</a> · <a href="https://paramant.app/ct-log" style="color:#555">CT log</a></p>
        <p style="margin-top:32px;font-size:11px;color:#333">ML-KEM-768 · Burn-on-read · EU/DE · BUSL-1.1</p>
      </div>`;
      const body = JSON.stringify({ from: 'PARAMANT <privacy@paramant.app>', to: [d.email], subject: 'Your PARAMANT API key', html });
      const resp = await new Promise((resolve, reject) => {
        const req2 = https.request({ hostname: 'api.resend.com', path: '/emails', method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        }, r => { let data = ''; r.on('data', c => data += c); r.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve({raw:data}); } }); });
        req2.on('error', reject);
        req2.write(body); req2.end();
      });
      if (resp.id) {
        log('info', 'welcome_mail_sent', { email: d.email, id: resp.id, label: d.label });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, id: resp.id }));
      } else {
        log('warn', 'welcome_mail_failed', { email: d.email, resp });
        res.writeHead(502); return res.end(J({ error: 'Resend error', detail: resp }));
      }
    } catch(e) { res.writeHead(500); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/team/devices ───────────────────────────────────────────────────
  if (path === '/v2/team/devices' && req.method === 'GET') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({ error: 'unauthorized' })); }
    const teamId = kd.team_id;
    if (!teamId) { res.writeHead(200); return res.end(J({ team_id: null, devices: [], message: 'Individuele key — geen team' })); }
    const devices = [];
    apiKeys.forEach((v, k) => {
      if (v.team_id === teamId) devices.push({ label: v.label, plan: v.plan, active: v.active, key_preview: k.slice(0,12)+'...' });
    });
    res.writeHead(200); return res.end(J({ team_id: teamId, devices, count: devices.length }));
  }

  // ── POST /v2/team/add-device ──────────────────────────────────────────────
  if (path === '/v2/team/add-device' && req.method === 'POST') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({ error: 'unauthorized' })); }
    if (!kd.team_id) { res.writeHead(403); return res.end(J({ error: 'Geen team — upgrade naar Pro' })); }
    if (kd.plan === 'dev') { res.writeHead(403); return res.end(J({ error: 'Team keys vereisen Pro of Enterprise' })); }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.label) { res.writeHead(400); return res.end(J({ error: 'label verplicht' })); }
      const newKey = 'pgp_' + require('crypto').randomBytes(16).toString('hex');
      apiKeys.set(newKey, { label: d.label, plan: kd.plan, team_id: kd.team_id, active: true, created: new Date().toISOString() });
      log('info', 'team_device_added', { label: d.label, team: kd.team_id });
      res.writeHead(201); return res.end(J({ ok: true, key: newKey, label: d.label, team_id: kd.team_id }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }


  // ── GET /v2/key-sector — sector routing helper ────────────────────────────
  if (path === '/v2/key-sector' && req.method === 'GET') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({ error: 'unauthorized' })); }
    const label = (kd.label || '').toLowerCase();
    const sector = label.includes('legal')   ? 'legal'
                 : label.includes('finance') ? 'finance'
                 : label.includes('iot')     ? 'iot'
                 : 'health';
    res.writeHead(200); return res.end(J({ sector, plan: kd.plan, team_id: kd.team_id || null }));
  }

  // ── GET /v2/monitor — Dashboard data (vereist geldige API key) ──────────────
  if (path === '/v2/monitor') {
    const kd = apiKeys.get(apiKey);
    if (!kd || !kd.active) {
      res.writeHead(401); return res.end(J({ error: 'Valid X-Api-Key required' }));
    }
    const total      = stats.inbound;
    const acked      = stats.outbound;
    const pending    = blobStore.size;
    const successRate = total > 0 ? Math.round((acked / total) * 1000) / 1000 : 1;
    return res.end(J({
      ok:              true,
      plan:            kd.plan || 'pro',
      blobs_in_flight: pending,
      stats: {
        inbound:       stats.inbound,
        burned:        stats.burned,
        webhooks_sent: stats.webhooks_sent,
      },
      delivery: {
        total:          total,
        acked:          acked,
        pending:        pending,
        success_rate:   successRate,
        avg_latency_ms: 0,
      },
    }));
  }

  // ── POST /v2/drop/create — Anonieme burn-on-read drop met BIP39 + Argon2id ────
  if (path === '/v2/drop/create' && req.method === 'POST') {
    if (!ramOk()) {
      const r = ramStatus();
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '10' });
      return res.end(J({ ok: false, error: 'Relay at capacity', retry_after_s: 10, slots_available: r.available_slots }));
    }
    inFlightInbound++;
    try {
      const d = JSON.parse((await readBody(req)).toString());
      const { hash, payload, ttl_ms, password } = d;
      if (!hash || !payload) { res.writeHead(400); return res.end(J({ error: 'hash en payload verplicht' })); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({ error: 'hash moet SHA-256 hex zijn' })); }
      if (blobStore.has(hash)) { res.writeHead(409); return res.end(J({ error: 'Hash al in gebruik' })); }
      const blob = Buffer.from(payload, 'base64');
      if (blob.length > MAX_BLOB) { res.writeHead(413); return res.end(J({ error: `Max ${Math.round(MAX_BLOB/1048576)}MB` })); }
      const _planDropTtl = { free: 3_600_000, pro: 86_400_000, enterprise: 604_800_000 };
      const ttl = Math.min(parseInt(ttl_ms || 3_600_000) || 3_600_000, _planDropTtl[keyData?.plan || 'pro']);
      // Argon2id password protection
      let pw_hash = null;
      if (password) {
        if (!argon2Lib) { res.writeHead(501); return res.end(J({ error: 'Argon2id not available on this relay' })); }
        pw_hash = await argon2Lib.hash(password, {
          type: argon2Lib.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1,
        });
      }
      // Drops zijn altijd burn-on-read
      blobStore.set(hash, { blob, ts: Date.now(), ttl, size: blob.length,
        sig_valid: false, apiKey, max_views: 1, views_remaining: 1, pw_hash, is_drop: true });
      setTimeout(() => {
        const e = blobStore.get(hash);
        if (e) { zeroBuffer(e.blob); blobStore.delete(hash); }
      }, ttl);
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      auditAppend(apiKey, 'drop_created', { hash: hash.slice(0,16)+'...', bytes: blob.length, pw_protected: !!pw_hash });
      log('info', 'drop_created', { hash: hash.slice(0,16), size: blob.length, pw: !!pw_hash, ttl });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash, ttl_ms: ttl, size: blob.length, pw_protected: !!pw_hash }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
    finally { inFlightInbound--; }
  }

  // ── POST /v2/drop/pickup — Haal drop op via BIP39 mnemonic + optioneel wachtwoord ──
  if (path === '/v2/drop/pickup' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 8192)).toString());
      const { mnemonic, password } = d;
      if (!mnemonic) { res.writeHead(400); return res.end(J({ error: 'mnemonic verplicht' })); }
      let lookupHash;
      try { lookupHash = mnemonicToLookupHash(mnemonic.trim()); }
      catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
      const entry = blobStore.get(lookupHash);
      if (!entry) {
        res.writeHead(404); return res.end(J({ error: 'Drop not found. Expired, already retrieved, or invalid mnemonic.' }));
      }
      // Argon2id password verification
      if (entry.pw_hash) {
        if (!password) { res.writeHead(401); return res.end(J({ error: 'Password required (password field)' })); }
        if (!argon2Lib) { res.writeHead(503); return res.end(J({ error: 'Argon2id not available' })); }
        const pwOk = await argon2Lib.verify(entry.pw_hash, password);
        if (!pwOk) { res.writeHead(403); return res.end(J({ error: 'Incorrect password' })); }
      }
      // Burn-on-read
      const blob = entry.blob;
      blobStore.delete(lookupHash);
      incMetric('blobs_burned'); incMetric('bytes_out_total', blob.length);
      stats.outbound++; stats.burned++; stats.bytes_out += blob.length;
      auditAppend(apiKey, 'drop_pickup', { hash: lookupHash.slice(0,16)+'...', bytes: blob.length });
      log('info', 'drop_pickup', { hash: lookupHash.slice(0,16), size: blob.length });
      res.writeHead(200, {
        'Content-Type':     'application/octet-stream',
        'Content-Length':   blob.length,
        'X-Paramant-Burned': 'true',
        'X-Paramant-Hash':   lookupHash,
      });
      return res.end(blob, () => { try { blob.fill(0); } catch {} });
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/drop/status — Controleer drop beschikbaarheid zonder te branden ─
  if (path === '/v2/drop/status' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.mnemonic) { res.writeHead(400); return res.end(J({ error: 'mnemonic verplicht' })); }
      let lookupHash;
      try { lookupHash = mnemonicToLookupHash(d.mnemonic.trim()); }
      catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
      const entry = blobStore.get(lookupHash);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (!entry) return res.end(J({ available: false }));
      return res.end(J({
        available:        true,
        size:             entry.size,
        ttl_remaining_ms: Math.max(0, entry.ttl - (Date.now() - entry.ts)),
        pw_protected:     !!entry.pw_hash,
      }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/verify-receipt — Verify a signed delivery receipt ───────────────
  // Verifies the ML-DSA-65 signature and re-walks the inclusion proof.
  // Receipt must be base64url-encoded JSON (as returned in X-Paramant-Receipt header).
  if (path === '/v2/verify-receipt' && req.method === 'POST') {
    try {
      const body = await readBody(req, 65536);
      const d = JSON.parse(body.toString());
      if (!d.receipt) { res.writeHead(400); return res.end(J({ error: 'receipt required' })); }

      let receiptObj;
      try {
        // Accept both base64 and base64url (add padding before decode)
        const padded = d.receipt.replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - padded.length % 4) % 4;
        receiptObj = JSON.parse(Buffer.from(padded + '='.repeat(padLen), 'base64').toString('utf8'));
      } catch(e) { res.writeHead(400); return res.end(J({ error: 'invalid receipt encoding' })); }

      if (!receiptObj.blob_hash || !receiptObj.inclusion_proof) {
        res.writeHead(400); return res.end(J({ error: 'receipt missing required fields (blob_hash, inclusion_proof)' }));
      }

      // Step 1 — Verify ML-DSA-65 receipt signature
      if (!mlDsa || !relayIdentity) {
        res.writeHead(503); return res.end(J({ error: 'Signature verification unavailable — ML-DSA-65 not loaded' }));
      }
      if (!receiptObj.signature) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ valid: false, reason: 'no_signature' }));
      }
      const { signature, ...receiptWithoutSig } = receiptObj;
      const canonical = canonicalJSON(receiptWithoutSig);
      let sigValid = false;
      try {
        sigValid = mlDsa.verify(relayIdentity.pk, Buffer.from(canonical, 'utf8'), Buffer.from(signature, 'base64'));
      } catch(e) { sigValid = false; }
      if (!sigValid) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ valid: false, reason: 'signature_invalid' }));
      }

      // Step 2 — Re-walk inclusion proof to recompute Merkle root
      const proof = receiptObj.inclusion_proof;
      if (!proof.leaf_hash) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ valid: false, reason: 'inclusion_proof_missing_leaf_hash' }));
      }
      let computedRoot = proof.leaf_hash;
      for (const step of (proof.audit_path || [])) {
        if (step.position === 'right') {
          computedRoot = ctNodeHash(computedRoot, step.hash);
        } else {
          computedRoot = ctNodeHash(step.hash, computedRoot);
        }
      }
      if (computedRoot !== proof.root) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ valid: false, reason: 'inclusion_proof_invalid',
          detail: `recomputed root ${computedRoot.slice(0,16)}… ≠ claimed root ${(proof.root||'').slice(0,16)}…` }));
      }

      // Step 3 — Verify STH signature (if present)
      if (proof.sth && proof.sth.signature) {
        const { signature: sthSig, ...sthPayload } = proof.sth;
        const sthCanonical = canonicalJSON(sthPayload);
        let sthValid = false;
        try {
          sthValid = mlDsa.verify(relayIdentity.pk, Buffer.from(sthCanonical, 'utf8'), Buffer.from(sthSig, 'base64'));
        } catch(e) { sthValid = false; }
        if (!sthValid) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(J({ valid: false, reason: 'sth_signature_invalid' }));
        }
        if (proof.sth.sha3_root !== proof.root) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(J({ valid: false, reason: 'sth_root_mismatch' }));
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({
        valid:          true,
        blob_hash:      receiptObj.blob_hash,
        retrieved_at:   new Date(receiptObj.retrieved_at).toISOString(),
        sector:         receiptObj.sector,
        relay_id:       receiptObj.relay_id,
        burn_confirmed: receiptObj.burn_confirmed,
        tree_size:      proof.tree_size,
        leaf_index:     proof.leaf_index,
      }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── 404 ──────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(J({ error: 'Not found', version: VERSION, docs: 'https://paramant.app/docs',
    endpoints: ['POST /v2/pubkey','GET /v2/pubkey/:device','POST /v2/inbound',
                'GET /v2/outbound/:hash','GET /v2/status/:hash','POST /v2/webhook',
                'GET /v2/stream-next','GET /v2/audit','GET /health','GET /metrics',
                'POST /v2/verify-receipt'] }));
});

// ── WebSocket streaming — push blob_ready events zonder polling ───────────────
const wsClients = new Map(); // apiKey → Set van ws connections
try {
  const { WebSocketServer } = require('ws');
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const parsed = url_.parse(req.url, true);
    if (parsed.pathname !== '/v2/stream') return socket.destroy();
    // Prefer: X-Api-Key header (best) → ?ticket= one-time token → ?k= (legacy, deprecated)
    let wsApiKey = (req.headers['x-api-key'] || '').trim();
    if (!wsApiKey && parsed.query.ticket) {
      const td = wsTickets.get(parsed.query.ticket);
      if (td && Date.now() < td.expires) { wsApiKey = td.apiKey; wsTickets.delete(parsed.query.ticket); }
      else { log('warn', 'ws_ticket_invalid', { ticket: parsed.query.ticket?.slice(0, 12) }); }
    }
    if (!wsApiKey && parsed.query.k) {
      log('warn', 'ws_key_in_querystring_rejected', { ip: (socket.remoteAddress||'').slice(0,15) });
      return socket.destroy();
    }
    const apiKey = wsApiKey;
    if (!apiKeys.get(apiKey)?.active) return socket.destroy();
    wss.handleUpgrade(req, socket, head, ws => {
      if (!wsClients.has(apiKey)) wsClients.set(apiKey, new Set());
      wsClients.get(apiKey).add(ws);
      ws.send(JSON.stringify({ type: 'connected', ts: new Date().toISOString() }));
      ws.on('close', () => wsClients.get(apiKey)?.delete(ws));
    });
  });
  global.wsPush = (apiKey, event) => {
    const clients = wsClients.get(apiKey);
    if (!clients) return;
    const msg = JSON.stringify({ type: 'blob_ready', ...event, ts: new Date().toISOString() });
    for (const ws of clients) { try { ws.send(msg); } catch {} }
  };
  log('info', 'websocket_streaming_active', { endpoint: '/v2/stream' });
} catch(e) { global.wsPush = () => {}; log('warn', 'ws_not_available', { hint: 'npm install ws' }); }

// ── PARAMANT Community Edition License Check ─────────────────────────────────
// This function and its call may NOT be removed or modified under BUSL-1.1.
// Community Edition: free for up to 5 active API keys.
// For unlimited keys, obtain a commercial license at https://paramant.app/pricing
// Tampering with this check constitutes a license violation under BUSL-1.1.
// ─────────────────────────────────────────────────────────────────────────────
const COMMUNITY_KEY_LIMIT = 5; // Fixed; never overridable via env (BUSL-1.1 § 4)
// Ed25519 public key — matches private key in ~/.paramant/license-signing-key.pem
// To rotate: run scripts/generate-license.js --init and paste new key here.
const ED25519_PUBLIC_KEY = 'ed8a6201c86f013b16718b3e6d9ded62362ca82ef7ae334308c12d71d18ae4e6';
// Ed25519 SPKI DER prefix for key reconstruction
const _ED25519_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

let EDITION          = 'community';
let LICENSE_MAX_KEYS = COMMUNITY_KEY_LIMIT; // effective limit — updated by checkLicense()
let LICENSE_PAYLOAD  = null;                // { max_keys, expires_at, issued_to, issued_at }

// ── Ed25519 base64url decoder ─────────────────────────────────────────────────
function _b64urlDecode(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(p + '='.repeat((4 - p.length % 4) % 4), 'base64');
}

function checkLicense() {
  // File integrity checksum (tamper detection)
  try {
    const checksum = crypto.createHash('sha3-256').update(fs.readFileSync(__filename)).digest('hex');
    log('info', 'relay_integrity', { checksum, file: __filename });
  } catch(e) {
    log('warn', 'relay_integrity_failed', { err: e.message });
  }

  // PLK_KEY is the canonical env var; PARAMANT_LICENSE accepted for backward compat
  const rawKey = process.env.PLK_KEY || process.env.PARAMANT_LICENSE || '';
  if (!rawKey) {
    console.log(`[PARAMANT] Edition: community | max keys: ${COMMUNITY_KEY_LIMIT}`);
    applyKeyLimitEnforcement();
    return;
  }

  try {
    if (!rawKey.startsWith('plk_')) throw new Error('must start with plk_');

    // Decode: last 64 bytes = Ed25519 signature, rest = payload JSON
    const combined    = _b64urlDecode(rawKey.slice(4));
    if (combined.length < 65) throw new Error('token too short');
    const sig         = combined.subarray(combined.length - 64);
    const payloadBuf  = combined.subarray(0, combined.length - 64);

    // Reconstruct public key from hardcoded hex (SPKI DER = prefix + 32 raw bytes)
    const pubDer = Buffer.concat([_ED25519_DER_PREFIX, Buffer.from(ED25519_PUBLIC_KEY, 'hex')]);
    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });

    if (!crypto.verify(null, payloadBuf, pubKey, sig)) throw new Error('signature invalid — key not issued by Paramant');

    const payload = JSON.parse(payloadBuf.toString('utf8'));
    if (!payload.expires_at || !payload.max_keys || !payload.issued_to) throw new Error('payload missing required fields');

    // Expiry check — fall back gracefully, do NOT crash
    const expiresAt = new Date(payload.expires_at);
    if (isNaN(expiresAt.getTime())) throw new Error('expires_at is not a valid date');
    if (expiresAt < new Date()) {
      log('warn', 'license_expired', { expires_at: payload.expires_at, issued_to: payload.issued_to });
      console.log(`[PARAMANT] Edition: community (license expired ${payload.expires_at}) | max keys: ${COMMUNITY_KEY_LIMIT}`);
      applyKeyLimitEnforcement();
      return;
    }

    // Valid license
    LICENSE_PAYLOAD  = payload;
    EDITION          = 'licensed';
    LICENSE_MAX_KEYS = payload.max_keys === 'unlimited' ? Infinity : parseInt(payload.max_keys, 10);
    log('info', 'license_valid', { edition: 'licensed', issued_to: payload.issued_to, expires_at: payload.expires_at, max_keys: payload.max_keys });
    console.log(`[PARAMANT] Edition: licensed | issued to: ${payload.issued_to} | expires: ${payload.expires_at} | max keys: ${payload.max_keys}`);

  } catch(e) {
    log('warn', 'license_invalid', { err: e.message, hint: 'PLK_KEY failed Ed25519 verification — falling back to community' });
    console.log(`[PARAMANT] Edition: community (invalid key: ${e.message}) | max keys: ${COMMUNITY_KEY_LIMIT}`);
  }
  applyKeyLimitEnforcement();
}

// ── Community Edition key-limit enforcement ───────────────────────────────────
// Free self-hosters: max 5 active API keys. Keys 6+ receive 402 on every request.
// Licensed (plk_*): no limit. Set PARAMANT_LICENSE=plk_... in .env to unlock.
// ─────────────────────────────────────────────────────────────────────────────
function applyKeyLimitEnforcement() {
  if (EDITION === 'licensed') {
    for (const v of apiKeys.values()) v.over_limit = false;
    log('info', 'edition', { edition: 'licensed', active_keys: [...apiKeys.values()].filter(k => k.active !== false).length, max_keys: LICENSE_MAX_KEYS === Infinity ? 'unlimited' : LICENSE_MAX_KEYS });
    return;
  }

  const entries = [...apiKeys.entries()];
  const active  = entries.filter(([, v]) => v.active !== false);

  if (active.length <= LICENSE_MAX_KEYS) {
    for (const [, v] of entries) v.over_limit = false;
    log('info', 'edition', { edition: EDITION, active_keys: active.length, limit: LICENSE_MAX_KEYS });
    return;
  }

  // Keys beyond LICENSE_MAX_KEYS are flagged over_limit
  let n = 0;
  for (const [, v] of entries) {
    if (v.active === false) continue;
    n++;
    v.over_limit = n > LICENSE_MAX_KEYS;
    if (v.over_limit) log('warn', 'key_over_limit', {
      label: v.label,
      hint: 'Add PLK_KEY=plk_... to .env to unlock unlimited users — https://paramant.app/pricing'
    });
  }
  log('warn', 'community_limit_exceeded', {
    active_keys: active.length,
    limit: LICENSE_MAX_KEYS,
    blocked: active.length - LICENSE_MAX_KEYS,
    operator_upgrade: 'https://paramant.app/pricing'
  });
}


// ── Self-registration — announce this relay to the registry ───────────────────
async function registerSelf() {
  if (!relayIdentity || !RELAY_SELF_URL) return;
  const target = RELAY_PRIMARY_URL || `http://localhost:${PORT}`;
  const timestamp = new Date().toISOString();
  const msg = Buffer.from(RELAY_SELF_URL + '|' + SECTOR + '|' + VERSION + '|' + timestamp, 'utf8');
  // API in @noble/post-quantum: sign(message, secretKey)
  let sig;
  try { sig = Buffer.from(mlDsa.sign(msg, relayIdentity.sk)); } catch (e) {
    log('warn', 'relay_self_register_sign_failed', { err: e.message }); return;
  }
  const body = JSON.stringify({
    url:        RELAY_SELF_URL,
    sector:     SECTOR,
    version:    VERSION,
    edition:    EDITION,
    public_key: relayIdentity.pk.toString('base64'),
    signature:  sig.toString('base64'),
    timestamp
  });
  try {
    const u = new URL('/v2/relays/register', target);
    const mod = target.startsWith('https://') ? https : http;
    await new Promise((resolve, reject) => {
      const req = mod.request({
        hostname: u.hostname,
        port:     u.port || (target.startsWith('https://') ? 443 : 80),
        path:     u.pathname,
        method:   'POST',
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, res2 => {
        let data = '';
        res2.on('data', d => { data += d; });
        res2.on('end', () => {
          try {
            const d = JSON.parse(data);
            if (d.ok) log('info', 'relay_self_registered', { url: RELAY_SELF_URL, target, ct_index: d.ct_index });
            else log('warn', 'relay_self_register_rejected', { error: d.error, target });
          } catch {}
          resolve();
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  } catch (e) {
    log('warn', 'relay_self_register_failed', { err: e.message, target });
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────
loadUsers();
loadTrialKeys();
checkLicense();
loadOrCreateRelayIdentity();
relayRegistryFromCTLog();
loadPeerSths();
// Generate a startup STH if the CT log has entries but no STH was persisted.
// Covers the case where the STH file was missing or the relay restarted after
// new CT entries were written without a corresponding STH flush.
if (ctLog.length > 0 && sthLog.length === 0) {
  const last = ctLog[ctLog.length - 1];
  produceSth(ctLog.length, last.tree_hash);
}
// Periodic STH gossip — re-broadcast latest STH every 10 min to catch newly registered peers
setInterval(() => {
  if (sthLog.length === 0 || !relayIdentity) return;
  broadcastSTH(sthLog[sthLog.length - 1]).catch(() => {});
}, 10 * 60_000);
server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  log('info', 'relay_started', { port: PORT, version: VERSION, sector: SECTOR, mode: RELAY_MODE,
      dsa: !!mlDsa, protocol: 'ghost-pipe-v2',
      relay_identity: relayIdentity ? relayIdentity.pk_hash.slice(0,16)+'…' : 'none' });
  // Register to the relay registry after a short delay to let the server fully bind
  if (relayIdentity && RELAY_SELF_URL) setTimeout(registerSelf, 500);
});
function emergencyZeroAndExit(reason, code = 0) {
  // Fix 8: flush CT write queue before exit
  _flushCtOnExit();
  _flushSthOnExit();
  _flushPeerSthsOnExit();
  // Zeroize all in-memory blobs before exit
  try {
    for (const [, e] of blobStore.entries()) {
      if (e.blob) zeroBuffer(e.blob);
    }
    // Clear pubkeys (contain receiver public keys — not secret but clean up anyway)
    pubkeys.clear();
    // Clear download tokens (contain hashes, not plaintext, but scrub anyway)
    downloadTokens.clear();
    log('info', 'shutdown_clean', { reason, burned: stats.burned });
  } catch (_) {}
  process.exit(code);
}

// Graceful shutdown on SIGTERM (systemctl stop) and SIGINT (Ctrl+C)
process.on('SIGTERM', () => emergencyZeroAndExit('SIGTERM'));
process.on('SIGINT',  () => emergencyZeroAndExit('SIGINT'));

// Catch unhandled promise rejections — log and exit cleanly so blobs are zeroized
process.on('unhandledRejection', (reason) => {
  const stack = (reason instanceof Error) ? reason.stack : String(reason);
  log('error', 'unhandled_rejection', { reason: String(reason).slice(0, 200), stack: stack?.slice(0, 1000) });
  emergencyZeroAndExit('unhandledRejection', 1);
});

// Catch synchronous uncaught exceptions (e.g. invalid header values)
process.on('uncaughtException', (err) => {
  log('error', 'uncaught_exception', { msg: err.message?.slice(0, 200), code: err.code });
  emergencyZeroAndExit('uncaughtException', 1);
});
