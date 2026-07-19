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
const { createClient } = require('redis');
const userTotp      = require('./lib/user-totp');
const userSigning   = require('./lib/user-signing');
const userWebauthn  = require('./lib/user-webauthn');
const tiers         = require('./lib/tiers');
const quota         = require('./lib/quota');
const keysTable     = require('./lib/keys-table');
const paraidRegistry = require('./lib/paraid-registry');

const VERSION    = '3.0.0';
// Per-restart nonce: stream-next hashes non-precomputable even if API key is known
const STREAM_NONCE = crypto.randomBytes(32);

// ── WS ticket store — avoids API key in WebSocket upgrade URL (finding #13) ──
// Client calls POST /v2/ws-ticket → gets 30s one-time ticket → connects with ?ticket=xxx
const wsTickets = new Map(); // ticket → { apiKey, expires }
setInterval(() => { const now = Date.now(); for (const [k, v] of wsTickets) if (now > v.expires) wsTickets.delete(k); }, 10_000);


// ── Drop / Argon2id / BIP39 — optioneel laden ─────────────────────────────────
let argon2Lib = null;
try { argon2Lib = require('argon2'); } catch(e) { /* npm install argon2 */ }
// Redis client for user TOTP endpoints
const RELAY_REDIS_URL = process.env.REDIS_URL || '';
let redisClient = null;
if (RELAY_REDIS_URL) {
  redisClient = createClient({ url: RELAY_REDIS_URL });
  redisClient.on('error', (err) => console.error('[relay/redis] error:', err.message));
  redisClient.connect()
    .then(() => console.log('[relay/redis] connected'))
    .catch(e => console.error('[relay/redis] connect failed:', e.message));
}
const PORT       = parseInt(process.env.PORT       || '3000');
const USERS_FILE = process.env.USERS_FILE          || './users.json';
const TTL_MS     = parseInt(process.env.TTL_MS     || '300000');
const MAX_BLOB   = parseInt(process.env.MAX_BLOB   || '5242880');
const MAX_AUDIT  = parseInt(process.env.MAX_AUDIT  || '1000');
const CLAIM_TTL_SECONDS = parseInt(process.env.CLAIM_TTL_SECONDS || String(7 * 86400)); // one-time API-key claim link lifetime
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

// ── Crypto agility registry (wire format v1) ─────────────────────────────────
// bootstrap() registers the relay's crypto algorithms once at module load. The
// set depends on CRYPTO_MODE: 'core' (default) = ML-KEM-768 + ML-DSA-65 only;
// 'extended' = all 18 algorithms (see ADR R006). Every crypto call site in this
// file goes through registry.getKEM/getSig so algorithms can be swapped without
// touching handlers.
const registry = require('./crypto/registry');
const cryptoMode = require('./crypto/bootstrap').bootstrap();
log('info', 'crypto_mode_loaded', { mode: cryptoMode });
const wireFormat = require('./crypto/wire-format');
const cryptoErrors = require('./crypto/errors');
const parasign = require('./parasign');
const envelopeMod = require('./envelope');
const parasignOpenApi = require('./lib/parasign-open-api'); // ParaSign Open Developer-API (/v1)

// Outbound wire format selector. Default 0 keeps the legacy on-the-wire format;
// setting PARAMANT_WIRE_VERSION=1 activates the self-describing v1 header
// (PQHB magic + version + kem_id + sig_id + flags). Inbound decoding accepts
// both v0 and v1 unconditionally — this flag only controls what we produce.
// NOTE: this relay is opaque to the encrypted blob — the sender already
// assembles the wire format client-side and we store the result verbatim.
// So WIRE_VERSION has no direct effect on what we emit on /v2/outbound; it
// exists for forward compatibility with variants of this relay that would
// re-wrap blobs in transit. Inbound validation (see peekInboundBlob below)
// runs unconditionally — any blob carrying the v1 magic bytes is parsed
// and rejected if its algorithm IDs are not in the registry.
const WIRE_VERSION = process.env.PARAMANT_WIRE_VERSION === '1' ? 1 : 0;

// Inspects the first bytes of a just-uploaded blob. If it carries the v1
// magic, decodes it to validate structure + algorithm support. Throws a
// CryptoError on malformed v1 blobs (caller maps to HTTP 415 / 400 via
// mapCryptoErrorToHttp). Returns null for v0 blobs — they pass through.
function peekInboundBlob(blob) {
  if (!wireFormat.isV1(blob)) return null;
  return wireFormat.decode(blob);
}

// Maps a CryptoError thrown from wireFormat.decode to the HTTP response the
// spec in docs/wire-format-v1.md requires. UnsupportedAlgorithm / InvalidVersion
// → 415 (server does not support this algorithm / version). All other
// CryptoErrors (InvalidMagic is filtered upstream by isV1, so what is left
// is MalformedBlob + InvalidFlags) → 400 (blob is v1 but structurally bad).
function mapCryptoErrorToHttp(err) {
  if (err instanceof cryptoErrors.UnsupportedAlgorithm) {
    return {
      status: 415,
      body: {
        error: 'unsupported_algorithm',
        kind: err.kind,
        id: err.id,
        supported: registry.listSupported(),
      },
    };
  }
  if (err instanceof cryptoErrors.InvalidVersion) {
    return {
      status: 415,
      body: {
        error: 'unsupported_wire_version',
        version: err.version,
        supported: err.supported,
      },
    };
  }
  if (err instanceof cryptoErrors.CryptoError) {
    return { status: 400, body: { error: 'malformed_wire_v1', detail: err.message } };
  }
  return null;
}
// `mlDsa` is retained as an availability probe used by `if (!mlDsa)` guards
// throughout this file. It holds the registry-resolved impl when present, or
// null when ML-DSA-65 could not be loaded (e.g. the @paramant/core binding is
// missing or failed to build).
let mlDsa = null;
try {
  mlDsa = registry.getSig(0x0002);
  if (mlDsa) log('info', 'ml_dsa_loaded', { alg: mlDsa.name });
} catch(e) { log('warn', 'ml_dsa_not_available', { hint: 'build/install @paramant/core', err: e.message }); }

const ALLOWED = {
  ghost_pipe: ['/health','/v2/pubkey','/v2/inbound','/v2/anon-inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream',
               '/v2/ack','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/session',
               '/v2/ws-ticket','/v2/fingerprint','/v2/relays','/v2/sign-dpa',
               '/v2/sth','/v2/verify-receipt','/v2/capabilities','/ct','/ct/feed','/v2/auth','/v2/user','/v2/setup',
               '/v2/sign','/v2/verify','/v2/lookup-signer','/v2/envelopes','/v2/claim','/v1'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/anon-inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/ack','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/session',
               '/v2/relays','/v2/sign-dpa','/v2/sth','/v2/verify-receipt',
               '/v2/capabilities','/ct','/ct/feed','/v2/auth','/v2/user','/v2/setup',
               '/v2/sign','/v2/verify','/v2/lookup-signer','/v2/envelopes','/v2/claim','/v1'],
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
const deviceQueues = new Map(); // `${acctOf(apiKey)}:${deviceId}` → string[]

// Cap per-device queue length. The read-side drain (/v2/stream-next) only shifts
// entries whose blob already expired, so a device that never polls would grow its
// queue without bound. Cap it and drop the oldest hash (FIFO) past the limit.
const MAX_DEVICE_QUEUE = parseInt(process.env.MAX_DEVICE_QUEUE || '1000');

function deviceQueuePush(apiKey, deviceId, hash) {
  if (!deviceId) return;
  const k = `${acctOf(apiKey)}:${deviceId}`;
  if (!deviceQueues.has(k)) deviceQueues.set(k, []);
  const q = deviceQueues.get(k);
  if (!q.includes(hash)) q.push(hash); // dedup
  while (q.length > MAX_DEVICE_QUEUE) q.shift(); // bound per-device memory
}

// ── DID — Decentralized Identity (W3C) ───────────────────────────────────────
const didRegistry = new Map();
// Per-API-key DID counter so the MAX_DID_PER_KEY cap is enforced in O(1) instead
// of an O(n) full scan of didRegistry on every registration. Kept in sync at the
// single didRegistry.set site (only incremented when a genuinely-new did is added,
// not on re-registration of an existing did).
const didKeyCounts = new Map(); // apiKey → count

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
const CT_MAX = 10000;
// Bounded, monotonically-indexed window (see lib/ct-window). Past CT_MAX the
// logical index keeps advancing (no duplicates / frozen STH) and lookups for a
// pruned index return null instead of the wrong entry.
const { CtWindow } = require('./lib/ct-window');
const ctWindow = new CtWindow(CT_MAX);
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
    const loaded = [];
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (Array.isArray(parsed)) {
          for (const entry of parsed) {
            if (entry && typeof entry === 'object' && !Array.isArray(entry)) loaded.push(entry);
          }
        } else {
          loaded.push(parsed);
        }
      } catch {}
    }
    ctWindow.load(loaded);
    if (ctWindow.windowLength) log('info', 'ct_log_loaded', { entries: ctWindow.windowLength, file: CT_FILE });
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
      const kp = registry.getSig(0x0002).generateKeyPair();
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
  for (const entry of ctWindow.entries) {
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

// CT-log hash primitives live in ./lib/ct-hash (pure, unit-tested there).
const { ctNodeHash, ctTreeHash, ctInclusionProof, blobLeafHash } = require('./lib/ct-hash');

// Coarsen an ISO timestamp to the top of its hour for PUBLIC projections only.
// The full-precision ts stays in the stored entry (and is committed in the leaf
// hash); this just blunts millisecond traffic-analysis in the public CT log.
function ctCoarseTs(ts) {
  if (!ts) return ts;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  d.setUTCMinutes(0, 0, 0);
  return d.toISOString();
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
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1); // real audit path at the new leaf position
  const entry = { index, leaf_hash, tree_hash, device_hash: deviceIdHash, ts, proof };
  ctWindow.append(entry);
  // Fix 8: async write via stream queue instead of appendFileSync
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
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
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = {
    index, type: 'relay_reg', leaf_hash, tree_hash,
    device_hash: pkHash,          // reused field — relay public key hash
    relay_url: relayUrl, relay_sector: sector,
    relay_version: version, relay_edition: edition,
    relay_pk_hash: pkHash,
    ts, proof
  };
  ctWindow.append(entry);
  // Fix 8: async write via stream queue
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
}

// Appends a blob transfer entry to the CT log and returns the entry with inclusion proof.
// Leaf hash: SHA3-256(0x02 || SHA3-256(sector) || ts) — commits to transfer identity.
// Called at inbound upload; the entry is stored in blobStore so the outbound handler
// can produce a signed delivery receipt without re-querying the CT log.
function ctAppendTransfer(blobHash, sector) {
  const ts = new Date().toISOString();
  const leaf_hash = blobLeafHash(blobHash, sector, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = {
    index, type: 'transfer', leaf_hash, tree_hash,
    blob_hash: blobHash, sector, ts, proof
  };
  ctWindow.append(entry);
  ctWrite(entry);
  const sth = produceSth(allEntries.length, entry.tree_hash);
  return { ...entry, sth };
}

// Appends a ParaSign signing event to the CT log (R017). Commits to the
// document hash and the signer public-key hash -- never to document content.
// Leaf hash reuses ctLeafHash(identityHash, keyHex, ts) with the signer
// public-key hash as identity and the document hash as the committed value.
function ctAppendParasign(documentHashHex, signerPkHash) {
  const ts = new Date().toISOString();
  const leaf_hash = ctLeafHash(signerPkHash, documentHashHex, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = {
    index, type: 'parasign', leaf_hash, tree_hash,
    document_hash: documentHashHex, signer_pk_hash: signerPkHash, ts, proof
  };
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
}

// Appends an envelope lifecycle event (create / view / sign / complete) to
// the CT log. The relay never sees the document - the leaf commits only to
// the envelope id, event type, and a sha3-256 over the structured payload.
function ctAppendEnvelope(eventType, envelopeId, payload) {
  const ts = new Date().toISOString();
  const valueHash = crypto.createHash('sha3-256')
    .update(eventType).update('|').update(envelopeId).update('|')
    .update(JSON.stringify(payload || {})).digest('hex');
  const leaf_hash = ctLeafHash(envelopeId, valueHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = {
    index, type: 'envelope_' + eventType, leaf_hash, tree_hash,
    envelope_id: envelopeId, payload: payload || {}, ts, proof
  };
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
}

// Appends a signing-pubkey lifecycle event (enroll / revoke) to the CT log so
// identity changes are tamper-evident. user_id is hashed (SHA3-256) before
// emission — verifiers see a stable identity-handle without the raw API key.
// `eventType` must be 'signing_pk_enrolled' or 'signing_pk_revoked'.
function ctAppendSigningPkEvent(eventType, userId, signerPkHash) {
  if (eventType !== 'signing_pk_enrolled' && eventType !== 'signing_pk_revoked') {
    throw new Error('invalid eventType: ' + eventType);
  }
  const ts = new Date().toISOString();
  const userIdHash = crypto.createHash('sha3-256').update(String(userId)).digest('hex');
  const leaf_hash = ctLeafHash(userIdHash, signerPkHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = {
    index, type: eventType, leaf_hash, tree_hash,
    user_id_hash: userIdHash, signer_pk_hash: signerPkHash, ts, proof
  };
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
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
    signature = Buffer.from(registry.getSig(0x0002).sign(Buffer.from(canonical, 'utf8'), relayIdentity.sk)).toString('base64');
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
// Cap the NUMBER of distinct peers we mirror. /v2/sth/ingest only verifies an
// ML-DSA-65 ownership signature (no API-key/admin gate), so an attacker can mint
// unlimited fresh relay keypairs and have each add a Map entry + an open write
// fd + a growing .jsonl file. Per-peer records are already capped (peer.sths
// shift), but the count of peers/fds/files was unbounded — so cap it and evict
// the least-recently-updated peer (closing its fd) when full.
const PEER_STH_MAX_PEERS = parseInt(process.env.PEER_STH_MAX_PEERS || '256');
// peerSths: relay pk_hash (hex) → { sths: STH[], pk_b64: string, last: epoch_ms }
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

// Close + drop the write stream for an evicted peer so its fd is released.
function _peerSthStreamClose(pkHash) {
  const stream = _peerSthStreams.get(pkHash);
  if (stream) { try { stream.end(); } catch {} _peerSthStreams.delete(pkHash); }
}

// Evict least-recently-updated peers until under PEER_STH_MAX_PEERS. Keeps the
// fd table and .jsonl set bounded regardless of how many keys an attacker mints.
function _evictPeerSthsIfNeeded() {
  if (peerSths.size <= PEER_STH_MAX_PEERS) return;
  const ordered = [...peerSths.entries()].sort((a, b) => (a[1].last || 0) - (b[1].last || 0));
  for (const [pkHash] of ordered) {
    if (peerSths.size <= PEER_STH_MAX_PEERS) break;
    peerSths.delete(pkHash);
    _peerSthStreamClose(pkHash);
    // Reclaim the evicted peer's on-disk .jsonl so the file set is actually
    // bounded (not just the fd table); a later re-ingest re-creates it fresh.
    try { fs.unlinkSync(path.join(PEER_STH_DIR, pkHash.replace(/[^a-f0-9]/g, '').slice(0, 64) + '.jsonl')); } catch {}
    log('info', 'peer_sth_evicted', { id: pkHash.slice(0, 16), peers: peerSths.size });
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
        const lastRec = recent.length > 0 ? Date.parse(recent[recent.length - 1].received_at || '') : 0;
        peerSths.set(id, { sths: recent, pk_b64, last: Number.isFinite(lastRec) ? lastRec : 0 });
      } catch {}
    }
    _evictPeerSthsIfNeeded();
    if (peerSths.size > 0) log('info', 'peer_sths_loaded', { peers: peerSths.size });
  } catch (e) {
    if (e.code !== 'ENOENT') log('warn', 'peer_sths_load_failed', { err: e.message });
  }
}

function _flushPeerSthsOnExit() {
  for (const stream of _peerSthStreams.values()) { try { stream.end(); } catch {} }
}

// ── Gossip — broadcast our latest STH to all registered peers ─────────────────
// Outbound HTTPS goes through safeHttpsRequest so the per-request DNS guard
// catches peers that registered with a public hostname but DNS-rebound to a
// private/loopback IP before gossip fires. Same defence as pushWebhooks.
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
    const target = new URL('/v2/sth/ingest', peer.url).toString();
    try {
      await safeHttpsRequest(target, {
        method:  'POST',
        timeout: 3000,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        body,
      });
    } catch (e) {
      if      (e.code === 'SSRF_URL') log('warn', 'gossip_ssrf_blocked',          { url: (peer.url||'').slice(0,60) });
      else if (e.code === 'SSRF_DNS') log('warn', 'gossip_dns_rebinding_blocked', { url: (peer.url||'').slice(0,60), resolved: e.resolved });
      // network errors are non-blocking, best-effort (peer may be offline)
    }
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

// Consistency proof over the retained window. fromSize/toSize are leaf counts
// within the in-memory tree (0 ≤ from ≤ to ≤ windowLength); entries pruned past
// the CT_MAX window cannot participate.
function ctConsistencyProof(fromSize, toSize) {
  if (fromSize < 0 || toSize < fromSize || toSize > ctWindow.windowLength) return null;
  if (fromSize === 0 || fromSize === toSize) return [];
  const leaves = ctWindow.entries.slice(0, toSize).map(e => e.leaf_hash);
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
  for(const [k,v] of [['blobs_in_flight',blobStore.size],['pubkeys',pubkeys.size],['edition',EDITION==='licensed'?1:0],['did_registry',didRegistry.size],['ct_log',ctWindow.size],['uptime_s',Math.floor(process.uptime())],['heap_bytes',process.memoryUsage().heapUsed]]){
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

function totpCode(secret, counter, algorithm = 'sha256') {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac(algorithm, key).update(buf).digest();
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
async function verifyTotpGeneric(token, secret, opts = {}) {
  const { window = 1, replayKey, algorithm = 'sha256' } = opts;
  const tokenBuf = Buffer.from(String(token || ''), 'utf8');
  if (tokenBuf.length !== 6) return { valid: false };
  const counter = Math.floor(Date.now() / 1000 / 30);
  let matched = false;
  let matchedSlot = null;
  for (let i = -window; i <= window; i++) {
    const c = counter + i;
    const expected = totpCode(secret, c, algorithm);
    const expectedBuf = Buffer.from(expected, 'utf8');
    const eq = tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf);
    if (eq) { matched = true; matchedSlot = c; }
  }
  if (!matched) return { valid: false };
  if (replayKey && redisClient) {
    // Atomic one-shot per matched slot. A per-slot key (not a single replayKey
    // that the next slot would overwrite) plus SET NX makes the get/set race-free:
    // NX returns null when the slot was already consumed, so two concurrent uses
    // of the same code, or reuse of a still-in-window code, are both rejected.
    const slotKey = `${replayKey}:${matchedSlot}`;
    const ok = await redisClient.set(slotKey, '1', { NX: true, EX: 90 }).catch(() => 'OK');
    if (ok === null) return { valid: false };
  }
  return { valid: true };
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
const apiKeys    = new Map();  // key → {plan, active, label, dsa_pub, account_id, is_primary, scope, kid}
const accounts   = new Map();  // account_id → {account_id, plan, email, primary_api_key, label}  (stap 1: account_id == key)
const accountKeys = new Map(); // account_id → Set<api_key>  (reverse index for per-account cap + listing)
const kidIndex   = new Map();  // kid → api_key  (non-secret key id for URLs/listings)
// Resolve a key to its account_id. For every loaded key account_id is preset
// (stap 1); for a legacy 1:1 key account_id === apiKey, so device/pubkey/webhook
// keys built from acctOf(apiKey) are byte-identical to the old apiKey-scoped
// ones — behaviour-neutral now, account-shared once a second key is added.
function acctOf(apiKey) { const v = apiKeys.get(apiKey); return (v && v.account_id) || apiKey; }
const blobStore  = new Map();  // hash → {blob, ts, ttl, size, sig?}

const anonInboundIpRequests = new Map(); // ip → [timestamps] for /v2/anon-inbound rate limit
const invDidIpRequests = new Map(); // ip → [timestamps] for keyless inv_ DID registration
const sthIngestIpRequests = new Map(); // ip → [timestamps] for /v2/sth/ingest (unauthenticated)
// Sweep both per-IP rate-limit maps hourly so they cannot grow without bound
// on attacker-rotated IPs (the limit windows already expire entries logically;
// this reclaims the memory). Mirrors the dpaIpRequests sweep. Use each map's
// own window: trial = 24h (DAY_MS at the call site), anon-inbound = 1h.
setInterval(() => {
  const now = Date.now();
  const trialCut = now - 86_400_000; // 24h
  const anonCut  = now - 3_600_000;  // 1h
  for (const [k, times] of trialIpRequests) { const kept = times.filter(t => t > trialCut); if (kept.length) trialIpRequests.set(k, kept); else trialIpRequests.delete(k); }
  for (const [k, times] of anonInboundIpRequests) { const kept = times.filter(t => t > anonCut); if (kept.length) anonInboundIpRequests.set(k, kept); else anonInboundIpRequests.delete(k); }
}, 3_600_000);

// Team rate limit tracking
const teamRateLimits = new Map(); // team_id → { count, resetAt }

// Eviction sweep for the limiter maps that lacked one (the other limiters already
// self-evict). Without this they grow unbounded — slow memory/audit creep,
// especially with spoofable client IPs. Mirrors the dpa*/usedTotp sweeps.
setInterval(() => {
  const now = Date.now();
  const HOUR = 3_600_000;
  for (const [k, times] of anonInboundIpRequests){ const kept = times.filter(t => now - t < HOUR); if (kept.length) anonInboundIpRequests.set(k, kept); else anonInboundIpRequests.delete(k); }
  for (const [k, times] of invDidIpRequests)     { const kept = times.filter(t => now - t < HOUR); if (kept.length) invDidIpRequests.set(k, kept);     else invDidIpRequests.delete(k); }
  for (const [k, times] of sthIngestIpRequests)  { const kept = times.filter(t => now - t < HOUR); if (kept.length) sthIngestIpRequests.set(k, kept);  else sthIngestIpRequests.delete(k); }
  for (const [k, b]     of teamRateLimits)       { if (b && now > b.resetAt) teamRateLimits.delete(k); }
}, 3_600_000);

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

// Per-USER throttle for /v2/user/{verify-totp,consume-backup}. The internal-auth
// guard proves the caller (admin proxy), not that the end user isn't brute-forcing
// their own 6-digit TOTP (10^6 space). Cap attempts per user in a sliding window;
// reset on success so legit retries never lock out. In-memory, mirrors
// checkMfaRateLimit; fails open on nothing (pure counter).
const USER_MFA_MAX = 10;
const USER_MFA_WINDOW_MS = 300_000; // 5 min
const userMfaAttempts = new Map(); // user_id → { count, resetAt }
function userMfaAttemptOk(user_id) {
  const now = Date.now();
  const b = userMfaAttempts.get(user_id) || { count: 0, resetAt: now + USER_MFA_WINDOW_MS };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + USER_MFA_WINDOW_MS; }
  if (b.count >= USER_MFA_MAX) return false;
  b.count++; userMfaAttempts.set(user_id, b); return true;
}
function userMfaAttemptReset(user_id) { userMfaAttempts.delete(user_id); }
setInterval(() => { const now = Date.now(); for (const [k, v] of userMfaAttempts) if (now > v.resetAt + USER_MFA_WINDOW_MS) userMfaAttempts.delete(k); }, 300_000);

// Per-IP rate limit for the public /v2/claim/reveal (max 20/min) — a claim token
// is a 256-bit random hex, so this just caps abusive polling, not real guessing.
const claimRateLimits = new Map();
function claimRateOk(ip) {
  const now = Date.now();
  const b = claimRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= 20) return false;
  b.count++; claimRateLimits.set(ip, b); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of claimRateLimits) if (now > v.resetAt + 60000) claimRateLimits.delete(k); }, 120_000);

// Per-IP rate limit for /v2/check-key (max 30/min) — prevents API key brute-force
const checkKeyRateLimits = new Map();
function checkKeyRateOk(ip) {
  const now = Date.now();
  const b = checkKeyRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= 30) return false;
  b.count++; checkKeyRateLimits.set(ip, b); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of checkKeyRateLimits) if (now > v.resetAt + 60000) checkKeyRateLimits.delete(k); }, 120_000);

// Per-IP rate limit for /v2/lookup-signer/:pk_hash (max 30/min) — prevents
// enumeration of (pubkey → email) bindings even though only exact hash matches.
const lookupSignerRateLimits = new Map();
function lookupSignerRateOk(ip) {
  const now = Date.now();
  const b = lookupSignerRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= 30) return false;
  b.count++; lookupSignerRateLimits.set(ip, b); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of lookupSignerRateLimits) if (now > v.resetAt + 60000) lookupSignerRateLimits.delete(k); }, 120_000);

// Per-IP rate limits for /v2/envelopes/* (Model 2 multi-party signing).
// Create is throttled per API key to prevent quota abuse; view/sign are
// per-IP to blunt enumeration of unguessable but still finite env-ids.
const envCreateLimits = new Map();        // apiKey  -> { count, resetAt }
const envViewLimits   = new Map();        // ip      -> { count, resetAt }
const envSignLimits   = new Map();        // ip      -> { count, resetAt }
function envCreateRateOk(apiKey) {
  const now = Date.now();
  const b = envCreateLimits.get(apiKey) || { count: 0, resetAt: now + 3600_000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 3600_000; }
  if (b.count >= 50) return false;          // 50/hour/key
  b.count++; envCreateLimits.set(apiKey, b); return true;
}
function envViewRateOk(ip) {
  const now = Date.now();
  const b = envViewLimits.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60_000; }
  if (b.count >= 30) return false;          // 30/min/ip
  b.count++; envViewLimits.set(ip, b); return true;
}
function envSignRateOk(ip) {
  const now = Date.now();
  const b = envSignLimits.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60_000; }
  if (b.count >= 10) return false;          // 10/min/ip
  b.count++; envSignLimits.set(ip, b); return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of envCreateLimits) if (now > v.resetAt + 60_000) envCreateLimits.delete(k);
  for (const [k, v] of envViewLimits)   if (now > v.resetAt + 60_000) envViewLimits.delete(k);
  for (const [k, v] of envSignLimits)   if (now > v.resetAt + 60_000) envSignLimits.delete(k);
}, 120_000);

// Per-IP rate limit for /v2/status/:hash (max 60/min) — prevents hash enumeration
const statusRateLimits = new Map();
function statusRateOk(ip) {
  const now = Date.now();
  const b = statusRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= 60) return false;
  b.count++; statusRateLimits.set(ip, b); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of statusRateLimits) if (now > v.resetAt + 60000) statusRateLimits.delete(k); }, 120_000);


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
  // There is no Cloudflare in front of this deployment (Caddy edge -> nginx), so
  // CF-Connecting-IP is never set legitimately — trusting it let a client spoof
  // their IP and rotate past per-IP rate limits. nginx authoritatively sets
  // X-Real-IP to the real client (via real_ip from Caddy's X-Forwarded-For) and
  // clears CF-Connecting-IP, so use X-Real-IP only, then the socket as a fallback.
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

// ── HTML escaping for email templates (prevents HTML injection in Resend emails) ──
function escHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Mask an email for logs: keep first local char + full domain, drop the rest.
// e.g. "alice@example.com" -> "a***@example.com". Keeps logs debuggable without
// writing raw PII to stdout/journald.
function maskEmail(e) {
  const s = String(e || '');
  const at = s.indexOf('@');
  if (at < 1) return s ? '***' : '';
  return s[0] + '***' + s.slice(at);
}

// Mask a client IP for logs: keep the network prefix, drop the host part.
// IPv4 1.2.3.4 -> "1.2.x.x"; IPv6 keeps the first two hextets. Enough to spot a
// noisy /16 or subnet without storing a full, identifying address.
function maskIp(ip) {
  const s = String(ip || '');
  if (!s) return '';
  if (s.includes(':')) { const p = s.split(':'); return p.slice(0, 2).join(':') + '::x'; }
  const p = s.split('.');
  if (p.length === 4) return p[0] + '.' + p[1] + '.x.x';
  return '***';
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

// ── Merkle audit chain ────────────────────────────────────────────────────────
// Tamper-evident log. chain_hash commits to EVERY field of the entry except
// itself (canonical encoding, see relay/lib/audit-chain.js). The old preimage
// covered only {ts,event,hash,bytes,prev_hash} so the richer fields (device,
// views_left, sig, sig-validity) were unprotected, and verifyChain never
// recomputed the hash at all — chain_valid was a false assurance (#19).
const { auditEntryHash, verifyChain } = require('./lib/audit-chain');

function auditAppend(key, event, data = {}) {
  if (!key) return;
  if (!auditChain.has(key)) auditChain.set(key, []);
  const chain    = auditChain.get(key);
  const prevHash = chain.length > 0 ? chain[chain.length - 1].chain_hash : '0'.repeat(64);
  const entry    = { ts: new Date().toISOString(), event, prev_hash: prevHash, ...data };
  entry.chain_hash = auditEntryHash(entry);
  chain.push(entry);
  if (chain.length > MAX_AUDIT) chain.shift();
}

// ── ML-DSA handtekening verificatie ──────────────────────────────────────────
function verifyDsaSignature(payload, signature, pubKeyHex) {
  if (!mlDsa || !signature || !pubKeyHex) return { valid: false, reason: 'ML-DSA not available or no sig' };
  try {
    const pub = Buffer.from(pubKeyHex, 'hex');
    const sig = Buffer.from(signature, 'hex');
    const msg = Buffer.from(payload);
    const valid = registry.getSig(0x0002).verify(sig, msg, pub);
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
// Atomic write: tmp + rename eliminates the O_TRUNC window where a concurrent
// reader sees an empty file mid-write. Combined with the sanity check in
// /v2/reload-users this prevents the apiKeys-wipe race on plan_change.
async function _atomicWriteUsers(data) {
  const tmp = `${USERS_FILE}.tmp.${process.pid}.${Date.now()}`;
  await fs.promises.writeFile(tmp, JSON.stringify(data, null, 2));
  await fs.promises.rename(tmp, USERS_FILE);
}
function _writeUsersJson(data) {
  _usersWriteQueue = _usersWriteQueue.then(() => _atomicWriteUsers(data))
    .catch(e => log('warn', 'users_write_error', { err: e.message }));
  return _usersWriteQueue;
}
function _mutateUsersJson(fn) {
  _usersWriteQueue = _usersWriteQueue.then(async () => {
    const raw = await fs.promises.readFile(USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    fn(data);
    await _atomicWriteUsers(data);
  }).catch(e => log('warn', 'users_write_error', { err: e.message }));
  return _usersWriteQueue;
}

// ── Billing auto-grant: paid Pro plan → parasign entitlement ──────────────
// /*MARK:parasign_billing_autograt*/ Called from the plan-change path when an
// account moves to a paid plan (pro/licensed/enterprise). Reuses the exact
// account-level fan-out + persistence of /v2/admin/keys/set-parasign: flips the
// `parasign` flag on every member key of the account, then persists to users.json.
// Idempotent and additive - safe to call on every paid update-plan.
const PARASIGN_PAID_PLANS = new Set(['pro', 'business', 'licensed', 'enterprise']);
function grantParasignOnPaidPlan(accountId) {
  if (!accountId) return { ok: false, reason: 'no_account' };
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  if (members.size === 0) return { ok: false, reason: 'no_keys' };
  let changed = 0;
  for (const m of members) { const mv = apiKeys.get(m); if (mv && mv.parasign !== true) { mv.parasign = true; changed++; } }
  _mutateUsersJson(ud => {
    for (const entry of ud.api_keys) {
      if ((entry.account_id || entry.key) === accountId) entry.parasign = true;
    }
    ud.updated = new Date().toISOString();
  }).then(() => log('info', 'parasign_grant_on_paid_plan', { account: String(accountId).slice(0, 12), keys: members.size, changed, persisted: true }))
    .catch(we => log('warn', 'parasign_persist_failed', { err: we.message }));
  return { ok: true, keys: members.size, changed };
}

// -- ParaSign /v1 key issuance -- THE single generator -------------------------
// Used by BOTH /v2/user/parasign-keys (self-serve) and /v2/admin/keys/mint-parasign
// (admin), so there is exactly one psk_ format + one storage path (no drift).
// Mirrors the pgp_ mint in /v2/admin/keys: a CSPRNG token, inserted into the live
// apiKeys/accounts/accountKeys/kidIndex maps and persisted to users.json, bound to
// `accountId` and carrying the parasign grant so /v1 auth accepts it. Inherits the
// account's plan+email so the key clicks straight into the tiers.js/quota.js
// entitlement layer (quota is keyed by account_id + plan). Returns the FULL key
// ONCE (caller shows it a single time) plus a masked form for logging/listing.
function mintParasignKey(accountId, opts = {}) {
  if (!accountId) throw new Error('accountId required');
  const acct = accounts.get(accountId);
  const anchorRec = apiKeys.get(accountId);
  const plan = opts.plan || (acct && acct.plan) || (anchorRec && anchorRec.plan) || 'community';
  const email = (acct && acct.email) || (anchorRec && anchorRec.email) || '';
  const built = keysTable.buildParasignKeyRecord({
    accountId, plan, email, label: opts.label, test: !!opts.test,
    randomHex: crypto.randomBytes(32).toString('hex'),
  });
  const { key, record, usersEntry } = built;
  apiKeys.set(key, record);
  if (!accounts.has(accountId)) accounts.set(accountId, { account_id: accountId, plan, email, primary_api_key: null, label: '' });
  if (!accountKeys.has(accountId)) accountKeys.set(accountId, new Set());
  accountKeys.get(accountId).add(key);
  const kid = keysTable.assignKid(kidIndex, key, log);
  record.kid = kid;
  kidIndex.set(kid, key);
  _mutateUsersJson(ud => {
    ud.api_keys.push(usersEntry);
    ud.updated = new Date().toISOString();
  }).then(() => log('info', 'parasign_key_minted', { account: String(accountId).slice(0, 12), kid, mode: opts.test ? 'test' : 'live', plan: record.plan, persisted: true }))
    .catch(we => log('warn', 'parasign_key_persist_failed', { err: we.message }));
  return { key, kid, account_id: accountId, plan: record.plan, mode: opts.test ? 'test' : 'live', masked: maskKey(key), scope: 'parasign', created: record.created };
}

function loadUsers() {
  if (process.env.USERS_JSON) {
    try { const d = JSON.parse(process.env.USERS_JSON); (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||"",email:k.email||"",active:true,created:k.created||null,...keysTable.parseAccountFields(k)}); }); keysTable.rebuildKeyIndexes(apiKeys,accounts,accountKeys,kidIndex,log); log("info","users_loaded",{count:apiKeys.size,source:"env"}); return; } catch(e) { log("error","users_json_parse",{err:e.message}); }
  }
  try {
    const d = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    (d.api_keys || []).forEach(k => {
      if (k.active) apiKeys.set(k.key, {
        plan: k.plan, label: k.label||'', email: k.email||'', active: true, dsa_pub: k.dsa_pub||'',
        daily_uploads: 0, daily_reset_ts: Date.now() + 86_400_000,
        is_trial: !!(k.plan === 'community' && k.trial_metadata),
        trial_created: k.created ? new Date(k.created).getTime() : null,
        uploads_today: 0, last_upload_day: '',
        created: k.created || null,
        ...keysTable.parseAccountFields(k),
      });
    });
    keysTable.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log);
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
            plan: 'community', label: k.label||'', email: k.email||'', active: true, dsa_pub: '',
            daily_uploads: 0, daily_reset_ts: Date.now() + 86_400_000,
            is_trial: true, trial_created: k.created || Date.now(),
            uploads_today: 0, last_upload_day: '',
            ...keysTable.parseAccountFields(k),
          });
          loaded++;
        }
      } catch {}
    }
    if (loaded > 0) { keysTable.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log); log('info', 'trial_keys_loaded', { count: loaded }); }
  } catch(e) { /* file may not exist yet */ }
}

// Pubkey plan limits and TTL.
// _pubkeyTtl stays local: it tracks how long a *registered device pubkey*
// is retained, which is not in TIER_LIMITS' scope yet (the brief only maps
// devices count + view TTL + max views + monthly quotas + file size).
// _pubkeyMax now reads device caps from TIER_LIMITS via tiers.tierLimitNum so
// there is one source of truth for the per-tier device count.
const _pubkeyTtl = { free: 7 * 86_400_000, pro: 30 * 86_400_000, enterprise: 365 * 86_400_000 };
const _pubkeyMax = new Proxy({}, {
  get(_t, plan) { return tiers.tierLimitNum(plan, 'devices'); },
});
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
// URL-level SSRF guard, extracted to relay/lib/ssrf-guard.js for unit coverage.
const { isSsrfSafeUrl } = require('./lib/ssrf-guard');

// ── Safe outbound HTTPS request ───────────────────────────────────────────────
// Single helper used by every outbound request the relay makes (gossip,
// webhooks). Two-stage SSRF guard:
//   1. isSsrfSafeUrl(urlStr) - reject by URL (RFC1918, localhost, ports, ...)
//   2. dns.lookup(hostname)  - re-resolve and reject if the resolved IP is
//      itself unsafe (DNS-rebinding: a hostname that was public at
//      registration may have flipped to a private IP before the request fires)
// The request connects to the resolved IP directly (`hostname: resolved.address`)
// with Host + servername set to the original hostname so TLS verification
// still works. This pins the connection to the IP we just verified and
// closes the TOCTOU window between the lookup and the connect.
const _dnsPromises = require('dns').promises;
async function safeHttpsRequest(urlStr, opts = {}) {
  if (!isSsrfSafeUrl(urlStr)) {
    const err = new Error('SSRF: URL not safe'); err.code = 'SSRF_URL'; throw err;
  }
  const u = new URL(urlStr);
  const resolved = await _dnsPromises.lookup(u.hostname);
  if (!isSsrfSafeUrl('https://' + resolved.address + '/')) {
    const err = new Error('SSRF: resolved IP not safe (possible DNS rebinding)');
    err.code = 'SSRF_DNS'; err.resolved = resolved.address;
    throw err;
  }
  const headers = Object.assign({ Host: u.hostname }, opts.headers || {});
  return new Promise((resolve, reject) => {
    const r = https.request({
      hostname:   resolved.address,
      port:       u.port || 443,
      path:       u.pathname + (u.search || ''),
      method:     opts.method || 'POST',
      headers,
      servername: u.hostname,
      timeout:    opts.timeout || 5000,
    }, res2 => {
      const chunks = [];
      res2.on('data', c => chunks.push(c));
      res2.on('end',  () => resolve({ status: res2.statusCode, headers: res2.headers, body: Buffer.concat(chunks) }));
    });
    r.on('timeout', () => { r.destroy(new Error('request timeout')); });
    r.on('error',   reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}

// ── Webhook push ──────────────────────────────────────────────────────────────
async function pushWebhooks(apiKey, deviceId, event, data) {
  const hooks = webhooks.get(`${deviceId}:${acctOf(apiKey)}`) || [];
  for (const hook of hooks) {
    const payload = J({ event, device_id: deviceId, ts: new Date().toISOString(), ...data });
    const sig = hook.secret ? crypto.createHmac('sha256', hook.secret).update(payload).digest('hex') : '';
    try {
      await safeHttpsRequest(hook.url, {
        method:  'POST',
        timeout: 5000,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload),
                   'X-Paramant-Event': event, 'X-Paramant-Sig': sig, 'User-Agent': `paramant-relay/${VERSION}` },
        body: payload,
      });
      stats.webhooks_sent++;
    } catch(e) {
      if      (e.code === 'SSRF_URL') log('warn', 'webhook_ssrf_blocked',          { url: (hook.url||'').slice(0,60) });
      else if (e.code === 'SSRF_DNS') log('warn', 'webhook_dns_rebinding_blocked', { url: (hook.url||'').slice(0,60), resolved: e.resolved });
      else                            log('warn', 'webhook_fail',                  { url: (hook.url||'').slice(0,60), err: e.message });
    }
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

// Mask a secret API key for list/observation output. Canonical implementation
// lives in lib/keys-table.js (unit-tested); aliased here for the admin handlers.
const maskKey = keysTable.maskApiKey;

// ── DID-auth replay protection ────────────────────────────────────────────────
// The previous DID-auth signed ONLY req.url, so any captured (X-DID,
// X-DID-Signature) pair replayed forever against the same URL. We now bind a
// freshness window (X-DID-TS, ±DID_AUTH_SKEW_MS) and a one-time nonce
// (X-DID-Nonce) into the signed message, and reject any (did|nonce) we have
// already accepted. The nonce cache self-evicts after the freshness window
// (mirrors the _usedTotpCodes sweep) and is hard-capped to bound memory under a
// nonce flood (evict-oldest, like the relay registry).
const DID_AUTH_SKEW_MS  = 300_000;        // ±5 min, matches the /v2/relays/register window
const MAX_DID_NONCES     = 50_000;        // hard cap on the in-flight nonce cache
const _usedDidNonces = new Map();         // `${did}|${nonce}` → expiry ms
setInterval(() => { const now = Date.now(); for (const [k, exp] of _usedDidNonces) if (now > exp) _usedDidNonces.delete(k); }, 30_000);

// Canonical bytes a DID client must sign. Binding the method + url + timestamp +
// nonce makes each signature single-use and non-transferable across requests.
// Byte-identical recipe MUST be reproduced by the SDK:
//   `${method}\n${url}\n${ts}\n${nonce}`
function didAuthMessage(method, url, ts, nonce) {
  return Buffer.from(`${String(method || '').toUpperCase()}\n${url}\n${ts}\n${nonce}`, 'utf8');
}

// authByDid: verify a DID-auth credential with replay protection. `ctx` carries
// the request method and the freshness headers (ts, nonce). A missing/stale ts,
// missing/oversized nonce, or a previously-seen (did|nonce) yields NO principal
// (fail-closed) — the legacy bare-url signature is no longer accepted.
function authByDid(didStr, signature, ctx) {
  const entry = didRegistry.get(didStr);
  if (!entry) return null;
  const vm = entry.doc.verificationMethod?.[0];
  if (!vm || !vm.publicKeyHex) return null;

  const { method = 'GET', url = '', ts = '', nonce = '' } = (ctx && typeof ctx === 'object') ? ctx : { url: ctx };
  // Freshness: timestamp must be a finite ms-epoch within the skew window.
  const tsNum = Number(ts);
  if (!ts || !Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > DID_AUTH_SKEW_MS) {
    log('warn', 'did_auth_stale_or_missing_ts', { did: didStr.slice(0,30) });
    return null;
  }
  // Nonce: required, hex, bounded length (128 hex = 64 random bytes is plenty).
  if (!nonce || !/^[0-9a-fA-F]{16,128}$/.test(nonce)) {
    log('warn', 'did_auth_bad_nonce', { did: didStr.slice(0,30) });
    return null;
  }
  const nonceKey = `${didStr}|${nonce.toLowerCase()}`;
  if (_usedDidNonces.has(nonceKey)) {
    log('warn', 'did_auth_replay_blocked', { did: didStr.slice(0,30) });
    return null;
  }

  try {
    const rawKey = Buffer.from(vm.publicKeyHex, 'hex');
    // Wrap raw uncompressed P-256 point in DER-SPKI if not already encoded (0x30 = SEQUENCE tag)
    const spkiKey = rawKey[0] === 0x30 ? rawKey : Buffer.concat([P256_SPKI_PREFIX, rawKey]);
    const valid = crypto.verify(
      'SHA256',
      didAuthMessage(method, url, ts, nonce),
      { key: spkiKey, format: 'der', type: 'spki' },
      Buffer.from(signature, 'hex')
    );
    if (valid) {
      // Burn the nonce only after a valid signature, so an attacker cannot pre-
      // poison the cache with arbitrary nonces. Expires one skew-window out;
      // evict the oldest entry first if the cache is at capacity (flood guard).
      if (_usedDidNonces.size >= MAX_DID_NONCES) {
        const oldest = _usedDidNonces.keys().next().value;
        if (oldest !== undefined) _usedDidNonces.delete(oldest);
      }
      _usedDidNonces.set(nonceKey, Date.now() + DID_AUTH_SKEW_MS);
      return entry;
    }
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Dsa-Signature, Authorization, X-DID, X-DID-Signature, X-DID-TS, X-DID-Nonce');
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

// ── ParaID issuer registry (fase 2): file-backed, elke mutatie CT-verankerd ──
const PARAID_REGISTRY_FILE = process.env.PARAID_REGISTRY_FILE || '/data/paraid-issuers.json';
const paraidIssuers = paraidRegistry.createRegistry({ file: PARAID_REGISTRY_FILE });
try { log('info', 'paraid_registry_loaded', { issuers: paraidIssuers.load() }); }
catch (e) { log('warn', 'paraid_registry_load_error', { err: e.message }); }

// ── ParaID demo issuer: signs demo credentials so logged-in users have a real,
// registry-anchored credential to use. ESM (noble) loaded via dynamic import so
// signatures match the browser verifier. Absent key file -> issuance disabled.
const PARAID_ISSUER_KEY_FILE = process.env.PARAID_ISSUER_KEY_FILE || '/data/paraid-demo-authority.sk.json';
let paraidIssuer = null;
import('./lib/paraid-issuer.mjs')
  .then((m) => { paraidIssuer = m.createIssuer({ keyFile: PARAID_ISSUER_KEY_FILE }); log('info', 'paraid_issuer_loaded', { did: paraidIssuer.did }); })
  .catch((e) => { log('warn', 'paraid_issuer_unavailable', { err: e.message }); });

// ── Code-transparency manifest: in-memory + /data, CT-verankerd bij publish ──
const CODE_MANIFEST_FILE = process.env.CODE_MANIFEST_FILE || '/data/code-manifest.json';
let codeManifest = null;
try { codeManifest = JSON.parse(require('fs').readFileSync(CODE_MANIFEST_FILE, 'utf8')); }
catch (e) { if (e.code !== 'ENOENT') log('warn', 'code_manifest_load_error', { err: e.message }); }

function ctAppendParaidIssuer(eventType, did, payload) {
  const ts = new Date().toISOString();
  const valueHash = crypto.createHash('sha3-256')
    .update(eventType).update('|').update(did).update('|')
    .update(JSON.stringify(payload || {})).digest('hex');
  const leaf_hash = ctLeafHash(did, valueHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = { index, type: eventType, leaf_hash, tree_hash, did, payload: payload || {}, ts, proof };
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
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
// -- Optional static frontend serving (opt-in via SERVE_FRONTEND=true) --------
// Off by default: production serves frontend/ via nginx. Plug-and-play self-host
// installs (install.sh) set SERVE_FRONTEND=true so the relay can serve /setup,
// /dashboard, etc directly. See relay/lib/static-serve.js + ADR R011.
const _static = require('./lib/static-serve').createStaticHandler({
  serveFrontend: process.env.SERVE_FRONTEND === 'true',
  frontendRoot: process.env.FRONTEND_ROOT || '/app/frontend',
  log,
});
if (_static.serveFrontend) log('info', 'static_serving_enabled', { root: _static.frontendRoot });

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
  // Freshness factors that make a DID-auth credential single-use (replay guard):
  // the client signs `${method}\n${url}\n${ts}\n${nonce}` and sends ts/nonce here.
  const didTs     = req.headers['x-did-ts']    || '';
  const didNonce  = req.headers['x-did-nonce'] || '';
  let didAuthEntry = null;
  if (!apiKey && didHeader && didSig) {
    didAuthEntry = authByDid(didHeader, didSig, { method: req.method, url: req.url, ts: didTs, nonce: didNonce });
    if (didAuthEntry) log('info', 'did_auth_mode', { did: didHeader.slice(0,30) });
  }
  const dsaSig  = req.headers['x-dsa-signature'] || '';
  // DID-auth NEVER mints its own principal. A DID only authenticates as the API
  // key it was REGISTERED under: inherit that key's real plan/active. Keyless DIDs
  // (e.g. 'inv_' receiver-session DIDs, registered without an API key) therefore
  // grant NO authenticated principal here — they keep working only through the
  // per-endpoint INVITE_RE pubkey-exchange bypass, never as a general auth subject.
  // (Previously any valid DID-auth forged {plan:'pro',active:true}, which let an
  // anonymous attacker self-register an inv_ DID and ride it into a pro session.)
  const didOwner = (didAuthEntry && didAuthEntry.key) ? apiKeys.get(didAuthEntry.key) : null;
  const keyData = apiKeys.get(apiKey)
    || ((didOwner && didOwner.active) ? { ...didOwner, label: didAuthEntry.device_id } : null);
  // account_id is what Phase 3 counters key on: the owning API key (1:1 today),
  // or for DID-auth the key the DID was registered under — never the device id.
  if (keyData && !keyData.account_id) keyData.account_id = apiKey || (didAuthEntry && didAuthEntry.key) || null;
  const clientIp = getClientIp(req);

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
  // Opt-in static frontend (off by default). Runs before the mode gate and the
  // API routes so plug-and-play installs can serve /setup, /dashboard, etc.
  // API paths are excluded inside maybeServeStatic, so production is unaffected.
  if (_static.maybeServeStatic(req, res, path)) return;
  if (path === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, relay: SECTOR, version: VERSION, status: 'operational', protocol: 'ghost-pipe-v2', docs: 'https://paramant.app/docs' }));
  }
  if (!modeAllows(path)) { res.writeHead(405); return res.end(J({ error: 'Not available in this relay mode', mode: RELAY_MODE })); }

  // ── ParaID issuer registry: publiek leesbaar, vóór de /v1-Bearer-gate ───────
  // Verifiers must be able to check issuer registrations without an API key.
  if (path === '/v1/paraid/issuers' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(J({ issuers: paraidIssuers.list() }));
  }
  // Issue a demo credential bound to a holder key. Rate-limited per IP. The
  // wallet page is session-gated client-side; issuance itself only ever mints
  // clearly-labelled demo credentials from the Paramant Demo Authority.
  if (path === '/v1/paraid/issue-demo' && req.method === 'POST') {
    if (!paraidIssuer) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'demo issuer not configured' })); }
    if (!envCreateRateOk('paraid:' + clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' }); return res.end(J({ error: 'issuance quota exceeded, try later' })); }
    let body;
    try { body = JSON.parse((await readBody(req, 8192)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    const out = paraidIssuer.issue({ holderBindingB64url: String(body.holder_binding || ''), subject: body.subject || {} });
    if (!out.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J(out)); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J(out));
  }
  // Substantial tier: issue from a passport MRZ. The relay re-validates the MRZ
  // check digits and derives age_over_18 + nationality itself; only those two
  // attributes are sealed, never name/birthdate/document number.
  if (path === '/v1/paraid/issue-document' && req.method === 'POST') {
    if (!paraidIssuer || !paraidIssuer.issueSubstantial) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'issuer not configured' })); }
    if (!envCreateRateOk('paraid:' + clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' }); return res.end(J({ error: 'issuance quota exceeded, try later' })); }
    let body;
    try { body = JSON.parse((await readBody(req, 8192)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    const out = paraidIssuer.issueSubstantial({ holderBindingB64url: String(body.holder_binding || ''), mrzLine1: String(body.mrz_line1 || ''), mrzLine2: String(body.mrz_line2 || ''), now: new Date() });
    if (!out.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J(out)); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J(out));
  }
  // ── Code-transparency manifest: publiek leesbaar, vóór de /v1-Bearer-gate ───
  // The SHA3-256 inventory of the deployed frontend, CT-anchored on publish.
  // Independent monitors fetch this and compare it against the live assets.
  if (path === '/v1/code-manifest' && req.method === 'GET') {
    if (!codeManifest) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'no manifest published yet' })); }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(J(codeManifest));
  }

  // ── ParaSign Open Developer-API (/v1) ────────────────────────────────────────
  // Thin public layer over the internal /v2 envelope machinery. Owns its own
  // Bearer psk_ auth + parasign-scope gate (independent of the X-Api-Key path).
  // All relay internals it needs are injected; see lib/parasign-open-api.js.
  if (path === '/v1' || path.startsWith('/v1/')) {
    // publicOrigin drives the sign_url handed out to signers, so it must NOT be
    // attacker-controllable via a spoofed Host / X-Forwarded-Host header (else an
    // attacker poisons the signing links -> phishing). Precedence:
    //   1) PARASIGN_PUBLIC_ORIGIN — explicit operator config, always wins. Every
    //      self-hosted / non-paramant.app deploy MUST set this.
    //   2) the request Host, but ONLY when it is on the paramant.app allowlist,
    //      and then forced to https (the proxy always terminates TLS in prod).
    //   3) a hard-coded safe default otherwise.
    const _host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
    const _hostOk = /^([a-z0-9-]+\.)*paramant\.app$/i.test(_host);
    const _publicOrigin = process.env.PARASIGN_PUBLIC_ORIGIN
      || (_hostOk ? `https://${_host}` : 'https://paramant.app');
    return parasignOpenApi.route({
      req, res, method: req.method, path, query, clientIp,
      authHeader: req.headers['authorization'] || '',
      publicOrigin: _publicOrigin,
      apiKeys,
      envStore: _envStore(),
      envCreateRateOk,
      safeHttpsRequest,
      canonicalJSON: parasign.canonicalJSON,
      sigEngine: (mlDsa && registry) ? registry.getSig(0x0002) : null,
      relayIdentity,
      signQuotaGate: async (accountId, plan) => quota.gateSign(redisClient, accountId, tiers.tierLimitNum(plan, 'signs_month'), log),
      readBody, J, log,
    });
  }

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
      signatures: mlDsa ? 'ML-DSA-65 (NIST FIPS 204)' : 'ML-DSA-65 unavailable: signing disabled',
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

  // ── GET /v2/capabilities — public, no auth ─────────────────────────────────
  // Advertises the wire format version and list of loaded crypto algorithms.
  // Built dynamically from the registry so this endpoint stays correct as
  // algorithms are added or removed. See docs/wire-format-v1.md.
  if (req.method === 'GET' && path === '/v2/capabilities') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J(registry.listSupported()));
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

  // -- First-time onboarding wizard (ADR R005) ----------------------------
  // Public, no auth. Gated on first-time mode: the relay is considered fresh
  // while it has no API keys loaded (apiKeys.size === 0), or when SETUP_MODE
  // is explicitly set. These are scaffolding stubs: /v2/setup/check reports
  // the gate; /v2/setup/apply is not yet implemented (returns 501).
  function _setupModeOn() {
    return apiKeys.size === 0 || process.env.SETUP_MODE === 'true';
  }

  // GET /v2/setup/check -- is the relay in first-time setup mode?
  if (req.method === 'GET' && path === '/v2/setup/check') {
    const setupMode = _setupModeOn();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ setupMode, ready: !setupMode }));
  }

  // GET /v2/setup/dns-check?domain=... -- informational DNS preflight.
  // Gated on setup mode so it cannot be used as a general resolver.
  if (req.method === 'GET' && path === '/v2/setup/dns-check') {
    if (!_setupModeOn()) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Setup is already complete on this relay.' }));
    }
    const domain = (query.domain || '').toString().trim().toLowerCase();
    if (!domain || !/^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/.test(domain)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'A valid fully-qualified domain is required.' }));
    }
    try {
      const addrs = await require('dns').promises.lookup(domain, { all: true });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, domain, resolves: addrs.length > 0, addresses: addrs.map(a => a.address) }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, domain, resolves: false, error: e.code || e.message }));
    }
  }

  // POST /v2/setup/apply -- apply first-time configuration.
  // Writes .env (atomic, backing up any existing one), mints the admin and
  // optional first-user API keys via the canonical apiKeys + users.json path,
  // applies a compliance preset, and records a setup_completed audit event.
  // TLS issuance is intentionally NOT run here -- it requires root + certbot
  // and is handled by install.sh / scripts/paramant-tls-bootstrap.sh.
  if (req.method === 'POST' && path === '/v2/setup/apply') {
    if (!_setupModeOn()) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Setup is already complete on this relay.' }));
    }
    try {
      const body = JSON.parse((await readBody(req, 16384)).toString());
      const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      const domainRe = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/;

      // -- validate sectors --
      const VALID_SECTORS = new Set(['general', 'health', 'finance', 'legal', 'iot']);
      const sectors = Array.isArray(body.sectors) ? body.sectors.filter(s => VALID_SECTORS.has(s)) : [];
      if (sectors.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'Select at least one valid sector.' }));
      }
      // -- validate domain (null = localhost mode) --
      let domain = null;
      if (typeof body.domain === 'string' && body.domain.trim()) {
        domain = body.domain.trim().toLowerCase();
        if (!domainRe.test(domain)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'Invalid domain. Leave blank for localhost mode.' }));
        }
      }
      // -- validate admin email --
      const adminEmail = (body.adminEmail || (body.admin && body.admin.email) || '').toString().trim();
      if (!adminEmail || adminEmail.length > 254 || !emailRe.test(adminEmail)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'A valid admin email is required.' }));
      }
      const enableTotp = body.enableTotp !== false;
      const autoTls = !!body.autoTls && !!domain;
      // -- compliance preset --
      const VALID_PLANS = new Set(['community', 'dev', 'pro', 'licensed', 'enterprise']);
      const PRESETS = {
        generic:  { BLOB_TTL_MS: 3600000, AUDIT_RETENTION_DAYS: 90,   ML_DSA_REQUIRED: 'false', CRYPTO_MODE: 'core' },
        nen7510:  { BLOB_TTL_MS: 1800000, AUDIT_RETENTION_DAYS: 2555, ML_DSA_REQUIRED: 'true',  CRYPTO_MODE: 'core' },
        iec62443: { BLOB_TTL_MS: 900000,  AUDIT_RETENTION_DAYS: 365,  ML_DSA_REQUIRED: 'true',  CRYPTO_MODE: 'core' },
        dora:     { BLOB_TTL_MS: 3600000, AUDIT_RETENTION_DAYS: 1825, ML_DSA_REQUIRED: 'true',  CRYPTO_MODE: 'core' },
        custom:   {},
        none:     {},
      };
      const tpl = Object.prototype.hasOwnProperty.call(PRESETS, body.complianceTemplate) ? body.complianceTemplate : 'generic';
      const preset = PRESETS[tpl];
      // -- optional first user --
      let firstUser = null;
      const fuEmail = (body.firstUserEmail || (body.first_user && body.first_user.email) || '').toString().trim();
      if (fuEmail) {
        if (fuEmail.length > 254 || !emailRe.test(fuEmail)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'First-user email is invalid. Leave it blank to skip.' }));
        }
        firstUser = {
          email: fuEmail,
          label: (body.firstUserLabel || '').toString().slice(0, 128) || 'first-user',
          plan: VALID_PLANS.has(body.firstUserPlan) ? body.firstUserPlan : 'pro',
        };
      }

      // -- mint keys (canonical apiKeys + users.json pattern) --
      const mint = (plan, label, email) => {
        const k = 'pgp_' + crypto.randomBytes(32).toString('hex');
        apiKeys.set(k, { plan, label, email, active: true });
        return k;
      };
      const adminKey = mint('enterprise', 'setup-admin', adminEmail);
      const firstUserKey = firstUser ? mint(firstUser.plan, firstUser.label, firstUser.email) : null;
      await _mutateUsersJson(d => {
        d.api_keys = d.api_keys || [];
        const now = new Date().toISOString();
        d.api_keys.push({ key: adminKey, plan: 'enterprise', label: 'setup-admin', email: adminEmail, active: true, created: now, is_admin: true });
        if (firstUserKey) d.api_keys.push({ key: firstUserKey, plan: firstUser.plan, label: firstUser.label, email: firstUser.email, active: true, created: now });
        d.updated = now;
      }).catch(we => log('warn', 'setup_persist_failed', { err: we.message }));

      // -- write .env (atomic temp+rename, back up existing) --
      const envPath = process.env.SETUP_ENV_FILE || path.join(process.cwd(), '.env');
      const envLines = [
        '# Generated by Paramant /setup on ' + new Date().toISOString(),
        'SECTORS=' + sectors.join(','),
        domain ? ('DOMAIN=' + domain) : '# DOMAIN= (localhost mode)',
        'RELAY_MODE=' + (domain ? 'domain' : 'localhost'),
        'AUTO_TLS=' + (autoTls ? 'true' : 'false'),
        'ADMIN_EMAIL=' + adminEmail,
        'ADMIN_TOTP_ENABLED=' + (enableTotp ? 'true' : 'false'),
        'COMPLIANCE_TEMPLATE=' + tpl,
      ].concat(Object.keys(preset).map(k => k + '=' + preset[k]))
       .concat(['SETUP_MODE=false']);
      let envWritten = false, envBackedUp = false;
      try {
        if (fs.existsSync(envPath)) { fs.copyFileSync(envPath, envPath + '.pre-setup'); envBackedUp = true; }
        const tmp = envPath + '.tmp.' + process.pid + '.' + Date.now();
        fs.writeFileSync(tmp, envLines.join('\n') + '\n', { mode: 0o600 });
        fs.renameSync(tmp, envPath);
        envWritten = true;
      } catch (we) { log('warn', 'setup_env_write_failed', { err: we.message, path: envPath }); }

      // -- audit --
      try { auditAppend(adminKey, 'setup_completed', { sectors: sectors.join(','), domain: domain || 'localhost', template: tpl, tls: autoTls, first_user: !!firstUserKey }); } catch (ae) { log('warn', 'setup_audit_failed', { err: ae.message }); }
      log('info', 'setup_completed', { sectors: sectors.join(','), domain: domain || 'localhost', template: tpl, env_written: envWritten });

      const proto = domain ? 'https' : 'http';
      const host = domain || (req.headers.host || 'localhost');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({
        ok: true,
        admin_api_key: adminKey,
        admin_api_key_masked: adminKey.slice(0, 12) + '...',
        first_user_api_key: firstUserKey,
        first_user_api_key_masked: firstUserKey ? firstUserKey.slice(0, 12) + '...' : null,
        sectors,
        compliance_template: tpl,
        env_written: envWritten,
        env_backed_up: envBackedUp,
        tls: autoTls ? 'pending' : 'n/a',
        next_step: envWritten ? 'restart_relay' : 'all_systems_go',
        dashboard_url: proto + '://' + host + '/dashboard',
        health_url: proto + '://' + host + '/all-systems-go',
      }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // GET /v2/health/deep -- aggregated readiness check for the post-setup page.
  // Public read (no auth) so the setup wizard and /all-systems-go can show it.
  if (req.method === 'GET' && path === '/v2/health/deep') {
    const checks = [];
    const add = (name, status, detail) => checks.push({ name, status, detail });

    add('relay', 'green', 'relay ' + VERSION + ' (' + SECTOR + ') up');

    const cmode = process.env.CRYPTO_MODE || 'core';
    add('crypto', mlDsa ? 'green' : 'yellow',
      mlDsa ? ('ML-DSA-65 loaded, mode=' + cmode) : ('ML-DSA-65 unavailable (build @paramant/core), mode=' + cmode));

    try {
      const dir = process.env.SETUP_ENV_FILE ? path.dirname(process.env.SETUP_ENV_FILE) : process.cwd();
      const probe = path.join(dir, '.health-write-' + process.pid);
      fs.writeFileSync(probe, 'ok'); fs.unlinkSync(probe);
      add('storage', 'green', 'data dir writable');
    } catch (e) { add('storage', 'red', 'not writable: ' + (e.code || e.message)); }

    const rs = ramStatus();
    add('memory', rs.ram_ok ? 'green' : 'yellow', rs.rss_mb + 'MB rss / ' + rs.ram_limit_mb + 'MB limit');

    try {
      if (typeof fs.statfsSync === 'function') {
        const st = fs.statfsSync(process.cwd());
        const freeGb = (st.bsize * st.bavail) / 1e9;
        add('disk', freeGb > 1 ? 'green' : 'yellow', freeGb.toFixed(1) + 'GB free');
      } else { add('disk', 'yellow', 'statfs unavailable on this Node'); }
    } catch (e) { add('disk', 'yellow', e.code || 'unknown'); }

    let tlsStatus = 'yellow', tlsDetail = 'TLS terminated at the edge (not on this relay)';
    try {
      const certFile = process.env.TLS_CERT_FILE || path.join(process.cwd(), 'deploy/certs/cert.pem');
      if (fs.existsSync(certFile) && typeof crypto.X509Certificate === 'function') {
        const cert = new crypto.X509Certificate(fs.readFileSync(certFile));
        const days = Math.floor((new Date(cert.validTo).getTime() - Date.now()) / 86400000);
        tlsStatus = days > 14 ? 'green' : (days > 0 ? 'yellow' : 'red');
        tlsDetail = days + ' days until expiry';
      }
    } catch (e) { tlsDetail = 'cert unreadable: ' + (e.code || e.message); }
    add('tls', tlsStatus, tlsDetail);

    add('users', apiKeys.size > 0 ? 'green' : 'yellow', apiKeys.size + ' API key(s) loaded');
    add('audit', 'green', 'Merkle hash chain active');

    const rank = { green: 0, yellow: 1, red: 2 };
    const overall = checks.reduce((m, c) => (rank[c.status] > rank[m] ? c.status : m), 'green');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ overall, version: VERSION, sector: SECTOR, checks }));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // User TOTP endpoints (internal — X-Internal-Auth only)
  // ═══════════════════════════════════════════════════════════════════════

  function _internalOk() {
    const tok = process.env.INTERNAL_AUTH_TOKEN;
    return !!tok && typeof req.headers["x-internal-auth"] === "string"
      && safeEqual(req.headers["x-internal-auth"], tok);
  }
  function _internalReject() {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(J({ error: "unauthorized" }));
  }

  // POST /v2/user/setup-totp
  if (req.method === "POST" && path === "/v2/user/setup-totp") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, provisional } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const existing = await userTotp.getUserTotpSecret(redisClient, user_id);
      if (existing) {
        // Idempotent: if provisional (not yet activated), return existing secret
        const activeVal = await redisClient.get(`paramant:user:totp_active:${user_id}`);
        if (activeVal === "true") {
          res.writeHead(409); return res.end(J({ error: "totp_already_configured" }));
        }
        // Backup codes are one-time: shown at first setup, not re-retrievable
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(J({ secret: existing, backup_codes: [] }));
      }
      const secret = userTotp.generateTotpSecret();
      await userTotp.storeUserTotpSecret(redisClient, user_id, secret);
      const activeKey = `paramant:user:totp_active:${user_id}`;
      if (provisional) {
        await redisClient.set(activeKey, "false", { EX: 14 * 86400 });
      } else {
        await redisClient.set(activeKey, "true");
      }
      // Backup codes are NOT minted here. They are generated once, at the moment
      // activation succeeds (/v2/user/activate-totp), so a reloaded setup page, a
      // second tab, or a re-issued setup link can never strand the user on an
      // empty backup-code set. The setup step only provisions the TOTP secret.
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ secret, backup_codes: [] }));
    } catch (err) {
      console.error("[user/setup-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/verify-totp
  if (req.method === "POST" && path === "/v2/user/verify-totp") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, totp } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !totp) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      if (!userMfaAttemptOk(user_id)) { res.writeHead(429); return res.end(J({ error: "too_many_attempts" })); }
      const secret = await userTotp.getUserTotpSecret(redisClient, user_id);
      if (!secret) { res.writeHead(404); return res.end(J({ error: "no_totp_setup" })); }
      const result = await verifyTotpGeneric(totp, secret, {
        algorithm: "sha256", window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      if (result && result.valid) userMfaAttemptReset(user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J(result));
    } catch (err) {
      console.error("[user/verify-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/activate-totp
  if (req.method === "POST" && path === "/v2/user/activate-totp") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      await redisClient.set(`paramant:user:totp_active:${user_id}`, "true");
      // Single source of truth for backup codes: mint them here, at the one moment
      // activation succeeds, and return them exactly once. Generating them at
      // activation (not at the QR/setup step) is what makes the whole flow robust
      // against reloads, second tabs, and re-issued setup links.
      await redisClient.del(`paramant:user:backup_codes_plaintext:${user_id}`);
      const backupCodes = await userTotp.regenerateBackupCodes(redisClient, user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ success: true, backup_codes: backupCodes }));
    } catch (err) {
      console.error("[user/activate-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/consume-backup
  if (req.method === "POST" && path === "/v2/user/consume-backup") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, code } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !code) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      if (!userMfaAttemptOk(user_id)) { res.writeHead(429); return res.end(J({ error: "too_many_attempts" })); }
      const result = await userTotp.consumeBackupCode(redisClient, user_id, code);
      if (result && (result.valid || result.success)) userMfaAttemptReset(user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J(result));
    } catch (err) {
      console.error("[user/consume-backup]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/regenerate-backup
  if (req.method === "POST" && path === "/v2/user/regenerate-backup") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      const codes = await userTotp.regenerateBackupCodes(redisClient, user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ backup_codes: codes }));
    } catch (err) {
      console.error("[user/regenerate-backup]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/delete-totp
  if (req.method === "POST" && path === "/v2/user/delete-totp") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      await userTotp.deleteUserTotp(redisClient, user_id);
      await redisClient.del(`paramant:user:totp_active:${user_id}`);
      await redisClient.del(`paramant:user:backup_codes_plaintext:${user_id}`);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ success: true }));
    } catch (err) {
      console.error("[user/delete-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }



  // POST /v2/user/get-totp-provisional — return existing provisional secret if present
  if (req.method === "POST" && path === "/v2/user/get-totp-provisional") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id } = JSON.parse((await readBody(req, 4096)).toString());
      const secret = await userTotp.getUserTotpSecret(redisClient, user_id);
      if (!secret) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(J({ exists: false }));
      }
      const activeRaw = await redisClient.get(`paramant:user:totp_active:${user_id}`);
      if (activeRaw === "true") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(J({ exists: false }));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ exists: true, secret, backup_codes: [] }));
    } catch (err) {
      console.error("[user/get-totp-provisional]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Account-bound signing identity (ML-DSA-65 public-key enrollment)
  // ═══════════════════════════════════════════════════════════════════════
  // Stores the *public half* of a user's signing key. Private keys never
  // reach the server. Multi-device (array per user); revoke keeps history.
  // Internal — X-Internal-Auth only — the admin server proxies user-session
  // requests through these.

  // POST /v2/user/signing-key — enroll a new pubkey. TOTP-gated.
  if (req.method === "POST" && path === "/v2/user/signing-key") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, pk_b64, label, totp } = JSON.parse((await readBody(req, 16384)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      if (!pk_b64 || typeof pk_b64 !== "string") { res.writeHead(400); return res.end(J({ error: "missing_pk_b64" })); }
      if (!totp || !/^\d{6}$/.test(String(totp))) { res.writeHead(400); return res.end(J({ error: "totp_required" })); }
      // TOTP gate — sensitive op, prevents session-hijack pk-swap
      const totpSecret = await userTotp.getUserTotpSecret(redisClient, user_id);
      if (!totpSecret) { res.writeHead(403); return res.end(J({ error: "no_totp_setup" })); }
      const totpResult = await verifyTotpGeneric(totp, totpSecret, {
        algorithm: "sha256", window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      if (!totpResult.valid) { res.writeHead(403); return res.end(J({ error: "invalid_totp" })); }
      // Store (server-side pk_hash computation — never trust client)
      let result;
      try {
        result = await userSigning.storeSigningPk(redisClient, user_id, { pk_b64, label });
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));
      }
      const ctEntry = ctAppendSigningPkEvent("signing_pk_enrolled", user_id, result.entry.pk_hash_sha3);
      log("info", "signing_pk_enrolled", {
        user_id: String(user_id).slice(0, 12) + "…",
        pk_hash: result.entry.pk_hash_sha3.slice(0, 16) + "…",
        reenrolled: result.reenrolled,
        ct_index: ctEntry.index,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({
        ok: true,
        pk_hash_sha3: result.entry.pk_hash_sha3,
        label: result.entry.label,
        enrolled_at: result.entry.enrolled_at,
        reenrolled: result.reenrolled,
        ct_index: ctEntry.index,
      }));
    } catch (err) {
      console.error("[user/signing-key POST]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // GET /v2/user/signing-key — list the user's enrolled keys (no TOTP, read-only).
  // Returns metadata only (pk_hash, label, timestamps); pk_b64 is intentionally
  // omitted so the index leaks no key material if the list response is logged.
  if (req.method === "GET" && path === "/v2/user/signing-key") {
    if (!_internalOk()) return _internalReject();
    try {
      const user_id = query.user_id;
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const arr = await userSigning.getSigningPks(redisClient, user_id);
      const projected = arr.map(e => ({
        alg: e.alg,
        pk_hash_sha3: e.pk_hash_sha3,
        label: e.label,
        enrolled_at: e.enrolled_at,
        revoked_at: e.revoked_at,
      }));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, keys: projected, total: projected.length }));
    } catch (err) {
      console.error("[user/signing-key GET]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // DELETE /v2/user/signing-key — revoke a pubkey. TOTP-gated. Keeps history
  // (sets revoked_at) so older envelopes remain verifiable as "valid at signing time".
  if (req.method === "DELETE" && path === "/v2/user/signing-key") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, pk_hash_sha3, totp } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !pk_hash_sha3) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      if (!totp || !/^\d{6}$/.test(String(totp))) { res.writeHead(400); return res.end(J({ error: "totp_required" })); }
      const totpSecret = await userTotp.getUserTotpSecret(redisClient, user_id);
      if (!totpSecret) { res.writeHead(403); return res.end(J({ error: "no_totp_setup" })); }
      const totpResult = await verifyTotpGeneric(totp, totpSecret, {
        algorithm: "sha256", window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      if (!totpResult.valid) { res.writeHead(403); return res.end(J({ error: "invalid_totp" })); }
      let result;
      try {
        result = await userSigning.revokeSigningPk(redisClient, user_id, pk_hash_sha3);
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));
      }
      if (!result.revoked) {
        const code = result.reason === "not_found" ? 404 : 409;
        res.writeHead(code, { "Content-Type": "application/json" });
        return res.end(J({ error: result.reason }));
      }
      const ctEntry = ctAppendSigningPkEvent("signing_pk_revoked", user_id, pk_hash_sha3);
      log("info", "signing_pk_revoked", {
        user_id: String(user_id).slice(0, 12) + "…",
        pk_hash: pk_hash_sha3.slice(0, 16) + "…",
        ct_index: ctEntry.index,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, revoked_at: result.entry.revoked_at, ct_index: ctEntry.index }));
    } catch (err) {
      console.error("[user/signing-key DELETE]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/signing-key/tofu — enrol a signing pubkey gated by an EMAIL-
  // BOUND invite token + the account's own email, INSTEAD of TOTP, for a
  // first-time (TOFU) invitee who has no TOTP. The relay self-verifies as
  // strictly as the TOTP gate it replaces — it does NOT merely trust the caller:
  //   GATE 1  the invite token must match this envelope party (PR-0, email-bound);
  //   GATE 2  the party's bound email MUST equal THIS account's own email
  //           (so a pubkey can only land on the account the invite was for —
  //           no path to set a key on someone else's account);
  //   GATE 3  one-shot per party slot (a single TOFU enrol per invite);
  //   + the cross-account-conflict check inside storeSigningPk still applies.
  // No valid invite token -> no enrol. Internal-auth only (admin proxy).
  if (req.method === "POST" && path === "/v2/user/signing-key/tofu") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, pk_b64, label, envelope_id, party_index, invite_token } = JSON.parse((await readBody(req, 16384)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      if (!pk_b64 || typeof pk_b64 !== "string") { res.writeHead(400); return res.end(J({ error: "missing_pk_b64" })); }
      if (!envelope_id || !invite_token) { res.writeHead(400); return res.end(J({ error: "missing_invite_context" })); }
      const pi = parseInt(party_index, 10);
      if (!Number.isInteger(pi) || pi < 0) { res.writeHead(400); return res.end(J({ error: "invalid_party_index" })); }

      const store = _envStore();
      if (!store) { res.writeHead(503); return res.end(J({ error: "envelope_store_unavailable" })); }

      // GATE 1 — invite token must match this envelope party (timing-safe, PR-0).
      if (!(await store.checkInviteToken(envelope_id, pi, invite_token))) {
        res.writeHead(403); return res.end(J({ error: "invalid_invite_token" }));
      }
      // GATE 2 — the party's bound email MUST equal THIS account's email.
      const view = await store.getForParty(envelope_id, pi, invite_token);
      const partyEmailHash = view && view.party ? (view.party.email_hash || "") : "";
      let acctEmail = "";
      try { acctEmail = (JSON.parse((await redisClient.get(`paramant:user:meta:${user_id}`)) || "{}").email) || ""; } catch {}
      const acctEmailHash = envelopeMod.partyEmailHash(acctEmail);
      // Timing-safe hex compare (the same helper envelope.js sign() uses) — for
      // consistency, so the unsafe `!==` pattern is never copied to a spot where
      // it would matter. safeHexEqual returns false for empty/length-mismatch too.
      if (!envelopeMod.safeHexEqual(partyEmailHash, acctEmailHash)) {
        res.writeHead(403); return res.end(J({ error: "account_email_mismatch" }));
      }
      // GATE 3 — one-shot per party slot (NX). Released on store failure below.
      const enrolKey = `paramant:tofu_enrol:${envelope_id}:${pi}`;
      const firstEnrol = await redisClient.set(enrolKey, String(user_id), { NX: true, EX: 30 * 86400 });
      if (firstEnrol === null) { res.writeHead(409); return res.end(J({ error: "already_enrolled" })); }

      // Store (server-side pk_hash; cross-account-conflict check inside).
      let result;
      try {
        result = await userSigning.storeSigningPk(redisClient, user_id, { pk_b64, label });
      } catch (e) {
        await redisClient.del(enrolKey).catch(() => {});
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));   // e.g. 'pubkey already enrolled to a different account'
      }
      const ctEntry = ctAppendSigningPkEvent("signing_pk_enrolled_tofu", user_id, result.entry.pk_hash_sha3);
      log("info", "signing_pk_enrolled_tofu", {
        user_id: String(user_id).slice(0, 12) + "…",
        pk_hash: result.entry.pk_hash_sha3.slice(0, 16) + "…",
        envelope: String(envelope_id).slice(0, 10) + "…", party: pi, ct_index: ctEntry.index,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, pk_hash_sha3: result.entry.pk_hash_sha3, enrolled_at: result.entry.enrolled_at, ct_index: ctEntry.index }));
    } catch (err) {
      console.error("[user/signing-key/tofu]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/signing-key/attested — enrol a signing pubkey gated by a
  // PASSKEY STEP-UP the admin already verified, INSTEAD of TOTP. This is the
  // "your sign-in passkey IS your signing key" path: a logged-in user who has a
  // passkey proves possession with a fresh WebAuthn assertion (verified in the
  // admin server, which owns rpId/origin — the relay never verifies assertions,
  // see the storage block below), and that step-up authorises the bind. It lets
  // a passkey-only account (no TOTP) enrol a signing key at all, which the
  // TOTP-gated route above cannot. The relay does NOT blindly trust the caller:
  //   GATE 1  internal-auth only (admin proxy);
  //   GATE 2  the account MUST already have >=1 active passkey credential — with
  //           no passkey there is nothing the admin could have stepped up, so a
  //           TOTP-less, passkey-less account can never reach a TOTP-free bind;
  //   + the cross-account-conflict check inside storeSigningPk still applies, and
  //   the server recomputes pk_hash (a client-supplied hash is never trusted).
  // Mirrors /tofu's "as strict as the TOTP gate it replaces" property.
  if (req.method === "POST" && path === "/v2/user/signing-key/attested") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, pk_b64, label, step_up_token } = JSON.parse((await readBody(req, 16384)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      if (!pk_b64 || typeof pk_b64 !== "string") { res.writeHead(400); return res.end(J({ error: "missing_pk_b64" })); }
      // GATE 1 (Auth M1) — a FRESH, one-shot step-up proof. The admin mints this
      // only after a live WebAuthn assertion and binds it to this user in Redis;
      // the relay consumes it atomically (getDel) and checks the binding. Without
      // it, "a passkey exists" (the old gate 2) — or any second admin code path
      // that skips the step-up ceremony — could enroll an attacker's signing key
      // on a hijacked session. The relay now enforces the step-up independently.
      if (typeof step_up_token !== "string" || !/^[a-f0-9]{64}$/.test(step_up_token)) {
        res.writeHead(403); return res.end(J({ error: "step_up_required" }));
      }
      if (!redisClient || !redisClient.isReady) { res.writeHead(503); return res.end(J({ error: "step_up_store_unavailable" })); }
      const _suKey = `paramant:signing:stepup:${step_up_token}`;
      const _suRaw = redisClient.getDel
        ? await redisClient.getDel(_suKey)
        : await (async () => { const v = await redisClient.get(_suKey); if (v !== null) await redisClient.del(_suKey); return v; })();
      let _su = null; try { _su = _suRaw ? JSON.parse(_suRaw) : null; } catch { _su = null; }
      // Freshness is enforced by the Redis EX on the token; a returned value means
      // still-valid. Bind the token to this exact account.
      if (!_su || _su.user_id !== user_id) { res.writeHead(403); return res.end(J({ error: "step_up_invalid" })); }
      // GATE 2 — the account must actually have a passkey (the factor the admin
      // stepped up). No passkey -> no attested bind (fall back to the TOTP route).
      const credCount = await userWebauthn.countActiveCredentials(redisClient, user_id);
      if (!credCount) { res.writeHead(403); return res.end(J({ error: "no_passkey_enrolled" })); }
      // Store (server-side pk_hash computation; cross-account-conflict check inside).
      let result;
      try {
        result = await userSigning.storeSigningPk(redisClient, user_id, { pk_b64, label });
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));   // e.g. 'pubkey already enrolled to a different account'
      }
      const ctEntry = ctAppendSigningPkEvent("signing_pk_enrolled_attested", user_id, result.entry.pk_hash_sha3);
      log("info", "signing_pk_enrolled_attested", {
        user_id: String(user_id).slice(0, 12) + "…",
        pk_hash: result.entry.pk_hash_sha3.slice(0, 16) + "…",
        reenrolled: result.reenrolled,
        ct_index: ctEntry.index,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({
        ok: true,
        pk_hash_sha3: result.entry.pk_hash_sha3,
        label: result.entry.label,
        enrolled_at: result.entry.enrolled_at,
        reenrolled: result.reenrolled,
        ct_index: ctEntry.index,
      }));
    } catch (err) {
      console.error("[user/signing-key/attested]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // ── WebAuthn / passkey credential storage (ADR R018, PR-A) ───────────────────
  // Durable storage only. The WebAuthn ceremony (challenge issue + attestation/
  // assertion verification, rpId/origin checks) lives in the admin server and
  // calls these endpoints over X-Internal-Auth. The relay never issues a
  // session and never verifies an assertion here — it only persists public
  // credential material so passkeys are as durable as TOTP/signing keys.

  // POST /v2/user/webauthn/handle — get-or-create the account's WebAuthn user
  // handle (random, no PII). Admin needs it to build registration options.
  if (req.method === "POST" && path === "/v2/user/webauthn/handle") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const handle = await userWebauthn.getOrCreateUserHandle(redisClient, user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, handle }));
    } catch (err) {
      console.error("[user/webauthn/handle]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/webauthn/credential — persist a credential the admin has
  // already verified. Idempotent on credId; rejects a credId bound elsewhere.
  if (req.method === "POST" && path === "/v2/user/webauthn/credential") {
    if (!_internalOk()) return _internalReject();
    try {
      const b = JSON.parse((await readBody(req, 16384)).toString());
      if (!b.user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      let result;
      try {
        result = await userWebauthn.storeCredential(redisClient, b.user_id, {
          credId: b.credId, publicKey: b.publicKey, counter: b.counter,
          transports: b.transports, prfSupported: b.prfSupported, aaguid: b.aaguid, label: b.label,
        });
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));
      }
      log("info", "webauthn_credential_stored", {
        user_id: String(b.user_id).slice(0, 12) + "…",
        cred_id: String(result.entry.credId).slice(0, 12) + "…",
        prf: result.entry.prfSupported, reenrolled: result.reenrolled,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, reenrolled: result.reenrolled, credId: result.entry.credId }));
    } catch (err) {
      console.error("[user/webauthn/credential POST]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // GET /v2/user/webauthn/credentials?user_id= — list active credentials (public
  // material only; admin uses this for exclude/allowCredentials and verify).
  if (req.method === "GET" && path === "/v2/user/webauthn/credentials") {
    if (!_internalOk()) return _internalReject();
    try {
      const user_id = query.user_id;
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const arr = await userWebauthn.getActiveCredentials(redisClient, user_id);
      const creds = arr.map(e => ({
        credId: e.credId, publicKey: e.publicKey, counter: e.counter,
        transports: e.transports, prfSupported: e.prfSupported, label: e.label,
        created_at: e.created_at, last_used_at: e.last_used_at,
      }));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, credentials: creds, total: creds.length }));
    } catch (err) {
      console.error("[user/webauthn/credentials GET]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // GET /v2/user/webauthn/lookup?cred_id= — resolve a credential id to its
  // account + stored verification material (for assertion verification). Revoked
  // credentials do not resolve.
  if (req.method === "GET" && path === "/v2/user/webauthn/lookup") {
    if (!_internalOk()) return _internalReject();
    try {
      const found = await userWebauthn.lookupByCredId(redisClient, query.cred_id);
      if (!found) { res.writeHead(404); return res.end(J({ found: false })); }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({
        found: true, user_id: found.userId,
        credId: found.entry.credId, publicKey: found.entry.publicKey,
        counter: found.entry.counter, prfSupported: found.entry.prfSupported,
      }));
    } catch (err) {
      console.error("[user/webauthn/lookup]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // GET /v2/user/webauthn/by-handle?handle= — resolve a WebAuthn userHandle (from
  // a discoverable-credential assertion) back to the account (usernameless login).
  if (req.method === "GET" && path === "/v2/user/webauthn/by-handle") {
    if (!_internalOk()) return _internalReject();
    try {
      const found = await userWebauthn.lookupByHandle(redisClient, query.handle);
      if (!found) { res.writeHead(404); return res.end(J({ found: false })); }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ found: true, user_id: found.userId }));
    } catch (err) {
      console.error("[user/webauthn/by-handle]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/webauthn/counter — persist a new signature counter after a
  // successful assertion. Counter-regression policy is the admin's decision.
  if (req.method === "POST" && path === "/v2/user/webauthn/counter") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, cred_id, counter } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !cred_id) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      const updated = await userWebauthn.updateCounter(redisClient, user_id, cred_id, counter);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, updated }));
    } catch (err) {
      console.error("[user/webauthn/counter]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // DELETE /v2/user/webauthn/credential — revoke a passkey. Keeps history, drops
  // the auth index. Returns remaining_active so the admin's lockout guard can
  // refuse a removal that would strand the account.
  if (req.method === "DELETE" && path === "/v2/user/webauthn/credential") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, cred_id } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !cred_id) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      let result;
      try {
        result = await userWebauthn.revokeCredential(redisClient, user_id, cred_id);
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));
      }
      if (!result.revoked) {
        const code = result.reason === "not_found" ? 404 : 409;
        res.writeHead(code, { "Content-Type": "application/json" });
        return res.end(J({ error: result.reason, remaining_active: result.remaining_active }));
      }
      log("info", "webauthn_credential_revoked", {
        user_id: String(user_id).slice(0, 12) + "…",
        cred_id: String(cred_id).slice(0, 12) + "…",
        remaining_active: result.remaining_active,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, remaining_active: result.remaining_active }));
    } catch (err) {
      console.error("[user/webauthn/credential DELETE]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // -- ParaSign /v1 self-serve API keys (user session via X-Internal-Auth) -------
  // The admin server proxies the logged-in account's request here. GATED on the
  // ParaSign entitlement: a paid plan (pro/enterprise/licensed) OR an explicit
  // grant on the account. No entitlement -> 403. Runs the SAME mintParasignKey
  // generator as the admin route. POST mints (full key ONCE), GET lists masked,
  // DELETE revokes (after which the /v1 auth rejects the key).
  if (path === "/v2/user/parasign-keys" && req.method === "POST") {
    if (!_internalOk()) return _internalReject();
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      const user_id = (d.user_id || "").toString();
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const accountId = acctOf(user_id);
      const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
      const memberRecords = [...members].map(k => apiKeys.get(k)).filter(Boolean);
      const acct = accounts.get(accountId);
      const plan = (acct && acct.plan) || (apiKeys.get(accountId) && apiKeys.get(accountId).plan) || "community";
      if (!keysTable.accountHasParasignEntitlement(memberRecords, plan)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(J({ error: "parasign_not_entitled", message: "This account is not entitled to the ParaSign API. Upgrade to a paid plan or ask an admin to enable ParaSign. / Dit account heeft geen recht op de ParaSign-API; upgrade naar een betaald plan of laat een beheerder ParaSign inschakelen." }));
      }
      const out = mintParasignKey(accountId, { test: d.test === true, label: d.label });
      log("info", "parasign_key_self_minted", { account: String(accountId).slice(0, 12), kid: out.kid, mode: out.mode });
      res.writeHead(201, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(J({ ok: true, key: out.key, kid: out.kid, account_id: out.account_id, plan: out.plan, mode: out.mode, scope: out.scope, key_masked: out.masked,
        note: "Store this key now -- it is shown once and cannot be retrieved in full again." }));
    } catch (err) {
      console.error("[user/parasign-keys POST]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  if (path === "/v2/user/parasign-keys" && req.method === "GET") {
    if (!_internalOk()) return _internalReject();
    try {
      const user_id = (query.user_id || "").toString();
      if (!user_id) { res.writeHead(400); return res.end(J({ error: "missing_user_id" })); }
      const accountId = acctOf(user_id);
      const members = accountKeys.get(accountId) || new Set();
      const keys = [...members]
        .map(k => [k, apiKeys.get(k)])
        .filter(([k, v]) => v && (v.scope === "parasign" || v.product === "parasign" || /^psk_/.test(k)))
        .map(([k, v]) => ({ kid: v.kid || keysTable.computeKid(k), key_masked: maskKey(k), mode: /^psk_test_/.test(k) ? "test" : "live", plan: v.plan, label: v.label || "", active: v.active !== false, created: v.created || null }));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, account_id: accountId, count: keys.length, keys }));
    } catch (err) {
      console.error("[user/parasign-keys GET]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  if (path === "/v2/user/parasign-keys" && req.method === "DELETE") {
    if (!_internalOk()) return _internalReject();
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const user_id = (d.user_id || "").toString();
      const target = (d.kid || d.key || "").toString();
      if (!user_id || !target) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      const accountId = acctOf(user_id);
      const members = accountKeys.get(accountId) || new Set();
      let hitKey = null;
      for (const k of members) { const v = apiKeys.get(k); if (!v) continue; if (k === target || v.kid === target) { hitKey = k; break; } }
      if (!hitKey) { res.writeHead(404); return res.end(J({ error: "key_not_found" })); }
      const rec = apiKeys.get(hitKey);
      if (!(rec.scope === "parasign" || rec.product === "parasign" || /^psk_/.test(hitKey))) { res.writeHead(400); return res.end(J({ error: "not_a_parasign_key" })); }
      rec.active = false;
      _mutateUsersJson(ud => {
        const ue = ud.api_keys.find(k => k.key === hitKey);
        if (ue) { ue.active = false; ue.revoked_at = new Date().toISOString(); }
        ud.updated = new Date().toISOString();
      }).then(() => log("info", "parasign_key_revoked", { account: String(accountId).slice(0, 12), kid: rec.kid || null, persisted: true }))
        .catch(we => log("warn", "parasign_key_revoke_persist_failed", { err: we.message }));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J({ ok: true, revoked: rec.kid || maskKey(hitKey) }));
    } catch (err) {
      console.error("[user/parasign-keys DELETE]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // ── POST /v2/claim/reveal — burn-on-reveal for the welcome-email claim link ──
  // Public: the bearer is the 256-bit claim token, not an API key. Returns the
  // key exactly once, then deletes the token atomically (getDel) so a second
  // reveal — or a mail-scanner prefetch — gets nothing.
  if (path === '/v2/claim/reveal' && req.method === 'POST') {
    if (!claimRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' })); }
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const token = String(d.token || '');
      if (!/^[a-f0-9]{64}$/.test(token)) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid_token' })); }
      if (!redisClient || !redisClient.isReady) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'claim store unavailable' })); }
      const k = `paramant:claim:${token}`;
      const key = redisClient.getDel ? await redisClient.getDel(k) : await (async () => { const v = await redisClient.get(k); if (v !== null) await redisClient.del(k); return v; })();
      if (key === null || key === undefined) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'claim_not_found_or_used' })); }
      log('info', 'claim_revealed', {});
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(J({ ok: true, key }));
    } catch (e) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_request' })); }
  }

  // ── GET /v2/check-key ───────────────────────────────────────────────────────
  if (path === '/v2/check-key') {
    if (!checkKeyRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' })); }
    const kd = apiKeys.get(apiKey);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ valid: !!(kd?.active), plan: kd?.plan || null }));
  }

  // ── GET /v2/lookup-signer/:pk_hash — public reverse-lookup for verifiers ──
  // Exact 64-hex-char SHA3-256 match only — no prefix scan, no enumeration.
  // The caller must already possess the envelope (= the pk) to ask; we return
  // label + email (if enrolled). Rate-limited 30/min/IP to blunt scraping.
  if (req.method === 'GET' && path.startsWith('/v2/lookup-signer/')) {
    if (!lookupSignerRateOk(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' }));
    }
    const pkHash = path.slice('/v2/lookup-signer/'.length);
    if (!/^[0-9a-f]{64}$/.test(pkHash)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'pk_hash must be 64-char SHA3-256 hex' }));
    }
    try {
      const found = await userSigning.lookupByPkHash(redisClient, pkHash);
      if (!found) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(J({ found: false }));
      }
      let email = null;
      try {
        const metaRaw = await redisClient.get(`paramant:user:meta:${found.userId}`);
        if (metaRaw) { const m = JSON.parse(metaRaw); email = m.email || null; }
      } catch {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({
        found: true,
        alg: found.entry.alg,
        label: found.entry.label,
        email,
        enrolled_at: found.entry.enrolled_at,
        revoked_at: found.entry.revoked_at,
      }));
    } catch (err) {
      console.error('[lookup-signer]', err.message);
      res.writeHead(500); return res.end(J({ error: 'internal' }));
    }
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
      // Keep the signing party's identity (name/org/email) for the legal Art. 28
      // record, but store only a masked IP: the full address is not needed for
      // the agreement and is unnecessary PII in a permanent append-only file.
      const record = JSON.stringify({ ref, name, title, org, kvk, email, version, signed_at, ip: maskIp(getClientIp(req)) });
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
              <tr><td style="color:#555;padding:4px 0">DPA version</td><td style="color:#ededed">${escHtml(version)}</td></tr>
              <tr><td style="color:#555;padding:4px 0">Processor</td><td style="color:#ededed">PARAMANT — Hetzner, Germany</td></tr>
            </table>
          </div>
          <p style="color:#888;font-size:13px;margin-bottom:24px">The full agreement text is available at <a href="https://paramant.app/dpa" style="color:#888">paramant.app/dpa</a>. Keep this email and the reference number for your records.</p>
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
        }, r => { let data = ''; r.on('data', c => data += c); r.on('end', () => { try { const p = JSON.parse(data); log('info', 'dpa_email_sent', { ref, email: maskEmail(email), id: p.id }); } catch(e) {} }); });
        req2.on('error', e => log('warn', 'dpa_email_failed', { err: e.message }));
        req2.write(emailBody); req2.end();
      }

      log('info', 'dpa_signed', { ref, org, email: maskEmail(email), version });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, ref, signed_at }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /metrics — Prometheus metrics (voor auth gate, ADMIN_TOKEN vereist) ──
  if (path === '/metrics') {
    const adminToken = process.env.ADMIN_TOKEN || '';
    if (!adminToken) {
      // Fail closed: without an ADMIN_TOKEN configured, metrics must not be public.
      res.writeHead(503, { 'Content-Type': 'text/plain' }); return res.end('Metrics disabled: ADMIN_TOKEN not configured');
    }
    const reqToken = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (!safeEqual(reqToken, adminToken)) {
      res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('Unauthorized');
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
    return res.end(renderPrometheus());
  }

  // ── ParaID issuer registry: admin writes ───────────────────────────────────
  // The public read lives BEFORE the /v1 Bearer-gate higher up. Admin writes:
  // the public apex 404s /v2/admin at nginx; these are reached from the admin
  // surface or the host itself. Every mutation is CT-anchored.
  if (path === '/v2/admin/paraid/issuers' && req.method === 'POST') {
    const adminTok = (req.headers['x-admin-token'] || '').trim();
    if (!process.env.ADMIN_TOKEN || !adminTok || !safeEqual(adminTok, process.env.ADMIN_TOKEN)) {
      res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 16384)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    const r = paraidIssuers.add({ label: body.label, publicKeyB64: body.public_key });
    if (!r.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J(r)); }
    const pkHash = crypto.createHash('sha3-256').update(Buffer.from(r.issuer.public_key, 'base64')).digest('hex');
    const ct = ctAppendParaidIssuer('paraid_issuer_added', r.issuer.did, { label: r.issuer.label, pk_hash: pkHash });
    log('info', 'paraid_issuer_added', { did: r.issuer.did, label: r.issuer.label });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, issuer: r.issuer, ct_index: ct.index }));
  }
  // Publish a new code-transparency manifest (deploy-time step, CT-anchored).
  if (path === '/v2/admin/code-manifest' && req.method === 'POST') {
    const adminTok = (req.headers['x-admin-token'] || '').trim();
    if (!process.env.ADMIN_TOKEN || !adminTok || !safeEqual(adminTok, process.env.ADMIN_TOKEN)) {
      res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 2 * 1024 * 1024)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    if (!body || !body.files || !body.manifest_hash || typeof body.files !== 'object') {
      res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'manifest needs files + manifest_hash' }));
    }
    const ct = ctAppendParaidIssuer('code_manifest_published', body.manifest_hash, {
      git_commit: body.git_commit || '', file_count: Object.keys(body.files).length,
    });
    codeManifest = { ...body, published: new Date().toISOString(), ct_index: ct.index };
    try { require('fs').writeFileSync(CODE_MANIFEST_FILE, JSON.stringify(codeManifest)); }
    catch (e) { log('warn', 'code_manifest_write_error', { err: e.message }); }
    log('info', 'code_manifest_published', { hash: body.manifest_hash.slice(0, 16), files: Object.keys(body.files).length });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, manifest_hash: body.manifest_hash, ct_index: ct.index }));
  }
  // Revoke ONE credential of a registered issuer (status-list entry). The id is
  // the hex SHA3-256 of the signed Merkle root: opaque, no personal data.
  if (path === '/v2/admin/paraid/credentials/revoke' && req.method === 'POST') {
    const adminTok = (req.headers['x-admin-token'] || '').trim();
    if (!process.env.ADMIN_TOKEN || !adminTok || !safeEqual(adminTok, process.env.ADMIN_TOKEN)) {
      res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 4096)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    const r = paraidIssuers.revokeCredential(String(body.issuer_did || ''), String(body.credential || '').toLowerCase());
    if (!r.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J(r)); }
    const ct = ctAppendParaidIssuer('paraid_credential_revoked', r.issuer.did, { credential: r.credential });
    log('info', 'paraid_credential_revoked', { did: r.issuer.did, credential: r.credential.slice(0, 16) });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, issuer_did: r.issuer.did, credential: r.credential, ct_index: ct.index }));
  }
  if (path === '/v2/admin/paraid/issuers/revoke' && req.method === 'POST') {
    const adminTok = (req.headers['x-admin-token'] || '').trim();
    if (!process.env.ADMIN_TOKEN || !adminTok || !safeEqual(adminTok, process.env.ADMIN_TOKEN)) {
      res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 4096)).toString()); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invalid json' })); }
    const r = paraidIssuers.revoke(String(body.did || ''));
    if (!r.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J(r)); }
    const ct = ctAppendParaidIssuer('paraid_issuer_revoked', r.issuer.did, { label: r.issuer.label });
    log('info', 'paraid_issuer_revoked', { did: r.issuer.did });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, issuer: r.issuer, ct_index: ct.index }));
  }

  // ── GET /ct, /ct/ — public CT log web UI (no auth) ─────────────────────────
  if ((path === '/ct' || path === '/ct/') && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(CT_PAGE);
  }

  // ── GET /ct/feed — public JSON feed for CT log UI (no auth, no keys) ─────────
  if (path === '/ct/feed' && req.method === 'GET') {
    const last50 = ctWindow.recent(50);
    const root   = ctWindow.last() ? ctWindow.last().tree_hash : '0'.repeat(64);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(J({
      relay_id: relayIdentity ? relayIdentity.pk_hash : null,
      sector:   SECTOR,
      version:  VERSION,
      tree_size: ctWindow.size,
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
    // Privacy: the public log projection deliberately omits device_hash and
    // coarsens timestamps to the hour. device_hash is a stable, deterministic
    // function of a participant public key, so publishing it unauthenticated
    // let anyone holding a target's pubkey confirm presence, reconstruct a
    // per-device activity timeline to the millisecond, and link a device
    // across sector relays. The transparency guarantee does NOT depend on it:
    // tamper-evidence comes from leaf_hash + tree_hash + the Merkle proof
    // (/v2/ct/proof) + the signed tree head, none of which reveal identity.
    const entries = ctWindow.sliceByIndex(from, limit).map(e => ({ index: e.index, type: e.type, leaf_hash: e.leaf_hash, tree_hash: e.tree_hash, ts: ctCoarseTs(e.ts) }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, size: ctWindow.size, root: ctWindow.last() ? ctWindow.last().tree_hash : '0'.repeat(64), entries }));
  }
  const ctpm0 = path.match(/^\/v2\/ct\/proof\/(\d+)$/);
  const ctpq0 = (!ctpm0 && path === '/v2/ct/proof') ? query.index : null;
  if (ctpm0 || (ctpq0 !== null && ctpq0 !== undefined)) {
    const idx = parseInt(ctpm0 ? ctpm0[1] : ctpq0);
    const entry = ctWindow.get(idx);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Index not found' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, index: idx, leaf_hash: entry.leaf_hash, tree_hash: entry.tree_hash, proof: entry.proof, ts: ctCoarseTs(entry.ts) }));
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
    try { verified = registry.getSig(0x0002).verify(sigBytes, msg, pkBytes); } catch {}
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
    // This endpoint is unauthenticated (ownership-signature only), so a flood of
    // attacker-minted relay keypairs is otherwise unbounded. Per-IP limiter caps
    // the rate before any body read / signature verify (mirrors anon-inbound).
    {
      const STH_INGEST_RPH = parseInt(process.env.STH_INGEST_RATE_PER_HOUR || '120');
      const HOUR_MS = 3_600_000;
      const ip      = getClientIp(req);
      const now     = Date.now();
      const ipTimes = (sthIngestIpRequests.get(ip) || []).filter(t => now - t < HOUR_MS);
      if (ipTimes.length >= STH_INGEST_RPH) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' });
        return res.end(J({ error: 'Rate limit: too many STH ingest requests from this address. Try again later.' }));
      }
      ipTimes.push(now);
      sthIngestIpRequests.set(ip, ipTimes);
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
    try { verified = registry.getSig(0x0002).verify(sigBytes, Buffer.from(canonical, 'utf8'), pkBytes); } catch {}
    if (!verified) {
      log('warn', 'sth_ingest_bad_sig', { relay_id: String(relay_id).slice(0, 32), pk_hash: computedPkHash.slice(0, 16) });
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Signature verification failed' }));
    }
    if (!peerSths.has(computedPkHash)) {
      peerSths.set(computedPkHash, { sths: [], pk_b64: public_key, last: Date.now() });
      _evictPeerSthsIfNeeded(); // bound distinct peers (Map entries + fds + .jsonl files)
    }
    const peer = peerSths.get(computedPkHash);
    // If this peer was just evicted by the cap (e.g. immediately re-added under
    // load), it is no longer in the Map — skip the write to avoid resurrecting it.
    if (!peer) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(J({ error: 'Peer relay table at capacity. Try again later.' }));
    }
    peer.pk_b64 = public_key;
    peer.last = Date.now();
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
    const toSize   = query.to !== undefined ? parseInt(query.to) : ctWindow.windowLength;
    if (isNaN(fromSize) || isNaN(toSize)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Query params required: from=<integer> (and optionally to=<integer>)' }));
    }
    if (fromSize < 0 || toSize < fromSize || toSize > ctWindow.windowLength) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: `Invalid range: 0 ≤ from (${fromSize}) ≤ to (${toSize}) ≤ window size (${ctWindow.windowLength})` }));
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

    // Read with retry — handle transient mid-write reads from concurrent _mutateUsersJson.
    let parsed = null;
    let parseErr = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const raw = await fs.promises.readFile(USERS_FILE, 'utf8');
        if (!raw || raw.trim().length === 0) throw new Error('empty file');
        const d = JSON.parse(raw);
        if (!d || !Array.isArray(d.api_keys)) throw new Error('invalid structure');
        parsed = d; parseErr = null; break;
      } catch (e) {
        parseErr = e;
        if (attempt < 3) await new Promise(r => setTimeout(r, 100));
      }
    }

    if (parseErr) {
      log('error', 'reload_users_parse_failed', { prev: prevCount, err: parseErr.message });
      res.writeHead(500); return res.end(J({ ok: false, error: 'reload_failed', prev: prevCount }));
    }

    // Build candidate Map without touching the live one.
    const candidate = new Map();
    for (const k of parsed.api_keys) {
      if (k.active) candidate.set(k.key, {
        plan: k.plan, label: k.label||'', email: k.email||'', active: true, dsa_pub: k.dsa_pub||'',
        daily_uploads: 0, daily_reset_ts: Date.now() + 86_400_000,
        is_trial: !!(k.plan === 'community' && k.trial_metadata),
        trial_created: k.created ? new Date(k.created).getTime() : null,
        uploads_today: 0, last_upload_day: '',
        created: k.created || null,
        ...keysTable.parseAccountFields(k),
      });
    }

    // Refuse to wipe a populated Map with an empty load — defends against the
    // 2026-05-08 race where a concurrent write left the file readable but empty.
    if (candidate.size === 0 && prevCount > 0) {
      log('warn', 'reload_users_rejected', { prev: prevCount, candidate: 0, reason: 'refusing_to_wipe_populated_map' });
      res.writeHead(409); return res.end(J({ ok: false, error: 'sanity_check_failed', prev: prevCount, candidate: 0 }));
    }

    // Atomic swap.
    apiKeys.clear();
    candidate.forEach((v, k) => apiKeys.set(k, v));
    keysTable.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log);

    applyKeyLimitEnforcement();
    log('info', 'reload_users', { prev: prevCount, now: apiKeys.size, delta: apiKeys.size - prevCount });
    res.writeHead(200); return res.end(J({ ok: true, loaded: apiKeys.size, prev: prevCount }));
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
      const existingPubkey = pubkeys.get(`${d.device_id}:${acctOf(apiKey)}`);
      if (existingPubkey && (!existingPubkey.expires || Date.now() < existingPubkey.expires)) {
        res.writeHead(409); return res.end(J({ error: 'Pubkey already registered for this session — first registration wins' }));
      }
      const fp = computeFingerprint(d.kyber_pub || '', d.ecdh_pub);
      const regAt = new Date().toISOString();
      pubkeys.set(`${d.device_id}:${acctOf(apiKey)}`, {
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
    const _pkKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${acctOf(apiKey)}`;
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
    const _fKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${acctOf(apiKey)}`;
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
      const _vKey = INVITE_RE.test(d.device_id) ? d.device_id : `${d.device_id}:${acctOf(apiKey)}`;
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
  // DEPRECATED 2026-05-28 (relay): the anonymous tier is being retired. The endpoint
  // continues to serve sdk-js 3.x callers but advertises retirement via the
  // Deprecation + Sunset response headers (RFC 8594 / draft-ietf-httpapi-deprecation).
  // Removal happens in a future major release after telemetry shows traffic has
  // drained.
  if (path === '/v2/anon-inbound' && req.method === 'POST') {
    // Sticky headers: every writeHead() below will inherit these unless it
    // explicitly overrides them, so 200/400/409/413/429/503 all carry them.
    res.setHeader('Deprecation', 'true');
    res.setHeader('Sunset', 'Wed, 31 Dec 2026 00:00:00 GMT');
    res.setHeader('Link', '<https://paramant.app/parashare>; rel="successor-version"');
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
      try { peekInboundBlob(blob); }
      catch(e) {
        const mapped = mapCryptoErrorToHttp(e);
        if (mapped) {
          log('warn', 'anon_inbound_wire_v1_reject', { status: mapped.status, err: e.code || e.name });
          res.writeHead(mapped.status, { 'Content-Type': 'application/json' });
          return res.end(J(mapped.body));
        }
        throw e;
      }
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
                    tree_size: ctEntry.index + 1, audit_path: ctEntry.proof, sth: ctEntry.sth || null,
                    ts: ctEntry.ts },
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
  // Public envelope recipient endpoints: GET status, POST view, POST sign
  // are reachable without an API key (the recipient may be an external
  // party). POST /v2/envelopes (create) is intentionally NOT in this list
  // and is still gated.
  const isEnvelopePublic = path.startsWith('/v2/envelopes/') && (
    req.method === 'GET' ||
    (req.method === 'POST' && (path.endsWith('/view') || path.endsWith('/sign')))
  );
  if (isAdminPath) {
    const adminHeader = (req.headers['x-admin-token'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '') || '').trim();
    const validAdmin = !!adminHeader && !!process.env.ADMIN_TOKEN && safeEqual(adminHeader, process.env.ADMIN_TOKEN);
    if (!validAdmin) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'ADMIN_TOKEN required for admin endpoints' }));
    }
    // Fall through to admin endpoint handlers below
  } else if (!keyData?.active && !isEnvelopePublic) {
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

      try { peekInboundBlob(blob); }
      catch(e) {
        const mapped = mapCryptoErrorToHttp(e);
        if (mapped) {
          log('warn', 'inbound_wire_v1_reject', { status: mapped.status, err: e.code || e.name });
          res.writeHead(mapped.status, { 'Content-Type': 'application/json' });
          return res.end(J(mapped.body));
        }
        throw e;
      }

      // ML-DSA handtekening verificatie (optioneel maar gelogd)
      let sigResult = { valid: false, reason: 'not provided' };
      if (dsa_signature && keyData.dsa_pub) {
        sigResult = verifyDsaSignature(hash, dsa_signature, keyData.dsa_pub);
      }

      // Per-tier view TTL ceiling -- single source of truth in lib/tiers.js.
      // Falls back to community ceiling when the plan is missing or unrecognised.
      const _plan = keyData?.plan || 'community';
      const _maxTtl = tiers.tierLimitNum(_plan, 'view_ttl_ms');
      const ttl = Math.min(parseInt(ttl_ms || TTL_MS), _maxTtl);
      // Access policies: max_views (default 1 = burn-on-read) + Argon2id password.
      // Per-tier max_views ceiling also lives in lib/tiers.js now.
      const maxViews = Math.max(1, Math.min(parseInt(reqMaxViews || 1) || 1, tiers.tierLimitNum(keyData?.plan || 'pro', 'max_views') || 1));
      let pw_hash = null;
      if (password) {
        if (!argon2Lib) { res.writeHead(501); return res.end(J({ error: 'Argon2id not available on this relay' })); }
        pw_hash = await argon2Lib.hash(password, { type: argon2Lib.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
      }
      // Phase 4 quota enforcement: decline a NEW transfer once the monthly tier
      // cap is reached. Access to existing blobs (download/view) is never gated.
      // A continuing multi-chunk upload (dedup hit) and Redis outages both pass
      // (fail-open) — this only declines fresh active use over the cap.
      if (keyData && keyData.account_id) {
        const _dedupKey = (meta && meta.file_id)
          ? crypto.createHash('sha3-256').update(String(meta.file_id)).digest('hex')
          : quota.firstChunkHash(blob);
        const _tLimit = tiers.tierLimitNum(keyData.plan || 'community', 'transfers_month');
        const _tGate  = await quota.gateTransfer(redisClient, keyData.account_id, _dedupKey, _tLimit, log);
        if (!_tGate.allowed) {
          log('info', 'quota_transfer_declined', { account: String(keyData.account_id).slice(0, 12), plan: keyData.plan || 'community', limit: _tLimit });
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: keyData.plan || 'community', limit: _tLimit }));
        }
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
          ts:        ctEntry.ts,
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

      // (Transfer already counted by the quota gate above, before storage.)

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
        ts:                     ctData.ts,
        retrieved_at:           Date.now(),
        sector:                 entry.sector || SECTOR,
        relay_id:               RELAY_SELF_URL || (SECTOR + '.paramant.app'),
        tree_size_at_retrieval: ctWindow.size,
        inclusion_proof:        inclusionProof,
        burn_confirmed:         burned,
      };
      let signature = null;
      if (mlDsa && relayIdentity) {
        try {
          const canonical = canonicalJSON(receiptPayload);
          signature = Buffer.from(registry.getSig(0x0002).sign(Buffer.from(canonical, 'utf8'), relayIdentity.sk)).toString('base64');
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
    if (!statusRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' })); }
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
      const k = `${d.device_id}:${acctOf(apiKey)}`;
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
    const qKey = `${acctOf(apiKey)}:${device}`;
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
      // Keyless inv_ registrations need no API key, so the per-key cap below does
      // not bound them — an anonymous flood would append forever to didRegistry +
      // ctLog. Throttle per IP (max 20/hour) to cap anonymous growth.
      if (!keyData && isReceiverSession) {
        const now = Date.now(), HOUR_MS = 3_600_000, MAX_INV_PER_IP = 20;
        const ipKey = getClientIp(req);
        const times = (invDidIpRequests.get(ipKey) || []).filter(t => now - t < HOUR_MS);
        if (times.length >= MAX_INV_PER_IP) {
          res.writeHead(429); return res.end(J({ error: 'Too many receiver-session registrations from this address. Try again later.' }));
        }
        times.push(now); invDidIpRequests.set(ipKey, times);
      }
      // Rate limit: max 500 DIDs per API key to prevent RAM DoS. Counter is O(1)
      // (didKeyCounts) instead of an O(n) scan of the whole registry per request.
      const MAX_DID_PER_KEY = 500;
      if (apiKey) {
        const keyDidCount = didKeyCounts.get(apiKey) || 0;
        if (keyDidCount >= MAX_DID_PER_KEY) {
          res.writeHead(429); return res.end(J({ error: `DID limit reached. Max ${MAX_DID_PER_KEY} DIDs per API key.` }));
        }
      }
      const did = generateDid(d.device_id, d.ecdh_pub);
      const doc = createDidDocument(did, d.device_id, d.ecdh_pub, d.dsa_pub || '');
      const _didIsNew = !didRegistry.has(did); // overwrite of same did must not double-count
      didRegistry.set(did, { device_id: d.device_id, key: apiKey, doc, ts: new Date().toISOString() });
      if (_didIsNew && apiKey) didKeyCounts.set(apiKey, (didKeyCounts.get(apiKey) || 0) + 1);
      const _didPlan = keyData?.plan || 'pro';
      pubkeys.set(`${d.device_id}:${acctOf(apiKey)}`, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', dsa_pub: d.dsa_pub || '', ts: new Date().toISOString(), expires: Date.now() + (_pubkeyTtl[_didPlan] ?? _pubkeyTtl.free) });
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
      const pk = pubkeys.get(`${d.device_id}:${acctOf(apiKey)}`);
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
      log('warn', 'mfa_rate_limited', { ip: maskIp(clientIp) });
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(J({ error: 'Too many MFA attempts — try again in 60 seconds' }));
    }
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const valid = verifyTotp(d.totp_code || '');
      log(valid ? 'info' : 'warn', 'mfa_attempt', { valid, ip: maskIp(clientIp) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: valid, error: valid ? null : 'Invalid TOTP code' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys — Key aanmaken ────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'POST') {
    try {
      // Parse FIRST, then do the cap check + insert in one synchronous tick (no
      // await between the count and the set) so two concurrent creates cannot
      // both pass a stale count — closes the prior check-before-await TOCTOU.
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
      // Account binding: explicit account_id adds a key to an existing account
      // (non-primary); otherwise this key opens its own account (1:1, the stap-1
      // default) as its primary.
      const account_id = (d.account_id && String(d.account_id)) || newKey;
      const is_primary = !d.account_id;
      const scope = keysTable.VALID_SCOPES.has(d.scope) ? d.scope : 'full';

      // Per-account cap (and the self-host relay-total cap) — checked atomically
      // with the insert below.
      const acctPlan = tiers.normalisePlan((accounts.get(account_id) && accounts.get(account_id).plan) || plan);
      const acctCap = ACCOUNT_KEY_LIMIT[acctPlan] ?? ACCOUNT_KEY_LIMIT.community;
      const acctActive = [...(accountKeys.get(account_id) || [])].filter((k) => apiKeys.get(k) && apiKeys.get(k).active !== false).length;
      if (acctActive >= acctCap) {
        res.writeHead(402, { 'Content-Type': 'application/json' });
        return res.end(J({ error: `Account key limit reached (${acctCap} keys on the ${acctPlan} plan).`, current_keys: acctActive, max_keys: acctCap, upgrade_url: 'https://paramant.app/pricing' }));
      }
      if (EDITION !== 'licensed' && LICENSE_MAX_KEYS !== Infinity) {
        const relayActive = [...apiKeys.values()].filter((v) => v.active !== false).length;
        if (relayActive >= LICENSE_MAX_KEYS) {
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({
            error: EDITION === 'community'
              ? `Community Edition limit reached (${COMMUNITY_KEY_LIMIT} keys). Add a plk_ license key to unlock unlimited users.`
              : `License limit reached (${LICENSE_MAX_KEYS} keys). Contact Paramant to upgrade your license.`,
            current_keys: relayActive, max_keys: LICENSE_MAX_KEYS, upgrade_url: 'https://paramant.app/pricing'
          }));
        }
      }

      const created = new Date().toISOString();
      apiKeys.set(newKey, { plan, label, email, active: true, account_id, is_primary, scope, created });
      if (!accounts.has(account_id)) accounts.set(account_id, { account_id, plan, email, primary_api_key: null, label });
      if (is_primary || !accounts.get(account_id).primary_api_key) accounts.get(account_id).primary_api_key = newKey;
      if (!accountKeys.has(account_id)) accountKeys.set(account_id, new Set());
      accountKeys.get(account_id).add(newKey);
      const kid = keysTable.assignKid(kidIndex, newKey, log);
      apiKeys.get(newKey).kid = kid;
      kidIndex.set(kid, newKey);

      _mutateUsersJson(ud => {
        ud.api_keys.push({ key: newKey, plan, label, email, active: true, created, account_id, is_primary, scope });
        ud.updated = new Date().toISOString();
      }).then(() => log('info', 'key_created_via_admin', { label, plan, account: String(account_id).slice(0, 12), persisted: true }))
        .catch(we => log('warn', 'key_persist_failed', { err: we.message, label }));
      applyKeyLimitEnforcement();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key: newKey, kid, account_id, plan, label }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/admin/keys ────────────────────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'GET') {
    // Account fields (kid/account_id/is_primary/scope/created) are ADDITIVE —
    // existing consumers read key/plan/label/email/active; stap-4 self-service
    // and the account-aware admin view use the account grouping.
    //
    // Blast-radius hygiene: the bulk list MASKS the secret key by default so a
    // full pgp_ value is never returned for every account at once. Server-to-
    // server callers that genuinely need the raw key (revoke/plan-change/reset)
    // opt in with ?reveal=1; per-row reveal is also available at
    // GET /v2/admin/keys/reveal/:account_id. key_masked is always present so
    // browser-facing list views can render rows without ever holding a secret.
    const reveal = query.reveal === '1' || query.reveal === 'true';
    const keys = [...apiKeys.entries()].map(([k, v]) => ({
      key: reveal ? k : maskKey(k), key_masked: maskKey(k), plan: v.plan, label: v.label, email: v.email || null, active: v.active, over_limit: v.over_limit || false,
      kid: v.kid || null, account_id: v.account_id || k, is_primary: !!v.is_primary, scope: v.scope || 'full', parasign: !!v.parasign, created: v.created || null /*MARK:parasign_list*/
    }));
    const licenseInfo = { edition: EDITION, active_keys: keys.length, key_limit: LICENSE_MAX_KEYS === Infinity ? null : LICENSE_MAX_KEYS, ...(LICENSE_PAYLOAD ? { license_expires: LICENSE_PAYLOAD.expires_at } : {}) };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: keys.length, masked: !reveal, keys, license: licenseInfo }));
  }

  // ── GET /v2/admin/keys/reveal/:account_id — reveal ONE full secret key ──────
  // Single-key counterpart to the masked list: returns the full pgp_ value for
  // exactly one account/key so an operator never has to pull the whole table in
  // the clear. Path-param (mirrors /v2/admin/usage/:account_id) so no query
  // parse. ADMIN_TOKEN-gated by the admin-path guard above. Matches by
  // account_id, then by the raw key, then by kid.
  const revealGet = path.match(/^\/v2\/admin\/keys\/reveal\/(.+)$/);
  if (revealGet && req.method === 'GET') {
    const id = decodeURIComponent(revealGet[1]);
    const entry = [...apiKeys.entries()].find(([k, v]) => (v.account_id || k) === id || k === id || v.kid === id);
    if (!entry) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'key_not_found' })); }
    const [k, v] = entry;
    log('info', 'admin_key_revealed', { account: String(v.account_id || k).slice(0, 12), kid: v.kid || null });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, key: k, key_masked: maskKey(k), kid: v.kid || null,
      account_id: v.account_id || k, plan: v.plan, label: v.label, email: v.email || null,
      active: v.active, is_primary: !!v.is_primary, scope: v.scope || 'full', parasign: !!v.parasign, created: v.created || null }));/*MARK:parasign_reveal*/
  }

  // ── GET /v2/admin/usage[/:account_id] — Phase 4 read-only observation ────
  // Returns this-month transfer + sign counts per account, plus the limits
  // from lib/tiers.js so an operator can sanity-check the counters before
  // any quota gate is ever enabled. Auth: ADMIN_TOKEN (handled above).
  if (path === '/v2/admin/usage' && req.method === 'GET') {
    const month = quota.ymKey();
    const out = [];
    for (const [k, v] of apiKeys.entries()) {
      const accountId = v.account_id || k;
      const usage = await quota.readUsage(redisClient, accountId, month);
      const plan = v.plan || 'community';
      out.push({
        account_id: accountId,
        api_key_prefix: k.slice(0, 12),
        plan,
        label: v.label || '',
        email: v.email || null,
        active: !!v.active,
        usage,
        limits: {
          transfers_month: tiers.tierLimit(plan, 'transfers_month'),
          signs_month:     tiers.tierLimit(plan, 'signs_month'),
          file_mb:         tiers.tierLimit(plan, 'file_mb'),
          devices:         tiers.tierLimit(plan, 'devices'),
        },
      });
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, month, count: out.length, redis_available: !!(redisClient && redisClient.isReady), accounts: out }));
  }
  const usageMatch = path.match(/^\/v2\/admin\/usage\/([A-Za-z0-9_.\-:]+)$/);
  if (usageMatch && req.method === 'GET') {
    const accountId = decodeURIComponent(usageMatch[1]);
    const entry = [...apiKeys.entries()].find(([k, v]) => (v.account_id || k) === accountId || k === accountId);
    const plan = entry ? (entry[1].plan || 'community') : 'community';
    const month = quota.ymKey();
    const usage = await quota.readUsage(redisClient, accountId, month);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true,
      account_id: accountId,
      plan,
      known_to_relay: !!entry,
      month,
      redis_available: !!(redisClient && redisClient.isReady),
      usage,
      limits: {
        transfers_month: tiers.tierLimit(plan, 'transfers_month'),
        signs_month:     tiers.tierLimit(plan, 'signs_month'),
        file_mb:         tiers.tierLimit(plan, 'file_mb'),
        devices:         tiers.tierLimit(plan, 'devices'),
      },
    }));
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
      // Keep the account's plan in step so the per-account cap re-evaluates.
      const _aid = apiKeys.get(key).account_id;
      if (_aid && accounts.has(_aid)) accounts.get(_aid).plan = plan;
      // Billing auto-grant: a paid Pro plan entitles the account to ParaSign /v1.
      if (PARASIGN_PAID_PLANS.has(plan)) grantParasignOnPaidPlan(_aid || key); /*MARK:parasign_billing_autograt*/
      _mutateUsersJson(ud => {
        const entry = ud.api_keys.find(k => k.key === key);
        if (entry) { entry.plan = plan; entry.plan_updated = new Date().toISOString(); }
        ud.updated = new Date().toISOString();
      }).catch(e => log('warn', 'plan_update_persist_failed', { err: e.message }));
      applyKeyLimitEnforcement();
      res.writeHead(200); return res.end(J({ ok: true, key, plan }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys/set-parasign - grant/revoke the ParaSign /v1 API ────
  // Admin override for the `parasign` entitlement, alongside the automatic grant
  // on payment. Sets the flag on the target key AND every sibling key of its
  // account (account-level grant), then persists to users.json. ADMIN_TOKEN-gated
  // by the admin-path guard above; the admin server fans this out to every sector
  // so the grant is fleet-consistent. Additive: no current relay path gates on it.
  if (path === '/v2/admin/keys/set-parasign' && req.method === 'POST') {/*MARK:parasign_endpoint*/
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const key = (d.key || '').toString();
      const enabled = d.enabled === true || d.parasign === true;
      if (!key) { res.writeHead(400); return res.end(J({ error: 'key required' })); }
      const kv = apiKeys.get(key);
      if (!kv) { res.writeHead(404); return res.end(J({ error: 'key_not_found' })); }
      const accountId = kv.account_id || key;
      const members = accountKeys.get(accountId) || new Set([key]);
      for (const m of members) { const mv = apiKeys.get(m); if (mv) mv.parasign = enabled; }
      _mutateUsersJson(ud => {
        for (const entry of ud.api_keys) {
          if ((entry.account_id || entry.key) === accountId) entry.parasign = enabled;
        }
        ud.updated = new Date().toISOString();
      }).then(() => log('info', 'parasign_grant_via_admin', { account: String(accountId).slice(0, 12), enabled, keys: members.size, persisted: true }))
        .catch(we => log('warn', 'parasign_persist_failed', { err: we.message }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key, account_id: accountId, parasign: enabled, keys_updated: members.size }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys/mint-parasign - mint a psk_ ParaSign /v1 key ─────────
  // Manual admin-setup path. ADMIN_TOKEN-gated (admin-path guard above). Runs the
  // SAME mintParasignKey generator as the self-serve route, so both paths share
  // one key format + one storage shape. Binds the key to {account_id} (or the
  // account of {key}); returns the FULL key ONCE (never re-retrievable in full).
  if (path === '/v2/admin/keys/mint-parasign' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      let accountId = (d.account_id && String(d.account_id)) || '';
      if (!accountId && d.key) accountId = acctOf(String(d.key));
      if (!accountId) { res.writeHead(400); return res.end(J({ error: 'account_id or key required' })); }
      const out = mintParasignKey(accountId, { test: d.test === true, label: d.label, plan: d.plan });
      res.writeHead(201, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(J({ ok: true, key: out.key, kid: out.kid, account_id: out.account_id, plan: out.plan, mode: out.mode, scope: out.scope, key_masked: out.masked,
        note: 'Store this key now - it is shown once and cannot be retrieved in full again.' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/admin/keys/primary/:account_id — read an account's primary + members ──
  // Read-only; path-param (mirrors /v2/admin/usage/:account_id) so no query parse.
  const primaryGet = path.match(/^\/v2\/admin\/keys\/primary\/(.+)$/);
  if (primaryGet && req.method === 'GET') {
    const accountId = decodeURIComponent(primaryGet[1]);
    const acct = accounts.get(accountId);
    const members = [...(accountKeys.get(accountId) || [])].map((k) => {
      const v = apiKeys.get(k) || {};
      return { kid: v.kid || null, is_primary: !!v.is_primary, scope: v.scope || 'full', active: v.active !== false, label: v.label || '' };
    });
    const primaryKey = acct && acct.primary_api_key;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, account_id: accountId, known: !!acct,
      primary_kid: primaryKey ? ((apiKeys.get(primaryKey) || {}).kid || null) : null, keys: members }));
  }

  // ── POST /v2/admin/keys/primary — designate {key} as {account_id}'s primary ──
  // Promotes the chosen key, demotes the previous primary within the account
  // (keysTable.designatePrimary), then persists. Mismatched account_id => 400, so
  // a key can never be moved into an account it does not belong to.
  if (path === '/v2/admin/keys/primary' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const accountId = (d.account_id || '').toString();
      const key = (d.key || '').toString();
      if (!accountId || !key) { res.writeHead(400); return res.end(J({ error: 'account_id and key required' })); }
      let result;
      try { result = keysTable.designatePrimary(apiKeys, accounts, accountKeys, accountId, key); }
      catch (ke) { res.writeHead(ke.code === 'key_not_found' ? 404 : 400); return res.end(J({ error: ke.code || 'invalid_request' })); }
      _mutateUsersJson(ud => {
        for (const entry of ud.api_keys) {
          if ((entry.account_id || entry.key) === accountId) entry.is_primary = (entry.key === key);
        }
        ud.updated = new Date().toISOString();
      }).then(() => log('info', 'primary_designated_via_admin', { account: accountId.slice(0, 12), persisted: true }))
        .catch(we => log('warn', 'primary_persist_failed', { err: we.message }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, account_id: accountId, primary_key: key, previous_primary: result.previous }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/send-welcome ──────────────────────────────────────────────
  if (path === '/v2/admin/send-welcome' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.email || !d.key) { res.writeHead(400); return res.end(J({ error: 'email and key required' })); }
      const RESEND_KEY = process.env.RESEND_API_KEY || '';
      if (!RESEND_KEY) { res.writeHead(503); return res.end(J({ error: 'RESEND_API_KEY not configured' })); }
      // H1: never put the raw API key in the email body (it would sit in the
      // mailbox and pass through Resend in plaintext). Mint a one-time claim
      // token and email a link instead. The token travels in the URL fragment
      // (#...), so it is never sent to the server on page load, never logged,
      // and never leaks via Referer; the claim page POSTs it to burn-on-reveal.
      if (!redisClient || !redisClient.isReady) { res.writeHead(503); return res.end(J({ error: 'claim store unavailable' })); }
      const claimToken = crypto.randomBytes(32).toString('hex');
      await redisClient.set(`paramant:claim:${claimToken}`, d.key, { EX: CLAIM_TTL_SECONDS });
      const claimUrl = `https://paramant.app/claim.html#${claimToken}`;
      const html = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:520px">
        <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
        <div style="background:#1a1a00;border:1px solid #2a2a00;border-radius:6px;padding:16px;margin-bottom:24px;color:#cccc00;font-size:12px">
          Your API key is ready to claim. The link below reveals it once and expires in 7 days. Save the key in your password manager the moment you see it — it is generated once and cannot be recovered.
        </div>
        <p style="color:#888;margin-bottom:24px">Plan: <strong style="color:#ededed">${escHtml((d.plan||'').toUpperCase())}</strong></p>
        <div style="margin-bottom:24px"><a href="${claimUrl}" style="display:inline-block;background:#ededed;color:#0c0c0c;text-decoration:none;padding:12px 20px;border-radius:6px;font-size:14px;font-weight:600">Reveal my API key</a></div>
        <p style="color:#555;font-size:12px;margin-bottom:24px">Or paste this link into your browser:<br><span style="color:#888;word-break:break-all">${claimUrl}</span></p>
        <p style="margin-top:24px;font-size:12px;color:#555"><a href="https://paramant.app/docs" style="color:#888">Docs</a> · <a href="https://paramant.app/ct-log" style="color:#555">CT log</a></p>
        <p style="margin-top:32px;font-size:11px;color:#333">ML-KEM-768 · Burn-on-read · EU/DE · BUSL-1.1</p>
      </div>`;
      const body = JSON.stringify({ from: 'PARAMANT <privacy@paramant.app>', to: [d.email], subject: 'Claim your PARAMANT API key', html });
      const resp = await new Promise((resolve, reject) => {
        const req2 = https.request({ hostname: 'api.resend.com', path: '/emails', method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        }, r => { let data = ''; r.on('data', c => data += c); r.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve({raw:data}); } }); });
        req2.on('error', reject);
        req2.write(body); req2.end();
      });
      if (resp.id) {
        log('info', 'welcome_mail_sent', { email: maskEmail(d.email), id: resp.id, label: d.label });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, id: resp.id }));
      } else {
        log('warn', 'welcome_mail_failed', { email: maskEmail(d.email), resp });
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

  // ── POST /v2/sign — ParaSign notary (R017) ───────────────────────────────────
  // The signature is made client-side; this relay NEVER receives a private key
  // and never receives document content -- only the SHA3-256 hash, the signer's
  // ML-DSA-65 signature, and the signer's public key. The relay verifies the
  // signature, logs it to the CT tree, and counter-signs the .psign envelope.
  if (path === '/v2/sign' && req.method === 'POST') {
    // RETIRED (H4): the legacy R017 notary verifies a bare, non-domain-separated
    // doc hash (no envelope/relay/recipe binding), unlike the R018 multi-party
    // recipe. It has no first-party callers — production signing uses the in-browser
    // R018 path (/sign -> /v2/user/sign/*). Return 410 rather than mint new weak
    // signatures. Existing .psign artifacts still verify via /v2/verify.
    res.writeHead(410, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'gone', message: 'POST /v2/sign (legacy R017 notary) is retired; sign in your browser at /sign (R018).' }));
  }
  if (path === '/v2/sign' && req.method === 'POST' && false) {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required (X-Api-Key)' })); }
    if (!mlDsa || !relayIdentity) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'ML-DSA-65 not available on this relay' })); }
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      const documentHash = (d.document_hash || '').toString().trim().toLowerCase();
      const signatureB64 = (d.signature || '').toString();
      const signerPubB64 = (d.signer_public_key || '').toString();
      const signerLabel  = d.signer_label ? d.signer_label.toString().slice(0, 256) : null;
      const ttlDays      = Number.isFinite(d.ttl_days) ? d.ttl_days : 365;

      if (!/^[0-9a-f]{64}$/.test(documentHash)) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'document_hash must be a 64-char SHA3-256 hex string' })); }
      if (!signatureB64 || !signerPubB64)       { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signature and signer_public_key are required' })); }

      // Refuse to notarise a signature that does not verify against the supplied
      // key. The signer MUST sign the domain-separated v2 message (pentest
      // #3/#4) so a signature minted for another purpose cannot be replayed as a
      // document notarisation. Legacy bare-hash (v1) signers are only accepted
      // when PARASIGN_ACCEPT_LEGACY_V1=true (transition escape hatch); by
      // default v1 is rejected, closing the cross-protocol replay.
      const _sigBuf = Buffer.from(signatureB64, 'base64');
      const _pubBuf = Buffer.from(signerPubB64, 'base64');
      const _sigEng = registry.getSig(0x0002);
      const _tryVerify = (bytes) => { try { return _sigEng.verify(_sigBuf, bytes, _pubBuf); } catch (e) { return false; } };
      let sigVersion = '2';
      let signerOk = _tryVerify(parasign.singleSignerMessage(documentHash));
      if (!signerOk && process.env.PARASIGN_ACCEPT_LEGACY_V1 === 'true') {
        signerOk = _tryVerify(Buffer.from(documentHash, 'hex'));
        if (signerOk) { sigVersion = '1'; log('warn', 'parasign_legacy_v1_signature', { doc: documentHash.slice(0, 16) + '…' }); }
      }
      if (!signerOk) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signer signature does not verify against signer_public_key (expected a v2 domain-separated signature: ML-DSA over sha3_256("paramant/parasign/notary/v1" || 0x00 || document_hash))' })); }

      // Phase 4 quota enforcement: decline a NEW counter-signature once the
      // monthly tier cap is reached. Verifying/reading existing envelopes is not
      // gated. Redis outages pass (fail-open).
      if (keyData && keyData.account_id) {
        const _sLimit = tiers.tierLimitNum(keyData.plan || 'community', 'signs_month');
        const _sGate  = await quota.gateSign(redisClient, keyData.account_id, _sLimit, log);
        if (!_sGate.allowed) {
          log('info', 'quota_sign_declined', { account: String(keyData.account_id).slice(0, 12), plan: keyData.plan || 'community', limit: _sLimit });
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'monthly_sign_quota_reached', dimension: 'signs_month', plan: keyData.plan || 'community', limit: _sLimit }));
        }
      }

      const signerPkHash = crypto.createHash('sha3-256').update(Buffer.from(signerPubB64, 'base64')).digest('hex');
      const ctEntry = ctAppendParasign(documentHash, signerPkHash);

      const envelope = parasign.buildEnvelope(
        { documentHashHex: documentHash, signatureB64, signerPubB64, signerLabel, ttlDays, ctLogIndex: ctEntry.index, version: sigVersion },
        { relaySign: (msg) => registry.getSig(0x0002).sign(msg, relayIdentity.sk), relayPkHash: relayIdentity.pk_hash });

      log('info', 'parasign_signed', { ct_index: ctEntry.index, signer_pk_hash: signerPkHash.slice(0, 16) + '…' });

      // (Sign already counted by the quota gate above, before the envelope was built.)

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, envelope }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // ── POST /v2/verify — ParaSign envelope verification (R017, public) ──────────
  // Stateless. The same checks run client-side; this is a convenience endpoint.
  if (path === '/v2/verify' && req.method === 'POST') {
    if (!mlDsa || !relayIdentity) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'ML-DSA-65 not available on this relay' })); }
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.envelope) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'envelope required' })); }
      const documentHashHex = d.document_hash ? d.document_hash.toString().trim().toLowerCase() : null;

      const result = parasign.verifyEnvelope(
        { documentHashHex, envelope: d.envelope },
        { sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch (e) { return false; } },
          relayPub: relayIdentity.pk });

      // The envelope signature can only be checked here if THIS relay notarised it.
      if (d.envelope.notary && d.envelope.notary.relay_pk_hash && d.envelope.notary.relay_pk_hash !== relayIdentity.pk_hash) {
        result.note = 'envelope was notarised by a different relay; verify its envelope_signature against notary.relay_pubkey_url';
      }

      const out = { valid: result.valid, errors: result.errors, verified_at: new Date().toISOString(),
        signer_label: (d.envelope.signer && d.envelope.signer.label) || null };
      if (result.note) out.note = result.note;
      res.writeHead(result.valid ? 200 : 422, { 'Content-Type': 'application/json' });
      return res.end(J(out));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // ── Multi-party envelope endpoints (ParaSign Model 2) ───────────────────────
  // The relay only knows: doc hash (sha3-256), envelope id (unguessable),
  // party labels, and party signatures over (sha3_256(id||doc_hash||index)).
  // Documents and private keys never reach this host.
  //
  // POST /v2/envelopes              -> create (auth: X-Api-Key)
  // GET  /v2/envelopes/:id          -> redacted status (public, rate-limited)
  // POST /v2/envelopes/:id/view     -> mark party viewed (public)
  // POST /v2/envelopes/:id/sign     -> party submits ML-DSA signature (public)
  function _envStore() {
    if (!redisClient || !redisClient.isReady) return null;
    if (!mlDsa || !registry || !relayIdentity) return null;
    if (!_envStore._inst) {
      _envStore._inst = new envelopeMod.EnvelopeStore(redisClient, {
        ctAppend: ctAppendEnvelope,
        sigVerify: (sig, msg, pub) => {
          try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; }
        },
      });
    }
    return _envStore._inst;
  }

  // POST /v2/envelopes -- create a new envelope.
  if (path === '/v2/envelopes' && req.method === 'POST') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required (X-Api-Key)' })); }
    if (!envCreateRateOk(apiKey)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' }); return res.end(J({ error: 'Envelope creation quota exceeded for this key (50/hour).' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable (redis or crypto not ready)' })); }
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      const docHash = (d.doc_hash || d.document_hash || '').toString().trim().toLowerCase();
      const parties = Array.isArray(d.parties) ? d.parties : [];
      const origFilename = (d.original_filename || '').toString();
      const ttlDays = Number.isFinite(d.ttl_days) ? d.ttl_days : envelopeMod.DEFAULT_TTL_DAYS;
      const creatorPkHash = d.creator_public_key
        ? crypto.createHash('sha3-256').update(Buffer.from(d.creator_public_key, 'base64')).digest('hex')
        : '';
      const creatorApiHash = crypto.createHash('sha3-256').update(apiKey).digest('hex');
      const out = await store.create({ creatorPkHash, creatorApiKeyHash: creatorApiHash, docHash, parties, originalFilename: origFilename, expiresInDays: ttlDays, bindingMode: d.binding_mode, recipeVersion: d.recipe_version });
      log('info', 'envelope_created', { id: out.id, parties: out.party_count, binding_mode: out.binding_mode });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, envelope: out }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // GET /v2/envelopes/:id -- redacted public status.
  if (req.method === 'GET' && path.startsWith('/v2/envelopes/')) {
    if (!envViewRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    const id = path.slice('/v2/envelopes/'.length).split('/')[0];
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(id)) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
    // Recipe the co-signer must reproduce. Open-mode slots are signer-bound
    // (recipe v4): the signer's public key is appended so the signature commits
    // to the exact key. Email/PRF slots stay email/document-hash bound (v2/v3).
    const recipeFor = (v, mode) => (mode || 'open') === 'open'
      ? 'sha3_256("paramant/parasign/doc/v1" || 0x00 || envelope.id || doc_hash || party_index_as_decimal || party_email_hash_bytes || signer_public_key_bytes)'
      : (v >= 2
        ? 'sha3_256(envelope.id || doc_hash || party_index_as_decimal || party_email_hash_bytes)'
        : 'sha3_256(envelope.id || doc_hash || party_index_as_decimal)');
    try {
      // ?p=<i>&t=<invite_token> -> party-scoped view. For email-bound envelopes
      // the token must match (getForParty returns null otherwise); for open
      // envelopes the token is not required. This gives the co-signer exactly
      // what it needs to recompute the (possibly v2) sign-message locally.
      if (query.p !== undefined) {
        const pi = parseInt(Array.isArray(query.p) ? query.p[0] : query.p, 10);
        const token = (Array.isArray(query.t) ? query.t[0] : query.t || '').toString();
        const view = await store.getForParty(id, pi, token);
        if (!view) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, envelope: view, sign_message_recipe: recipeFor(view.recipe_version, view.binding_mode) }));
      }
      const env = await store.getRedacted(id);
      if (!env) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, envelope: env, sign_message_recipe: recipeFor(env.recipe_version, env.binding_mode) }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'internal' }));
    }
  }

  // POST /v2/envelopes/:id/view -- party signals it has opened the envelope.
  if (req.method === 'POST' && path.startsWith('/v2/envelopes/') && path.endsWith('/view')) {
    if (!envViewRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    const id = path.slice('/v2/envelopes/'.length, -'/view'.length);
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(id)) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString() || '{}');
      const pi = parseInt(d.party_index, 10);
      if (!Number.isInteger(pi) || pi < 0) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
      // For email-bound envelopes the per-party invite token must match before
      // we record a view; getForParty returns null on a bad/absent token (and
      // does not require one for open envelopes).
      const gate = await store.getForParty(id, pi, (d.token || '').toString());
      if (!gate) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
      const ok = await store.markViewed(id, pi);
      if (!ok) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // POST /v2/envelopes/:id/sign -- party submits its ML-DSA-65 signature.
  if (req.method === 'POST' && path.startsWith('/v2/envelopes/') && path.endsWith('/sign')) {
    if (!envSignRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    const id = path.slice('/v2/envelopes/'.length, -'/sign'.length);
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(id)) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not found' })); }
    try {
      const d = JSON.parse((await readBody(req, 32768)).toString());
      const pi = parseInt(d.party_index, 10);
      const signerPub = (d.signer_public_key || '').toString();
      const sig = (d.signature || '').toString();
      const accountId = (d.account_id || '').toString();
      if (!Number.isInteger(pi) || pi < 0 || !signerPub || !sig) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'party_index, signer_public_key, signature required' }));
      }
      // Crypto M1: when the trusted admin proxy names the signer's account_id,
      // pin the submitted key to that account's ENROLLED active signing keys.
      // The email-binding check proves *which mailbox*; this proves the signature
      // was made by a key the account actually enrolled — so a leaked internal
      // token can't fill an email-bound slot with an attacker-substituted key.
      // Fail-closed (Redis is already a hard dependency of the envelope store).
      if (accountId) {
        try {
          const active = await userSigning.getActiveSigningPks(redisClient, accountId);
          const subj = Buffer.from(signerPub, 'base64');
          const enrolled = active.some(e => {
            try { return Buffer.from(e.pk_b64, 'base64').equals(subj); } catch { return false; }
          });
          if (!enrolled) { res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signer_not_enrolled' })); }
        } catch (e) {
          res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signer_not_enrolled' }));
        }
      }
      // Email-bound envelopes (R018): the store accepts the signature only when
      // a trusted internal caller (the admin proxy, which verified the signer's
      // authenticated session email) asserts a matching verified_email_hash.
      // _internalOk() gates that trust on the X-Internal-Auth header; a public
      // caller cannot set it, so it can never satisfy an email-bound slot.
      const internalTrusted = _internalOk();
      const verifiedEmailHash = (d.verified_email_hash || '').toString();
      const out = await store.sign(id, pi, signerPub, sig, { internalTrusted, verifiedEmailHash });
      if (!out.ok) {
        const code = out.code === 'not_found' ? 404
          : out.code === 'bad_signature' ? 400
          : (out.code === 'closed' || out.code === 'voided' || out.code === 'invite_expired') ? 410
          : (out.code === 'email_binding_required' || out.code === 'email_mismatch') ? 403
          : 409;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        return res.end(J({ error: out.code }));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, idempotent: out.code === 'idem', signed_count: out.signed_count, party_count: out.party_count, status: out.status }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
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
        sigValid = registry.getSig(0x0002).verify(Buffer.from(signature, 'base64'), Buffer.from(canonical, 'utf8'), relayIdentity.pk);
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
      // Bind the proof's leaf to the asserted blob_hash: recompute the leaf the
      // same way the relay produced it. Without this the proof only proves "some
      // leaf is in the tree", not that it is the leaf for THIS blob_hash. (The
      // signature already covers both, so this is defense-in-depth against a
      // relay self-inconsistency.)
      const expectedLeaf = blobLeafHash(receiptObj.blob_hash, receiptObj.sector, receiptObj.ts);
      if (proof.leaf_hash !== expectedLeaf) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ valid: false, reason: 'leaf_hash_mismatch' }));
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
          sthValid = registry.getSig(0x0002).verify(Buffer.from(sthSig, 'base64'), Buffer.from(sthCanonical, 'utf8'), relayIdentity.pk);
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
      log('warn', 'ws_key_in_querystring_rejected', { ip: maskIp(socket.remoteAddress) });
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
// Per-account key cap (SaaS product dimension). Orthogonal to the BUSL-fixed
// per-relay COMMUNITY_KEY_LIMIT: a key is over_limit if it busts EITHER (F).
// Community is env-tunable within 3..5; pro/enterprise are uncapped.
const ACCOUNT_KEY_LIMIT = Object.freeze({
  community: Math.min(5, Math.max(3, parseInt(process.env.ACCOUNT_KEY_LIMIT_COMMUNITY || '5', 10) || 5)),
  pro: Infinity,
  enterprise: Infinity,
});
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
  // Per-account cap (ACCOUNT_KEY_LIMIT) OR'd with the self-host relay-total cap
  // (LICENSE_MAX_KEYS, only when edition !== 'licensed'); see lib/keys-table
  // computeOverLimit. Flags v.over_limit but never deactivates a key — reversible
  // on upgrade, mirroring the prior community-edition behaviour.
  const over = keysTable.computeOverLimit(apiKeys, accounts, accountKeys, {
    capForPlan: (p) => ACCOUNT_KEY_LIMIT[tiers.normalisePlan(p)] ?? ACCOUNT_KEY_LIMIT.community,
    licenseMaxKeys: LICENSE_MAX_KEYS,
    edition: EDITION,
  });
  let flagged = 0;
  for (const [key, v] of apiKeys) {
    const was = v.over_limit;
    v.over_limit = over.has(key);
    if (v.over_limit) {
      flagged += 1;
      if (!was) log('warn', 'key_over_limit', { label: v.label, account: String(v.account_id || key).slice(0, 12) });
    }
  }
  const active = [...apiKeys.values()].filter((v) => v.active !== false).length;
  log('info', 'edition', { edition: EDITION, active_keys: active, relay_limit: LICENSE_MAX_KEYS === Infinity ? 'unlimited' : LICENSE_MAX_KEYS, account_cap_community: ACCOUNT_KEY_LIMIT.community, over_limit: flagged });
}


// ── Self-registration — announce this relay to the registry ───────────────────
async function registerSelf() {
  if (!relayIdentity || !RELAY_SELF_URL) return;
  const target = RELAY_PRIMARY_URL || `http://localhost:${PORT}`;
  const timestamp = new Date().toISOString();
  const msg = Buffer.from(RELAY_SELF_URL + '|' + SECTOR + '|' + VERSION + '|' + timestamp, 'utf8');
  // API in @noble/post-quantum: sign(message, secretKey)
  let sig;
  try { sig = Buffer.from(registry.getSig(0x0002).sign(msg, relayIdentity.sk)); } catch (e) {
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
if (ctWindow.windowLength > 0 && sthLog.length === 0) {
  const last = ctWindow.last();
  produceSth(ctWindow.windowLength, last.tree_hash);
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
