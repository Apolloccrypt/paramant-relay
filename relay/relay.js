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
// Same module, second name. The request handler declares `const path =
// parsed.pathname`, which shadows the module for the whole body of that
// function, so a path.join() below that line is a method call on a string and
// throws. Inside a try/catch that is not a crash but a permanent wrong answer:
// the storage probe of /v2/health/deep has reported "not writable: path.join
// is not a function" on every request since it was written. Code inside the
// request handler uses nodePath.
const nodePath = path;
const url_   = require('url');
const { createClient } = require('redis');
const clientIpLib = require('./lib/client-ip');
const userTotp      = require('./lib/user-totp');
const totpLib       = require('./lib/totp');
const redisDeadlines = require('./lib/redis-deadline'); // one bound for every redis call
const redisCounter  = require('./lib/redis-counter');   // INCR that always carries an expiry
const rateLimit     = require('./lib/rate-limit');
const authThrottle  = require('./lib/auth-throttle');
const authGate      = require('./lib/auth-gate');
const sessionTokens = require('./lib/session-token'); // pst_ ParaSend session tokens
const userSigning   = require('./lib/user-signing');
const userWebauthn  = require('./lib/user-webauthn');
const tiers         = require('./lib/tiers');
const entitlements  = require('./lib/entitlements'); // product+tier separation (ParaSend vs ParaSign)
const quota         = require('./lib/quota');
const keysTable     = require('./lib/keys-table');

// Single source of truth for the relay version: relay/package.json, held equal
// to the root package.json, both Docker labels and the deploy check by
// tests/version-consistency.test.mjs. This used to be a literal, and that
// literal said 3.1.0 while relay/package.json and the image label both said
// 3.0.0 -- four places, three answers, which is what made a tag meaningless.
// package.json is COPY'd into the runtime stage of relay/Dockerfile for exactly
// this read; the fallback only covers a stripped deployment and is deliberately
// loud rather than a plausible wrong number.
const VERSION    = (() => {
  try { return require('./package.json').version; }
  catch { return '0.0.0-unknown'; }
})();
// Per-restart nonce: stream-next hashes non-precomputable even if API key is known
const STREAM_NONCE = crypto.randomBytes(32);

// ── WS ticket store — avoids API key in WebSocket upgrade URL (finding #13) ──
// Client calls POST /v2/ws-ticket → gets 30s one-time ticket → connects with ?ticket=xxx
const wsTickets = new Map(); // ticket → { apiKey, expires }
setInterval(() => { const now = Date.now(); for (const [k, v] of wsTickets) if (now > v.expires) wsTickets.delete(k); }, 10_000);


// ── Drop / Argon2id / BIP39 — optioneel laden ─────────────────────────────────
let argon2Lib = null;
try { argon2Lib = require('argon2'); } catch(e) { /* npm install argon2 */ }
// A redis call that answers inside a deadline, or an outage. node-redis queues
// commands while it reconnects, so against an unreachable server a GET neither
// resolves nor rejects: the route waits, forever.
//
// #368 bounded exactly one read, on the TOTP path, and wrote the rest up in
// SECURITY.md as open: "every other redis-backed route still inherits it". It
// does not any more. The bound now lives on the CLIENT (lib/redis-deadline),
// so every command in relay.js, relay/lib/* and envelope.js is bounded by
// construction rather than by a list somebody has to keep correct. The name of
// the knob is unchanged, PARAMANT_REDIS_DEADLINE_MS, and it is now the single
// configuration source for both services.
const REDIS_DEADLINE_MS = redisDeadlines.redisDeadlineMs();
function redisDeadline(promise, ms = REDIS_DEADLINE_MS) {
  return redisDeadlines.withRedisDeadline(promise, { ms, op: 'redis' });
}

// Redis client for user TOTP endpoints
const RELAY_REDIS_URL = process.env.REDIS_URL || '';
let redisClient = null;
if (RELAY_REDIS_URL) {
  // guardRedisClient is what makes the bound unconditional; redisClientBounds
  // adds disableOfflineQueue, without which a command issued during a reconnect
  // is held rather than refused. Neither is sufficient alone: the queue is what
  // hangs a dead socket, the deadline is what catches a black hole, where the
  // client still believes it is ready.
  redisClient = redisDeadlines.guardRedisClient(
    createClient({ url: RELAY_REDIS_URL, ...redisDeadlines.redisClientBounds() }),
    { ms: REDIS_DEADLINE_MS, label: 'relay/redis' });
  redisClient.on('error', (err) => console.error('[relay/redis] error:', err.message));
  redisClient.connect()
    .then(() => console.log('[relay/redis] connected'))
    .catch(e => console.error('[relay/redis] connect failed:', e.message));
}

const PORT       = parseInt(process.env.PORT       || '3000');
const USERS_FILE = process.env.USERS_FILE          || './users.json';
const TTL_MS     = parseInt(process.env.TTL_MS     || '300000');
// The largest single BLOB the relay accepts on the wire, in bytes. Every blob a
// client sends is padded to exactly this size (crypto-wasm BLOCK), so the length
// of an upload says nothing about the file inside it.
//
// THIS IS NOT THE FILE SIZE LIMIT, and reading it as one is the bug this file
// carried for a long time. The relay never sees a file: a 500 MB file arrives as
// 112 separate padded blobs, each one of these. The file ceiling is a product
// number and lives in relay/lib/tiers.js as `file_mb`; it is enforced by
// counting a file's blocks (see FILE_CEILING below), not by comparing one blob
// against it. `Math.min(MAX_BLOB, file_mb * 1048576)` on a single blob was that
// confusion written down, and it held every file on every tier to 5 MB.
//
// Move this number only when the wire format or the memory budget changes.
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
const billingCatalog  = require('./lib/billing-catalog');   // server-side price + entitlement map
const mollie          = require('./lib/mollie');            // Mollie Payments API client
const billing         = require('./lib/billing');           // Mollie webhook decision state machine
const billingRecurring = require('./lib/billing-recurring'); // subscription + mandate layer
const parasignStoreMod = require('./lib/parasign-store');    // durable encrypted /v1 side-store
const parasignStamp = require('./lib/parasign-stamp');       // server-side PDF stamp-worker
const qes           = require('./lib/qes');                   // qualified-signature layer, off unless flagged
const tierGate         = require('./lib/tier-gate');         // per-tier feature gate (billing hardening)
const userHistory      = require('./lib/user-history');      // GET /v2/user/history (Pro+)
const usagePurpose     = require('./lib/usage-purpose');     // POST /v2/user/usage-purpose (internal)
const parasignAuditExport = require('./lib/parasign-audit-export'); // GET /v2/parasign/audit-export (Business+)
const transferNotify   = require('./lib/transfer-notify');   // ParaSend Pro upload/download mail
const invoiceMod       = require('./lib/invoice');            // invoice numbering, records and VAT split
const invoicePdf       = require('./lib/invoice-pdf');        // one-page PDF writer, no dependency
const creditNote       = require('./lib/credit-note');        // credit notes (CN series) for money that goes back
const billingHistory   = require('./lib/billing-history');    // one chronological list, derived from the records
const billingExport    = require('./lib/billing-export');     // period export of both series, CSV/JSON, for the books
const zipStore         = require('./lib/zip-store');          // store-only zip writer, no dependency
const moneybird        = require('./lib/moneybird');          // optional Moneybird push (external sales invoices)
const planExpiry       = require('./lib/plan-expiry');      // paid-term warning + expiry mail (in-process planner)
const coupon           = require('./lib/coupon');             // gift codes: a term given away, never a sale
const sharedGrants     = require('./lib/shared-grants');     // one paid term, visible on every relay container
const partyBackfill    = require('./lib/parasign-party-backfill'); // one-shot fill of the party worklist index

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
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/session','/v2/session-token',
               '/v2/ws-ticket','/v2/fingerprint','/v2/relays','/v2/sign-dpa',
               '/v2/sth','/v2/verify-receipt','/v2/transfers','/v2/capabilities','/v2/health','/ct','/ct/feed','/v2/auth','/v2/user','/v2/setup',
               '/v2/sign','/v2/verify','/v2/lookup-signer','/v2/envelopes','/v2/billing','/v2/claim','/v2/parasign','/v2/qes','/v1'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/anon-inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/ack','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/session','/v2/session-token',
               '/v2/relays','/v2/sign-dpa','/v2/sth','/v2/verify-receipt','/v2/transfers',
               '/v2/capabilities','/v2/health','/ct','/ct/feed','/v2/auth','/v2/user','/v2/setup',
               '/v2/sign','/v2/verify','/v2/lookup-signer','/v2/envelopes','/v2/billing','/v2/claim','/v2/parasign','/v2/qes','/v1'],
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
const { CtWindow, reindexEntries } = require('./lib/ct-window');
const ctWindow = new CtWindow(CT_MAX);
// Where the transparency log lives on disk.
//
// This used to be `process.env.CT_FILE || null`: opt-in, RAM-only unless a
// deployment remembered to set it. docker-compose.yml does set it, so
// production was fine and nobody looked again. Every other relay - a self-host,
// a community node, a `node relay.js` on a laptop - kept its whole log in
// memory and lost it on restart, and losing it is not the worst part.
//
// Measured on a booted relay: four entries, restart, and the log comes back at
// size 0 while RELAY_IDENTITY_FILE brings the SAME signing key back, and
// STH_FILE brings the old signed heads back with it. The relay then signs
// tree_size 1 again over a different root, so /v2/sth/history ends up holding
// two contradictory heads for the same tree size under one key. Not an empty
// log: a forked one, published, signed, and indistinguishable from tampering.
// Every receipt issued before the restart also stops resolving - /v2/ct/proof
// answers 404 for an index that is now beyond the log's own size.
//
// So persistence is the default now, and it lands wherever the signed heads
// already land: the head and the tree it attests to belong on the same volume,
// and a deployment that sets STH_FILE to a writable path was already saying
// where that is. An explicitly EMPTY CT_FILE still selects RAM-only, for the
// caller who means it; unset no longer means it by accident.
const _ctFileDefault = () => {
  const sth = process.env.STH_FILE;
  return sth ? nodePath.join(nodePath.dirname(sth), 'ct-log.json') : '/data/ct-log.json';
};
const CT_FILE = process.env.CT_FILE !== undefined
  ? (process.env.CT_FILE || null)   // explicit, empty means RAM-only on purpose
  : _ctFileDefault();
const CT_MAX_SIZE = parseInt(process.env.CT_MAX_SIZE || String(100 * 1024 * 1024)); // 100 MB default

// Fix 8: async CT write stream with queued writes and log rotation
let _ctStream    = null;
let _ctWriteQueue = [];
let _ctDraining  = false;

function _ctOpenStream() {
  if (!CT_FILE) return;
  // mkdir first, as _sthOpenStream already did. Without it a fresh volume that
  // has no /data yet takes the CT log back to RAM-only silently, which is the
  // state this default exists to end.
  try {
    fs.mkdirSync(nodePath.dirname(CT_FILE), { recursive: true });
    _ctStream = fs.createWriteStream(CT_FILE, { flags: 'a' });
    _ctStream.on('error', e => log('warn', 'ct_stream_error', { err: e.message }));
  } catch (e) {
    log('error', 'ct_log_not_persisted', {
      err: e.message, file: CT_FILE,
      hint: 'The transparency log is RAM-only: it is lost on restart and the relay '
          + 'will refuse to sign a tree head that contradicts one it already signed. '
          + 'Point CT_FILE at a writable path.',
    });
  }
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
    // One-shot, idempotent recount of the stored index field (2026-09). The
    // public log had five entries whose persisted .index was stale after an
    // April rebuild: positions 42..46 carried indices 4..8, so /v2/ct/log
    // listed duplicates while /v2/ct/proof, which resolves by position, was
    // right all along. The index of an entry IS its position, so recount from
    // position here, before the window is built, and persist the correction so
    // the next boot finds nothing to do. Only the index field is rewritten:
    // the line order and every leaf_hash stay exactly as they were, which is
    // what keeps the Merkle root byte-identical. One log line per log.
    const ctFixed = reindexEntries(loaded);
    if (ctFixed > 0) {
      log('info', 'ct_log_reindexed', { fixed: ctFixed, entries: loaded.length, file: CT_FILE });
      // Write to a sibling temp file and rename over the original, so a crash
      // mid-write leaves the old log intact rather than a half-written one.
      try {
        const tmp = CT_FILE + '.reindex.tmp';
        fs.writeFileSync(tmp, loaded.map(e => JSON.stringify(e) + '\n').join(''));
        fs.renameSync(tmp, CT_FILE);
      } catch (e) {
        log('warn', 'ct_log_reindex_write_failed', { err: e.message, file: CT_FILE });
      }
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
    fs.mkdirSync(nodePath.dirname(STH_FILE), { recursive: true });
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

// What this relay has already put its name to. Two things, because they catch
// two different halves of the same break:
//   _sthSignedRoots  tree_size -> sha3_root, for the heads still in sthLog. It
//                    is pruned in step with sthLog, so it stays bounded by
//                    STH_MAX and does not grow with the log.
//   _sthMaxSignedSize the largest tree_size ever signed. One number, never
//                    pruned, and the half that survives the window: a tree that
//                    walked BACKWARDS is a contradiction even when the head it
//                    contradicts has aged out of memory.
const _sthSignedRoots = new Map();
let _sthMaxSignedSize = -1;
for (const s of sthLog) {
  if (!s || typeof s.tree_size !== 'number' || !s.sha3_root) continue;
  _sthSignedRoots.set(s.tree_size, s.sha3_root);
  if (s.tree_size > _sthMaxSignedSize) _sthMaxSignedSize = s.tree_size;
}
// Set once the relay has caught a contradiction. It is not cleared: a log that
// has forked stays forked until someone looks at it.
let ctLogForked = null;

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
        fs.mkdirSync(nodePath.dirname(RELAY_IDENTITY_FILE), { recursive: true });
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
  // ct_index is taken from the window position, not from the entry's stored
  // index field: this runs over entries rehydrated from disk, and that field
  // is the one a rebuild can leave stale. The startup recount above already
  // repairs it, but reading position keeps this correct even when the log is
  // fed from somewhere the recount did not touch.
  for (let p = 0; p < ctWindow.entries.length; p++) {
    const entry = ctWindow.entries[p];
    if (entry.type !== 'relay_reg') continue;
    const key = entry.relay_pk_hash;
    if (!key) continue;
    const ctIndex = ctWindow.logicalIndexAt(p);
    const existing = relayRegistry.get(key);
    if (!existing) {
      relayRegistry.set(key, {
        url: entry.relay_url, sector: entry.relay_sector,
        version: entry.relay_version, edition: entry.relay_edition || 'community',
        pk_hash: key, verified_since: entry.ts, last_seen: entry.ts,
        ct_index: ctIndex, last_ct_index: ctIndex
      });
    } else {
      existing.last_seen    = entry.ts;
      existing.last_ct_index = ctIndex;
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

// The field gate. Every name that reaches a log entry, a leaf preimage or an
// entry type is declared in ./lib/ct-fields, and relay/test/ct-fields.test.js
// holds that declaration against a hand-written copy AND against the literals
// this file really passes. The log is the one place where a stray field is
// permanent and public at once, so it is the one place worth this much
// ceremony. See the header of ct-fields.js for what went wrong without it.
const ctFields = require('./lib/ct-fields');

// Strip anything undeclared off an entry before it is stored, written to
// CT_FILE or projected onto a public route, and say loudly that it happened.
// Stripping rather than throwing: an undeclared field is by construction one no
// reader knows about, so dropping it breaks nothing that exists, while letting
// it through publishes it forever.
function ctGateEntry(family, entry) {
  const { entry: gated, rejected } = ctFields.gateEntry(family, entry);
  if (rejected.length) {
    log('error', 'ct_entry_field_rejected', {
      family, type: entry.type || 'key_reg', rejected,
      hint: 'A field reached a CT log entry without being declared in relay/lib/ct-fields.js. '
          + 'It was dropped. If the log should carry it, add it there and to '
          + 'relay/test/ct-fields.test.js, which is where someone has to write down why.',
    });
  }
  return gated;
}

// The same gate for a payload, applied BEFORE the leaf is hashed. Order is
// load-bearing: the leaf commits to the payload, so gating after hashing would
// commit to a field the stored entry no longer has, and every recomputation of
// that leaf would then fail.
function ctGatePayload(eventType, payload) {
  const { payload: gated, rejected } = ctFields.gatePayload(eventType, payload);
  if (rejected.length) {
    log('error', 'ct_payload_field_rejected', {
      type: eventType, rejected,
      hint: 'Declare it in PAYLOAD_FIELDS in relay/lib/ct-fields.js, or leave it out of the log.',
    });
  }
  return gated;
}

// An event type is a leaf format: it is concatenated into the entry type and,
// for the signing-key and envelope families, hashed into the leaf preimage. An
// undeclared one throws, and that is safe to do BECAUSE ct-fields.test.js scans
// this file and envelope.js for the literals actually passed and fails if any
// of them is missing from the list. Without that scan this is exactly the guard
// that silently broke trust-on-first-use enrolment for months.
function ctRequireEventType(family, eventType) {
  if (!ctFields.isAllowedEventType(family, eventType)) {
    throw new Error(`ct-fields: undeclared ${family} event type "${eventType}": `
      + 'add it to EVENT_TYPES in relay/lib/ct-fields.js and say why in relay/test/ct-fields.test.js');
  }
}

// ── The hour, defined once ───────────────────────────────────────────────────
// Everything the CT log publishes about WHEN something happened is rounded to
// the top of its hour, and every route that does that rounding goes through one
// of these two functions. One definition, so a new public projection cannot
// quietly pick a different resolution, and so relay/test/route-ct-public-time.test.js
// has a single thing to hold every route to.
//
// The full-precision timestamp stays in the stored entry (it is committed in
// the leaf hash, so a receipt must carry it back for /v2/verify-receipt) and in
// the receipt the customer keeps. Precision belongs in the private receipt;
// coarseness belongs in the public log.
const CT_HOUR_MS = 3_600_000;

// Epoch milliseconds -> the top of that hour, still epoch milliseconds.
function ctCoarseMs(ms) {
  const n = typeof ms === 'number' ? ms : Number(ms);
  if (!Number.isFinite(n)) return ms;
  return Math.floor(n / CT_HOUR_MS) * CT_HOUR_MS;
}

// ISO timestamp -> the top of its hour, as an ISO timestamp.
function ctCoarseTs(ts) {
  if (!ts) return ts;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return new Date(ctCoarseMs(d.getTime())).toISOString();
}

// Recursive canonical JSON (sorted keys, no whitespace) — used for signing receipts + STH.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

// Every ctAppend* below takes its index from ctWindow.nextIndex(), which is
// base + window length: the position the new leaf is about to occupy. The
// value is stored on the entry as a convenience for the response it goes into,
// and CtWindow.append() rejects an entry whose index is not nextIndex(), so a
// freshly appended entry can never disagree with its position. Read paths that
// serve entries back out do not rely on that field regardless; see /v2/ct/log.
function ctAppend(deviceId, pubKeyHex, apiKey) {
  const ts = new Date().toISOString();
  const deviceIdHash = crypto.createHash('sha3-256').update(deviceId + apiKey.slice(0,8)).digest('hex');
  const leaf_hash = ctLeafHash(deviceIdHash, pubKeyHex, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1); // real audit path at the new leaf position
  const entry = ctGateEntry('key_reg', { index, leaf_hash, tree_hash, device_hash: deviceIdHash, ts, proof });
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
  const entry = ctGateEntry('relay_reg', {
    index, type: 'relay_reg', leaf_hash, tree_hash,
    device_hash: pkHash,          // reused field — relay public key hash
    relay_url: relayUrl, relay_sector: sector,
    relay_version: version, relay_edition: edition,
    relay_pk_hash: pkHash,
    ts, proof
  });
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
  const entry = ctGateEntry('transfer', {
    index, type: 'transfer', leaf_hash, tree_hash,
    blob_hash: blobHash, sector, ts, proof
  });
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
  const entry = ctGateEntry('parasign', {
    index, type: 'parasign', leaf_hash, tree_hash,
    document_hash: documentHashHex, signer_pk_hash: signerPkHash, ts, proof
  });
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
}

// Appends an envelope lifecycle event (create / view / sign / complete) to
// the CT log. The relay never sees the document - the leaf commits only to
// the envelope id, event type, and a sha3-256 over the structured payload.
function ctAppendEnvelope(eventType, envelopeId, payload) {
  // `type` is the event name as given, not 'envelope_' + it. Every call site in
  // envelope.js already passes the full name ('envelope_sign', 'envelope_void',
  // ...), so the old concatenation published 'envelope_envelope_sign', and
  // scripts/heartbeat/parasign.mjs has been filtering the public log for
  // `type === 'envelope_sign'` against a value that never existed. That check
  // is the strongest evidence the ParaSign heartbeat collects, and it could not
  // fire. The declared list below is what would have caught it, which is why
  // this repair rides along with the gate rather than as a separate errand.
  //
  // Nothing already signed moves: the leaf preimage is
  // ctLeafHash(envelopeId, sha3(eventType|id|payload), ts) and takes the raw
  // eventType, never this string. `type` lives on the entry and in the public
  // projection only, so no inclusion proof and no receipt changes value.
  const type = eventType;
  ctRequireEventType('envelope', type);
  // Gated first, then hashed: the leaf commits to this object, so it must be
  // the same object the entry stores.
  const gatedPayload = ctGatePayload(type, payload);
  const ts = new Date().toISOString();
  const valueHash = crypto.createHash('sha3-256')
    .update(eventType).update('|').update(envelopeId).update('|')
    .update(JSON.stringify(gatedPayload)).digest('hex');
  const leaf_hash = ctLeafHash(envelopeId, valueHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = ctGateEntry('envelope', {
    index, type, leaf_hash, tree_hash,
    envelope_id: envelopeId, payload: gatedPayload, ts, proof
  });
  ctWindow.append(entry);
  ctWrite(entry);
  produceSth(allEntries.length, entry.tree_hash);
  return entry;
}

// Appends a signing-pubkey lifecycle event (enroll / revoke) to the CT log so
// identity changes are tamper-evident. user_id is hashed (SHA3-256) before
// emission — verifiers see a stable identity-handle without the raw API key.
// `eventType` is one of EVENT_TYPES.signing_pk in relay/lib/ct-fields.js.
function ctAppendSigningPkEvent(eventType, userId, signerPkHash) {
  // This guard used to name two of the four types its own call sites pass:
  // 'signing_pk_enrolled_tofu' and 'signing_pk_enrolled_attested' threw here,
  // the route's outer catch turned that into a 500 AFTER the key was stored,
  // and neither enrolment path ever reached the transparency log. The list now
  // lives in ct-fields.js with a test that scans the call sites, so a name can
  // no longer be missing from it without the build saying so.
  ctRequireEventType('signing_pk', eventType);
  const ts = new Date().toISOString();
  const userIdHash = crypto.createHash('sha3-256').update(String(userId)).digest('hex');
  const leaf_hash = ctLeafHash(userIdHash, signerPkHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = ctGateEntry('signing_pk', {
    index, type: eventType, leaf_hash, tree_hash,
    user_id_hash: userIdHash, signer_pk_hash: signerPkHash, ts, proof
  });
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
  // Append-only, enforced. A transparency log's whole claim is that tree_size
  // only ever grows and that a size, once signed, keeps its root forever. Both
  // break at once when the tree is lost but the key and the head history are
  // not: the relay walks back to tree_size 1 and signs a second, different root
  // for it. That signature is real, so no verifier can tell it from tampering,
  // and the relay produced it without a single warning.
  //
  // So a head that contradicts one already signed is not produced at all. A
  // missing head is visible and recoverable; a forged-looking one is neither.
  // Re-signing the SAME root at the same size is allowed: that is idempotent,
  // not a contradiction.
  const priorRoot = _sthSignedRoots.get(tree_size);
  const contradicts = priorRoot !== undefined && priorRoot !== sha3_root;
  const wentBackwards = tree_size < _sthMaxSignedSize;
  if (contradicts || wentBackwards) {
    if (!ctLogForked) {
      ctLogForked = {
        tree_size, max_signed_size: _sthMaxSignedSize,
        signed_root: priorRoot || null, refused_root: sha3_root,
        reason: contradicts ? 'root_differs_at_same_size' : 'tree_size_went_backwards',
        at: new Date().toISOString(),
      };
    }
    log('error', 'sth_refused_would_fork', {
      tree_size, max_signed_size: _sthMaxSignedSize,
      reason: contradicts ? 'root_differs_at_same_size' : 'tree_size_went_backwards',
      signed_root: priorRoot ? priorRoot.slice(0, 16) + '…' : null,
      refused_root: String(sha3_root).slice(0, 16) + '…',
      hint: 'This relay has already signed a larger or different tree. The usual cause is a '
          + 'restart with a persisted STH log and a CT log that was not persisted. Restore CT_FILE '
          + 'from backup, or start a new relay identity; do not delete the STH log.',
    });
    return null;
  }
  // The timestamp is coarsened to the hour BEFORE it is signed, because it is
  // the sharpest of the three doors onto the exact time of a leaf, not the
  // mildest. An STH is produced on every single append, so tree_size N is leaf
  // N-1, and this timestamp used to be Date.now() taken microseconds after that
  // leaf's own ts. Measured on a booted relay: given the leaf hash from
  // /v2/ct/log and the STH at tree_size = index + 1 from /v2/sth/history, a
  // candidate document was confirmed in ONE hash. That is worse than the feed
  // was: the feed carried fifty entries, the history carries a thousand, the
  // heads are mirrored to every peer, and the leak was inside a signature, so
  // coarsening it in the projection would have been a lie rather than a fix.
  // Hence at production. Old heads on disk keep the precise timestamp they were
  // signed with and still verify: verification recomputes the canonical payload
  // from whatever fields the head carries, both in receipt-verify.js and in
  // /v2/sth/ingest, and neither pins a resolution.
  //
  // The cost is real and worth naming: an archiver can no longer tell from a
  // head alone where in the hour it was signed. tree_size still orders the
  // heads, monotonically and per append, so freshness monitoring and the
  // consistency proofs are untouched. The log's own resolution has been an hour
  // everywhere else all along; the head was the one place still saying more.
  const payload  = { relay_id, sha3_root, timestamp: ctCoarseMs(Date.now()), tree_size, version: 1 };
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
  _sthSignedRoots.set(tree_size, sha3_root);
  if (tree_size > _sthMaxSignedSize) _sthMaxSignedSize = tree_size;
  sthLog.push(sth);
  // Prune the root map in step with the head window so it stays bounded.
  // _sthMaxSignedSize is what keeps the guard whole past this point.
  if (sthLog.length > STH_MAX) { const dropped = sthLog.shift(); _sthSignedRoots.delete(dropped.tree_size); }
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
    const stream = fs.createWriteStream(nodePath.join(PEER_STH_DIR, safe + '.jsonl'), { flags: 'a' });
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
    try { fs.unlinkSync(nodePath.join(PEER_STH_DIR, pkHash.replace(/[^a-f0-9]/g, '').slice(0, 64) + '.jsonl')); } catch {}
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
        const lines = fs.readFileSync(nodePath.join(PEER_STH_DIR, file), 'utf8').split('\n').filter(l => l.trim());
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
  // ct_log_persisted and ct_log_forked are the two the transparency log is
  // actually judged on. A relay whose log is RAM-only is one restart away from
  // signing a second history, and a relay that has refused to sign has stopped
  // producing heads entirely. Both were invisible before: the first showed as
  // nothing at all, the second as a log that simply went quiet.
  for(const [k,v] of [['blobs_in_flight',blobStore.size],['pubkeys',pubkeys.size],['edition',EDITION==='licensed'?1:0],['did_registry',didRegistry.size],['ct_log',ctWindow.size],['ct_log_persisted',CT_FILE?1:0],['ct_log_forked',ctLogForked?1:0],['uptime_s',Math.floor(process.uptime())],['heap_bytes',process.memoryUsage().heapUsed]]){
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

function base32Decode(s) { return totpLib.base32Decode(s); }

function totpCode(secret, counter, algorithm = 'sha256') { return totpLib.totpCode(secret, counter, algorithm); }

// Fix 5: used-code tracking — window = 30s each side → 3 windows × 30s = 90s expiry
const _usedTotpCodes = new Map(); // code+counter → expiry ms
setInterval(() => { const now = Date.now(); for (const [k, exp] of _usedTotpCodes) if (now > exp) _usedTotpCodes.delete(k); }, 30_000);

function verifyTotp(token) {
  if (!TOTP_SECRET) return false;
  const tokenBuf = Buffer.from(String(token || ''), 'utf8');
  if (tokenBuf.length !== 6) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  // Dual-verify: accept a code valid under SHA-256 OR SHA-1 (the RFC 6238 default),
  // so admin login works with Google/Microsoft Authenticator and iCloud Keychain.
  // Both algorithm passes and every window run in full (never short-circuit) so the
  // scan stays constant-time, and the per-slot replay guard is preserved unchanged.
  let matched = false;
  for (const algorithm of ['sha256', 'sha1']) {
    for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
      const c = counter + i;
      const expected = totpCode(TOTP_SECRET, c, algorithm);
      const expectedBuf = Buffer.from(expected, 'utf8');
      const eq = tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf);
      if (eq) {
        // Fix 5c: reject reused codes: key = token + counter slot
        const useKey = `${token}:${c}`;
        if (_usedTotpCodes.has(useKey)) { matched = false; continue; }
        _usedTotpCodes.set(useKey, (c + 2) * 30 * 1000); // expire after 2 windows past use
        matched = true;
      }
    }
  }
  return matched;
}
async function verifyTotpGeneric(token, secret, opts = {}) {
  // Delegates to the extracted pure core; redisClient is the injected replay store.
  return totpLib.verifyTotpGeneric(token, secret, opts, redisClient);
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
    if (!authGate.sessionValid(s, now)) sessions.delete(id);
  }
}, 60000);


// ── RAM guard ────────────────────────────────────────────────────────────────
// Blobs live in RAM and only in RAM. That is a promise this product makes in
// terms.html, in press.html and in the Art. 28 processing register in dpa.html,
// so the way to carry bigger files is to hold each one for a shorter time, not
// to spill it to disk. Capacity here is therefore a memory budget.
//
// THE TWO NUMBERS, and this is the meaning scripts/check-guards.mjs enforces:
// RAM_LIMIT_MB is what blobs may occupy, and RAM_RESERVE_MB is headroom ADDED
// on top of it for the process itself. The guard trips at the SUM, so the sum
// is what has to stay below the container's cgroup limit. It did not: the
// health relay ran 8192 + 512 inside a container capped at 8192, so the kernel
// always got there first and the guard was dead code. That was fixed by moving
// the numbers to 6656 + 512, and check-guards.mjs now fails the build if the
// sum ever climbs back to the cap.
//
// What changes here is only HOW the budget is spent, not what the two numbers
// mean: the ceiling used to be a count of 5 MB slots, which stopped being the
// right unit once a single transfer could be a hundred of them. It is bytes
// now. Do not reinterpret RAM_RESERVE_MB as a slice held back below the limit;
// operators and self-host installs set these, and check-guards.mjs reads them
// the way they are described above.
const RAM_LIMIT_MB    = parseInt(process.env.RAM_LIMIT_MB    || '512');
const RAM_RESERVE_MB  = parseInt(process.env.RAM_RESERVE_MB  || '256');
// What blobs may occupy, in bytes.
const BLOB_BUDGET_BYTES = Math.max(32 * 1048576, RAM_LIMIT_MB * 1048576);
// Kept as a blob COUNT for the status view and the self-host installs that read
// it, but derived from the byte budget rather than being the budget itself.
const BLOB_SIZE_MB    = 5;
const MAX_BLOBS       = Math.floor(BLOB_BUDGET_BYTES / (BLOB_SIZE_MB * 1048576));

// Running total of blob bytes, kept as blobs are stored and dropped. The old
// version summed the whole map on every call, and ramOk() runs on every upload:
// at a hundred blobs per transfer that is a full scan per chunk.
let blobBytesHeld = 0;

function ramStats() {
  const mem    = process.memoryUsage();
  const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
  const rssMB  = Math.round(mem.rss      / 1024 / 1024);
  return {
    heapMB, rssMB,
    blobBytes: blobBytesHeld,
    blobMB: Math.round(blobBytesHeld / 1024 / 1024),
    blobCount: blobStore.size,
  };
}

// Is there room for one more blob? Two independent questions, and both have to
// answer yes.
//
//   1. the blob budget: what is already held, plus what is mid-upload, plus the
//      one being asked about, must fit in BLOB_BUDGET_BYTES.
//   2. actual process memory: RSS must stay under RAM_LIMIT_MB + RAM_RESERVE_MB,
//      which scripts/check-guards.mjs holds below the container's cgroup limit,
//      so this branch can actually fire. It catches the memory a blob costs on the way
//      in that the budget does not model -- a 5 MiB blob arrives base64'd inside
//      a JSON body, so it is roughly 19 MB of transient buffers before it
//      becomes a 5 MiB Buffer.
function ramOk() {
  const { rssMB } = ramStats();
  const wouldHold = blobBytesHeld + (inFlightInbound + 1) * MAX_BLOB;
  if (wouldHold > BLOB_BUDGET_BYTES) return false;
  if (rssMB + Math.ceil(((inFlightInbound + 1) * MAX_BLOB * 4) / 1048576) > RAM_LIMIT_MB + RAM_RESERVE_MB) return false;
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
    blob_budget_mb:   Math.round(BLOB_BUDGET_BYTES / 1048576),
    blob_budget_free_mb: Math.max(0, Math.round((BLOB_BUDGET_BYTES - s.blobBytes) / 1048576)),
    ram_ok:           ramOk(),
    available_slots:  Math.max(0, Math.floor((BLOB_BUDGET_BYTES - s.blobBytes) / MAX_BLOB) - inFlightInbound),
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
// sha256(api_key) → api_key. A ParaSend session-token record names its owner by
// hash, never in the clear, so a read-only leak of the store (an RDB snapshot,
// a replica, a backup, a MONITOR session) carries no live pgp_ key. This map is
// the way back, and it exists only in this process's memory: nothing derives a
// key from a hash, it is looked up in the table the relay already has.
const apiKeyByHash = new Map();
let _hashIndexBuiltAt = 0;
function rebuildApiKeyHashIndex() {
  apiKeyByHash.clear();
  for (const k of apiKeys.keys()) apiKeyByHash.set(sessionTokens.keyHash(k), k);
  _hashIndexBuiltAt = Date.now();
  return apiKeyByHash.size;
}
// Resolve a hash, self-healing. The index is rebuilt on load and on
// /v2/reload-users, which is where the table normally changes, but keys are
// also created at run time (/v2/admin/keys, team keys, the claim flow) without
// going through either. So a miss rebuilds and asks again, and a hit is checked
// against apiKeys, which means a stale entry can never resolve to a key that is
// gone. The rebuild is bounded: it runs when the table changed size, and
// otherwise at most once a second, so a flood of invented hashes cannot turn a
// lookup into a full scan per request.
function apiKeyFromHash(hash) {
  const hit = apiKeyByHash.get(hash);
  if (hit && apiKeys.has(hit)) return hit;
  if (apiKeyByHash.size !== apiKeys.size || Date.now() - _hashIndexBuiltAt > 1000) {
    rebuildApiKeyHashIndex();
    const again = apiKeyByHash.get(hash);
    if (again && apiKeys.has(again)) return again;
  }
  return null;
}
// Resolve a key to its account_id. For every loaded key account_id is preset
// (stap 1); for a legacy 1:1 key account_id === apiKey, so device/pubkey/webhook
// keys built from acctOf(apiKey) are byte-identical to the old apiKey-scoped
// ones — behaviour-neutral now, account-shared once a second key is added.
function acctOf(apiKey) { const v = apiKeys.get(apiKey); return (v && v.account_id) || apiKey; }
// How an account is named to somebody it sent a signing request to. The address
// on the account, because that is exactly what the invitation mail already put
// in front of this reader: admin/server.js sends signingInviteEmail with
// senderLabel = the sender's session address. Showing the same string back on
// the worklist tells the recipient nothing new and lets them match the row to
// the mail. Precedence is the one _indexAccountExpiry() uses: a member key's
// address first, the account summary second.
//
// Returns '' when the account cannot be named. The caller then says so rather
// than dropping a document somebody is waiting on: an unnamed sender is a worse
// row, an invisible request is a worse product.
function senderLabelOf(accountId) {
  if (!accountId) return '';
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  for (const m of members) { const mv = apiKeys.get(m); if (mv && mv.email) return mv.email; }
  return (accounts.get(accountId) || {}).email || '';
}
// Resolve the record an ENTITLEMENT decision must read. The accounts map is a
// summary ({account_id, plan, email, primary_api_key, label}) and never carries
// the per-product plans: setProductPlan writes plan_parasign/plan_parasend onto
// the apiKeys records (and users.json), not here. A gate that reads accounts
// alone therefore misses a paid upgrade entirely and falls back to legacy
// `plan` -> free. That is exactly what the ParaSign web sign gate did: a paying
// Pro account kept hitting the 2-signature free wall. Merge both, taking the
// HIGHEST per-product tier any key of the account carries so a stale free key
// can never hold a paid account down.
function entitlementRecordOf(accountId) {
  if (!accountId) return null;
  const acct = accounts.get(accountId);
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  return entitlements.mergeAccountRecord(acct, [...members].map(m => apiKeys.get(m)));
}

// EVERY ParaSend ceiling a request is held to, off the product axis and nowhere
// else. Reading `keyData.plan` for a limit is the fault this function exists to
// end: the Mollie webhook upgrades an account through setProductPlan ->
// entitlements.applyProductTier, which writes plan_parasend and deliberately
// never touches the unified `plan`. A gate reading `plan` therefore cannot see
// a paid ParaSend upgrade at all, so a Pro buyer would keep the community hour,
// the single read and the 5-device cap while /pricing sells him 24 hours, 10
// reads and 50 devices. Only the manual admin route sets `plan` as well, which
// is why nothing was visible before self-serve billing.
//
// A record with no tier on file resolves to community, the strictest ParaSend
// tier. A missing plan is not evidence of a paid one; the previous `|| 'pro'`
// defaults on the device cap and the pubkey TTL were the mirror image of that
// rule and handed an unplanned key the Pro ceiling.
function parasendLimitsOf(rec) {
  return entitlements.getEntitlements(rec || null).parasend;
}

// An entitlement number as the admin views report it. The entitlement layer
// says Infinity for an uncapped structural limit; the admin JSON has always
// said -1 (tiers.UNLIMITED), and JSON.stringify turns Infinity into null, which
// an operator reads as "no data" rather than "no cap".
function _reportLimit(v) {
  return v === Infinity ? tiers.UNLIMITED : v;
}

// The file ceiling an upload is really held to, in MB.
//
// This used to return min(MAX_BLOB, file_mb) because the gate compared a single
// blob against file_mb, which meant every tier was really held to one 5 MB
// block. It no longer does: a file is carried as many blobs and the ceiling is
// enforced by counting them (FILE_MAX_BLOCKS below), so the number an operator
// sees here is the tier's own, and MAX_BLOB does not enter into it.
function _effectiveFileMb(ent) {
  // Through _reportLimit, so an uncapped row reports -1 and not null.
  //
  // This used to be Math.min(MAX_BLOB / 1048576, file_mb), which happened to
  // launder Infinity into a finite 5 on the way out. Removing the min removed
  // that accident too: the enterprise row is Infinity, JSON.stringify turns
  // Infinity into null, and an operator reads null as "no data" rather than
  // "no cap". The whole point of _reportLimit is that -1 is how this API says
  // uncapped.
  return _reportLimit(ent.parasend.limits.file_mb);
}

// How many padded blocks a file of `fileMb` may occupy.
//
// The relay cannot see a file. It sees blobs, and it learns which blobs belong
// together from the `meta.file_id` the sender already sends for quota dedup. So
// the file ceiling is enforced as a block count, and the conversion needs the
// plaintext each block actually carries.
//
// CLIENT_CHUNK_PLAIN is the chunk size the web app uses (parashare.page.js
// CHUNK_PLAIN). It is deliberately under MAX_BLOB so the wire prelude, the AEAD
// tag and the per-chunk metadata header fit in the same block. A client that
// chunks smaller than this simply gets fewer bytes through before it hits the
// ceiling; that is its own problem and not a security boundary. The security
// boundaries are MAX_BLOB, the relay's memory budget and the monthly quota, and
// all three sit underneath this. Hence the slack: this number is a product
// limit, and it should err towards letting an honest 500 MB file finish.
const CLIENT_CHUNK_PLAIN = 4.5 * 1024 * 1024;
const FILE_BLOCK_SLACK   = 4;
function fileMaxBlocks(fileMb) {
  if (!Number.isFinite(fileMb) || fileMb < 0) return Infinity;
  return Math.ceil((fileMb * 1048576) / CLIENT_CHUNK_PLAIN) + FILE_BLOCK_SLACK;
}

// Blocks seen per file, so a file ceiling can be enforced across the uploads
// that make up one file. Keyed by the sender's file_id, scoped to the account so
// two accounts cannot collide or interfere. Entries are short-lived: a transfer
// is minutes, and the sweep below drops anything idle for an hour.
const fileBlocks = new Map(); // `${account}:${file_id}` → { blocks, ts }
const FILE_BLOCKS_TTL_MS = 3600_000;
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of fileBlocks.entries()) {
    if (now - v.ts > FILE_BLOCKS_TTL_MS) fileBlocks.delete(k);
  }
}, 300_000).unref?.();

// Blobs currently held per account, for the concurrent_blobs ceiling. Kept as a
// counter rather than scanned out of blobStore: this is read on every upload.
const accountBlobs = new Map(); // account_id → count
function accountBlobsAdd(acct, n) {
  if (!acct) return;
  const next = (accountBlobs.get(acct) || 0) + n;
  if (next <= 0) accountBlobs.delete(acct); else accountBlobs.set(acct, next);
}
const blobStore  = new Map();  // hash → {blob, ts, ttl, size, sig?}

// Every write to blobStore goes through these two, so blobBytesHeld cannot drift
// away from what is really held. It is the number the capacity guard decides on,
// and a guard reading a stale total is worse than no guard: it refuses uploads
// the relay could take, or accepts ones it cannot.
function blobPut(hash, entry) {
  const prev = blobStore.get(hash);
  if (prev) { blobBytesHeld -= (prev.size || 0); accountBlobsAdd(prev.account_id, -1); }
  blobBytesHeld += (entry.size || 0);
  accountBlobsAdd(entry.account_id, 1);
  blobStore.set(hash, entry);
}
// Drops the entry and wipes the bytes. zeroBuffer is what makes "destroyed"
// true rather than "dereferenced", so it belongs here and not at each call site
// where it can be forgotten.
// wipe=false is for the one case where the bytes are still needed: a burn-on-read
// drops the entry BEFORE the response is written, so that a second reader cannot
// find it, but the buffer itself is what is being sent. Those callers wipe on
// 'finish' instead. Everywhere else the default is right.
function blobDrop(hash, wipe = true) {
  const e = blobStore.get(hash);
  if (!e) return false;
  blobBytesHeld -= (e.size || 0);
  if (blobBytesHeld < 0) blobBytesHeld = 0;
  accountBlobsAdd(e.account_id, -1);
  blobStore.delete(hash);
  if (wipe) zeroBuffer(e.blob);
  return true;
}

const anonInboundIpRequests = new Map(); // ip → [timestamps] for /v2/anon-inbound rate limit
const invDidIpRequests = new Map(); // ip → [timestamps] for keyless inv_ DID registration
const sthIngestIpRequests = new Map(); // ip → [timestamps] for /v2/sth/ingest (unauthenticated)
// Same window, same reason, for POST /v2/relays/register. The STH ingest route
// got one because it is "unauthenticated (ownership-signature only), so a flood
// of attacker-minted relay keypairs is otherwise unbounded". Its neighbour
// registers those very keypairs and had nothing: every registration appends to
// the CT log (on disk since the persistence fix) and every append gossips a
// fresh head to every peer in the registry, so one unauthenticated POST bought
// an amplified fan-out and unbounded disk. The 2026-09-05 review, finding 21.
const relayRegisterIpRequests = new Map(); // ip → [timestamps] for /v2/relays/register (unauthenticated)
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
  for (const [k, times] of relayRegisterIpRequests) { const kept = times.filter(t => now - t < HOUR); if (kept.length) relayRegisterIpRequests.set(k, kept); else relayRegisterIpRequests.delete(k); }
  for (const [k, b]     of teamRateLimits)       { if (b && now > b.resetAt) teamRateLimits.delete(k); }
}, 3_600_000);

function checkTeamRateLimit(teamId, limit) {
  if (!teamId) return true;
  return rateLimit.fixedWindowAllow(teamRateLimits, teamId, limit, 60000);
}

// M2: Per-IP rate limit for /v2/admin/verify-mfa (max 5 attempts per minute)
const mfaRateLimits = new Map(); // ip → { count, resetAt }
function checkMfaRateLimit(ip) {
  return rateLimit.fixedWindowAllow(mfaRateLimits, ip, 5, 60000);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of mfaRateLimits) if (now > v.resetAt + 60000) mfaRateLimits.delete(k); }, 120_000);

// Per-USER throttle for /v2/user/{verify-totp,consume-backup}. The internal-auth
// guard proves the caller (admin proxy), not that the end user isn't brute-forcing
// their own 6-digit TOTP (10^6 space). Cap attempts per user in a sliding window;
// reset on success so legit retries never lock out. In-memory, mirrors
// checkMfaRateLimit; fails open on nothing (pure counter).
const USER_MFA_MAX = 10;            // failures before the delay starts, not a cap
const USER_MFA_WINDOW_MS = 300_000; // 5 min
const userMfaAttempts = new Map(); // user_id → { count, resetAt } (failures)
// Counts FAILURES, not attempts, and answers with a delay rather than a refusal.
// Was: an increment on the way IN plus a 429 at USER_MFA_MAX, which meant ten
// posts naming somebody else's user_id locked that account out of verify-totp
// and consume-backup for the whole window. The user_id is request input, so a
// refusal keyed on it is a weapon aimed at the account, not at the guesser.
// lib/auth-throttle.js holds the (unit-tested) decision; the Map and its sweep
// stay here, as with the other limiters.
function userMfaDelayMs(user_id) {
  return authThrottle.throttleDelayMs(
    authThrottle.failureCount(userMfaAttempts, user_id),
    { threshold: USER_MFA_MAX });
}
function userMfaNoteFailure(user_id) { authThrottle.noteFailure(userMfaAttempts, user_id, USER_MFA_WINDOW_MS); }
function userMfaAttemptReset(user_id) { authThrottle.clearFailures(userMfaAttempts, user_id); }
setInterval(() => { const now = Date.now(); for (const [k, v] of userMfaAttempts) if (now > v.resetAt + USER_MFA_WINDOW_MS) userMfaAttempts.delete(k); }, 300_000);

// Per-IP rate limit for the public /v2/claim/reveal (max 20/min) — a claim token
// is a 256-bit random hex, so this just caps abusive polling, not real guessing.
const claimRateLimits = new Map();
function claimRateOk(ip) {
  return rateLimit.fixedWindowAllow(claimRateLimits, ip, 20, 60000);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of claimRateLimits) if (now > v.resetAt + 60000) claimRateLimits.delete(k); }, 120_000);

// Per-IP rate limit for /v2/check-key (max 30/min) — prevents API key brute-force
const checkKeyRateLimits = new Map();
function checkKeyRateOk(ip) {
  return rateLimit.fixedWindowAllow(checkKeyRateLimits, ip, 30, 60000);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of checkKeyRateLimits) if (now > v.resetAt + 60000) checkKeyRateLimits.delete(k); }, 120_000);

// Per-IP rate limit for /v2/lookup-signer/:pk_hash (max 30/min) — prevents
// enumeration of (pubkey → email) bindings even though only exact hash matches.
const lookupSignerRateLimits = new Map();
function lookupSignerRateOk(ip) {
  return rateLimit.fixedWindowAllow(lookupSignerRateLimits, ip, 30, 60000);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of lookupSignerRateLimits) if (now > v.resetAt + 60000) lookupSignerRateLimits.delete(k); }, 120_000);

// ── Guessing budget for POST /v2/session/join ────────────────────────────────
// The route takes a pre-shared secret and answers whether it was right. It has
// no API key on purpose (the PSS is the authentication), and until the
// 2026-09-05 review, finding 6, it had nothing else either: a wrong secret got a
// 403 and left the session sitting there, so whoever had the session id could
// try passphrases at wire speed. A PSS is a human-chosen phrase -- the docs
// spell one out as an example -- so minutes of that is enough.
//
// Two budgets, because they stop different attackers. The per-IP window is the
// same shape as every other limiter here and stops one host hammering. The
// per-session budget is the one that matters: it survives a rotating source
// address, and it is bounded by the thing being attacked rather than by who is
// attacking it. Five wrong answers destroys the session, which is the correct
// end state anyway -- a session whose secret has been guessed at five times is
// not a session anyone should still be able to join.
const sessionJoinLimits = new Map();      // ip -> { count, resetAt }
const SESSION_JOIN_MAX_ATTEMPTS = 5;
function sessionJoinRateOk(ip) {
  return rateLimit.fixedWindowAllow(sessionJoinLimits, ip, 10, 60_000);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of sessionJoinLimits) if (now > v.resetAt + 60_000) sessionJoinLimits.delete(k); }, 120_000);

// Per-IP rate limits for /v2/envelopes/* (Model 2 multi-party signing).
// Create is throttled per API key to prevent quota abuse; view/sign are
// per-IP to blunt enumeration of unguessable but still finite env-ids.
const envCreateLimits = new Map();        // apiKey  -> { count, resetAt }
const envViewLimits   = new Map();        // ip      -> { count, resetAt }
const envSignLimits   = new Map();        // ip      -> { count, resetAt }
function envCreateRateOk(apiKey) {
  return rateLimit.fixedWindowAllow(envCreateLimits, apiKey, 50, 3600_000);
}
function envViewRateOk(ip) {
  return rateLimit.fixedWindowAllow(envViewLimits, ip, 30, 60_000);
}
function envSignRateOk(ip) {
  return rateLimit.fixedWindowAllow(envSignLimits, ip, 10, 60_000);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of envCreateLimits) if (now > v.resetAt + 60_000) envCreateLimits.delete(k);
  for (const [k, v] of envViewLimits)   if (now > v.resetAt + 60_000) envViewLimits.delete(k);
  for (const [k, v] of envSignLimits)   if (now > v.resetAt + 60_000) envSignLimits.delete(k);
}, 120_000);

// Fleet-wide envelope-create rate limit. The per-process envCreateLimits above
// only bound ONE relay instance; behind the multi-instance deployment a client
// got N times the intended 50/hour. This shares the counter in redis: INCR a
// per-key hourly bucket, EXPIRE it on first hit. Fails OPEN to the per-process
// limiter when redis is down, so an outage never hard-blocks paying integrators
// (they still get the local 50/hour cap). The bucket rolls hourly by wall clock.
const ENV_CREATE_LIMIT = 50;
async function envCreateRateOkShared(apiKey) {
  if (!redisClient || !redisClient.isReady) return envCreateRateOk(apiKey);
  try {
    const bucket = Math.floor(Date.now() / 3600_000);
    const rk = `paramant:rl:envcreate:${bucket}:${apiKey}`;
    const n = await redisCounter.incrInWindow(redisClient, rk, 3600);
    return n <= ENV_CREATE_LIMIT;
  } catch (e) {
    log('warn', 'env_create_rl_redis_fail', { err: e.message });
    return envCreateRateOk(apiKey);
  }
}

// ── ParaSign /v1 durable side-store (documents + webhook meta) ────────────────
// Encrypted-at-rest in redis (AES-256-GCM), in-memory fallback without a key.
// A SINGLE instance is shared by the /v1 router and the /v2 sign path (the
// completion-webhook emit reads the same webhook meta). Key: PARASIGN_STORE_KEY,
// else the already-required TOTP master key.
function _parasignStoreKey() {
  return process.env.PARASIGN_STORE_KEY || process.env.PARAMANT_TOTP_MASTER_KEY || null;
}
function _parasignStore() {
  if (!_parasignStore._inst) {
    _parasignStore._inst = parasignStoreMod.createParaSignStore({
      redis: redisClient, encKey: _parasignStoreKey(), log,
    });
    log('info', 'parasign_store_backend', { backend: _parasignStore._inst.backend });
  }
  return _parasignStore._inst;
}

// Per-IP rate limit for /v2/status/:hash.
//
// Raised from 60/min. A streaming send asks this once per block to see whether
// the receiver has taken the one it is waiting on, and a 500 MB file is 112
// blocks: at 60/min a fast upload tripped its own back-pressure check and fell
// back to sending blind, which is the behaviour the window exists to prevent.
//
// The old comment called this an anti-enumeration limit. It is not really doing
// that work: the argument is a 64-hex hash, so guessing one is not something a
// rate limit is holding back. What it bounds is cost, and 240/min is still a
// small number of map lookups.
const statusRateLimits = new Map();
function statusRateOk(ip) {
  return rateLimit.fixedWindowAllow(statusRateLimits, ip, 240, 60000);
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

// ── Client IP: X-Real-IP, but only from a peer we put there ourselves ───────
// Every per-IP limit in this file keys on this. It used to read the header
// unconditionally, on the stated assumption that nginx sets it authoritatively.
// nginx does that on the apex and on relay.paramant.app; it did not on the four
// sector hostnames or in the /rp/<sector>/ blocks, and nginx forwards unknown
// client headers by default. So on those hosts a caller chose their own address
// and rotated past every limiter. See lib/client-ip.js for the whole story and
// for why the trusted set has to include the docker bridge and not just
// loopback. The edge configs now set the header everywhere, and
// test/trusted-edge-gate.test.js keeps them that way; this is the lock on the
// other side of that door, so a single missed nginx block is no longer a bypass.
const getClientIp = clientIpLib.makeClientIp({ trusted: process.env.TRUSTED_PROXY_CIDRS });

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

// ── Reusable Resend mailer ────────────────────────────────────────────────────
// Fire-and-forget. Returns false (no-op) when RESEND_API_KEY is unset or there is
// no recipient, so a caller never blocks on mail and mail stays optional. Used by
// the ParaSend Pro transfer notifications (upload/download) and by the invoice
// mail, which is the one caller that passes an attachment; the DPA and
// inbound-claim flows keep their own richly-templated inline sends.
function sendResendEmail({ to, subject, text, html, from, cc, attachments } = {}) {
  const RESEND_KEY = process.env.RESEND_API_KEY || '';
  if (!RESEND_KEY || !to) return false;
  const payload = {
    from: from || 'PARAMANT <privacy@paramant.app>',
    to: Array.isArray(to) ? to : [to],
    subject: subject || '',
  };
  if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];
  if (html) payload.html = html;
  if (text) payload.text = text;
  // Resend takes attachments as { filename, content } with content base64.
  // Used by the invoice mail; every other caller leaves it undefined and the
  // request body is byte for byte what it was.
  if (Array.isArray(attachments) && attachments.length) payload.attachments = attachments;
  const body = JSON.stringify(payload);
  try {
    const req2 = https.request({ hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, r => { let data = ''; r.on('data', c => data += c); r.on('end', () => { try { const p = JSON.parse(data); log('info', 'resend_email_sent', { id: p.id, subject }); } catch (e) {} }); });
    req2.on('error', e => log('warn', 'resend_email_failed', { err: e.message }));
    req2.write(body); req2.end();
    return true;
  } catch (e) { log('warn', 'resend_email_failed', { err: e.message }); return false; }
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
// The ceiling per tier lives in lib/tiers.js (outbound_per_hour) with every
// other per-tier number. It used to be a local three-key table keyed on the raw
// plan string, { free, pro, enterprise }, with a `?? free` fallback: 'community'
// and 'business' were not in it, so a Business account, which pays for the
// highest volume of all, was rate limited at the free 50 per hour. tiers.js
// normalises the plan name (free/dev -> community, licensed -> enterprise), so
// every plan the pricing page sells now resolves to its own ceiling. It takes
// the KEY RECORD, not a plan string: outbound_per_hour is a ParaSend ceiling
// and resolves on the product axis with the other five, so a webhook upgrade
// (plan_parasend only) raises it.
const OUTBOUND_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour sliding window
const outboundRateMap = new Map(); // apiKey → { count, resetAt }
function outboundRateOk(apiKey, rec) {
  const max = parasendLimitsOf(rec).limits.outbound_per_hour;
  if (max === Infinity) return true;
  const now = Date.now();
  let c = outboundRateMap.get(apiKey);
  if (!c || now > c.resetAt) { c = { count: 0, resetAt: now + OUTBOUND_RATE_WINDOW_MS }; }
  if (c.count >= max) return false;
  c.count++; outboundRateMap.set(apiKey, c);
  return true;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of outboundRateMap) if (now > v.resetAt) outboundRateMap.delete(k); }, 3_600_000);

// ── Delivery receipt store (PR #341, finding 2) ─────────────────────────
// The signed delivery receipt used to ride out on the download itself, in the
// X-Paramant-Receipt response header. It carries a full ML-DSA-65 signature and
// an inclusion proof, so that header measured 18551 bytes and the response
// header block 19560. Node's own default maxHeaderSize is 16384, so a client
// using fetch() or a default http.request could not download a blob at all
// (UND_ERR_HEADERS_OVERFLOW), and nginx's default proxy_buffer_size of 4k/8k
// answers 502 on an upstream header block that size.
//
// So the receipt is handed over by REFERENCE instead: the download carries a
// receipt id and the hash of the receipt bytes, and the bytes themselves are
// fetched from GET /v2/transfers/:receipt_id/receipt. Same receipt, same
// signature, same verification through POST /v2/verify-receipt.
//
// Kept in RAM like everything else on this relay, and deliberately short-lived:
// a client fetches its receipt in the same breath as the download.
//
// The budget is PER ACCOUNT, not one shared queue. A single global LRU is a
// cross-tenant eviction channel: one account doing enough downloads pushes
// another account's receipt out inside its own 15 minute window, and before
// this route the receipt was guaranteed to be on the response itself. So an
// account can only ever evict its OWN oldest receipt, and the global ceiling is
// a backstop that takes from the LARGEST holder, which can never be the small
// tenant it would be protecting.
//
// Where it lives. REDIS when the relay has one, which is what the envelope
// store already runs on, and the in-process Map only as the fallback for a
// relay without redis. A Map alone means every restart 404s every outstanding
// receipt: a deploy in the middle of somebody's download window silently costs
// them their proof of delivery, and a restart is a thing operators do on
// purpose. With redis the receipt survives the process that issued it.
//
// Memory. The stored form is the receipt JSON, not its base64url wrapper: the
// wrapper is 4/3 the size and re-encoding it on the way out is deterministic,
// so the hash stays stable and about 4.6 KB per receipt is not held. That puts
// a receipt at roughly 14 KB.
//
// The per-account cap is DERIVED from the tier's own outbound ceiling: two
// hours of downloading at the rate that tier pays for. A flat 200 was wrong for
// exactly the tier that pays most, business at 2000 downloads an hour would
// lose its oldest receipts after six minutes of steady use, inside the 15
// minute window it was promised. Enterprise has no outbound ceiling to double,
// so it takes an explicit one.
//
//   community  50/h  ->   100      pro   500/h  ->  1000
//   business 2000/h  ->  4000      enterprise   -> RECEIPT_UNCAPPED_TIER_MAX
//
// The global backstop applies to the Map path only, where the memory is this
// process's. With redis the bound is the TTL, the per-account cap, and redis'
// own maxmemory policy.
const RECEIPT_TTL_MS = 15 * 60 * 1000;
const RECEIPT_TTL_S = Math.round(RECEIPT_TTL_MS / 1000);
const RECEIPT_UNCAPPED_TIER_MAX = Math.max(1, parseInt(process.env.PARAMANT_RECEIPT_UNCAPPED_MAX || '10000', 10) || 10000);
// A fixed override, for tests that need to drive the eviction rule without
// making thousands of downloads. Unset in production, where the tier decides.
const RECEIPT_PER_ACCOUNT_OVERRIDE = parseInt(process.env.PARAMANT_RECEIPT_PER_ACCOUNT_MAX || '0', 10) || 0;
// The retention cap rides on outbound_per_hour, so it is a ParaSend ceiling too
// and takes the key record rather than a plan string.
function receiptCapFor(rec) {
  if (RECEIPT_PER_ACCOUNT_OVERRIDE > 0) return RECEIPT_PER_ACCOUNT_OVERRIDE;
  const rate = parasendLimitsOf(rec).limits.outbound_per_hour;
  const cap = Number.isFinite(rate) ? rate * 2 : RECEIPT_UNCAPPED_TIER_MAX;
  return Math.max(1, Math.min(cap, RECEIPT_UNCAPPED_TIER_MAX));
}
const RECEIPT_TOTAL_MAX = Math.max(1, parseInt(process.env.PARAMANT_RECEIPT_TOTAL_MAX || '4000', 10) || 4000);
const RECEIPT_RK = (id) => `paramant:receipt:${id}`;
const RECEIPT_AK = (owner) => `paramant:receipts:acct:${owner}`;
const deliveryReceipts = new Map(); // receipt_id -> { json, hash, apiKey, owner, expiresAt }
const receiptsByOwner = new Map();  // owner (account_id) -> Set<receipt_id>, insertion ordered
function _dropReceipt(id) {
  const rec = deliveryReceipts.get(id);
  if (!rec) return;
  deliveryReceipts.delete(id);
  const own = receiptsByOwner.get(rec.owner);
  if (own) { own.delete(id); if (own.size === 0) receiptsByOwner.delete(rec.owner); }
}
function _dropOldestOf(owner) {
  const own = receiptsByOwner.get(owner);
  if (!own) return false;
  const oldest = own.values().next();
  if (oldest.done) return false;
  _dropReceipt(oldest.value);
  return true;
}
async function storeDeliveryReceipt(json, hash, apiKey, owner, rec) {
  const id = crypto.randomBytes(16).toString('hex');
  const bucket = owner || apiKey || '_anonymous';
  const cap = receiptCapFor(rec);
  if (redisClient && redisClient.isReady) {
    try {
      const ak = RECEIPT_AK(bucket);
      await redisClient.set(RECEIPT_RK(id), JSON.stringify({ json, hash, apiKey: apiKey || null }), { EX: RECEIPT_TTL_S });
      await redisClient.zAdd(ak, { score: Date.now(), value: id });
      await redisClient.expire(ak, RECEIPT_TTL_S);
      // The cap is per account and enforced against that account's own index,
      // so a busy tenant can only ever drop its own oldest.
      const over = (await redisClient.zCard(ak)) - cap;
      if (over > 0) {
        const stale = await redisClient.zRange(ak, 0, over - 1);
        if (stale.length) {
          await redisClient.del(stale.map(RECEIPT_RK));
          await redisClient.zRemRangeByRank(ak, 0, over - 1);
        }
      }
      return id;
    } catch (e) {
      // Never fail a download over its receipt: fall through to the Map.
      log('warn', 'receipt_store_redis_failed', { err: e.message });
    }
  }
  // Sets preserve insertion order and every entry has the same TTL, so the head
  // of a bucket is always that owner's entry closest to expiring.
  while ((receiptsByOwner.get(bucket)?.size || 0) >= cap) {
    if (!_dropOldestOf(bucket)) break;
  }
  // Global backstop. Take from whoever holds the most, never from whoever
  // happens to be oldest, so a burst cannot evict a quiet tenant.
  while (deliveryReceipts.size >= RECEIPT_TOTAL_MAX) {
    let biggest = null; let most = 0;
    for (const [o, set] of receiptsByOwner) if (set.size > most) { most = set.size; biggest = o; }
    if (biggest === null || !_dropOldestOf(biggest)) break;
  }
  deliveryReceipts.set(id, { json, hash, apiKey: apiKey || null, owner: bucket, expiresAt: Date.now() + RECEIPT_TTL_MS });
  if (!receiptsByOwner.has(bucket)) receiptsByOwner.set(bucket, new Set());
  receiptsByOwner.get(bucket).add(id);
  return id;
}
setInterval(() => { const now = Date.now(); for (const [id, r] of deliveryReceipts) if (now > r.expiresAt) _dropReceipt(id); }, 60_000).unref?.();

// Read one back. Redis first, so a receipt issued by a process that has since
// been restarted is still there; the Map is the fallback for a relay with no
// redis. Returns { json, hash, apiKey } or null.
async function fetchDeliveryReceipt(id) {
  if (redisClient && redisClient.isReady) {
    try {
      const raw = await redisClient.get(RECEIPT_RK(id));
      if (raw) return JSON.parse(raw);
    } catch (e) {
      log('warn', 'receipt_fetch_redis_failed', { err: e.message });
    }
  }
  const rec = deliveryReceipts.get(id);
  if (!rec) return null;
  if (Date.now() > rec.expiresAt) { _dropReceipt(id); return null; }
  return rec;
}

// Deprecation window for the fat header. Nothing in this repo reads it outside
// its own tests, but an out-of-tree client might, so an operator can put it back
// for one release with PARAMANT_INLINE_RECEIPT_HEADER=1. It is off by default
// because on a default nginx the fat header is a 502, not a feature. To be
// removed after 2026-12-01; see docs/api.md.
const INLINE_RECEIPT_HEADER = process.env.PARAMANT_INLINE_RECEIPT_HEADER === '1';

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

// ── Per-product entitlement setter (billing) ──────────────────────────────
// Set ONE product's plan (plan_parasign OR plan_parasend) for an account,
// independently of the other product, then persist. This is what the Mollie
// webhook calls on a paid payment. Models grantParasignOnPaidPlan's account
// fan-out + users.json persistence. Idempotent (a repeat call with the same tier
// changes nothing -> changed:0). For parasign it also flips the `parasign` access
// flag on when the tier is paid (non-free). NEVER touches the other product.
// paidUntil travels with the tier: a Date (or ISO string) sets the period this
// grant is paid for, null clears it, and undefined leaves whatever is on record
// alone. That last case keeps every admin grant behaving exactly as before.
function setProductPlan(accountId, product, tier, paidUntil, bundle) {
  if (!accountId || (product !== 'parasend' && product !== 'parasign')) return { ok: false, reason: 'bad_args' };
  const norm = product === 'parasign'
    ? entitlements.normaliseParasignTier(tier)
    : entitlements.normaliseParasendTier(tier);
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  if (members.size === 0) return { ok: false, reason: 'no_keys' };
  let changed = 0;
  for (const m of members) {
    const mv = apiKeys.get(m);
    if (!mv) continue;
    // Single field-level rule (writes only this product's field + the parasign
    // access flag; never the other product or the unified `plan`).
    if (entitlements.applyProductTier(mv, product, norm, paidUntil, bundle).changed) changed++;
  }
  // Mirror onto the accounts summary too. Readers that only hold an account_id
  // (the ParaSign web sign gate among them) resolve through entitlementRecordOf,
  // but keeping the summary in step means a stale accounts record can never
  // outvote a paid grant on any future read path either.
  const _acct = accounts.get(accountId);
  if (_acct) {
    entitlements.applyProductTier(_acct, product, norm, paidUntil, bundle);
    _acct.plan_updated = new Date().toISOString();
  }
  // paidUntil is passed on to the DISK write as well. Without it the period
  // lived only in memory: applyProductTier leaves the field alone when it is
  // undefined, so users.json kept a bare tier and a relay restart handed every
  // paying account an unbounded grant again. That is the bug this branch is
  // for, surviving the very restart it was supposed to end.
  _mutateUsersJson(ud => {
    for (const entry of ud.api_keys) {
      if ((entry.account_id || entry.key) === accountId) {
        entitlements.applyProductTier(entry, product, norm, paidUntil, bundle);
        entry.plan_updated = new Date().toISOString();
      }
    }
    ud.updated = new Date().toISOString();
  }).then(() => log('info', 'billing_entitlement_set', { account: String(accountId).slice(0, 12), product, tier: norm, keys: members.size, changed, persisted: true }))
    .catch(we => log('warn', 'billing_entitlement_persist_failed', { err: we.message }));
  // Keep the shared expiry index in step with the period that was just written.
  // This is the ONLY thing that lets a container which has never seen this
  // account mail its owner: users.json is per container, redis is not.
  _indexAccountExpiry(accountId, product);
  // And into the ONE store all five relay containers share. Everything above
  // this line is local: the api-key records are in this process, users.json is
  // on this container's own volume (docker-compose.yml gives every relay a
  // volume of its own), so without this the term is true on exactly the relay
  // that happened to serve the request. nginx sends public /v2/ to relay-main,
  // which is where both customer grant paths land -- the Mollie webhook and
  // POST /v2/billing/redeem -- while every screen and the ParaSign signature
  // gate are served off relay-health by the admin plane. See lib/shared-grants.
  _publishSharedGrant(accountId);
  return { ok: true, product, tier: norm, keys: members.size, changed };
}

// ── The shared half of a grant (lib/shared-grants) ───────────────────────────
// Publish what this container now holds for the account, so the other four can
// hydrate it. Reads the record back rather than trusting the arguments, exactly
// as _indexAccountExpiry does, so a grant that left one product alone publishes
// what is really on file for both. Fire-and-forget: a redis outage may delay the
// other containers, never the grant itself.
function _publishSharedGrant(accountId) {
  if (!redisClient || !redisClient.isReady || !accountId) return;
  const rec = entitlementRecordOf(accountId);
  if (!rec) return;
  Promise.resolve(sharedGrants.publish(redisClient, accountId, rec))
    .then((r) => {
      if (!r || r.ok) return;
      log('warn', 'shared_grant_publish_failed', { account: String(accountId).slice(0, 12), err: r.error });
    })
    .catch(e => log('warn', 'shared_grant_publish_failed', { account: String(accountId).slice(0, 12), err: e.message }));
}

// Apply a shared grant to THIS container's own records: every member key, the
// accounts summary, and users.json. After this the local table is the one that
// answers /v2/admin/keys, /v2/admin/entitlements and the signs_month gate, so
// nothing downstream needs to know that the term was granted elsewhere.
//
// Never publishes. This is the read side of the same row, and a hydration that
// published would have five containers writing each other's messages forever.
//
// Never downgrades either: sharedGrants.applyTo is entitlements
// .mergeProductGrantInto, which copies a grant only when it beats the one on
// file. An account this container has no key for is skipped; it will be picked
// up by the reseed once the admin key fan-out has reached this sector.
// `revoked` says the shared row carries revoked_at: the fleet's record is that
// this account has no paid term at all. That is the ONE downgrade this path
// applies, and it exists because the container that took the money back is not
// the container the customer's screens are served from.
function _hydrateSharedGrant(accountId, grant, revoked) {
  if (!accountId || (!grant && !revoked)) return [];
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  if (members.size === 0) return [];
  // Decide once, against the account's best current grant, so five member keys
  // do not each answer the question differently.
  const merged = { ...(entitlementRecordOf(accountId) || {}) };
  const moved = grant ? sharedGrants.applyTo(merged, grant) : sharedGrants.applyRevocation(merged);
  if (moved.length === 0) return [];
  for (const product of moved) {
    const tier = merged[entitlements.PRODUCT_PLAN_FIELD[product]];
    const paidUntil = merged[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]] || null;
    const bundle = merged[entitlements.PRODUCT_BUNDLE_FIELD[product]] || null;
    for (const m of members) {
      const mv = apiKeys.get(m);
      if (mv) entitlements.applyProductTier(mv, product, tier, paidUntil, bundle);
    }
    const acct = accounts.get(accountId);
    if (acct) {
      entitlements.applyProductTier(acct, product, tier, paidUntil, bundle);
      acct.plan_updated = new Date().toISOString();
    }
    _mutateUsersJson(ud => {
      for (const entry of ud.api_keys) {
        if ((entry.account_id || entry.key) === accountId) {
          entitlements.applyProductTier(entry, product, tier, paidUntil, bundle);
          entry.plan_updated = new Date().toISOString();
        }
      }
      ud.updated = new Date().toISOString();
    }).catch(we => log('warn', 'shared_grant_persist_failed', { err: we.message }));
  }
  log(revoked && !grant ? 'warn' : 'info', revoked && !grant ? 'shared_grant_revoked' : 'shared_grant_hydrated', {
    account: String(accountId).slice(0, 12), products: moved.join(','), keys: members.size });
  return moved;
}

// Pull one account's shared grant and apply it. Used by the subscriber.
async function _pullSharedGrant(accountId) {
  if (!redisClient || !redisClient.isReady || !accountId) return [];
  const row = await sharedGrants.readRow(redisClient, accountId);
  if (!row) return [];
  return _hydrateSharedGrant(accountId, row.grant, !!row.revokedAt);
}

// One reconciliation pass, both directions, over the accounts that have a term.
// Runs shortly after boot and then on a slow timer. This is the net under the
// channel, and it is what makes the mechanism safe rather than clever: a
// container that was down for the deploy, a subscriber that lost its socket, a
// message published while this process was still loading users.json -- all of
// them heal here, without anybody noticing and without a customer having to
// redeem twice.
//
// THE OUTBOUND HALF IS NOT OPTIONAL, and it is the half that matters on the day
// this ships. Every term granted BEFORE this existed lives only on the container
// that granted it and has no shared row at all, so a pass that only pulled would
// leave exactly the customers this change is for -- the ones already holding a
// term nobody else can see -- untouched until they bought a second one.
//
// It fills in accounts redis has NO row for, and nothing else. That restriction
// is the whole safety of the downgrade half: a container holding a record that
// is a minute out of date must never be able to write it over a fresher fact,
// and a revoked account keeps its row precisely so this pass leaves it alone.
// Before the restriction, relay-health reseeding its own still-paid record put a
// charged-back customer straight back on Pro, one second after relay-main had
// taken it away.
async function _reseedSharedGrants() {
  if (!redisClient || !redisClient.isReady) return 0;
  let rows = [];
  try { rows = await sharedGrants.readAll(redisClient); }
  catch (e) { log('warn', 'shared_grant_reseed_failed', { err: e.message }); return 0; }
  const shared = new Map(rows.map((r) => [r.accountId, r]));

  // Outbound: terms this container holds that redis has never heard of.
  for (const { accountId, record } of accountsWithTerms()) {
    if (shared.has(accountId)) continue;
    const local = sharedGrants.grantOf(record);
    if (!local) continue;
    const out = await sharedGrants.publish(redisClient, accountId, local);
    if (!out.ok) { log('warn', 'shared_grant_publish_failed', { account: String(accountId).slice(0, 12), err: out.error }); continue; }
    shared.set(accountId, { grant: local, revokedAt: null });
    log('info', 'shared_grant_seeded', { account: String(accountId).slice(0, 12) });
  }

  // Inbound: what the shared row holds that this container does not, in both
  // directions -- a term it has not been told about, and a term it should no
  // longer be handing out.
  let hydrated = 0;
  for (const [accountId, row] of shared) {
    if (_hydrateSharedGrant(accountId, row.grant, !!row.revokedAt).length) hydrated++;
  }
  return hydrated;
}

// Mirror one product's paid period into the redis expiry index (lib/plan-expiry).
// Reads back the record it just wrote rather than trusting the argument, so an
// admin grant that passed paidUntil undefined (leave whatever is on file) is
// indexed with what is actually on file. Fire-and-forget: a redis outage may
// delay a reminder, never a grant.
function _indexAccountExpiry(accountId, product) {
  if (!redisClient || !redisClient.isReady) return;
  const rec = entitlementRecordOf(accountId);
  if (!rec) return;
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  let email = (accounts.get(accountId) || {}).email || '';
  for (const m of members) { const mv = apiKeys.get(m); if (mv && mv.email) { email = mv.email; break; } }
  const products = product ? [product] : entitlements.PRODUCTS;
  for (const prod of products) {
    planExpiry.upsertExpiry(redisClient, {
      accountId,
      product: prod,
      tier: rec[entitlements.PRODUCT_PLAN_FIELD[prod]],
      paidUntil: rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[prod]] || null,
      bundle: rec[entitlements.PRODUCT_BUNDLE_FIELD[prod]] || null,
      email,
    }).catch(e => log('warn', 'plan_expiry_index_failed', { product: prod, err: e.message }));
  }
}

// ── Mollie pointers (customer + per-product subscription) ────────────────────
// Where the recurring layer keeps its two ids. They live on the same records as
// the entitlement fields, and on the same serialized users.json queue, so a
// restart does not lose the link between an account and what it is subscribed
// to. Written per ACCOUNT (every member key gets the same pointer), because a
// customer belongs to the buyer, not to one of his keys.
function _setMolliePointer(accountId, field, value) {
  if (!accountId || !field) return { ok: false, reason: 'bad_args' };
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  for (const m of members) {
    const mv = apiKeys.get(m);
    if (!mv) continue;
    if (value === null || value === undefined) delete mv[field];
    else mv[field] = value;
  }
  const acct = accounts.get(accountId);
  if (acct) { if (value === null || value === undefined) delete acct[field]; else acct[field] = value; }
  _mutateUsersJson(ud => {
    for (const entry of (ud.api_keys || [])) {
      if ((entry.account_id || entry.key) === accountId) {
        if (value === null || value === undefined) delete entry[field];
        else entry[field] = value;
      }
    }
    ud.updated = new Date().toISOString();
  }).catch(we => log('warn', 'billing_pointer_persist_failed', { field, err: we.message }));
  return { ok: true };
}

// The record the recurring layer reads its pointers from. Same resolution as
// the entitlement path: the per-key record carries the fields, the accounts
// summary is only a mirror.
function _billingRecordOf(accountId) {
  const members = accountKeys.get(accountId) || (apiKeys.has(accountId) ? new Set([accountId]) : new Set());
  for (const m of members) { const mv = apiKeys.get(m); if (mv) return mv; }
  return accounts.get(accountId) || null;
}

// ── Billing profile: the customer half of an invoice ─────────────────────────
// Three optional fields the account owner fills in himself (company name,
// address, VAT id).
//
// IN REDIS, NOT IN users.json. Every relay container has its own /data volume
// (docker-compose.yml: relay-main-data, relay-health-data, ...), so a profile
// saved through the container the account page happens to talk to would be
// invisible to the container nginx routes the Mollie webhook to, and the
// invoice would go out without the company details the customer had just
// entered. Redis is the one store all five relays share.
const BILLING_PROFILE_KEY = (accountId) => `paramant:billing:profile:${accountId}`;

async function _setBillingProfile(accountId, profile) {
  if (!accountId || !profile) return { ok: false, reason: 'bad_args' };
  if (!redisClient || !redisClient.isReady) return { ok: false, reason: 'no_redis' };
  const clean = {
    company: profile.company || '',
    address: profile.address || '',
    vat: profile.vat || '',
    updated_at: new Date().toISOString(),
  };
  // No TTL. These details are part of documents that must be kept.
  try { await redisClient.set(BILLING_PROFILE_KEY(accountId), JSON.stringify(clean)); }
  catch (e) { return { ok: false, reason: e.message }; }
  return { ok: true };
}

// What goes in the "Billed to" block. The email address always: it is the only
// customer detail an account is guaranteed to have, and it comes off the
// account record rather than out of redis, so a document is still addressed to
// someone even when the profile store is empty or unreachable.
async function _billingBuyerOf(accountId) {
  const rec = _billingRecordOf(accountId) || {};
  const buyer = { email: rec.email || '', company: '', address: '', vat: '' };
  if (!redisClient || !redisClient.isReady) return buyer;
  try {
    const raw = await redisClient.get(BILLING_PROFILE_KEY(accountId));
    if (raw) {
      const p = JSON.parse(raw);
      buyer.company = p.company || '';
      buyer.address = p.address || '';
      buyer.vat = p.vat || '';
    }
  } catch { /* an unreadable profile must not cost the customer his document */ }
  return buyer;
}

// One warning per process, not one per payment: a missing BILLING_SELLER_VAT is
// a configuration fact, and repeating it on every sale would bury the log line
// that means something.
let _sellerVatWarned = false;

// Issue the document for a payment that is settled and matched. Deliberately
// runs for a REPEAT webhook too (an 'already_processed' outcome on a paid
// payment): issueDocument is idempotent per payment id, so a retry cannot
// produce a second invoice, and a first attempt that lost redis gets a second
// chance instead of leaving the customer with nothing. Never throws: an
// entitlement that was granted must not be undone by paperwork.
async function _issueInvoiceForPayment(payment, outcome) {
  try {
    const md = (payment && payment.metadata) || {};
    const order = billingCatalog.resolveOrder({ product: md.product, plan: md.plan, interval: md.interval });
    if (order.error) return;
    const seller = invoiceMod.sellerFromEnv(process.env);
    if (!seller.vat && !_sellerVatWarned) {
      _sellerVatWarned = true;
      log('warn', 'billing_invoice_no_vat_number', {
        reason: 'BILLING_SELLER_VAT is not set',
        effect: 'documents go out as a payment receipt, not a VAT invoice',
      });
    }
    const redis = (redisClient && redisClient.isReady) ? redisClient : null;
    const out = await invoiceMod.issueDocument({
      payment,
      order: Object.assign({ accountId: md.accountId }, order),
      seller,
      buyer: await _billingBuyerOf(md.accountId),
      periodEnd: outcome && outcome.paidUntil,
    }, redis);

    if (out.result !== 'issued') {
      log(out.result === 'existing' ? 'info' : 'warn', 'billing_invoice', {
        payment_id: payment.id, result: out.result, reason: out.reason, number: out.number,
      });
      return;
    }
    log('info', 'billing_invoice', {
      payment_id: payment.id, result: 'issued', number: out.number, kind: out.record.kind,
      account: String(md.accountId).slice(0, 12), total: out.record.amount_gross,
    });
    _mailInvoice(out.record);
    _moneybirdPush(out.record);
  } catch (e) {
    log('error', 'billing_invoice_failed', { payment_id: payment && payment.id, err: e.message });
  }
}

// The document into Mick's bookkeeping, if and only if a Moneybird token and an
// administration id are configured. AFTERCARE: fired and not awaited, so a slow
// or unreachable Moneybird cannot hold up a webhook, and pushDocument itself
// never throws. A failure queues the document for the six-hour sweep started at
// the bottom of this file; see lib/moneybird.js.
function _moneybirdPush(record) {
  if (!record) return;
  if (!moneybird.configured(moneybird.configFromEnv(process.env))) return;
  Promise.resolve()
    .then(() => moneybird.pushDocument({
      record,
      redis: (redisClient && redisClient.isReady) ? redisClient : null,
      env: process.env,
      renderPdf: (r) => invoicePdf.render(r, { buyerHint: invoiceMod.BUYER_HINT }),
      log,
    }))
    .catch((e) => log('warn', 'moneybird_push_failed', { number: record.number, err: e.message }));
}

// The document as mail, with the PDF attached. No mail path configured means no
// mail and no error: the record exists and /v2/billing/invoices still serves it,
// which is the half that has to work.
function _mailInvoice(record) {
  if (!record || !record.buyer || !record.buyer.email) return false;
  let pdf;
  try { pdf = invoicePdf.render(record, { buyerHint: invoiceMod.BUYER_HINT }); }
  catch (e) { log('warn', 'billing_invoice_pdf_failed', { number: record.number, err: e.message }); return false; }
  const isInvoice = record.kind === 'invoice';
  const subject = `${isInvoice ? 'Invoice' : 'Payment receipt'} ${record.number} - ${record.seller.name}`;
  const lines = [
    `Thank you for your payment.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${record.invoice_date}`,
    `${record.description}`,
    `Total: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% VAT, ${record.currency} ${record.amount_vat})`,
    ``,
    isInvoice ? '' : `${invoiceMod.RECEIPT_NOTE}`,
    invoiceMod.buyerIsComplete(record.buyer) ? '' : `${invoiceMod.BUYER_HINT}.`,
    ``,
    `The document is attached, and every document stays available on your account page.`,
    ``,
    record.seller.name,
  ].filter((l, i, a) => !(l === '' && a[i - 1] === ''));
  return sendResendEmail({
    to: record.buyer.email,
    from: 'PARAMANT <billing@paramant.app>',
    subject,
    text: lines.join('\n'),
    attachments: [{ filename: `${record.number}.pdf`, content: pdf.toString('base64') }],
  });
}

// The document for money that goes back. A chargeback or a refund reaches us on
// the SAME tr_ id as the payment, so the invoice it reverses is found from that
// id alone; the credit note gets its own number in its own series and refers to
// the invoice by number and date, because an issued invoice may not be
// withdrawn (see lib/credit-note.js).
//
// Runs for a repeat webhook too, and for a partial refund, on the same
// reasoning as _issueInvoiceForPayment: issueCreditNote is idempotent per
// reversal, so a retry can only ever repair. Never throws: paperwork must not
// be able to fail a webhook.
async function _creditNoteForPayment(payment) {
  try {
    const redis = (redisClient && redisClient.isReady) ? redisClient : null;
    if (!redis) return;
    const out = await creditNote.issueCreditNote({ payment }, redis);
    if (out.result !== 'issued') {
      // 'none' is the ordinary answer for a payment that has no invoice (money
      // taken before the invoice module existed) and for a repeat of a reversal
      // already credited in full. Neither is a fault, and neither is silent.
      log(out.result === 'existing' || out.result === 'none' ? 'info' : 'warn', 'billing_credit_note', {
        payment_id: payment.id, result: out.result, reason: out.reason, number: out.number,
      });
      return out;
    }
    log('warn', 'billing_credit_note', {
      payment_id: payment.id, result: 'issued', number: out.number, credits: out.credited,
      account: String(out.record.account_id || '').slice(0, 12),
      total: out.record.amount_gross, reason: out.record.reason, partial: out.record.partial,
    });
    _mailCreditNote(out.record);
    _moneybirdPush(out.record);
    return out;
  } catch (e) {
    log('error', 'billing_credit_note_failed', { payment_id: payment && payment.id, err: e.message });
    return { result: 'unavailable', reason: e.message };
  }
}

// The credit note as mail, with the PDF attached. Same shape and same
// no-mail-path-is-not-an-error rule as _mailInvoice: the record exists and
// /v2/billing/invoices serves it either way.
function _mailCreditNote(record) {
  if (!record || !record.buyer || !record.buyer.email) return false;
  let pdf;
  try { pdf = invoicePdf.render(record, { buyerHint: invoiceMod.BUYER_HINT }); }
  catch (e) { log('warn', 'billing_credit_pdf_failed', { number: record.number, err: e.message }); return false; }
  const chargedBack = record.reason === 'chargeback';
  const subject = `${record.title} ${record.number} - ${record.seller.name}`;
  const lines = [
    chargedBack
      ? `Your payment was charged back, so the invoice below has been credited.`
      : `Your payment has been refunded, so the invoice below has been credited.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${record.invoice_date}`,
    `Credit for invoice ${record.credit_for} of ${record.credit_for_date}`,
    `${record.description}`,
    `Total credited: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% VAT, ${record.currency} ${record.amount_vat})`,
    ``,
    record.partial ? 'This is a partial credit. The remainder of that invoice still stands.' : '',
    record.note || '',
    ``,
    `The document is attached, and every document stays available on your account page.`,
    ``,
    record.seller.name,
  ].filter((l, i, a) => !(l === '' && a[i - 1] === ''));
  return sendResendEmail({
    to: record.buyer.email,
    from: 'PARAMANT <billing@paramant.app>',
    subject,
    text: lines.join('\n'),
    attachments: [{ filename: `${record.number}.pdf`, content: pdf.toString('base64') }],
  });
}

// Per-key persistence for the ParaSign entitlement toggle. Injected into
// lib/parasign-open-api.js so its grantParaSignScope/setParaSignEnabled are no
// longer in-memory-only stubs: the flip on the live apiKeys record is mirrored
// to users.json (so it survives a restart) and an audit entry records it. Write
// runs on the serialized users-queue; returns immediately. Scoped to ONE key,
// unlike grantParasignOnPaidPlan which fans out over a whole account.
function _persistParaSignScope(key, { parasign, plan } = {}) {
  if (!key) return { ok: false, reason: 'no_key' };
  const rec = apiKeys.get(key);
  const acct = (rec && rec.account_id) || key;
  _mutateUsersJson(ud => {
    for (const entry of (ud.api_keys || [])) {
      if (entry.key === key) {
        if (parasign !== undefined) entry.parasign = !!parasign;
        if (plan) entry.plan = plan;
      }
    }
    ud.updated = new Date().toISOString();
  }).then(() => log('info', 'parasign_scope_persisted', { account: String(acct).slice(0, 12), parasign: !!parasign, plan: plan || null }))
    .catch(we => log('warn', 'parasign_persist_failed', { err: we.message }));
  try { auditAppend(key, 'parasign_scope_change', { parasign: !!parasign, plan: plan || null }); } catch {}
  return { ok: true };
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
  // The new key inherits the account's EFFECTIVE per-product tiers, resolved
  // over every key the account holds. Minting used to pass the legacy `plan`
  // only, which silently issued a free-tier ParaSign key to a paying account.
  // EFFECTIVE, not the tier on file: the new key record carries no paid_until,
  // so re-issuing a lapsed tier here would turn an expired subscription into a
  // permanent one. A record with no per-product tier at all is left undefined,
  // so buildParasignKeyRecord still derives from the legacy plan as before.
  const eff = entitlementRecordOf(accountId) || {};
  // Tier AND period, together, or the new key is an unbounded copy of a bounded
  // grant. An ALREADY expired grant is minted as the floor tier with no period
  // at all (effectiveProductTier reports it as expired), so a lapsed account
  // does not get a stale date on a fresh key either.
  const _effGrant = (product) => {
    if (eff[entitlements.PRODUCT_PLAN_FIELD[product]] == null) return {};
    const g = entitlements.effectiveProductTier(eff, product);
    return { tier: g.tier, paidUntil: g.expired ? null : eff[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]] };
  };
  const _pg = _effGrant('parasign');
  const _ps = _effGrant('parasend');
  const built = keysTable.buildParasignKeyRecord({
    accountId, plan, email, label: opts.label, test: !!opts.test,
    planParasign: opts.planParasign || _pg.tier,
    planParasend: opts.planParasend || _ps.tier,
    paidUntilParasign: _pg.paidUntil,
    paidUntilParasend: _ps.paidUntil,
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
    try { const d = JSON.parse(process.env.USERS_JSON); (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||"",email:k.email||"",active:true,created:k.created||null,...keysTable.parseAccountFields(k)}); }); keysTable.rebuildKeyIndexes(apiKeys,accounts,accountKeys,kidIndex,log); rebuildApiKeyHashIndex(); log("info","users_loaded",{count:apiKeys.size,source:"env"}); return; } catch(e) { log("error","users_json_parse",{err:e.message}); }
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
    rebuildApiKeyHashIndex();
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
    if (loaded > 0) { keysTable.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log); rebuildApiKeyHashIndex(); log('info', 'trial_keys_loaded', { count: loaded }); }
  } catch(e) { /* file may not exist yet */ }
}

// Pubkey plan limits and TTL.
// _pubkeyTtl stays local: it tracks how long a *registered device pubkey*
// is retained, which is not in TIER_LIMITS' scope yet (the brief only maps
// devices count + view TTL + max views + monthly quotas + file size).
// _pubkeyMax now reads device caps from TIER_LIMITS via tiers.tierLimitNum so
// there is one source of truth for the per-tier device count.
// Keyed on the ParaSend tier the callers resolve, plus `free`, which is what an
// anonymous keyless DID registration passes. It used to hold three rows and a
// `?? free` fallback, so `community` and `business` were not in it and reached
// the free row by accident, the same kind of hole tiers.js closed for the other
// dimensions. Every name a caller can produce now has its own row, so a value
// is never the result of a miss.
const _pubkeyTtl = {
  free:        7 * 86_400_000,
  community:   7 * 86_400_000,
  pro:        30 * 86_400_000,
  business:   30 * 86_400_000, // legacy plan name; never below pro
  enterprise: 365 * 86_400_000,
};
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
      blobDrop(h);
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
function safeEqual(a, b) { return authGate.safeEqual(a, b); }

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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Dsa-Signature, X-Capsule-Sha256, Authorization, X-DID, X-DID-Signature, X-DID-TS, X-DID-Nonce');
  res.setHeader('Cache-Control',                'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options',       'nosniff');
  res.setHeader('Content-Security-Policy',      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
  res.setHeader('Strict-Transport-Security',    'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy',              'no-referrer');
  // A relay answers json to script, never inside a frame. frame-ancestors in
  // the CSP above already says so to a current browser; this is the same
  // sentence for the ones that only read the older header. Measured on
  // 2026-09-03: all five sector relays sent no X-Frame-Options at all, while
  // paramant.app itself did.
  res.setHeader('X-Frame-Options',              'DENY');
  // interest-cohort was never a registered Permissions-Policy feature. FLoC was
  // withdrawn in 2022 and the name was never added to the feature registry, so
  // a policy consisting only of it parses to an empty policy: the header is
  // present, looks like hardening in a scan that only checks presence, and
  // governs nothing. These are registered features, and denying them costs a
  // json api nothing.
  res.setHeader('Permissions-Policy',           'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
  // X-Paramant-Version intentionally omitted — version disclosure via response header removed (security hardening v2.3.3)
  res.setHeader('X-Paramant-Sector',            SECTOR);
  res.setHeader('X-Crypto-Version',             'ML-KEM-768+AES-256-GCM');
  res.setHeader('X-Hybrid-Mode',                'available');
}


// ── Code-transparency manifest: in-memory + /data, CT-verankerd bij publish ──
const CODE_MANIFEST_FILE = process.env.CODE_MANIFEST_FILE || '/data/code-manifest.json';
let codeManifest = null;
try { codeManifest = JSON.parse(require('fs').readFileSync(CODE_MANIFEST_FILE, 'utf8')); }
catch (e) { if (e.code !== 'ENOENT') log('warn', 'code_manifest_load_error', { err: e.message }); }

// Append one event to the CT log and produce a fresh STH. Named for ParaID
// when it was written, but the code-transparency manifest anchors through
// this same function, so it outlives the product it was named after. `did`
// is any opaque subject identifier, not necessarily a DID.
function ctAppendEvent(eventType, did, payload) {
  ctRequireEventType('did_event', eventType);
  // Gated before it is hashed, as in ctAppendEnvelope: the leaf commits to this
  // object, so the entry must store the same one.
  const gatedPayload = ctGatePayload(eventType, payload);
  const ts = new Date().toISOString();
  const valueHash = crypto.createHash('sha3-256')
    .update(eventType).update('|').update(did).update('|')
    .update(JSON.stringify(gatedPayload)).digest('hex');
  const leaf_hash = ctLeafHash(did, valueHash, ts);
  const index = ctWindow.nextIndex();
  const allEntries = [...ctWindow.entries, { leaf_hash }];
  const tree_hash = ctTreeHash(allEntries);
  const proof = ctInclusionProof(allEntries, allEntries.length - 1);
  const entry = ctGateEntry('did_event', { index, type: eventType, leaf_hash, tree_hash, did, payload: gatedPayload, ts, proof });
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

// Every request, with one catch around the lot.
//
// The handler below is 4000 lines of `await`, and until now it was passed
// straight to createServer as an async callback with nothing behind it. An
// async callback that throws produces an unhandled rejection: the client gets
// no answer at all, and on Node 22 the process exits. That was survivable only
// because almost nothing in here could reject -- a redis call against a dead
// server hung instead. Now that every redis call fails inside a bound, the
// throw is the normal outage path, so it needs an answer and not a crash.
//
// Redis unreachable is 503 (the service could not answer, the caller did
// nothing wrong); anything else is 500.
const server = http.createServer((req, res) => {
  handleRelayRequest(req, res).catch((err) => relayRequestFailed(req, res, err));
});

// A route-level catch that is about to answer 4xx or 5xx for what is really the
// store being unreachable. One line at the top of each such catch turns that
// into the honest answer instead.
//
// WHY IT IS NEEDED AT ALL. Every redis command is bounded now, so an outage
// arrives as a rejection rather than as a hang -- but this file catches its own
// errors on 31 routes and answers 400 "bad_request" or 500 "internal" for them.
// A caller reading either of those has no way to tell "you sent nonsense" or
// "we have a bug" from "come back in ten seconds", and a monitor watching for
// 5xx sees a bug where there is an outage. Whoever adds the 32nd route is
// covered by the top-level catch in relayRequestFailed, which answers the same
// way; this is for the routes that already swallow.
function redisOutage503(err, res) {
  if (!redisDeadlines.isRedisOutage(err)) return false;
  log('error', 'redis_unavailable', { err: (err && err.message) || String(err) });
  if (res.headersSent || res.writableEnded) return true;
  res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '5' });
  res.end(J({ error: 'redis_unavailable', hint: 'the relay store did not answer inside its deadline' }));
  return true;
}

function relayRequestFailed(req, res, err) {
  const outage = redisDeadlines.isRedisOutage(err);
  log('error', outage ? 'redis_unavailable' : 'request_failed', {
    method: req.method, url: String(req.url || '').split('?')[0],
    err: (err && err.message) || String(err),
  });
  // A handler that already started writing cannot be given a status any more.
  if (res.headersSent || res.writableEnded) { try { res.end(); } catch (_) { /* gone */ } return; }
  const headers = { 'Content-Type': 'application/json' };
  if (outage) headers['Retry-After'] = '5';
  res.writeHead(outage ? 503 : 500, headers);
  res.end(J(outage
    ? { error: 'redis_unavailable', hint: 'the relay store did not answer inside its deadline' }
    : { error: 'internal_error' }));
}

async function handleRelayRequest(req, res) {
  setHeaders(res, req);
  const parsed  = url_.parse(req.url, true);
  const path    = parsed.pathname;
  const query   = parsed.query;
  // `let`, not `const`: a ParaSend session token (pst_) resolves BELOW into the
  // api-key it was minted for, and everything downstream -- acctOf, the audit
  // chain, the device queues, the quota gates -- then behaves exactly as it
  // would for a request that carried that key itself. That identity is the
  // point: a token is a narrower way to present the same account, never a
  // second account with a history of its own.
  let apiKey = (req.headers['x-api-key'] || '').trim();
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
  // ── ParaSend session token (Authorization: Bearer pst_...) ─────────────────
  // Only when no X-Api-Key was sent: a request that carries a real key is that
  // key's request, and a token may never widen or narrow it. The token resolves
  // to the api-key it was minted for; from here on the request IS that key's,
  // with one difference, enforced a few lines down: the scope allowlist.
  //
  // The refusals are all silent by design. A bad token yields no principal and
  // the ordinary 401 gate answers it, the same 401 an unknown api-key gets, so
  // nothing here separates "no such token" from "expired" from "revoked".
  //
  // Redis down is NOT a refusal. Without a store no token can be checked, and
  // answering 401 would tell a legitimate holder their credential is bad. It is
  // a 503, so the browser retries instead of throwing the sender back to login.
  const _bearer = sessionTokens.bearerToken(req.headers['authorization'] || '');
  let viaSessionToken = false;
  // Which allowlist this token is judged against, set from the record the token
  // resolves to and never from anything the caller sent. A browser picks a
  // purpose when it MINTS (through the admin plane, on a signed-in session);
  // once minted, the purpose is a property of the credential.
  let sessionTokenPurpose = null;
  if (!apiKey && sessionTokens.isSessionToken(_bearer)) {
    if (!redisClient) {
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '5' });
      return res.end(J({ error: 'redis_unavailable', hint: 'session tokens need the relay store' }));
    }
    try {
      const _pst = await sessionTokens.resolve(redisClient, _bearer, apiKeyFromHash);
      if (_pst) { apiKey = _pst.key; viaSessionToken = true; sessionTokenPurpose = _pst.purpose; }
    } catch (err) {
      if (redisOutage503(err, res)) return;
      throw err;
    }
  }
  const dsaSig  = req.headers['x-dsa-signature'] || '';
  // DID-auth NEVER mints its own principal. A DID only authenticates as the API
  // key it was REGISTERED under: inherit that key's real plan/active. Keyless DIDs
  // (e.g. 'inv_' receiver-session DIDs, registered without an API key) therefore
  // grant NO authenticated principal here — they keep working only through the
  // per-endpoint INVITE_RE pubkey-exchange bypass, never as a general auth subject.
  // (Previously any valid DID-auth forged {plan:'pro',active:true}, which let an
  // anonymous attacker self-register an inv_ DID and ride it into a pro session.)
  // The decision itself lives in lib/auth-gate didPrincipal (pure, unit-tested):
  // it also refuses a revoked enrollment (revoked/revoked_at on the registry
  // entry) and guarantees account_id = owner key, so getEntitlements and the
  // transfers_month/signs_month gates below run against the owner's REAL plan,
  // identical to a request carrying the owner's X-Api-Key.
  const keyData = apiKeys.get(apiKey)
    || authGate.didPrincipal(didAuthEntry, (k) => apiKeys.get(k));
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

  // ── The scope of a ParaSend session token ──────────────────────────────────
  // Here, and not inside the five routes it opens. A gate that each route had
  // to remember to call is a gate that the sixty-ninth route forgets, and the
  // whole value of this credential is that it is provably narrower than an
  // api-key. So it sits above every route comparison in this function: an
  // allowlist, checked once, with no way past it.
  //
  // 403 rather than 401 on purpose. The token is real and the account is real;
  // what is missing is authority for THIS route, and a 401 would send the page
  // off to mint a replacement that would be refused in exactly the same way.
  if (viaSessionToken && !sessionTokens.scopeAllows(req.method, path, sessionTokenPurpose)) {
    log('warn', 'session_token_out_of_scope', { method: req.method, path, purpose: sessionTokenPurpose });
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(J({
      error: 'session_token_out_of_scope',
      hint: 'a pst_ session token opens the short list of routes it was minted for; use an API key for anything else',
    }));
  }

  // -- The scope of a v2 API key ----------------------------------------------
  // Beside the session-token allowlist above, and for the same reason: one
  // choke point above every route comparison, so no route has to remember it.
  //
  // A key is minted read-only / send-only / sign-only, the relay stores that
  // scope and shows it back in the key list and on the dashboard, and until now
  // it enforced none of it. Every key, whatever its label said, could write
  // anywhere on the v2 plane. The route table and the scope matrix both live in
  // lib/keys-table.js (pure, unit-tested); relay.js only asks the question.
  //
  // Only runs when a real key resolved. Keyless and public routes keep keyData
  // null and are untouched, as does the inv_ receiver-session bypass. A legacy
  // key without a scope, and any key minted 'full', is allowed every action by
  // construction, so nothing that works today stops working.
  //
  // 403, not 401: the key is real and active, it just does not carry authority
  // for this route, and a 401 would send the caller off to re-authenticate with
  // the same key and be refused again.
  if (keyData) {
    const _scopeAction = keysTable.scopeActionFor(req.method, path);
    if (!keysTable.requireScope(keyData, _scopeAction)) {
      log('warn', 'insufficient_scope', { method: req.method, path, scope: keyData.scope || 'full', required: _scopeAction });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(J({
        error: 'insufficient_scope',
        required_action: _scopeAction,
        scope: keyData.scope || 'full',
        hint: 'this API key was issued with a narrower scope than this route needs',
      }));
    }
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
      store: _parasignStore(),
      stamp: parasignStamp,
      envCreateRateOk: envCreateRateOkShared,
      persistParaSignScope: _persistParaSignScope,
      safeHttpsRequest,
      canonicalJSON: parasign.canonicalJSON,
      sigEngine: (mlDsa && registry) ? registry.getSig(0x0002) : null,
      relayIdentity,
      // READ-ONLY gate: reject a /v1 create when the account is already over
      // its monthly signs cap, but do NOT increment here. signs_month counts
      // actual SIGNATURES and is incremented per accepted party-signature in the
      // /v2/envelopes/:id/sign path; counting at create too would double-count a
      // /v1 envelope (its signers post back through that same sign path). The
      // LIMIT comes from entitlements (plan_parasign, legacy-plan fallback), the
      // per-product ParaSign tier, never the product-blind tiers.js helpers.
      // Decision is shared with the R018 sign path (quota.signGateDecision):
      // every tier blocks AT its included quota, this one included.
      signQuotaGate: async (accountId, rec) => {
        const ent = entitlements.getEntitlements(rec || {}).parasign;
        if (!accountId || !Number.isFinite(ent.quotas.signs_month)) return { allowed: true, over_limit: false };
        try {
          const u = await quota.readUsage(redisClient, accountId);
          if (!u.available || !Number.isFinite(u.signs_this_month)) return { allowed: true, over_limit: false };
          const dec = quota.signGateDecision(u.signs_this_month, ent);
          return {
            allowed: dec.allowed, over_limit: !dec.allowed,
            reason: dec.reason, plan: ent.tier, limit: dec.limit,
            used: u.signs_this_month,
            reset_date: quota.nextResetDate(),
          };
        } catch { return { allowed: true, over_limit: false }; }
      },
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

  // ── POST /v2/qes/sign, a qualified signature over a hash (flag-gated) ────
  // Off unless PARASIGN_QES_PROVIDER names a provider: without the flag this
  // path does not exist and /sign shows no option for it.
  //
  // The document is prepared here (signature dictionary plus ByteRange), the
  // SHA-256 of the CAdES signed attributes goes to the QTSP, and the signature
  // comes back. Only that digest leaves the relay; the PDF does not.
  //
  // Without a service token and a SAD there is nothing to sign with, so the
  // route answers 409 and hands back the authorisation URL. That is not a
  // shortcut we chose: the Cleverbase Signing API only offers authType
  // "oauth2code", so a natural person has to authorise in the Cleverbase app
  // for every batch of signatures. There is no machine-to-machine route.
  if (path === '/v2/qes/sign' && req.method === 'POST') {
    if (!qes.enabled()) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
    try {
      const d = JSON.parse((await readBody(req, 32 * 1024 * 1024)).toString());
      const pdf = Buffer.from(String(d.document || ''), 'base64');
      if (pdf.subarray(0, 5).toString('latin1') !== '%PDF-') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'document must be a base64 PDF' }));
      }
      const client = qes.clientFor();
      if (!d.service_token || !d.sad || !d.credential_id) {
        let authorizeUrl = null;
        let reason = 'A qualified signature needs the signer to authorise it in the provider app.';
        try {
          authorizeUrl = client.authorizeUrl({ scope: 'service', state: crypto.randomBytes(16).toString('hex') });
        } catch (e) { reason = e.message; }
        res.writeHead(409, { 'Content-Type': 'application/json' });
        return res.end(J({
          error: 'qes_authorisation_required',
          provider: qes.provider(),
          authorize_url: authorizeUrl,
          reason,
        }));
      }
      const out = await qes.signPdf({
        pdf, client,
        credentialID: String(d.credential_id),
        serviceToken: String(d.service_token),
        authorise: () => String(d.sad),
        signerName: d.signer_name ? String(d.signer_name).slice(0, 120) : null,
        reason: d.reason ? String(d.reason).slice(0, 200) : null,
        providerName: qes.provider(),
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({
        document: out.pdf.toString('base64'),
        level: out.level,
        tsa_url: out.tsaUrl,
        qes: out.qes,
      }));
    } catch (e) {
      log('warn', 'qes_sign_failed', { error: e.message });
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
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
      // Qualified electronic signature layer. Empty string means off, which is
      // the default: with no provider configured nothing about signing changes
      // and the /sign page shows no extra option at all.
      parasign_qes: qes.provider(),
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
      const envPath = process.env.SETUP_ENV_FILE || nodePath.join(process.cwd(), '.env');
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
  // In full mode this is a public read (no auth) so the setup wizard and
  // /all-systems-go can show it. In ghost_pipe and iot the same payload is an
  // information leak (version, key count, free disk, cert age), so there it
  // sits behind the X-Internal-Auth header that already gates the user
  // endpoints: monitoring on the host can read it, the open internet cannot.
  // With no INTERNAL_AUTH_TOKEN configured the route stays closed (the gate
  // treats missing config as closed), which is the pre-existing behaviour of
  // every internal endpoint.
  if (req.method === 'GET' && path === '/v2/health/deep') {
    if (RELAY_MODE !== 'full' && !_internalOk()) return _internalReject();
    const checks = [];
    const add = (name, status, detail) => checks.push({ name, status, detail });

    add('relay', 'green', 'relay ' + VERSION + ' (' + SECTOR + ') up');

    const cmode = process.env.CRYPTO_MODE || 'core';
    add('crypto', mlDsa ? 'green' : 'yellow',
      mlDsa ? ('ML-DSA-65 loaded, mode=' + cmode) : ('ML-DSA-65 unavailable (build @paramant/core), mode=' + cmode));

    // The directory the relay really writes to, which in the shipped compose is
    // NOT the working directory. Every relay container runs with
    // read_only: true and WORKDIR /app (docker-compose.yml x-relay-hardening,
    // relay/Dockerfile), so a probe in process.cwd() throws EROFS on a
    // perfectly healthy relay. The state lives on the /data volume named by
    // USERS_FILE and CT_FILE, and that is the only directory whose
    // writability this check has any reason to care about. cwd stays the
    // fallback for a bare-metal install that sets neither.
    const dataDir = process.env.SETUP_ENV_FILE ? nodePath.dirname(process.env.SETUP_ENV_FILE)
      : (process.env.USERS_FILE ? nodePath.dirname(process.env.USERS_FILE) : process.cwd());

    try {
      const probe = nodePath.join(dataDir, '.health-write-' + process.pid);
      fs.writeFileSync(probe, 'ok'); fs.unlinkSync(probe);
      add('storage', 'green', 'data dir writable (' + dataDir + ')');
    } catch (e) { add('storage', 'red', 'not writable (' + dataDir + '): ' + (e.code || e.message)); }

    const rs = ramStatus();
    add('memory', rs.ram_ok ? 'green' : 'yellow', rs.rss_mb + 'MB rss / ' + rs.ram_limit_mb + 'MB limit');

    try {
      if (typeof fs.statfsSync === 'function') {
        // Same directory as the write probe: free space on the /app image
        // layer says nothing about the volume the relay fills.
        const st = fs.statfsSync(dataDir);
        const freeGb = (st.bsize * st.bavail) / 1e9;
        add('disk', freeGb > 1 ? 'green' : 'yellow', freeGb.toFixed(1) + 'GB free on ' + dataDir);
      } else { add('disk', 'yellow', 'statfs unavailable on this Node'); }
    } catch (e) { add('disk', 'yellow', e.code || 'unknown'); }

    let tlsStatus = 'yellow', tlsDetail = 'TLS terminated at the edge (not on this relay)';
    try {
      const certFile = process.env.TLS_CERT_FILE || nodePath.join(process.cwd(), 'deploy/certs/cert.pem');
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

    // The store, said out loud. Until now nothing in either health route
    // mentioned redis, so a relay whose TOTP secrets and replay guard were
    // unreachable reported the same green as a healthy one. The probe is
    // bounded like every other redis call (lib/redis-deadline), so a dead store
    // makes this route slower by at most one deadline and never hangs it.
    if (!redisClient) {
      add('redis', 'yellow', 'not configured (REDIS_URL empty)');
    } else {
      try {
        const pong = await redisClient.ping();
        add('redis', pong === 'PONG' ? 'green' : 'red', pong === 'PONG' ? 'reachable' : 'unexpected ping reply');
      } catch (e) {
        // No detail from the error: it carries the configured deadline in its
        // message, and in full mode this route is public.
        log('warn', 'deep_health_redis_unreachable', { err: (e && e.message) || 'unknown' });
        add('redis', 'red', 'unreachable');
      }
    }

    const rank = { green: 0, yellow: 1, red: 2 };
    const overall = checks.reduce((m, c) => (rank[c.status] > rank[m] ? c.status : m), 'green');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ overall, version: VERSION, sector: SECTOR, checks }));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // User TOTP endpoints (internal — X-Internal-Auth only)
  // ═══════════════════════════════════════════════════════════════════════

  function _internalOk() {
    return authGate.internalAuthOk(process.env.INTERNAL_AUTH_TOKEN, req.headers["x-internal-auth"]);
  }
  function _internalReject() {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(J({ error: "unauthorized" }));
  }

  // ── POST /v2/session-token: mint a ParaSend session token ──────────────────
  // Called by the admin panel on behalf of a logged-in user, never by a
  // browser. Two credentials have to line up:
  //
  //   X-Internal-Auth   the admin plane speaking, same gate as every /v2/user/*
  //                     route. Not configured means closed (auth-gate treats a
  //                     missing token as closed), like every internal endpoint.
  //   X-Api-Key         the account the token will speak for. The admin sends
  //                     the session's own key through proxyApiKey(), so the
  //                     browser never gets to name an account: it can only ever
  //                     be handed a token for the account it is signed in as.
  //
  // A token may not mint another token. It cannot reach here anyway -- the
  // scope allowlist refuses this path far above -- but the check is written out
  // rather than inferred, because "an unreachable path" is a property of code
  // somewhere else and this is the line that must not be wrong.
  if (req.method === 'POST' && path === '/v2/session-token') {
    if (!_internalOk()) return _internalReject();
    if (viaSessionToken) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'session_token_out_of_scope', hint: 'a session token cannot mint another one' }));
    }
    const owner = apiKeys.get(apiKey);
    if (!owner || !owner.active) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
    }
    if (!redisClient) {
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '5' });
      return res.end(J({ error: 'redis_unavailable', hint: 'session tokens need the relay store' }));
    }
    // The purpose picks the allowlist the minted token will be judged against.
    // It is read from the admin plane's body, which is the only caller that can
    // reach this route at all (X-Internal-Auth above), and an unknown word is
    // refused rather than folded onto a default: handing back a token that
    // opens the wrong three routes is worse than handing back nothing. An
    // ABSENT purpose is the ParaSend one, so the admin route that predates
    // purposes keeps working byte for byte.
    let _purpose = sessionTokens.PURPOSE_PARASEND;
    try {
      const b = JSON.parse((await readBody(req, 1024)).toString() || '{}');
      if (b && b.purpose !== undefined && b.purpose !== null) _purpose = String(b.purpose);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'bad_json' }));
    }
    if (!sessionTokens.normalisePurpose(_purpose)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'unknown_purpose', hint: 'purpose must be one of: parasend, app' }));
    }
    try {
      const minted = await sessionTokens.mint(redisClient, apiKey, Date.now(), _purpose);
      // The per-account ceiling. Twenty live tokens is far above any honest
      // use of a page that mints one per load, so this is a signed-in session
      // being used as a credential factory. 429 rather than 403: the account is
      // fine and the answer changes on its own as the tokens expire.
      if (minted.capped) {
        log('warn', 'session_token_capped', {
          account: String(owner.account_id || apiKey).slice(0, 12), live: minted.live, cap: minted.cap,
        });
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        return res.end(J({ error: 'session_token_cap_reached', cap: minted.cap }));
      }
      log('info', 'session_token_minted', {
        account: String(owner.account_id || apiKey).slice(0, 12),
        ttl_s: minted.expires_in_s,
        purpose: minted.purpose,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({
        ok: true,
        token: minted.token,
        expires_ms: minted.expires_ms,
        expires_in_s: minted.expires_in_s,
        purpose: minted.purpose,
      }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
      throw err;
    }
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
      if (redisOutage503(err, res)) return;
      console.error("[user/setup-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/verify-totp
  if (req.method === "POST" && path === "/v2/user/verify-totp") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, totp, throttled_upstream } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !totp) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      // Throttle, never refuse: see userMfaDelayMs.
      //
      // WHY throttled_upstream EXISTS. This sleep is charged to an account, and
      // only a request that names an EXISTING account ever reaches it: the admin
      // returns two steps earlier for an address it cannot find. So the delay is
      // an account-existence oracle at the admin's edge, worth up to two seconds,
      // which is four orders of magnitude louder than the 4 ms difference the
      // fixed floor was built to hide. Measured through the admin at twelve
      // prior failures: 306 ms for an address that exists against 252 ms for one
      // that does not, with no overlap; at the cap, 2006 against 252.
      //
      // The delay has to be applied somewhere that does not know whether the
      // account exists, and that is the admin, which owns a failure counter
      // keyed on the hashed ADDRESS. So a caller may declare that it has already
      // paid, and this route then counts the failure and reports what it would
      // have charged, without charging it twice. The route is X-Internal-Auth
      // only, so the only callers who can set this are callers who could already
      // pass any user_id they like; it moves the delay, it does not remove it.
      // A caller that does not set it pays here exactly as before.
      const ownDelayMs = userMfaDelayMs(user_id);
      if (!throttled_upstream) await authThrottle.sleep(ownDelayMs);
      // Bounded, so an unreachable redis answers 503 here instead of parking the
      // request in front of the single-use guard that is supposed to fail closed.
      let secret;
      try {
        secret = await redisDeadline(userTotp.getUserTotpSecret(redisClient, user_id));
      } catch (e) {
        log("error", "totp_replay_store_unavailable", { account: String(user_id).slice(0, 12), endpoint: "login", stage: "secret_read" });
        res.writeHead(503, { "Content-Type": "application/json" });
        return res.end(J({ error: "replay_store_unavailable" }));
      }
      if (!secret) { res.writeHead(404); return res.end(J({ error: "no_totp_setup" })); }
      const result = await verifyTotpGeneric(totp, secret, {
        window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      // The single-use guard could not reach Redis. Fail closed: this is the
      // endpoint that mints admin-panel sessions, and without the NX key an
      // observed code can be replayed inside its own 30-second slot. 503, not
      // 401, so the caller can tell "service down" from "wrong code", and not a
      // counted failure either.
      if (result && result.error === totpLib.REPLAY_STORE_UNAVAILABLE) {
        log("error", "totp_replay_store_unavailable", { account: String(user_id).slice(0, 12), endpoint: "login" });
        res.writeHead(503, { "Content-Type": "application/json" });
        return res.end(J({ error: "replay_store_unavailable" }));
      }
      if (!result || !result.valid) userMfaNoteFailure(user_id);
      if (result && result.valid) {
        userMfaAttemptReset(user_id);
        // Dual-verify accepted this code. If it validated under SHA-1, record a
        // structured, countable event (never the code or the secret) so SHA-1-app
        // usage is measurable in the logs. This is the login/verify path.
        if (result.algorithm === "sha1") log("info", "totp_sha1_accepted", { account: String(user_id).slice(0, 12), endpoint: "login" });
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      // throttle_ms is what this account owed before the attempt, so an upstream
      // that took the delay on itself can be checked against it.
      return res.end(J({ ...result, throttle_ms: ownDelayMs }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
      console.error("[user/activate-totp]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/consume-backup
  if (req.method === "POST" && path === "/v2/user/consume-backup") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, code, throttled_upstream } = JSON.parse((await readBody(req, 4096)).toString());
      if (!user_id || !code) { res.writeHead(400); return res.end(J({ error: "missing_fields" })); }
      // Same treatment as verify-totp. The delay is what bounds the argon2 work
      // a wrong code triggers now that the refusal is gone; the per-IP caps on
      // the admin side bound it from the other end.
      // Same existence oracle, same opt-out: see /v2/user/verify-totp above.
      if (!throttled_upstream) await authThrottle.sleep(userMfaDelayMs(user_id));
      const result = await userTotp.consumeBackupCode(redisClient, user_id, code);
      if (result && (result.valid || result.success)) userMfaAttemptReset(user_id);
      else userMfaNoteFailure(user_id);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(J(result));
    } catch (err) {
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
      console.error("[user/get-totp-provisional]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/usage-purpose: store the one-time dashboard survey answer
  // ("What do you use Paramant for?") on the account key record. Internal,
  // X-Internal-Auth only: the admin server proxies the authenticated user
  // session through this (same trust model as the TOTP endpoints above).
  // A second call overwrites (last answer wins; see lib/usage-purpose.js).
  if (req.method === "POST" && path === "/v2/user/usage-purpose") {
    if (!_internalOk()) return _internalReject();
    try {
      const { user_id, purpose } = JSON.parse((await readBody(req, 4096)).toString());
      const out = usagePurpose.setUsagePurpose({ apiKeys, mutateUsersJson: _mutateUsersJson }, user_id, purpose);
      if (out.status === 200) {
        const _acct = (apiKeys.get(user_id) || {}).account_id || user_id;
        log('info', 'usage_purpose_set', { account: String(_acct).slice(0, 12), purpose });
      }
      res.writeHead(out.status, { "Content-Type": "application/json" });
      return res.end(J(out.body));
    } catch (err) {
      console.error("[user/usage-purpose]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // POST /v2/user/envelopes: account-scoped signing worklist for the normal
  // dashboard. Internal only. The admin proxy supplies user_id from the
  // authenticated session, never from browser-controlled account input. POST
  // keeps today's key-shaped user_id out of access-log query strings.
  if (req.method === "POST" && path === "/v2/user/envelopes") {
    if (!_internalOk()) return _internalReject();
    try {
      const input = JSON.parse((await readBody(req, 4096)).toString());
      const userId = (input.user_id || "").toString();
      const limit = Math.max(1, Math.min(parseInt(input.limit || "100", 10) || 100, 250));
      if (!userId || userId.length > 200) { res.writeHead(400); return res.end(J({ error: "invalid_user_id" })); }
      const store = _envStore();
      if (!store) { res.writeHead(503); return res.end(J({ error: "envelope_store_unavailable" })); }
      const documents = await store.listAccountEnvelopes(userId, { limit });
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(J({ ok: true, documents, count: documents.length }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
      console.error("[user/envelopes GET]", err.message);
      res.writeHead(500); return res.end(J({ error: "internal" }));
    }
  }

  // ── POST /v2/parasign/inbox/:id/resend: send me that invitation again ──────
  // Internal auth plus an asserted verified email hash, the same pair the
  // recipient-side document and participant-receipt reads take. It is NOT in
  // any session-token scope: it reads the stored per-party invite token back so
  // the admin can put it in a mail, and a route that can produce a capability
  // must never be reachable from a browser.
  //
  // IT MINTS NOTHING. getPartyInvite() returns the token create() wrote. A fresh
  // capability would keep an invite alive past its window and orphan the link
  // already in the party's mailbox; the seven-day window runs from created_at
  // and is untouched, so the resent link dies at the same moment as the first.
  //
  // The relay does not send mail and does not hold addresses, so it answers with
  // the material and the admin does the sending, to the session address whose
  // hash it just asserted. That address is the only one the mail can reach.
  //
  // It sits up here beside the other internal /v2/user routes rather than beside
  // GET /v2/parasign/inbox further down, because the api-key gate stands between
  // the two and this request carries no api-key: the admin authenticates as
  // itself, not as the account.
  const parasignResendMatch = path.match(/^\/v2\/parasign\/inbox\/([A-Za-z0-9_-]{20,64})\/resend$/);
  if (parasignResendMatch && req.method === 'POST') {
    if (!_internalOk()) return _internalReject();
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'envelope_store_unavailable' })); }
    const verifiedEmailHash = (req.headers['x-verified-email-hash'] || '').toString().trim().toLowerCase();
    try {
      const invite = await store.getPartyInvite(parasignResendMatch[1], verifiedEmailHash);
      // One answer for "no such envelope", "not your envelope" and "not waiting
      // on you any more". A caller who is not the party learns nothing, not even
      // that the id exists.
      if (!invite) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store' });
      return res.end(J({
        ok: true,
        party_index: invite.party_index,
        party_label: invite.party_label,
        invite_token: invite.invite_token,
        document: invite.document,
        sender: senderLabelOf(invite.sender_account_id),
        sent_at: invite.sent_at,
        signing_closes_at: invite.signing_closes_at,
      }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
      console.error('[parasign/inbox resend]', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'internal' }));
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
        window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      if (totpResult.error === totpLib.REPLAY_STORE_UNAVAILABLE) {
        log("error", "totp_replay_store_unavailable", { account: String(user_id).slice(0, 12), endpoint: "signing-key" });
        res.writeHead(503, { "Content-Type": "application/json" });
        return res.end(J({ error: "replay_store_unavailable" }));
      }
      if (!totpResult.valid) { res.writeHead(403); return res.end(J({ error: "invalid_totp" })); }
      // Store (server-side pk_hash computation — never trust client)
      let result;
      try {
        result = await userSigning.storeSigningPk(redisClient, user_id, { pk_b64, label });
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(J({ error: e.message }));
      }
      if (totpResult.algorithm === "sha1") log("info", "totp_sha1_accepted", { account: String(user_id).slice(0, 12), endpoint: "sign" });
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
        totp_algorithm: totpResult.algorithm,
      }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
        window: 1,
        replayKey: `paramant:user:replay:${user_id}`,
      });
      if (totpResult.error === totpLib.REPLAY_STORE_UNAVAILABLE) {
        log("error", "totp_replay_store_unavailable", { account: String(user_id).slice(0, 12), endpoint: "signing-key" });
        res.writeHead(503, { "Content-Type": "application/json" });
        return res.end(J({ error: "replay_store_unavailable" }));
      }
      if (!totpResult.valid) { res.writeHead(403); return res.end(J({ error: "invalid_totp" })); }
      if (totpResult.algorithm === "sha1") log("info", "totp_sha1_accepted", { account: String(user_id).slice(0, 12), endpoint: "sign" });
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
      if (redisOutage503(err, res)) return;
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
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_request' })); }
  }

  // ── GET /v2/check-key ───────────────────────────────────────────────────────
  if (path === '/v2/check-key') {
    if (!checkKeyRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' })); }
    const kd = apiKeys.get(apiKey);
    // How long a sealed file waits on the relay, in milliseconds, straight out
    // of tiers.js. The "Send a link" chooser on /parashare has to name those
    // times in its own first sentence, before a file is picked, and a sentence
    // that carries hand-written hours is a sentence that goes stale the first
    // time a tier changes. So the numbers are served, not written.
    //
    // Two fields because the page asks two different questions. `link_ttl_ms`
    // is the ceiling THIS key is really held to, read through the ParaSend
    // entitlement, so a ParaSend Pro buyer whose legacy `plan` still says
    // community is told 24 hours and not 1 hour -- the same source POST
    // /v2/inbound clamps against, so the page cannot promise what the upload
    // will not give. `link_ttl_ms_by_plan` is the plain tiers.js table the
    // chooser needs to say "1 hour on Community, 24 hours on Pro, 7 days on
    // Enterprise" to a reader who is on none of them yet. Business stays in
    // the payload because it is a real server-side ceiling; it is not a
    // ParaSend plan, so the page does not name it.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      valid: !!(kd?.active),
      plan: kd?.plan || null,
      link_ttl_ms: parasendLimitsOf(kd).limits.view_ttl_ms,
      link_ttl_ms_by_plan: {
        community:  tiers.tierLimit('community',  'view_ttl_ms'),
        pro:        tiers.tierLimit('pro',        'view_ttl_ms'),
        business:   tiers.tierLimit('business',   'view_ttl_ms'),
        enterprise: tiers.tierLimit('enterprise', 'view_ttl_ms'),
      },
    }));
  }

  // ── GET /v2/lookup-signer/:pk_hash, reverse-lookup for verifiers ─────────
  // Exact 64-hex-char SHA3-256 match only — no prefix scan, no enumeration.
  // Rate-limited 30/min/IP to blunt scraping.
  //
  // THE EMAIL ADDRESS NEEDS A KEY NOW. The comment here used to defend handing
  // it to anyone, on the grounds that "the caller must already possess the
  // envelope (= the pk) to ask". That stopped being true. GET /v2/envelopes/:id
  // is public, and it used to put signer_pk_hash in its answer, so the pk hash
  // was free: envelope id -> hash -> the real mailbox of everyone who signed,
  // in two unauthenticated GETs. The 2026-09-05 review, finding 4.
  //
  // Both halves are closed. The public envelope projection no longer carries
  // the hash (envelope.js getRedacted), and the address here is now only for a
  // caller that presented a live API key. What stays public is what a verifier
  // checking a .psign file actually needs and already has in the file itself:
  // that this key is enrolled, under what label, since when, and whether it was
  // revoked. Verification does not need to know the person's mailbox.
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
      // The identity half. keyData is resolved once, above the route table, and
      // an inactive or absent key leaves it falsy: no key, no address.
      let email = null;
      if (keyData && keyData.active) {
        try {
          const metaRaw = await redisClient.get(`paramant:user:meta:${found.userId}`);
          if (metaRaw) { const m = JSON.parse(metaRaw); email = m.email || null; }
        } catch {}
      }
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
      if (redisOutage503(err, res)) return;
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
    const ct = ctAppendEvent('code_manifest_published', body.manifest_hash, {
      git_commit: body.git_commit || '', file_count: Object.keys(body.files).length,
    });
    codeManifest = { ...body, published: new Date().toISOString(), ct_index: ct.index };
    try { require('fs').writeFileSync(CODE_MANIFEST_FILE, JSON.stringify(codeManifest)); }
    catch (e) { log('warn', 'code_manifest_write_error', { err: e.message }); }
    log('info', 'code_manifest_published', { hash: body.manifest_hash.slice(0, 16), files: Object.keys(body.files).length });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, manifest_hash: body.manifest_hash, ct_index: ct.index }));
  }

  // ── GET /ct, /ct/ — public CT log web UI (no auth) ─────────────────────────
  if ((path === '/ct' || path === '/ct/') && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(CT_PAGE);
  }

  // ── GET /ct/feed — public JSON feed for CT log UI (no auth, no keys) ─────────
  if (path === '/ct/feed' && req.method === 'GET') {
    // `i` comes from the window position (start_index + i), never from the
    // entry's stored index field. See /v2/ct/log below.
    //
    // `t` is coarsened by ctCoarseTs, exactly like /v2/ct/log and /v2/ct/proof.
    // It used to be the stored full-precision ts, and that turned the hour
    // rounding on the other two routes into decoration. A leaf commits to the
    // millisecond timestamp, so anyone holding a candidate document could take
    // the exact `t` from this feed, join it to the full leaf_hash that
    // /v2/ct/log publishes at the same index, and confirm the document in ONE
    // hash - no search at all - for the fifty most recent entries, which is
    // precisely the traffic worth hiding. Coarsening here does not fix the
    // underlying unsalted leaf (that needs a salted tree), but it puts the
    // free path back behind the same hour of brute force as the rest of the
    // log. Every projection that leaves this process goes through ctCoarseTs;
    // the full ts stays in the stored entry and in the receipt.
    const last50 = ctWindow.recentPage(50);
    const root   = ctWindow.last() ? ctWindow.last().tree_hash : '0'.repeat(64);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(J({
      relay_id: relayIdentity ? relayIdentity.pk_hash : null,
      sector:   SECTOR,
      version:  VERSION,
      tree_size: ctWindow.size,
      root,
      entries: last50.entries.map((e, i) => ({
        i:    last50.start_index + i,
        t:    ctCoarseTs(e.ts),
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
    // The published index is the entry's POSITION in the log (start_index + i),
    // never the index field stored with the entry. Those two agreed until an
    // April rebuild left five entries with a stale field, and the listing then
    // reported indices 4..8 twice while the entries really sat at 42..46. The
    // Merkle tree, /v2/ct/proof and the STH were all correct throughout,
    // because they address the log by position; only this projection lied.
    const pageR = ctWindow.page(from, limit);
    const entries = pageR.entries.map((e, i) => ({ index: pageR.start_index + i, type: e.type, leaf_hash: e.leaf_hash, tree_hash: e.tree_hash, ts: ctCoarseTs(e.ts) }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, size: ctWindow.size, root: ctWindow.last() ? ctWindow.last().tree_hash : '0'.repeat(64), entries }));
  }
  const ctpm0 = path.match(/^\/v2\/ct\/proof\/(\d+)$/);
  const ctpq0 = (!ctpm0 && path === '/v2/ct/proof') ? query.index : null;
  if (ctpm0 || (ctpq0 !== null && ctpq0 !== undefined)) {
    const idx = parseInt(ctpm0 ? ctpm0[1] : ctpq0);
    // Positional by construction: get() resolves idx - base into the window, so
    // this route never consulted the stored index field and was already right
    // while the listing was wrong. The echoed `index` is the requested one.
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
    // `forked` is present only when this relay has refused to sign a head that
    // would contradict one it already signed. It is on the PUBLIC endpoint on
    // purpose: an outside monitor watching heads would otherwise see nothing but
    // a log that stopped advancing, and could not tell that from a quiet week.
    return res.end(J({ ok: true, sth: latest, ...(ctLogForked ? { forked: ctLogForked } : {}) }));
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
    // Before the body read and before the signature verify, exactly as the STH
    // ingest route does it: an ML-DSA-65 verification is not something an
    // unauthenticated caller gets to ask for at will.
    {
      const REGISTER_RPH = parseInt(process.env.RELAY_REGISTER_RATE_PER_HOUR || '10');
      const HOUR_MS = 3_600_000;
      const ip      = getClientIp(req);
      const now     = Date.now();
      const ipTimes = (relayRegisterIpRequests.get(ip) || []).filter(t => now - t < HOUR_MS);
      if (ipTimes.length >= REGISTER_RPH) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' });
        return res.end(J({ error: 'Rate limit: too many relay registrations from this address. Try again later.' }));
      }
      ipTimes.push(now);
      relayRegisterIpRequests.set(ip, ipTimes);
    }
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
    const edition = rEdition || 'community';
    const verified_since = existing?.verified_since || new Date().toISOString();

    // Append to the transparency log only when the registration SAYS something
    // new. A relay that re-registers on its heartbeat used to write a fresh leaf
    // every time, each one carrying an attacker-choosable url and sector, each
    // one producing a signed head that gossips to every peer. The log is on disk
    // now, so "unbounded appends" is unbounded disk. A repeat that changes
    // nothing moves last_seen and stops there.
    const changed = !existing
      || existing.url !== rUrl
      || existing.sector !== rSector
      || existing.version !== rVersion
      || existing.edition !== edition;
    const ctEntry = changed ? ctAppendRelayReg(rUrl, rSector, rVersion, edition, pkHash) : null;
    const nowIso = new Date().toISOString();

    // Evict the LEAST RECENTLY SEEN, not the first inserted. A Map keeps
    // insertion order and `set` on an existing key does not move it, so the old
    // "oldest key wins" rule threw out the relay that had been in the federation
    // longest and was still checking in every hour. Anyone able to register
    // MAX_RELAY_REGISTRY fresh keypairs could push every real relay out of the
    // public list; now the entries that keep proving they are alive are the last
    // to go, and a flood evicts itself.
    if (!existing && relayRegistry.size >= MAX_RELAY_REGISTRY) {
      let stalestKey = null;
      let stalestAt = Infinity;
      for (const [k, v] of relayRegistry) {
        const seen = Date.parse(v.last_seen || v.verified_since || '') || 0;
        if (seen < stalestAt) { stalestAt = seen; stalestKey = k; }
      }
      if (stalestKey) {
        relayRegistry.delete(stalestKey);
        log('warn', 'relay_registry_evict', { evicted: stalestKey.slice(0, 16), last_seen: new Date(stalestAt).toISOString(), size: relayRegistry.size });
      }
    }
    const ctIndex = ctEntry ? ctEntry.index : (existing?.last_ct_index ?? existing?.ct_index ?? null);
    relayRegistry.set(pkHash, {
      url: rUrl, sector: rSector, version: rVersion, edition,
      pk_hash: pkHash, verified_since,
      last_seen: ctEntry ? ctEntry.ts : nowIso,
      ct_index: existing?.ct_index ?? ctIndex,
      last_ct_index: ctIndex
    });
    log('info', 'relay_registered', { url: rUrl, sector: rSector, pk_hash: pkHash.slice(0,16)+'…', ct_index: ctIndex, logged: !!ctEntry });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, pk_hash: pkHash, ct_index: ctIndex, verified_since }));
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
      blobDrop(blobHash);
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
  // Relay verifieert: SHA3-256(pss) == commitment  (relay kan dit NIET vervalsen)
  // Na join: pubkeys gebonden aan sessie, niet overschrijfbaar
  //
  // Guessing is budgeted twice: per source address, and per session. See
  // sessionJoinRateOk above for why both.
  if (path === '/v2/session/join' && req.method === 'POST') {
    if (!sessionJoinRateOk(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(J({ error: 'Too many requests. Retry after 60 seconds.' }));
    }
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

      // Verifieer PSS commitment: SHA3-256(pss) moet overeenkomen.
      // safeEqual and not !==: everything else in this codebase that compares a
      // secret is constant-time (lib/auth-gate.js), and a comparison that leaks
      // how far it got is an offline lever on a weak passphrase.
      const pssHash = crypto.createHash('sha3-256').update(d.pss).digest('hex');
      if (!authGate.safeEqual(pssHash, sess.commitment)) {
        sess.bad_attempts = (sess.bad_attempts || 0) + 1;
        const spent = sess.bad_attempts >= SESSION_JOIN_MAX_ATTEMPTS;
        if (spent) sessions.delete(d.session_id);
        log('warn', 'session_join_bad_pss', { sid: d.session_id.slice(0, 12), attempt: sess.bad_attempts, burned: spent });
        res.writeHead(403);
        return res.end(J({
          error: 'Pre-shared secret does not match commitment',
          attempts_left: Math.max(0, SESSION_JOIN_MAX_ATTEMPTS - sess.bad_attempts),
        }));
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
    rebuildApiKeyHashIndex();

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
        // FIRST REGISTRATION WINS, the same rule the keyed branch below enforces
        // and the same rule the session manifest cites as "a property worth
        // keeping". This branch did not have it: it did an unconditional set, so
        // anyone who saw the ?s= token in the share link (an access log, browser
        // history, an extension, the chat the link travelled through) could
        // overwrite BOTH key slots with their own ECDH and ML-KEM keys after the
        // honest parties had registered. Sender and receiver would then encrypt
        // to the attacker, with only a manual fingerprint comparison in the way.
        // A slot is a one-time capability; once filled it is filled.
        //
        // The one thing that must keep working is a refresh: the receiver stores
        // its keypair in sessionStorage and re-registers the identical keys after
        // a reload. Byte-identical content is therefore a replay and answers 200
        // with the same fingerprint. Anything else is a takeover attempt: 409.
        const heldInvite = pubkeys.get(d.device_id);
        if (heldInvite && (!heldInvite.expires || Date.now() < heldInvite.expires)) {
          const same = safeEqual(heldInvite.ecdh_pub || '', String(d.ecdh_pub || ''))
                    && safeEqual(heldInvite.kyber_pub || '', String(d.kyber_pub || ''));
          if (!same) {
            log('warn', 'pubkey_invite_overwrite_refused', { device: d.device_id.slice(0, 12) });
            res.writeHead(409, { 'Content-Type': 'application/json' });
            return res.end(J({ error: 'Pubkey already registered for this session: first registration wins' }));
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(J({ ok: true, fingerprint: heldInvite.fingerprint }));
        }
        pubkeys.set(d.device_id, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', fingerprint: invFp, ts: new Date().toISOString(), registered_at: new Date().toISOString(), expires: Date.now() + INVITE_PUBKEY_TTL });
        log('info', 'pubkey_registered_invite', { device: d.device_id.slice(0, 12), fp: invFp });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, fingerprint: invFp }));
      }
      // Non-invite: require valid API key
      if (!keyData?.active) { res.writeHead(401); return res.end(J({ error: 'Invalid API key' })); }
      // Device cap on the PRODUCT axis (parasendLimitsOf), not on the unified
      // `plan`. This read was `keyData.plan || 'pro'`: it could not see a
      // webhook-written plan_parasend, and its default handed a key with no
      // plan at all the Pro cap of 50 devices - the mirror image of the fault
      // closed on the inbound ceilings. The strictest tier is the right
      // default; _pubkeyMax stays as the tiers.js lookup for other callers.
      const _psend = parasendLimitsOf(keyData);
      const plan = _psend.tier;
      const maxDevices = _psend.limits.devices;
      // The cap governs how many devices an account may HAVE, so it applies to a
      // registration that would ADD one. A device this account already holds is
      // re-registered, not added: the map entry is replaced and the count does
      // not grow. Checking the cap first turned every re-registration by an
      // account over its cap into a 429, and re-registration is the normal path
      // (a community device pubkey lives 7 days and the expiry sweep runs
      // hourly), so an account over its cap could never refresh a device it
      // already had and would lose them one by one. Being over the cap is a real
      // state: every account that registered while the counter matched nothing
      // (see below), and any account moved to a lower tier afterwards.
      const _pkSlot = `${d.device_id}:${acctOf(apiKey)}`;
      const _alreadyHeld = pubkeys.has(_pkSlot);
      if (maxDevices !== Infinity && !_alreadyHeld) {
        // Count what is actually STORED. Every write and every lookup on this
        // map is keyed `<device_id>:<account_id>` (acctOf), but this counter
        // matched on `:<api_key>`, which equals the account id only for a key
        // that has none. So for every real account the tally stayed 0 and the
        // cap never fired, whatever the tier said. Counting the same suffix
        // the route writes makes the ceiling above enforceable.
        const keyPrefix = `:${acctOf(apiKey)}`;
        let deviceCount = 0;
        for (const k of pubkeys.keys()) { if (k.endsWith(keyPrefix)) deviceCount++; }
        if (deviceCount >= maxDevices) {
          res.writeHead(429); return res.end(J({ error: `Device limit reached. Max ${maxDevices} devices on ${plan} plan.`, limit: maxDevices, plan }));
        }
      }
      const ttl = _pubkeyTtl[plan] ?? _pubkeyTtl.free;
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      const attestResult = verifyAttestation(d.ecdh_pub, d.device_id, d.attestation || null);
      const existingPubkey = pubkeys.get(_pkSlot);
      if (existingPubkey && (!existingPubkey.expires || Date.now() < existingPubkey.expires)) {
        res.writeHead(409); return res.end(J({ error: 'Pubkey already registered for this session: first registration wins' }));
      }
      const fp = computeFingerprint(d.kyber_pub || '', d.ecdh_pub);
      const regAt = new Date().toISOString();
      pubkeys.set(_pkSlot, {
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
    // A named device slot belongs to an account, and reading one needs the key
    // that owns it. These three routes sit before the auth gate so the keyless
    // inv_ share-link flow can work, and until the 2026-09-05 review (finding
    // 22l) they let that keylessness spill onto the named slots as well: acctOf
    // returns the header value verbatim for a key it does not know, so
    // `X-Api-Key: <account_id>` addressed any account's namespace. Today
    // account_id and api_key are the same string, so that header is also the
    // real key and little is lost; the moment accounts move to non-secret
    // acct_ ids, it becomes a cross-account read oracle. The inv_ branch stays
    // keyless, which is the whole reason these routes are here.
    if (!INVITE_RE.test(deviceId) && !keyData?.active) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
    }
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
    // Same rule as GET /v2/pubkey/:device above.
    if (!INVITE_RE.test(deviceId) && !keyData?.active) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
    }
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
      // Same rule as GET /v2/pubkey/:device above. A fingerprint check is a
      // yes/no oracle over a stored key, so it needs the same entitlement as
      // reading the key it is checking.
      if (!INVITE_RE.test(d.device_id) && !keyData?.active) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
      }
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
      // Bind the committed hash to the actual bytes: the hash is written into the
      // CT-log leaf and the signed delivery receipt, so an unverified claim would
      // let a caller mint a relay-signed, CT-anchored proof for bytes the relay
      // never held. The honest client sends hash = sha256(payload bytes), so this
      // is non-breaking. Rejected before peek / ctAppendTransfer / blobStore.set.
      if (crypto.createHash('sha256').update(blob).digest('hex') !== hash) { res.writeHead(400); return res.end(J({ error: 'hash_mismatch' })); }
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
      blobPut(hash, {
        blob, ts: now, ttl, size: blob.length,
        apiKey: null, max_views: 1, views_remaining: 1, sector: SECTOR,
        ct_entry: { index: ctEntry.index, leaf_hash: ctEntry.leaf_hash, tree_hash: ctEntry.tree_hash,
                    tree_size: ctEntry.index + 1, audit_path: ctEntry.proof, sth: ctEntry.sth || null,
                    ts: ctEntry.ts },
      });
      setTimeout(() => { blobDrop(hash); }, ttl);
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
  const isBillingWebhook = path === '/v2/billing/webhook' && req.method === 'POST';
  // The admin plane cancelling on behalf of a logged-in session. It carries
  // X-Internal-Auth, which no public caller can set, and the route itself
  // resolves the account from the user_id in the body. Without this line the
  // pipeline answered "Invalid API key" before the route was ever reached, and
  // the Cancel plan button on /account had no way to stop a collection at all.
  const isInternalBillingCancel = path === '/v2/billing/cancel'
    && req.method === 'POST' && _internalOk();
  if (isAdminPath) {
    const adminHeader = (req.headers['x-admin-token'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '') || '').trim();
    const validAdmin = !!adminHeader && !!process.env.ADMIN_TOKEN && safeEqual(adminHeader, process.env.ADMIN_TOKEN);
    if (!validAdmin) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'ADMIN_TOKEN required for admin endpoints' }));
    }
    // Fall through to admin endpoint handlers below
  } else if (!keyData?.active && !isEnvelopePublic && !isBillingWebhook && !isInternalBillingCancel) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
  }

  // ── POST /v2/session/create — Sender maakt PSS-gebonden sessie ─────────────
  // Vereist: geldige API key, commitment = SHA3-256(pss) als hex.
  // SHA3, niet SHA-256: /join rekent sha3-256 en deze kant zei jarenlang iets
  // anders. Beide geven 64 hex, dus een SDK die de foutmelding volgde bouwde een
  // sessie die nooit te joinen was en kreeg pas bij join een 403 die "verkeerde
  // PSS" zei. docs/security.md had het als enige goed.
  // Geeft: session_id (pss_<32hex>), expires_ms
  // Relay ziet alleen de hash — kan PSS niet reconstrueren
  if (path === '/v2/session/create' && req.method === 'POST') {
    if (!keyData) { res.writeHead(401); return res.end(J({ error: 'Valid API key required' })); }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.commitment || !/^[a-f0-9]{64}$/.test(d.commitment)) {
        res.writeHead(400);
        return res.end(J({ error: 'commitment must be SHA3-256 hex (64 chars) of your pre-shared secret' }));
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

  // ── The streaming manifest ───────────────────────────────────────────────────
  //
  // WHY THIS EXISTS. The sender used to upload every block of a file and only
  // then tell the receiver, by registering `<session>_ready` with the full token
  // list. For a 500 MB file that is 112 blocks sitting in the relay's memory at
  // once, for as long as the whole upload takes, and blobs live in RAM: that is
  // 560 MB held for one transfer, and it is also 560 MB that a restart throws
  // away. The fleet restarted hourly for twenty-one days in July and August and
  // nobody lost a transfer, but only because there was almost no traffic.
  //
  // With a manifest the receiver learns each token as it is minted and takes the
  // block straight away, so the sender can keep a small sliding window instead of
  // the whole file. The same change cuts the memory a transfer costs and the
  // window in which a restart can lose something.
  //
  // WHY NOT REUSE `_ready`. POST /v2/pubkey answers 409 on a second write to the
  // same slot: first registration wins, and that is a property worth keeping.
  // A manifest is append-only by nature and needed its own door.
  //
  // The manifest hangs off the session, so it expires with it and needs no sweep
  // of its own. Writing needs the session's API key, exactly like the pubkey
  // route above. Reading needs only the session id, exactly like
  // GET /v2/pubkey/:device, which is how the receiver already reads `_ready`:
  // knowing the pss_ token IS the capability, and the tokens it hands back are
  // useless without the private key that decrypts what they point at.
  const sessMfm = path.match(/^\/v2\/session\/(pss_[a-f0-9]{48})\/manifest$/);
  if (sessMfm && req.method === 'POST') {
    if (!keyData) { res.writeHead(401); return res.end(J({ error: 'Valid API key required' })); }
    const sess = sessions.get(sessMfm[1]);
    if (!sess)                   { res.writeHead(404); return res.end(J({ error: 'Session not found or expired' })); }
    if (sess.api_key !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Session belongs to a different API key' })); }
    let d;
    try { d = JSON.parse((await readBody(req, 8192)).toString()); }
    catch (e) { res.writeHead(400); return res.end(J({ error: 'bad_request' })); }
    const idx   = Number(d.index);
    const total = Number(d.total_chunks);
    const token = typeof d.token === 'string' ? d.token : '';
    if (!Number.isInteger(idx) || idx < 0 || idx > 100000) { res.writeHead(400); return res.end(J({ error: 'index must be a non-negative integer' })); }
    if (!Number.isInteger(total) || total < 1 || total > 100000) { res.writeHead(400); return res.end(J({ error: 'total_chunks must be a positive integer' })); }
    if (idx >= total) { res.writeHead(400); return res.end(J({ error: 'index must be below total_chunks' })); }
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(token)) { res.writeHead(400); return res.end(J({ error: 'token must be a download token' })); }
    if (!sess.manifest) sess.manifest = { total, tokens: new Map(), meta: null };
    if (sess.manifest.total !== total) { res.writeHead(409); return res.end(J({ error: 'total_chunks changed mid-transfer' })); }
    // First write wins per index, for the same reason the pubkey slot does: a
    // second token for a block the receiver may already have taken would point
    // it at a blob that is gone.
    if (!sess.manifest.tokens.has(idx)) sess.manifest.tokens.set(idx, token);
    if (typeof d.meta === 'string' && d.meta.length <= 2048 && !sess.manifest.meta) sess.manifest.meta = d.meta;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, have: sess.manifest.tokens.size, total }));
  }
  if (sessMfm && req.method === 'GET') {
    const sess = sessions.get(sessMfm[1]);
    if (!sess)          { res.writeHead(404); return res.end(J({ error: 'Session not found or expired' })); }
    if (!sess.manifest) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(J({ ok: true, total: 0, chunks: [], complete: false })); }
    const m = sess.manifest;
    const chunks = [...m.tokens.entries()].sort((a, b) => a[0] - b[0]).map(([index, token]) => ({ index, token }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, total: m.total, meta: m.meta, chunks, complete: chunks.length === m.total }));
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
      // Bind the committed hash to the actual bytes: the hash is written into the
      // CT-log leaf and the signed delivery receipt, so an unverified claim would
      // let a caller mint a relay-signed, CT-anchored proof for bytes the relay
      // never held. The honest client sends hash = sha256(payload bytes), so this
      // is non-breaking. Rejected before peek / ctAppendTransfer / blobStore.set.
      if (crypto.createHash('sha256').update(blob).digest('hex') !== hash) { res.writeHead(400); return res.end(J({ error: 'hash_mismatch' })); }
      const _psend = parasendLimitsOf(keyData);

      // ── Two ceilings, and they are not the same ceiling ──────────────────
      //
      // 1. THE BLOB CEILING. MAX_BLOB is the wire-format roof: every blob is
      //    padded to exactly this, so anything larger is malformed rather than
      //    merely big. It is the operator's number and no tier may exceed it.
      //    This is not a product limit and does not vary by plan.
      if (blob.length > MAX_BLOB) {
        res.writeHead(413);
        return res.end(J({ error: 'blob_too_large', max_bytes: MAX_BLOB,
          hint: 'one blob is one padded block; split the file into chunks' }));
      }

      // 2. THE FILE CEILING. The tier's file_mb, enforced across the blocks
      //    that make up one file. This is the number the site sells. Comparing
      //    a single blob against it, which is what this code used to do, held
      //    every file to the size of one block and made file_mb unsellable.
      //
      //    A sender without a file_id is sending one standalone block, which is
      //    by definition inside any file ceiling, so there is nothing to count.
      const _fileMb = _psend.limits.file_mb;
      const _fileId = meta && meta.file_id ? String(meta.file_id).slice(0, 128) : null;
      if (_fileId && Number.isFinite(_fileMb)) {
        const _fk   = `${acctOf(apiKey)}:${_fileId}`;
        const _seen = fileBlocks.get(_fk);
        const _n    = (_seen ? _seen.blocks : 0) + 1;
        if (_n > fileMaxBlocks(_fileMb)) {
          log('info', 'file_ceiling_reached', { account: String(keyData?.account_id || '').slice(0, 12), plan: _psend.tier, file_mb: _fileMb });
          res.writeHead(413, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'file_too_large', dimension: 'file_mb',
            plan: _psend.tier, limit_mb: _fileMb,
            message: `Max ${_fileMb}MB per file on ${_psend.tier}` }));
        }
        fileBlocks.set(_fk, { blocks: _n, ts: Date.now() });
      }

      // 3. THE CONCURRENCY CEILING. Blobs live in RAM, so what one account may
      //    hold at once is a real resource and not a paperwork limit. The
      //    relay-wide budget (ramOk, above) is the harder floor underneath;
      //    this one stops a single account from taking the whole pool while
      //    everyone else gets the 503.
      const _maxConc = _psend.limits.concurrent_blobs;
      if (Number.isFinite(_maxConc) && keyData && keyData.account_id) {
        const _held = accountBlobs.get(acctOf(apiKey)) || 0;
        if (_held >= _maxConc) {
          log('info', 'concurrency_ceiling_reached', { account: String(keyData.account_id).slice(0, 12), plan: _psend.tier, held: _held, limit: _maxConc });
          res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '5' });
          return res.end(J({ error: 'too_many_blocks_in_flight', dimension: 'concurrent_blobs',
            plan: _psend.tier, limit: _maxConc, held: _held, retry_after_s: 5,
            hint: 'blocks free up as the receiver takes them' }));
        }
      }

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

      // Per-tier ceilings, off the SAME ParaSend entitlement as the size gate
      // above and the quota gate below. ONE default for both, and it is the
      // strictest one. The two used to disagree a line apart: the TTL fell back
      // to 'community' and max_views to 'pro', so a key with no plan was held
      // to the community link lifetime and handed the Pro read count at the
      // same time. That default was fixed; the SOURCE was not, and reading the
      // unified `plan` here meant a ParaSend Pro buyer still got 1 hour and 1
      // read, because the webhook only ever writes plan_parasend.
      const _maxTtl = _psend.limits.view_ttl_ms;
      const ttl = Math.min(parseInt(ttl_ms || TTL_MS), _maxTtl);
      // Access policies: max_views (default 1 = burn-on-read) + Argon2id password.
      const maxViews = Math.max(1, Math.min(parseInt(reqMaxViews || 1) || 1, _psend.limits.max_views || 1));
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
        // ParaSend entitlement: transfers_month for this account's plan_parasend
        // (falls back to the legacy plan when not yet migrated). Independent of
        // the ParaSign signs quota below.
        const _tLimit = _psend.quotas.transfers_month;
        const _tGate  = await quota.gateTransfer(redisClient, keyData.account_id, _dedupKey, _tLimit, log);
        if (!_tGate.allowed) {
          // Report the tier that DECIDED, not the unified plan. A ParaSend Pro
          // buyer whose `plan` still reads community would otherwise be told
          // he is on community while being held to the Pro ceiling.
          log('info', 'quota_transfer_declined', { account: String(keyData.account_id).slice(0, 12), plan: _psend.tier, limit: _tLimit });
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: _psend.tier, limit: _tLimit }));
        }
      }

      // Append transfer to CT log before storing — so proof is available at outbound time
      const ctEntry = ctAppendTransfer(hash, SECTOR);
      blobPut(hash, { blob, ts: Date.now(), ttl, size: blob.length,
        account_id: acctOf(apiKey),
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
        blobDrop(hash);
      }, ttl);

      const deviceId = meta?.device_id;
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      // `via` marks the credential, not a second identity. The chain is the
      // owner's, keyed on the owner's api-key exactly as it is for a request
      // that carried the key, and only the field says the fifteen-minute token
      // was what presented it. Without it an account owner reading their own
      // audit log cannot tell a transfer made from a browser session apart from
      // one made with the key itself, which is the difference that matters when
      // they are trying to work out what happened.
      auditAppend(apiKey, 'inbound', { hash: hash.slice(0,16)+'...', bytes: blob.length, device: deviceId, sig: sigResult.valid ? 'ML-DSA-OK' : 'unsigned', ...(viaSessionToken ? { via: 'pst' } : {}) });
      log('info', 'blob_stored', { hash: hash.slice(0,16), size: blob.length, sig: sigResult.valid });
      // ParaSend Pro upload notification (no-op below Pro+ or without RESEND key).
      transferNotify.maybeNotify({ keyData, event: 'upload', hashPrefix: hash, bytes: blob.length, sendEmail: sendResendEmail });

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
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(400); return res.end(J({ error: e.message })); }
    finally { inFlightInbound--; }
  }

  // ── DELETE /v2/inbound/:hash — Caller-initiated abort (orphan cleanup) ────────
  const delm = path.match(/^\/v2\/inbound\/([a-f0-9]{64})$/);
  if (delm && req.method === 'DELETE') {
    const entry = blobStore.get(delm[1]);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Not found' })); }
    // An anonymous blob is stored with apiKey: null, and `entry.apiKey && ...`
    // skipped the owner check entirely for it. On the READ side that is the
    // design and it is written down: the 64-hex hash is the capability, the
    // payload is encrypted with a key in the URL fragment that the relay never
    // sees, and it burns after one read. Destroying is not reading. Whoever
    // glimpsed the hash in an access log, a browser history or a mail gateway's
    // link scanner could end the transfer without ever being able to open it,
    // and the sender would never learn why. So a blob with no owner has no
    // owner who can abort it either: it goes when it burns or when its TTL
    // runs out. The 2026-09-05 review, finding 22d.
    if (!entry.apiKey || entry.apiKey !== apiKey) { res.writeHead(403); return res.end(J({ error: 'Forbidden' })); }
    blobDrop(delm[1]);
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
    if (!outboundRateOk(apiKey, keyData)) {
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
      // Unlisted immediately so a concurrent reader cannot find it, but NOT
      // wiped: `blob` below is the buffer being served. Wiping here handed the
      // downloader five megabytes of zeroes.
      blobDrop(outm[1], false);
      res.on('finish', () => zeroBuffer(blob));
      res.on('close',  () => zeroBuffer(blob));
      incMetric('blobs_burned'); stats.burned++;
    }
    incMetric('bytes_out_total', blob.length);
    stats.outbound++; stats.bytes_out += blob.length;
    auditAppend(apiKey, burned ? 'outbound_burn' : 'outbound_view',
      { hash: outm[1].slice(0,16)+'...', bytes: blob.length, views_left: entry.views_remaining });
    log('info', burned ? 'blob_burned' : 'blob_served',
      { hash: outm[1].slice(0,16), views_left: entry.views_remaining });
    // ParaSend Pro download notification. Notify the transfer OWNER (the uploader),
    // whose key is on the blob entry — not the downloader. No-op below Pro+ / no key.
    {
      const _ownerKd = entry.apiKey ? apiKeys.get(entry.apiKey) : null;
      transferNotify.maybeNotify({ keyData: _ownerKd, event: 'download', hashPrefix: outm[1], bytes: blob.length, sendEmail: sendResendEmail });
    }

    // ── Build signed delivery receipt ────────────────────────────────────────
    let receiptHeader = null;
    let receiptJson = null;
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
      receiptJson = JSON.stringify(receipt);
      receiptHeader = Buffer.from(receiptJson).toString('base64url');
    }

    const outHeaders = {
      'Content-Type':       'application/octet-stream',
      'Content-Length':     blob.length,
      'X-Paramant-Burned':  burned ? 'true' : 'false',
      'X-Paramant-Hash':    outm[1],
    };
    // The receipt travels by reference, not by value: an id to fetch it with and
    // the hash of the exact bytes that will come back, so the handover itself is
    // verifiable. The payload is ~18 KB and does not fit in a response header
    // that Node clients or a default nginx will accept (see the store above).
    if (receiptHeader) {
      const receiptHash = crypto.createHash('sha3-256').update(receiptHeader).digest('hex');
      const _receiptKey = entry.apiKey || apiKey || null;
      const _receiptRec = (_receiptKey && apiKeys.get(_receiptKey)) || keyData || null;
      const receiptId = await storeDeliveryReceipt(receiptJson, receiptHash, _receiptKey,
        _receiptKey ? acctOf(_receiptKey) : null, _receiptRec);
      outHeaders['X-Paramant-Receipt-Id'] = receiptId;
      outHeaders['X-Paramant-Receipt-Hash'] = 'sha3-256:' + receiptHash;
      outHeaders['X-Paramant-Receipt-Url'] = `/v2/transfers/${receiptId}/receipt`;
      // DEPRECATED, off by default, removed after 2026-12-01. When it is off,
      // say so ON THE RESPONSE. A client that reads X-Paramant-Receipt and finds
      // nothing there has no way to tell "this transfer had no receipt" from
      // "the receipt moved", and the Python SDK's own handling of an absent
      // header is a silent receipt=None (sdk-py/paramant_sdk.py:681). A silent
      // downgrade of a delivery proof is the one failure mode this route must
      // not have, so the removal announces itself and says where to go.
      if (INLINE_RECEIPT_HEADER) outHeaders['X-Paramant-Receipt'] = receiptHeader;
      else outHeaders['X-Paramant-Receipt-Deprecated'] = `removed 2026-12-01; GET /v2/transfers/${receiptId}/receipt`;
    }
    res.writeHead(200, outHeaders);
    if (burned) return res.end(blob, () => { try { blob.fill(0); } catch {} });
    return res.end(blob);
  }

  // ── GET /v2/transfers/:receipt_id/receipt ─ the delivery receipt, by reference ─
  // Answers with the exact base64url payload GET /v2/outbound/:hash used to put
  // in its X-Paramant-Receipt header, so a client that already decodes that
  // string, or posts it to /v2/verify-receipt, needs no other change.
  // The id is 16 random bytes handed only to the caller that did the download,
  // and the receipt is additionally bound to that caller's API key. An unknown,
  // expired, or foreign id answers with ONE 404, so the route can never be used
  // to probe whether a transfer existed.
  const rcptm = path.match(/^\/v2\/transfers\/([a-f0-9]{32})\/receipt$/);
  if (rcptm && req.method === 'GET') {
    const rec = await fetchDeliveryReceipt(rcptm[1]);
    const gone = { error: 'Not found. Expired, or never issued.' };
    if (!rec) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J(gone)); }
    if (rec.apiKey && rec.apiKey !== apiKey) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J(gone)); }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(J({ ok: true, receipt: Buffer.from(rec.json).toString('base64url'), receipt_hash: 'sha3-256:' + rec.hash }));
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
    // Webhook registration is an advertised ParaSend Pro capability. Before this
    // gate ANY tier (incl. Free/community) could register a ghostpipe webhook.
    // Require a live key and ParaSend Pro+ (community/free -> 403). The ParaSign
    // /v1 completion webhooks are unaffected: they live behind the /v1 parasign
    // scope, not this route.
    if (!keyData || keyData.active === false) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'API key required' }));
    }
    if (!tierGate.isParasendProPlus(keyData)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'tier_upgrade_required', feature: 'webhooks', message: 'Webhook registration requires a Pro plan or higher.' }));
    }
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

  // ── GET /v2/user/history — per-account send/link history (ParaSend/ParaSign Pro) ─
  // Pure read-view over the per-key Merkle audit chain (no new storage). Pro+ only.
  if (path === '/v2/user/history' && req.method === 'GET') {
    const acct = acctOf(apiKey);
    const memberKeys = [...(accountKeys.get(acct) || new Set([apiKey]))];
    return userHistory.handle({
      res, J, keyData, memberKeys,
      auditFor: (k) => auditChain.get(k) || [],
      query,
    });
  }

  // ── GET /v2/parasign/audit-export — ParaSign Business signing-audit export ────
  // Tier-gated on the audit_export entitlement (Business+). CSV or JSON export of
  // the account's tamper-evident audit chain + the CT signed tree head.
  if (path === '/v2/parasign/audit-export' && req.method === 'GET') {
    const acct = acctOf(apiKey);
    const memberKeys = [...(accountKeys.get(acct) || new Set([apiKey]))];
    return parasignAuditExport.handle({
      res, J, keyData, memberKeys,
      auditFor: (k) => auditChain.get(k) || [],
      ctHead: () => (sthLog.length ? sthLog[sthLog.length - 1] : null),
      verifyChain,
      query,
      // Full per-envelope .psign export: enumerate the account's envelopes via
      // the index and rebuild each completed one's notary-signed .psign, reusing
      // the exact recipe GET /v1/receipt uses (parasignOpenApi.buildEnvelopePsign).
      account: acct,
      envStore: _envStore(),
      metaStore: _parasignStore(),
      buildPsign: parasignOpenApi.buildEnvelopePsign,
      sigEngine: (mlDsa && registry) ? registry.getSig(0x0002) : null,
      relayIdentity,
      canonicalJSON: parasign.canonicalJSON,
      publicOrigin: process.env.PARASIGN_PUBLIC_ORIGIN || 'https://paramant.app',
    });
  }

  // ── GET /v2/parasign/inbox: what is waiting for THIS account's signature ─────
  // The mirror of the worklist behind POST /v2/user/envelopes. That one lists
  // what the account SENT, off the per-account index; this one lists what was
  // sent TO it, off the per-party index in envelope.js. Until it existed a
  // signed-in recipient could not learn a signing request existed at all: the
  // only handle on an envelope was the per-party invite token in the mail, and
  // losing the mail meant losing the document.
  //
  // THE ADDRESS IS DERIVED HERE, NEVER SUPPLIED. The account is already
  // authenticated (api-key, or an app-purpose session token resolved to the
  // same key, above), and its registered address is on the key record. Hashing
  // that with the canonical partyEmailHash is the whole authorisation: an
  // account can only ever be handed the worklist of the address it signed in
  // with. Accepting a hash from a header instead would have made this route a
  // way to read anybody's worklist, which is why the trusted-header pattern the
  // /v2/envelopes/:id/document route uses is deliberately NOT copied here.
  //
  // WHAT IT WILL NOT SAY. No invite token, no document hash, no capsule, no
  // envelope-wide party list. The answer is knowing-THAT a document waits, from
  // whom, since when and until when. Opening it still takes the link in the
  // mail, so this route cannot become a second way in.
  if (path === '/v2/parasign/inbox' && req.method === 'GET') {
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'envelope_store_unavailable' })); }
    const acct = acctOf(apiKey);
    // The address on the key, falling back to the account summary. Same
    // precedence _indexAccountExpiry() uses for the address it mails.
    const selfEmail = (keyData && keyData.email) || (accounts.get(acct) || {}).email || '';
    const selfHash = envelopeMod.partyEmailHash(selfEmail);
    // An account with no address on record is a party to nothing: the hash of
    // an empty string is not a party hash, so answering empty is the truth.
    if (!selfHash) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(J({ ok: true, documents: [], count: 0 }));
    }
    const limit = Math.max(1, Math.min(parseInt((Array.isArray(query.limit) ? query.limit[0] : query.limit) || '50', 10) || 50, 200));
    try {
      const documents = await store.listPartyEnvelopes(selfHash, { limit, resolveSender: senderLabelOf });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(J({ ok: true, documents, count: documents.length }));
    } catch (err) {
      if (redisOutage503(err, res)) return;
      console.error('[parasign/inbox]', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'internal' }));
    }
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
      // The key a new enrollment binds to: the presented API key, or for a
      // DID-authenticated register the key the AUTHENTICATING DID was enrolled
      // under (keyData.account_id). Binding to '' here would mint a keyless
      // enrollment from an authenticated session AND skip the per-key cap.
      const ownerKey = apiKey || (keyData && keyData.account_id) || '';
      // Rate limit: max 500 DIDs per API key to prevent RAM DoS. Counter is O(1)
      // (didKeyCounts) instead of an O(n) scan of the whole registry per request.
      const MAX_DID_PER_KEY = 500;
      if (ownerKey) {
        const keyDidCount = didKeyCounts.get(ownerKey) || 0;
        if (keyDidCount >= MAX_DID_PER_KEY) {
          res.writeHead(429); return res.end(J({ error: `DID limit reached. Max ${MAX_DID_PER_KEY} DIDs per API key.` }));
        }
      }
      const did = generateDid(d.device_id, d.ecdh_pub);
      const doc = createDidDocument(did, d.device_id, d.ecdh_pub, d.dsa_pub || '');
      const _didIsNew = !didRegistry.has(did); // overwrite of same did must not double-count
      didRegistry.set(did, { device_id: d.device_id, key: ownerKey, doc, ts: new Date().toISOString() });
      if (_didIsNew && ownerKey) didKeyCounts.set(ownerKey, (didKeyCounts.get(ownerKey) || 0) + 1);
      // Pubkey TTL follows the authenticated ParaSend tier; an ANONYMOUS
      // (keyless inv_) registration gets the free-tier TTL, never the pro
      // default. Same fix as POST /v2/pubkey: the tier comes off the product
      // axis, and a key with no plan on file lands on community (7 days) rather
      // than being handed the pro 30 by the `|| 'pro'` default.
      const _didPlan = keyData ? parasendLimitsOf(keyData).tier : 'free';
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
    // Same owner resolution as everywhere: the API key, or for DID-auth the key
    // the DID enrolled under. Never '' (which would match keyless inv_ entries).
    const _didListKey = apiKey || (keyData && keyData.account_id) || null;
    const dids = [...didRegistry.values()].filter(e => _didListKey && e.key === _didListKey).map(e => ({ did: e.doc.id, device: e.device_id, ts: e.ts }));
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
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(400); return res.end(J({ error: e.message })); }
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
      kid: v.kid || null, account_id: v.account_id || k, is_primary: !!v.is_primary, scope: v.scope || 'full', parasign: !!v.parasign, created: v.created || null,
      // Per-product truth for the admin panel: the stored per-product tier, or a
      // no-downgrade derivation from the legacy plan for un-migrated records
      // (mirrors getEntitlements' fallback) so an operator never sees a blank.
      plan_parasign: v.plan_parasign || entitlements.derivePlanParasign(v.plan, v.parasign),
      plan_parasend: v.plan_parasend || entitlements.derivePlanParasend(v.plan),
      // The period the tier was paid for. WITHOUT this the tier above is the
      // whole story a reader gets, and "no period" is read everywhere as "never
      // expires" (entitlements.effectiveProductTier, and the same rule mirrored
      // client-side in dashboard.js/account.inline1.js). Every account surface
      // in admin/ is built on this projection, so leaving it out made a lapsed
      // account render as "Pro, active" long after the relay's own gates had
      // floored it to free. The date is on the record; it just never left.
      paid_until_parasign: v[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign] || null,
      paid_until_parasend: v[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasend] || null,
      // Is there a collection standing behind this account. The account page
      // told every customer auto_renews:false because nothing on this
      // projection could say otherwise, and with BILLING_MODE set that is the
      // opposite of the truth: checkout opens a mandate and a subscription, and
      // Mollie collects again on its own. A page that says a plan does not
      // renew, next to a plan that does, is the one thing the buyer cannot
      // check for himself.
      auto_renews: Object.values(billingRecurring.PRODUCT_SUBSCRIPTION_FIELD).some((f) => !!v[f]),
      usage_purpose: v.usage_purpose || null, usage_purpose_at: v.usage_purpose_at || null /*MARK:parasign_list*/
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
      active: v.active, is_primary: !!v.is_primary, scope: v.scope || 'full', parasign: !!v.parasign, created: v.created || null,
      plan_parasign: v.plan_parasign || entitlements.derivePlanParasign(v.plan, v.parasign),
      plan_parasend: v.plan_parasend || entitlements.derivePlanParasend(v.plan),
      paid_until_parasign: v[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign] || null,
      paid_until_parasend: v[entitlements.PRODUCT_PAID_UNTIL_FIELD.parasend] || null,
      usage_purpose: v.usage_purpose || null, usage_purpose_at: v.usage_purpose_at || null }));/*MARK:parasign_reveal*/
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
      // The limits an operator reads here are the limits the relay enforces, so
      // they come off the same product axis the gates read and NOT off the
      // unified `plan`, which a webhook upgrade never moves. Both product tiers
      // ride along, because `plan` alone no longer explains the numbers.
      const ent = entitlements.getEntitlements(v);
      out.push({
        account_id: accountId,
        api_key_prefix: k.slice(0, 12),
        plan,
        parasend_tier: ent.parasend.tier,
        parasign_tier: ent.parasign.tier,
        label: v.label || '',
        email: v.email || null,
        active: !!v.active,
        usage,
        limits: {
          transfers_month: _reportLimit(ent.parasend.quotas.transfers_month),
          signs_month:     _reportLimit(ent.parasign.quotas.signs_month),
          file_mb:         _effectiveFileMb(ent),
          devices:         _reportLimit(ent.parasend.limits.devices),
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
    // Same product axis as the list above and as the gates themselves.
    const ent = entitlements.getEntitlements(entry ? entry[1] : null);
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
      parasend_tier: ent.parasend.tier,
      parasign_tier: ent.parasign.tier,
      limits: {
        transfers_month: _reportLimit(ent.parasend.quotas.transfers_month),
        signs_month:     _reportLimit(ent.parasign.quotas.signs_month),
        file_mb:         _effectiveFileMb(ent),
        devices:         _reportLimit(ent.parasend.limits.devices),
      },
    }));
  }

  // ── GET /v2/admin/billing/export: the books for one period ────────────────
  // Every document issued between `from` and `to`, both ends inclusive, both
  // series (PS invoices and receipts, CN credit notes), in the shape the person
  // doing the VAT return actually opens. Auth: ADMIN_TOKEN, handled above with
  // every other /v2/admin path; this is the whole customer base's billing in one
  // response and it may never hang off a customer key.
  //
  //   ?from=2026-09-01&to=2026-09-30   the period, on the date the DOCUMENT
  //                                    states, not on when it was written
  //   ?format=csv                      default. Semicolon, UTF-8 BOM, comma
  //                                    decimals: a Dutch Excel opens it as a
  //                                    table of numbers, not one column of text
  //   ?format=json                     the same rows with dots and no BOM
  //   ?pdfs=1                          a zip: one PDF per document plus the
  //                                    ledger file, so the archive stands alone
  //
  // Read-only from end to end. It draws no number, writes no record and cannot
  // change what a document says; see lib/billing-export.js.
  if (path === '/v2/admin/billing/export' && req.method === 'GET') {
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'export_unavailable', hint: 'the documents live in redis' }));
    }
    const from = String(query.from || '').trim();
    const to = String(query.to || '').trim();
    const format = String(query.format || 'csv').trim().toLowerCase();
    if (format !== 'csv' && format !== 'json') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'bad_format', hint: 'format=csv or format=json' }));
    }
    const exported = await billingExport.build({ from, to, redis: redisClient });
    if (exported.error) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: exported.error, hint: 'from and to are YYYY-MM-DD, from <= to' }));
    }
    // A number in the global list with no document behind it is the one gap
    // lib/invoice.js cannot close (a crash between INCR and the write-back). It
    // rides along in the JSON body and is logged either way, because a hole in
    // a numbered series is exactly what an auditor comes looking for.
    if (exported.missing.length) {
      log('warn', 'billing_export_missing_documents', {
        from, to, count: exported.missing.length, numbers: exported.missing.slice(0, 20),
      });
    }
    log('info', 'billing_export', {
      from, to, format, pdfs: query.pdfs === '1', documents: exported.count, scanned: exported.scanned,
    });

    const base = billingExport.fileBase(from, to);
    if (query.pdfs === '1') {
      const built = billingExport.buildZipEntries(exported, { render: invoicePdf.render, format });
      if (built.failures.length) {
        log('warn', 'billing_export_pdf_failed', { from, to, count: built.failures.length });
      }
      let zip;
      try { zip = zipStore.buildZip(built.entries); }
      catch (e) {
        log('error', 'billing_export_zip_failed', { from, to, err: e.message });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'zip_failed' }));
      }
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Length': zip.length,
        'Content-Disposition': `attachment; filename="${base}.zip"`,
        'Cache-Control': 'private, no-store',
      });
      return res.end(zip);
    }

    if (format === 'json') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store' });
      return res.end(J(billingExport.asJson(exported)));
    }
    const csv = Buffer.from(billingExport.toCsv(exported.rows), 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Length': csv.length,
      'Content-Disposition': `attachment; filename="${base}.csv"`,
      'Cache-Control': 'private, no-store',
    });
    return res.end(csv);
  }

  // ── POST /v2/admin/keys/erase ─────────────────────────────────────────────
  // Revoke stops a key working; this removes the person. Article 17 GDPR asks for
  // erasure, and until now "delete account" left the email address in users.json
  // on every sector while only Redis was cleared. Audit finding 5 of 2026-07-21.
  //
  // Takes an account_id or a key and erases the identifying fields from both
  // places the account lives, keeping what a payment must stay traceable by.
  // Idempotent: a retry after a sector was briefly unreachable finds nothing left
  // and reports zero, which is a success and not an error.
  if (path === '/v2/admin/keys/erase' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const target = d.account_id || d.key;
      if (!target) { res.writeHead(400); return res.end(J({ error: 'account_id or key required' })); }
      let result = { accounts: 0, keys: 0, fields: 0 };
      await _mutateUsersJson(ud => {
        result = keysTable.erasePersonalData(ud, target);
        ud.updated = new Date().toISOString();
      });
      // Drop the in-memory copies too, otherwise the erased address stays
      // readable until the next restart.
      for (const [k, v] of apiKeys) {
        if (k === target || (v && v.account_id === target)) {
          for (const f of keysTable.PERSONAL_DATA_FIELDS) delete v[f];
          v.active = false;
        }
      }
      const acct = accounts.get(target);
      if (acct) { for (const f of keysTable.PERSONAL_DATA_FIELDS) delete acct[f]; }
      // The expiry index carries a copy of the address so any container can
      // mail from it. An erasure that left that copy behind would be an
      // erasure in name only, and the next sweep would write to it.
      if (redisClient && redisClient.isReady) {
        planExpiry.forgetAccount(redisClient, target)
          .catch(e => log('warn', 'plan_expiry_forget_failed', { err: e.message }));
      }
      log('info', 'account_erased', { target: String(target).slice(0, 16), ...result });
      res.writeHead(200); return res.end(J({ ok: true, erased: result }));
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(400); return res.end(J({ error: e.message })); }
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
      // Every live ParaSend session token for this key, gone from the shared
      // store, so the other four sectors stop honouring them too. Not awaited:
      // the revocation itself is already done above (the key is inactive in
      // this process and being persisted), and a slow redis must not hold up
      // the answer. It is also not the only thing standing between a revoked
      // key and a live token -- a resolved token is looked up in apiKeys like
      // any other credential, so this sweep is the fast path, not the guarantee.
      if (redisClient) {
        sessionTokens.revokeForKey(redisClient, revokedKey)
          .then(n => { if (n) log('info', 'session_tokens_revoked', { key: revokedKey.slice(0, 16), count: n }); })
          .catch(e => log('warn', 'session_token_revoke_failed', { err: e.message }));
      }
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

  // ── /v2/admin/coupons: create, list, withdraw ──────────────────────────
  // On the ordinary admin gate above (ADMIN_TOKEN, checked once for every
  // /v2/admin path), and on nothing else: a coupon raises a tier without a
  // payment, so the ability to mint one is exactly the ability to give the
  // product away. No session token of either purpose can reach these paths.
  //
  // The three verbs are deliberately not four. There is no edit: raising the
  // cap on a code people are already redeeming against, or changing what it
  // grants under them, is how two customers end up with different answers for
  // the same code. Withdraw it and make another.
  //
  // The withdraw carries the code IN THE PATH and takes no body. A DELETE with
  // a body that the auth gate above refuses before reading is a request whose
  // bytes are still on the wire when the 401 goes out, and the next request on
  // that kept-alive connection is answered by a socket that has lost its place.
  // Nothing needs a body here, so nothing sends one.
  if (path === '/v2/admin/coupons') {
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'coupons_unavailable', hint: 'the coupon store lives in redis' }));
    }
    try {
      if (req.method === 'GET') {
        const list = await coupon.listCoupons(redisClient);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, coupons: list }));
      }
      if (req.method === 'POST') {
        const body = JSON.parse((await readBody(req, 2048)).toString() || '{}');
        const out = await coupon.createCoupon(redisClient, {
          code: body.code,
          // Omitting `grants` means the campaign default: both products on Pro
          // for ninety days. One number, in lib/coupon.js, not in a curl line.
          grants: body.grants || undefined,
          max_redemptions: body.max_redemptions,
          valid_until: body.valid_until,
          created_by: body.created_by || 'admin',
          note: body.note,
        });
        if (!out.ok) {
          res.writeHead(out.error === 'code_exists' ? 409 : 400, { 'Content-Type': 'application/json' });
          return res.end(J({ error: out.error }));
        }
        log('info', 'coupon_created', {
          code: out.coupon.code, max: out.coupon.max_redemptions,
          grants: out.coupon.grants.map((g) => `${g.product}:${g.tier}:${g.days}d`).join(','),
          valid_until: out.coupon.valid_until,
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, coupon: out.coupon }));
      }
    } catch (e) {
      if (redisOutage503(e, res)) return;
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
    res.writeHead(405, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'method_not_allowed' }));
  }

  // ── /v2/admin/coupons/:code ────────────────────────────────────────────────
  // GET .../redemptions: the counter on the list says how many, this says which
  // accounts and when. It is the trail behind a term that was given rather than
  // sold, so it is the one thing a coupon leaves that an auditor can follow.
  //
  // DELETE .../:code: withdraw. A stamp, not a delete: the redemptions that
  // already happened are the record of terms that were given away, and they
  // stay readable. No term already granted is taken back.
  if (path.startsWith('/v2/admin/coupons/')) {
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'coupons_unavailable' }));
    }
    const rest = path.slice('/v2/admin/coupons/'.length);
    const wantsRedemptions = rest.endsWith('/redemptions');
    const c = coupon.normaliseCode(decodeURIComponent(
      wantsRedemptions ? rest.slice(0, -'/redemptions'.length) : rest));
    if (!c.ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_code' })); }
    try {
      if (wantsRedemptions && req.method === 'GET') {
        const doc = await coupon.getCoupon(redisClient, c.code);
        if (!doc) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unknown_code' })); }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, coupon: doc, redemptions: await coupon.redemptionsOf(redisClient, c.code) }));
      }
      if (!wantsRedemptions && req.method === 'DELETE') {
        const out = await coupon.revokeCoupon(redisClient, c.code);
        if (!out.ok) {
          res.writeHead(out.error === 'unknown_code' ? 404 : 400, { 'Content-Type': 'application/json' });
          return res.end(J({ error: out.error }));
        }
        log('info', 'coupon_revoked', { code: out.coupon.code, used: out.coupon.used });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true, coupon: out.coupon }));
      }
    } catch (e) {
      if (redisOutage503(e, res)) return;
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
    res.writeHead(405, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'method_not_allowed' }));
  }

  // ── POST /v2/billing/checkout — start a Mollie payment (authenticated) ───────
  // The amount comes from the server-side catalog, NEVER from the request body.
  // The caller only names product+plan+interval; it can never set a price.
  if (path === '/v2/billing/checkout' && req.method === 'POST') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    const accountId = acctOf(apiKey);
    let body;
    try { body = JSON.parse((await readBody(req, 2048)).toString() || '{}'); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_json' })); }
    const order = billingCatalog.resolveOrder({ product: body.product, plan: body.plan, interval: body.interval });
    if (order.error) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: order.error })); }
    const stance = mollie.billingStance();
    const mode = stance.mode;
    const origin = process.env.PARASIGN_PUBLIC_ORIGIN || 'https://paramant.app';
    try {
      // A Mollie customer, and a payment marked as the FIRST of a series. Both
      // are required before Mollie will create a mandate, and without a mandate
      // there is no authority to collect a second time: the payment succeeds,
      // the tier is granted, and the money never comes in again. That is what
      // made every sale a one-off.
      //
      // Only when BILLING_MODE was set by hand (stance.recurring). With it
      // empty, as production has run since billing exists, the customer step is
      // skipped and the payload below is byte for byte the one-off payment of
      // 2026-08-08. See mollie.billingStance for why an inferred mode is not
      // enough to open mandates against a real account.
      const cust = await billingRecurring.ensureCustomer(accountId, {
        recurring: stance.recurring, mode,
        getAccount: (aid) => _billingRecordOf(aid),
        saveCustomer: (aid, id) => _setMolliePointer(aid, billingRecurring.CUSTOMER_FIELD, id),
        mollie,
      });
      if (cust.result === 'failed') {
        log('error', 'billing_customer_failed', { account: String(accountId).slice(0, 12), err: cust.reason, status: cust.status });
      }
      const customerId = cust.customerId;
      const payment = await mollie.createPayment(mode, Object.assign({
        amount: { currency: order.currency, value: order.amount },
        description: `Paramant ${billingCatalog.orderLabel(order)} (${order.interval})`,
        redirectUrl: `${origin}/dashboard?billing=return`,
        webhookUrl: `${origin}/v2/billing/webhook`,
        metadata: { accountId, product: order.product, plan: order.plan, interval: order.interval },
      }, customerId ? { customerId, sequenceType: 'first' } : {}));
      const checkoutUrl = payment && payment._links && payment._links.checkout && payment._links.checkout.href;
      log('info', 'billing_checkout_created', { account: String(accountId).slice(0, 12), product: order.product, plan: order.plan, interval: order.interval, payment_id: payment && payment.id, mode, recurring: !!customerId });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, payment_id: payment && payment.id, checkout_url: checkoutUrl, mode }));
    } catch (e) {
      log('error', 'billing_checkout_failed', { account: String(accountId).slice(0, 12), err: e.message, status: e.status });
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'checkout_failed' }));
    }
  }

  // ── POST /v2/billing/webhook — Mollie payment status callback ────────────────
  // Mollie POSTs only { id } (form-encoded). The four hard rules live in
  // lib/billing.processPayment; here we (1) re-fetch the payment from Mollie and
  // trust ONLY that, then pass idempotency + entitlement effects as deps. Always
  // 200 on a handled event so Mollie stops retrying; 503 only for a transient
  // fetch failure we want retried.
  if (path === '/v2/billing/webhook' && req.method === 'POST') {
    let paymentId = '';
    try {
      const raw = (await readBody(req, 4096)).toString();
      paymentId = (new URLSearchParams(raw).get('id') || '').trim();
      if (!paymentId) { try { paymentId = (JSON.parse(raw).id || '').trim(); } catch { /* not json */ } }
    } catch { /* empty body */ }
    if (!/^tr_[A-Za-z0-9]+$/.test(paymentId)) {
      log('warn', 'billing_webhook_bad_id', { raw_id: String(paymentId).slice(0, 24) });
      res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_payment_id' }));
    }
    const stance = mollie.billingStance();
    const mode = stance.mode;
    let payment;
    try { payment = await mollie.getPayment(mode, paymentId); }
    catch (e) {
      const f = billing.classifyFetchError(e);
      log(f.level, 'billing_webhook_fetch_failed', {
        payment_id: paymentId, err: e.message, status: e.status, reason: f.reason, retry: f.retry });
      if (!f.retry) {
        // Permanent: acknowledge so Mollie stops retrying an event we can never
        // resolve. Nothing was granted; the warn log above is the trail.
        res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(J({ ok: true, ignored: 'unknown_payment' }));
      }
      res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'fetch_failed' }));
    }
    const _rok = () => !!(redisClient && redisClient.isReady);
    const _idemKey = (id) => `paramant:billing:done:${id}`;
    // The payment id that bought the period currently on file, per product.
    // Stored on the account record (and so in users.json) alongside the Mollie
    // pointers, which is what makes the idempotency guard durable.
    const _paidByField = (product) => `paid_by_${product}`;
    // The entitlement products one line item covers: one for a product plan,
    // two for the Firm bundle. Unknown metadata yields none, and nothing is
    // written for a payment we could not attribute.
    const catalogGrantsOf = (product, plan) => (billingCatalog.grantsOf(product, plan) || [])
      .filter((g) => entitlements.PRODUCTS.includes(g.product));
    const outcome = await billing.processPayment(payment, {
      setProductPlan,
      // Lets a renewal extend from where the paid period ends instead of from
      // the day the money landed, so paying early never costs the buyer days.
      currentPaidUntil: async (accountId, product) => {
        const rec = accounts.get(accountId);
        return (rec && rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]]) || null;
      },
      // Redis holds the marker, but redis is a cache here and users.json is the
      // record. When redis is down or has been flushed, isProcessed used to
      // answer 'no' and the grant ran a second time -- and since a grant extends
      // from the paid_until already on file, one payment bought two months. So
      // the account record carries the payment id that bought its current
      // period, and that answer survives anything redis does.
      isProcessed: async (id) => {
        if (_rok()) {
          try { const v = await redisClient.get(_idemKey(id)); if (v) return v; } catch { /* fall through to disk */ }
        }
        const rec = _billingRecordOf((payment.metadata || {}).accountId);
        if (!rec) return false;
        for (const p of entitlements.PRODUCTS) if (rec[_paidByField(p)] === id) return 'granted';
        return false;
      },
      markProcessed: async (id, val) => {
        const md = payment.metadata || {};
        // Persist first: this is the half that has to outlive a restart.
        // Every product this payment granted, so a Firm payment is remembered on
        // both halves. Reading only md.product would leave the parasend side
        // with no id on file, and a redis flush would then let the same bundle
        // payment grant a second month.
        const bought = catalogGrantsOf(md.product, md.plan);
        if (md.accountId && bought.length) {
          for (const g of bought) {
            // A revoke takes the money back, so the id that bought the period goes
            // with it; leaving it would make the reversal look like a live grant.
            _setMolliePointer(md.accountId, _paidByField(g.product), val === 'granted' ? id : null);
          }
        }
        if (!_rok()) return;
        try { await redisClient.set(_idemKey(id), String(val), { EX: 60 * 86400 }); } catch { /* best effort */ }
      },
    });
    // The collecting half. A grant only says what this payment bought; without
    // a subscription nothing asks for the next period. Deliberately AFTER the
    // grant and never able to undo it: a buyer who paid keeps what he paid for
    // even if Mollie refuses the subscription, and the error level is the
    // signal that this account will not renew by itself. With BILLING_MODE
    // empty (stance.recurring false) this is a silent skip: the 08-08 webhook
    // granted and stopped there, and so does this one.
    if (outcome.result === 'granted') {
      const sub = await billingRecurring.ensureSubscription(payment, outcome, {
        recurring: stance.recurring,
        mode,
        webhookUrl: `${process.env.PARASIGN_PUBLIC_ORIGIN || 'https://paramant.app'}/v2/billing/webhook`,
        getAccount: (aid) => _billingRecordOf(aid),
        saveSubscription: (aid, product, id) => _setMolliePointer(aid, billingRecurring.subscriptionFieldOf(product), id),
        mollie,
      });
      if (sub.result !== 'skipped') {
        log(sub.level || 'info', 'billing_subscription', {
          payment_id: paymentId, account: String(outcome.account).slice(0, 12),
          product: outcome.product, result: sub.result, reason: sub.reason,
          subscription_id: sub.subscriptionId, start_date: sub.startDate,
        });
      }
    }
    // The paperwork. A grant is money received, and money received without a
    // document is what this whole branch is about: no number, no VAT split, no
    // record to hand a bookkeeper. Runs AFTER the grant and can never undo it.
    //
    // 'already_processed' is included on purpose. A repeat webhook for a paid
    // payment means the entitlement half is settled, but the document half may
    // have failed the first time (redis down at exactly that moment), and
    // issueDocument is idempotent per payment id, so a retry can only ever
    // repair, never duplicate.
    if (payment && payment.status === 'paid' &&
        (outcome.result === 'granted' ||
         (outcome.result === 'ignored' && outcome.reason === 'already_processed'))) {
      await _issueInvoiceForPayment(payment, outcome);
    }
    // Money going back. An issued invoice may not be withdrawn, so the document
    // for it is a CREDIT NOTE with its own number in its own series, referring
    // to the invoice it credits (lib/credit-note.js).
    //
    // Not gated on outcome.result. A chargeback revokes the entitlement and a
    // refund does not, but both are money the customer no longer paid, and both
    // need the document. A partial refund arrives as a still-'paid' payment
    // with amountRefunded set, which no outcome would ever have caught.
    if (creditNote.isReversal(payment) && redisClient && redisClient.isReady) {
      const credit = await _creditNoteForPayment(payment);
      // The marker on the invoice, and only when the WHOLE invoice went back: a
      // partly refunded invoice is still partly true, and stamping it reversed
      // would say the opposite. The credit note is the record either way.
      if (credit && credit.fully_credited) {
        const rev = await invoiceMod.recordReversal({ payment }, redisClient);
        if (rev.result === 'reversed') log('warn', 'billing_invoice_reversed', { payment_id: paymentId, number: rev.number });
      }
    } else if (outcome.result === 'revoked' && redisClient && redisClient.isReady) {
      // A revoke we could not read an amount for. The marker is still the
      // honest minimum: the record must not keep claiming money that went back.
      const rev = await invoiceMod.recordReversal({ payment }, redisClient);
      if (rev.result === 'reversed') log('warn', 'billing_invoice_reversed', { payment_id: paymentId, number: rev.number });
    }
    // Monitoring: log every webhook with payment-id, status and outcome. The
    // 'error' level marks the alert cases (paid but no entitlement: amount
    // mismatch, missing metadata, or a grant that failed).
    log(outcome.level || 'info', 'billing_webhook', {
      payment_id: paymentId, status: payment && payment.status,
      result: outcome.result, account: outcome.account ? String(outcome.account).slice(0, 12) : undefined,
      product: outcome.product, reason: outcome.reason,
    });
    res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(J({ ok: true }));
  }

  // ── GET /v2/billing/invoices: this account's documents (authenticated) ────
  // Every document ever issued to this account, newest first, read from the
  // append-only per-account list. Never another account's: listFor re-checks
  // account_id on each record it loads, so a shared or leaked number still
  // yields nothing here.
  if (path === '/v2/billing/invoices' && req.method === 'GET') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invoices_unavailable' }));
    }
    const accountId = acctOf(apiKey);
    const records = await invoiceMod.listFor(accountId, redisClient);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true,
      // The listing carries no seller/buyer blocks: the account page shows a
      // row per document and the PDF is the document. Less to leak, less to
      // keep in step.
      invoices: records.map(r => ({
        number: r.number, kind: r.kind, date: r.invoice_date, description: r.description,
        currency: r.currency, amount_net: r.amount_net, amount_vat: r.amount_vat,
        amount_gross: r.amount_gross, vat_rate: r.vat_rate,
        reversed_at: r.reversed_at || null,
        // Credit notes ride in the same list, in the same order the customer's
        // documents happened. These four fields are what tells the page a row
        // is money going back and which invoice it belongs to.
        credit_for: r.credit_for || null,
        reason: r.kind === 'credit_note' ? (r.reason || null) : null,
        partial: r.kind === 'credit_note' ? !!r.partial : false,
        credit_notes: r.credit_notes || null,
        pdf_url: `/v2/billing/invoices/${r.number}.pdf`,
      })),
    }));
  }

  // ── GET /v2/billing/history: one chronological list (authenticated) ──────
  // Derived, never stored: the invoice and credit-note records for the money,
  // and the paid periods on those same records (cross-read against the
  // plan-expiry index) for the terms that ended. See lib/billing-history.js for
  // why a period end is not simply a date in the past.
  if (path === '/v2/billing/history' && req.method === 'GET') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'history_unavailable' }));
    }
    const history = await billingHistory.build({ accountId: acctOf(apiKey), redis: redisClient, now: new Date() });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, history }));
  }

  // -- POST /v2/billing/redeem: spend a gift code (authenticated) -------------
  // The one path to a paid tier that involves no money. It is deliberately NOT
  // a checkout with a 100% discount: nothing reaches Mollie, no invoice number
  // is drawn, and nothing lands in the books as revenue, because nothing was
  // sold. What it shares with a payment is the half the customer cares about,
  // and it shares it by calling the SAME setProductPlan the webhook calls, so
  // the entitlement layer, the expiry index and the reminder mails see an
  // ordinary paid term and need no special case for a gift.
  //
  // Reachable on a pst_ session token with purpose `app` (lib/session-token.js
  // APP_SCOPE), because the two pages carrying the field hold no api-key. The
  // ACCOUNT IS THE ONE THE RELAY RESOLVED, never one the body names: a code is
  // spent on the caller's own account or not at all.
  if (path === '/v2/billing/redeem' && req.method === 'POST') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'redeem_unavailable', message: coupon.MESSAGES.no_redis }));
    }
    let body;
    try { body = JSON.parse((await readBody(req, 512)).toString() || '{}'); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_json' })); }
    const accountId = acctOf(apiKey);

    // The seat is taken FIRST, atomically, and given back below if the grant
    // that should follow it does not happen. The other order lets the hundred
    // and first request be granted while the cap is being read.
    let claim;
    try { claim = await coupon.claim(redisClient, { code: body && body.code, accountId, now: new Date() }); }
    catch (e) {
      if (redisOutage503(e, res)) return;
      log('warn', 'coupon_claim_failed', { account: String(accountId).slice(0, 12), err: e.message });
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'redeem_unavailable', message: coupon.MESSAGES.no_redis }));
    }
    if (!claim.ok) {
      // 409 for a code that exists and cannot be spent (run out, already used,
      // expired, withdrawn), 404 for one we have never heard of. Both carry the
      // plain sentence the page prints; the machine-readable error is for logs
      // and tests, never for the reader.
      const status = claim.error === 'unknown' || claim.error === 'bad_code' ? 404 : 409;
      log('info', 'coupon_refused', { account: String(accountId).slice(0, 12), reason: claim.error });
      res.writeHead(status, { 'Content-Type': 'application/json' });
      return res.end(J({ error: claim.error, message: coupon.messageFor(claim.error) }));
    }

    // Rule 3 (lib/coupon.js): the gift is ADDED to a term that is still
    // running, never substituted for it. grantEnd is billing.extendFrom plus
    // the days, so paying customers keep every day they bought.
    const rec = entitlementRecordOf(accountId) || {};
    // ONE instant for the whole redemption. Reading the clock per product gives
    // the two halves of a single gift dates a millisecond apart, which is a lie
    // on /account and a needless second entry in the expiry index.
    const at = new Date();
    const granted = [];
    let failure = null;
    for (const g of claim.grants) {
      const current = rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[g.product]] || null;
      const ends = coupon.grantEnd(current, at, g.days);
      let out;
      // null, not undefined: a gift is not a Firm purchase, so any bundle
      // marker from an earlier Firm term goes with the term it belonged to.
      // Leaving it would make the expiry mail call a gifted month a Firm plan.
      try { out = setProductPlan(accountId, g.product, g.tier, ends, null); }
      catch (e) { out = { ok: false, reason: e.message }; }
      if (!out || !out.ok) { failure = (out && out.reason) || 'not_applied'; break; }
      granted.push({ product: g.product, tier: out.tier, days: g.days, ends: ends.toISOString() });
    }
    if (failure) {
      // Nothing half-given: the seat goes back so the code is not silently one
      // shorter than the cap says, and the reader is told to try again.
      await coupon.release(redisClient, claim.code, accountId);
      log('error', 'coupon_grant_failed', { account: String(accountId).slice(0, 12), code: claim.code, reason: failure });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'grant_failed', message: coupon.MESSAGES.grant_failed }));
    }

    // The line on /account. Written after the term is really on the account, so
    // a row here always has a term behind it, and written to its own store
    // because no invoice series may hold a document for a thing that was given.
    const redeemedAt = at.toISOString();
    await billingHistory.recordGift(redisClient, accountId, {
      code: claim.code,
      label: coupon.historyLabel(claim.code, claim.grants),
      grants: granted,
      redeemed_at: redeemedAt,
    });

    // One mail, on the existing route. Not an invoice and not a receipt: there
    // is nothing to put a number on.
    const to = (rec && rec.email) || (accounts.get(accountId) || {}).email || '';
    if (to) {
      const msg = coupon.redeemMail({
        code: claim.code,
        grants: granted.map((g) => ({ ...g, ends: g.ends })),
        siteUrl: process.env.SITE_URL || planExpiry.DEFAULT_SITE_URL,
      });
      if (msg) {
        Promise.resolve(sendResendEmail({ to, subject: msg.subject, text: msg.text, html: msg.html }))
          .catch((e) => log('warn', 'coupon_mail_failed', { err: e.message }));
      }
    }

    log('info', 'coupon_redeemed', {
      account: String(accountId).slice(0, 12), code: claim.code, used: claim.used,
      products: granted.map((g) => `${g.product}:${g.tier}`).join(','),
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true,
      code: claim.code,
      granted,
      // The sentence the page prints. Built here so the mail, the history line
      // and the page all name the same plans and the same dates.
      message: coupon.successMessage(granted),
    }));
  }

  // ── GET /v2/billing/invoices/:number.pdf: one document (authenticated) ────
  // Rendered on demand from the stored record rather than kept as a blob: the
  // record is the thing that must survive seven years, and a layout change then
  // reprints every old document unchanged in content.
  if (path.startsWith('/v2/billing/invoices/') && req.method === 'GET') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    const number = decodeURIComponent(path.slice('/v2/billing/invoices/'.length)).replace(/\.pdf$/i, '');
    // Both series: PS for what was charged, CN for what was credited back. They
    // share one document keyspace and one per-account list, so a credit note is
    // downloaded by the same route that serves the invoice it credits.
    if (!invoiceMod.parseDocumentNumber(number)) {
      res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_invoice_number' }));
    }
    if (!redisClient || !redisClient.isReady) {
      res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'invoices_unavailable' }));
    }
    const record = await invoiceMod.getFor(acctOf(apiKey), number, redisClient);
    if (!record) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
    let pdf;
    try { pdf = invoicePdf.render(record, { buyerHint: invoiceMod.BUYER_HINT }); }
    catch (e) {
      log('error', 'billing_invoice_pdf_failed', { number, err: e.message });
      res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'render_failed' }));
    }
    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Length': pdf.length,
      'Content-Disposition': `attachment; filename="${number}.pdf"`,
      'Cache-Control': 'private, no-store',
    });
    return res.end(pdf);
  }

  // ── GET/POST /v2/billing/profile: the customer half of an invoice ─────────
  // Company name, address and VAT id, all optional. Without them a document is
  // still valid as a receipt to the email address on the account, and says on
  // its face how to get the company details onto the next one.
  if (path === '/v2/billing/profile' && (req.method === 'GET' || req.method === 'POST')) {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    const accountId = acctOf(apiKey);
    if (req.method === 'POST') {
      let body;
      try { body = JSON.parse((await readBody(req, 4096)).toString() || '{}'); }
      catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_json' })); }
      // Trimmed and length-capped, and nothing else: these strings are printed
      // on a PDF and mailed, never interpolated into markup or a query.
      const clean = (v, max) => String(v == null ? '' : v).replace(/\r/g, '').trim().slice(0, max);
      const profile = {
        company: clean(body.company, 120),
        address: clean(body.address, 300),
        vat: clean(body.vat, 40),
      };
      if (profile.address.split('\n').length > 6) {
        res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'address_too_many_lines' }));
      }
      const saved = await _setBillingProfile(accountId, profile);
      if (!saved.ok) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'profile_unavailable' })); }
      log('info', 'billing_profile_saved', { account: String(accountId).slice(0, 12), has_company: !!profile.company, has_vat: !!profile.vat });
    }
    const buyer = await _billingBuyerOf(accountId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, email: buyer.email, company: buyer.company, address: buyer.address, vat: buyer.vat }));
  }

  // ── POST /v2/billing/cancel — stop the next collection (authenticated) ──────
  // Selling a subscription without a way to end it is not allowed in the EU, and
  // it is the first thing a buyer looks for before he buys. Cancelling stops the
  // NEXT collection only: paid_until is untouched, so the period already paid
  // for runs to its end and the tier goes with it. Anything else would be taking
  // back time that was bought.
  if (path === '/v2/billing/cancel' && req.method === 'POST') {
    let body;
    try { body = JSON.parse((await readBody(req, 1024)).toString() || '{}'); }
    catch { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'bad_json' })); }
    // TWO CALLERS. An api-key caller cancels its own account, as before. The
    // ADMIN PLANE calls with X-Internal-Auth and the session's user_id, because
    // the Cancel plan button on /account is the only cancel a customer will ever
    // use and it had no way to reach this route at all: there was no proxy, and
    // an app-scoped session token is denied this path (session-token.js). So the
    // button wrote a redis marker, mailed "cancellation scheduled", and left the
    // Mollie subscription collecting.
    const internal = _internalOk();
    const _who = internal ? (body && body.user_id) : apiKey;
    if (!internal && !keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unauthorized' })); }
    if (internal && (!_who || !apiKeys.has(_who))) {
      res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unknown_account' }));
    }
    const accountId = acctOf(_who);
    // No product named means every collection this account has: the buyer who
    // presses Cancel is cancelling his plan, not one line of it, and he cannot
    // be expected to know that a Firm subscription is a different row from a
    // ParaSign one.
    const product = body && body.product;
    if (product && !billingRecurring.subscriptionFieldOf(product)) {
      res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'unknown_product' }));
    }
    const mode = mollie.billingMode();
    const _rec0 = _billingRecordOf(accountId) || {};
    const products = product
      ? [product]
      : Object.keys(billingRecurring.PRODUCT_SUBSCRIPTION_FIELD)
        .filter((p) => !!_rec0[billingRecurring.subscriptionFieldOf(p)]);
    const results = [];
    let out = { result: 'noop', reason: 'no_subscription' };
    for (const p of (products.length ? products : [product || 'firm'])) {
      out = await billingRecurring.cancelForProduct(accountId, p, {
        mode,
        getAccount: (aid) => _billingRecordOf(aid),
        saveSubscription: (aid, pp, id) => _setMolliePointer(aid, billingRecurring.subscriptionFieldOf(pp), id),
        mollie,
      });
      results.push({ product: p, result: out.result, reason: out.reason });
      log(out.level || 'info', 'billing_cancel', {
        account: String(accountId).slice(0, 12), product: p, result: out.result, reason: out.reason, mode,
      });
      if (out.result === 'failed' || out.result === 'refused') break;
    }
    if (out.result === 'failed' || out.result === 'refused') {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'cancel_failed', reason: out.reason, results }));
    }
    // What the buyer needs to see: nothing more will be collected, and until
    // when he still has what he paid for.
    const _rec = _billingRecordOf(accountId);
    // A bundle is not an entitlement product and holds no paid_until of its own,
    // so the date the buyer keeps is the EARLIEST of the products it covers:
    // that is the day the plan he cancelled stops being whole. Reading
    // PRODUCT_PAID_UNTIL_FIELD['firm'] answered null and told a Firm customer
    // who had just cancelled that he had nothing left.
    const _untilOf = (p) => (_rec && _rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[p]]) || null;
    const _forDate = product || (results.find((r) => r.result === 'cancelled') || {}).product || 'firm';
    const _covered = (billingCatalog.BUNDLES[_forDate] || { grants: [{ product: _forDate }] }).grants
      .map((g) => _untilOf(g.product)).filter(Boolean).sort();
    const until = _covered[0] || entitlements.PRODUCTS.map((p) => _untilOf(p)).filter(Boolean).sort()[0] || null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, cancelled: results.some((r) => r.result === 'cancelled'), results, product: _forDate, access_until: until }));
  }

  // ── POST /v2/admin/keys/update-plan ─────────────────────────────────────────
  if (path === '/v2/admin/keys/update-plan' && req.method === 'POST') {
    if (!_internalOk()) return _internalReject();
    try {
      const { key, plan } = JSON.parse((await readBody(req, 1024)).toString());
      // 'business' is a first-class tier in tiers.js/entitlements; without it a
      // Business plan-change (incl. a Mollie ParaSign Business purchase) failed here.
      const VALID_PLANS = new Set(['community','dev','pro','business','licensed','enterprise']);
      if (!key || !VALID_PLANS.has(plan)) { res.writeHead(400); return res.end(J({ error: 'invalid_params' })); }
      if (!apiKeys.has(key)) { res.writeHead(404); return res.end(J({ error: 'key_not_found' })); }
      const _rec = apiKeys.get(key);
      _rec.plan = plan;
      // Re-derive the per-product plans from the new unified plan (there is no
      // per-product admin endpoint yet). An explicit admin plan change may raise
      // or lower a product tier; that is intentional, not a silent migration.
      _rec.plan_parasend = entitlements.derivePlanParasend(plan);
      _rec.plan_parasign = entitlements.derivePlanParasign(plan, _rec.parasign);
      // Keep the account's plan in step so the per-account cap re-evaluates.
      const _aid = _rec.account_id;
      if (_aid && accounts.has(_aid)) accounts.get(_aid).plan = plan;
      // Billing auto-grant: a paid Pro plan entitles the account to ParaSign /v1.
      if (PARASIGN_PAID_PLANS.has(plan)) grantParasignOnPaidPlan(_aid || key); /*MARK:parasign_billing_autograt*/
      _mutateUsersJson(ud => {
        const entry = ud.api_keys.find(k => k.key === key);
        if (entry) { entry.plan = plan; entry.plan_parasend = _rec.plan_parasend; entry.plan_parasign = _rec.plan_parasign; entry.plan_updated = new Date().toISOString(); }
        ud.updated = new Date().toISOString();
      }).catch(e => log('warn', 'plan_update_persist_failed', { err: e.message }));
      applyKeyLimitEnforcement();
      res.writeHead(200); return res.end(J({ ok: true, key, plan }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys/set-product-plan ────────────────────────────────────
  // Fine-grained sibling of /v2/admin/keys/update-plan: moves ONE product's tier
  // (plan_parasign OR plan_parasend) on the target key's account and leaves the
  // unified `plan` AND the other product untouched. Same internal-auth gate as
  // update-plan. Body { key, product, tier }. An unknown product, or a tier that
  // is not on that product's ladder, is rejected 400 (never silently floored to
  // the base tier). Delegates the account fan-out + users.json persistence to
  // setProductPlan - the exact block the Mollie webhook uses - so there is one
  // per-product entitlement path, not a second copy.
  if (path === '/v2/admin/keys/set-product-plan' && req.method === 'POST') {
    if (!_internalOk()) return _internalReject();
    try {
      const { key, product, tier } = JSON.parse((await readBody(req, 1024)).toString());
      if (!key) { res.writeHead(400); return res.end(J({ error: 'invalid_params' })); }
      const v = entitlements.validateProductPlan(product, tier);
      if (!v.ok) { res.writeHead(400); return res.end(J({ error: v.error })); }
      if (!apiKeys.has(key)) { res.writeHead(404); return res.end(J({ error: 'key_not_found' })); }
      const accountId = acctOf(key);
      // EXPLICITLY does not set the unified `plan` and does not touch the other
      // product; setProductPlan writes only plan_<product> (+ the parasign access
      // flag on a paid parasign tier).
      const out = setProductPlan(accountId, v.product, v.tier);
      if (!out.ok) { res.writeHead(422); return res.end(J({ error: out.reason || 'not_applied' })); }
      try { auditAppend(key, 'admin_product_plan_changed', { product: v.product, tier: out.tier, keys: out.keys }); } catch {}
      log('info', 'admin_product_plan_changed', { account: String(accountId).slice(0, 12), product: v.product, tier: out.tier, keys: out.keys, changed: out.changed });
      res.writeHead(200); return res.end(J({ ok: true, key, product: v.product, tier: out.tier }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  const entitlementRead = path.match(/^\/v2\/admin\/entitlements\/([^/]+)$/);
  if (entitlementRead && req.method === 'GET') {
    if (!_internalOk()) return _internalReject();
    let requested;
    try { requested = decodeURIComponent(entitlementRead[1]); }
    catch { res.writeHead(400); return res.end(J({ error: 'invalid_account_id' })); }
    const accountId = apiKeys.has(requested) ? acctOf(requested) : requested;
    if (!accounts.has(accountId) && !accountKeys.has(accountId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'account_not_found' }));
    }
    const record = entitlementRecordOf(accountId);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(J({ ok: true, account_id: accountId, entitlements: entitlements.getEntitlements(record) }));
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
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(400); return res.end(J({ error: e.message })); }
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
    } catch (e) { if (redisOutage503(e, res)) return; res.writeHead(500); return res.end(J({ error: e.message })); }
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
      // Display only, no limit hangs off it. The unified plan stays the value
      // of this long-standing field so nothing reading it breaks, but the
      // default was the generous one (a key with no plan on file reported
      // itself as pro), and the tier the stats beside it are actually measured
      // against now travels alongside.
      plan:            kd.plan || 'community',
      parasend_tier:   parasendLimitsOf(kd).tier,
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
  // DEAD CODE (retained for reference only; guarded by `&& false`). This is the
  // legacy R017 notary body. It held the ONLY gateSign/recordSign call in the
  // relay, which is why signatures went uncounted for so long: the live signing
  // path is POST /v2/envelopes/:id/sign (R018), which now meters signs itself.
  // Do NOT re-enable without moving the metering; kept only to document history.
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
        // ParaSign entitlement: signs_month for this account's plan_parasign
        // (independent of the ParaSend transfers quota). Separate counter key.
        const _psign  = entitlements.getEntitlements(keyData).parasign;
        const _sLimit = _psign.quotas.signs_month;
        const _sGate  = await quota.gateSign(redisClient, keyData.account_id, _sLimit, log);
        if (!_sGate.allowed) {
          // The tier that DECIDED, as on the transfer gate: the unified plan
          // does not move on a ParaSign purchase either, so reporting it here
          // tells a paying customer he is on a tier he is not being held to.
          log('info', 'quota_sign_declined', { account: String(keyData.account_id).slice(0, 12), plan: _psign.tier, limit: _sLimit });
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'monthly_sign_quota_reached', dimension: 'signs_month', plan: _psign.tier, limit: _sLimit }));
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
      if (redisOutage503(e, res)) return;
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
    if (!(await envCreateRateOkShared(apiKey))) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '3600' }); return res.end(J({ error: 'Envelope creation quota exceeded for this key (50/hour).' })); }
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
      const out = await store.create({ creatorPkHash, creatorApiKeyHash: creatorApiHash, accountId: acctOf(apiKey), docHash, parties, originalFilename: origFilename, expiresInDays: ttlDays, bindingMode: d.binding_mode, recipeVersion: d.recipe_version, requestedAppearance: d.requested_appearance });
      log('info', 'envelope_created', { id: out.id, parties: out.party_count, binding_mode: out.binding_mode });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, envelope: out }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // POST /v2/envelopes/:id/document -- creator uploads the browser-encrypted
  // document capsule. The relay stores ciphertext only. Authorization is the
  // envelope creator's account, resolved from its API key.
  const envDocumentMatch = path.match(/^\/v2\/envelopes\/([A-Za-z0-9_-]{20,64})\/document$/);
  if (envDocumentMatch && req.method === 'POST') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required (X-Api-Key)' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    const maxCapsule = MAX_BLOB + 8192;
    const declared = parseInt(req.headers['content-length'] || '0', 10);
    if (declared > maxCapsule) { res.writeHead(413, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'document_too_large', max_bytes: MAX_BLOB })); }
    try {
      const capsule = await readBody(req, maxCapsule);
      const capsuleSha256 = (req.headers['x-capsule-sha256'] || '').toString().trim().toLowerCase();
      const out = await store.putDocumentCapsule(envDocumentMatch[1], acctOf(apiKey), capsule, capsuleSha256);
      if (!out.ok) {
        const status = out.code === 'not_owner' ? 403 : out.code === 'hash_mismatch' ? 400 : out.code === 'expired' ? 410 : 404;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        return res.end(J({ error: out.code }));
      }
      log('info', 'envelope_document_stored', { id: envDocumentMatch[1], bytes: out.size });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, sha256: out.sha256, size: out.size, expires_in: out.expires_in }));
    } catch (e) {
      const tooLarge = /too large/i.test(e.message || '');
      res.writeHead(tooLarge ? 413 : 400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: tooLarge ? 'document_too_large' : e.message, max_bytes: MAX_BLOB }));
    }
  }

  // GET /v2/envelopes/:id/document -- ciphertext read requires both the invite
  // capability and an internal assertion of the authenticated recipient email.
  // A copied or intercepted link alone is therefore insufficient.
  if (envDocumentMatch && req.method === 'GET') {
    if (!_internalOk()) return _internalReject();
    if (!envViewRateOk(clientIp)) { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' }); return res.end(J({ error: 'Too many requests' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    const pi = parseInt(Array.isArray(query.p) ? query.p[0] : query.p, 10);
    const token = (Array.isArray(query.t) ? query.t[0] : query.t || '').toString();
    const verifiedEmailHash = (req.headers['x-verified-email-hash'] || '').toString().trim().toLowerCase();
    try {
      const out = await store.getDocumentCapsule(envDocumentMatch[1], pi, token, verifiedEmailHash);
      if (!out.ok) {
        const status = out.code === 'not_authorized' ? 403 : out.code === 'invite_expired' || out.code === 'voided' ? 410 : 404;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        return res.end(J({ error: out.code }));
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': out.capsule.length,
        'Cache-Control': 'private, no-store',
        'X-Capsule-Sha256': out.sha256,
      });
      return res.end(out.capsule);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'internal' }));
    }
  }

  // GET /v2/envelopes/:id/owner-check -- narrow account-ownership proof for
  // authenticated services that send invitations. It reveals no envelope data.
  const envOwnerMatch = path.match(/^\/v2\/envelopes\/([A-Za-z0-9_-]{20,64})\/owner-check$/);
  if (envOwnerMatch && req.method === 'GET') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required (X-Api-Key)' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
    try {
      if (!(await store.isOwner(envOwnerMatch[1], acctOf(apiKey)))) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'not_found' }));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true }));
    } catch {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(J({ error: 'store_unavailable' }));
    }
  }

  // Account-owner actions for envelopes created from the signed-in web app.
  // These v2 envelopes use the account's pgp_ key, so the psk_-only /v1
  // receipt and void routes cannot serve the dashboard. Ownership is checked
  // against the durable account_id before state or evidence is returned.
  const envCancelMatch = path.match(/^\/v2\/envelopes\/([A-Za-z0-9_-]{20,64})\/cancel$/);
  if (envCancelMatch && req.method === 'POST') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'store_unavailable' })); }
    try {
      if (!(await store.isOwner(envCancelMatch[1], acctOf(apiKey)))) {
        res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' }));
      }
      const out = await store.voidEnvelope(envCancelMatch[1], 'Cancelled by the account owner');
      if (!out.ok) {
        const status = out.code === 'already_complete' ? 409 : out.code === 'not_found' ? 404 : 409;
        res.writeHead(status, { 'Content-Type': 'application/json' }); return res.end(J({ error: out.code }));
      }
      try { await store.deleteDocumentCapsule(envCancelMatch[1]); } catch {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, id: envCancelMatch[1], status: 'void', voided_at: out.voided_at || null }));
    } catch {
      res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'store_unavailable' }));
    }
  }

  const envReceiptMatch = path.match(/^\/v2\/envelopes\/([A-Za-z0-9_-]{20,64})\/receipt$/);
  if (envReceiptMatch && req.method === 'GET') {
    if (!keyData) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'API key required' })); }
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'store_unavailable' })); }
    try {
      if (!(await store.isOwner(envReceiptMatch[1], acctOf(apiKey)))) {
        res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' }));
      }
      const env = await store.getForReceipt(envReceiptMatch[1]);
      if (!env) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
      if (env.status !== 'complete') { res.writeHead(409, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_ready' })); }
      if (!mlDsa || !relayIdentity) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'notary_unavailable' })); }
      const psign = parasignOpenApi.buildEnvelopePsign({
        env, meta: null, canonicalJSON: parasign.canonicalJSON,
        sigEngine: registry.getSig(0x0002), relayIdentity,
        publicOrigin: process.env.PUBLIC_ORIGIN || 'https://paramant.app',
      });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="Paramant-${envReceiptMatch[1]}.psign"`,
        'Cache-Control': 'private, no-store',
      });
      return res.end(J(psign));
    } catch {
      res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'receipt_failed' }));
    }
  }

  // Participant receipt for the signed-in web flow. Internal-auth plus the
  // invite capability and verified email hash are all required. This lets a
  // recipient save the final proof without exposing the owner-only endpoint.
  const envParticipantReceiptMatch = path.match(/^\/v2\/envelopes\/([A-Za-z0-9_-]{20,64})\/participant-receipt$/);
  if (envParticipantReceiptMatch && req.method === 'GET') {
    if (!_internalOk()) return _internalReject();
    const store = _envStore();
    if (!store) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'store_unavailable' })); }
    const partyIndex = parseInt(Array.isArray(query.p) ? query.p[0] : query.p, 10);
    const token = (Array.isArray(query.t) ? query.t[0] : query.t || '').toString();
    const verifiedEmailHash = (req.headers['x-verified-email-hash'] || '').toString();
    try {
      const party = await store.getForParty(envParticipantReceiptMatch[1], partyIndex, token);
      if (!party || !envelopeMod.safeHexEqual(party.party.email_hash, verifiedEmailHash)) {
        res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' }));
      }
      const env = await store.getForReceipt(envParticipantReceiptMatch[1]);
      if (!env) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
      if (env.status !== 'complete') { res.writeHead(409, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_ready' })); }
      if (!mlDsa || !relayIdentity) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'notary_unavailable' })); }
      const psign = parasignOpenApi.buildEnvelopePsign({
        env, meta: null, canonicalJSON: parasign.canonicalJSON,
        sigEngine: registry.getSig(0x0002), relayIdentity,
        publicOrigin: process.env.PUBLIC_ORIGIN || 'https://paramant.app',
      });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="Paramant-${envParticipantReceiptMatch[1]}.psign"`,
        'Cache-Control': 'private, no-store',
      });
      return res.end(J(psign));
    } catch {
      res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'receipt_failed' }));
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
      : (v >= 5
        ? 'sha3_256("paramant/parasign/doc/v1" || 0x00 || envelope.id || doc_hash || party_index_as_decimal || party_email_hash_bytes || signer_public_key_bytes || appearance_hash_bytes)'
        : v >= 3
          ? 'sha3_256("paramant/parasign/doc/v1" || 0x00 || envelope.id || doc_hash || party_index_as_decimal || party_email_hash_bytes)'
          : v >= 2
            ? 'sha3_256(envelope.id || doc_hash || party_index_as_decimal || party_email_hash_bytes)'
            : 'sha3_256(envelope.id || doc_hash || party_index_as_decimal)');
    try {
      // ?p=<i>&t=<invite_token> -> party-scoped view. The token must match in
      // every binding mode (getForParty returns null otherwise, as a plain 404).
      // This gives the co-signer exactly what it needs to recompute the
      // (possibly v2) sign-message locally, and gives a passer-by nothing.
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
      // The per-party invite token must match before we record a view, in every
      // binding mode; getForParty returns null on a bad or absent token. A view
      // is written into the CT log as evidence of when a party opened the
      // document, so an unauthenticated stamp on someone else's slot is a
      // falsified record, not a cosmetic one.
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
      // The per-party invite capability. Open-mode slots have no mailbox to bind
      // to, so this token is what proves the submitter is the party whose slot
      // this is; the store refuses an open slot without it.
      const inviteToken = (d.token || d.invite_token || '').toString();
      // Email-bound envelopes (R018): the store accepts the signature only when
      // a trusted internal caller (the admin proxy, which verified the signer's
      // authenticated session email) asserts a matching verified_email_hash.
      // _internalOk() gates that trust on the X-Internal-Auth header; a public
      // caller cannot set it, so it can never satisfy an email-bound slot. Read
      // here rather than at the call, because it also decides whether the
      // account_id in the body may be believed at all (see below).
      const internalTrusted = _internalOk();
      const verifiedEmailHash = (d.verified_email_hash || '').toString();
      if (!Number.isInteger(pi) || pi < 0 || !signerPub || !sig) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'party_index, signer_public_key, signature required' }));
      }

      // ── WHOSE METER RUNS, and where that answer comes from ──────────────────
      // It used to come straight out of the body (`d.account_id`), and every
      // quota decision below sat inside `if (accountId)`. Leaving the field out
      // therefore skipped the pre-gate AND the increment, while the signature was
      // accepted all the same: unlimited signing on a plan that sells two a
      // month. Absence was read as permission.
      //
      // The account is now resolved server-side, and absence is a refusal:
      //   1. an internal-auth caller (the admin proxy) may name the SIGNER's
      //      account -- that is the claim the enrolled-key pin below verifies;
      //   2. otherwise the envelope's OWN stored account_id, written at create()
      //      from the creating API key and not writable from any request;
      //   3. neither -> 403. A signature that no account answers for is refused
      //      rather than waved through.
      // A public caller naming account_id is ignored outright, so the body can no
      // longer steer whose meter runs, nor drain a stranger's quota.
      const claimedAccountId = internalTrusted ? (d.account_id || '').toString() : '';
      let ownerAccountId;
      try { ownerAccountId = await store.ownerAccountId(id); }
      catch (e) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'Envelope store unavailable' })); }
      // No record at all stays a plain 404, exactly as before: the account rule
      // must not turn into an oracle for which envelope ids exist.
      if (ownerAccountId === null) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'not_found' })); }
      const accountId = claimedAccountId || ownerAccountId;
      if (!accountId) {
        log('warn', 'sign_no_account', { envelope: String(id).slice(0, 10) });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(J({ error: 'account_required' }));
      }

      // Crypto M1: when the trusted admin proxy names the signer's account_id,
      // pin the submitted key to that account's ENROLLED active signing keys.
      // The email-binding check proves *which mailbox*; this proves the signature
      // was made by a key the account actually enrolled — so a leaked internal
      // token can't fill an email-bound slot with an attacker-substituted key.
      // Fail-closed (Redis is already a hard dependency of the envelope store).
      // Only the CLAIMED account is pinned: the envelope owner is the party being
      // billed, not the party holding the pen, and open-mode signers enrol no
      // keys with us at all.
      if (claimedAccountId) {
        try {
          const active = await userSigning.getActiveSigningPks(redisClient, claimedAccountId);
          const subj = Buffer.from(signerPub, 'base64');
          const enrolled = active.some(e => {
            try { return Buffer.from(e.pk_b64, 'base64').equals(subj); } catch { return false; }
          });
          if (!enrolled) { res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signer_not_enrolled' })); }
        } catch (e) {
          res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end(J({ error: 'signer_not_enrolled' }));
        }
      }
      // ── Signs-quota enforcement (was NEVER counted) ─────────────────────────
      // This R018 route is the ONE active signing path (POST /v2/sign is retired,
      // and the only gateSign/recordSign lived in a dead `&& false` block below).
      // So no signature was ever metered: the dashboard signs-counter never moved
      // and a plan's monthly signs_month cap was unenforceable. We meter the
      // SIGNER's account (the account the enrolled key belongs to, named by the
      // admin proxy as account_id). Pre-gate is READ-ONLY (a bare usage read) so
      // an invalid signature that store.sign() will reject is never counted; the
      // increment happens AFTER, and ONLY for a genuinely NEW signature, so an
      // idempotent retry ('idem') never double-counts. Fail-open on redis trouble
      // or an unknown account: a signer is never blocked by infra.
      const _signerPlan = (accounts.get(accountId) && accounts.get(accountId).plan)
        || (apiKeys.get(accountId) && apiKeys.get(accountId).plan) || 'community';
      // Signs limit from ENTITLEMENTS (plan_parasign, legacy-plan fallback), the
      // per-product ParaSign tier -- never the product-blind tiers.js helpers.
      // Tier behaviour: every tier blocks AT its included quota.
      //   free      2 included, blocks at 2
      //   pro       100 included, blocks at 100
      //   business  1000 included, blocks at 1000
      //   enterprise config ceiling, unchanged
      // Pro used to meter past 100 at EUR 0.40 a signature up to 1000. No
      // billing line ever collected that money, so the meter was a promise the
      // kassa could not keep; it is gone, here and on the site.
      // The block decision itself is quota.signGateDecision, shared with the
      // /v1 create gate so both paths can never diverge.
      // entitlementRecordOf merges the accounts summary with the per-product
      // plans on the account's keys; reading `accounts` alone hid paid upgrades.
      const _signerRec = entitlementRecordOf(accountId) || { plan: _signerPlan };
      const _signEnt = entitlements.getEntitlements(_signerRec).parasign;
      const _signIncluded = _signEnt.quotas.signs_month;
      let _signUsed = null;      // count this month, feeds the 200 quota field
      let _signReserved = false; // this request took a slot and owes a release if the signature does not land
      // No `accountId &&` here on purpose: the account is resolved above and an
      // absent one already returned 403, so this gate can no longer be skipped by
      // leaving a field out of the request.
      //
      // The gate DECIDES AND COUNTS in one redis round trip (quota.gateSign, one
      // Lua script). It used to read the count here, decide here, and increment
      // 38 lines below, past a whole ML-DSA verification: ten requests that
      // arrived together all read the same number, all found room, and all
      // signed. See the 2026-09-05 review, finding 8.
      //
      // Counting first costs one thing, and it is paid back below: a signature
      // the store then rejects, or an idempotent retry, has taken a slot it did
      // not use, so both release it. That is the same reservation shape
      // lib/coupon.js uses for a seat.
      //
      // The rule itself is still quota.signGateDecision's `used >= included`; the
      // Lua enforces the same comparison, and quota-gate.test.js holds the two to
      // each other at the boundary so the /v1 create gate cannot drift from this
      // one.
      if (Number.isFinite(_signIncluded)) {
        const _g = await quota.gateSign(redisClient, accountId, _signIncluded, log);
        if (!_g.allowed) {
          log('info', 'quota_sign_declined', { account: String(accountId).slice(0, 12), plan: _signEnt.tier, reason: 'quota', limit: _signIncluded, used: _g.used });
          res.writeHead(402, { 'Content-Type': 'application/json' });
          return res.end(J({ error: 'monthly_sign_quota_reached', dimension: 'signs_month',
            plan: _signEnt.tier, limit: _signIncluded, used: _g.used,
            reset_date: quota.nextResetDate() }));
        }
        _signReserved = _g.counted;
        if (Number.isFinite(_g.used)) _signUsed = _g.used;
      }

      const out = await store.sign(id, pi, signerPub, sig, {
        internalTrusted,
        verifiedEmailHash,
        inviteToken,
        appearance: d.appearance,
      });
      if (!out.ok) {
        // The slot was taken before the store had its say. The signature did not
        // land, so the month does not owe it.
        if (_signReserved) await quota.releaseSign(redisClient, accountId, log);
        const code = out.code === 'not_found' ? 404
          : (out.code === 'bad_signature' || out.code === 'invalid_appearance') ? 400
          : (out.code === 'closed' || out.code === 'voided' || out.code === 'invite_expired') ? 410
          : (out.code === 'email_binding_required' || out.code === 'email_mismatch'
             || out.code === 'invite_token_required') ? 403
          : 409;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        return res.end(J({ error: out.code }));
      }

      // Exactly one signature is counted per NEW accepted party-signature
      // (signs_month is a signature counter, so multi-party envelopes count per
      // party). The count was already taken by the gate above, so all that is
      // left here is the retry case: an 'idem' answer means this signature was
      // already counted the first time round, and the slot this request reserved
      // has to go back or a client that retries pays twice for one signature.
      if (out.code !== 'new' && _signReserved) {
        const _rel = await quota.releaseSign(redisClient, accountId, log);
        if (Number.isFinite(_rel.used)) _signUsed = _rel.used;
        _signReserved = false;
      }
      // A path that reserved a slot and neither released it nor signed would
      // leak a unit a month. There is no such path: every return between the
      // gate and here releases first, and the only remaining exits are this
      // 200 and the throw that the outer handler turns into a 500 (where a lost
      // unit is the safe direction and the month self-heals on the 1st).

      // ── Completion webhooks (were never fired from the sign path) ───────────
      // envelope.sent/.voided already fire from the /v1 router; the sign path (in
      // relay.js) is where a signature actually lands, so signer.completed and
      // envelope.completed must originate HERE. emitEvent reads the per-envelope
      // webhook target from the same durable store; it no-ops for non-/v1
      // envelopes (no meta record) and is HMAC-SHA256 signed like the others.
      // Fire-and-forget so a slow/broken webhook never delays the signer's 200.
      if (out.code === 'new') {
        const _pdeps = { store: _parasignStore(), safeHttpsRequest, J, log };
        parasignOpenApi.emitEvent(_pdeps, id, 'signer.completed', {
          party_index: pi, signed_count: out.signed_count, party_count: out.party_count,
        });
        if (out.status === 'complete') {
          parasignOpenApi.emitEvent(_pdeps, id, 'envelope.completed', {
            status: 'completed', signed_count: out.signed_count, party_count: out.party_count,
          });
        }
      }

      // API contract with the dashboard: every successful sign response carries
      // a `quota` field so the frontend can render usage without a second call.
      // Two numbers, because there are only two: what this account has signed
      // this month and what its tier includes. Omitted entirely when redis could
      // not be read (fail-open, the field is best-effort). There is always an
      // account by this point; a request without one never got here.
      const _quotaField = (_signUsed != null && Number.isFinite(_signIncluded)) ? {
        used: _signUsed,
        included: _signIncluded,
        reset_date: quota.nextResetDate(),
      } : null;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, idempotent: out.code === 'idem', signed_count: out.signed_count, party_count: out.party_count, status: out.status,
        signed_at: out.signed_at, appearance: out.appearance, appearance_hash: out.appearance_hash,
        ...(_quotaField ? { quota: _quotaField } : {}) }));
    } catch (e) {
      if (redisOutage503(e, res)) return;
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(J({ error: e.message }));
    }
  }

  // ── POST /v2/verify-receipt — Verify a signed delivery receipt ───────────────
  // Verifies the ML-DSA-65 signature and re-walks the inclusion proof.
  // Receipt must be base64url-encoded JSON, as returned by
  // GET /v2/transfers/:receipt_id/receipt (before 2026-09, the X-Paramant-Receipt header).
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
}

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

// ── Paid-term reminders ──────────────────────────────────────────────────────
// The one thing standing between a customer and a plan that stops without a
// word. There is no cron on the server, so the schedule lives here: one sweep a
// short random delay after boot, then every six hours. Five relay containers
// run this same line against one redis, and a SET NX lock in lib/plan-expiry
// means exactly one of them does the work each window. Nothing about "already
// warned him" is held in this process: the markers are redis keys carrying the
// paid_until they belong to, so a restart, a redeploy and a second container
// all send zero extra mail.
//
// The seed is what makes the index complete. Accounts live in users.json, per
// container; every container puts what it knows into the shared index once at
// boot, so an account that paid before this existed is still warned.
//
// PLAN_EXPIRY_BOOT_DELAY_MS shortens the boot delay. It exists so a test can
// watch the one thing this planner promises the customer -- the mail seven days
// before his term ends -- inside a test run instead of waiting the production
// 30 to 60 seconds. Unset (production) the delay is unchanged.
const _expiryBootDelay = parseInt(process.env.PLAN_EXPIRY_BOOT_DELAY_MS || '', 10);
planExpiry.startPlanExpiryPlanner({
  redis: redisClient,
  sendEmail: ({ to, subject, text, html }) => sendResendEmail({ to, subject, text, html }),
  log,
  siteUrl: process.env.SITE_URL || planExpiry.DEFAULT_SITE_URL,
  seed: () => planExpiry.seedIndex(redisClient, accountsWithTerms()),
  ...(Number.isFinite(_expiryBootDelay) ? { bootDelayMs: _expiryBootDelay } : {}),
});

// ── Paid terms granted on another container ──────────────────────────────────
// The half of a grant that is not this container's own (lib/shared-grants). A
// term bought or redeemed on relay-main has to be true on relay-health too,
// because that is the relay the account page, the homepage figure and the
// ParaSign signature gate are all served from.
//
// Two mechanisms, on purpose. The CHANNEL is what makes it immediate: the
// customer redeems a code and reloads the page a second later, and a mechanism
// that took a minute to catch up would show him the same "Community, free for
// good" that this whole change exists to end. The RESEED is what makes it
// reliable: a container that was down for the deploy, or a subscriber whose
// socket dropped, heals on the next pass instead of staying wrong until
// somebody notices.
//
// The subscriber is its own connection because a subscribed node-redis client
// can run nothing else, and a raw one because the deadline guard on the shared
// client bounds single commands and has no business wrapping a subscription
// that is meant to stay open.
const SHARED_GRANT_RESEED_MS = 60_000;
if (redisClient && RELAY_REDIS_URL) {
  // One pass at a time. The pass reads redis once per granted account, so on a
  // large estate a slow store could otherwise start a second pass on top of the
  // first and have the two publish over each other.
  let reseeding = false;
  const seedOnce = () => {
    if (reseeding) return Promise.resolve();
    reseeding = true;
    return _reseedSharedGrants()
      .then((n) => { if (n) log('info', 'shared_grants_reseeded', { hydrated: n }); })
      .catch(e => log('warn', 'shared_grant_reseed_failed', { err: e.message }))
      .finally(() => { reseeding = false; });
  };
  // A short delay so the first pass runs after loadUsers and after the client
  // has had a chance to connect; a container with nothing to hydrate pays one
  // SMEMBERS for it.
  setTimeout(seedOnce, 2000).unref?.();
  setInterval(seedOnce, SHARED_GRANT_RESEED_MS).unref?.();

  const subscriber = createClient({ url: RELAY_REDIS_URL, ...redisDeadlines.redisClientBounds() });
  subscriber.on('error', (err) => log('warn', 'shared_grant_subscriber_error', { err: err.message }));
  subscriber.connect()
    .then(() => subscriber.subscribe(sharedGrants.CHANNEL, (message) => {
      const accountId = String(message || '').trim();
      if (!accountId) return;
      _pullSharedGrant(accountId)
        .catch(e => log('warn', 'shared_grant_pull_failed', { account: accountId.slice(0, 12), err: e.message }));
    }))
    .then(() => log('info', 'shared_grant_subscriber_ready', { channel: sharedGrants.CHANNEL }))
    .catch(e => log('warn', 'shared_grant_subscriber_failed', { err: e.message }));
}

// ── The party worklist migration ─────────────────────────────────────────────
// One run, ever, across the estate: fill the per-party envelope index for the
// envelopes created before that index existed. Same shape as the two planners
// around it (nothing in process memory, a SET NX lock so one of five containers
// does the scan), with one difference: it is a migration and not a sweep, so a
// finished run writes a redis marker and no later boot scans anything.
partyBackfill.startPartyIndexBackfill({
  redis: redisClient,
  // Its own store, not the request-scoped one. The migration reads envelope
  // hashes and writes index members: no signature is verified and no CT entry
  // is appended, so it needs neither engine, and a boot job that reached into a
  // request closure for a dependency would be a boot job that only runs once a
  // request has already happened.
  store: redisClient ? new envelopeMod.EnvelopeStore(redisClient) : null,
  log,
});

// ── Moneybird retries ────────────────────────────────────────────────────────
// The push after an invoice or a credit note is aftercare and is allowed to
// fail: Moneybird can be down, a token can expire, and neither may cost a
// customer his plan. What may NOT happen is that the document then quietly
// stays out of the books, so a failed push queues the document number and this
// sweep works through the queue every six hours. Same shape as the paid-term
// planner above and for the same reasons: nothing in process memory, a SET NX
// lock so exactly one of five containers pushes, and no timer at all when
// MONEYBIRD_TOKEN and MONEYBIRD_ADMINISTRATION_ID are unset (the default).
moneybird.startMoneybirdPlanner({
  redis: redisClient,
  env: process.env,
  renderPdf: (r) => invoicePdf.render(r, { buyerHint: invoiceMod.BUYER_HINT }),
  log,
});

// One entry per ACCOUNT, not per key: an account with three keys is one
// customer with one address. A fresh generator per call, so a seed that failed
// on an unreachable redis can be retried against a full list instead of an
// exhausted one.
function* accountsWithTerms() {
  const seenAccounts = new Set();
  for (const [key, rec] of apiKeys) {
    const accountId = (rec && rec.account_id) || key;
    if (seenAccounts.has(accountId)) continue;
    seenAccounts.add(accountId);
    const merged = entitlementRecordOf(accountId);
    if (!merged) continue;
    yield { accountId, record: { ...merged, email: rec.email || (accounts.get(accountId) || {}).email || '' } };
  }
}
server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  log('info', 'relay_started', { port: PORT, version: VERSION, sector: SECTOR, mode: RELAY_MODE,
      dsa: !!mlDsa, protocol: 'ghost-pipe-v2',
      relay_identity: relayIdentity ? relayIdentity.pk_hash.slice(0,16)+'…' : 'none' });
  // Say it once, loudly, at boot: without a key for the active billing mode
  // every checkout and every webhook fails, and the only earlier symptom was a
  // 503 on a public endpoint that nobody watches. Never log the key itself.
  //
  // The stance is the second half of that line. BILLING_MODE empty means
  // one-off payments only, as on 2026-08-08; 'live' or 'test' by hand turns on
  // customers, mandates and subscriptions. warn, not info, when it is inferred:
  // it is a legitimate stance, but one nobody has decided on yet, and the
  // decision belongs in .env at deploy time, not in a key prefix.
  {
    const _bs = mollie.billingStance();
    const _bk = mollie.apiKeyFor(_bs.mode);
    log(!_bk ? 'error' : (_bs.recurring ? 'info' : 'warn'), 'billing_config', {
      mode: _bs.mode, mode_source: _bs.source, recurring: _bs.recurring,
      key_present: !!_bk, key_prefix: _bk ? _bk.slice(0, 5) : null,
      stance: _bs.recurring
        ? `${_bs.mode}: one-off payments plus customers, mandates and subscriptions (BILLING_MODE=${_bs.mode})`
        : `${_bs.mode}: one-off payments only, no customers or subscriptions (BILLING_MODE not set)`,
    });
  }
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
