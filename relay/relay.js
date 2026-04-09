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

const VERSION    = '2.3.6';
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
const SECTOR     = process.env.SECTOR              || 'relay';

// Probeer @noble/post-quantum te laden voor ML-DSA
let mlDsa = null;
try {
  const { ml_dsa65: mlDsaLib } = require('@noble/post-quantum/ml-dsa.js');
  mlDsa = mlDsaLib || null;
  if (mlDsa) log('info', 'ml_dsa_loaded', { alg: 'ML-DSA-65 NIST FIPS 204' });
} catch(e) { log('warn', 'ml_dsa_not_available', { hint: 'npm install @noble/post-quantum' }); }

const ALLOWED = {
  ghost_pipe: ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/drop','/v2/session'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users','/v2/drop','/v2/session'],
  full:       null,
};

function modeAllows(p) {
  const a = ALLOWED[RELAY_MODE];
  return !a || a.some(x => p === x || p.startsWith(x + '/'));
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
const CT_FILE = process.env.CT_FILE || null; // opt-in only — auto-derive disabled to preserve RAM-only default

// Load persisted CT log on startup
if (CT_FILE) {
  try {
    const lines = fs.readFileSync(CT_FILE, 'utf8').split('\n').filter(l => l.trim());
    for (const line of lines) {
      try { ctLog.push(JSON.parse(line)); } catch {}
    }
    if (ctLog.length) log('info', 'ct_log_loaded', { entries: ctLog.length, file: CT_FILE });
  } catch (e) {
    if (e.code !== 'ENOENT') log('warn', 'ct_log_load_failed', { err: e.message });
  }
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
  // Persist to disk (NDJSON append — survives relay restarts)
  if (CT_FILE) {
    try { fs.appendFileSync(CT_FILE, JSON.stringify(entry) + '\n'); } catch {}
  }
  return entry;
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

function base32Decode(s) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = [];
  s = s.toUpperCase().replace(/=+$/, '');
  for (const c of s) {
    value = (value << 5) | alpha.indexOf(c);
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

function verifyTotp(token) {
  if (!TOTP_SECRET) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    if (totpCode(TOTP_SECRET, counter + i) === token) return true;
  }
  return false;
}

// ── Download tokens — one-time public download links
const downloadTokens = new Map(); // token -> { hash, key, expires_ms, used }

// Known link-preview bots — serve safe HTML placeholder, never trigger burn
const PRELOAD_BOTS = /WhatsApp|Telegram(?:Bot)?|Slackbot|Discordbot|facebookexternalhit|Twitterbot|LinkedInBot|Googlebot|bingbot|YandexBot|DuckDuckBot|ia_archiver|python-requests|python-urllib|Go-http-client/i;

function _dlConfirmPage(token, fileName, sizeStr, ttlStr) {
  // Filename not stored in relay (finding #4) — real name is in encrypted payload
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
    <div class="meta-row"><span class="meta-label">File</span><span class="meta-val">${name}</span></div>
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
const pubkeys    = new Map();  // device:key → {ecdh_pub, kyber_pub, dsa_pub, ts}
const webhooks   = new Map();  // device:key → [{url, secret}]
const auditChain = new Map();  // key → Merkle chain [{ts,event,hash,bytes,device,prev_hash,chain_hash}]

function log(level, msg, data = {}) {
  if (typeof msg === 'string')
    console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, v: VERSION, ...data }));
}

function J(o) { return JSON.stringify(o); }

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
      });
    });
    log('info', 'users_loaded', { count: apiKeys.size, sector: SECTOR });
  } catch(e) { log('warn', 'no_users_file'); }
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
  const entry = [...didRegistry.values()].find(e => e.doc.id === didStr);
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
const ALLOWED_ORIGINS = ['https://paramant.app', 'https://www.paramant.app'];
function setHeaders(res, req) {
  const origin = req?.headers?.origin || '';
  // Reflect any origin — API key is the auth. Allows browser extensions (moz-extension://, chrome-extension://) and self-hosted frontends.
  const allowOrigin = origin || '*';
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
  if (keyData?.over_limit) {
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
    const adminOk  = adminTok && adminTok === (process.env.ADMIN_TOKEN || '');
    const ram = ramStatus();
    const base = { ok: true, version: VERSION, sector: SECTOR };
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
      key_limit: EDITION === 'licensed' ? null : COMMUNITY_KEY_LIMIT,
      active_keys: [...apiKeys.values()].filter(k => k.active !== false).length };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J(adminOk ? full : base));
  }

  // ── GET /v2/check-key ───────────────────────────────────────────────────────
  if (path === '/v2/check-key') {
    const kd = apiKeys.get(apiKey);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ valid: !!(kd?.active), plan: kd?.plan || null }));
  }

  // ── GET /metrics — Prometheus metrics (voor auth gate, ADMIN_TOKEN vereist) ──
  if (path === '/metrics') {
    const adminToken = process.env.ADMIN_TOKEN || '';
    const reqToken = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (adminToken && reqToken !== adminToken) {
      res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('Unauthorized');
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
    return res.end(renderPrometheus());
  }

  // ── GET /v2/ct/log + /v2/ct/proof — publiek, geen auth ──────────────────────
  if (path === '/v2/ct/log') {
    const limit = Math.min(parseInt(query.limit || '100'), 1000);
    const from  = parseInt(query.from || '0');
    const entries = ctLog.slice(from, from + limit).map(e => ({ index: e.index, leaf_hash: e.leaf_hash, tree_hash: e.tree_hash, device_hash: e.device_hash, ts: e.ts }));
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

  // ── GET /v2/did/:did — publiek DID document resolven ─────────────────────────
  const didm0 = path.match(/^\/v2\/did\/([^/]+)$/);
  if (didm0 && req.method === 'GET') {
    const entry = [...didRegistry.values()].find(e => e.doc.id === decodeURIComponent(didm0[1]));
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
    return res.end(_dlConfirmPage(token, td.file_name, sizeStr, ttlStr));
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
    // Mark as used BEFORE sending (burn-on-read)
    td.used = true;
    const blob = entry.blob;
    blobStore.delete(td.hash);
    log('info', 'dl_token_used', { token: token.slice(0,8), hash: td.hash.slice(0,16) });
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      // Filename not stored in relay (finding #4) — receiver decrypts actual name from payload
      'Content-Disposition': (() => {
        if (!td.file_name) return 'attachment; filename="paramant-encrypted-file"';
        const safe = td.file_name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\/]/g, '_');
        const enc  = encodeURIComponent(td.file_name);
        return `attachment; filename="${safe}"; filename*=UTF-8''${enc}`;
      })(),
      'Cache-Control': 'no-store',
      'X-Burned': 'true',
      'X-Hash': td.hash,
    });
    return res.end(blob, () => { try { blob.fill(0); } catch {} });
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
    return res.end(J({ ok: true, file_name: td.file_name, file_size: td.file_size, ttl_left_s: ttl_left, used: false }));
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
    if (!tok || (tok !== (process.env.ADMIN_TOKEN || ''))) {
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

  // ── POST /v2/pubkey — Registreer pubkeys (ML-KEM + ECDH + ML-DSA optioneel) ─
  if (path === '/v2/pubkey' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({ error: 'device_id and ecdh_pub required' })); }
      if (INVITE_RE.test(d.device_id)) {
        // Store without API key suffix — readable by any party who knows the session token
        pubkeys.set(d.device_id, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', ts: new Date().toISOString(), expires: Date.now() + INVITE_PUBKEY_TTL });
        log('info', 'pubkey_registered_invite', { device: d.device_id.slice(0, 12) });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(J({ ok: true }));
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
      pubkeys.set(`${d.device_id}:${apiKey}`, {
        ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '',
        dsa_pub:  d.dsa_pub  || '',
        ts: new Date().toISOString(),
        expires: Date.now() + ttl,
      });
      log('info', 'pubkey_registered', { device: d.device_id, kyber: !!d.kyber_pub, dsa: !!d.dsa_pub, plan, ttl_days: Math.round(ttl/86400000) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, dsa_supported: !!mlDsa, ct_index: ctEntry.index, ct_tree_hash: ctEntry.tree_hash, attested: attestResult.valid, attestation_method: attestResult.method || null }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/pubkey/:device ───────────────────────────────────────────────────
  const pkm = path.match(/^\/v2\/pubkey\/([^/]+)$/);
  if (pkm && req.method === 'GET') {
    const deviceId = decodeURIComponent(pkm[1]);
    // Invite sessions: stored and retrieved without API key
    const _pkKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${apiKey}`;
    const entry = pubkeys.get(_pkKey);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'No pubkeys for this device. Start receiver first.' })); }
    if (entry.expires && Date.now() > entry.expires) {
      pubkeys.delete(_pkKey);
      res.writeHead(404); return res.end(J({ error: 'Pubkey registration expired. Re-register the device.' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, ecdh_pub: entry.ecdh_pub, kyber_pub: entry.kyber_pub, dsa_pub: entry.dsa_pub || '', ts: entry.ts }));
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
      const { hash, payload, ttl_ms, meta, dsa_signature, max_views: reqMaxViews, password } = d;

      if (!hash || !payload) { res.writeHead(400); return res.end(J({ error: 'hash and payload required' })); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({ error: 'hash must be SHA-256 hex' })); }
      if (blobStore.has(hash)) { res.writeHead(409); return res.end(J({ error: 'Hash already in use' })); }

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
      blobStore.set(hash, { blob, ts: Date.now(), ttl, size: blob.length,
        sig_valid: sigResult.valid, apiKey, max_views: maxViews, views_remaining: maxViews, pw_hash });
      setTimeout(() => {
        const e = blobStore.get(hash);
        if (e) { zeroBuffer(e.blob); blobStore.delete(hash); }
      }, ttl);

      const deviceId = meta?.device_id;
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      auditAppend(apiKey, 'inbound', { hash: hash.slice(0,16)+'...', bytes: blob.length, device: deviceId, sig: sigResult.valid ? 'ML-DSA-OK' : 'unsigned' });
      log('info', 'blob_stored', { hash: hash.slice(0,16), size: blob.length, sig: sigResult.valid });

      if (deviceId) pushWebhooks(apiKey, deviceId, 'blob_ready', { hash, size: blob.length, ttl_ms: ttl, sig_valid: sigResult.valid });
      if (global.wsPush) global.wsPush(apiKey, { hash, size: blob.length, device: deviceId, sig_valid: sigResult.valid });
      natsPush(apiKey, deviceId || 'unknown', hash, blob.length);

      // Genereer one-time download token
      const dlToken = require('crypto').randomBytes(24).toString('hex');
      downloadTokens.set(dlToken, {
        hash,
        key: apiKey,
        expires_ms: Date.now() + ttl,
        used: false,
        file_name: '',  // filename intentionally not stored in relay (finding #4)
        file_size: blob.length,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash, ttl_ms: ttl, size: blob.length, sig_verified: sigResult.valid, download_token: dlToken }));
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
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': blob.length,
      'X-Paramant-Burned': burned ? 'true' : 'false',
      'X-Paramant-Hash':   outm[1],
    });
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
    const device = query.device || ''; const seq = parseInt(query.seq || '0');
    const next = seq + 1;
    // HMAC secret = STREAM_NONCE+apiKey — non-precomputable without relay-session nonce (finding #9)
    const streamSecret = crypto.createHmac('sha256', STREAM_NONCE).update(apiKey).digest();
    const h = crypto.createHmac('sha256', streamSecret).update(`${device}|${next}`).digest('hex');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, device, seq: next, hash: h, available: blobStore.has(h) }));
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
    const deviceHash = crypto.createHash('sha3-256').update(decodeURIComponent(attm[1])).digest('hex');
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
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      const valid = verifyTotp(d.totp_code || '');
      log(valid ? 'info' : 'warn', 'mfa_attempt', { valid, ip: req.socket?.remoteAddress });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: valid, error: valid ? null : 'Invalid TOTP code' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys — Key aanmaken ────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      const newKey = (d.key && /^pgp_[0-9a-f]{32,64}$/.test(d.key)) ? d.key : 'pgp_' + crypto.randomBytes(32).toString('hex');
      const plan = d.plan || 'pro';
      const label = d.label || '';
      const email = d.email || '';
      apiKeys.set(newKey, { plan, label, active: true });
      // Persist to users.json so key survives relay restarts
      try {
        const usersData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        usersData.api_keys.push({ key: newKey, plan, label, email, active: true, created: new Date().toISOString() });
        usersData.updated = new Date().toISOString();
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
        log('info', 'key_created_via_admin', { label, plan, persisted: true });
      } catch(we) {
        log('warn', 'key_persist_failed', { err: we.message, label });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key: newKey, plan, label }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/admin/keys ────────────────────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'GET') {
    const keys = [...apiKeys.entries()].map(([k, v]) => ({
      key: k, plan: v.plan, label: v.label, active: v.active, over_limit: v.over_limit || false
    }));
    const licenseInfo = { edition: EDITION, active_keys: keys.length, key_limit: EDITION === 'licensed' ? null : COMMUNITY_KEY_LIMIT };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: keys.length, keys, license: licenseInfo }));
  }

  // ── POST /v2/admin/keys/revoke ────────────────────────────────────────────
  if (path === '/v2/admin/keys/revoke' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      if (!apiKeys.has(d.key)) { res.writeHead(404); return res.end(J({ error: 'Key not found' })); }
      apiKeys.get(d.key).active = false;
      // Persist revocation to users.json
      try {
        const usersData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const entry = usersData.api_keys.find(k => k.key === d.key);
        if (entry) { entry.active = false; entry.revoked_at = new Date().toISOString(); }
        usersData.updated = new Date().toISOString();
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
        log('info', 'key_revoked_via_admin', { key: d.key.slice(0,16), persisted: true });
      } catch(we) {
        log('warn', 'key_revoke_persist_failed', { err: we.message });
      }
      res.writeHead(200); return res.end(J({ ok: true }));
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

  // ── 404 ──────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(J({ error: 'Not found', version: VERSION, docs: 'https://paramant.app/docs',
    endpoints: ['POST /v2/pubkey','GET /v2/pubkey/:device','POST /v2/inbound',
                'GET /v2/outbound/:hash','GET /v2/status/:hash','POST /v2/webhook',
                'GET /v2/stream-next','GET /v2/audit','GET /health','GET /metrics'] }));
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
const COMMUNITY_KEY_LIMIT = parseInt(process.env.MAX_KEYS || '5');
let EDITION = 'community';

function checkLicense() {
  const fs2 = require('fs');
  const crypto2 = require('crypto');
  try {
    const checksum = crypto2.createHash('sha3-256')
      .update(fs2.readFileSync(__filename))
      .digest('hex');
    log('info', 'relay_integrity', { checksum, file: __filename });
  } catch(e) {
    log('warn', 'relay_integrity_failed', { err: e.message });
  }

  const LICENSE_KEY = process.env.PARAMANT_LICENSE || '';
  if (LICENSE_KEY) {
    // Format: plk_ + exactly 64 lowercase hex chars = 68 chars total
    const PLK_RE = /^plk_[0-9a-f]{64}$/;
    if (PLK_RE.test(LICENSE_KEY)) {
      EDITION = 'licensed';
      log('info', 'license_valid', { edition: 'licensed', key_prefix: LICENSE_KEY.slice(0, 12) + '...' });
    } else {
      log('warn', 'license_invalid', {
        hint: 'License key must be plk_ followed by exactly 64 lowercase hex characters (68 chars total)',
        length_provided: LICENSE_KEY.length,
        expected_length: 68
      });
    }
  }
  applyKeyLimitEnforcement();
}

// ── Community Edition key-limit enforcement ───────────────────────────────────
// Free self-hosters: max 5 active API keys. Keys 6+ receive 402 on every request.
// Licensed (plk_*): no limit. Set PARAMANT_LICENSE=plk_... in .env to unlock.
// ─────────────────────────────────────────────────────────────────────────────
function applyKeyLimitEnforcement() {
  if (EDITION === 'licensed') {
    // Clear any leftover flags from a previous community run
    for (const v of apiKeys.values()) v.over_limit = false;
    log('info', 'edition', { edition: 'licensed', active_keys: [...apiKeys.values()].filter(k => k.active !== false).length });
    return;
  }

  const entries = [...apiKeys.entries()];
  const active  = entries.filter(([, v]) => v.active !== false);

  if (active.length <= COMMUNITY_KEY_LIMIT) {
    for (const [, v] of entries) v.over_limit = false;
    log('info', 'edition', { edition: EDITION, active_keys: active.length, limit: COMMUNITY_KEY_LIMIT });
    return;
  }

  // First COMMUNITY_KEY_LIMIT active keys keep working; the rest are blocked
  let n = 0;
  for (const [, v] of entries) {
    if (v.active === false) continue;
    n++;
    v.over_limit = n > COMMUNITY_KEY_LIMIT;
    if (v.over_limit) log('warn', 'key_over_limit', {
      label: v.label,
      hint: 'Community Edition: relay operator can add PARAMANT_LICENSE=plk_... to .env to unlock unlimited users'
    });
  }
  log('warn', 'community_limit_exceeded', {
    active_keys: active.length,
    limit: COMMUNITY_KEY_LIMIT,
    blocked: active.length - COMMUNITY_KEY_LIMIT,
    operator_upgrade: 'https://paramant.app/pricing'
  });
}


// ── Start ─────────────────────────────────────────────────────────────────────
loadUsers();
checkLicense();
server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  log('info', 'relay_started', { port: PORT, version: VERSION, sector: SECTOR, mode: RELAY_MODE,
      dsa: !!mlDsa, protocol: 'ghost-pipe-v2' });
});
function emergencyZeroAndExit(reason, code = 0) {
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
  log('error', 'unhandled_rejection', { reason: String(reason).slice(0, 200) });
  emergencyZeroAndExit('unhandledRejection', 1);
});

// Catch synchronous uncaught exceptions (e.g. invalid header values)
process.on('uncaughtException', (err) => {
  log('error', 'uncaught_exception', { msg: err.message?.slice(0, 200), code: err.code });
  emergencyZeroAndExit('uncaughtException', 1);
});
