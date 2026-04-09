'use strict';
const http   = require('http');
const crypto = require('crypto');
const https  = require('https');
const fs     = require('fs');
const url_   = require('url');

const VERSION    = '2.3.6';
// Per-restart nonce: stream-next hashes non-precomputable even if API key is known
const STREAM_NONCE = crypto.randomBytes(32);
// WS ticket store — avoids API key in WebSocket upgrade URL (finding #13)
const wsTickets = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of wsTickets) if (now > v.expires) wsTickets.delete(k); }, 10_000);

const PORT       = parseInt(process.env.PORT       || '4000');
const USERS_FILE = process.env.USERS_FILE          || './users.json';
const TTL_MS     = parseInt(process.env.TTL_MS     || '300000');
const MAX_BLOB   = parseInt(process.env.MAX_BLOB   || '5242880');
const MAX_AUDIT  = parseInt(process.env.MAX_AUDIT  || '1000');
const RELAY_MODE = process.env.RELAY_MODE          || 'full';
const SECTOR     = process.env.SECTOR              || 'relay';
const CT_LOG_FILE = process.env.CT_LOG_FILE        || '/data/ct-log.json';

let mlDsa = null;
try {
  const { ml_dsa65: lib } = require('@noble/post-quantum/ml-dsa');
  mlDsa = lib || null;
  if (mlDsa) log('info', 'ml_dsa_loaded', { alg: 'ML-DSA-65 NIST FIPS 204' });
} catch(e) { log('warn', 'ml_dsa_not_available', { hint: 'npm install @noble/post-quantum' }); }

const ALLOWED = {
  ghost_pipe: ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics','/v2/dl',
               '/v2/key-sector','/v2/team','/v2/reload-users'],
  full:       null,
};
function modeAllows(p) { const a = ALLOWED[RELAY_MODE]; return !a || a.some(x => p === x || p.startsWith(x + '/')); }

let natsClient = null, natsJs = null;
async function initNats() {
  if (!process.env.NATS_URL) return;
  try {
    const { connect } = require('nats');
    const servers = process.env.NATS_URL;
    try {
      const _u = new URL(servers.includes('://') ? servers : 'nats://' + servers);
      if (!servers.startsWith('tls://') && _u.hostname !== 'localhost' && _u.hostname !== '127.0.0.1')
        log('warn', 'nats_no_tls', { hint: 'NATS_URL does not use tls:// — plaintext NATS on non-localhost exposes transfer metadata' });
    } catch {}
    const opts = { servers };
    if (process.env.NATS_USER)  opts.user  = process.env.NATS_USER;
    if (process.env.NATS_PASS)  opts.pass  = process.env.NATS_PASS;
    if (process.env.NATS_TOKEN) opts.token = process.env.NATS_TOKEN;
    natsClient = await connect(opts);
    natsJs = natsClient.jetstream();
    try { const jsm = await natsClient.jetstreamManager(); await jsm.streams.add({ name: 'PARAMANT', subjects: ['paramant.>'], max_age: 300e9 }); } catch(e) {}
    log('info', 'nats_connected', { servers });
  } catch(e) { log('warn', 'nats_not_available', { hint: 'NATS connection failed', err: e.message }); }
}
async function natsPush(apiKey, deviceId, hash, size) {
  if (!natsJs) return;
  try {
    const { StringCodec } = require('nats');
    await natsJs.publish(
      `paramant.${crypto.createHash('sha256').update(apiKey).digest('hex').slice(0,16)}.${crypto.createHash('sha256').update(deviceId).digest('hex').slice(0,16)}`,
      StringCodec().encode(JSON.stringify({ hash, size, ts: new Date().toISOString() }))
    );
  } catch(e) {}
}
initNats();

const didRegistry = new Map();
function generateDid(deviceId, pubKeyHex) {
  return `did:paramant:${crypto.createHash('sha256').update(deviceId + pubKeyHex).digest('hex').slice(0,32)}`;
}
function createDidDocument(did, deviceId, ecdhPubHex, dsaPubHex) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did, created: new Date().toISOString(),
    assertionMethod: [did + '#keys-1'], capabilityInvocation: [did + '#keys-1'],
    verificationMethod: [{ id: `${did}#keys-1`, type: 'JsonWebKey2020', controller: did, publicKeyHex: ecdhPubHex }],
    service: [{ id: `${did}#ghost-pipe`, type: 'GhostPipeRelay',
      serviceEndpoint: `https://${SECTOR}.paramant.app`, device: deviceId,
      protocol: 'ghost-pipe-v2', encryption: 'ML-KEM-768+ECDH+AES-256-GCM' }]
  };
}

const ctLog = [];
const CT_MAX = 10000;
function loadCtLog() {
  try {
    const d = JSON.parse(fs.readFileSync(CT_LOG_FILE, 'utf8'));
    if (Array.isArray(d)) { ctLog.push(...d); log('info', 'ct_log_loaded', { count: ctLog.length }); }
  } catch(e) { if (e.code !== 'ENOENT') log('warn', 'ct_log_load_failed', { err: e.message }); }
}
// RFC 6962-style Merkle tree — SHA3-256 with domain separation bytes:
//   leaf:  SHA3-256(0x00 || data)  — prevents second-preimage attacks
//   inner: SHA3-256(0x01 || left || right)
function ctLeafHash(deviceIdHash, pubKeyHex, ts) {
  return crypto.createHash('sha3-256').update(Buffer.from([0x00]))
    .update(Buffer.concat([Buffer.from(deviceIdHash,'hex'), Buffer.from(pubKeyHex.slice(0,64),'hex'), Buffer.from(ts,'utf8')]))
    .digest('hex');
}
function ctNodeHash(l, r) {
  return crypto.createHash('sha3-256').update(Buffer.from([0x01])).update(Buffer.from(l,'hex')).update(Buffer.from(r,'hex')).digest('hex');
}
function ctTreeHash(entries) {
  if (!entries.length) return '0'.repeat(64);
  let h = entries.map(e => e.leaf_hash);
  while (h.length > 1) {
    const n = [];
    for (let i = 0; i < h.length; i += 2) n.push(i+1 < h.length ? ctNodeHash(h[i], h[i+1]) : h[i]);
    h = n;
  }
  return h[0];
}
function ctInclusionProof(entries, idx) {
  if (entries.length <= 1) return [];
  let h = entries.map(e => e.leaf_hash), path = [], i = idx;
  while (h.length > 1) {
    const sib = i % 2 === 0 ? i+1 : i-1;
    if (sib < h.length) path.push({ hash: h[sib], position: i%2===0 ? 'right' : 'left' });
    const n = [];
    for (let j = 0; j < h.length; j += 2) n.push(j+1 < h.length ? ctNodeHash(h[j], h[j+1]) : h[j]);
    h = n; i = Math.floor(i/2);
  }
  return path;
}
function ctAppend(deviceId, pubKeyHex, apiKey, event = 'pubkey') {
  const ts = new Date().toISOString();
  const deviceIdHash = crypto.createHash('sha3-256').update(deviceId + apiKey.slice(0,8)).digest('hex');
  const leaf_hash = ctLeafHash(deviceIdHash, pubKeyHex, ts);
  const index = ctLog.length;
  const allEntries = [...ctLog, { leaf_hash }];
  const entry = { index, leaf_hash, tree_hash: ctTreeHash(allEntries), device_hash: deviceIdHash, ts, event, proof: ctInclusionProof(allEntries, index) };
  ctLog.push(entry);
  if (ctLog.length > CT_MAX) ctLog.shift();
  try { fs.writeFileSync(CT_LOG_FILE, JSON.stringify(ctLog)); } catch(e) { log('warn', 'ct_log_persist_failed', { err: e.message }); }
  return entry;
}

const attestations = new Map();
function verifyAttestation(pubKeyHex, deviceId, attestationObj) {
  if (!attestationObj) return { valid: false, reason: 'no_attestation', attested: false };
  const method = attestationObj.method || 'unknown';
  let result;
  if (method === 'tpm2') result = { valid: Date.now() - (attestationObj.ts||0) < 300000, method: 'tpm2', pcr: attestationObj.pcr_values||[] };
  else if (method === 'apple') result = { valid: !!attestationObj.auth_data, method: 'apple_secure_enclave' };
  else if (method === 'software') result = { valid: true, method: 'software', warning: 'not_hardware_backed' };
  else result = { valid: false, reason: 'unknown_method' };
  const deviceHash = crypto.createHash('sha256').update(deviceId).digest('hex');
  attestations.set(deviceHash, { ...result, attested: result.valid, verified_ts: new Date().toISOString() });
  log(result.valid ? 'info' : 'warn', 'attestation_result', { device: deviceId.slice(0,8), method, valid: result.valid });
  return result;
}

const metricsCounters = { requests_total:0, requests_authed:0, blobs_stored:0, blobs_burned:0, bytes_in_total:0, bytes_out_total:0, errors_total:0, ack_total:0, did_registrations:0 };
function incMetric(k, v=1) { if (k in metricsCounters) metricsCounters[k] += v; }
function renderPrometheus() {
  const L = [];
  for (const [k,v] of Object.entries(metricsCounters)) { L.push(`# TYPE paramant_${k} counter`); L.push(`paramant_${k}{sector="${SECTOR}",v="${VERSION}"} ${v}`); }
  for (const [k,v] of [['blobs_in_flight',blobStore.size],['pubkeys',pubkeys.size],['did_registry',didRegistry.size],['ct_log',ctLog.length],['uptime_s',Math.floor(process.uptime())],['heap_bytes',process.memoryUsage().heapUsed]]) { L.push(`# TYPE paramant_${k} gauge`); L.push(`paramant_${k}{sector="${SECTOR}"} ${v}`); }
  const rs = ramStatus();
  for (const [k,v] of [['ram_slots_available',rs.available_slots],['ram_blobs_max',rs.blobs_max],['ram_blob_mb',rs.blob_ram_mb],['ram_rss_mb',rs.rss_mb],['ram_heap_mb',rs.heap_mb]]) { L.push(`# TYPE paramant_${k} gauge`); L.push(`paramant_${k}{sector="${SECTOR}"} ${v}`); }
  return L.join('\n') + '\n';
}

const TOTP_SECRET = process.env.TOTP_SECRET || '';
const TOTP_WINDOW = 1;
function base32Decode(s) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = [];
  for (const c of s.toUpperCase().replace(/=+$/,'')) { value = (value << 5) | alpha.indexOf(c); bits += 5; if (bits >= 8) { output.push((value >>> (bits-8)) & 0xFF); bits -= 8; } }
  return Buffer.from(output);
}
function totpCode(secret, counter) {
  const key = base32Decode(secret), buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  // SHA-256 TOTP (non-standard RFC 6238 variant — requires Aegis/Raivo with SHA-256 algorithm)
  const mac = crypto.createHmac('sha256', key).update(buf).digest();
  const offset = mac[mac.length-1] & 0xf;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6,'0');
}
function verifyTotp(token) {
  if (!TOTP_SECRET) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) { if (totpCode(TOTP_SECRET, counter+i) === token) return true; }
  return false;
}

const downloadTokens = new Map();
setInterval(() => { const now = Date.now(); for (const [t,d] of downloadTokens) if (d.used || now > d.expires_ms) downloadTokens.delete(t); }, 60000);

const RAM_LIMIT_MB   = parseInt(process.env.RAM_LIMIT_MB   || '512');
const RAM_RESERVE_MB = parseInt(process.env.RAM_RESERVE_MB || '256');
const BLOB_SIZE_MB   = 5;
const MAX_BLOBS      = Math.floor(RAM_LIMIT_MB / BLOB_SIZE_MB);
function ramStats() {
  const mem = process.memoryUsage();
  let blobBytes = 0; for (const e of blobStore.values()) blobBytes += (e.size||0);
  return { heapMB: Math.round(mem.heapUsed/1024/1024), rssMB: Math.round(mem.rss/1024/1024), blobMB: Math.round(blobBytes/1024/1024), blobCount: blobStore.size };
}
function ramOk() {
  const { rssMB, blobCount } = ramStats();
  const effective = blobCount + inFlightInbound;
  if (effective >= MAX_BLOBS) return false;
  if (rssMB + BLOB_SIZE_MB * (inFlightInbound+1) > RAM_LIMIT_MB + RAM_RESERVE_MB) return false;
  return true;
}
function ramStatus() {
  const s = ramStats();
  return { blobs_in_flight: s.blobCount, blobs_uploading: inFlightInbound, blobs_max: MAX_BLOBS, blob_ram_mb: s.blobMB, heap_mb: s.heapMB, rss_mb: s.rssMB, ram_limit_mb: RAM_LIMIT_MB, ram_ok: ramOk(), available_slots: Math.max(0, MAX_BLOBS - s.blobCount - inFlightInbound) };
}
setInterval(() => { const r = ramStatus(); if (!r.ram_ok) log('warn','ram_pressure',r); else if (r.blobs_in_flight > MAX_BLOBS*0.7) log('info','ram_high',r); }, 60000);

const apiKeys    = new Map();
const blobStore  = new Map();
const pubkeys    = new Map();
const webhooks   = new Map();
const auditChain = new Map();

// Free tier rate limiting: 10 uploads/day per key
const freeRateLimits = new Map();
function checkFreeRateLimit(apiKey) {
  const today = new Date().toISOString().slice(0,10);
  const b = freeRateLimits.get(apiKey) || { count: 0, date: today };
  if (b.date !== today) { b.count = 0; b.date = today; }
  if (b.count >= 10) return false;
  b.count++; freeRateLimits.set(apiKey, b); return true;
}

const teamRateLimits = new Map();
function checkTeamRateLimit(teamId, limit) {
  if (!teamId) return true;
  const now = Date.now();
  const b = teamRateLimits.get(teamId) || { count: 0, resetAt: now + 60000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60000; }
  if (b.count >= limit) return false;
  b.count++; teamRateLimits.set(teamId, b); return true;
}

const OUTBOUND_RATE = { free: 50, pro: 500, enterprise: Infinity };
const OUTBOUND_RATE_WINDOW_MS = 3_600_000;
const outboundRateMap = new Map();
function outboundRateOk(apiKey, plan) {
  const max = OUTBOUND_RATE[plan] ?? OUTBOUND_RATE.free;
  if (max === Infinity) return true;
  const now = Date.now();
  let c = outboundRateMap.get(apiKey);
  if (!c || now > c.resetAt) c = { count: 0, resetAt: now + OUTBOUND_RATE_WINDOW_MS };
  if (c.count >= max) return false;
  c.count++; outboundRateMap.set(apiKey, c); return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k,v] of outboundRateMap) if (now > v.resetAt) outboundRateMap.delete(k);
  const yesterday = new Date(now - 86400000).toISOString().slice(0,10);
  for (const [k,v] of freeRateLimits) if (v.date < yesterday) freeRateLimits.delete(k);
}, 3_600_000);

function log(level, msg, data = {}) {
  if (typeof msg === 'string') console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, v: VERSION, ...data }));
}
function J(o) { return JSON.stringify(o); }

function auditAppend(key, event, data = {}) {
  if (!key) return;
  if (!auditChain.has(key)) auditChain.set(key, []);
  const chain = auditChain.get(key);
  const prevHash = chain.length > 0 ? chain[chain.length-1].chain_hash : '0'.repeat(64);
  const entry = { ts: new Date().toISOString(), event, prev_hash: prevHash, ...data };
  entry.chain_hash = crypto.createHash('sha256').update(JSON.stringify({ ts: entry.ts, event, hash: data.hash||'', bytes: data.bytes||0, prev_hash: prevHash })).digest('hex');
  chain.push(entry);
  if (chain.length > MAX_AUDIT) chain.shift();
}
function verifyChain(entries) {
  for (let i = 1; i < entries.length; i++) { if (entries[i].prev_hash !== entries[i-1].chain_hash) return false; }
  return true;
}

function verifyDsaSignature(payload, signature, pubKeyHex) {
  if (!mlDsa || !signature || !pubKeyHex) return { valid: false, reason: 'ML-DSA not available or no sig' };
  try {
    const valid = mlDsa.verify(Buffer.from(pubKeyHex,'hex'), Buffer.from(payload), Buffer.from(signature,'hex'));
    return { valid, alg: 'ML-DSA-65' };
  } catch(e) { return { valid: false, reason: e.message }; }
}

let stats = { inbound: 0, outbound: 0, burned: 0, webhooks_sent: 0, bytes_in: 0, bytes_out: 0 };
// In-flight counter: incremented BEFORE readBody() to close TOCTOU window.
// Node.js is single-threaded so check + increment is atomic.
let inFlightInbound = 0;

function loadUsers() {
  if (process.env.USERS_JSON) {
    try { const d = JSON.parse(process.env.USERS_JSON); (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||'',active:true}); }); log('info','users_loaded',{count:apiKeys.size,source:'env'}); return; } catch(e) { log('error','users_json_parse',{err:e.message}); }
  }
  try {
    const d = JSON.parse(fs.readFileSync(USERS_FILE,'utf8'));
    (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||'',active:true,dsa_pub:k.dsa_pub||''}); });
    log('info','users_loaded',{count:apiKeys.size,sector:SECTOR});
  } catch(e) { log('warn','no_users_file'); }
}

const _pubkeyTtl = { free: 7*86_400_000, pro: 30*86_400_000, enterprise: 365*86_400_000 };
const _pubkeyMax = { free: 5, pro: 50, enterprise: Infinity };
const INVITE_PUBKEY_TTL = 3_600_000;

setInterval(() => {
  const now = Date.now();
  for (const [k,v] of pubkeys) if (v.expires && now > v.expires) pubkeys.delete(k);
}, 3600000);
setInterval(() => {
  const now = Date.now();
  for (const [h,e] of blobStore) if (now - e.ts > e.ttl) { try { e.blob.fill(0); } catch {} blobStore.delete(h); }
}, 30_000);

// SSRF guard — blocks RFC1918, loopback, link-local, IPv6 ULA, cloud metadata,
// and alternate IP representations (decimal, hex, octal, short-form, IPv4-mapped IPv6)
function isSsrfSafeUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase().replace(/^\[|\]$/g,'');
    if (/^\d+$/.test(h)) return false;                          // decimal IP (e.g. 2130706433)
    if (/^0x[0-9a-f]+$/i.test(h)) return false;                 // hex IP (e.g. 0x7f000001)
    if (/^(0\d+\.){1,3}0?\d+$/.test(h)) return false;           // octal octets (e.g. 0177.0.0.1)
    if (/^\d+\.\d+$/.test(h)) return false;                     // short-form (e.g. 127.1)
    // IPv4-mapped IPv6 ::ffff:x.x.x.x — recurse to validate the v4 part
    if (/^::ffff:/i.test(h)) return isSsrfSafeUrl('https://' + h.replace(/^::ffff:/i,'') + '/');
    if (h === 'localhost' || h === '0.0.0.0' || h === '0') return false;
    if (/^127\./.test(h)) return false;
    if (/^::1$|^0{0,4}:0{0,4}:0{0,4}:0{0,4}:0{0,4}:0{0,4}:0{0,4}:0*1$/.test(h)) return false;
    if (/^169\.254\./.test(h)) return false;
    if (/^fe80/i.test(h)) return false;
    if (/^10\./.test(h)) return false;
    if (/^192\.168\./.test(h)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
    if (/^f[cd]/i.test(h)) return false;                        // IPv6 ULA (fc00::/7)
    if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return false;
    if (h === 'metadata.google.internal' || h === 'metadata.aws.internal') return false;
    return true;
  } catch { return false; }
}

async function pushWebhooks(apiKey, deviceId, event, data) {
  const hooks = webhooks.get(`${deviceId}:${apiKey}`) || [];
  for (const hook of hooks) {
    if (!isSsrfSafeUrl(hook.url)) { log('warn','webhook_ssrf_blocked',{url:(hook.url||'').slice(0,60)}); continue; }
    // DNS rebinding defense: re-resolve hostname before firing to prevent TTL-switch attacks
    try {
      const _wu = new URL(hook.url);
      const _r = await require('dns').promises.lookup(_wu.hostname);
      if (!isSsrfSafeUrl('https://' + _r.address + '/')) { log('warn','webhook_dns_rebinding_blocked',{url:hook.url.slice(0,60),resolved:_r.address}); continue; }
    } catch(e) { log('warn','webhook_dns_resolve_fail',{url:(hook.url||'').slice(0,60),err:e.message}); continue; }
    const payload = J({ event, device_id: deviceId, ts: new Date().toISOString(), ...data });
    try {
      const sig = hook.secret ? crypto.createHmac('sha256',hook.secret).update(payload).digest('hex') : '';
      const rq = https.request(hook.url, { method:'POST', headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload),'X-Paramant-Event':event,'X-Paramant-Sig':sig,'User-Agent':`paramant-relay/${VERSION}`} });
      rq.on('error',()=>{}); rq.write(payload); rq.end();
      stats.webhooks_sent++;
    } catch(e) { log('warn','webhook_fail',{url:(hook.url||'').slice(0,60)}); }
  }
}

// DER-SPKI prefix for P-256 uncompressed public key (65 bytes → 91 bytes total)
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200','hex');
// Constant-time token comparison — prevents timing side-channel on admin token (finding)
function safeEqual(a, b) {
  try {
    const ba = Buffer.from(String(a||''),'utf8'), bb = Buffer.from(String(b||''),'utf8');
    if (ba.length !== bb.length) {
      // Still execute compare to avoid length oracle — result is always false
      const pad = Buffer.alloc(Math.max(ba.length,bb.length));
      crypto.timingSafeEqual(pad,pad);
      return false;
    }
    return crypto.timingSafeEqual(ba,bb);
  } catch { return false; }
}

function authByDid(didStr, signature, payload) {
  const entry = [...didRegistry.values()].find(e => e.doc.id === didStr);
  if (!entry) return null;
  const vm = entry.doc.verificationMethod?.[0];
  if (!vm?.publicKeyHex) return null;
  try {
    const rawKey = Buffer.from(vm.publicKeyHex,'hex');
    // Wrap raw uncompressed P-256 point in DER-SPKI if not already encoded (0x30 = SEQUENCE tag)
    const spkiKey = rawKey[0] === 0x30 ? rawKey : Buffer.concat([P256_SPKI_PREFIX, rawKey]);
    if (crypto.verify('SHA256', Buffer.from(payload), { key:spkiKey, format:'der', type:'spki' }, Buffer.from(signature,'hex'))) return entry;
  } catch(e) { log('warn','did_auth_verify_error',{err:e.message,did:didStr.slice(0,30)}); }
  return null;
}

const ALLOWED_ORIGINS = ['https://paramant.app','https://www.paramant.app'];
function setHeaders(res, req) {
  const origin = req?.headers?.origin || '';
  res.setHeader('Access-Control-Allow-Origin',  ALLOWED_ORIGINS.includes(origin) ? origin : 'https://paramant.app');
  res.setHeader('Vary',                         'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Dsa-Signature, Authorization, X-Admin-Token, X-DID, X-DID-Signature');
  res.setHeader('Cache-Control',                'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options',       'nosniff');
  // X-Paramant-Version intentionally omitted — version disclosure removed (security hardening v2.3.3)
  res.setHeader('X-Paramant-Sector',            SECTOR);
}

function readBody(req, max = MAX_BLOB * 2) {
  return new Promise((res,rej) => {
    const c = []; let n = 0;
    req.on('data', d => { n += d.length; if (n > max) return rej(new Error('Too large')); c.push(d); });
    req.on('end', () => res(Buffer.concat(c)));
    req.on('error', rej);
  });
}

const server = http.createServer(async (req, res) => {
  setHeaders(res, req);
  const parsed = url_.parse(req.url, true);
  const path   = parsed.pathname;
  const query  = parsed.query;
  const apiKey = (req.headers['x-api-key'] || '').trim();
  if (query.k) {
    log('warn','key_in_querystring_rejected',{path:path.slice(0,40),ip:(req.socket?.remoteAddress||'').slice(0,15)});
    res.writeHead(400); return res.end(J({ error: 'API key must be sent in X-Api-Key header, not query string' }));
  }
  const didHeader = req.headers['x-did'] || '';
  const didSig    = req.headers['x-did-signature'] || '';
  let didAuthEntry = null;
  if (!apiKey && didHeader && didSig) {
    didAuthEntry = authByDid(didHeader, didSig, req.url);
    if (didAuthEntry) log('info','did_auth_mode',{did:didHeader.slice(0,30)});
  }
  const keyData = apiKeys.get(apiKey) || (didAuthEntry ? { plan:'free', active:true, label:didAuthEntry.device_id } : null);
  incMetric('requests_total');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (path === '/') { res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,relay:SECTOR,version:VERSION,status:'operational',protocol:'ghost-pipe-v2',docs:'https://paramant.app/docs'})); }
  if (!modeAllows(path)) { res.writeHead(405); return res.end(J({error:'Not available in this relay mode',mode:RELAY_MODE})); }

  if (path === '/health') {
    const adminOk = safeEqual((req.headers['x-admin-token']||'').trim(), process.env.ADMIN_TOKEN||'') && !!(process.env.ADMIN_TOKEN);
    const ram = ramStatus();
    const base = { ok:true, version:VERSION, sector:SECTOR, mode:RELAY_MODE, uptime_s:Math.floor(process.uptime()), blobs:blobStore.size, ram_ok:ram.ram_ok, available_slots:ram.available_slots };
    const full = { ...base, ...ram, pubkeys:pubkeys.size, webhooks:[...webhooks.values()].flat().length, stats, quantum_ready:true, protocol:'ghost-pipe-v2', encryption:'ML-KEM-768 + ECDH P-256 + AES-256-GCM', signatures:mlDsa?'ML-DSA-65 (NIST FIPS 204)':'ECDSA P-256 (ML-DSA fallback)', audit:'Merkle hash chain', storage:'RAM-only, zero plaintext, burn-on-read', padding:'5MB fixed (DPI-masking)', jurisdiction:'EU/DE, GDPR, no US CLOUD Act' };
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J(adminOk ? full : base));
  }

  if (path === '/v2/check-key') {
    const kd = apiKeys.get(apiKey);
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({valid:!!(kd?.active),plan:kd?.plan||null}));
  }

  if (path === '/metrics') {
    const reqToken = (req.headers['authorization']||'').replace('Bearer ','').trim();
    if ((process.env.ADMIN_TOKEN||'') && reqToken !== process.env.ADMIN_TOKEN) { res.writeHead(401,{'Content-Type':'text/plain'}); return res.end('Unauthorized'); }
    res.writeHead(200,{'Content-Type':'text/plain; version=0.0.4; charset=utf-8'}); return res.end(renderPrometheus());
  }

  if (path === '/v2/ct/log') {
    const limit = Math.min(parseInt(query.limit||'100'),1000), from = parseInt(query.from||'0');
    const entries = ctLog.slice(from, from+limit).map(e => ({index:e.index,leaf_hash:e.leaf_hash,tree_hash:e.tree_hash,device_hash:e.device_hash,ts:e.ts,event:e.event||'pubkey'}));
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,size:ctLog.length,root:ctLog.length?ctLog[ctLog.length-1].tree_hash:'0'.repeat(64),entries}));
  }
  const ctpm = path.match(/^\/v2\/ct\/proof\/(\d+)$/);
  if (ctpm) {
    const entry = ctLog[parseInt(ctpm[1])];
    if (!entry) { res.writeHead(404); return res.end(J({error:'Index not found'})); }
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,index:parseInt(ctpm[1]),leaf_hash:entry.leaf_hash,tree_hash:entry.tree_hash,proof:entry.proof,ts:entry.ts}));
  }

  const didm0 = path.match(/^\/v2\/did\/([^/]+)$/);
  if (didm0 && req.method === 'GET') {
    const entry = [...didRegistry.values()].find(e => e.doc.id === decodeURIComponent(didm0[1]));
    if (!entry) { res.writeHead(404); return res.end(J({error:'DID not found'})); }
    res.writeHead(200,{'Content-Type':'application/did+json'}); return res.end(J(entry.doc));
  }

  const dlm = path.match(/^\/v2\/dl\/([a-f0-9]{48})(\/get)?$/);
  if (dlm && req.method === 'GET') {
    const td = downloadTokens.get(dlm[1]);
    if (!td) { res.writeHead(404); return res.end(J({error:'Link not found or already used'})); }
    if (td.used) { res.writeHead(410); return res.end(J({error:'This link has already been used'})); }
    if (Date.now() > td.expires_ms) { downloadTokens.delete(dlm[1]); res.writeHead(410); return res.end(J({error:'Link expired'})); }
    const entry = blobStore.get(td.hash);
    if (!entry) { downloadTokens.delete(dlm[1]); res.writeHead(404); return res.end(J({error:'File not found — already burned'})); }
    // Mark as used BEFORE sending — burn-on-read
    td.used = true;
    const blob = entry.blob; blobStore.delete(td.hash);
    log('info','dl_token_used',{token:dlm[1].slice(0,8),hash:td.hash.slice(0,16)});
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':td.file_name?`attachment; filename="${td.file_name}"`:'attachment','X-Burned':'true','X-Hash':td.hash});
    return res.end(blob, () => { try { blob.fill(0); } catch {} });
  }

  const dlim = path.match(/^\/v2\/dl\/([a-f0-9]{48})\/info$/);
  if (dlim && req.method === 'GET') {
    const td = downloadTokens.get(dlim[1]);
    if (!td || td.used || Date.now() > td.expires_ms) { res.writeHead(404); return res.end(J({ok:false,error:'Link not found, used, or expired'})); }
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,file_name:td.file_name,file_size:td.file_size,ttl_left_s:Math.round((td.expires_ms-Date.now())/1000),used:false}));
  }

  if (path === '/v2/reload-users' && req.method === 'POST') {
    const tok = (req.headers['x-api-key']||req.headers['authorization']?.replace('Bearer ','')||'').trim();
    if (!tok || !safeEqual(tok, process.env.ADMIN_TOKEN||'')) { res.writeHead(401); return res.end(J({error:'unauthorized'})); }
    if (process.env.USERS_JSON) { res.writeHead(400); return res.end(J({error:'USERS_JSON env in gebruik — bestand reload niet van toepassing'})); }
    const prev = apiKeys.size; apiKeys.clear(); loadUsers();
    log('info','reload_users',{prev,now:apiKeys.size}); res.writeHead(200); return res.end(J({ok:true,loaded:apiKeys.size}));
  }

  // inv_ session tokens bypass API key auth for pubkey endpoints only.
  // Public keys are not sensitive; security comes from fingerprint verification.
  const INVITE_RE = /^inv_[a-zA-Z0-9]{32}(_ready)?$/;

  if (path === '/v2/pubkey' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({error:'device_id and ecdh_pub required'})); }
      if (INVITE_RE.test(d.device_id)) {
        pubkeys.set(d.device_id, {ecdh_pub:d.ecdh_pub,kyber_pub:d.kyber_pub||'',ts:new Date().toISOString(),expires:Date.now()+INVITE_PUBKEY_TTL});
        log('info','pubkey_registered_invite',{device:d.device_id.slice(0,12)});
        res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true}));
      }
      if (!keyData?.active) { res.writeHead(401); return res.end(J({error:'Invalid API key'})); }
      const plan = keyData.plan || 'free';
      const maxDevices = _pubkeyMax[plan] ?? _pubkeyMax.free;
      if (maxDevices !== Infinity) {
        let cnt = 0; for (const k of pubkeys.keys()) if (k.endsWith(`:${apiKey}`)) cnt++;
        if (cnt >= maxDevices) { res.writeHead(429); return res.end(J({error:`Device limit reached. Max ${maxDevices} devices on ${plan} plan.`,limit:maxDevices,plan})); }
      }
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      const attestResult = verifyAttestation(d.ecdh_pub, d.device_id, d.attestation||null);
      pubkeys.set(`${d.device_id}:${apiKey}`, {ecdh_pub:d.ecdh_pub,kyber_pub:d.kyber_pub||'',dsa_pub:d.dsa_pub||'',ts:new Date().toISOString(),expires:Date.now()+(_pubkeyTtl[plan]??_pubkeyTtl.free)});
      log('info','pubkey_registered',{device:d.device_id,kyber:!!d.kyber_pub,dsa:!!d.dsa_pub,plan,ttl_days:Math.round((_pubkeyTtl[plan]??_pubkeyTtl.free)/86400000)});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,dsa_supported:!!mlDsa,ct_index:ctEntry.index,ct_tree_hash:ctEntry.tree_hash,attested:attestResult.valid,attestation_method:attestResult.method||null}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  const pkm = path.match(/^\/v2\/pubkey\/([^/]+)$/);
  if (pkm && req.method === 'GET') {
    const deviceId = decodeURIComponent(pkm[1]);
    const _pkKey = INVITE_RE.test(deviceId) ? deviceId : `${deviceId}:${apiKey}`;
    const entry = pubkeys.get(_pkKey);
    if (!entry) { res.writeHead(404); return res.end(J({error:'No pubkeys for this device. Start receiver first.'})); }
    if (entry.expires && Date.now() > entry.expires) { pubkeys.delete(_pkKey); res.writeHead(404); return res.end(J({error:'Pubkey registration expired. Re-register the device.'})); }
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,ecdh_pub:entry.ecdh_pub,kyber_pub:entry.kyber_pub,dsa_pub:entry.dsa_pub||'',ts:entry.ts}));
  }

  // Admin paths: ONLY ADMIN_TOKEN is accepted — no enterprise keys, no pgp_ keys.
  // isAdminPath gate MUST come before the main auth gate (fixes admin 401 bug sessie 4).
  const isAdminPath = path.startsWith('/v2/admin');
  if (isAdminPath) {
    const adminHeader = (req.headers['x-admin-token']||req.headers['authorization']?.replace(/^Bearer\s+/i,'')||'').trim();
    if (!adminHeader || !process.env.ADMIN_TOKEN || !safeEqual(adminHeader, process.env.ADMIN_TOKEN)) {
      res.writeHead(401,{'Content-Type':'application/json'}); return res.end(J({error:'ADMIN_TOKEN required for admin endpoints'}));
    }
  } else if (!keyData?.active) {
    res.writeHead(401,{'Content-Type':'application/json'}); return res.end(J({error:'Invalid API key',hint:'X-Api-Key: pgp_...'}));
  }

  if (path === '/v2/inbound' && req.method === 'POST') {
    if (!ramOk()) {
      const r = ramStatus();
      res.writeHead(503,{'Content-Type':'application/json','Retry-After':'10','X-Ram-Slots':String(r.available_slots)});
      log('warn','inbound_rejected_ram',r);
      return res.end(J({ok:false,error:'Relay at capacity. Retry in 10 seconds.',retry_after_s:10,slots_available:r.available_slots,blobs_in_flight:r.blobs_in_flight}));
    }
    if (keyData?.plan === 'free' && !checkFreeRateLimit(apiKey)) {
      res.writeHead(429,{'Content-Type':'application/json','Retry-After':'86400'});
      return res.end(J({error:'Free tier limit reached (10 uploads/day)',retry_after_s:86400}));
    }
    // Reserve slot BEFORE awaiting body — closes TOCTOU window under concurrency.
    // Node.js is single-threaded so check + increment is atomic.
    inFlightInbound++;
    try {
      const body = await readBody(req);
      const d = JSON.parse(body.toString());
      const { hash, payload, ttl_ms, meta, dsa_signature } = d;
      if (!hash || !payload) { res.writeHead(400); return res.end(J({error:'hash and payload required'})); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({error:'hash must be SHA-256 hex'})); }
      if (blobStore.has(hash)) { res.writeHead(409); return res.end(J({error:'Hash already in use'})); }
      const blob = Buffer.from(payload,'base64');
      if (blob.length > MAX_BLOB) { res.writeHead(413); return res.end(J({error:`Max ${Math.round(MAX_BLOB/1048576)}MB`})); }
      let sigResult = { valid: false, reason: 'not provided' };
      if (dsa_signature && keyData.dsa_pub) sigResult = verifyDsaSignature(hash, dsa_signature, keyData.dsa_pub);
      const _planMaxTtl = { free: 3_600_000, dev: 3_600_000, pro: 86_400_000, enterprise: 604_800_000 };
      const ttl = Math.min(parseInt(ttl_ms||TTL_MS), _planMaxTtl[keyData?.plan||'free'] || _planMaxTtl.free);
      blobStore.set(hash, {blob,ts:Date.now(),ttl,size:blob.length,sig_valid:sigResult.valid,apiKey});
      setTimeout(() => { const e = blobStore.get(hash); if(e){try{e.blob.fill(0);}catch{}blobStore.delete(hash);} }, ttl);
      const deviceId = meta?.device_id;
      incMetric('blobs_stored'); incMetric('bytes_in_total',blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      auditAppend(apiKey,'inbound',{hash:hash.slice(0,16)+'...',bytes:blob.length,device:deviceId,sig:sigResult.valid?'ML-DSA-OK':'unsigned'});
      ctAppend(deviceId||apiKey.slice(0,16), hash, apiKey, 'transfer');
      log('info','blob_stored',{hash:hash.slice(0,16),size:blob.length,sig:sigResult.valid});
      if (deviceId) pushWebhooks(apiKey, deviceId,'blob_ready',{hash,size:blob.length,ttl_ms:ttl,sig_valid:sigResult.valid});
      if (global.wsPush) global.wsPush(apiKey,{hash,size:blob.length,device:deviceId,sig_valid:sigResult.valid});
      natsPush(apiKey, deviceId||'unknown', hash, blob.length);
      const dlToken = crypto.randomBytes(24).toString('hex');
      downloadTokens.set(dlToken, {hash,key:apiKey,expires_ms:Date.now()+ttl,used:false,file_name:meta?.file_name||'',file_size:blob.length});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,hash,ttl_ms:ttl,size:blob.length,sig_verified:sigResult.valid,download_token:dlToken}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
    finally { inFlightInbound--; }
  }

  const outm = path.match(/^\/v2\/outbound\/([a-f0-9]{64})$/);
  if (outm && req.method === 'GET') {
    const entry = blobStore.get(outm[1]);
    if (!entry) { res.writeHead(404); return res.end(J({error:'Not found. Expired, burned, or never stored.'})); }
    if (entry.apiKey && entry.apiKey !== apiKey) { res.writeHead(403); return res.end(J({error:'Forbidden'})); }
    if (!outboundRateOk(apiKey, keyData?.plan)) { res.writeHead(429,{'Content-Type':'application/json'}); return res.end(J({error:'Outbound rate limit exceeded. Retry after the hourly window resets.'})); }
    const blob = entry.blob; blobStore.delete(outm[1]);
    incMetric('blobs_burned'); incMetric('bytes_out_total',blob.length);
    stats.outbound++; stats.burned++; stats.bytes_out += blob.length;
    auditAppend(apiKey,'outbound_burn',{hash:outm[1].slice(0,16)+'...',bytes:blob.length});
    log('info','blob_burned',{hash:outm[1].slice(0,16)});
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':blob.length,'X-Paramant-Burned':'true','X-Paramant-Hash':outm[1]});
    return res.end(blob, () => { try { blob.fill(0); } catch {} });
  }

  const stm = path.match(/^\/v2\/status\/([a-f0-9]{64})$/);
  if (stm && req.method === 'GET') {
    const e = blobStore.get(stm[1]);
    res.writeHead(200,{'Content-Type':'application/json'});
    if (!e) return res.end(J({available:false}));
    if (e.apiKey && e.apiKey !== apiKey) { res.writeHead(403); return res.end(J({error:'Forbidden'})); }
    return res.end(J({available:true,bytes:e.size,ttl_remaining_ms:Math.max(0,e.ttl-(Date.now()-e.ts)),sig_valid:e.sig_valid}));
  }

  if (path === '/v2/webhook' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,4096)).toString());
      if (!d.device_id || !d.url) { res.writeHead(400); return res.end(J({error:'device_id and url required'})); }
      if (!isSsrfSafeUrl(d.url)) { res.writeHead(400); return res.end(J({error:'url must be a valid public HTTPS URL (private/loopback addresses not allowed)'})); }
      const k = `${d.device_id}:${apiKey}`;
      if (!webhooks.has(k)) webhooks.set(k,[]);
      webhooks.get(k).push({url:d.url,secret:d.secret||''});
      log('info','webhook_registered',{device:d.device_id});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/ws-ticket' && req.method === 'POST') {
    const ticket = 'wst_' + crypto.randomBytes(24).toString('hex');
    wsTickets.set(ticket, {apiKey, expires: Date.now() + 30_000});
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,ticket,expires_in:30}));
  }

  if (path === '/v2/stream-next') {
    const device = query.device||'', seq = parseInt(query.seq||'0'), next = seq+1;
    // HMAC secret = STREAM_NONCE+apiKey — non-precomputable without relay-session nonce (finding #9)
    const streamSecret = crypto.createHmac('sha256',STREAM_NONCE).update(apiKey).digest();
    const h = crypto.createHmac('sha256',streamSecret).update(`${device}|${next}`).digest('hex');
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,device,seq:next,hash:h,available:blobStore.has(h)}));
  }

  if (path === '/v2/audit') {
    if (!apiKey || !apiKeys.has(apiKey) || !apiKeys.get(apiKey)?.active) { res.writeHead(401,{'Content-Type':'application/json'}); return res.end(J({error:'API key required'})); }
    const limit = Math.min(parseInt(query.limit||'100'),MAX_AUDIT);
    const entries = (auditChain.get(apiKey)||[]).slice(-limit).reverse();
    if (query.format === 'csv') {
      res.writeHead(200,{'Content-Type':'text/csv','Content-Disposition':'attachment; filename="paramant_audit.csv"'});
      return res.end('ts,event,hash,bytes,device,chain_hash\n' + entries.map(e=>`${e.ts},${e.event},${e.hash||''},${e.bytes||0},${e.device||''},${e.chain_hash}`).join('\n'));
    }
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,count:entries.length,chain_valid:verifyChain([...(auditChain.get(apiKey)||[])]),entries}));
  }

  if (path === '/v2/did/register' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({error:'device_id and ecdh_pub required'})); }
      if (apiKey) {
        let cnt = 0; for (const e of didRegistry.values()) if (e.key === apiKey) cnt++;
        if (cnt >= 500) { res.writeHead(429); return res.end(J({error:'DID limit reached. Max 500 DIDs per API key.'})); }
      }
      const did = generateDid(d.device_id, d.ecdh_pub);
      const doc = createDidDocument(did, d.device_id, d.ecdh_pub, d.dsa_pub||'');
      didRegistry.set(did, {device_id:d.device_id,key:apiKey,doc,ts:new Date().toISOString()});
      const plan = keyData?.plan || 'free';
      pubkeys.set(`${d.device_id}:${apiKey}`, {ecdh_pub:d.ecdh_pub,kyber_pub:d.kyber_pub||'',dsa_pub:d.dsa_pub||'',ts:new Date().toISOString(),expires:Date.now()+(_pubkeyTtl[plan]??_pubkeyTtl.free)});
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      incMetric('did_registrations');
      auditAppend(apiKey,'did_registered',{did,device:d.device_id});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,did,document:doc,ct_index:ctEntry.index}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  const didm = path.match(/^\/v2\/did\/([^/]+)$/);
  if (didm && req.method === 'GET') {
    const entry = [...didRegistry.values()].find(e => e.doc.id === decodeURIComponent(didm[1]));
    if (!entry) { res.writeHead(404); return res.end(J({error:'DID not found'})); }
    res.writeHead(200,{'Content-Type':'application/did+json'}); return res.end(J(entry.doc));
  }
  if (path === '/v2/did' && req.method === 'GET') {
    const dids = [...didRegistry.values()].filter(e=>e.key===apiKey).map(e=>({did:e.doc.id,device:e.device_id,ts:e.ts}));
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,count:dids.length,dids}));
  }

  if (path === '/v2/attest' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,65536)).toString());
      if (!d.device_id || !d.attestation) { res.writeHead(400); return res.end(J({error:'device_id and attestation required'})); }
      const pk = pubkeys.get(`${d.device_id}:${apiKey}`);
      if (!pk) { res.writeHead(404); return res.end(J({error:'Device not registered'})); }
      const result = verifyAttestation(pk.ecdh_pub, d.device_id, d.attestation);
      auditAppend(apiKey,'attestation',{device:d.device_id,method:d.attestation.method,valid:result.valid});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,...result,device:d.device_id}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }
  const attm = path.match(/^\/v2\/attest\/([^/]+)$/);
  if (attm && req.method === 'GET') {
    const deviceHash = crypto.createHash('sha256').update(decodeURIComponent(attm[1])).digest('hex');
    const att = attestations.get(deviceHash);
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,device_hash:deviceHash,attestation:att||{attested:false,reason:'never_attested'}}));
  }

  if (path === '/v2/ack' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,4096)).toString());
      if (!d.hash) { res.writeHead(400); return res.end(J({error:'hash required'})); }
      incMetric('ack_total');
      auditAppend(apiKey,'ack_received',{hash:d.hash.slice(0,16)+'...',device:d.device_id||''});
      log('info','ack_received',{hash:d.hash.slice(0,16)});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,hash:d.hash}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/admin/verify-mfa' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,1024)).toString());
      const valid = verifyTotp(d.totp_code||'');
      log(valid?'info':'warn','mfa_attempt',{valid,ip:req.socket?.remoteAddress});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:valid,error:valid?null:'Invalid TOTP code'}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/admin/keys' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,4096)).toString());
      const newKey = (d.key && /^pgp_[0-9a-f]{32,64}$/.test(d.key)) ? d.key : 'pgp_' + crypto.randomBytes(16).toString('hex');
      apiKeys.set(newKey, {plan:d.plan||'pro',label:d.label||'',active:true});
      log('info','key_created_via_admin',{label:d.label,plan:d.plan});
      res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,key:newKey,plan:d.plan,label:d.label}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }
  if (path === '/v2/admin/keys' && req.method === 'GET') {
    const keys = [...apiKeys.entries()].map(([k,v]) => ({key:k,plan:v.plan,label:v.label,active:v.active}));
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,count:keys.length,keys}));
  }
  if (path === '/v2/admin/keys/revoke' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,1024)).toString());
      if (!apiKeys.has(d.key)) { res.writeHead(404); return res.end(J({error:'Key not found'})); }
      apiKeys.get(d.key).active = false;
      try {
        const usersData = JSON.parse(fs.readFileSync(USERS_FILE,'utf8'));
        const entry = usersData.api_keys.find(k => k.key === d.key);
        if (entry) { entry.active = false; entry.revoked_at = new Date().toISOString(); }
        usersData.updated = new Date().toISOString();
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersData,null,2));
        log('info','key_revoked_via_admin',{key:d.key.slice(0,16),persisted:true});
      } catch(e) { log('warn','key_revoke_persist_failed',{err:e.message}); }
      res.writeHead(200); return res.end(J({ok:true}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/admin/send-welcome' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req,4096)).toString());
      if (!d.email || !d.key) { res.writeHead(400); return res.end(J({error:'email and key required'})); }
      const RESEND_KEY = process.env.RESEND_API_KEY||'';
      if (!RESEND_KEY) { res.writeHead(503); return res.end(J({error:'RESEND_API_KEY not configured'})); }
      const html = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:520px"><div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div><div style="background:#1a1a00;border:1px solid #2a2a00;border-radius:6px;padding:16px;margin-bottom:24px;color:#cccc00;font-size:12px">IMPORTANT: Save this API key in your password manager immediately. It is generated once and cannot be recovered.</div><p style="color:#888;margin-bottom:24px">Your API key is ready.</p><div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px"><div style="font-size:11px;color:#555;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">API KEY — ${(d.plan||'').toUpperCase()}</div><div style="font-size:14px;color:#ededed;word-break:break-all">${d.key}</div></div><pre style="background:#111;border:1px solid #1a1a1a;border-radius:4px;padding:16px;font-size:12px;color:#888;overflow-x:auto">pip install cryptography\n\npython3 paramant-receiver.py \\\n  --key ${d.key} \\\n  --device my-device \\\n  --output /tmp/received/</pre><p style="margin-top:24px;font-size:12px;color:#555"><a href="https://paramant.app/docs" style="color:#888">Docs</a> · <a href="https://paramant.app/ct-log" style="color:#555">CT log</a></p><p style="margin-top:32px;font-size:11px;color:#333">ML-KEM-768 · Burn-on-read · EU/DE · BUSL-1.1</p></div>`;
      const body = JSON.stringify({from:'PARAMANT <privacy@paramant.app>',to:[d.email],subject:'Your PARAMANT API key',html});
      const resp = await new Promise((resolve,reject) => {
        const rq = https.request({hostname:'api.resend.com',path:'/emails',method:'POST',headers:{'Authorization':`Bearer ${RESEND_KEY}`,'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}}, r => { let data=''; r.on('data',c=>data+=c); r.on('end',()=>{try{resolve(JSON.parse(data));}catch(e){resolve({raw:data});}}); });
        rq.on('error',reject); rq.write(body); rq.end();
      });
      if (resp.id) { log('info','welcome_mail_sent',{email:d.email,id:resp.id}); res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,id:resp.id})); }
      else { log('warn','welcome_mail_failed',{email:d.email,resp}); res.writeHead(502); return res.end(J({error:'Resend error',detail:resp})); }
    } catch(e) { res.writeHead(500); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/team/devices' && req.method === 'GET') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({error:'unauthorized'})); }
    if (!kd.team_id) { res.writeHead(200); return res.end(J({team_id:null,devices:[],message:'Individuele key — geen team'})); }
    const devices = [];
    apiKeys.forEach((v,k) => { if(v.team_id===kd.team_id) devices.push({label:v.label,plan:v.plan,active:v.active,key_preview:k.slice(0,12)+'...'}); });
    res.writeHead(200); return res.end(J({team_id:kd.team_id,devices,count:devices.length}));
  }
  if (path === '/v2/team/add-device' && req.method === 'POST') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({error:'unauthorized'})); }
    if (!kd.team_id) { res.writeHead(403); return res.end(J({error:'Geen team — upgrade naar Pro'})); }
    if (kd.plan === 'dev') { res.writeHead(403); return res.end(J({error:'Team keys vereisen Pro of Enterprise'})); }
    try {
      const d = JSON.parse((await readBody(req,4096)).toString());
      if (!d.label) { res.writeHead(400); return res.end(J({error:'label verplicht'})); }
      const newKey = 'pgp_' + crypto.randomBytes(16).toString('hex');
      apiKeys.set(newKey, {label:d.label,plan:kd.plan,team_id:kd.team_id,active:true,created:new Date().toISOString()});
      log('info','team_device_added',{label:d.label,team:kd.team_id});
      res.writeHead(201); return res.end(J({ok:true,key:newKey,label:d.label,team_id:kd.team_id}));
    } catch(e) { res.writeHead(400); return res.end(J({error:e.message})); }
  }

  if (path === '/v2/key-sector' && req.method === 'GET') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({error:'unauthorized'})); }
    const label = (kd.label||'').toLowerCase();
    const sector = label.includes('legal')?'legal':label.includes('finance')?'finance':label.includes('iot')?'iot':'health';
    res.writeHead(200); return res.end(J({sector,plan:kd.plan,team_id:kd.team_id||null}));
  }

  if (path === '/v2/monitor') {
    const kd = apiKeys.get(apiKey);
    if (!kd?.active) { res.writeHead(401); return res.end(J({error:'Geldige x-api-key vereist'})); }
    const total = stats.inbound, acked = stats.outbound, pending = blobStore.size;
    res.writeHead(200,{'Content-Type':'application/json'}); return res.end(J({ok:true,plan:kd.plan||'free',blobs_in_flight:pending,stats:{inbound:stats.inbound,burned:stats.burned,webhooks_sent:stats.webhooks_sent},delivery:{total,acked,pending,success_rate:total>0?Math.round((acked/total)*1000)/1000:1,avg_latency_ms:0}}));
  }

  res.writeHead(404,{'Content-Type':'application/json'});
  res.end(J({error:'Not found',version:VERSION,docs:'https://paramant.app/docs',endpoints:['POST /v2/pubkey','GET /v2/pubkey/:device','POST /v2/inbound','GET /v2/outbound/:hash','GET /v2/status/:hash','POST /v2/webhook','GET /v2/stream-next','GET /v2/audit','GET /health','GET /metrics']}));
});

const wsClients = new Map();
try {
  const { WebSocketServer } = require('ws');
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const parsed = url_.parse(req.url, true);
    if (parsed.pathname !== '/v2/stream') return socket.destroy();
    let wsApiKey = (req.headers['x-api-key']||'').trim();
    if (!wsApiKey && parsed.query.ticket) {
      const td = wsTickets.get(parsed.query.ticket);
      if (td && Date.now() < td.expires) { wsApiKey = td.apiKey; wsTickets.delete(parsed.query.ticket); }
    }
    if (!wsApiKey && parsed.query.k) { wsApiKey = parsed.query.k; log('warn','ws_legacy_key_in_url',{hint:'Use POST /v2/ws-ticket — ?k= deprecated'}); }
    if (!apiKeys.get(wsApiKey)?.active) return socket.destroy();
    wss.handleUpgrade(req, socket, head, ws => {
      if (!wsClients.has(wsApiKey)) wsClients.set(wsApiKey, new Set());
      wsClients.get(wsApiKey).add(ws);
      ws.send(JSON.stringify({type:'connected',ts:new Date().toISOString()}));
      ws.on('close', () => wsClients.get(wsApiKey)?.delete(ws));
    });
  });
  global.wsPush = (apiKey, event) => {
    const clients = wsClients.get(apiKey);
    if (!clients) return;
    const msg = JSON.stringify({type:'blob_ready',...event,ts:new Date().toISOString()});
    for (const ws of clients) { try { ws.send(msg); } catch {} }
  };
  log('info','websocket_streaming_active',{endpoint:'/v2/stream'});
} catch(e) { global.wsPush = () => {}; log('warn','ws_not_available',{hint:'npm install ws'}); }

loadUsers();
loadCtLog();
server.listen(PORT, '127.0.0.1', () => {
  log('info','relay_started',{port:PORT,version:VERSION,sector:SECTOR,mode:RELAY_MODE,dsa:!!mlDsa,protocol:'ghost-pipe-v2'});
});
process.on('SIGTERM', () => {
  for (const [,e] of blobStore) { try { e.blob.fill(0); } catch {} }
  log('info','shutdown_clean',{burned:stats.burned});
  process.exit(0);
});
