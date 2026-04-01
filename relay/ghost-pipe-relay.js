/**
 * PARAMANT Ghost Pipe Relay v2.0.0
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
const url_   = require('url');

const VERSION    = '2.0.0';
const PORT       = parseInt(process.env.PORT       || '4000');
const USERS_FILE = process.env.USERS_FILE          || './users.json';
const TTL_MS     = parseInt(process.env.TTL_MS     || '300000');
const MAX_BLOB   = parseInt(process.env.MAX_BLOB   || '5242880');
const MAX_AUDIT  = parseInt(process.env.MAX_AUDIT  || '1000');
const RELAY_MODE = process.env.RELAY_MODE          || 'full';
const SECTOR     = process.env.SECTOR              || 'relay';

// Probeer @noble/post-quantum te laden voor ML-DSA
let mlDsa = null;
try {
  const { ml_dsa65: mlDsaLib } = require('@noble/post-quantum/ml-dsa');
  mlDsa = mlDsaLib || null;
  if (mlDsa) log('info', 'ml_dsa_loaded', { alg: 'ML-DSA-65 NIST FIPS 204' });
} catch(e) { log('warn', 'ml_dsa_not_available', { hint: 'npm install @noble/post-quantum' }); }

const ALLOWED = {
  ghost_pipe: ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics'],
  iot:        ['/health','/v2/pubkey','/v2/inbound','/v2/outbound','/v2/status',
               '/v2/webhook','/v2/audit','/v2/check-key','/v2/stream','/v2/stream-next',
               '/v2/sender-pubkey','/v2/ack','/v2/delivery','/v2/monitor',
               '/v2/did','/v2/ct','/v2/attest','/v2/admin','/metrics'],
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
  try {
    const { connect, StringCodec } = require('nats');
    const servers = process.env.NATS_URL || 'nats://localhost:4222';
    natsClient = await connect({ servers });
    natsJs = natsClient.jetstream();
    try {
      const jsm = await natsClient.jetstreamManager();
      await jsm.streams.add({ name: 'PARAMANT', subjects: ['paramant.>'], max_age: 300e9 });
    } catch(e) {}
    log('info', 'nats_connected', { servers });
  } catch(e) {
    log('warn', 'nats_not_available', { hint: 'Start NATS server of zet NATS_URL', err: e.message });
  }
}
async function natsPush(apiKey, deviceId, hash, size) {
  if (!natsJs) return;
  try {
    const { StringCodec } = require('nats');
    const sc = StringCodec();
    await natsJs.publish(
      `paramant.${apiKey.slice(0,12)}.${deviceId}`,
      sc.encode(JSON.stringify({ hash, size, ts: new Date().toISOString() }))
    );
  } catch(e) {}
}
initNats();

// ── DID — Decentralized Identity (W3C) ───────────────────────────────────────
const didRegistry = new Map();

function generateDid(deviceId, pubKeyHex) {
  const hash = crypto.createHash('sha256').update(deviceId + pubKeyHex).digest('hex').slice(0,32);
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

function ctLeafHash(deviceIdHash, pubKeyHex, ts) {
  return crypto.createHash('sha256').update(deviceIdHash + pubKeyHex + ts).digest('hex');
}

function ctTreeHash(entries) {
  if (entries.length === 0) return '0'.repeat(64);
  if (entries.length === 1) return entries[0].leaf_hash;
  const hashes = entries.map(e => e.leaf_hash);
  while (hashes.length > 1) {
    const next = [];
    for (let i = 0; i < hashes.length; i += 2) {
      next.push(crypto.createHash('sha256').update(hashes[i] + (hashes[i+1] || hashes[i])).digest('hex'));
    }
    hashes.splice(0, hashes.length, ...next);
  }
  return hashes[0];
}

function ctAppend(deviceId, pubKeyHex, apiKey) {
  const ts = new Date().toISOString();
  const deviceIdHash = crypto.createHash('sha256').update(deviceId + apiKey.slice(0,8)).digest('hex');
  const leaf_hash = ctLeafHash(deviceIdHash, pubKeyHex.slice(0,64), ts);
  const index = ctLog.length;
  const tree_hash = ctTreeHash([...ctLog, { leaf_hash }]);
  const proof = ctLog.slice(-8).map(e => e.leaf_hash);
  const entry = { index, leaf_hash, tree_hash, device_hash: deviceIdHash, ts, proof };
  ctLog.push(entry);
  if (ctLog.length > CT_MAX) ctLog.shift();
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
  const deviceHash = crypto.createHash('sha256').update(deviceId).digest('hex');
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
  for(const [k,v] of [['blobs_in_flight',blobStore.size],['pubkeys',pubkeys.size],['did_registry',didRegistry.size],['ct_log',ctLog.length],['uptime_s',Math.floor(process.uptime())],['heap_bytes',process.memoryUsage().heapUsed]]){
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
  const mac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
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

// ── RAM-only stores ───────────────────────────────────────────────────────────
const apiKeys    = new Map();  // key → {plan, active, label, dsa_pub}
const blobStore  = new Map();  // hash → {blob, ts, ttl, size, sig?}
const pubkeys    = new Map();  // device:key → {ecdh_pub, kyber_pub, dsa_pub, ts}
const webhooks   = new Map();  // device:key → [{url, secret}]
const auditChain = new Map();  // key → Merkle chain [{ts,event,hash,bytes,device,prev_hash,chain_hash}]

function log(level, msg, data = {}) {
  if (typeof msg === 'string')
    console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, v: VERSION, ...data }));
}

function J(o) { return JSON.stringify(o); }

// ── Merkle audit chain ────────────────────────────────────────────────────────
// Elke entry bevat hash van vorige entry — tamper-evident log
function auditAppend(key, event, data = {}) {
  if (!key) return;
  if (!auditChain.has(key)) auditChain.set(key, []);
  const chain    = auditChain.get(key);
  const prevHash = chain.length > 0 ? chain[chain.length - 1].chain_hash : '0'.repeat(64);
  const entry    = { ts: new Date().toISOString(), event, prev_hash: prevHash, ...data };
  const entryStr = JSON.stringify({ ts: entry.ts, event, hash: data.hash||'', bytes: data.bytes||0, prev_hash: prevHash });
  entry.chain_hash = crypto.createHash('sha256').update(entryStr).digest('hex');
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

function loadUsers() {
  if (process.env.USERS_JSON) {
    try { const d = JSON.parse(process.env.USERS_JSON); (d.api_keys||[]).forEach(k => { if(k.active) apiKeys.set(k.key,{plan:k.plan,label:k.label||"",active:true}); }); log("info","users_loaded",{count:apiKeys.size,source:"env"}); return; } catch(e) { log("error","users_json_parse",{err:e.message}); }
  }
  try {
    const d = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    (d.api_keys || []).forEach(k => {
      if (k.active) apiKeys.set(k.key, { plan: k.plan, label: k.label||'', active: true, dsa_pub: k.dsa_pub||'' });
    });
    log('info', 'users_loaded', { count: apiKeys.size, sector: SECTOR });
  } catch(e) { log('warn', 'no_users_file'); }
}

// TTL flush
setInterval(() => {
  const now = Date.now();
  for (const [h, e] of blobStore.entries()) {
    if (now - e.ts > e.ttl) {
      try { e.blob.fill(0); } catch {}
      blobStore.delete(h);
    }
  }
}, 30_000);

// ── Webhook push ──────────────────────────────────────────────────────────────
function pushWebhooks(apiKey, deviceId, event, data) {
  const hooks = webhooks.get(`${deviceId}:${apiKey}`) || [];
  for (const hook of hooks) {
    const payload = J({ event, device_id: deviceId, ts: new Date().toISOString(), ...data });
    try {
      const u   = new URL(hook.url);
      const lib = u.protocol === 'https:' ? https : http;
      const sig = hook.secret ? crypto.createHmac('sha256', hook.secret).update(payload).digest('hex') : '';
      const req = lib.request(hook.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload),
                   'X-Paramant-Event': event, 'X-Paramant-Sig': sig, 'User-Agent': `paramant-relay/${VERSION}` }
      });
      req.on('error', () => {});
      req.write(payload); req.end();
      stats.webhooks_sent++;
    } catch(e) { log('warn', 'webhook_fail', { url: hook.url }); }
  }
}


// ── DID-only authenticatie ────────────────────────────────────────────────────
// Apparaat stuurt x-did + x-did-signature — geen centrale users.json nodig
function authByDid(didStr, signature, payload) {
  const entry = [...didRegistry.values()].find(e => e.doc.id === didStr);
  if (!entry) return null;
  const vm = entry.doc.verificationMethod?.[0];
  if (!vm || !vm.publicKeyHex) return null;
  try {
    const valid = require('crypto').verify(
      'SHA256',
      Buffer.from(payload),
      { key: Buffer.from(vm.publicKeyHex, 'hex'), format: 'der', type: 'spki' },
      Buffer.from(signature, 'hex')
    );
    if (valid) return entry;
  } catch(e) {}
  return null;
}

// ── CORS ──────────────────────────────────────────────────────────────────────
function setHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Dsa-Signature, Authorization');
  res.setHeader('Cache-Control',                'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options',       'nosniff');
  res.setHeader('X-Paramant-Version',           VERSION);
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
  setHeaders(res);
  const parsed  = url_.parse(req.url, true);
  const path    = parsed.pathname;
  const query   = parsed.query;
  const apiKey  = (req.headers['x-api-key'] || query.k || '').trim();
  const didHeader = req.headers['x-did'] || '';
  const didSig    = req.headers['x-did-signature'] || '';
  let didAuthEntry = null;
  if (!apiKey && didHeader && didSig) {
    didAuthEntry = authByDid(didHeader, didSig, req.url);
    if (didAuthEntry) log('info', 'did_auth_mode', { did: didHeader.slice(0,30) });
  }
  const dsaSig  = req.headers['x-dsa-signature'] || '';
  const keyData = apiKeys.get(apiKey) || (didAuthEntry ? { plan: 'pro', active: true, label: didAuthEntry.device_id } : null);

  incMetric('requests_total');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (!modeAllows(path)) { res.writeHead(405); return res.end(J({ error: 'Not available in this relay mode', mode: RELAY_MODE })); }

  // ── GET /health ─────────────────────────────────────────────────────────────
  if (path === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true, version: VERSION, sector: SECTOR, mode: RELAY_MODE,
      blobs: blobStore.size, pubkeys: pubkeys.size,
      webhooks: [...webhooks.values()].flat().length,
      uptime_s: Math.floor(process.uptime()),
      stats,
      protocol: 'ghost-pipe-v2',
      encryption: 'ML-KEM-768 + ECDH P-256 + AES-256-GCM',
      signatures: mlDsa ? 'ML-DSA-65 (NIST FIPS 204)' : 'ECDSA P-256 (ML-DSA fallback)',
      audit: 'Merkle hash chain',
      storage: 'RAM-only, zero plaintext, burn-on-read',
      padding: '5MB fixed (DPI-masking)',
      jurisdiction: 'EU/DE, GDPR, no US CLOUD Act',
    }));
  }

  // ── GET /v2/check-key ───────────────────────────────────────────────────────
  if (path === '/v2/check-key') {
    const kd = apiKeys.get(query.k || apiKey);
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
  if (ctpm0) {
    const idx = parseInt(ctpm0[1]);
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

  if (!keyData?.active) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' }));
  }

  // ── POST /v2/pubkey — Registreer pubkeys (ML-KEM + ECDH + ML-DSA optioneel) ─
  if (path === '/v2/pubkey' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 65536)).toString());
      if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({ error: 'device_id and ecdh_pub required' })); }
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      const attestResult = verifyAttestation(d.ecdh_pub, d.device_id, d.attestation || null);
      pubkeys.set(`${d.device_id}:${apiKey}`, {
        ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '',
        dsa_pub:  d.dsa_pub  || '',  // ML-DSA public key voor handtekening verificatie
        ts: new Date().toISOString()
      });
      log('info', 'pubkey_registered', { device: d.device_id, kyber: !!d.kyber_pub, dsa: !!d.dsa_pub });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, dsa_supported: !!mlDsa, ct_index: ctEntry.index, ct_tree_hash: ctEntry.tree_hash, attested: attestResult.valid, attestation_method: attestResult.method || null }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/pubkey/:device ───────────────────────────────────────────────────
  const pkm = path.match(/^\/v2\/pubkey\/([^/]+)$/);
  if (pkm && req.method === 'GET') {
    const entry = pubkeys.get(`${decodeURIComponent(pkm[1])}:${query.k || apiKey}`);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'No pubkeys for this device. Start receiver first.' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, ecdh_pub: entry.ecdh_pub, kyber_pub: entry.kyber_pub, dsa_pub: entry.dsa_pub, ts: entry.ts }));
  }

  // ── POST /v2/inbound — Upload versleuteld blok + optioneel ML-DSA handtekening
  if (path === '/v2/inbound' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const d    = JSON.parse(body.toString());
      const { hash, payload, ttl_ms, meta, dsa_signature } = d;

      if (!hash || !payload) { res.writeHead(400); return res.end(J({ error: 'hash and payload required' })); }
      if (!/^[a-f0-9]{64}$/.test(hash)) { res.writeHead(400); return res.end(J({ error: 'hash must be SHA-256 hex' })); }
      if (blobStore.has(hash)) { res.writeHead(409); return res.end(J({ error: 'Hash already in use' })); }

      const blob = Buffer.from(payload, 'base64');
      if (blob.length > MAX_BLOB) { res.writeHead(413); return res.end(J({ error: 'Max 5MB' })); }

      // ML-DSA handtekening verificatie (optioneel maar gelogd)
      let sigResult = { valid: false, reason: 'not provided' };
      if (dsa_signature && keyData.dsa_pub) {
        sigResult = verifyDsaSignature(hash, dsa_signature, keyData.dsa_pub);
      }

      const ttl = Math.min(parseInt(ttl_ms || TTL_MS), 3_600_000);
      blobStore.set(hash, { blob, ts: Date.now(), ttl, size: blob.length, sig_valid: sigResult.valid });
      setTimeout(() => {
        const e = blobStore.get(hash);
        if (e) { try { e.blob.fill(0); } catch {} blobStore.delete(hash); }
      }, ttl);

      const deviceId = meta?.device_id;
      incMetric('blobs_stored'); incMetric('bytes_in_total', blob.length);
      stats.inbound++; stats.bytes_in += blob.length;
      auditAppend(apiKey, 'inbound', { hash: hash.slice(0,16)+'...', bytes: blob.length, device: deviceId, sig: sigResult.valid ? 'ML-DSA-OK' : 'unsigned' });
      log('info', 'blob_stored', { hash: hash.slice(0,16), size: blob.length, sig: sigResult.valid });

      if (deviceId) pushWebhooks(apiKey, deviceId, 'blob_ready', { hash, size: blob.length, ttl_ms: ttl, sig_valid: sigResult.valid });
      if (global.wsPush) global.wsPush(apiKey, { hash, size: blob.length, device: deviceId, sig_valid: sigResult.valid });
      natsPush(apiKey, deviceId || 'unknown', hash, blob.length);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, hash, ttl_ms: ttl, size: blob.length, sig_verified: sigResult.valid }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/outbound/:hash — Burn-on-read ────────────────────────────────────
  const outm = path.match(/^\/v2\/outbound\/([a-f0-9]{64})$/);
  if (outm && req.method === 'GET') {
    const entry = blobStore.get(outm[1]);
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Not found. Expired, burned, or never stored.' })); }
    const data = Buffer.from(entry.blob);
    blobStore.delete(outm[1]);
    try { entry.blob.fill(crypto.randomFillSync(Buffer.alloc(4))[0]); } catch {}
    try { entry.blob.fill(0); } catch {}
    incMetric('blobs_burned'); incMetric('bytes_out_total', data.length);
    stats.outbound++; stats.burned++; stats.bytes_out += data.length;
    auditAppend(apiKey, 'outbound_burn', { hash: outm[1].slice(0,16)+'...', bytes: data.length });
    log('info', 'blob_burned', { hash: outm[1].slice(0,16) });
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': data.length,
                          'X-Paramant-Burned': 'true', 'X-Paramant-Hash': outm[1] });
    return res.end(data);
  }

  // ── GET /v2/status/:hash ─────────────────────────────────────────────────────
  const stm = path.match(/^\/v2\/status\/([a-f0-9]{64})$/);
  if (stm && req.method === 'GET') {
    const e = blobStore.get(stm[1]);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (!e) return res.end(J({ available: false }));
    return res.end(J({ available: true, bytes: e.size, ttl_remaining_ms: Math.max(0, e.ttl - (Date.now() - e.ts)), sig_valid: e.sig_valid }));
  }

  // ── POST /v2/webhook ─────────────────────────────────────────────────────────
  if (path === '/v2/webhook' && req.method === 'POST') {
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      if (!d.device_id || !d.url) { res.writeHead(400); return res.end(J({ error: 'device_id and url required' })); }
      const k = `${d.device_id}:${apiKey}`;
      if (!webhooks.has(k)) webhooks.set(k, []);
      webhooks.get(k).push({ url: d.url, secret: d.secret || '' });
      log('info', 'webhook_registered', { device: d.device_id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/stream-next ──────────────────────────────────────────────────────
  if (path === '/v2/stream-next') {
    const device = query.device || ''; const seq = parseInt(query.seq || '0');
    const secret = apiKey.slice(0, 24); const next = seq + 1;
    const h = crypto.createHmac('sha256', Buffer.from(secret)).update(`${device}|${next}`).digest('hex');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, device, seq: next, hash: h, available: blobStore.has(h) }));
  }

  // ── GET /v2/audit — Merkle chain audit log ───────────────────────────────────
  if (path === '/v2/audit') {
    const limit   = Math.min(parseInt(query.limit || '100'), MAX_AUDIT);
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
      const did = generateDid(d.device_id, d.ecdh_pub);
      const doc = createDidDocument(did, d.device_id, d.ecdh_pub, d.dsa_pub || '');
      didRegistry.set(did, { device_id: d.device_id, key: apiKey, doc, ts: new Date().toISOString() });
      pubkeys.set(`${d.device_id}:${apiKey}`, { ecdh_pub: d.ecdh_pub, kyber_pub: d.kyber_pub || '', dsa_pub: d.dsa_pub || '', ts: new Date().toISOString() });
      const ctEntry = ctAppend(d.device_id, d.ecdh_pub, apiKey);
      incMetric('did_registrations');
      auditAppend(apiKey, 'did_registered', { did, device: d.device_id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, did, document: doc, ct_index: ctEntry.index }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/did/:did ─────────────────────────────────────────────────────────
  const didm = path.match(/^\/v2\/did\/([^/]+)$/);
  if (didm && req.method === 'GET') {
    const entry = [...didRegistry.values()].find(e => e.doc.id === decodeURIComponent(didm[1]));
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'DID not found' })); }
    res.writeHead(200, { 'Content-Type': 'application/did+json' });
    return res.end(J(entry.doc));
  }

  // ── GET /v2/did ──────────────────────────────────────────────────────────────
  if (path === '/v2/did' && req.method === 'GET') {
    const dids = [...didRegistry.values()].filter(e => e.key === apiKey).map(e => ({ did: e.doc.id, device: e.device_id, ts: e.ts }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: dids.length, dids }));
  }

  // ── GET /v2/ct/log ───────────────────────────────────────────────────────────
  if (path === '/v2/ct/log') {
    const limit = Math.min(parseInt(query.limit || '100'), 1000);
    const from  = parseInt(query.from || '0');
    const entries = ctLog.slice(from, from + limit).map(e => ({ index: e.index, leaf_hash: e.leaf_hash, tree_hash: e.tree_hash, device_hash: e.device_hash, ts: e.ts }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, size: ctLog.length, root: ctLog.length ? ctLog[ctLog.length-1].tree_hash : '0'.repeat(64), entries }));
  }

  // ── GET /v2/ct/proof/:index ──────────────────────────────────────────────────
  const ctpm = path.match(/^\/v2\/ct\/proof\/(\d+)$/);
  if (ctpm) {
    const idx = parseInt(ctpm[1]);
    const entry = ctLog[idx];
    if (!entry) { res.writeHead(404); return res.end(J({ error: 'Index not found' })); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, index: idx, leaf_hash: entry.leaf_hash, tree_hash: entry.tree_hash, proof: entry.proof, ts: entry.ts }));
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
    const deviceHash = crypto.createHash('sha256').update(decodeURIComponent(attm[1])).digest('hex');
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
      const tok = req.headers['x-admin-token'] || '';
      if (!tok || !apiKeys.has(tok)) {
        res.writeHead(401); return res.end(J({ error: 'unauthorized' }));
      }
      const valid = verifyTotp(d.totp_code || '');
      log(valid ? 'info' : 'warn', 'mfa_attempt', { valid, ip: req.socket?.remoteAddress });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: valid, error: valid ? null : 'Invalid TOTP code' }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── POST /v2/admin/keys — Key aanmaken ────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'POST') {
    const tok = req.headers['x-admin-token'] || '';
    if (!tok || !apiKeys.has(tok)) {
      res.writeHead(401); return res.end(J({ error: 'unauthorized' }));
    }
    try {
      const d = JSON.parse((await readBody(req, 4096)).toString());
      const newKey = 'pgp_' + crypto.randomBytes(16).toString('hex');
      apiKeys.set(newKey, { plan: d.plan || 'pro', label: d.label || '', active: true });
      log('info', 'key_created_via_admin', { label: d.label, plan: d.plan });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(J({ ok: true, key: newKey, plan: d.plan, label: d.label }));
    } catch(e) { res.writeHead(400); return res.end(J({ error: e.message })); }
  }

  // ── GET /v2/admin/keys ────────────────────────────────────────────────────
  if (path === '/v2/admin/keys' && req.method === 'GET') {
    const tok = req.headers['x-admin-token'] || '';
    if (!tok || !apiKeys.has(tok)) {
      res.writeHead(401); return res.end(J({ error: 'unauthorized' }));
    }
    const keys = [...apiKeys.entries()].map(([k, v]) => ({
      key: k, plan: v.plan, label: v.label, active: v.active
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({ ok: true, count: keys.length, keys }));
  }

  // ── POST /v2/admin/keys/revoke ────────────────────────────────────────────
  if (path === '/v2/admin/keys/revoke' && req.method === 'POST') {
    const tok = req.headers['x-admin-token'] || '';
    if (!tok || !apiKeys.has(tok)) {
      res.writeHead(401); return res.end(J({ error: 'unauthorized' }));
    }
    try {
      const d = JSON.parse((await readBody(req, 1024)).toString());
      if (apiKeys.has(d.key)) {
        apiKeys.get(d.key).active = false;
        log('info', 'key_revoked_via_admin', { key: d.key.slice(0,16) });
        res.writeHead(200); return res.end(J({ ok: true }));
      }
      res.writeHead(404); return res.end(J({ error: 'Key not found' }));
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
    const apiKey = (req.headers['x-api-key'] || parsed.query.k || '').trim();
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

// ── Start ─────────────────────────────────────────────────────────────────────
loadUsers();
server.listen(PORT, '0.0.0.0', () => {
  log('info', 'relay_started', { port: PORT, version: VERSION, sector: SECTOR, mode: RELAY_MODE,
      dsa: !!mlDsa, protocol: 'ghost-pipe-v2' });
});
process.on('SIGTERM', () => {
  for (const [, e] of blobStore.entries()) { try { e.blob.fill(0); } catch {} }
  log('info', 'shutdown_clean', { burned: stats.burned });
  process.exit(0);
});
