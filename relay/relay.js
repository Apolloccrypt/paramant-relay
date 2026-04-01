// ══════════════════════════════════════════════════════════════════
//  PARAMANT RELAY v5.2 — Multi-room + Hardened
//  Fixes v5.2:
//   - Multi-room per WS (presence + chatrooms gelijktijdig)
//   - roomBuffer 60s TTL (was direct gewist)
//   - seq bounds check
//   - chatsSeen periodic cleanup
//   - MAX_ROOMS_PER_CONN cap
//   - bcastRoom() helper voor expliciete room-routing
// ══════════════════════════════════════════════════════════════════
'use strict';
const WebSocket = require('ws');
const http      = require('http');

// ── Config ─────────────────────────────────────────────────────────
const PORT              = parseInt(process.env.PORT          || '8080', 10);
const TRANSFER_MODE = process.env.TRANSFER_MODE || 'document';
const STREAM_MAX_BLOCK = parseInt(process.env.STREAM_MAX_BLOCK || String(512 * 1024));
const STREAM_TTL_MS    = parseInt(process.env.STREAM_TTL_MS    || '60000');
const streamBlobs = new Map();

// ─── Stripe Webhook HMAC verificatie ──────────────────────────────────────
function verifyStripeSignature(body, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  try {
    // Parse stripe-signature header: t=timestamp,v1=signature[,v1=signature2]
    const parts = sigHeader.split(',');
    let timestamp = null;
    const signatures = [];
    for (const part of parts) {
      if (part.startsWith('t=')) timestamp = part.slice(2);
      if (part.startsWith('v1=')) signatures.push(part.slice(3));
    }
    if (!timestamp || signatures.length === 0) return false;

    // Reject timestamps older than 5 minutes (replay attack protection)
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(Date.now() / 1000 - ts) > 300) {
      log('warn', 'stripe_replay_attack', { ts, now: Date.now() / 1000 });
      return false;
    }

    // Compute expected signature: HMAC-SHA256(secret, timestamp + '.' + body)
    const crypto = require('crypto');
    const signedPayload = timestamp + '.' + body.toString();
    const expected = crypto
      .createHmac('sha256', secret)
      .update(signedPayload, 'utf8')
      .digest('hex');

    // Constant-time compare against all provided signatures
    return signatures.some(sig => {
      try {
        return crypto.timingSafeEqual(
          Buffer.from(expected, 'hex'),
          Buffer.from(sig, 'hex')
        );
      } catch { return false; }
    });
  } catch (e) {
    log('warn', 'stripe_sig_error', { error: e.message });
    return false;
  }
}

function streamCleanup() {
  const now = Date.now();
  for (const [h, b] of streamBlobs.entries()) {
    if (now - b.ts > STREAM_TTL_MS) streamBlobs.delete(h);
  }
}
setInterval(streamCleanup, 10000);

// ─── Admin Rate Limiter ────────────────────────────────────────────────────
const adminRateMap = new Map(); // ip → { count, window_start }
const ADMIN_RATE_LIMIT = 10;    // Max requests per minuut
const ADMIN_RATE_WINDOW = 60000; // 1 minuut

function adminRateLimit(ip) {
  const now = Date.now();
  const entry = adminRateMap.get(ip) || { count: 0, window_start: now };
  if (now - entry.window_start > ADMIN_RATE_WINDOW) {
    // Reset window
    entry.count = 1;
    entry.window_start = now;
  } else {
    entry.count++;
  }
  adminRateMap.set(ip, entry);
  if (entry.count > ADMIN_RATE_LIMIT) {
    log('warn', 'admin_rate_limit', { ip, count: entry.count });
    return false;
  }
  return true;
}

// Cleanup rate map elke 5 minuten
setInterval(() => {
  const cutoff = Date.now() - ADMIN_RATE_WINDOW * 2;
  for (const [ip, e] of adminRateMap.entries()) {
    if (e.window_start < cutoff) adminRateMap.delete(ip);
  }
}, 300000);


const RELAY_MODE = process.env.RELAY_MODE || 'full';
const ALLOWED_PATHS = {
  ghost_pipe: ['/health', '/v2/inbound', '/v2/outbound', '/v2/status', '/v2/verify-key', '/v2/check-key', '/v2/stream', '/v2/stream-next', '/v2/subscribe', '/v2/events', '/v2/audit', '/v2/pubkey', '/admin/provision-key', '/admin/users', '/admin/stripe-webhook', '/admin/stripe-checkout'],
  iot:        ['/health', '/v2/inbound', '/v2/outbound', '/v2/status', '/v2/verify-key', '/v2/check-key', '/v2/stream', '/v2/stream-next', '/v2/subscribe', '/v2/events', '/v2/audit', '/v2/pubkey', '/admin/provision-key', '/admin/users'],
  full:       null
};

function normalizePath(rawPath) {
  try {
    // Gebruik URL normalisatie om path traversal te voorkomen
    const url = new URL(rawPath, 'http://relay.internal');
    return url.pathname;
  } catch {
    return null;
  }
}

function modeAllows(rawPath) {
  if (RELAY_MODE === 'full') return true;
  const allowed = ALLOWED_PATHS[RELAY_MODE];
  if (!allowed) return true;
  const path = normalizePath(rawPath);
  if (!path) return false; // Ongeldige URL → blokkeer
  // Exacte match of sub-path (met normalisatie)
  return allowed.some(function(p) {
    return path === p || (p.endsWith('/') && path.startsWith(p));
  });
}

const ALLOWED_ORIGIN    = process.env.ALLOWED_ORIGIN         || 'https://paramant.app';
const MAX_PKT           = 14 * 1024 * 1024;
const RATE_WIN          = 10_000;
const RATE_MAX          = 50;
const PRES_WIN          = 30_000;
const PRES_MAX          = 6;
const MAX_ROOMS_PER_CONN= 12;    // max rooms per WS (1 presence + max 10 chats + 1 spare)
const MAX_PEERS         = 10;
const MAX_CONNS_IP      = 20;
const MAX_CONNS         = 500;
const PING_IV           = 25_000;
const MAX_LED           = 300;
const MAX_CHAT_LED      = 50;
const HTTP_RATE_WIN     = 60_000;
const HTTP_RATE_MAX     = 300; // 5/sec — monitoring tools werken correct
const VERSION           = '5.6.0';
const BOOT              = Date.now();

// ── State ───────────────────────────────────────────────────────────
let totalMsgs = 0, totalBytes = 0, abuseBlocked = 0;
const ledger    = [];
// Audit log per API key — Ghost Pipe + stream transfers
const auditLog  = new Map(); // apiKey → [{ts, event, hash, bytes, direction, device}]
const MAX_AUDIT = 500; // max entries per key

function auditPush(apiKey, event, data) {
  if (!apiKey) return;
  if (!auditLog.has(apiKey)) auditLog.set(apiKey, []);
  const entries = auditLog.get(apiKey);
  entries.push({
    ts:        new Date().toISOString(),
    event,
    hash:      (data.hash  || '').slice(0, 16) + '...',
    bytes:     data.bytes  || data.size || 0,
    direction: data.direction || event,
    device:    data.device || null,
    seq:       data.seq    || null,
    ttl_ms:    data.ttl_ms || null,
  });
  if (entries.length > MAX_AUDIT) entries.shift();
}
const rooms     = new Map();   // roomName → Set<ws>

// ── Invite rooms ─────────────────────────────────────────────────────────────
const inviteRooms = new Map(); // token → { creatorApiKey, expires, lastActivity }

function sanitizeToken(t) {
  if (typeof t !== 'string') return null;
  const c = t.replace(/[^a-zA-Z0-9]/g, '').slice(0, 48);
  return c.length === 32 ? c : null;
}
function invRoomKey(token) { return 'inv_' + token; }
function isInvRoom(r)      { return typeof r === 'string' && r.startsWith('inv_'); }
function cleanInvRoom(token) {
  const rk = invRoomKey(token);
  inviteRooms.delete(token);
  const s = rooms.get(rk);
  if (s) { s.forEach(c => { try { c.close(1001, 'Room closed'); } catch {} }); rooms.delete(rk); }
  roomBuffer.delete(rk);
}
setInterval(() => {
  const now = Date.now();
  for (const [t, m] of inviteRooms) {
    if (now > m.expires || now - m.lastActivity > 30 * 60_000) cleanInvRoom(t);
  }
}, 5 * 60_000);

// ── Ghost Pipe Mempool ────────────────────────────────────────────
// RAM-only, burn-on-read, TTL 300s, tot 5MB per pakket
const gpMempool    = new Map();
const pendingBurn  = new Map(); // hash → { blob, timer, ts } wacht op ACK
const GP_TTL      = 300_000;
const GP_MAX_BLOB      = 5 * 1024 * 1024;
const GP_MAX_BODY_SIZE = Math.ceil(GP_MAX_BLOB * 1.4) + 8192; // base64 overhead + JSON
let   gpTotalIn   = 0;
let   gpTotalOut  = 0;
let   gpBurned    = 0;

// ── API Key Usage Tracking ────────────────────────────────────────
// Map<apiKey, {plan, label, in, out, bytes_in, bytes_out, created, last_used}>
const apiKeys = new Map();
const API_KEY_PREFIX = 'pgp_';


// ══════════════════════════════════════════════════════════════
//  USER STORAGE — Betaalde gebruikers en API keys
//  Opgeslagen in /home/paramant/users.json (persistent)
// ══════════════════════════════════════════════════════════════
const fs   = require('fs');
const path = require('path');

const USERS_FILE = process.env.USERS_FILE || '/home/paramant/users.json';


// ──────────────────────────────────────────────────────────────
//  EMAIL DELIVERY — Mailgun (stel MAILGUN_API_KEY in .env in)
// ──────────────────────────────────────────────────────────────
async function sendApiKeyEmail(email, apiKey, plan) {
  if (!email || !apiKey) return;
  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) {
    log('warn', 'email_skip', { reason: 'RESEND_API_KEY niet geconfigureerd', email });
    return;
  }
  const planLabel = plan === 'kantoor' ? 'Kantoor (€149/mnd)' : 'Pro (€29/mnd)';
  const dlUrl     = `https://relay.paramant.app/dl/paramant-linux-x64?token=${apiKey}`;
  const body = {
    from:    'PARAMANT <noreply@paramant.app>',
    to:      [email],
    subject: `Jouw PARAMANT API Key — ${planLabel}`,
    html: `<!DOCTYPE html>
<html lang="nl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Jouw PARAMANT API Key</title></head>
<body style="margin:0;padding:0;background:#f9fafb;font-family:'JetBrains Mono',ui-monospace,monospace">
<div style="max-width:560px;margin:40px auto;background:#ffffff;border:1px solid #e5e7eb">

  <div style="padding:28px 32px;border-bottom:1px solid #e5e7eb">
    <div style="font-size:16px;font-weight:900;color:#111827;letter-spacing:-.01em">PARAMANT</div>
    <div style="font-size:11px;color:#9ca3af;margin-top:4px;letter-spacing:.06em">POST-QUANTUM DATA TRANSPORT</div>
  </div>

  <div style="padding:32px">
    <div style="font-size:13px;color:#6b7280;margin-bottom:6px;letter-spacing:.06em">JOUW API KEY — ${planLabel.toUpperCase()}</div>
    <div style="font-size:10px;color:#6b7280;margin-bottom:16px">Bewaar deze key veilig. Deel hem nooit.</div>

    <div style="background:#f3f4f6;border:1px solid #e5e7eb;padding:16px;margin-bottom:24px;word-break:break-all">
      <div style="font-size:10px;color:#9ca3af;margin-bottom:8px;letter-spacing:.08em">API KEY</div>
      <div style="font-size:13px;color:#111827;font-weight:700">${apiKey}</div>
    </div>

    <div style="margin-bottom:24px">
      <span style="padding:4px 10px;background:#f0fdf4;border:1px solid #a7f3d0;font-size:10px;color:#065f46;margin-right:6px">✓ Actief</span>
      <span style="padding:4px 10px;background:#f9fafb;border:1px solid #e5e7eb;font-size:10px;color:#6b7280;margin-right:6px">${planLabel}</span>
      <span style="padding:4px 10px;background:#f9fafb;border:1px solid #e5e7eb;font-size:10px;color:#6b7280">ML-KEM-768</span>
    </div>

    <div style="font-size:11px;color:#9ca3af;margin-bottom:10px;letter-spacing:.08em">SNEL STARTEN</div>

    <div style="background:#f9fafb;border:1px solid #e5e7eb;padding:14px;margin-bottom:8px">
      <div style="font-size:10px;color:#9ca3af;margin-bottom:6px">1. Open het dashboard</div>
      <a href="https://paramant.app/dashboard" style="color:#059669;font-size:12px;text-decoration:none">paramant.app/dashboard →</a>
      <div style="font-size:11px;color:#9ca3af;margin-top:4px">Plak uw API key — het dashboard detecteert automatisch uw relay endpoint.</div>
    </div>

    <div style="background:#f9fafb;border:1px solid #e5e7eb;padding:14px;margin-bottom:8px">
      <div style="font-size:10px;color:#9ca3af;margin-bottom:6px">2. CLI</div>
      <div style="font-size:11px;color:#111827">paramant send bestand.pdf --key ${apiKey.slice(0,20)}...</div>
    </div>

    <div style="background:#f9fafb;border:1px solid #e5e7eb;padding:14px;margin-bottom:24px">
      <div style="font-size:10px;color:#9ca3af;margin-bottom:6px">3. REST API</div>
      <div style="font-size:11px;color:#111827">POST relay.paramant.app/v2/inbound</div>
      <div style="font-size:11px;color:#9ca3af">X-Api-Key: ${apiKey.slice(0,20)}...</div>
    </div>

    <a href="https://paramant.app/dashboard" style="display:block;padding:13px 24px;background:#111827;color:#ffffff;text-align:center;font-size:12px;font-weight:700;letter-spacing:.04em;text-decoration:none">OPEN DASHBOARD →</a>
  </div>

  <div style="padding:20px 32px;border-top:1px solid #e5e7eb;background:#f9fafb">
    <div style="font-size:10px;color:#9ca3af;line-height:1.9">
      © 2026 PARAMANT · Business Source License 1.1<br>
      Hetzner Nuremberg (DE) · GDPR · Geen US CLOUD Act<br>
      <a href="https://paramant.app/license" style="color:#9ca3af">Licentie</a> ·
      <a href="https://paramant.app/privacy" style="color:#9ca3af">Privacy</a> ·
      <a href="mailto:privacy@paramant.app" style="color:#9ca3af">privacy@paramant.app</a>
    </div>
  </div>

</div>
</body>
</html>`
  };

  const https = require('https');
  const postData = JSON.stringify(body);
  const req = https.request({
    hostname: 'api.resend.com',
    path: '/emails',
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${resendKey}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  }, r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => {
      if (r.statusCode === 200 || r.statusCode === 201) {
        log('info', 'email_sent', { email, plan });
      } else {
        log('warn', 'email_failed', { email, status: r.statusCode, body: d.slice(0,200) });
      }
    });
  });
  req.on('error', e => log('warn', 'email_error', { error: e.message }));
  req.write(postData);
  req.end();
}

// Laad users bij start
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      // Laad API keys in memory
      (data.api_keys || []).forEach(k => {
        apiKeys.set(k.key, {
          plan:       k.plan,
          label:      k.label,
          limit:      k.limit,
          in:         k.usage_in  || 0,
          out:        k.usage_out || 0,
          bytes_in:   0,
          bytes_out:  0,
          created:    k.created,
          last_used:  k.last_used || null,
          email:      k.email || null,
          stripe_id:  k.stripe_id || null,
          active:     k.active !== false
        });
      });
      log('info', 'users_loaded', { count: data.api_keys?.length || 0 });
    }
  } catch(e) {
    log('warn', 'users_load_error', { error: e.message });
  }
}

function saveUsers() {
  try {
    const data = {
      updated: new Date().toISOString(),
      api_keys: []
    };
    apiKeys.forEach((v, k) => {
      data.api_keys.push({
        key:        k,
        plan:       v.plan,
        label:      v.label,
        limit:      v.limit,
        usage_in:   v.in,
        usage_out:  v.out,
        created:    v.created,
        last_used:  v.last_used,
        email:      v.email,
        stripe_id:  v.stripe_id,
        active:     v.active
      });
    });
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
  } catch(e) {
    log('warn', 'users_save_error', { error: e.message });
  }
}

// Sla op elke 60s en bij nieuwe key
setInterval(saveUsers, 60000);

 // Ghost Pipe key prefix

function validateApiKey(key, clientIp) {
  if (!key || !key.startsWith(API_KEY_PREFIX)) return null;
  const entry = apiKeys.get(key);
  if (!entry) return null;
  if (entry.active === false) return null;

  // IP Pinning — kantoor/enterprise keys kunnen IPs beperken
  if (entry.allowed_ips && entry.allowed_ips.length > 0 && clientIp && clientIp !== 'unknown') {
    const ip = clientIp.split(':').pop(); // IPv4 uit IPv6
    const allowed = entry.allowed_ips.some(allowed => {
      if (allowed.includes('/')) {
        // CIDR check (simpel voor /24 en /16)
        const [net, bits] = allowed.split('/');
        const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
        const ipInt  = ip.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0) >>> 0;
        const netInt = net.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0) >>> 0;
        return (ipInt & mask) === (netInt & mask);
      }
      return ip === allowed;
    });
    if (!allowed) {
      log('warn', 'ip_blocked', { key_prefix: key.slice(0,12), ip, allowed: entry.allowed_ips });
      return { _blocked: true, reason: 'IP niet toegestaan voor dit plan', ip };
    }
  }

  // Plan limieten
  if (entry.limit !== null && entry.limit !== undefined) {
    const used = (entry.usage_in || 0) + (entry.usage_out || 0);
    if (used > entry.limit * 1.1) return null;
  }
  return entry;
}

// Geo/concurrent detectie — key sharing alarm
const keyIpTracker  = new Map(); // key_prefix → { ips: Set, countries: Set, last_alert: ts }
const geoCache      = new Map(); // ip → country code (via CF header)

function trackKeyIp(apiKey, ip, countryCode) {
  if (!apiKey || !ip || ip === 'unknown') return;
  const k = apiKey.slice(0, 16);
  if (!keyIpTracker.has(k)) {
    keyIpTracker.set(k, { ips: new Set(), countries: new Set(), last_alert: 0 });
  }
  const tracker = keyIpTracker.get(k);
  tracker.ips.add(ip);
  if (countryCode) tracker.countries.add(countryCode);

  const now = Date.now();
  // Alert: >10 unieke IPs OF >3 landen binnen 1 uur
  const suspicious = tracker.ips.size > 10 || tracker.countries.size > 3;
  if (suspicious && now - tracker.last_alert > 3600_000) {
    tracker.last_alert = now;
    log('warn', 'key_sharing_suspected', {
      key_prefix:   k,
      unique_ips:   tracker.ips.size,
      countries:    [...tracker.countries].join(','),
      action:       'manual_review_required'
    });
    // TODO: stuur alert email naar admin
  }

  // Reset elke 60 minuten
  setTimeout(() => {
    tracker.ips.delete(ip);
    if (tracker.ips.size === 0) tracker.countries.delete(countryCode);
  }, 3600_000);
}

function trackUsage(key, dir, bytes) {
  const entry = apiKeys.get(key);
  if (!entry) return;
  if (dir === 'in')  { entry.in++;  entry.bytes_in  += bytes; }
  if (dir === 'out') { entry.out++; entry.bytes_out += bytes; }
  entry.last_used = Date.now();
}

// Demo key voor testen — in productie via admin endpoint of database
apiKeys.set('pgp_test_key_dev_only', {
  plan: 'dev', label: 'Development Test Key',
  in: 0, out: 0, bytes_in: 0, bytes_out: 0,
  created: Date.now(), last_used: null,
  monthly_limit: 1000
});

function gpPut(hash, blob) {
  if (gpMempool.has(hash)) {
    clearTimeout(gpMempool.get(hash).timer);
    gpMempool.get(hash).blob.fill(0);
    gpMempool.delete(hash);
  }
  const timer = setTimeout(() => {
    if (gpMempool.has(hash)) {
      gpMempool.get(hash).blob.fill(0);
      gpMempool.delete(hash);
      gpBurned++;
      log('info', 'gp_ttl_burn', { h: hash.slice(0,12) });
    }
  }, GP_TTL);
  gpMempool.set(hash, { blob, ts: Date.now(), timer, size: blob.length });
  gpTotalIn++;
  log('info', 'gp_inbound', { h: hash.slice(0,12), size: blob.length });
  auditPush(apiKey, 'upload', { hash, bytes: blob.length, direction: 'inbound' });
}

function gpGet(hash) {
  const e = gpMempool.get(hash);
  if (!e) return null;
  clearTimeout(e.timer);
  const out = Buffer.from(e.blob); // kopie voor streaming
  gpMempool.delete(hash);
  // PENDING BURN: originele blob blijft in RAM totdat:
  // A) Client stuurt POST /v2/ack/:hash (succesvolle decryptie bevestigd)
  // B) 30 seconden verlopen zijn (timeout — stream kan gefaald zijn)
  // In beide gevallen: blob.fill(0) dan delete
  // Dit is GEEN soft burn: data is al uit gpMempool verwijderd,
  // tweede GET op dezelfde hash geeft 404. pendingBurn is intern cleanup.
  const ackTimer = setTimeout(() => {
    const p = pendingBurn.get(hash);
    if (p) { p.blob.fill(0); pendingBurn.delete(hash); log('info','ack_timeout_zeroed',{hash:hash.slice(0,16)}); }
  }, 30_000);
  pendingBurn.set(hash, { blob: e.blob, timer: ackTimer, ts: Date.now() });
  gpTotalOut++;
  log('info', 'gp_burn_read', { h: hash.slice(0,12), size: e.size });
  return out;
}
const chatsSeen = new Set();
const ipConns   = new Map();
const httpRates = new Map();
const J = o => JSON.stringify(o);
loadUsers(); // laad persistent keys uit users.json

// ── Logging ─────────────────────────────────────────────────────────
function log(level, msg, meta = {}) {
  console.log(J({ ts: new Date().toISOString(), level, msg, ...meta, v: VERSION }));
}
function logAbuse(reason, meta = {}) {
  abuseBlocked++;
  log('warn', 'abuse_blocked', { reason, ...meta });
}

// ── Ledger ──────────────────────────────────────────────────────────
const chatLedgerCount = new Map();
const LEDGER_TTL = 15 * 60 * 1000;

function pruneLedger() {
  const cutoff = Date.now() - LEDGER_TTL;
  while (ledger.length && ledger[0].t < cutoff) {
    const old = ledger.shift();
    chatLedgerCount.set(old.h, Math.max(0, (chatLedgerCount.get(old.h)||1) - 1));
  }
}

function addLedger(h, seq, b) {
  if (!h || h === '__presence__') return;
  pruneLedger();
  const prefix = h.slice(0, 16);
  const cc = chatLedgerCount.get(prefix) || 0;
  if (cc >= MAX_CHAT_LED) return;
  chatLedgerCount.set(prefix, cc + 1);
  ledger.push({ h: prefix, s: seq, b, t: Date.now() });
  if (ledger.length > MAX_LED) {
    const old = ledger.shift();
    chatLedgerCount.set(old.h, Math.max(0, (chatLedgerCount.get(old.h)||1) - 1));
  }
  totalMsgs++; totalBytes += b; chatsSeen.add(prefix);
}

// ── Helpers ─────────────────────────────────────────────────────────
function sanitize(raw) {
  if (typeof raw !== 'string') return null;
  if (raw === '__presence__') return '__presence__';
  if (/^inv_[a-zA-Z0-9]{32}$/.test(raw)) return raw; // invite room key
  const c = raw.toLowerCase().replace(/[^0-9a-f]/g,'').slice(0,64);
  return c.length >= 8 ? c : null;
}
function online() { let n=0; rooms.forEach(s => { n += s.size; }); return n; }
function getIP(req) {
  // Note: x-forwarded-for kan gespoofed worden zonder trusted proxy check.
  // Op Hetzner/Cloudflare: overweeg alleen de LAATSTE hop te vertrouwen.
  return (req.headers['x-forwarded-for']||'').split(',').pop().trim()
    || req.socket?.remoteAddress
    || 'unknown';
}

// ── HTTP rate limiter ────────────────────────────────────────────────
function httpRateOk(ip) {
  const now = Date.now();
  let r = httpRates.get(ip);
  if (!r || now - r.win > HTTP_RATE_WIN) { r = { cnt: 0, win: now }; httpRates.set(ip, r); }
  return ++r.cnt <= HTTP_RATE_MAX;
}
setInterval(() => {
  const now = Date.now();
  httpRates.forEach((v,k) => { if (now - v.win > HTTP_RATE_WIN * 2) httpRates.delete(k); });
}, 300_000);

// ── HTTP API ─────────────────────────────────────────────────────────

// ─── HEARTBEAT LICENSE CHECK (self-hosted relay) ──────────────────────────
// Pings api.paramant.app/license elke 24u om licentie te verifiëren
// Na 3 mislukte checks → read-only modus (outbound werkt, inbound geblokkeerd)

// ─── AIR-GAPPED LICENSE VERIFICATIE ────────────────────────────────────────
// Enterprise: klant krijgt getekend licentiebestand ipv heartbeat
// Format: base64(JSON payload) + '.' + HMAC-SHA256 handtekening
// Geen internetverbinding nodig — relay verifieert lokaal
const AIRGAP_LICENSE = process.env.PARAMANT_AIRGAP_LICENSE || null;
const LICENSE_HMAC_SECRET = 'paramant-license-v1-' + (process.env.ADMIN_TOKEN || '');

function verifyAirgapLicense() {
  if (!AIRGAP_LICENSE) return null;
  try {
    const crypto = require('crypto');
    const [payloadB64, sig] = AIRGAP_LICENSE.split('.');
    if (!payloadB64 || !sig) return null;
    const expected = crypto.createHmac('sha256', LICENSE_HMAC_SECRET)
      .update(payloadB64).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      log('warn', 'airgap_license_invalid_signature', {});
      return null;
    }
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
    if (payload.expires < Date.now()) {
      log('warn', 'airgap_license_expired', { expired: new Date(payload.expires).toISOString() });
      return null;
    }
    log('info', 'airgap_license_valid', { plan: payload.plan, expires: new Date(payload.expires).toISOString() });
    return payload;
  } catch(e) {
    log('warn', 'airgap_license_error', { error: e.message });
    return null;
  }
}

// Admin endpoint: genereer air-gapped licentie
// POST /admin/generate-airgap-license
// Body: { admin_token, plan, valid_days, label }

const IS_SELF_HOSTED  = process.env.PARAMANT_LICENSE_KEY ? true : false;
const LICENSE_KEY     = process.env.PARAMANT_LICENSE_KEY || null;
const LICENSE_API     = 'https://relay.paramant.app/v2/verify-key';
let   licenseValid    = !IS_SELF_HOSTED; // cloud relay altijd geldig
let   licenseMissed   = 0;
const LICENSE_MAX_MISS = 3;

async function checkLicense() {
  if (!IS_SELF_HOSTED) return; // cloud relay: geen check nodig
  // Air-gapped license: geen heartbeat nodig
  if (AIRGAP_LICENSE) {
    const lic = verifyAirgapLicense();
    if (lic) { licenseValid = true; licenseMissed = 0; return; }
    licenseValid = false; return;
  }
  try {
    const https = require('https');
    const body  = JSON.stringify({ api_key: LICENSE_KEY });
    await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'relay.paramant.app',
        path:     '/v2/verify-key',
        method:   'POST',
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'User-Agent': 'paramant-relay-selfhosted/1.0' }
      }, res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          try {
            const r = JSON.parse(d);
            if (r.valid && ['kantoor','enterprise'].includes(r.plan)) {
              licenseValid  = true;
              licenseMissed = 0;
              log('info', 'license_ok', { plan: r.plan });
            } else {
              throw new Error('Licentie ongeldig of plan onvoldoende (vereist: Kantoor/Enterprise)');
            }
          } catch(e) { reject(e); }
          resolve();
        });
      });
      req.on('error', reject);
      req.write(body); req.end();
    });
  } catch(e) {
    licenseMissed++;
    log('warn', 'license_check_failed', { missed: licenseMissed, max: LICENSE_MAX_MISS, error: e.message });
    if (licenseMissed >= LICENSE_MAX_MISS) {
      licenseValid = false;
      log('warn', 'license_readonly_mode', { reason: '3 license checks mislukt — inbound geblokkeerd' });
    }
  }
}

// Controleer bij start en dan elke 24u
if (IS_SELF_HOSTED) {
  checkLicense();
  setInterval(checkLicense, 24 * 3600_000);
  log('info', 'self_hosted_mode', { license_key: LICENSE_KEY?.slice(0,12)+'...' });
}

const srv = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  const ip = getIP(req);
  // Health: altijd bereikbaar, voor rate check
  if (url === '/health' || url === '/healthz') {
    res.setHeader('Access-Control-Allow-Origin','*');
    return res.end(JSON.stringify({
          ok: true,
          uptime_s: Math.floor((Date.now()-BOOT)/1000),
          version: VERSION,
          connections: online(),
          quantum_ready: true, relay_mode: RELAY_MODE,
          algorithms: {
            kem:     'ML-KEM-768 (NIST FIPS 203)',
            classic: 'ECDH P-256',
            sym:     'AES-256-GCM',
            kdf:     'HKDF-SHA-256'
          },
          block_size_bytes: GP_MAX_BLOB,
          burn_on_read: true,
          crypto_version: 'hkdf-sha256-v2-hybrid',
          security_patch: '2026-03-30',
          stream_blobs: streamBlobs.size,
          relay_location: 'Hetzner DE (Nuremberg)'
        }));
  }
  // Publieke read-only API endpoints: wildcard CORS zodat monitoring tools werken
  // WebSocket origin-check blijft strikt (verifyClient)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Admin-Token, X-Hash, X-Filename, X-Size, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const POST_OK = ['/v2/inbound','/v2/verify-key','/admin/provision-key','/admin/stripe-webhook','/admin/stripe-checkout','/v2/webhook','/v2/ack','/admin/generate-airgap-license','/admin/set-ip-pin','/v2/manifest','/admin/users','/v2/stream','/v2/stream-status','/v2/chat/create-room'];

// ─── RELAY RESTRICTION — check allowed_relays per key ─────────────────────
function getRequestHost(req) {
  // Cloudflare tunnel stuurt het originele hostname via Host header
  const h = req.headers['host'] || req.headers['x-forwarded-host'] || '';
  return h.split(':')[0].toLowerCase();
}

function keyAllowedOnRelay(keyData, reqHost) {
  // Als geen allowed_relays ingesteld → key werkt op alle relays (backwards compat)
  if (!keyData.allowed_relays || keyData.allowed_relays.length === 0) return true;
  // relay.paramant.app is altijd toegestaan voor algemene keys
  if (reqHost === 'relay.paramant.app') {
    return keyData.allowed_relays.includes('relay.paramant.app') || 
           keyData.allowed_relays.includes('*');
  }
  return keyData.allowed_relays.includes(reqHost) || 
         keyData.allowed_relays.includes('*');
}
  if (req.method !== 'GET' && !(req.method === 'POST' && POST_OK.includes(url))) {
    res.writeHead(405); return res.end(J({error:'Method not allowed'}));
  }

  // Health: altijd bereikbaar, vóór rate check
  if (url === '/health' || url === '/healthz') {
    res.setHeader('Access-Control-Allow-Origin','*');
    return res.end(JSON.stringify({ ok:true, uptime_s:Math.floor((Date.now()-BOOT)/1000), version:VERSION, connections:online() }));
  }

  if (url !== '/health' && url !== '/healthz') {
    if (!httpRateOk(ip)) {
      logAbuse('http_rate_limit', { ip, url });
      res.writeHead(429); return res.end(J({error:'Too many requests'}));
    }
  }


  if (url === '/') {
    return res.end(J({ service:'PARAMANT Relay', version:VERSION, note:'Zero plaintext. Hash prefix + size + timestamp only.' }));
  }
  if (url === '/api/stats') {
    return res.end(J({ ok:true, messages:totalMsgs, bytes:totalBytes, chats:chatsSeen.size, online:online(), abuse_blocked:abuseBlocked, uptime_s:Math.floor((Date.now()-BOOT)/1000), version:VERSION, next_flush_ts:nextFlushTs(), gp_mempool:gpMempool.size, gp_total_in:gpTotalIn, gp_total_out:gpTotalOut }));
  }
  if (url === '/api/ledger') {
    pruneLedger();
    return res.end(J({ ok:true, count:ledger.length, entries:ledger.slice(-50).reverse().map(e=>({ chatHash:e.h+'…', seq:e.s, bytes:e.b, timestamp:e.t, iso:new Date(e.t).toISOString() })) }));
  }
  const m = url.match(/^\/api\/ledger\/([0-9a-f]{4,64})$/i);
  if (m) {
    const px = m[1].toLowerCase();
    const entries = ledger.filter(e=>e.h.startsWith(px)).slice(-50).reverse().map(e=>({ chatHash:e.h+'…', seq:e.s, bytes:e.b, timestamp:e.t }));
    return res.end(J({ ok:true, chatHashPrefix:px, count:entries.length, entries }));
  }
  // ════════════════════════════════════════════════════════════
  //  GHOST PIPE v2 — Post-quantum stateless file transport
  //  Burn-on-read · RAM-only · TTL 300s · Max 5MB
  // ════════════════════════════════════════════════════════════

  // POST /v2/inbound — Push encrypted blob
  if (url === '/v2/inbound' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', chunk => {
      body = Buffer.concat([body, chunk]);
      if (body.length > GP_MAX_BODY_SIZE) {
        req.destroy();
        res.writeHead(413); res.end(J({ error: 'Payload too large', max: GP_MAX_BLOB }));
      }
    });
    req.on('end', () => {
      try {
        let data, hash, b64;
        const ct = (req.headers['content-type'] || '').toLowerCase();

        if (ct.includes('application/octet-stream')) {
          // Binary upload: X-Hash header + raw body (geen base64 overhead)
          hash = (req.headers['x-hash'] || '').trim();
          // Converteer binary direct naar base64 voor interne opslag
          b64 = body.toString('base64');
          data = { hash, payload: b64, api_key: req.headers['x-api-key'] || '' };
        } else {
          data = JSON.parse(body.toString('utf8'));
          hash = (data.hash || '').trim();
          b64  = data.payload || '';
        }
        const apiKey = (data.api_key || req.headers['x-api-key'] || '').trim();
        const clientIp0 = req.headers['cf-connecting-ip'] || req.socket?.remoteAddress || 'unknown';
        const keyEntry = apiKey ? validateApiKey(apiKey, clientIp0) : null;

        // ── PAYWALL LOGICA ────────────────────────────────────
        // 1. Ghost Pipe vereist altijd een API key — check EERST
        if (!apiKey) {
          res.writeHead(402);
          return res.end(J({
            error: 'Ghost Pipe vereist een API key',
            info: 'Ghost Pipe is een betaalde dienst. De gratis chat werkt zonder key.',
            upgrade: 'https://paramant.app/#pricing',
            plans: { pro: '€29/mnd', kantoor: '€149/mnd' }
          }));
        }

        // 2. API key opgegeven maar ongeldig → blokkeer
        if (keyEntry && keyEntry._blocked) {
          res.writeHead(403);
          return res.end(J({ error: keyEntry.reason, ip: keyEntry.ip, upgrade: 'https://paramant.app' }));
        }
        if (apiKey && !keyEntry) {
          res.writeHead(401);
          return res.end(J({ error: 'Ongeldige of verlopen API key', upgrade: 'https://paramant.app/#pricing' }));
        }

        // Bereken payload grootte
        const payloadBytes = Math.ceil(b64.length * 3 / 4);

        // 3. Ghost Pipe key aanwezig — check plan limieten
        if (!keyEntry) {
          res.writeHead(402);
          return res.end(J({
            error: 'Ghost Pipe vereist een API key',
            info: 'Ghost Pipe is een betaalde dienst. De chat is gratis.',
            upgrade: 'https://paramant.app/#pricing',
            upgrade_cta: 'Pro plan €29/mnd — API key inbegrepen'
          }));
        }

        // 3. Pro tier: max 500MB (100 blokken × 5MB)
        const PRO_MAX = 100 * 5 * 1024 * 1024;
        if (keyEntry && keyEntry.plan === 'pro' && payloadBytes > PRO_MAX) {
          res.writeHead(402);
          return res.end(J({
            error: 'Pro plan: max 500MB per transfer',
            upgrade: 'https://paramant.app/#pricing',
            upgrade_cta: 'Kantoor plan €149/mnd voor tot 2GB'
          }));
        }

        // Ghost Pipe is betaald — geen gratis rate limit nodig

        // 5. Limiet check voor betaalde keys
        if (keyEntry) {
          const used = (keyEntry.in || 0) + (keyEntry.out || 0);
          if (keyEntry.limit !== Infinity && used >= keyEntry.limit) {
            res.writeHead(402);
            return res.end(J({
              error: 'Maandlimiet bereikt',
              used, limit: keyEntry.limit,
              upgrade: 'https://paramant.app/#pricing'
            }));
          }
          trackUsage(apiKey, 'in', payloadBytes);
          saveUsers();
        }
        // ── EINDE PAYWALL ─────────────────────────────────────

        // X-Block-Index header support (manifest blocks)
        const manifestHash  = data.manifest_hash || req.headers['x-manifest-hash'] || null;
        const blockIndex    = data.block_index !== undefined
          ? parseInt(data.block_index)
          : parseInt(req.headers['x-block-index'] || '-1');

        // Als manifest opgegeven: genereer blok-hash automatisch
        if (manifestHash && blockIndex >= 0 && !hash) {
          const crypto = require('crypto');
          hash = crypto.createHash('sha256')
            .update(manifestHash + ':' + blockIndex)
            .digest('hex');
        }

        if (!hash || hash.length < 32) {
          res.writeHead(400); return res.end(J({ error: 'hash vereist (min 32 hex)' }));
        }
        if (!b64) {
          res.writeHead(400); return res.end(J({ error: 'payload vereist' }));
        }
        if (gpMempool.has(hash)) {
          res.writeHead(409); return res.end(J({ error: 'Hash al in gebruik' }));
        }

        const blob = Buffer.from(b64, 'base64');
        if (blob.length !== GP_MAX_BLOB) {
          res.writeHead(400);
          return res.end(J({ error: `Payload moet exact ${GP_MAX_BLOB} bytes zijn (ontvangen: ${blob.length})` }));
        }

        const timer = setTimeout(() => {
          const e = gpMempool.get(hash);
          if (e) { e.blob.fill(0); gpMempool.delete(hash); log('info','gp_expired',{hash:hash.slice(0,12)}); }
        }, GP_TTL);

        const nonce = data.nonce || null; // optionele nonce voor privacy
        gpMempool.set(hash, { blob, timer, ts: Date.now(), apiKey: apiKey || null, nonce });
        gpTotalIn++;
        const clientIp  = req.headers['cf-connecting-ip'] || req.socket?.remoteAddress || 'unknown';
        const clientGeo = req.headers['cf-ipcountry'] || '';
        if (apiKey) trackKeyIp(apiKey, clientIp, clientGeo);
        logAbuse('gp_in', { hash: hash.slice(0,12), size: blob.length, plan: keyEntry?.plan || 'free' });

        res.writeHead(200);
        return res.end(J({
          ok: true, hash,
          size: blob.length,
          ttl_ms: GP_TTL,
          expires_at: Date.now() + GP_TTL,
          burn_on_read: true,
          crypto_version: 'hkdf-sha256-v2-hybrid',
          security_patch: '2026-03-30',
          plan: keyEntry?.plan || 'free'
        }));
      } catch(e) {
        log('warn','gp_inbound_error',{msg:e.message});
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }

  // GET /v2/outbound/:hash — Pull + burn
  const gpMatch = url.match(/^\/v2\/outbound\/([a-fA-F0-9]{32,128})$/);
  if (gpMatch && req.method === 'GET') {
    const hash = gpMatch[1];
    const blob = gpGet(hash);
    // Track outbound als API key meegegeven
    const outKey = (req.headers['x-api-key'] || '').trim();
    const outEntry = outKey ? validateApiKey(outKey) : null;
    if (outEntry) trackUsage(outKey, 'out', blob ? blob.length : 0);
    if (!blob) {
      res.writeHead(404);
      return res.end(J({ error: 'Not found — expired, burned, or never pushed', hash }));
    }
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', blob.length);
    res.setHeader('X-GP-Burned', 'true');
    res.setHeader('X-GP-Burn-On-Read', 'true');
    res.writeHead(200);
    return res.end(blob);
  }

  // GET /v2/status/:hash — Check zonder burn (alleen aanwezigheid)
  const gpStatusMatch = url.match(/^\/v2\/status\/([a-fA-F0-9]{32,128})$/);
  if (gpStatusMatch && req.method === 'GET') {
    const hash = gpStatusMatch[1];
    const entry = gpMempool.get(hash);
    if (!entry) {
      res.writeHead(404);
      return res.end(J({ available: false, hash }));
    }
    const remaining_ms = Math.max(0, (entry.ts + GP_TTL) - Date.now());
    return res.end(J({
      available: true,
      hash,
      size: entry.size,
      remaining_ms,
      expires_at: entry.ts + GP_TTL
    }));
  }

  // ── POST /v2/manifest — Registreer multi-block transfer ──────────────
  // Klant registreert hoeveel blokken er komen, krijgt een manifest-hash terug
  if (url === '/v2/manifest' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { total_blocks, recipient_hash, api_key } = JSON.parse(body.toString());
        const apiKey = (api_key || req.headers['x-api-key'] || '').trim();
        const clientIp0 = req.headers['cf-connecting-ip'] || req.socket?.remoteAddress || 'unknown';
        const keyEntry = apiKey ? validateApiKey(apiKey, clientIp0) : null;
        if (keyEntry && keyEntry._blocked) {
          res.writeHead(403);
          return res.end(J({ error: keyEntry.reason, ip: keyEntry.ip, upgrade: 'https://paramant.app' }));
        }
        if (apiKey && !keyEntry) {
          res.writeHead(401); return res.end(J({ error: 'Ongeldige API key' }));
        }
        if (!total_blocks || total_blocks > 400) { // max 400 blokken = 2GB
          res.writeHead(400); return res.end(J({ error: 'total_blocks vereist (max 400)' }));
        }
        // Plan check: gratis max 1 blok (5MB), pro max 100 (500MB), kantoor max 400 (2GB)
        const maxBlocks = keyEntry
          ? (keyEntry.plan === 'enterprise' ? 999999 : keyEntry.plan === 'kantoor' ? 400 : 100)
          : 1;
        if (total_blocks > maxBlocks) {
          res.writeHead(403); return res.end(J({
            error: `Plan limiet: max ${maxBlocks} blokken (${maxBlocks*5}MB)`,
            upgrade: 'https://paramant.app/#pricing'
          }));
        }
        const crypto = require('crypto');
        const manifestHash = crypto.randomBytes(32).toString('hex');
        // Sla manifest op in mempool met dezelfde TTL
        const timer = setTimeout(() => gpMempool.delete('manifest:'+manifestHash), GP_TTL * 2);
        gpMempool.set('manifest:'+manifestHash, {
          blob: Buffer.alloc(0), // placeholder
          ts: Date.now(), timer,
          size: 0,
          manifest: { total_blocks, received: 0, recipient_hash, complete: false }
        });
        log('info', 'manifest_created', { hash: manifestHash.slice(0,12), blocks: total_blocks });
        res.writeHead(200);
        return res.end(J({ ok: true, manifest_hash: manifestHash, total_blocks, max_blocks: maxBlocks }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }

  // GET /v2/usage — Usage per API key (vereist x-api-key header)
  // GET /v2/usage — Usage per API key
  if (url === '/v2/usage' && req.method === 'GET') {
    const key = (req.headers['x-api-key'] || '').trim();
    const entry = validateApiKey(key);
    if (!entry) {
      res.writeHead(401); return res.end(J({ error: 'Geldige x-api-key header vereist' }));
    }
    return res.end(J({
      ok: true,
      key_prefix: key.slice(0, 12) + '...',
      plan: entry.plan,
      label: entry.label,
      packets_in:   entry.in,
      packets_out:  entry.out,
      bytes_in:     entry.bytes_in,
      bytes_out:    entry.bytes_out,
      monthly_limit: entry.monthly_limit,
      last_used:    entry.last_used,
      created:      entry.created,
    }));
  }

  // GET /v2/stats — Ghost Pipe statistieken
  if (url === '/v2/stats' && req.method === 'GET') {
    return res.end(J({
      ok: true,
      mempool_entries: gpMempool.size,
      total_in:  gpTotalIn,
      total_out: gpTotalOut,
      total_burned: gpBurned,
      ttl_ms:    GP_TTL,
      max_blob:  GP_MAX_BLOB,
      burn_on_read: true
    }));
  }

  // ── POST /admin/provision-key — Stripe webhook + handmatige provisioning ──
  if (url === '/admin/provision-key' && req.method === 'POST') {
    const clientIp = req.socket.remoteAddress || 'unknown';
    if (!adminRateLimit(clientIp)) {
      res.writeHead(429);
      return res.end(JSON.stringify({ error: 'Te veel verzoeken — probeer later opnieuw' }));
    }
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body.toString());
        // Admin token: via header OF via body
        const tok = req.headers['x-admin-token'] || data.admin_token || '';
        if (tok !== (process.env.ADMIN_TOKEN || (() => { throw new Error('ADMIN_TOKEN not set'); })())) {
          res.writeHead(401); return res.end(J({ error: 'Unauthorized' }));
        }
        const { email, plan = 'pro', label, send_email, allowed_relays } = data;
        const cryptoM = require('crypto');
        const keyId   = cryptoM.randomBytes(16).toString('hex');
        const apiKey  = `pgp_${keyId}`;
        const limits  = { free: 100, pro: 10000, kantoor: Infinity };
        const lim     = limits[plan] || 10000;
        apiKeys.set(apiKey, {
          plan, label: label || email || 'manual',
          in: 0, out: 0, bytes_in: 0, bytes_out: 0,
          created: Date.now(), last_used: null,
          limit: lim, email: email || null, active: true,
          allowed_relays: allowed_relays || []
        });
        saveUsers();
        log('info', 'key_provisioned', { plan, email, prefix: apiKey.slice(0,12) });
        if (send_email && email) sendApiKeyEmail(email, apiKey, plan);
        res.writeHead(200);
        return res.end(J({ ok: true, key: apiKey, api_key: apiKey, plan, limit: lim }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }

  // ── POST /admin/stripe-webhook — Stripe betaling afgehandeld ──
  if (url === '/admin/stripe-webhook' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const stripeSignature = req.headers['stripe-signature'];
        const stripeSecret = process.env.STRIPE_WEBHOOK_SECRET;
        if (!verifyStripeSignature(body, stripeSignature, stripeSecret)) {
          res.writeHead(400);
          log('warn', 'stripe_invalid_signature', { ip: req.socket.remoteAddress });
          return res.end(JSON.stringify({ error: 'Ongeldige Stripe signature' }));
        }
        // In productie: verifieer Stripe-Signature header
        // const sig = req.headers['stripe-signature'];
        // const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        const event = JSON.parse(body.toString());
        if (event.type === 'checkout.session.completed') {
          const session  = event.data.object;
          const email    = session.customer_email || session.customer_details?.email;
          const plan     = session.metadata?.plan || 'pro';
          if (email) {
            const crypto = require('crypto');
            const apiKey = `pgp_${plan}_${crypto.randomBytes(16).toString('hex')}`;
            const limits = { free: 100, pro: 10000, enterprise: 999999 };
            apiKeys.set(apiKey, {
              plan, label: email,
              in: 0, out: 0, bytes_in: 0, bytes_out: 0,
              created: Date.now(), last_used: null,
              monthly_limit: limits[plan] || 10000,
              email
            });
            log('info', 'stripe_key_provisioned', { plan, email, key_prefix: apiKey.slice(0,16) });
            // TODO: stuur email via Mailgun/SendGrid met de API key
            sendApiKeyEmail(email, apiKey, plan);
          }
        }
        res.writeHead(200); return res.end(J({ received: true }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }


  // POST /admin/stripe-checkout — maak Stripe checkout sessie
  if (url === '/admin/stripe-checkout' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { email, plan } = JSON.parse(body.toString());
        // Stripe price IDs — stel in via env vars
        const prices = {
          'PRO PLAN':    process.env.STRIPE_PRICE_PRO    || 'price_1TG7dlJMhSdoTn1km0SORqNt',
          'KANTOOR PLAN': process.env.STRIPE_PRICE_KANTOOR || 'price_1TG7e3JMhSdoTn1krMor7wyn',
        };
        const priceId = prices[plan] || prices['PRO PLAN'];
        
        // Als STRIPE_SECRET_KEY niet geconfigureerd is, geef fallback
        if (!process.env.STRIPE_SECRET_KEY) {
          res.writeHead(200);
          return res.end(J({ 
            ok: false, 
            fallback: true,
            message: 'Stripe niet geconfigureerd — gebruik email fallback'
          }));
        }
        
        // Stripe API call
        // Stripe vereist application/x-www-form-urlencoded
        const params = new URLSearchParams({
          'payment_method_types[]': 'card',
          'line_items[0][price]': priceId,
          'line_items[0][quantity]': '1',
          'mode': 'subscription',
          'customer_email': email || '',
          'success_url': 'https://paramant.app/chat?checkout=success',
          'cancel_url': 'https://paramant.app/#pricing',
          'metadata[plan]': plan,
          'metadata[email]': email || ''
        });
        const postData = params.toString();
        
        const https = require('https');
        const stripeReq = https.request({
          hostname: 'api.stripe.com',
          path: '/v1/checkout/sessions',
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, stripeRes => {
          let data = '';
          stripeRes.on('data', d => data += d);
          stripeRes.on('end', () => {
            try {
              const session = JSON.parse(data);
              res.writeHead(200);
              res.end(J({ ok: true, url: session.url }));
            } catch(e) {
              res.writeHead(500); res.end(J({ error: 'Stripe parse error' }));
            }
          });
        });
        stripeReq.on('error', e => {
          res.writeHead(500); res.end(J({ error: e.message }));
        });
        stripeReq.write(postData);
        stripeReq.end();
        
      } catch(e) {
        res.writeHead(400); res.end(J({ error: e.message }));
      }
    });
    return;
  }


  // POST /v2/verify-key — valideer API key (gebruikt door app.html paywall)
  if (url === '/v2/verify-key' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { api_key } = JSON.parse(body.toString());
        const entry = validateApiKey(api_key);
        if (entry) {
          res.writeHead(200);
          res.end(J({
            ok:     true,
            valid:  true,
            plan:   entry.plan   || 'pro',
            limit:  entry.limit  || 10000,
            used:   entry.in + entry.out,
            expires: entry.expires || null
          }));
        } else {
          res.writeHead(200);
          res.end(J({ ok: true, valid: false, error: 'Ongeldige of onbekende API key' }));
        }
      } catch(e) {
        res.writeHead(400);
        res.end(J({ ok: false, error: e.message }));
      }
    });
    return;
  }


  // GET /admin/users — overzicht alle API keys (admin only)
  if (url.startsWith('/admin/users') && req.method === 'GET') {
    const adminToken = req.headers['x-admin-token'] || '';
    if (adminToken !== (process.env.ADMIN_TOKEN || (() => { throw new Error('ADMIN_TOKEN not set'); })())) {
      res.writeHead(401); return res.end(J({ error: 'Unauthorized' }));
    }
    const users = [];
    apiKeys.forEach((v, k) => {
      users.push({
        key_prefix: k.slice(0, 12) + '...',
        plan:       v.plan,
        label:      v.label,
        email:      v.email,
        usage:      v.in + v.out,
        limit:      v.limit,
        created:    new Date(v.created).toISOString(),
        last_used:  v.last_used ? new Date(v.last_used).toISOString() : null,
        active:     v.active
      });
    });
    res.writeHead(200);
    return res.end(J({ ok: true, count: users.length, users }));
  }



  // GET /noble-mlkem.js — self-hosted Noble post-quantum library
  if (url === '/noble-mlkem.js' && req.method === 'GET') {
    const fs = require('fs');
    const fpath = '/home/paramant/app/noble-mlkem.js';
    if (!fs.existsSync(fpath)) {
      res.writeHead(404); return res.end('Not found');
    }
    const content = fs.readFileSync(fpath);
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
      'Access-Control-Allow-Origin': '*'
    });
    return res.end(content);
  }



  // GET /dl/:file.sha256 — SHA256 checksum voor binary verificatie
  // Berekent dynamisch uit het binaire bestand op schijf
  const sha256Match = url.match(/^\/dl\/([a-zA-Z0-9._-]+)\.sha256$/);
  if (sha256Match && (req.method === 'GET' || req.method === 'HEAD')) {
    const fname   = sha256Match[1].replace(/[^a-zA-Z0-9._-]/g,'');
    const urlObj  = new URL('https://x.com' + req.url);
    const token   = urlObj.searchParams.get('token') || req.headers['x-api-key'] || '';
    if (!token || !token.startsWith('pgp_')) {
      res.writeHead(401); return res.end(J({ error: 'API key vereist' }));
    }
    const keyEntry = validateApiKey(token);
    if (!keyEntry) { res.writeHead(403); return res.end(J({ error: 'Ongeldige key' })); }
    const fpath = require('path').join('/home/paramant/app/dl', fname);
    const fs    = require('fs');
    if (!fs.existsSync(fpath)) {
      res.writeHead(404); return res.end(J({ error: 'Not found' }));
    }
    const hash = require('crypto').createHash('sha256')
      .update(fs.readFileSync(fpath)).digest('hex');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(hash + '  ' + fname + '\n');
  }

  // GET /dl/:file — CLI binary downloads
  const dlMatch = url.match(/^\/dl\/([a-zA-Z0-9._-]+)$/);
  if (dlMatch && req.method === 'GET') {
    const dlToken = new URL('https://x.com' + req.url).searchParams.get('token') || req.headers['x-api-key'] || '';
    if (!dlToken || !dlToken.startsWith('pgp_')) { res.writeHead(401); return res.end(J({ error: 'API key vereist' })); }
    if (!validateApiKey(dlToken)) { res.writeHead(403); return res.end(J({ error: 'Ongeldige key' })); }
    const fname = dlMatch[1].replace(/[^a-zA-Z0-9._-]/g,'');
    const fpath = require('path').join('/home/paramant/app/dl', fname);
    const fs = require('fs');
    if (!fs.existsSync(fpath)) {
      res.writeHead(404); return res.end(J({error:'Not found'}));
    }
    const stat = fs.statSync(fpath);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': stat.size,
      'Content-Disposition': `attachment; filename="${fname}"`,
      'Cache-Control': 'no-cache'
    });
    fs.createReadStream(fpath).pipe(res);
    log('info', 'dl_request', { file: fname, size: stat.size });
    return;
  }


  // POST /v2/ack/:hash — Client bevestigt succesvolle ontvangst en decryptie
  // Na ACK wordt de blob definitief vernietigd (zero-overwrite)
  const ackMatch = url.match(/^\/v2\/ack\/([a-fA-F0-9]{32,128})$/);
  if (ackMatch && req.method === 'POST') {
    const hash = ackMatch[1];
    const pending = pendingBurn.get(hash);
    if (!pending) {
      res.writeHead(404);
      return res.end(J({ error: 'Geen pending ACK voor deze hash' }));
    }
    clearTimeout(pending.timer);
    pending.blob.fill(0);      // Zero-overwrite
    pendingBurn.delete(hash);
    log('info', 'ack_received', { hash: hash.slice(0,16), age_ms: Date.now() - pending.ts });
    res.writeHead(200);
    return res.end(J({ ok: true, destroyed: true }));
  }



  // ── POST /v2/pubkey — Registreer ontvanger pubkeys (ML-KEM-768 + ECDH) ────
  if (url === '/v2/pubkey' && req.method === 'POST') {
    let body = ''; req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const d = JSON.parse(body);
        if (!d.device_id || !d.ecdh_pub) { res.writeHead(400); return res.end(J({error:'device_id en ecdh_pub vereist'})); }
        if (!keyData || !keyData.active) { res.writeHead(403); return res.end(J({error:'Ongeldige key'})); }
        if (!global.pubkeyStore) global.pubkeyStore = new Map();
        global.pubkeyStore.set(d.device_id + ':' + apiKey, {
          ecdh_pub:  d.ecdh_pub,
          kyber_pub: d.kyber_pub || '',
          ts: new Date().toISOString(),
        });
        log('info', 'pubkey_registered', {device: d.device_id, kyber: !!d.kyber_pub});
        res.writeHead(200); return res.end(J({ok: true}));
      } catch(e) { res.writeHead(400); return res.end(J({error: e.message})); }
    }); return;
  }

  // ── GET /v2/pubkey/:device — Haal ontvanger pubkeys op (voor zender) ──────
  const pubkeyMatch = url.match(/^\/v2\/pubkey\/([^?]+)/);
  if (pubkeyMatch && req.method === 'GET') {
    const apiKeyParam = new URL(req.url, 'http://r').searchParams.get('k') || apiKey;
    const deviceId    = decodeURIComponent(pubkeyMatch[1]);
    if (!global.pubkeyStore) global.pubkeyStore = new Map();
    const entry = global.pubkeyStore.get(deviceId + ':' + apiKeyParam);
    if (!entry) { res.writeHead(404); return res.end(J({error:'Geen pubkeys geregistreerd voor dit device'})); }
    res.writeHead(200); return res.end(J({ok: true, ecdh_pub: entry.ecdh_pub, kyber_pub: entry.kyber_pub, ts: entry.ts}));
  }

  // GET /v2/audit — Exporteerbare audit log voor compliance (hash + timestamp + bytes)
  // Geen inhoud, alleen metadata voor compliance/AVG/DORA
  if (url.startsWith('/v2/audit') && req.method === 'GET') {
    const apiKey = (req.headers['x-api-key'] || '').trim();
    const keyData = apiKeys.get(apiKey);
    if (!keyData || !keyData.active) { res.writeHead(403); return res.end(J({error:'Ongeldige key'})); }

    const params = new URL(req.url, 'http://r.internal').searchParams;
    const limit  = Math.min(parseInt(params.get('limit') || '100'), 500);
    const filter = params.get('event') || '';
    const search = params.get('q') || '';

    // Haal audit entries op voor deze key
    const entries = (auditLog.get(apiKey) || [])
      .filter(e => !filter || e.event === filter)
      .filter(e => !search || (e.hash || '').includes(search))
      .slice(-limit)
      .reverse()
      .map(e => ({
        ts:        e.ts,
        event:     e.event,
        hash:      e.hash,
        bytes:     e.bytes,
        direction: e.direction,
        device:    e.device,
        seq:       e.seq,
      }));

    // CSV export
    if (params.get('format') === 'csv') {
      const csv = 'tijdstip,event,hash,bytes,richting,apparaat\n' +
        entries.map(e => `${e.ts},${e.event},${e.hash},${e.bytes},${e.direction},${e.device||''}`).join('\n');
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="paramant_audit.csv"' });
      return res.end(csv);
    }

    return res.end(J({ ok: true, count: entries.length, entries }));
  }


  // POST /v2/webhook — Registreer webhook voor ontvangst notificatie
  if (url === '/v2/webhook' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { hash, callback_url, api_key: wk } = JSON.parse(body.toString());
        const apiKey = wk || req.headers['x-api-key'] || '';
        const entry  = apiKey ? validateApiKey(apiKey) : null;
        if (!entry) { res.writeHead(401); return res.end(J({ error: 'API key vereist voor webhooks' })); }
        if (!hash || !callback_url) { res.writeHead(400); return res.end(J({ error: 'hash + callback_url vereist' })); }
        if (!callback_url.startsWith('https://')) { res.writeHead(400); return res.end(J({ error: 'callback_url moet HTTPS zijn' })); }

        // Sla webhook op bij de blob
        const blob = gpMempool.get(hash);
        if (!blob) { res.writeHead(404); return res.end(J({ error: 'Hash niet gevonden' })); }
        blob.webhook = callback_url;
        log('info', 'webhook_registered', { hash: hash.slice(0,12), url: callback_url.slice(0,40) });
        res.writeHead(200);
        return res.end(J({ ok: true, hash, webhook: 'registered' }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }


  // POST /admin/set-ip-pin — Stel toegestane IPs in voor een key (Kantoor/Enterprise)
  if (url === '/admin/set-ip-pin' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { admin_token, api_key, allowed_ips } = JSON.parse(body.toString());
        if (admin_token !== process.env.ADMIN_TOKEN) {
          res.writeHead(401); return res.end(J({ error: 'Unauthorized' }));
        }
        const entry = apiKeys.get(api_key);
        if (!entry) { res.writeHead(404); return res.end(J({ error: 'Key niet gevonden' })); }
        if (!['kantoor','enterprise'].includes(entry.plan)) {
          res.writeHead(403); return res.end(J({ error: 'IP pinning alleen voor Kantoor/Enterprise plan' }));
        }
        entry.allowed_ips = Array.isArray(allowed_ips) ? allowed_ips : [];
        saveUsers();
        log('info', 'ip_pin_set', { key_prefix: api_key.slice(0,12), ips: entry.allowed_ips });
        res.writeHead(200);
        return res.end(J({ ok: true, api_key: api_key.slice(0,12)+'...', allowed_ips: entry.allowed_ips }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }


  // POST /admin/generate-airgap-license — Genereer air-gapped licentie voor Enterprise
  if (url === '/admin/generate-airgap-license' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const { admin_token, plan, valid_days, label } = JSON.parse(body.toString());
        if (admin_token !== process.env.ADMIN_TOKEN) {
          res.writeHead(401); return res.end(J({ error: 'Unauthorized' }));
        }
        const crypto = require('crypto');
        const expires = Date.now() + (valid_days || 365) * 86400_000;
        const payload = { plan: plan || 'enterprise', expires, label: label || '', issued: Date.now() };
        const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
        const sig = crypto.createHmac('sha256', 'paramant-license-v1-' + process.env.ADMIN_TOKEN)
          .update(payloadB64).digest('hex');
        const license = payloadB64 + '.' + sig;
        log('info', 'airgap_license_generated', { plan: payload.plan, expires: new Date(expires).toISOString() });
        res.writeHead(200);
        return res.end(J({
          ok: true,
          license,
          expires: new Date(expires).toISOString(),
          valid_days: valid_days || 365,
          usage: 'Stel in als: PARAMANT_AIRGAP_LICENSE=' + license
        }));
      } catch(e) {
        res.writeHead(400); return res.end(J({ error: e.message }));
      }
    });
    return;
  }


  // ── POST /v2/stream — IoT stream upload ─────────────────────────────────
  if (url === '/v2/stream' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      try {
        const apiKey = req.headers['x-api-key'] || '';
        const keyData = apiKeys.get(apiKey);
        if (!keyData || !keyData.active) {
          res.writeHead(401); return res.end(J({ error: 'Ongeldige API key' }));
        }
        const data = JSON.parse(body.toString());
        const { hash, payload, meta } = data;
        if (!hash || !payload) {
          res.writeHead(400); return res.end(J({ error: 'hash en payload vereist' }));
        }
        const buf = Buffer.from(payload, 'base64');
        const maxBlock = parseInt(process.env.STREAM_MAX_BLOCK || '524288');
        if (buf.length > maxBlock) {
          res.writeHead(413); return res.end(J({ error: 'Blok te groot, max: ' + maxBlock }));
        }
        const ttl = parseInt(process.env.STREAM_TTL_MS || '60000');
        if (typeof streamBlobs !== 'undefined') {
          streamBlobs.set(hash, { data: buf, ts: Date.now(), meta: meta || {} });
  auditPush(apiKey, 'stream_upload', { hash, bytes: buf ? buf.length : 0, device: meta && meta.device_id, seq: meta && meta.sequence });
        } else {
          // Fallback: gebruik hoofd blobs map met korte TTL
          blobs.set(hash, buf); auditPush(apiKey, "stream_upload", { hash, bytes: buf.length, device: meta && meta.device_id, seq: meta && meta.sequence });
          setTimeout(() => {
            const b = blobs.get(hash);
            if (b) { try { require('crypto').randomFillSync(b); } catch { b.fill(0); } auditPush(apiKey, 'gp_download_burn', { hash, bytes: 0 }); blobs.delete(hash); }
          }, ttl);
        }
        keyData.in = (keyData.in || 0) + 1;
        log('info', 'stream_stored', { hash: hash.slice(0,16), size: buf.length });
        res.writeHead(200); res.end(J({ ok: true, hash, ttl_ms: ttl, size: buf.length }));
      } catch(e) { res.writeHead(400); res.end(J({ error: e.message })); }
    });
    return;
  }

  // ── GET /v2/stream/:hash — IoT stream ophalen ────────────────────────────
  if (url.startsWith('/v2/stream/') && !url.startsWith('/v2/stream-status/') && req.method === 'GET') {
    const hash = url.slice(11);
    const store = typeof streamBlobs !== 'undefined' ? streamBlobs : blobs;
    const blob = store.get(hash);
    if (!blob) {
      res.writeHead(404); return res.end(J({ error: 'Niet gevonden of verlopen' }));
    }
    const buf = typeof blob.data !== 'undefined' ? Buffer.from(blob.data) : Buffer.from(blob);
    store.delete(hash);
    try { require('crypto').randomFillSync(typeof blob.data !== 'undefined' ? blob.data : blob); } catch {}
    log('info', 'stream_delivered', { hash: hash.slice(0,16), size: buf.length });
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'X-Paramant-Hash': hash });
    return res.end(buf);
  }

  // ── GET /v2/stream-status/:hash ──────────────────────────────────────────
  if (url.startsWith('/v2/stream-status/') && req.method === 'GET') {
    const hash = url.slice(18);
    const store = typeof streamBlobs !== 'undefined' ? streamBlobs : blobs;
    const blob = store.get(hash);
    if (!blob) {
      res.writeHead(200); return res.end(J({ available: false }));
    }
    const age = typeof blob.ts !== 'undefined' ? Date.now() - blob.ts : 0;
    const ttl = parseInt(process.env.STREAM_TTL_MS || '60000');
    res.writeHead(200);
    return res.end(J({ available: true, age_ms: age, ttl_remaining_ms: Math.max(0, ttl - age), size: typeof blob.data !== 'undefined' ? blob.data.length : blob.length }));
  }

  // ── GET /v2/check-key?k=pgp_xxx — key verificatie (Cloudflare-safe) ──────
  if (url.startsWith('/v2/check-key') && req.method === 'GET') {
    try {
      const params = new URL(req.url, 'http://relay.internal').searchParams;
      const apiKey = (params.get('k') || '').trim();
      if (!apiKey || !/^pgp_[a-f0-9]{32}$/.test(apiKey)) {
        res.writeHead(200);
        return res.end(J({ valid: false, error: 'Ongeldig formaat' }));
      }
      const keyData = apiKeys.get(apiKey);
      if (keyData && keyData.active) {
        res.writeHead(200);
        return res.end(J({ valid: true, plan: keyData.plan || 'pro' }));
      }
      res.writeHead(200);
      return res.end(J({ valid: false, error: 'Onbekende of inactieve key' }));
    } catch(e) {
      res.writeHead(200);
      return res.end(J({ valid: false, error: e.message }));
    }
  }

  // ── GET /v2/stream-next — REST polling ontvanger ──────────────────────────
  // Gebruik: GET /v2/stream-next?device=mri-001&seq=42&k=pgp_xxx
  // Berekent de hash voor seq+1 zodat ontvanger weet wat op te halen.
  // Geeft available:true als het blok beschikbaar is op de relay.
  if (url.startsWith('/v2/stream-next') && req.method === 'GET') {
    const p     = new URL(req.url, 'http://relay.internal').searchParams;
    const apiKey = (p.get('k') || '').trim();
    const device = (p.get('device') || '').trim();
    const seq    = parseInt(p.get('seq') || '0', 10);
    if (!apiKey || !device) {
      res.writeHead(400); return res.end(J({error: 'k en device vereist'}));
    }
    const kd = apiKeys.get(apiKey);
    if (!kd || !kd.active) {
      res.writeHead(403); return res.end(J({error: 'Ongeldige key'}));
    }
    // Bereken hash voor volgende sequence (zender en ontvanger delen secret)
    const nextSeq  = seq + 1;
    const secret   = apiKey.slice(0, 24);
    const msg      = device + '|' + nextSeq;
    const keyBytes = Buffer.from(secret);
    const hmacVal  = require('crypto').createHmac('sha256', Buffer.from(secret)).update(Buffer.from(msg)).digest('hex');
    // Check of dit blok beschikbaar is
    const available = streamBlobs.has(hmacVal);
    res.writeHead(200);
    return res.end(J({
      ok: true, device, seq: nextSeq, hash: hmacVal,
      available, ts: new Date().toISOString()
    }));
  }

  // ── POST /v2/subscribe — Webhook registratie ───────────────────────────────
  // Gebruik: POST /v2/subscribe {device_id, callback_url, api_key}
  // Relay POSTt naar callback_url zodra een nieuw blok binnenkomt voor device.
  if (url === '/v2/subscribe' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const d = JSON.parse(body);
        if (!d.api_key || !d.device_id || !d.callback_url) {
          res.writeHead(400); return res.end(J({error: 'api_key, device_id en callback_url vereist'}));
        }
        const kd = apiKeys.get(d.api_key);
        if (!kd || !kd.active) {
          res.writeHead(403); return res.end(J({error: 'Ongeldige key'}));
        }
        if (!webhooks) global.webhooks = new Map();
        const key = d.device_id + ':' + d.api_key;
        webhooks.set(key, {
          callback_url: d.callback_url,
          device_id: d.device_id,
          registered: new Date().toISOString()
        });
        log('info', 'webhook_registered', {device: d.device_id, url: d.callback_url});
        res.writeHead(200);
        return res.end(J({ok: true, device_id: d.device_id, message: 'Webhook geregistreerd'}));
      } catch(e) {
        res.writeHead(400); return res.end(J({error: e.message}));
      }
    });
    return;
  }

  // ── GET /v2/events — Server-Sent Events live feed ─────────────────────────
  // Gebruik: GET /v2/events?device=mri-001&k=pgp_xxx
  // Browser/client houdt verbinding open, relay stuurt events bij nieuw blok.
  if (url.startsWith('/v2/events') && req.method === 'GET') {
    const p      = new URL(req.url, 'http://relay.internal').searchParams;
    const apiKey = (p.get('k') || '').trim();
    const device = (p.get('device') || '').trim();
    const kd     = apiKey ? apiKeys.get(apiKey) : null;
    if (!kd || !kd.active) {
      res.writeHead(403); return res.end(J({error: 'Ongeldige key'}));
    }
    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 3000\n\n');
    res.write('data: ' + J({type: 'connected', device, ts: new Date().toISOString()}) + '\n\n');
    // Registreer SSE client
    if (!global.sseClients) global.sseClients = new Map();
    const clientKey = device + ':' + Date.now();
    global.sseClients.set(clientKey, {res, device, apiKey});
    req.on('close', () => { if (global.sseClients) global.sseClients.delete(clientKey); });
    // Heartbeat elke 30s
    const hb = setInterval(() => {
      try { res.write(': heartbeat\n\n'); } catch(e) { clearInterval(hb); }
    }, 30000);
    return;
  }

  // ── POST /v2/chat/create-room ──────────────────────────────────────────────
  if (url === '/v2/chat/create-room' && req.method === 'POST') {
    const apiKey = (req.headers['x-api-key'] || '').trim();
    if (!apiKey || !validateApiKey(apiKey, ip)) {
      res.writeHead(401); return res.end(J({ error: 'Geldige x-api-key vereist' }));
    }
    const token = require('crypto').randomBytes(16).toString('hex'); // 32 hex chars
    const expires = Date.now() + 60 * 60_000; // 60 minuten
    inviteRooms.set(token, { creatorApiKey: apiKey, expires, lastActivity: Date.now() });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(J({
      ok: true,
      token,
      invite_url: 'https://paramant.app/chat?invite=' + token,
      expires_iso: new Date(expires).toISOString(),
    }));
  }

  res.writeHead(404); res.end(J({error:'Not found'}));
});

// ── Per-room packet buffer ───────────────────────────────────────────
const roomBuffer = new Map();
const ROOM_BUF   = 5;
function bufRoom(room, seq, payload, nick) {
  if (room === '__presence__') return;
  const buf = roomBuffer.get(room) || [];
  buf.push({ seq, payload, ts: Date.now(), nick });
  if (buf.length > ROOM_BUF) buf.shift();
  roomBuffer.set(room, buf);
}

// ── WebSocket relay ──────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://paramant.app',
  'http://localhost:8080',
  'http://localhost:3001',
  'null', // file:// opent met origin 'null'
];
const wss = new WebSocket.Server({
  server: srv,
  maxPayload: MAX_PKT + 1024,
  verifyClient: (info) => {
    const origin = info.origin || '';
    // Sta toe: paramant.app, localhost, file://, .onion
    if (ALLOWED_ORIGINS.includes(origin)) return true;
    if (origin.endsWith('.onion')) return true;
    if (origin === 'null') return true; // file://
    if (!origin) return true; // geen origin (native clients)
    logAbuse('ws_origin_blocked', { origin });
    return false;
  }
});

wss.on('connection', (ws, req) => {
  const ip = getIP(req);

  if (online() >= MAX_CONNS) {
    logAbuse('global_conn_cap', { ip });
    ws.close(1013, 'Server full');
    return;
  }
  const ipCount = (ipConns.get(ip) || 0) + 1;
  if (ipCount > MAX_CONNS_IP) {
    logAbuse('ip_conn_cap', { ip, count: ipCount });
    ws.close(1013, 'Too many connections');
    return;
  }
  ipConns.set(ip, ipCount);

  // ── Per-connection state ─────────────────────────────────────────
  // subs: Set van alle rooms waar deze verbinding in zit
  // Meerdere rooms tegelijk mogelijk (presence + meerdere chatrooms)
  const subs = new Set();
  let nick = 'anon';
  let cnt = 0, win = Date.now();
  let presCnt = 0, presWin = Date.now();

  const pt = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
    else clearInterval(pt);
  }, PING_IV);

  const send = o => { if (ws.readyState === WebSocket.OPEN) ws.send(J(o)); };

  // Broadcast naar een specifieke room (niet naar zichzelf tenzij includeSelf)
  function bcastRoom(roomName, obj, includeSelf = false) {
    const s = rooms.get(roomName);
    if (!s) return;
    const msg = J(obj);
    s.forEach(p => {
      if (p.readyState === WebSocket.OPEN && (includeSelf || p !== ws)) p.send(msg);
    });
  }

  // Verlaat een specifieke room en stuur peer_left
  function leaveRoom(r) {
    if (!subs.has(r)) return;
    subs.delete(r);
    const s = rooms.get(r);
    if (!s) return;
    s.delete(ws);
    if (!s.size) {
      rooms.delete(r);
      if (isInvRoom(r)) {
        // Invite room: direct wisgsen bij laatste leave
        const token = r.slice(4); // strip 'inv_'
        cleanInvRoom(token);
      } else {
        // 60s TTL — late joiners in dezelfde sessie ontvangen nog gemiste pakketten
        const _r = r;
        setTimeout(() => roomBuffer.delete(_r), 60_000);
      }
    } else {
      bcastRoom(r, { type:'peer_left', nick, peers: s.size });
    }
  }

  const rateOk = () => {
    const now = Date.now();
    if (now - win > RATE_WIN) { cnt = 0; win = now; }
    return ++cnt <= RATE_MAX;
  };
  const presRateOk = () => {
    const now = Date.now();
    if (now - presWin > PRES_WIN) { presCnt = 0; presWin = now; }
    return ++presCnt <= PRES_MAX;
  };

  ws.on('message', raw => {
    if (!rateOk()) {
      logAbuse('ws_rate_limit', { ip, nick });
      return send({ type:'error', code:429, msg:'Rate limit exceeded' });
    }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object') return;

    // ── JOIN ─────────────────────────────────────────────────────
    if (msg.type === 'join') {
      // Invite room join (geen API key vereist voor deelnemer)
      let r;
      if (msg.inviteToken !== undefined) {
        const token = sanitizeToken(msg.inviteToken);
        if (!token) return send({ type:'error', code:400, msg:'Invalid inviteToken' });
        const meta = inviteRooms.get(token);
        if (!meta) return send({ type:'error', code:404, msg:'Room niet gevonden of verlopen' });
        if (Date.now() > meta.expires) {
          cleanInvRoom(token);
          return send({ type:'error', code:410, msg:'Invite verlopen' });
        }
        meta.lastActivity = Date.now();
        r = invRoomKey(token);
      } else {
        r = sanitize(msg.chatHash);
        if (!r) return send({ type:'error', code:400, msg:'Invalid chatHash' });
      }

      // Al in deze room — bevestig maar stuur buffer NIET opnieuw
      // (buffer replay alleen bij eerste join, niet bij herverbinding of presence-cycle)
      if (subs.has(r)) {
        send({ type:'joined', chatHash:r, peers:rooms.get(r)?.size||1, online:online() });
        return;
      }

      // Cap op aantal rooms per verbinding
      if (subs.size >= MAX_ROOMS_PER_CONN) {
        return send({ type:'error', code:429, msg:'Too many rooms' });
      }

      nick = String(msg.nick||'anon').slice(0,15).replace(/[^\w\-._!~@]/g,'');
      if (!rooms.has(r)) rooms.set(r, new Set());
      const s = rooms.get(r);
      if (s.size >= MAX_PEERS) return send({ type:'error', code:429, msg:'Room full' });

      s.add(ws);
      subs.add(r);
      // chatsSeen alleen in addLedger — niet bij join (anders telt lege rooms mee)

      send({ type:'joined', chatHash:r, peers:s.size, online:online() });
      bcastRoom(r, { type:'peer_joined', nick, peers:s.size });

      // Stuur gebufferde pakketten aan nieuwe deelnemer
      const buf = roomBuffer.get(r);
      if (buf?.length) {
        buf.forEach(b => {
          if (ws.readyState === WebSocket.OPEN)
            ws.send(J({ type:'packet', nick:b.nick, seq:b.seq, chatHash:r, payload:b.payload, ts:b.ts, replayed:true }));
        });
      }
    }

    // ── LEAVE ────────────────────────────────────────────────────
    else if (msg.type === 'leave') {
      const r = sanitize(msg.chatHash);
      if (r) leaveRoom(r);
    }

    // ── PACKET ───────────────────────────────────────────────────
    else if (msg.type === 'packet') {
      // Route pakketten naar de chatHash in het bericht — niet de "huidige" room
      const targetRoom = sanitize(msg.chatHash);
      if (!targetRoom) return send({ type:'error', code:403, msg:'Invalid chatHash' });
      // Vereist dat de afzender in de doelroom zit
      if (!subs.has(targetRoom)) return send({ type:'error', code:403, msg:'Join first' });
      if (!msg.payload || typeof msg.payload !== 'object') return;

      if (msg.payload?.pType === 'presence') {
        if (!presRateOk()) {
          logAbuse('presence_rate_limit', { ip, nick });
          return;
        }
      }

      const ps = J(msg.payload), bytes = Buffer.byteLength(ps);
      if (bytes > MAX_PKT) {
        logAbuse('pkt_too_large', { ip, bytes, nick });
        return send({ type:'error', code:413, msg:'Packet too large' });
      }

      // seq bounds check — voorkom Number.MAX_VALUE
      const seq = typeof msg.seq === 'number'
        ? Math.min(Math.max(0, Math.floor(msg.seq)), 2_147_483_647)
        : 0;

      addLedger(targetRoom, seq, bytes);
      if (!isInvRoom(targetRoom)) bufRoom(targetRoom, seq, msg.payload, nick); // burn-on-read: geen buffer voor invite rooms
      bcastRoom(targetRoom, { type:'packet', nick, seq, chatHash:targetRoom, payload:msg.payload, ts:Date.now() });
      send({ type:'ack', seq });
    }

    else if (msg.type === 'ping')  send({ type:'pong', ts:Date.now(), online:online() });
    else if (msg.type === 'stats') send({ type:'stats', messages:totalMsgs, bytes:totalBytes, online:online(), chats:chatsSeen.size });
  });

  ws.on('close', () => {
    clearInterval(pt);
    const remaining = (ipConns.get(ip) || 1) - 1;
    if (remaining <= 0) ipConns.delete(ip);
    else ipConns.set(ip, remaining);
    // Verlaat alle subscribed rooms bij disconnect
    [...subs].forEach(r => leaveRoom(r));
  });

  ws.on('error', () => {});
});

// ── Start ────────────────────────────────────────────────────────────
srv.listen(PORT, '127.0.0.1', () => {
  log('info', 'relay_started', { port: PORT, version: VERSION });
});

// ── Hourly flush — wist alle bewijssporen op het hele uur ──────────
function doHourlyFlush() {
  const before = { msgs: totalMsgs, chats: chatsSeen.size, ledger: ledger.length, conns: online() };

  // Stap 1: wis alle data
  ledger.length = 0;
  chatLedgerCount.clear();
  chatsSeen.clear();
  roomBuffer.clear();
  totalMsgs = 0;
  totalBytes = 0;

  // Stap 2: stuur flush event naar alle clients (2s grace period om te tonen)
  const msg = JSON.stringify({ type: 'flush', ts: Date.now(), next: nextFlushTs() });
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });

  // Stap 3: verbreek ALLE verbindingen na 3s
  // Browsers moeten opnieuw verbinden — geen ghost-users meer
  setTimeout(() => {
    const n = wss.clients.size;
    wss.clients.forEach(c => {
      if (c.readyState === WebSocket.OPEN || c.readyState === WebSocket.CONNECTING) {
        c.close(1001, 'Hourly flush — reconnect required');
      }
    });
    // Wis ook room-state want alle connections zijn weg
    rooms.clear();
    ipConns.clear();
    log('info', 'hourly_flush_complete', { ...before, disconnected: n });
  }, 3000);

  log('info', 'hourly_flush_started', before);
}
function nextFlushTs() {
  const now = new Date();
  const next = new Date(now);
  next.setHours(now.getHours() + 1, 0, 0, 0);
  return next.getTime();
}
function scheduleFlush() {
  const msUntil = nextFlushTs() - Date.now();
  setTimeout(() => {
    doHourlyFlush();
    setInterval(doHourlyFlush, 3_600_000);
  }, msUntil);
  log('info', 'flush_scheduled', { next_iso: new Date(nextFlushTs()).toISOString(), in_s: Math.floor(msUntil/1000) });
}
scheduleFlush();

// Ledger cleanup elke 5 minuten (entries ouder dan LEDGER_TTL)
setInterval(pruneLedger, 5 * 60 * 1000);

// ── Graceful shutdown ────────────────────────────────────────────────
['SIGTERM','SIGINT'].forEach(sig => process.on(sig, () => {
  log('info', 'shutdown', { signal: sig });
  wss.clients.forEach(c => c.close(1001, 'Server restart'));
  srv.close(() => { log('info', 'shutdown_complete'); process.exit(0); });
  setTimeout(() => process.exit(1), 5000);
}));

