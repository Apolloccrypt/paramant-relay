'use strict';
const express = require('express');
const emailTemplates = require('./lib/email-templates');
const pow = require('./lib/pow-captcha');
const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');
const { initRedis, redis } = require('./lib/redis');
const { logAuditEvent, getAuditEvents } = require('./lib/audit');
const { spawn } = require('child_process');
const cliCommands = require('./lib/cli-commands');
const cliAudit = require('./lib/cli-audit');
const cliRate = require('./lib/cli-ratelimit');
const configStore = require('./lib/config-store');
const webauthn = require('./lib/webauthn');
const { sessionKeyFields, proxyApiKey, revealKey } = require('./lib/account-keys');
const { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');

const PORT        = parseInt(process.env.PORT || '4200', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const BASE_PATH   = (process.env.BASE_PATH || '').replace(/\/$/, '');

// All five relay sectors the admin needs to know about. Until 2026-05-28 the
// 'main' relay (the one served at relay.paramant.app, internal SECTOR="relay")
// was missing from this map even though docker-compose exposes RELAY_MAIN.
// That blanked it out of signup fan-out, /admin/keys/all aggregation, and
// stats -- so its /data/users.json drifted ~8 days behind the other sectors
// (24 keys vs 114 on health). The map is the single source of truth for
// every Object.keys(SECTORS) iteration in this file; add a sector here and
// the rest follows. findUserByEmail() stays health-only on purpose: health
// is the canonical admin-UI source and the lookup is hot-path.
const SECTORS = {
  main:    process.env.RELAY_MAIN    || 'http://relay-main:3000',
  health:  process.env.RELAY_HEALTH  || 'http://relay-health:3005',
  legal:   process.env.RELAY_LEGAL   || 'http://relay-legal:3002',
  finance: process.env.RELAY_FINANCE || 'http://relay-finance:3003',
  iot:     process.env.RELAY_IOT     || 'http://relay-iot:3004',
};

if (!ADMIN_TOKEN) { console.error('[PARAMANT-ADMIN] ADMIN_TOKEN is not set — refusing to start'); process.exit(1); }

async function createSession() {
  const sid = crypto.randomBytes(32).toString('hex');
  await redis().set(`paramant:admin:session:${sid}`, '1', { EX: 3600 });
  return sid;
}

async function validateSession(sid) {
  if (!sid) return false;
  const exists = await redis().get(`paramant:admin:session:${sid}`);
  if (!exists) return false;
  await redis().expire(`paramant:admin:session:${sid}`, 3600);
  return true;
}

async function destroySession(sid) {
  if (sid) await redis().del(`paramant:admin:session:${sid}`);
}

// @deprecated 2026-04-21 — /request-key trial flow retired. /signup now handles all key issuance.
// ── Self-service trial key tracking ──────────────────────────────────────────
const trialEmailTrack = new Map(); // email → { lastAt }
const trialIpTrack    = new Map(); // ip → { count, resetAt }
function checkTrialIpLimit(ip) {
  const now = Date.now();
  const b = trialIpTrack.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 60_000; }
  if (b.count >= 3) return false;
  b.count++;
  trialIpTrack.set(ip, b);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of trialIpTrack)    if (now > v.resetAt + 120_000) trialIpTrack.delete(k);
  for (const [k, v] of trialEmailTrack) if (now - v.lastAt > 8 * 86_400_000) trialEmailTrack.delete(k);
}, 3_600_000);
async function sendTrialEmail(to, firstName, key) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) { console.warn('[trial] RESEND_API_KEY not set'); return false; }
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'PARAMANT <noreply@paramant.app>',
      to: [to],
      subject: 'Your PARAMANT trial API key',
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0c0c0c"><div style="max-width:580px;margin:40px auto;padding:40px;background:#0c0c0c;color:#ededed;font-family:monospace"><h2 style="color:#2d8a5c;margin:0 0 24px;font-size:18px;letter-spacing:.04em">PARAMANT TRIAL KEY</h2>${firstName ? `<p>Hi ${firstName},</p>` : ''}<p>Here's your 30-day trial API key:</p><pre style="background:#181818;border:1px solid #242424;border-radius:6px;padding:16px;font-size:13px;word-break:break-all;margin:16px 0">${key}</pre><h3 style="color:#2d8a5c;font-size:13px;letter-spacing:.06em;text-transform:uppercase;margin:24px 0 12px">Quick start</h3><pre style="background:#181818;border:1px solid #242424;border-radius:6px;padding:16px;font-size:12px;line-height:1.6"># Upload a file (burn-on-read)\ncurl -X POST https://health.paramant.app/v2/upload \\\n  -H "X-API-Key: ${key}" \\\n  -F "file=@document.pdf"\n\n# Returns a one-time URL\n# Recipient visits once — file is destroyed</pre><p style="color:#aaa;font-size:12px;margin-top:20px">Trial limits: 10 uploads/day &middot; 1h TTL &middot; 5 MB max &middot; ML-KEM-768</p><p style="font-size:12px;margin:8px 0"><a href="https://paramant.app/docs" style="color:#2d8a5c">paramant.app/docs</a></p><hr style="border:none;border-top:1px solid #242424;margin:24px 0"><p style="color:#6e6e6e;font-size:11px;margin:0">PARAMANT &middot; privacy@paramant.app &middot; Hetzner DE &middot; GDPR &middot; no US CLOUD Act</p></div></body></html>`,
    }),
  });
  if (!resp.ok) { const t = await resp.text().catch(() => ''); console.error('[trial] Resend', resp.status, t); return false; }
  return true;
}

// Fix 1: rate limiting on /auth/login — 5 attempts per 15 min per IP
const loginAttempts = new Map(); // ip → { count, resetAt }
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const b = loginAttempts.get(ip) || { count: 0, resetAt: now + 15 * 60_000 };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + 15 * 60_000; }
  if (b.count >= 5) return false;
  b.count++;
  loginAttempts.set(ip, b);
  return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of loginAttempts) if (now > v.resetAt + 60_000) loginAttempts.delete(k); }, 120_000);

async function authMiddleware(req, res, next) {
  const sid = (req.headers['x-session'] || '').trim();
  try {
    const valid = await validateSession(sid);
    if (!valid) return res.status(401).json({ error: 'unauthorized' });
    req.sessionToken = ADMIN_TOKEN;
    next();
  } catch (err) {
    console.error('[auth] middleware error:', err.message);
    res.status(503).json({ error: 'session_store_unavailable' });
  }
}

function relayFetch(sector, relPath, method, body, rawResponse, tokenOverride) {
  return new Promise((resolve, reject) => {
    const base = SECTORS[sector];
    if (!base) return reject(new Error(`Unknown sector: ${sector}`));
    const url = new URL(relPath, base);
    const payload = body ? JSON.stringify(body) : undefined;
    const tok = tokenOverride || ADMIN_TOKEN;
    const opts = {
      hostname: url.hostname, port: parseInt(url.port) || 80,
      path: url.pathname + (url.search || ''), method: method || 'GET',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Token': tok, 'Authorization': `Bearer ${tok}` },
    };
    if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);
    const req = http.request(opts, r => {
      const chunks = [];
      r.on('data', c => chunks.push(c));
      r.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        if (rawResponse) return resolve({ status: r.statusCode, text: raw });
        try { resolve({ status: r.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: r.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function eachSector(list, fn) {
  const r = {};
  await Promise.allSettled(list.map(async s => { try { r[s] = await fn(s); } catch(e) { r[s] = { error: e.message }; } }));
  return r;
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err)
    return res.status(400).json({ error: 'invalid_json', message: 'Request body must be valid JSON' });
  next(err);
});
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=()');
  next();
});
app.use(BASE_PATH || '/', express.static(path.join(__dirname, 'public')));

const api = express.Router();

api.post('/auth/login', async (req, res) => {
  // Rate limit by IP — use X-Real-IP (set by nginx to $remote_addr, not client-spoofable)
  // rather than X-Forwarded-For first-entry, which an attacker can set arbitrarily.
  const ip = req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  if (!checkLoginRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many login attempts — try again in 15 minutes' });
  }
  const { token, totp } = req.body || {};
  if (!token) return res.status(401).json({ error: 'Token required' });
  if (!totp || !/^\d{6}$/.test(totp)) return res.status(400).json({ error: 'TOTP code required (6 digits)' });
  // Fix 1 + Fix 3: timing-safe ADMIN_TOKEN comparison only — pgp_ enterprise path removed
  // (pgp_ keys are regular API keys managed per-sector; they don't grant admin access)
  const tokenBuf = Buffer.from(token, 'utf8');
  const adminBuf = Buffer.from(ADMIN_TOKEN, 'utf8');
  const isMaster = ADMIN_TOKEN.length > 0
    && tokenBuf.length === adminBuf.length
    && crypto.timingSafeEqual(tokenBuf, adminBuf);
  if (!isMaster) return res.status(401).json({ error: 'Invalid token' });
  try {
    const r = await relayFetch('health', '/v2/admin/verify-mfa', 'POST', { totp_code: totp }, false, ADMIN_TOKEN);
    if (!r.body?.ok) return res.status(401).json({ error: 'Invalid TOTP code' });
    const sid = await createSession();
    return res.json({ ok: true, session: sid, expires_in: 3600 });
  } catch (e) {
    // Fix 10: don't leak internal relay address in error response
    console.error('[admin] relay unreachable:', e.message);
    return res.status(502).json({ error: 'Relay unreachable' });
  }
});

api.post('/auth/logout', async (req, res) => { await destroySession((req.headers['x-session'] || '').trim()); res.json({ ok: true }); });
api.get('/auth/check', authMiddleware, (req, res) => res.json({ ok: true }));

function sectorRoute(relPath, method) {
  return [authMiddleware, async (req, res) => {
    const { sector } = req.params;
    if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
    try {
      const r = await relayFetch(sector, relPath, method || req.method, method === 'GET' ? null : req.body, false, req.sessionToken);
      res.status(r.status).json(r.body);
    } catch (e) { res.status(502).json({ error: e.message }); }
  }];
}

api.get('/sectors/:sector/keys',            ...sectorRoute('/v2/admin/keys',        'GET'));
api.post('/sectors/:sector/keys',           ...sectorRoute('/v2/admin/keys',        'POST'));
api.post('/sectors/:sector/keys/revoke',    ...sectorRoute('/v2/admin/keys/revoke', 'POST'));
api.post('/sectors/:sector/keys/welcome',   ...sectorRoute('/v2/admin/send-welcome','POST'));
api.get('/sectors/:sector/health',          ...sectorRoute('/health',               'GET'));

function parseMetrics(text) {
  const m = {};
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const sp = line.lastIndexOf(' ');
    if (sp < 0) continue;
    const name = line.slice(0, sp).trim().replace(/\{[^}]*\}/, '');
    const val  = parseFloat(line.slice(sp + 1));
    if (!isNaN(val)) m[name] = val;
  }
  return m;
}

api.get('/sectors/:sector/stats', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/metrics', 'GET', null, true, ADMIN_TOKEN);
    if (r.status !== 200) return res.status(r.status).json({ error: 'metrics unavailable' });
    res.json({ ok: true, metrics: parseMetrics(r.text) });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

api.get('/overview', authMiddleware, async (req, res) => {
  const sectors = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/metrics', 'GET', null, true, ADMIN_TOKEN);
    return { ok: r.status === 200, metrics: parseMetrics(r.text) };
  });
  res.json({ ok: true, sectors });
});

api.get('/keys/all', authMiddleware, async (req, res) => {
  const sectors = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/v2/admin/keys', 'GET', null, false, req.sessionToken);
    return r.status === 200 ? (r.body?.keys || []) : [];
  });
  res.json({ ok: true, sectors });
});

function keyResults(results) {
  const created  = Object.entries(results).filter(([,v]) => v.status === 200 || v.status === 201).map(([s,v]) => ({ sector: s, key: v.data?.key }));
  const failed   = Object.entries(results).filter(([,v]) => v.status !== 200 && v.status !== 201).map(([s,v]) => ({
    sector: s,
    status: v.status,
    error: v.data?.error || `HTTP ${v.status}`,
    ...(v.status === 402 && v.data?.upgrade_url ? { upgrade_url: v.data.upgrade_url } : {})
  }));
  const upgradeRequired = failed.some(f => f.status === 402);
  return { created, failed, allOk: failed.length === 0, upgradeRequired };
}

api.post('/keys/all', authMiddleware, async (req, res) => {
  const body = { ...req.body, key: 'pgp_' + crypto.randomBytes(32).toString('hex') };
  const results = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/v2/admin/keys', 'POST', body, false, req.sessionToken);
    return { status: r.status, data: r.body };
  });
  const { created, failed, allOk, upgradeRequired } = keyResults(results);
  const statusCode = upgradeRequired ? 402 : (allOk ? 200 : 207);
  res.status(statusCode).json({ ok: allOk, created, failed, results,
    ...(upgradeRequired ? { upgrade_url: 'https://paramant.app/pricing' } : {}) });
});

api.post('/keys/sectors', authMiddleware, async (req, res) => {
  const { sectors, ...body } = req.body || {};
  if (!Array.isArray(sectors) || !sectors.length) return res.status(400).json({ error: 'sectors array required' });
  const invalid = sectors.filter(s => !SECTORS[s]);
  if (invalid.length) return res.status(400).json({ error: `Unknown sectors: ${invalid.join(', ')}` });
  const sectorBody = { ...body, key: 'pgp_' + crypto.randomBytes(32).toString('hex') };
  const results = await eachSector(sectors, async s => {
    const r = await relayFetch(s, '/v2/admin/keys', 'POST', sectorBody, false, req.sessionToken);
    return { status: r.status, data: r.body };
  });
  const { created, failed, allOk, upgradeRequired } = keyResults(results);
  const statusCode = upgradeRequired ? 402 : (allOk ? 200 : 207);
  res.status(statusCode).json({ ok: allOk, created, failed, results,
    ...(upgradeRequired ? { upgrade_url: 'https://paramant.app/pricing' } : {}) });
});

api.post('/keys/all/revoke', authMiddleware, async (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: 'key required' });
  const results = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/v2/admin/keys/revoke', 'POST', { key }, false, req.sessionToken);
    return { status: r.status, ok: r.status === 200 };
  });
  const anyRevoked = Object.values(results).some(r => r.ok);
  if (anyRevoked) {
    try { await logAuditEvent(key, 'admin_key_revoked', { admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
  }
  res.status(anyRevoked ? 200 : 502).json({ ok: anyRevoked, results });
});


api.post('/admin/resend-setup', async (req, res) => {
  const tok = (req.headers['x-admin-token'] || req.headers['x-api-key'] || '').trim();
  if (!ADMIN_TOKEN || tok.length !== ADMIN_TOKEN.length ||
      !crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(ADMIN_TOKEN)))
    return res.status(401).json({ error: 'unauthorized' });
  const { user_id, email } = req.body || {};
  if (!user_id || !email) return res.status(400).json({ error: 'missing_fields' });
  // Rate limit: max 10 admin resends per user per 24h
  const adminRlKey = `paramant:ratelimit:admin_resend:${user_id}`;
  const adminRlCnt = await redis().incr(adminRlKey);
  if (adminRlCnt === 1) await redis().expire(adminRlKey, 86400);
  if (adminRlCnt > 10) return res.status(429).json({ error: 'rate_limited', admin_message: 'Max 10 resends per user per 24h' });
  try {
    await Promise.all([
      redis().del(`paramant:user:totp:${user_id}`),
      redis().del(`paramant:user:totp_active:${user_id}`),
      redis().del(`paramant:user:backup_codes:${user_id}`),
      redis().del(`paramant:user:backup_codes_plaintext:${user_id}`),
    ]);
    for await (const k of redis().scanIterator({ MATCH: 'paramant:user:setup_token:*', COUNT: 100 })) {
      const raw = await redis().get(k);
      if (raw) { try { const d = JSON.parse(raw); if (d.user_id === user_id) await redis().del(k); } catch {} }
    }
    const setupToken = crypto.randomBytes(32).toString('hex');
    await redis().set(
      `paramant:user:setup_token:${setupToken}`,
      JSON.stringify({ user_id, email }),
      { EX: 14 * 86400 }
    );
    await sendSetupEmail(email, setupToken);
    const expiresAt = Date.now() + 14 * 86400 * 1000;
    const setupUrl = `${SITE_URL}/auth/setup/${setupToken}`;
    try { await logAuditEvent(user_id, 'admin_setup_resent', { email, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    console.log(`[admin/resend-setup] sent to ${email}`);
    res.json({ success: true, email, expires_at: expiresAt, setup_url: setupUrl });
  } catch (err) {
    console.error('[admin/resend-setup]', err.message);
    res.status(500).json({ error: err.message });
  }
});

api.get('/license-status', authMiddleware, async (req, res) => {
  const sectors = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/health', 'GET', null, false, ADMIN_TOKEN);
    if (r.status !== 200) return { ok: false, error: `HTTP ${r.status}` };
    const { edition, max_keys, license_expires, license_issued_to } = r.body || {};
    return { ok: true, edition: edition || 'community', max_keys: max_keys ?? null, license_expires: license_expires || null, license_issued_to: license_issued_to || null };
  });
  const anyLicensed = Object.values(sectors).some(s => s.edition === 'licensed');
  res.json({ ok: true, anyLicensed, sectors });
});

api.post('/reload-all', authMiddleware, async (req, res) => {
  const results = await eachSector(Object.keys(SECTORS), async s => {
    const r = await relayFetch(s, '/v2/reload-users', 'POST', {}, false, req.sessionToken);
    return r.body;
  });
  try { await logAuditEvent('admin', 'admin_relay_reload_all', { admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
  res.json({ ok: Object.values(results).every(r => r.ok), results });
});

// -- Visual config (env-file editor) -----------------------------------------
// Whitelist-driven read/write of the relay env file so operators do not have to
// SSH in and hand-edit .env. Disabled unless ADMIN_CONFIG_ENV_PATH points at a
// file the admin can reach (typically a shared volume). See admin/lib/
// config-schema.js + config-store.js and ADMIN.md.

api.get('/admin/config', authMiddleware, (req, res) => {
  if (!configStore.isEnabled()) {
    return res.status(503).json({
      error: 'config_unavailable',
      message: 'Set ADMIN_CONFIG_ENV_PATH to the relay env file to enable the visual config editor.',
    });
  }
  try {
    res.json({ ok: true, enabled: true, ...configStore.readConfig() });
  } catch (err) {
    res.status(500).json({ error: 'config_read_failed', message: err.message });
  }
});

api.put('/admin/config', authMiddleware, async (req, res) => {
  if (!configStore.isEnabled()) {
    return res.status(503).json({ error: 'config_unavailable' });
  }
  const changes = Array.isArray(req.body && req.body.changes) ? req.body.changes : null;
  if (!changes) return res.status(400).json({ error: 'bad_request', message: 'Body must be { changes: [{ key, value }] }' });

  const result = configStore.writeConfig(changes);
  if (!result.ok) return res.status(400).json({ error: 'config_write_failed', message: result.error });

  const admin_ip = req.headers['x-real-ip'] || 'unknown';
  // Audit each change with masked values; never log secrets in plaintext.
  for (const ch of changes) {
    try {
      await logAuditEvent('admin', 'admin_config_changed', {
        key: ch.key,
        new_value: configStore.auditValue(ch.key, ch.value),
        admin_ip,
      });
    } catch {}
  }
  if (result.backup) {
    try { await logAuditEvent('admin', 'admin_config_backup_created', { backup_file: result.backup, admin_ip }); } catch {}
  }

  const requiresRestart = result.applied.some(a => a.requires_restart);
  res.json({
    ok: true,
    applied: result.applied,
    requires_restart: requiresRestart,
    restart_targets: [...new Set(result.applied.map(a => a.requires_restart))],
    rolled_back: false,
  });
});

// Restart is a deliberate manual operator step. The admin service does NOT
// execute docker/systemctl on the relays: that would be a shell exec from the
// admin container and an automatic production action. We return instructions
// and let the operator run it.
api.post('/admin/config/restart', authMiddleware, async (req, res) => {
  const admin_ip = req.headers['x-real-ip'] || 'unknown';
  try { await logAuditEvent('admin', 'admin_config_restart_requested', { admin_ip }); } catch {}
  res.status(501).json({
    ok: false,
    manual_restart_required: true,
    message: 'Config saved. Restart the relays to apply: `docker compose restart` on the relay host (or your orchestrator equivalent). The admin panel does not restart production services automatically.',
  });
});

// Config-scoped audit feed for the panel's Configuration tab.
api.get('/admin/config/audit', authMiddleware, async (req, res) => {
  try {
    const events = await getAuditEvents('admin', {
      limit: 100,
      event_types: ['admin_config_changed', 'admin_config_backup_created', 'admin_config_restart_requested'],
    });
    res.json({ ok: true, events });
  } catch (err) {
    res.status(500).json({ error: 'audit_read_failed', message: err.message });
  }
});

// ── Self-service trial key request — DEPRECATED 2026-04-21 ──────────────────
// Trial-key-by-email flow retired. /signup + TOTP is the single acquisition path.
// Historical trial keys remain valid until their natural 30-day expiry.
api.post('/request-key', (req, res) => {
  res.status(410).json({
    error: 'endpoint_deprecated',
    message: 'The /request-key trial flow has been retired. Create a free account at paramant.app/signup to receive your API key with TOTP protection.',
    migration_path: 'https://paramant.app/signup',
    deprecation_date: '2026-04-21',
    existing_keys_note: 'Trial keys issued before this date remain valid until their original 30-day expiry.'
  });
});

// ── User auth constants ───────────────────────────────────────────────────────
const INTERNAL_TOKEN = process.env.INTERNAL_AUTH_TOKEN || "";
const SITE_URL       = process.env.SITE_URL            || "https://paramant.app";

function parseCookies(req) {
  const c = {};
  (req.headers.cookie || "").split(";").forEach(part => {
    const [k, ...v] = part.trim().split("=");
    if (k) c[k.trim()] = decodeURIComponent(v.join("="));
  });
  return c;
}

// Call relay internal endpoint (with X-Internal-Auth)
async function callRelay(endpoint, body, method = "POST") {
  const relayUrl = SECTORS.health;
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Token": ADMIN_TOKEN,
      "Authorization": `Bearer ${ADMIN_TOKEN}`,
      "X-Internal-Auth": INTERNAL_TOKEN,
    },
    keepalive: false,
  };
  if (method !== "GET" && method !== "HEAD") {
    opts.body = JSON.stringify(body || {});
  }
  const res = await fetch(`${relayUrl}${endpoint}`, opts);
  return res;
}

// Find API key entry by email (queries health relay)
async function findUserByEmail(email) {
  const lower = email.toLowerCase();
  const r = await relayFetch("health", "/v2/admin/keys", "GET", null, false, ADMIN_TOKEN);
  if (r.status !== 200) return null;
  const keys = r.body?.keys || [];
  return keys.find(k => k.email && k.email.toLowerCase() === lower && k.active !== false) || null;
}

// Find API key entry by its key id (reverse of findUserByEmail). Used by the
// usernameless/discoverable passkey login to resolve the email for the session
// record after identity has been proven by the credential. Same source/cost as
// findUserByEmail (one /v2/admin/keys read). Returns null if not found.
async function findUserById(userId) {
  if (!userId) return null;
  const r = await relayFetch("health", "/v2/admin/keys", "GET", null, false, ADMIN_TOKEN);
  if (r.status !== 200) return null;
  const keys = r.body?.keys || [];
  return keys.find(k => k.key === userId && k.active !== false) || null;
}

// Send setup email via Resend
async function sendSetupEmail(email, setupToken, isReset = false) {
  const msg = emailTemplates.setupEmail({ token: setupToken, requestedAt: Date.now(), requestIP: '', isReset: !!isReset });
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html, headers: msg.headers }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => '')}`);
}


// Send signup email-verification link
async function sendVerificationEmail(email, token, requestIP) {
  const msg = emailTemplates.signupVerificationEmail({ email, token, requestedAt: Date.now(), requestIP });
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html, headers: msg.headers }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => '')}`);
}

// Send "someone tried to sign up with your email" notice to an existing
// account owner. Called from the duplicate branch of /api/user/signup so
// both branches do the same kind of outbound work (no timing oracle).
async function sendDuplicateSignupAttempt(email, requestIP) {
  const msg = emailTemplates.duplicateSignupAttemptEmail({ email, requestedAt: Date.now(), requestIP });
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html, headers: msg.headers }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => '')}`);
}

// Send TOTP reset confirmation email (step 1 of two-stage flow)
async function sendResetConfirmEmail(email, confirmToken, maskedIp, requestedAt) {
  const msg = emailTemplates.resetConfirmationEmail({ confirmToken, requestedAt, requestIP: maskedIp });
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html, headers: msg.headers }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => '')}`);
}

// ── User session middleware ────────────────────────────────────────────────────
async function authUser(req, res, next) {
  const token = parseCookies(req).paramant_user_session;
  if (!token) return res.status(401).json({ error: "unauthenticated" });
  try {
    const raw = await redis().get(`paramant:user:session:${token}`);
    if (!raw) return res.status(401).json({ error: "session_expired" });
    await redis().expire(`paramant:user:session:${token}`, 3600);
    req.userSession = JSON.parse(raw);
    req.userSessionToken = token;
    next();
  } catch (err) {
    console.error("[authUser]", err.message);
    res.status(503).json({ error: "session_store_unavailable" });
  }
}

// ── Developer dashboard allowlist ───────────────────────────────────────────
// Extra gate ON TOP OF authUser for the hidden /developer dashboard. The email
// allowlist comes from env only (DEVELOPER_ALLOWLIST, comma-separated) — never
// hardcoded. The pure logic lives in ./lib/developer-gate (unit-tested in
// admin/test/developer-gate.test.js).
const { isDeveloper } = require("./lib/developer-gate");
// Gate for /api/user/developer/* data endpoints. Runs after authUser (which
// 401s on no session). A valid session that is not on the allowlist gets a
// 404 — indistinguishable from "this route does not exist", so the developer
// surface stays hidden from logged-in non-developers (never 403).
function developerGate(req, res, next) {
  if (!isDeveloper(req.userSession && req.userSession.email))
    return res.status(404).json({ error: "not_found" });
  next();
}
// Operations-dashboard data libs (CLI catalogue + snapshot builder). Source of
// truth for the descriptions is paramant-solutions/tools/. Unit-tested in
// admin/test/developer-snapshot.test.js.
const { DEVELOPER_TOOLS } = require('./lib/developer-tools');
const { buildSnapshot } = require('./lib/developer-snapshot');
const developerConfig = require('./lib/developer-config');

// Session cookie is SameSite=Lax (was Strict). Deliberate choice (ADR R018):
// the invite/co-sign flow lands a recipient via a top-level navigation from an
// emailed link (cross-site, from their mail client). A Strict cookie is NOT
// sent on that first cross-site navigation, so an already-logged-in recipient
// would be bounced to re-authenticate on exactly the flow this is built for.
// Lax sends the cookie on top-level GET navigations only -- NOT on cross-site
// POST/DELETE -- so CSRF protection for the state-changing endpoints is
// preserved. HttpOnly + Secure are unchanged. NOTE: this also moves the
// existing email+TOTP login to Lax (one shared cookie).
function setUserCookie(res, token) {
  res.setHeader("Set-Cookie",
    `paramant_user_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600`
  );
}

function clearUserCookie(res) {
  res.setHeader("Set-Cookie",
    "paramant_user_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  );
}

// ── Signup flow ───────────────────────────────────────────────────────────────


// GET /api/captcha/challenge
api.get('/captcha/challenge', async (req, res) => {
  try {
    res.json(await pow.issueChallenge());
  } catch (e) {
    res.status(500).json({ error: 'challenge_failed' });
  }
});

// Disposable / reserved domain denylist
const BLOCKED_DOMAINS = new Set([
  'localhost', 'example.com', 'example.org', 'example.net',
  'test.com', 'test.local', 'test.invalid',
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net',
  'guerrillamail.org', 'guerrillamail.de', 'guerrillamail.info',
  'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
  'spam4.me', 'yopmail.com', 'yopmail.fr', 'cool.fr.nf',
  'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx',
  'mega.zik.dj', 'speed.1s.fr', 'courriel.fr.nf',
  'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
  'trashmail.at', 'trashmail.com', 'trashmail.io',
  'trashmail.me', 'trashmail.net', 'trashmail.org',
  'dispostable.com', 'fakeinbox.com', 'maildrop.cc',
  'discard.email', 'tempr.email', 'temp-mail.org',
]);
// Also block reserved TLDs
const BLOCKED_TLDS = ['.local', '.test', '.invalid', '.example', '.localhost'];

function isBlockedEmail(email) {
  const lower = email.toLowerCase();
  const atIdx = lower.lastIndexOf('@');
  if (atIdx < 0) return true;
  const domain = lower.slice(atIdx + 1);
  if (BLOCKED_DOMAINS.has(domain)) return true;
  for (const tld of BLOCKED_TLDS) {
    if (domain.endsWith(tld)) return true;
  }
  return false;
}

// POST /api/user/signup — stage 1: issue verification email, do NOT create account yet
api.post("/user/signup", async (req, res) => {
  const { email, label, dpa_accepted, challenge_id, nonce } = req.body || {};
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";

  // 1. PoW first — before any email lookup (prevents oracle abuse)
  const proof = await pow.verifyChallenge(challenge_id, nonce);
  if (!proof.valid) return res.status(403).json({ error: 'captcha_failed', reason: proof.reason });

  // 2. Basic field validation
  if (!email || !dpa_accepted) return res.status(400).json({ error: "missing_fields" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
  if (isBlockedEmail(email)) return res.status(422).json({ error: "invalid_email", reason: "domain_not_allowed" });

  const norm = email.toLowerCase().trim();

  // 3. Per-IP rate limit (10 per hour)
  const ipKey = `paramant:signup:ratelimit:ip:${ip}`;
  const ipCount = await redis().incr(ipKey);
  if (ipCount === 1) await redis().expire(ipKey, 3600);
  if (ipCount > 10) return res.status(429).json({ error: "rate_limited" });

  // 4. Per-email rate limit (10 verification emails per 24h, hashed for privacy)
  const emailHash = crypto.createHash('sha256').update(norm).digest('hex');
  const emailKey = `paramant:signup:ratelimit:email:${emailHash}`;
  const emailCount = await redis().incr(emailKey);
  if (emailCount === 1) await redis().expire(emailKey, 86400);
  if (emailCount > 10) return res.status(429).json({ error: "rate_limited", reason: "too_many_attempts_for_email" });

  // 5. Both branches do the same kind of work (one Redis SET + one outbound
  // mail enqueue) and return the same response, so the request cannot be
  // used as an existence oracle through timing or response shape. The
  // outbound mail is dispatched fire-and-forget via setImmediate so the
  // Resend API latency (~200-500ms) is not in the response path.
  const existing = await findUserByEmail(norm);
  const verifyToken = crypto.randomBytes(32).toString("hex");

  if (existing) {
    // Dummy token entry under an isolated namespace. Cannot be redeemed for
    // signup (the verify route only reads paramant:signup:pending:*). Keeps
    // the Redis I/O equivalent to the new-email branch.
    await redis().set(
      `paramant:signup:duplicate:${verifyToken}`,
      JSON.stringify({ email_hash: emailHash, ip, attempted_at: Date.now() }),
      { EX: 86400 }
    );
    // Fire-and-forget: tell the actual owner someone tried to claim their
    // address. Only the real account holder can receive this mail, so it is
    // not itself an oracle.
    setImmediate(() => {
      sendDuplicateSignupAttempt(norm, ip).catch(err =>
        console.error("[signup] duplicate notice failed:", err.message));
    });
    console.log(`[signup] duplicate signup attempt: ${emailHash.slice(0, 8)} from ${ip}`);
  } else {
    // Real pending signup token.
    await redis().set(
      `paramant:signup:pending:${verifyToken}`,
      JSON.stringify({ email: norm, label: label || null, ip, requested_at: Date.now() }),
      { EX: 86400 }
    );
    // Fire-and-forget verification mail. On Resend failure we delete the
    // pending token so the caller can retry the signup form. Per-email rate
    // limit still applies, but a single Resend hiccup will not surface as a
    // 500 to the user.
    setImmediate(() => {
      sendVerificationEmail(norm, verifyToken, ip).catch(err => {
        console.error("[signup] verification email failed:", err.message);
        redis().del(`paramant:signup:pending:${verifyToken}`).catch(() => {});
      });
    });
    console.log(`[signup] pending signup for ${norm} from ${ip}`);
  }

  // Identical response shape and timing in both branches.
  res.json({ success: true, message: "verification_email_sent" });
});

// GET /api/user/signup/verify/:token — stage 2: create account after email click
api.get("/user/signup/verify/:token", async (req, res) => {
  const { token } = req.params;
  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    return res.redirect('/signup?error=invalid_token');
  }

  const raw = await redis().get(`paramant:signup:pending:${token}`);
  if (!raw) {
    // Re-click on already-consumed token: if we verified this one recently, just send them back to /signup/verified.
    const consumed = await redis().get(`paramant:signup:consumed:${token}`);
    if (consumed) return res.redirect('/signup/verified');
    return res.redirect('/signup?error=expired_token');
  }

  let pending;
  try { pending = JSON.parse(raw); } catch { return res.redirect('/signup?error=invalid_token'); }

  // Consume immediately (one-shot)
  await redis().del(`paramant:signup:pending:${token}`);

  const { email, label } = pending;

  // Check again — race guard
  const existing = await findUserByEmail(email);
  if (existing) return res.redirect('/signup?error=account_exists');

  // Create the account across every sector listed in SECTORS so the key works
  // on every relay -- including main (relay.paramant.app, internal sector
  // "relay") which the SDK and direct API consumers target. Before SECTORS
  // gained the 'main' entry (added together with this comment), the fan-out
  // silently skipped main even while claiming to write to "every sector",
  // and main's users.json drifted weeks behind the others.
  const keyVal = "pgp_" + crypto.randomBytes(32).toString("hex");
  const createdAt = new Date().toISOString();
  const createBody = {
    key: keyVal,
    email,
    label: label || null,
    plan: "community",
    active: true,
    created: createdAt,
    created_at_ts: Date.now(),
  };

  // health is the source of truth for admin UI visibility. Must succeed.
  const primaryRes = await relayFetch("health", "/v2/admin/keys", "POST", createBody, false, ADMIN_TOKEN);
  if (primaryRes.status !== 200 && primaryRes.status !== 201) {
    console.error("[signup/verify] key creation failed on health:", primaryRes.status, primaryRes.body);
    return res.redirect('/signup?error=server_error');
  }

  // Fan-out to the other sectors. Best-effort — if one is briefly unavailable, reload-users
  // can pick it up later; we don't want to leak a half-created account by failing the whole
  // signup here after health succeeded.
  const otherSectors = Object.keys(SECTORS).filter(s => s !== "health");
  await Promise.all(otherSectors.map(s =>
    relayFetch(s, "/v2/admin/keys", "POST", createBody, false, ADMIN_TOKEN).catch(e => {
      console.error(`[signup/verify] key propagation failed on ${s}:`, e && e.message || e);
    })
  ));

  const setupToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:setup_token:${setupToken}`,
    JSON.stringify({ user_id: keyVal, email, label: label || null }),
    { EX: 14 * 86400 }
  );
  await redis().set(
    `paramant:user:meta:${keyVal}`,
    JSON.stringify({ email, created_at: createdAt })
  ).catch(() => {});

  try {
    await sendSetupEmail(email, setupToken);
  } catch (err) {
    console.error("[signup/verify] setup email failed:", err.message);
    // Account exists, don't undo — they can contact support
  }

  // Mark this token as consumed so later re-clicks (refresh/back/double-tap) route back to /signup/verified instead of error.
  await redis().set(`paramant:signup:consumed:${token}`, keyVal, { EX: 30 * 86400 }).catch(() => {});

  console.log(`[signup/verify] account created for ${email} (${keyVal.slice(0, 12)}...)`);
  res.redirect('/signup/verified');
});

// POST /api/user/setup/:token — retrieve TOTP QR data (idempotent)
api.post("/user/setup/:token", async (req, res) => {
  const { token } = req.params;
  const raw = await redis().get(`paramant:user:setup_token:${token}`);
  if (!raw) return res.status(401).json({ error: "invalid_or_expired_token" });

  const { user_id, email } = JSON.parse(raw);

  // Idempotency: return existing provisional secret if one was already generated
  let secret, backup_codes;
  const provRes = await callRelay("/v2/user/get-totp-provisional", { user_id });
  if (provRes.ok) {
    const prov = await provRes.json();
    if (prov.exists) { secret = prov.secret; backup_codes = prov.backup_codes; }
  }

  if (!secret) {
    const relayRes = await callRelay("/v2/user/setup-totp", { user_id, provisional: true });
    if (!relayRes.ok) return res.status(relayRes.status).json(await relayRes.json().catch(() => ({ error: "relay_error" })));
    ({ secret, backup_codes } = await relayRes.json());
  }

  const issuer = "Paramant";
  const encodedEmail = encodeURIComponent(email);
  const otpauth = `otpauth://totp/${issuer}:${encodedEmail}?secret=${secret}&issuer=${issuer}&algorithm=SHA256&digits=6&period=30`;

  res.json({ email, otpauth, secret, backup_codes });
});

// POST /api/user/setup/:token/confirm — verify first code, activate TOTP, issue session
api.post("/user/setup/:token/confirm", async (req, res) => {
  const { token } = req.params;
  const { totp } = req.body || {};

  const raw = await redis().get(`paramant:user:setup_token:${token}`);
  if (!raw) return res.status(401).json({ error: "invalid_or_expired_token" });

  const { user_id, email } = JSON.parse(raw);

  const verifyRes = await callRelay("/v2/user/verify-totp", { user_id, totp });
  if (!verifyRes.ok) return res.status(401).json({ error: "invalid_code" });
  const result = await verifyRes.json();
  if (!result.valid) return res.status(401).json({ error: "invalid_code" });

  // Activation mints the backup codes and returns them exactly once. This is the
  // only place the plaintext codes exist, so we read them straight from the
  // activate response — no separate (and previously non-existent) lookup.
  const activateRes = await callRelay("/v2/user/activate-totp", { user_id });
  const { backup_codes } = activateRes.ok ? await activateRes.json() : { backup_codes: [] };
  await redis().del(`paramant:user:setup_token:${token}`);

  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id, email, created_at: Date.now(), ip: req.headers["x-real-ip"] || "unknown", ua: req.get("user-agent") || "", ...sessionKeyFields(user_id) }),
    { EX: 3600 }
  );

  setUserCookie(res, sessionToken);

  res.json({ success: true, email, backup_codes });
});

// ── Login flow ────────────────────────────────────────────────────────────────

// POST /api/user/login
api.post("/user/login", async (req, res) => {
  const { email, totp } = req.body || {};
  if (!email || !totp) return res.status(400).json({ error: "missing_fields" });

  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const ipKey    = `paramant:user:ratelimit:ip:${ip}`;
  const emailKey = `paramant:user:ratelimit:email:${email.toLowerCase()}`;
  const ipCount    = await redis().incr(ipKey);    if (ipCount    === 1) await redis().expire(ipKey,    900);
  const emailCount = await redis().incr(emailKey); if (emailCount === 1) await redis().expire(emailKey, 900);
  if (ipCount > 5 || emailCount > 10) return res.status(429).json({ error: "rate_limited" });

  const user = await findUserByEmail(email);
  if (!user) return res.status(401).json({ error: "invalid_credentials" });

  const activeRaw = await redis().get(`paramant:user:totp_active:${user.key}`);
  if (activeRaw !== "true") {
    const metaRaw = await redis().get(`paramant:user:meta:${user.key}`).catch(() => null);
    let um = {}; try { if (metaRaw) um = JSON.parse(metaRaw); } catch {}
    if (um.totp_required) {
      if (um.email || user.email) {
        const setupToken = (await import('crypto')).randomBytes ? require('crypto').randomBytes(32).toString('hex') : '';
        if (setupToken) {
          await redis().set(`paramant:user:setup_token:${setupToken}`, JSON.stringify({ user_id: user.key, email: um.email || user.email }), { EX: 14 * 86400 });
          sendSetupEmail(um.email || user.email, setupToken).catch(e => console.error('[login/totp_required] email:', e.message));
        }
      }
      // Setup mail is dispatched fire-and-forget above. Respond identically
      // to "no such account" so the status code cannot be used as an
      // enumeration oracle. Was: 403 totp_setup_required, which leaked the
      // fact that the email belongs to a real account with admin-required
      // TOTP not yet set up.
      return res.status(401).json({ error: "invalid_credentials" });
    }
    // Same 401 for TOTP-not-configured so this branch also does not leak
    // account existence. Was: 403 totp_not_configured.
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const verifyRes = await callRelay("/v2/user/verify-totp", { user_id: user.key, totp });
  if (!verifyRes.ok) return res.status(401).json({ error: "invalid_credentials" });
  const result = await verifyRes.json();
  if (!result.valid) return res.status(401).json({ error: "invalid_credentials" });

  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id: user.key, email: user.email, created_at: Date.now(), ip, ua: req.get("user-agent") || "", ...sessionKeyFields(user.key) }),
    { EX: 3600 }
  );

  setUserCookie(res, sessionToken);

  res.json({
    success: true,
    email: user.email,
    session_expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
  });
});

// POST /api/user/login-with-backup
api.post("/user/login-with-backup", async (req, res) => {
  const { email, backup_code } = req.body || {};
  if (!email || !backup_code) return res.status(400).json({ error: "missing_fields" });

  const user = await findUserByEmail(email);
  if (!user) return res.status(401).json({ error: "invalid_credentials" });

  const consumeRes = await callRelay("/v2/user/consume-backup", {
    user_id: user.key,
    code: backup_code.trim().toUpperCase(),
  });
  const result = await consumeRes.json();
  if (!result.valid) return res.status(401).json({ error: "invalid_credentials" });

  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id: user.key, email: user.email, created_at: Date.now(), ip: req.headers["x-real-ip"] || "unknown", ua: req.get("user-agent") || "", via: "backup_code", ...sessionKeyFields(user.key) }),
    { EX: 3600 }
  );

  setUserCookie(res, sessionToken);
  res.json({ success: true, email: user.email });
});


// ── Passkey (WebAuthn) login (ADR R018, PR-A) ───────────────────────────────
// Two-step ceremony. rpId/origin are config constants (webauthn.RP_ID /
// EXPECTED_ORIGIN), never derived from the request. Challenges are one-shot.
// Passkey is a sufficient sole login factor (no TOTP step) -- see R018.

// POST /api/user/auth/webauthn/login/options
// Issues an authentication challenge. Uniform response shape regardless of
// whether the email exists / has passkeys (unknown -> stable decoy credential),
// so it is not an account-existence oracle. Rate-limited per IP AND per account.
api.post("/user/auth/webauthn/login/options", async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.loginOptions;
  if (!(await webauthn.rateHit(redis(), `lo:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });
  const email = (req.body?.email || "").toString().toLowerCase().trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
  if (!(await webauthn.rateHit(redis(), `lo:acct:${webauthn.scopeHash(email)}`, L.account, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // Resolve the account's passkeys (email-first). Any failure / no-passkey /
  // unknown email falls through to a stable decoy so verify fails identically.
  let userId = null, allowCredentials = [];
  try {
    const user = await findUserByEmail(email);
    if (user) {
      userId = user.key;
      const r = await callRelay(`/v2/user/webauthn/credentials?user_id=${encodeURIComponent(userId)}`, null, "GET");
      if (r.status === 200) {
        const body = await r.json().catch(() => ({}));
        allowCredentials = (body.credentials || []).map(c => ({ id: c.credId, transports: c.transports }));
      }
    }
  } catch (e) { /* fall through to decoy */ }
  // Residual: a populated allowCredentials reveals "this account has >=1
  // passkey" (not "exists" -- an account without passkeys also gets the decoy).
  if (allowCredentials.length === 0) {
    allowCredentials = [{ id: Buffer.from(webauthn.scopeHash("decoy:" + email), "hex").toString("base64url") }];
  }

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID: webauthn.RP_ID,
      allowCredentials,
      userVerification: "required",
    });
  } catch (e) {
    console.error("[webauthn/login/options]", e.message);
    return res.status(500).json({ error: "internal" });
  }
  const flowId = webauthn.newFlowId();
  await webauthn.putAuthFlow(redis(), flowId, { challenge: options.challenge, email, user_id: userId });
  res.json({ flowId, options });
});

// POST /api/user/auth/webauthn/login/discoverable/options
// Usernameless / cross-device login. Returns options with an EMPTY
// allowCredentials list so the browser offers its account-chooser + the QR
// "use a phone" path (WebAuthn hybrid transport). No email is bound to the
// flow: identity is established at verify from the discoverable credential the
// user proves possession of (credId -> account, cross-checked against the
// assertion's userHandle). Rate-limited per IP only (no account scope to leak).
api.post("/user/auth/webauthn/login/discoverable/options", async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.loginOptions;
  if (!(await webauthn.rateHit(redis(), `lo:disc:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID: webauthn.RP_ID,
      allowCredentials: [],          // discoverable: browser shows QR + account chooser
      userVerification: "required",
    });
  } catch (e) {
    console.error("[webauthn/login/discoverable/options]", e.message);
    return res.status(500).json({ error: "internal" });
  }
  const flowId = webauthn.newFlowId();
  await webauthn.putAuthFlow(redis(), flowId, { challenge: options.challenge, discoverable: true });
  res.json({ flowId, options });
});

// POST /api/user/auth/webauthn/login/verify
// Verifies the assertion and, on success, issues the session. Identity comes
// ONLY from the assertion (never a client-supplied user id). Rate-limited per
// IP AND per account.
api.post("/user/auth/webauthn/login/verify", async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.loginVerify;
  if (!(await webauthn.rateHit(redis(), `lv:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  const { flowId, response } = req.body || {};
  const flow = await webauthn.takeAuthFlow(redis(), flowId);   // one-shot: consumed before any crypto
  if (!flow || !response) return res.status(401).json({ error: "invalid_credentials" });
  if (flow.email && !(await webauthn.rateHit(redis(), `lv:acct:${webauthn.scopeHash(flow.email)}`, L.account, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // Identity from the assertion only: resolve its credential id to an account
  // via the relay. For an email-first flow the account MUST match the one the
  // challenge was bound to (a decoy flow has user_id=null -> always rejected).
  // For a discoverable (usernameless) flow there is no bound account: identity
  // IS whatever the proven credential resolves to, additionally cross-checked
  // against the assertion's userHandle so the credential and its claimed handle
  // must agree before a session is issued.
  let lookup;
  try {
    const r = await callRelay(`/v2/user/webauthn/lookup?cred_id=${encodeURIComponent(String(response.id || ""))}`, null, "GET");
    if (r.status !== 200) return res.status(401).json({ error: "invalid_credentials" });
    lookup = await r.json();
  } catch (e) { return res.status(401).json({ error: "invalid_credentials" }); }
  if (!lookup || !lookup.user_id) return res.status(401).json({ error: "invalid_credentials" });

  let authedUserId, authedEmail;
  if (flow.discoverable) {
    // Usernameless: cross-check the assertion's userHandle resolves to the SAME
    // account as the credential id (defence in depth against a mismatched pair).
    const handleB64 = response.response && response.response.userHandle;
    if (!handleB64) return res.status(401).json({ error: "invalid_credentials" });
    try {
      const hr = await callRelay(`/v2/user/webauthn/by-handle?handle=${encodeURIComponent(String(handleB64))}`, null, "GET");
      if (hr.status !== 200) return res.status(401).json({ error: "invalid_credentials" });
      const hb = await hr.json();
      if (!hb.user_id || hb.user_id !== lookup.user_id) return res.status(401).json({ error: "invalid_credentials" });
    } catch (e) { return res.status(401).json({ error: "invalid_credentials" }); }
    authedUserId = lookup.user_id;
    authedEmail = (await findUserById(authedUserId).catch(() => null))?.email || null;
  } else {
    if (!flow.user_id || lookup.user_id !== flow.user_id) return res.status(401).json({ error: "invalid_credentials" });
    authedUserId = flow.user_id;
    authedEmail = flow.email;
  }

  // Verify the assertion. expectedOrigin/expectedRPID are config constants.
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: flow.challenge,
      expectedOrigin: webauthn.EXPECTED_ORIGIN,
      expectedRPID: webauthn.RP_ID,
      credential: {
        id: lookup.credId,
        publicKey: new Uint8Array(Buffer.from(lookup.publicKey, "base64url")),
        counter: lookup.counter | 0,
      },
      requireUserVerification: true,
    });
  } catch (e) { return res.status(401).json({ error: "invalid_credentials" }); }
  if (!verification.verified) return res.status(401).json({ error: "invalid_credentials" });

  // Cloned-authenticator guard (the exact rule, in webauthn.counterIsAcceptable):
  //   stored or new counter == 0 -> allowed, not compared (iCloud Keychain = 0)
  //   both non-zero -> new MUST be strictly higher, else refuse with NO session.
  const newCounter = verification.authenticationInfo.newCounter;
  if (!webauthn.counterIsAcceptable(lookup.counter, newCounter)) {
    try { logAuditEvent("webauthn_counter_regression", { user_id: String(authedUserId).slice(0, 12) + "…", stored: lookup.counter | 0, presented: newCounter | 0 }); } catch {}
    return res.status(401).json({ error: "invalid_credentials" });
  }
  // Persist the advanced counter (auth already succeeded; best-effort).
  try { await callRelay("/v2/user/webauthn/counter", { user_id: authedUserId, cred_id: lookup.credId, counter: newCounter }); } catch {}

  // Issue the session. Passkey is a sufficient sole factor (ADR R018) -- NO TOTP
  // step. Same shape/TTL/cookie as the email+TOTP path. via marks how the
  // passkey was presented: 'webauthn' (email-first) or 'webauthn_xdev'
  // (usernameless / cross-device).
  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id: authedUserId, email: authedEmail, created_at: Date.now(), ip, ua: req.get("user-agent") || "", via: flow.discoverable ? "webauthn_xdev" : "webauthn", ...sessionKeyFields(authedUserId) }),
    { EX: 3600 }
  );
  setUserCookie(res, sessionToken);
  try { logAuditEvent("webauthn_login", { user_id: String(authedUserId).slice(0, 12) + "…" }); } catch {}
  res.json({ success: true, email: authedEmail });
});


// Shared WebAuthn registration core (ADR R018). Verifies the attestation
// against the one-shot reg-flow's challenge (rpId/origin are config constants,
// never request-derived) and persists the credential with its initial counter
// (counter-init). Used by BOTH the setup_token onboarding flow and the
// authUser+TOTP add-passkey flow — one implementation, different gates in front.
// The relay's storeCredential keeps the cross-account-conflict check (a credId
// already bound to another account is rejected -> surfaced here as 409).
// Returns { ok:true } or { ok:false, status, error }.
async function webauthnVerifyAndStore(flow, response, label) {
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: flow.challenge,
      expectedOrigin: webauthn.EXPECTED_ORIGIN,
      expectedRPID: webauthn.RP_ID,
      requireUserVerification: true,
    });
  } catch (e) { return { ok: false, status: 400, error: "verification_failed" }; }
  if (!verification.verified || !verification.registrationInfo) return { ok: false, status: 400, error: "verification_failed" };
  const info = verification.registrationInfo;
  const cred = info.credential;   // { id, publicKey: Uint8Array, counter, transports? }
  try {
    const sr = await callRelay("/v2/user/webauthn/credential", {
      user_id: flow.user_id,
      credId: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString("base64url"),
      counter: cred.counter | 0,                       // counter-init
      transports: (response.response && response.response.transports) || cred.transports || [],
      prfSupported: !!(response.clientExtensionResults && response.clientExtensionResults.prf && response.clientExtensionResults.prf.enabled),
      aaguid: info.aaguid || "",
      label: (label || "").toString().slice(0, 64) || null,
    });
    if (sr.status !== 200) {
      // 400 from the relay = storeCredential rejected (e.g. cross-account
      // credential conflict) -> 409; anything else -> 502.
      const body = await sr.json().catch(() => ({}));
      return { ok: false, status: sr.status === 400 ? 409 : 502, error: body.error || "credential_store_failed" };
    }
  } catch (e) { return { ok: false, status: 502, error: "relay_unreachable" }; }
  return { ok: true };
}

// ── Passkey (WebAuthn) registration (ADR R018, PR-A) — TOFU moment ──────────
// First passkey on an account: the foundation of the identity claim. The ONLY
// accepted proof of mailbox possession is a valid setup_token from the email-
// verification signup path (paramant:user:setup_token:*, created only after the
// user clicked the verification link in signup stage 2). So a passkey can NOT
// be registered for an arbitrary email, and there is NO "logged-in implies may
// register" shortcut. The invite-token binding (PR-0, email-bound) is
// deliberately NOT accepted here yet — that path is wired in PR-C with the
// envelope email-hash check.

// POST /api/user/auth/webauthn/register/options
api.post("/user/auth/webauthn/register/options", async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.registerOptions;
  if (!(await webauthn.rateHit(redis(), `ro:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // TOFU binding: a valid setup_token is the only accepted proof here.
  const setupToken = (req.body?.setup_token || "").toString();
  if (!/^[0-9a-f]{64}$/.test(setupToken)) return res.status(400).json({ error: "setup_token_required" });
  const raw = await redis().get(`paramant:user:setup_token:${setupToken}`);
  if (!raw) return res.status(401).json({ error: "invalid_setup_token" });
  let pending; try { pending = JSON.parse(raw); } catch { return res.status(401).json({ error: "invalid_setup_token" }); }
  const { user_id, email } = pending;
  if (!user_id || !email) return res.status(401).json({ error: "invalid_setup_token" });
  if (!(await webauthn.rateHit(redis(), `ro:acct:${webauthn.scopeHash(email)}`, L.account, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // Per-account user handle (random, no PII) + already-registered creds to exclude.
  let handle, excludeCredentials = [];
  try {
    const hr = await callRelay("/v2/user/webauthn/handle", { user_id });
    handle = (await hr.json()).handle;
    const cr = await callRelay(`/v2/user/webauthn/credentials?user_id=${encodeURIComponent(user_id)}`, null, "GET");
    if (cr.status === 200) excludeCredentials = ((await cr.json()).credentials || []).map(c => ({ id: c.credId, transports: c.transports }));
  } catch (e) { console.error("[webauthn/register/options]", e.message); return res.status(502).json({ error: "relay_unreachable" }); }
  if (!handle) return res.status(500).json({ error: "internal" });

  let options;
  try {
    options = await generateRegistrationOptions({
      rpName: webauthn.RP_NAME,
      rpID: webauthn.RP_ID,
      userName: email,
      userID: new Uint8Array(Buffer.from(handle, "base64url")),
      userDisplayName: email,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      extensions: { prf: {} },   // probe PRF support (consumed by PR-B vault unlock)
    });
  } catch (e) { console.error("[webauthn/register/options]", e.message); return res.status(500).json({ error: "internal" }); }

  const flowId = webauthn.newFlowId();
  await webauthn.putRegFlow(redis(), flowId, { challenge: options.challenge, user_id, email, setup_token: setupToken });
  res.json({ flowId, options });
});

// POST /api/user/auth/webauthn/register/verify
// Verifies the attestation, stores the credential, and (TOFU onboarding) issues
// the session. Identity comes from the one-shot reg-flow (bound to the verified
// email via the setup_token), never from client fields.
api.post("/user/auth/webauthn/register/verify", async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.registerVerify;
  if (!(await webauthn.rateHit(redis(), `rv:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  const { flowId, response } = req.body || {};
  const flow = await webauthn.takeRegFlow(redis(), flowId);   // one-shot: consumed before any crypto
  if (!flow || !response) return res.status(401).json({ error: "invalid_registration" });
  if (!(await webauthn.rateHit(redis(), `rv:acct:${webauthn.scopeHash(flow.email)}`, L.account, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // Re-confirm the setup_token still binds this email (mailbox proof) and is
  // unconsumed; it is deleted on success below (one-shot onboarding).
  if (!(await redis().get(`paramant:user:setup_token:${flow.setup_token}`)))
    return res.status(401).json({ error: "invalid_setup_token" });

  // Verify the attestation + persist the credential (shared core: rpId/origin
  // config constants, counter-init, cross-account-conflict check inside).
  const stored = await webauthnVerifyAndStore(flow, response, req.body && req.body.label);
  if (!stored.ok) return res.status(stored.status).json({ error: stored.error });

  // Lockout invariant: a passkey-onboarded account has no TOTP, so this single
  // passkey would be its only factor. Mint backup codes (existing relay infra)
  // so the account stays recoverable via /api/user/login-with-backup -> re-enrol
  // a passkey, even before the email-reset-can-enrol-passkey path exists. The
  // codes are returned ONCE for the user to save. (The IndexedDB vault is not
  // touched here, so the PR-B passphrase-wrap invariant is unaffected.)
  //
  // HARD BOUNDARY: regenerate-backup WIPES existing codes, so it must run ONLY
  // on a fresh onboarding account. That is guaranteed here because a still-valid
  // setup_token means TOTP setup (the only other path that mints codes) has not
  // completed -- so there are no codes to wipe. NEVER move this call outside the
  // setup_token-gated path (e.g. into an add-passkey-to-existing-account flow),
  // or it would destroy a live account's recovery codes.
  let recoveryCodes = [];
  try {
    const br = await callRelay("/v2/user/regenerate-backup", { user_id: flow.user_id });
    if (br.status === 200) recoveryCodes = (await br.json()).backup_codes || [];
  } catch (e) { /* best-effort; surfaced below as recovery_codes: [] */ }

  // One-shot: consume the setup_token so it cannot be reused for another
  // registration or for TOTP setup.
  await redis().del(`paramant:user:setup_token:${flow.setup_token}`).catch(() => {});

  // Issue the session — TOFU onboarding. Passkey is now this account's factor
  // (R018); NO TOTP step. Lax cookie. via:'webauthn-register'.
  // NB: a passkey session does NOT unlock ML-DSA signing — /v2/user/signing-key
  // stays TOTP-gated until the passkey step-up (R018) is built, so signing is
  // blocked (not bypassed) for a passkey-only account.
  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id: flow.user_id, email: flow.email, created_at: Date.now(), ip, ua: req.get("user-agent") || "", via: "webauthn-register", ...sessionKeyFields(flow.user_id) }),
    { EX: 3600 }
  );
  setUserCookie(res, sessionToken);
  try { logAuditEvent("webauthn_register", { user_id: String(flow.user_id).slice(0, 12) + "…" }); } catch {}
  res.json({ success: true, email: flow.email, recovery_codes: recoveryCodes });
});


// ── Add a passkey to an EXISTING logged-in account (authUser + TOTP step-up) ──
// Same WebAuthn ceremony as onboarding, but gated by a live session AND a fresh
// TOTP code instead of a setup_token. Adding a login method is a factor
// mutation, so a valid session ALONE is not enough — a valid TOTP is required
// before the ceremony is released. This flow issues NO new session (already
// logged in) and does NOT touch backup codes (the account already has recovery;
// running regenerate-backup would wipe it). Passkey is purely additive, so the
// lockout invariant trivially holds. /v2/user/signing-key stays TOTP-gated, so
// this does NOT unlock ML-DSA signing.

// POST /api/user/account/webauthn/register/options  (authUser + TOTP step-up)
api.post("/user/account/webauthn/register/options", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;          // identity from the session, never the client
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.registerOptions;
  if (!(await webauthn.rateHit(redis(), `aro:ip:${ip}`, L.ip, L.windowSec))) return res.status(429).json({ error: "rate_limited" });
  if (!(await webauthn.rateHit(redis(), `aro:acct:${webauthn.scopeHash(user_id)}`, L.account, L.windowSec))) return res.status(429).json({ error: "rate_limited" });

  // ── TOTP STEP-UP GATE ──────────────────────────────────────────────────────
  // No valid TOTP -> no registration ceremony, no passkey. The ceremony
  // (options) is released ONLY past this check.
  const totp = (req.body && req.body.totp || "").toString();
  if (!/^\d{6}$/.test(totp)) return res.status(400).json({ error: "totp_required" });
  let totpOk = false;
  try {
    const vr = await callRelay("/v2/user/verify-totp", { user_id, totp });
    const vb = await vr.json().catch(() => ({}));
    totpOk = vr.ok && vb.valid === true;
  } catch (e) { return res.status(502).json({ error: "relay_unreachable" }); }
  if (!totpOk) return res.status(403).json({ error: "invalid_totp" });
  // ── ceremony released past here ─────────────────────────────────────────────

  let handle, excludeCredentials = [];
  try {
    const hr = await callRelay("/v2/user/webauthn/handle", { user_id });
    handle = (await hr.json()).handle;
    const cr = await callRelay(`/v2/user/webauthn/credentials?user_id=${encodeURIComponent(user_id)}`, null, "GET");
    if (cr.status === 200) excludeCredentials = ((await cr.json()).credentials || []).map(c => ({ id: c.credId, transports: c.transports }));
  } catch (e) { console.error("[account/webauthn/register/options]", e.message); return res.status(502).json({ error: "relay_unreachable" }); }
  if (!handle) return res.status(500).json({ error: "internal" });

  let options;
  try {
    options = await generateRegistrationOptions({
      rpName: webauthn.RP_NAME,
      rpID: webauthn.RP_ID,
      userName: email,
      userID: new Uint8Array(Buffer.from(handle, "base64url")),
      userDisplayName: email,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      extensions: { prf: {} },
    });
  } catch (e) { console.error("[account/webauthn/register/options]", e.message); return res.status(500).json({ error: "internal" }); }

  const flowId = webauthn.newFlowId();
  await webauthn.putRegFlow(redis(), flowId, { challenge: options.challenge, user_id, email, via: "account-stepup" });
  res.json({ flowId, options });
});

// POST /api/user/account/webauthn/register/verify  (authUser)
api.post("/user/account/webauthn/register/verify", authUser, async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.registerVerify;
  if (!(await webauthn.rateHit(redis(), `arv:ip:${ip}`, L.ip, L.windowSec))) return res.status(429).json({ error: "rate_limited" });

  const { flowId, response } = req.body || {};
  const flow = await webauthn.takeRegFlow(redis(), flowId);            // one-shot
  if (!flow || !response) return res.status(401).json({ error: "invalid_registration" });
  // ── authUser-binding: the ceremony MUST belong to the same session that did
  //    the TOTP step-up (flow.via marks the account path, flow.user_id is the
  //    step-up's account). Identity is the session's user_id, never a client field.
  if (flow.via !== "account-stepup" || flow.user_id !== req.userSession.user_id)
    return res.status(403).json({ error: "session_mismatch" });

  const stored = await webauthnVerifyAndStore(flow, response, req.body && req.body.label);
  if (!stored.ok) return res.status(stored.status).json({ error: stored.error });

  // No new session (already logged in). No backup-code regeneration (would wipe
  // the account's existing recovery). Additive factor -> lockout-safe.
  try { logAuditEvent("webauthn_account_passkey_added", { user_id: String(req.userSession.user_id).slice(0, 12) + "…" }); } catch {}
  res.json({ success: true });
});

// GET /api/user/account/webauthn/credentials  (authUser) — dashboard listing.
api.get("/user/account/webauthn/credentials", authUser, async (req, res) => {
  try {
    const cr = await callRelay(`/v2/user/webauthn/credentials?user_id=${encodeURIComponent(req.userSession.user_id)}`, null, "GET");
    const body = await cr.json().catch(() => ({}));
    const passkeys = (body.credentials || []).map(c => ({
      credId: c.credId, label: c.label, created_at: c.created_at, last_used_at: c.last_used_at, prfSupported: c.prfSupported,
    }));
    res.json({ passkeys, total: passkeys.length });
  } catch (e) { return res.status(502).json({ error: "relay_unreachable" }); }
});


// POST /api/user/envelopes (authUser) — create a signing envelope SAME-ORIGIN
// (replaces the old direct browser -> health.paramant.app POST, audit #2).
// recipe_version 3 (domain-prefixed). Party 0 is the signer themselves (their
// session email), so a self-sign (no recipients) still gets an envelope and
// goes through the per-document activation gate (R018: every signature is a
// passkey-PRF activation; no separate weaker self-sign route). The relay is
// reached with the session's own pgp_ key as X-Api-Key.
api.post("/user/envelopes", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  if (!(await webauthn.rateHit(redis(), `env:ip:${ip}`, 30, 900))) return res.status(429).json({ error: "rate_limited" });
  const docHash = (req.body?.doc_hash || "").toString().trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(docHash)) return res.status(400).json({ error: "invalid_doc_hash" });
  const recipients = Array.isArray(req.body?.recipients) ? req.body.recipients : [];
  const originalFilename = (req.body?.original_filename || "").toString().slice(0, 200);
  const creatorPublicKey = (req.body?.creator_public_key || "").toString();
  // Party 0 = the signer (self), bound to their verified session email.
  const parties = [{ label: ((req.body?.signer_label || "") + " (you)").trim(), email }];
  for (const r of recipients) {
    if (r && r.email) parties.push({ label: (r.label || "").toString().slice(0, 80), email: r.email.toString() });
  }
  try {
    const rr = await fetch(`${SECTORS.health}/v2/envelopes`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Api-Key": proxyApiKey(req.userSession) },
      body: JSON.stringify({ doc_hash: docHash, parties, original_filename: originalFilename, binding_mode: "email", recipe_version: 3, creator_public_key: creatorPublicKey }),
    });
    const body = await rr.json().catch(() => ({}));
    if (rr.status !== 200) return res.status(rr.status).json({ error: body.error || "envelope_create_failed" });
    return res.json(body);   // { ok, envelope: { id, party_links:[{party_index, sign_path, invite_token}], ... } }
  } catch (e) {
    console.error("[user/envelopes POST]", e.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// ── Per-document signing activation (R018: per-document PRF activation) ───────
// A signature requires a fresh, server-issued, ONE-SHOT activation bound to
// EXACTLY (account, envelope, party, doc-hash). Issuance authorizes BEFORE the
// client unlocks its key (no token -> no unlock). Consumption at submit is
// ATOMIC via GETDEL, so two concurrent submits with the same token cannot both
// pass (no TOCTOU). The relay never holds this token; the admin proxy verifies
// + consumes it and forwards to the relay sign with PR-0's verified_email_hash.
const SIGN_ACTIVATION_TTL = 300;   // 5 min: room for the human PRF gesture (Face ID, hesitation)

// Canonical party-email hash — byte-identical to relay/envelope.js partyEmailHash.
function partyEmailHashAdmin(email) {
  const norm = (email || "").toString().trim().toLowerCase();
  if (!norm) return "";
  return crypto.createHash("sha3-256").update("paramant/party-email/v1\x00", "utf8").update(norm, "utf8").digest("hex");
}

// POST /api/user/sign/activation (authUser) — AUTHORIZE + ISSUE (pre-unlock gate).
api.post("/user/sign/activation", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;          // identity from the session, never the client
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  if (!(await webauthn.rateHit(redis(), `act:ip:${ip}`, 20, 900))) return res.status(429).json({ error: "rate_limited" });
  if (!(await webauthn.rateHit(redis(), `act:acct:${webauthn.scopeHash(user_id)}`, 30, 900))) return res.status(429).json({ error: "rate_limited" });

  const envelope_id = (req.body?.envelope_id || "").toString();
  const party_index = parseInt(req.body?.party_index, 10);
  const doc_hash = (req.body?.doc_hash || "").toString().trim().toLowerCase();
  const invite_token = (req.body?.invite_token || "").toString();
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(envelope_id)) return res.status(400).json({ error: "invalid_envelope_id" });
  if (!Number.isInteger(party_index) || party_index < 0) return res.status(400).json({ error: "invalid_party_index" });
  if (!/^[0-9a-f]{64}$/.test(doc_hash)) return res.status(400).json({ error: "invalid_doc_hash" });

  // ── AUTHORIZE before issuing (no token -> the client cannot proceed to unlock).
  // The party view is token-gated (PR-0). Bind to: the invite capability (token),
  // the signer's verified session email == the party's bound email, and the
  // exact document hash == the envelope's doc_hash.
  let env;
  try {
    const r = await callRelay(`/v2/envelopes/${encodeURIComponent(envelope_id)}?p=${party_index}&t=${encodeURIComponent(invite_token)}`, null, "GET");
    if (r.status !== 200) return res.status(403).json({ error: "not_authorized" });
    env = (await r.json()).envelope;
  } catch (e) { return res.status(502).json({ error: "relay_unreachable" }); }
  const sessionEmailHash = partyEmailHashAdmin(email);
  if (!env || env.doc_hash !== doc_hash) return res.status(403).json({ error: "doc_hash_mismatch" });
  if (!env.party || !sessionEmailHash || env.party.email_hash !== sessionEmailHash) return res.status(403).json({ error: "not_authorized" });
  // Signing-invite window (7d from creation, != 30d record retention): fail here,
  // before the client runs the passkey-PRF, when the invite is no longer signable.
  if (env.sign_expires_at && Date.parse(env.sign_expires_at) < Date.now()) return res.status(410).json({ error: "invite_expired" });

  // ── ISSUE: one-shot record, server-side binding only, EX 300s.
  const activation_id = crypto.randomBytes(32).toString("base64url");
  await redis().set(`paramant:sign:activation:${activation_id}`,
    JSON.stringify({ account_id: user_id, envelope_id, party_index, doc_hash, email_hash: sessionEmailHash, issued_at: Date.now() }),
    { EX: SIGN_ACTIVATION_TTL });
  res.json({ activation_id, email_hash: sessionEmailHash, recipe_version: env.recipe_version || 3, sign_domain: "paramant/parasign/doc/v1" });
});

// POST /api/user/sign/submit (authUser) — ATOMIC CONSUME + forward to relay sign.
api.post("/user/sign/submit", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const { activation_id, signer_public_key, signature } = req.body || {};
  if (!activation_id || typeof activation_id !== "string") return res.status(400).json({ error: "activation_id_required" });
  if (!signer_public_key || !signature) return res.status(400).json({ error: "signature_required" });

  // ── ATOMIC one-shot consume. GETDEL returns the record AND deletes it in one
  // round-trip: of two concurrent submits with the same activation_id, exactly
  // one receives the record; the other gets null and is rejected. No TOCTOU.
  let raw;
  try { raw = await redis().getDel(`paramant:sign:activation:${activation_id}`); }
  catch (e) { return res.status(502).json({ error: "store_unavailable" }); }
  if (!raw) return res.status(409).json({ error: "activation_invalid_or_used" });
  let act; try { act = JSON.parse(raw); } catch { return res.status(409).json({ error: "activation_invalid_or_used" }); }

  // The submit must come from the same account the activation was issued to.
  if (act.account_id !== user_id) return res.status(403).json({ error: "account_mismatch" });

  // Forward to the relay sign with PR-0's internal-auth email binding. The relay
  // recomputes the v3 domain-prefixed message from its OWN stored envelope fields
  // (doc_hash, party_index, email_hash) and verifies the ML-DSA-65 signature —
  // doc/party/email are bound both by the consumed activation and by the message.
  try {
    const r = await callRelay(`/v2/envelopes/${encodeURIComponent(act.envelope_id)}/sign`, {
      party_index: act.party_index, signer_public_key, signature, verified_email_hash: act.email_hash,
    }, "POST");
    const body = await r.json().catch(() => ({}));
    if (r.status !== 200) return res.status(r.status).json({ error: body.error || "sign_failed" });
    try { logAuditEvent("parasign_doc_signed", { account: String(user_id).slice(0, 12) + "…", envelope: String(act.envelope_id).slice(0, 10) + "…", party: act.party_index }); } catch {}
    return res.json({ ok: true, signed_count: body.signed_count, party_count: body.party_count, status: body.status });
  } catch (e) { return res.status(502).json({ error: "relay_unreachable" }); }
});


// POST /api/user/auth/request-totp-reset (public — two-stage: sends confirmation first)
api.post("/user/auth/request-totp-reset", async (req, res) => {
  const { email, challenge_id, nonce } = req.body || {};
  if (!email || typeof email !== "string") return res.status(400).json({ error: "invalid_request" });
  const norm = email.toLowerCase().trim();

  // PoW verification — prevents automated reset flooding
  const proof = await pow.verifyChallenge(challenge_id, nonce);
  if (!proof.valid) return res.status(403).json({ error: 'captcha_failed', reason: proof.reason });

  // Rate limit: max 5/24h per email (hashed for privacy), 10/hr per IP
  const emailHash = crypto.createHash("sha256").update(norm).digest("hex").slice(0, 16);
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const emailRlKey = `paramant:ratelimit:totp_reset:${emailHash}`;
  const ipRlKey    = `paramant:ratelimit:totp_reset_ip:${ip}`;
  const [emailCnt, ipCnt] = await Promise.all([redis().incr(emailRlKey), redis().incr(ipRlKey)]);
  await Promise.all([
    emailCnt === 1 ? redis().expire(emailRlKey, 86400) : Promise.resolve(),
    ipCnt    === 1 ? redis().expire(ipRlKey,    3600)  : Promise.resolve(),
  ]);
  if (emailCnt > 5 || ipCnt > 10) {
    console.warn(`[totp-reset-req] rate limited: emailHash=${emailHash} ip=${ip}`);
    return res.status(429).json({ error: "too_many_requests", retry_after: 86400 });
  }

  const alwaysOk = { success: true, message: "If an account exists for this email, a confirmation email has been sent." };

  const user = await findUserByEmail(norm).catch(() => null);
  if (!user) return res.json(alwaysOk); // no enumeration

  // Generate short-lived confirmation token — does NOT touch TOTP state yet
  const confirmToken = crypto.randomBytes(32).toString("hex");
  const requestedAt  = Date.now();
  const maskedIp = ip.includes(".") ? ip.split(".").slice(0,2).join(".") + ".x.x" : ip.split(":").slice(0,2).join(":") + "::x";
  await redis().set(
    `paramant:user:reset_confirm:${confirmToken}`,
    JSON.stringify({ user_id: user.key, email: norm, requested_at: requestedAt, masked_ip: maskedIp }),
    { EX: 3600 } // 60 minutes
  );

  try { await logAuditEvent(user.key, "totp_reset_requested", { ip, ua: (req.get("user-agent") || "").slice(0, 200) }); } catch {}

  try {
    await sendResetConfirmEmail(norm, confirmToken, maskedIp, new Date(requestedAt).toISOString());
    console.log(`[totp-reset-req] confirmation email sent to ${norm}`);
  } catch (err) {
    console.error("[totp-reset-req] email failed:", err.message);
  }

  res.json(alwaysOk);
});

// POST /api/user/auth/reset-confirm — second stage: user clicked confirmation link
api.post("/user/auth/reset-confirm", async (req, res) => {
  const { token } = req.body || {};
  if (!token || typeof token !== "string") return res.status(400).json({ error: "invalid_request" });

  const raw = await redis().get(`paramant:user:reset_confirm:${token}`);
  if (!raw) return res.status(401).json({ error: "invalid_or_expired_token" });

  const data = JSON.parse(raw);
  const { user_id, email, requested_at } = data;

  // Consume confirmation token — one-time use
  await redis().del(`paramant:user:reset_confirm:${token}`);

  // NOW clear TOTP state
  await Promise.all([
    redis().del(`paramant:user:totp:${user_id}`),
    redis().del(`paramant:user:totp_active:${user_id}`),
    redis().del(`paramant:user:backup_codes:${user_id}`),
    redis().del(`paramant:user:backup_codes_plaintext:${user_id}`),
  ]);
  for await (const k of redis().scanIterator({ MATCH: "paramant:user:setup_token:*", COUNT: 100 })) {
    const r = await redis().get(k);
    if (r) { try { const d = JSON.parse(r); if (d.user_id === user_id) await redis().del(k); } catch {} }
  }

  const setupToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:setup_token:${setupToken}`,
    JSON.stringify({ user_id, email }),
    { EX: 14 * 86400 }
  );

  try { await logAuditEvent(user_id, "totp_reset_confirmed", { age_sec: Math.floor((Date.now() - requested_at) / 1000), ip: req.headers["x-real-ip"] || "unknown" }); } catch {}

  try {
    await sendSetupEmail(email, setupToken, true);
  } catch (err) {
    console.error("[reset-confirm] setup email failed:", err.message);
    return res.status(500).json({ error: "email_failed" });
  }

  console.log(`[reset-confirm] TOTP reset completed for ${email}`);
  res.json({ success: true, message: "Setup email sent. Check your inbox." });
});

// POST /api/user/logout
api.post("/user/logout", async (req, res) => {
  const token = parseCookies(req).paramant_user_session;
  if (token) await redis().del(`paramant:user:session:${token}`);
  clearUserCookie(res);
  res.json({ success: true });
});

// GET /api/user/session/verify
api.get("/user/session/verify", async (req, res) => {
  const token = parseCookies(req).paramant_user_session;
  if (!token) return res.json({ authenticated: false });
  const raw = await redis().get(`paramant:user:session:${token}`);
  if (!raw) return res.json({ authenticated: false });
  await redis().expire(`paramant:user:session:${token}`, 3600);
  const s = JSON.parse(raw);
  res.json({
    authenticated: true,
    email: s.email,
    expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
  });
});

// ── Account management ────────────────────────────────────────────────────────

// GET /api/user/me
// JSON identity + account-summary endpoint backing the client-side /dashboard.
// Same authUser cookie middleware as /api/user/account. Returns just what the
// dashboard needs (no sessions scan -- that belongs to /account). 401 when the
// paramant_user_session cookie is absent or expired.
api.get("/user/me", authUser, async (req, res) => {
  try {
    const { user_id, email } = req.userSession;
    const user = await findUserByEmail(email);
    const backupCount = await redis()
      .sCard(`paramant:user:backup_codes:${user_id}`)
      .catch(() => 0);
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.json({
      email,
      label: user?.label || null,
      plan: (user && user.plan) || "standard",
      created_at: user?.created_at || null,
      api_key_masked: user_id.slice(0, 8) + "..." + user_id.slice(-4),
      backup_codes_remaining: backupCount,
      session_expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    });
  } catch (err) {
    console.error("[user/me]", err.message);
    res.status(503).json({ error: "user_data_unavailable" });
  }
});

// Legacy server-rendered dashboard fragment has been removed in favour of
// /api/user/me + client-side rendering in frontend/dashboard.html. Kept as a
// 410 stub so any cached old loader gets a clear "go re-fetch the page" answer
// instead of a silent failure.
api.get("/user/dashboard-fragment", (req, res) => {
  res.status(410).json({ error: "gone", hint: "use /api/user/me" });
});

// GET /api/user/check
// Lightweight session-validity probe for nginx auth_request on gated tool
// routes (/parashare, /drop, /sign). authUser handles the cookie check
// and returns 401 on miss; this handler only fires on hit.
api.get("/user/check", authUser, (req, res) => {
  res.status(200).end();
});

// GET /api/user/developer/check
// nginx auth_request probe for the /developer page (mirrors /user/check, with
// the allowlist layer). authUser returns 401 on no session -> nginx redirects
// to login. A valid session that is NOT on the developer allowlist gets 403,
// which nginx remaps to 404 so the page's existence stays hidden. Allowlisted
// session -> 200 and nginx serves /developer.html.
api.get("/user/developer/check", authUser, (req, res) => {
  if (!isDeveloper(req.userSession.email)) return res.status(403).end();
  res.status(200).end();
});

// GET /api/user/developer/tools
// Developer-only data endpoint behind authUser + developerGate (404 for
// non-allowlisted). Provisional: the page renders the tool list statically;
// this endpoint exists so the gated /api/user/developer/* surface is wired and
// testable from day one.
api.get("/user/developer/tools", authUser, developerGate, (req, res) => {
  res.json({ status: "live", tools: DEVELOPER_TOOLS });
});

// ── Per-account saved tool config (cross-device). All three are gated by
// authUser + developerGate and scoped to the session's user_id (no IDOR). Pure
// validation lives in lib/developer-config (unit-tested). The config is data
// only -- never executed; a literal key is refused (defence in depth).
api.get("/user/developer/tool-config", authUser, developerGate, async (req, res) => {
  try {
    const raw = await redis().get(developerConfig.KEY(req.userSession.user_id));
    let configs = {};
    if (raw) { try { configs = JSON.parse(raw) || {}; } catch {} }
    res.json({ configs });
  } catch (e) { res.status(503).json({ error: "store_unavailable" }); }
});
api.post("/user/developer/tool-config", authUser, developerGate, async (req, res) => {
  const { tool, command } = req.body || {};
  const v = developerConfig.validateConfig(tool, command);
  if (!v.ok) return res.status(400).json({ error: v.error });
  try {
    const raw = await redis().get(developerConfig.KEY(req.userSession.user_id));
    const m = developerConfig.mergeConfig(raw, v.tool, v.command);
    if (!m.ok) return res.status(400).json({ error: m.error });
    await redis().set(developerConfig.KEY(req.userSession.user_id), m.json);
    res.json({ ok: true });
  } catch (e) { res.status(503).json({ error: "store_unavailable" }); }
});
api.delete("/user/developer/tool-config", authUser, developerGate, async (req, res) => {
  const tool = (req.body && req.body.tool) || req.query.tool;
  if (typeof tool !== "string" || !developerConfig.TOOL_NAMES.has(tool)) return res.status(400).json({ error: "unknown_tool" });
  try {
    const raw = await redis().get(developerConfig.KEY(req.userSession.user_id));
    await redis().set(developerConfig.KEY(req.userSession.user_id), developerConfig.removeConfig(raw, tool));
    res.json({ ok: true });
  } catch (e) { res.status(503).json({ error: "store_unavailable" }); }
});

// GET /api/user/developer/snapshot — one call for the initial dashboard render:
// {email, plan, key_masked, quota:{transfers,signs,caps}, audit:[last 50],
//  tools_status:{per tool}}. 3s in-memory cache per account so a refresh storm
// cannot hammer Redis.
const _snapCache = new Map(); // uid -> { at, data }
api.get("/user/developer/snapshot", authUser, developerGate, async (req, res) => {
  const uid = req.userSession.user_id;
  const hit = _snapCache.get(uid);
  if (hit && Date.now() - hit.at < 3000) return res.json(hit.data);
  let plan = "community";
  try { const u = await findUserByEmail(req.userSession.email); if (u && u.plan) plan = u.plan; } catch {}
  try {
    const data = await buildSnapshot({ redis, getAuditEvents, plan }, req.userSession);
    _snapCache.set(uid, { at: Date.now(), data });
    if (_snapCache.size > 500) _snapCache.clear();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: "snapshot_failed" });
  }
});

// GET /api/user/developer/stream — Server-Sent Events. Pushes new audit events
// for this account as they land. SSE (not WebSocket): simpler, rides the
// existing HTTP/auth/cookie stack, no upgrade handshake. Server-side 2s poll of
// the account's audit zset; pushes deltas + a heartbeat. Closes on disconnect.
api.get("/user/developer/stream", authUser, developerGate, async (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write("retry: 4000\n");
  res.write('event: hello\ndata: {"ok":true}\n\n');
  const uid = req.userSession.user_id;
  let lastTs = Date.now();
  let alive = true;
  const tick = async () => {
    if (!alive) return;
    try {
      const events = await getAuditEvents(uid, { limit: 20 });
      const fresh = events.filter((e) => (e.ts || 0) > lastTs).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      for (const ev of fresh) { lastTs = Math.max(lastTs, ev.ts || 0); res.write(`event: audit\ndata: ${JSON.stringify(ev)}\n\n`); }
      res.write(`event: ping\ndata: ${Date.now()}\n\n`);
    } catch {}
  };
  const iv = setInterval(tick, 2000);
  req.on("close", () => { alive = false; clearInterval(iv); try { res.end(); } catch {} });
});

// GET /api/user/account
api.get("/user/account", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;
  const user = await findUserByEmail(email);
  const backupCount = await redis().sCard(`paramant:user:backup_codes:${user_id}`).catch(() => 0);

  const sessions = [];
  for await (const key of redis().scanIterator({ MATCH: "paramant:user:session:*", COUNT: 100 })) {
    const raw = await redis().get(key);
    if (!raw) continue;
    const s = JSON.parse(raw);
    if (s.user_id !== user_id) continue;
    const token = key.replace("paramant:user:session:", "");
    sessions.push({
      ip_masked: maskIp(s.ip || ""),
      user_agent_short: (s.ua || "").split(" ")[0].slice(0, 40) || "—",
      last_seen: new Date(s.created_at).toISOString(),
      current: token === req.userSessionToken,
      via: s.via || "totp",
    });
  }

  res.json({
    email,
    label: user?.label || null,
    plan: user?.plan || null,
    created_at: user?.created_at || null,
    api_key_masked: user_id.slice(0, 8) + "..." + user_id.slice(-4),
    backup_codes_remaining: backupCount,
    session_expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    sessions,
  });
});

function maskIp(ip) {
  if (!ip) return "—";
  if (ip.includes(".")) {
    const p = ip.split(".");
    return `${p[0]}.${p[1]}.${p[2]}.0`;
  }
  return ip.split(":").slice(0, 2).join(":") + "::0";
}

// GET /api/user/account/key
api.get("/user/account/key", authUser, async (req, res) => {
  // stap 3: reveal the account's PRIMARY api-key (== user_id today), and only
  // when the account is legacy_revealable. The `revealable` field is additive;
  // existing callers read `.api_key`, unchanged while every account is 1:1.
  res.json(revealKey(req.userSession));
});

// GET /api/user/dashboard/overview — read-only Operations data for the normal
// (non-developer) dashboard: plan, masked key, this-month quota, recent audit.
// authUser only (NO developer gate). Reuses buildSnapshot minus the tools
// catalogue. 3s per-account cache so the dashboard's 5s poll can't hammer Redis.
const _ovCache = new Map(); // uid -> { at, data }
api.get("/user/dashboard/overview", authUser, async (req, res) => {
  const uid = req.userSession.user_id;
  const hit = _ovCache.get(uid);
  if (hit && Date.now() - hit.at < 3000) return res.json(hit.data);
  let plan = "community";
  try { const u = await findUserByEmail(req.userSession.email); if (u && u.plan) plan = u.plan; } catch {}
  try {
    const snap = await buildSnapshot({ redis, getAuditEvents, plan }, req.userSession);
    const data = { plan: snap.plan, key_masked: snap.key_masked, quota: snap.quota, audit: snap.audit };
    _ovCache.set(uid, { at: Date.now(), data });
    if (_ovCache.size > 500) _ovCache.clear();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: "overview_failed" });
  }
});

// ── Account-bound signing identity (proxies to relay /v2/user/signing-key) ──
// The browser talks to admin (session-cookie); admin forwards to relay with
// the internal-auth token. user_id is taken from the session, never from the
// request body — so a logged-in attacker cannot enroll a pubkey for someone else.

// POST /api/user/account/signing-key — enroll a new pubkey (body: { pk_b64, label, totp })
api.post("/user/account/signing-key", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const { pk_b64, label, totp } = req.body || {};
  if (!pk_b64 || typeof pk_b64 !== "string") return res.status(400).json({ error: "missing_pk_b64" });
  if (!totp || !/^\d{6}$/.test(String(totp))) return res.status(400).json({ error: "totp_required" });
  try {
    const relayRes = await callRelay("/v2/user/signing-key", { user_id, pk_b64, label, totp }, "POST");
    const body = await relayRes.json().catch(() => ({ error: "bad_relay_response" }));
    return res.status(relayRes.status).json(body);
  } catch (err) {
    console.error("[user/signing-key POST]", err.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// POST /api/user/account/signing-key/tofu — TOFU enrol for a first-time invitee
// (no TOTP), gated by an email-bound invite token instead. We forward the
// SESSION's user_id (never a client-supplied id) + the invite context; the
// relay self-verifies the token, that the party email == this account's email,
// the one-shot, and the cross-account conflict. No invite context here means the
// relay rejects — there is no TOTP-free enrol path without a valid invite.
api.post("/user/account/signing-key/tofu", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const { pk_b64, label, envelope_id, party_index, invite_token } = req.body || {};
  if (!pk_b64 || typeof pk_b64 !== "string") return res.status(400).json({ error: "missing_pk_b64" });
  if (!envelope_id || !invite_token) return res.status(400).json({ error: "missing_invite_context" });
  try {
    const relayRes = await callRelay("/v2/user/signing-key/tofu", { user_id, pk_b64, label, envelope_id, party_index, invite_token }, "POST");
    const body = await relayRes.json().catch(() => ({ error: "bad_relay_response" }));
    return res.status(relayRes.status).json(body);
  } catch (err) {
    console.error("[user/signing-key/tofu POST]", err.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// ── Passkey step-up for binding a signing key (ADR R018) — the "your sign-in
// passkey IS your signing key" gate. A logged-in user proves possession of one
// of THEIR OWN passkeys with a fresh assertion; that step-up replaces TOTP for
// the signing-key bind, so a passkey-only account (no authenticator app) can
// enrol a signing key, and nobody needs a separate signing passphrase. rpId/
// origin are config constants (never request-derived). The SAME WebAuthn get()
// the client runs for this assertion also carries the PRF eval that wraps the
// ML-DSA key locally — one Face ID / Touch ID tap both authorises and unlocks.

// POST /api/user/account/signing-key/step-up/options (authUser) — issue a
// one-shot assertion challenge over THIS account's own passkeys.
api.post("/user/account/signing-key/step-up/options", authUser, async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.loginOptions;
  if (!(await webauthn.rateHit(redis(), `su:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });
  const { user_id } = req.userSession;
  if (!(await webauthn.rateHit(redis(), `su:acct:${webauthn.scopeHash(user_id)}`, L.account, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  // Challenge is bound to THIS account's own passkeys only. No passkey -> tell
  // the client to add one first (the attested relay bind would reject anyway).
  let allowCredentials = [];
  try {
    const r = await callRelay(`/v2/user/webauthn/credentials?user_id=${encodeURIComponent(user_id)}`, null, "GET");
    if (r.status === 200) allowCredentials = ((await r.json()).credentials || []).map(c => ({ id: c.credId, transports: c.transports }));
  } catch (e) { console.error("[signing-key/step-up/options]", e.message); return res.status(502).json({ error: "relay_unreachable" }); }
  if (allowCredentials.length === 0) return res.status(409).json({ error: "no_passkey" });

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID: webauthn.RP_ID,
      allowCredentials,
      userVerification: "required",
    });
  } catch (e) { console.error("[signing-key/step-up/options]", e.message); return res.status(500).json({ error: "internal" }); }
  const flowId = webauthn.newFlowId();
  await webauthn.putAuthFlow(redis(), flowId, { challenge: options.challenge, user_id, step_up: "signing-key" });
  res.json({ flowId, options });
});

// POST /api/user/account/signing-key/step-up/bind (authUser) — verify the fresh
// assertion (mirrors login/verify) and, on success, forward the pubkey bind to
// the relay's TOTP-free attested route. The asserted credential MUST belong to
// the logged-in account; the flow is one-shot (consumed before any crypto).
api.post("/user/account/signing-key/step-up/bind", authUser, async (req, res) => {
  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const L = webauthn.LIMITS.loginVerify;
  if (!(await webauthn.rateHit(redis(), `sub:ip:${ip}`, L.ip, L.windowSec)))
    return res.status(429).json({ error: "rate_limited" });

  const { user_id } = req.userSession;
  const { flowId, response, pk_b64, label } = req.body || {};
  if (!pk_b64 || typeof pk_b64 !== "string") return res.status(400).json({ error: "missing_pk_b64" });
  const flow = await webauthn.takeAuthFlow(redis(), flowId);   // one-shot
  if (!flow || !response || flow.step_up !== "signing-key") return res.status(401).json({ error: "step_up_required" });
  // The step-up MUST belong to the same session that is binding the key.
  if (flow.user_id !== user_id) return res.status(401).json({ error: "step_up_required" });

  // Resolve the asserted credential and confirm it is THIS account's passkey.
  let lookup;
  try {
    const r = await callRelay(`/v2/user/webauthn/lookup?cred_id=${encodeURIComponent(String(response.id || ""))}`, null, "GET");
    if (r.status !== 200) return res.status(401).json({ error: "step_up_required" });
    lookup = await r.json();
  } catch (e) { return res.status(401).json({ error: "step_up_required" }); }
  if (!lookup || !lookup.user_id || lookup.user_id !== user_id) return res.status(401).json({ error: "step_up_required" });

  // Verify the assertion. expectedOrigin/expectedRPID are config constants.
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: flow.challenge,
      expectedOrigin: webauthn.EXPECTED_ORIGIN,
      expectedRPID: webauthn.RP_ID,
      credential: {
        id: lookup.credId,
        publicKey: new Uint8Array(Buffer.from(lookup.publicKey, "base64url")),
        counter: lookup.counter | 0,
      },
      requireUserVerification: true,
    });
  } catch (e) { return res.status(401).json({ error: "step_up_required" }); }
  if (!verification.verified) return res.status(401).json({ error: "step_up_required" });

  // Cloned-authenticator guard (the same rule as login/verify).
  const newCounter = verification.authenticationInfo.newCounter;
  if (!webauthn.counterIsAcceptable(lookup.counter, newCounter)) {
    try { logAuditEvent("webauthn_counter_regression", { user_id: String(user_id).slice(0, 12) + "…", stored: lookup.counter | 0, presented: newCounter | 0 }); } catch {}
    return res.status(401).json({ error: "step_up_required" });
  }
  try { await callRelay("/v2/user/webauthn/counter", { user_id, cred_id: lookup.credId, counter: newCounter }); } catch {}

  // Step-up proven -> forward the bind to the relay's TOTP-free attested route.
  try {
    const relayRes = await callRelay("/v2/user/signing-key/attested", { user_id, pk_b64, label }, "POST");
    const body = await relayRes.json().catch(() => ({ error: "bad_relay_response" }));
    return res.status(relayRes.status).json(body);
  } catch (err) {
    console.error("[signing-key/step-up/bind]", err.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// GET /api/user/account/signing-key — list this user's enrolled keys
api.get("/user/account/signing-key", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  try {
    const relayRes = await callRelay(`/v2/user/signing-key?user_id=${encodeURIComponent(user_id)}`, null, "GET");
    const body = await relayRes.json().catch(() => ({ error: "bad_relay_response" }));
    return res.status(relayRes.status).json(body);
  } catch (err) {
    console.error("[user/signing-key GET]", err.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// DELETE /api/user/account/signing-key — revoke a pubkey (body: { pk_hash_sha3, totp })
api.delete("/user/account/signing-key", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const { pk_hash_sha3, totp } = req.body || {};
  if (!pk_hash_sha3 || !/^[0-9a-f]{64}$/.test(pk_hash_sha3)) return res.status(400).json({ error: "invalid_pk_hash" });
  if (!totp || !/^\d{6}$/.test(String(totp))) return res.status(400).json({ error: "totp_required" });
  try {
    const relayRes = await callRelay("/v2/user/signing-key", { user_id, pk_hash_sha3, totp }, "DELETE");
    const body = await relayRes.json().catch(() => ({ error: "bad_relay_response" }));
    return res.status(relayRes.status).json(body);
  } catch (err) {
    console.error("[user/signing-key DELETE]", err.message);
    return res.status(502).json({ error: "relay_unreachable" });
  }
});

// POST /api/user/account/backup-codes/regenerate
api.post("/user/account/backup-codes/regenerate", authUser, async (req, res) => {
  const relayRes = await callRelay("/v2/user/regenerate-backup", { user_id: req.userSession.user_id });
  if (!relayRes.ok) return res.status(500).json({ error: "regenerate_failed" });
  res.json(await relayRes.json());
});

// POST /api/user/account/totp/reset
api.post("/user/account/totp/reset", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;

  await callRelay("/v2/user/delete-totp", { user_id });

  const setupToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:setup_token:${setupToken}`,
    JSON.stringify({ user_id, email }),
    { EX: 14 * 86400 }
  );

  try {
    await sendSetupEmail(email, setupToken);
  } catch (err) {
    console.error("[totp/reset] email failed:", err.message);
    return res.status(500).json({ error: "email_failed" });
  }

  // Invalidate all sessions for this user
  for await (const key of redis().scanIterator({ MATCH: "paramant:user:session:*", COUNT: 100 })) {
    const raw = await redis().get(key);
    if (raw) { const s = JSON.parse(raw); if (s.user_id === user_id) await redis().del(key); }
  }

  clearUserCookie(res);
  res.json({ success: true });
});

// POST /api/user/account/sessions/revoke-others
api.post("/user/account/sessions/revoke-others", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  let revoked = 0;
  for await (const key of redis().scanIterator({ MATCH: "paramant:user:session:*", COUNT: 100 })) {
    const raw = await redis().get(key);
    if (!raw) continue;
    const s = JSON.parse(raw);
    const token = key.replace("paramant:user:session:", "");
    if (s.user_id === user_id && token !== req.userSessionToken) {
      await redis().del(key);
      revoked++;
    }
  }
  res.json({ success: true, revoked });
});

// DELETE /api/user/account
api.delete("/user/account", authUser, async (req, res) => {
  const { user_id } = req.userSession;

  // Revoke key across all sectors
  await eachSector(Object.keys(SECTORS), async s => {
    await relayFetch(s, "/v2/admin/keys/revoke", "POST", { key: user_id }, false, ADMIN_TOKEN);
  });

  await callRelay("/v2/user/delete-totp", { user_id });

  for await (const key of redis().scanIterator({ MATCH: "paramant:user:session:*", COUNT: 100 })) {
    const raw = await redis().get(key);
    if (raw) { const s = JSON.parse(raw); if (s.user_id === user_id) await redis().del(key); }
  }

  clearUserCookie(res);
  res.json({ success: true });
});

// ── Session → API key proxy ───────────────────────────────────────────────────
api.all("/relay/:sector/*path", authUser, async (req, res) => {
  const sector = req.params.sector;
  const relayBase = SECTORS[sector];
  if (!relayBase) return res.status(404).json({ error: "unknown_sector" });

  const relayPath = "/" + (req.params.path || "");
  const fetchOpts = {
    method: req.method,
    headers: {
      "X-Api-Key": proxyApiKey(req.userSession),
      "Content-Type": "application/json",
    },
  };

  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    fetchOpts.body = JSON.stringify(req.body);
  }

  try {
    const proxyRes = await fetch(`${relayBase}${relayPath}`, fetchOpts);
    const ct = proxyRes.headers.get("content-type") || "";
    res.status(proxyRes.status).set("content-type", ct);
    res.send(ct.includes("application/json") ? await proxyRes.json() : await proxyRes.text());
  } catch (err) {
    console.error("[proxy]", err.message);
    res.status(502).json({ error: "relay_unreachable" });
  }
});

// ── Anonymous drop rate limiting ──────────────────────────────────────────────
api.post("/drop/upload", async (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "invalid_email" });
  }
  const rlKey = `paramant:drop:ratelimit:${email.toLowerCase()}`;
  const count = await redis().incr(rlKey);
  if (count === 1) await redis().expire(rlKey, 86400);
  if (count > 3) {
    return res.status(429).json({
      error: "rate_limited",
      message: "Daily limit reached. Create a free account for unlimited drops.",
    });
  }
  const anonRes = await relayFetch("health", "/v2/anon-inbound", "POST", req.body, false, "");
  res.status(anonRes.status).json(anonRes.body);
});


// ── Billing ───────────────────────────────────────────────────────────────────

const PLANS = [
  {
    id: 'community',
    name: 'Community',
    price_monthly_eur: 0,
    price_yearly_eur: 0,
    limits: { file_size_mb: 5, link_ttl_hours: 1, reads_per_link: 1, registered_devices: 5 },
  },
  {
    id: 'pro',
    name: 'Pro',
    price_monthly_eur: 9,
    price_yearly_eur: 89,
    limits: { file_size_mb: 5, link_ttl_hours: 24, reads_per_link: 10, registered_devices: 50 },
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price_monthly_eur: null,
    price_yearly_eur: null,
    limits: { file_size_mb: null, link_ttl_hours: 168, reads_per_link: 100, registered_devices: null },
  },
];

async function sendBillingConfirmation(email, plan, amount, period) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) { console.warn('[billing] RESEND_API_KEY not set'); return; }
  const planName = PLANS.find(p => p.id === plan)?.name || plan;
  const amountStr = amount === 0 ? 'Free' : `€${amount}/${period === 'yearly' ? 'yr' : 'mo'}`;
  const msg = emailTemplates.billingConfirmationEmail({ planName, period, amountStr, stub: true });
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html }),
  });
  if (!res.ok) console.error('[billing] Resend error:', res.status, await res.text().catch(() => ''));
}

async function sendCancellationScheduled(email, plan, cancelAt) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) { console.warn('[billing] RESEND_API_KEY not set'); return; }
  const planName = PLANS.find(p => p.id === plan)?.name || plan;
  const cancelDate = new Date(cancelAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const msg = emailTemplates.billingCancellationEmail({ planName, cancelDate });
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: msg.from, replyTo: msg.replyTo, to: [email], subject: msg.subject, text: msg.text, html: msg.html }),
  });
  if (!res.ok) console.error('[billing] Resend cancel error:', res.status, await res.text().catch(() => ''));
}

api.get("/user/billing/plans", (req, res) => {
  res.json({ plans: PLANS });
});

api.post("/user/billing/checkout", authUser, async (req, res) => {
  const { plan_id, period } = req.body || {};
  if (!plan_id || !['monthly', 'yearly'].includes(period)) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  const plan = PLANS.find(p => p.id === plan_id);
  if (!plan || plan.id === 'community') return res.status(400).json({ error: 'invalid_plan' });
  if (plan.price_monthly_eur === null) return res.status(400).json({ error: 'enterprise_contact_sales' });

  const amount = period === 'yearly' ? plan.price_yearly_eur : plan.price_monthly_eur;
  const token = crypto.randomBytes(20).toString('hex');
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();

  await redis().set(
    `paramant:user:checkout:${token}`,
    JSON.stringify({
      user_id: req.userSession.user_id,
      email: req.userSession.email,
      plan_id,
      plan_name: plan.name,
      period,
      amount_eur: amount,
      status: 'pending',
      created_at: new Date().toISOString(),
    }),
    { EX: 3600 }
  );

  // PLACEHOLDER: replace this block with stripe.checkout.sessions.create() when integrating Stripe
  res.json({ checkout_url: `/billing/checkout/${token}`, expires_at: expiresAt });
});

api.get("/user/billing/checkout/:token", authUser, async (req, res) => {
  const raw = await redis().get(`paramant:user:checkout:${req.params.token}`);
  if (!raw) return res.status(404).json({ error: 'checkout_not_found' });
  const s = JSON.parse(raw);
  if (s.user_id !== req.userSession.user_id) return res.status(403).json({ error: 'forbidden' });
  res.json({ plan_id: s.plan_id, plan_name: s.plan_name, period: s.period, amount_eur: s.amount_eur, email: s.email, status: s.status });
});

api.post("/user/billing/checkout/:token/confirm", authUser, async (req, res) => {
  const raw = await redis().get(`paramant:user:checkout:${req.params.token}`);
  if (!raw) return res.status(404).json({ error: 'checkout_not_found' });
  const session = JSON.parse(raw);
  if (session.user_id !== req.userSession.user_id) return res.status(403).json({ error: 'forbidden' });
  if (session.status !== 'pending') return res.status(409).json({ error: 'already_processed' });

  // Get current plan for audit log
  const keysRes = await relayFetch("health", "/v2/admin/keys", "GET", null, false, ADMIN_TOKEN);
  const currentKey = (keysRes.body?.keys || []).find(k => k.key === session.user_id);
  const fromPlan = currentKey?.plan || 'community';

  // PLACEHOLDER: replace with stripe.webhooks.constructEvent() verification when integrating Stripe
  const updateRes = await callRelay("/v2/admin/keys/update-plan", { key: session.user_id, plan: session.plan_id });
  if (!updateRes.ok) {
    console.error('[billing] update-plan failed:', updateRes.status);
    return res.status(502).json({ error: 'plan_update_failed' });
  }

  // (cross-sector /v2/reload-users trigger removed: update-plan already mutates
  // the relay's in-memory apiKeys directly. The reload was the cause of the
  // 2026-05-08 wipe race against the concurrent users.json write.)

  const now = new Date().toISOString();
  const nextBilling = session.period === 'yearly'
    ? new Date(Date.now() + 365 * 86_400_000).toISOString()
    : new Date(Date.now() + 30 * 86_400_000).toISOString();

  await redis().set(
    `paramant:user:billing:${session.user_id}`,
    JSON.stringify({ plan: session.plan_id, period: session.period, amount_eur: session.amount_eur, activated_at: now, next_billing_date: nextBilling })
  );

  await logAuditEvent(session.user_id, 'plan_changed', {
    from: fromPlan, to: session.plan_id, period: session.period, amount_eur: session.amount_eur, via: 'stub_checkout',
  });

  await redis().set(
    `paramant:user:checkout:${req.params.token}`,
    JSON.stringify({ ...session, status: 'completed', completed_at: now }),
    { EX: 3600 }
  );

  try { await sendBillingConfirmation(session.email, session.plan_id, session.amount_eur, session.period); }
  catch (err) { console.error('[billing] confirmation email failed:', err.message); }

  res.json({ success: true, new_plan: session.plan_id, effective_from: now });
});

api.post("/user/billing/cancel", authUser, async (req, res) => {
  const { user_id, email } = req.userSession;
  const billingRaw = await redis().get(`paramant:user:billing:${user_id}`);
  const billing = billingRaw ? JSON.parse(billingRaw) : null;
  const cancelAt = billing?.next_billing_date || new Date(Date.now() + 30 * 86_400_000).toISOString();
  await redis().set(`paramant:user:plan_cancel_at:${user_id}`, cancelAt);
  await logAuditEvent(user_id, 'plan_cancellation_scheduled', { cancel_at: cancelAt, plan: billing?.plan || 'pro', via: 'user_request' });
  try { await sendCancellationScheduled(email, billing?.plan || 'pro', cancelAt); }
  catch (err) { console.error('[billing] cancel email failed:', err.message); }
  res.json({ scheduled_downgrade_at: cancelAt });
});

api.get("/user/billing/status", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const billingRaw = await redis().get(`paramant:user:billing:${user_id}`);
  const billing = billingRaw ? JSON.parse(billingRaw) : null;
  const cancelAt = await redis().get(`paramant:user:plan_cancel_at:${user_id}`);
  const keysRes = await relayFetch("health", "/v2/admin/keys", "GET", null, false, ADMIN_TOKEN);
  const currentKey = (keysRes.body?.keys || []).find(k => k.key === user_id);
  res.json({
    current_plan: currentKey?.plan || 'community',
    period: billing?.period || null,
    amount_eur: billing?.amount_eur ?? 0,
    next_billing_date: billing?.next_billing_date || null,
    cancellation_scheduled_at: cancelAt || null,
    stub_notice: 'Payment integration pending. No real charges apply.',
  });
});

api.get("/user/billing/history", authUser, async (req, res) => {
  const { user_id } = req.userSession;
  const events = await getAuditEvents(user_id, {
    limit: 10,
    event_types: ['plan_changed', 'plan_cancellation_scheduled', 'plan_downgraded'],
  });
  res.json({ history: events });
});


// ─── Telemetry / dashboard endpoints ──────────────────────────────────────────
const telemetry = require("./lib/telemetry");

api.get("/admin/overview", authMiddleware, async (req, res) => {
  try {
    const [activeSessions, recentAudit, planDist, signupsToday] = await Promise.all([
      telemetry.countActiveSessions(),
      telemetry.getRecentAuditEvents(10),
      telemetry.getPlanDistribution(relayFetch, ADMIN_TOKEN),
      telemetry.countSignupsToday(relayFetch, ADMIN_TOKEN),
    ]);
    const today = new Date().toISOString().split("T")[0];
    const proUpgrades = recentAudit.filter(e =>
      e.event_type === "plan_changed" &&
      (e.metadata?.to === "pro" || e.metadata?.to === "enterprise") &&
      new Date(e.ts).toISOString().startsWith(today)
    ).length;
    res.json({
      stats: { signups_today: signupsToday, active_sessions: activeSessions, pro_upgrades_today: proUpgrades, revenue_mrr: 0 },
      recent_activity: recentAudit,
      alerts: [],
      plan_distribution: planDist,
    });
  } catch (err) { console.error("[admin/overview]", err.message); res.status(500).json({ error: "internal" }); }
});

api.get("/admin/users", authMiddleware, async (req, res) => {
  try {
    const allUsers = await telemetry.getUsersWithTotp(relayFetch, ADMIN_TOKEN);

    // Filters
    const statusFilter = req.query.status || "";
    const planFilter   = req.query.plan   || "";
    let filtered = allUsers;
    if (statusFilter === "active")  filtered = filtered.filter(u => u.active);
    if (statusFilter === "revoked") filtered = filtered.filter(u => !u.active);
    if (planFilter) filtered = filtered.filter(u => (u.plan || "community") === planFilter);

    // Sort
    filtered.sort((a, b) => {
      const ta = a.created ? new Date(a.created).getTime() : 0;
      const tb = b.created ? new Date(b.created).getTime() : 0;
      return tb - ta;
    });

    // Pagination
    const page     = Math.max(1, parseInt(req.query.page)      || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.page_size) || 50));
    const totalItems = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    const safePage   = Math.min(page, totalPages);
    const start = (safePage - 1) * pageSize;
    const users = filtered.slice(start, start + pageSize);

    res.json({
      users,
      counts: {
        total: allUsers.length,
        active: allUsers.filter(u => u.active).length,
        community: allUsers.filter(u => u.plan === "community").length,
        pro: allUsers.filter(u => u.plan === "pro").length,
        enterprise: allUsers.filter(u => u.plan === "enterprise").length,
      },
      pagination: {
        page: safePage,
        page_size: pageSize,
        total_items: totalItems,
        total_pages: totalPages,
        has_next: safePage < totalPages,
        has_prev: safePage > 1,
      },
    });
  } catch (err) { console.error("[admin/users]", err.message); res.status(500).json({ error: "internal" }); }
});

// GET /admin/user-detail/:key — full key returned with audit log (YELLOW-1)
api.get("/admin/user-detail/:key", authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    if (!key || !key.startsWith("pgp_")) return res.status(400).json({ error: "invalid_key" });
    const allUsers = await telemetry.getUsersWithTotp(relayFetch, ADMIN_TOKEN);
    const user = allUsers.find(u => u.key === key);
    if (!user) return res.status(404).json({ error: "not_found" });
    const events = await getAuditEvents(key, { limit: 20 });
    try { await logAuditEvent(key, 'admin_key_viewed', { admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ...user, key: key, key_id: key, audit_events: events });
  } catch (err) { console.error("[admin/user-detail]", err.message); res.status(500).json({ error: "internal" }); }
});

api.get("/admin/audit", authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const userFilter = req.query.user || null;
    const eventFilter = req.query.event || null;
    const sinceMs = req.query.since ? new Date(req.query.since).getTime() : 0;
    const events = [];
    for await (const key of redis().scanIterator({ MATCH: "paramant:user:audit:*", COUNT: 100 })) {
      const userId = key.split(":").pop();
      if (userFilter && !userId.includes(userFilter)) continue;
      const entries = await redis().zRange(key, 0, -1).catch(() => []);
      for (const entry of entries) {
        try {
          const ev = JSON.parse(entry);
          if (sinceMs && ev.ts < sinceMs) continue;
          if (eventFilter && ev.event_type !== eventFilter) continue;
          events.push({ user_id: userId, ...ev });
        } catch {}
      }
    }
    events.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    res.json({ events: events.slice(0, limit), total: events.length });
  } catch (err) { console.error("[admin/audit]", err.message); res.status(500).json({ error: "internal" }); }
});

api.get("/admin/billing", authMiddleware, async (req, res) => {
  try {
    const [planDist, recentAudit] = await Promise.all([
      telemetry.getPlanDistribution(relayFetch, ADMIN_TOKEN),
      telemetry.getRecentAuditEvents(200),
    ]);
    res.json({
      stub_mode: true, mrr_eur: 0,
      total_customers: Object.values(planDist).reduce((a, b) => a + b, 0),
      churn_this_month: 0,
      plan_distribution: planDist,
      recent_checkouts: recentAudit.filter(e => e.event_type === "plan_changed").slice(0, 20),
    });
  } catch (err) { console.error("[admin/billing]", err.message); res.status(500).json({ error: "internal" }); }
});

api.get("/admin/relay-detail", authMiddleware, async (req, res) => {
  try {
    const details = {};
    await Promise.all(Object.keys(SECTORS).map(async s => {
      try {
        const [hRes, mRes] = await Promise.all([
          relayFetch(s, "/health", "GET", null, false, ADMIN_TOKEN),
          relayFetch(s, "/metrics", "GET", null, true, ADMIN_TOKEN).catch(() => ({ status: 0, text: '' })),
        ]);
        if (hRes.status !== 200) { details[s] = { error: "HTTP " + hRes.status }; return; }
        const d = { ...hRes.body };
        // extract uptime_s from prometheus metrics
        const uptimeMatch = (mRes.text || '').match(/paramant_uptime_s\{[^}]*\}\s+([\d.]+)/);
        if (uptimeMatch) d.uptime_s = parseFloat(uptimeMatch[1]);
        // normalize blobs field name for frontend
        if (d.blobs_in_flight !== undefined && d.blobs === undefined) d.blobs = d.blobs_in_flight;
        details[s] = d;
      } catch (e) { details[s] = { error: e.message }; }
    }));
    res.json({ sectors: details });
  } catch (err) { console.error("[admin/relay-detail]", err.message); res.status(500).json({ error: "internal" }); }
});


// ── POST /admin/force-totp ───────────────────────────────────────────────────────
api.post('/admin/force-totp', authMiddleware, async (req, res) => {
  const { key, required, reason } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  if (typeof required !== 'boolean') return res.status(400).json({ error: 'required_must_be_boolean' });
  if (!await checkAdminRl('force_totp', 'admin', 20)) return res.status(429).json({ error: 'rate_limited' });
  try {
    const metaRaw = await redis().get(`paramant:user:meta:${key}`).catch(() => null);
    let userMeta = {};
    try { if (metaRaw) userMeta = JSON.parse(metaRaw); } catch {}
    const before = !!userMeta.totp_required;
    if (required) {
      userMeta.totp_required = true;
      userMeta.totp_required_at = Date.now();
      userMeta.totp_required_by = 'admin';
    } else {
      userMeta.totp_required = false;
      delete userMeta.totp_required_at;
      delete userMeta.totp_required_by;
    }
    await redis().set(`paramant:user:meta:${key}`, JSON.stringify(userMeta));

    let sessions_revoked = 0;
    let setup_email_sent = false;
    if (required) {
      const totpActive = await redis().get(`paramant:user:totp_active:${key}`).catch(() => null);
      if (totpActive !== 'true') {
        for await (const rkey of redis().scanIterator({ MATCH: `paramant:user:session:*`, COUNT: 100 })) {
          const raw = await redis().get(rkey).catch(() => null);
          if (raw) { try { const ss = JSON.parse(raw); if (ss.user_id === key) { await redis().del(rkey); sessions_revoked++; } } catch {} }
        }
        if (userMeta.email) {
          try {
            const setupToken = require('crypto').randomBytes(32).toString('hex');
            await redis().set(`paramant:user:setup_token:${setupToken}`, JSON.stringify({ user_id: key, email: userMeta.email }), { EX: 14 * 86400 });
            await sendSetupEmail(userMeta.email, setupToken);
            setup_email_sent = true;
          } catch (e) { console.error('[admin/force-totp] setup email:', e.message); }
        }
      }
    }
    try { await logAuditEvent(key, 'admin_totp_required_toggled', { before, after: required, reason: reason || null, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, totp_required: required, user_email: userMeta.email || null, sessions_revoked, setup_email_sent });
  } catch (err) { console.error('[admin/force-totp]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// ── Admin helpers ─────────────────────────────────────────────────────────────
async function getAdminKeyMeta(key_id) {
  const [keysRes, metaRaw] = await Promise.all([
    relayFetch('health', '/v2/admin/keys', 'GET', null, false, ADMIN_TOKEN),
    redis().get(`paramant:user:meta:${key_id}`).catch(() => null),
  ]);
  const k = (keysRes.body?.keys || []).find(k => k.key === key_id) || {};
  let meta = {};
  try { if (metaRaw) meta = JSON.parse(metaRaw); } catch {}
  return {
    email: meta.email || k.email || null,
    plan: k.plan || 'community',
    label: k.label || null,
    active: k.active !== false,
    sectors: k.sectors || [],
  };
}

async function checkAdminRl(scope, id, limit) {
  const key = `paramant:ratelimit:admin_${scope}:${id}`;
  const cnt = parseInt(await redis().get(key).catch(() => '0') || '0');
  if (cnt >= limit) return false;
  await redis().multi().incr(key).expire(key, 86400).exec().catch(() => {});
  return true;
}

// ── POST /admin/send-welcome ───────────────────────────────────────────────────
api.post('/admin/send-welcome', authMiddleware, async (req, res) => {
  const { key } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  try {
    const meta = await getAdminKeyMeta(key);
    if (!meta.email) return res.status(422).json({ error: 'no_email', message: 'No email on record for this key' });
    if (req.query.preview === '1') {
      const tpl = emailTemplates.welcomeEmail({ apiKey: key, plan: meta.plan, label: meta.label, sectors: meta.sectors });
      return res.json({ ...tpl, recipient: meta.email });
    }
    if (!await checkAdminRl('welcome', key, 10)) return res.status(429).json({ error: 'rate_limited' });
    await emailTemplates.sendEmail(meta.email, emailTemplates.welcomeEmail({ apiKey: key, plan: meta.plan, label: meta.label, sectors: meta.sectors }));
    try { await logAuditEvent(key, 'admin_welcome_sent', { email: meta.email, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, email: meta.email });
  } catch (err) { console.error('[admin/send-welcome]', err.message); res.status(500).json({ error: 'send_failed', message: err.message }); }
});

// ── POST /admin/reset-totp ────────────────────────────────────────────────────
api.post('/admin/reset-totp', authMiddleware, async (req, res) => {
  const { key, mode = 'request' } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  if (!['request', 'direct'].includes(mode)) return res.status(400).json({ error: 'invalid_mode' });
  try {
    const meta = await getAdminKeyMeta(key);
    if (!meta.email) return res.status(422).json({ error: 'no_email' });
    if (!await checkAdminRl('reset_totp', key, 5)) return res.status(429).json({ error: 'rate_limited' });
    if (mode === 'direct') {
      await callRelay('/v2/user/delete-totp', { user_id: key }).catch(() => {});
      const setupToken = crypto.randomBytes(32).toString('hex');
      await redis().set(`paramant:user:setup_token:${setupToken}`, JSON.stringify({ user_id: key, email: meta.email }), { EX: 14 * 86_400 });
      await emailTemplates.sendEmail(meta.email, emailTemplates.setupEmail({ token: setupToken, requestedAt: Date.now(), requestIP: req.headers['x-real-ip'], isReset: true }));
      try { await logAuditEvent(key, 'admin_totp_reset_initiated', { mode: 'direct', email: meta.email, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
      res.json({ ok: true, mode: 'direct', email: meta.email });
    } else {
      const confirmToken = crypto.randomBytes(32).toString('hex');
      await redis().set(`paramant:user:reset_confirm:${confirmToken}`, JSON.stringify({ user_id: key, email: meta.email, admin_initiated: true }), { EX: 3600 });
      await emailTemplates.sendEmail(meta.email, emailTemplates.resetConfirmationEmail({ confirmToken, requestedAt: Date.now(), requestIP: req.headers['x-real-ip'] }));
      try { await logAuditEvent(key, 'admin_totp_reset_initiated', { mode: 'request', email: meta.email, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
      res.json({ ok: true, mode: 'request', email: meta.email });
    }
  } catch (err) { console.error('[admin/reset-totp]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// ── POST /admin/change-plan ───────────────────────────────────────────────────
api.post('/admin/change-plan', authMiddleware, async (req, res) => {
  const { key, new_plan, notify = true } = req.body || {};
  const VALID = ['community', 'pro', 'enterprise', 'trial'];
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  if (!VALID.includes(new_plan)) return res.status(400).json({ error: 'invalid_plan', valid: VALID });
  if (!await checkAdminRl('change_plan', 'admin', 20)) return res.status(429).json({ error: 'rate_limited' });
  try {
    const meta = await getAdminKeyMeta(key);
    const updateRes = await callRelay('/v2/admin/keys/update-plan', { key, plan: new_plan });
    if (!updateRes.ok) return res.status(502).json({ error: 'relay_error' });
    await Promise.allSettled(Object.keys(SECTORS).map(s => relayFetch(s, '/v2/reload-users', 'POST', {}, false, ADMIN_TOKEN)));
    if (notify && meta.email) {
      const planName = new_plan.charAt(0).toUpperCase() + new_plan.slice(1);
      emailTemplates.sendEmail(meta.email, emailTemplates.billingConfirmationEmail({ planName, period: 'admin', amountStr: 'admin-provisioned', stub: true })).catch(e => console.error('[admin/change-plan] email:', e.message));
    }
    try { await logAuditEvent(key, 'admin_plan_changed', { from: meta.plan, to: new_plan, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, from: meta.plan, to: new_plan, email_sent: !!(notify && meta.email) });
  } catch (err) { console.error('[admin/change-plan]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// ── POST /admin/revoke-sessions ───────────────────────────────────────────────
api.post('/admin/revoke-sessions', authMiddleware, async (req, res) => {
  const { key } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  try {
    let count = 0;
    for await (const rkey of redis().scanIterator({ MATCH: 'paramant:user:session:*', COUNT: 100 })) {
      const raw = await redis().get(rkey).catch(() => null);
      if (raw) { try { const s = JSON.parse(raw); if (s.user_id === key) { await redis().del(rkey); count++; } } catch {} }
    }
    try { await logAuditEvent(key, 'admin_sessions_revoked', { count, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, revoked: count });
  } catch (err) { console.error('[admin/revoke-sessions]', err.message); res.status(500).json({ error: 'internal' }); }
});

// ── POST /admin/disable-key ───────────────────────────────────────────────────
api.post('/admin/disable-key', authMiddleware, async (req, res) => {
  const { key, reason = 'not specified', notify = false } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  if (!await checkAdminRl('disable_key', 'admin', 10)) return res.status(429).json({ error: 'rate_limited' });
  try {
    const meta = await getAdminKeyMeta(key);
    await eachSector(Object.keys(SECTORS), async s => relayFetch(s, '/v2/admin/keys/revoke', 'POST', { key }, false, ADMIN_TOKEN).catch(() => {}));
    if (notify && meta.email) {
      const planName = meta.plan.charAt(0).toUpperCase() + meta.plan.slice(1);
      emailTemplates.sendEmail(meta.email, emailTemplates.billingCancellationEmail({ planName, cancelDate: new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) })).catch(e => console.error('[admin/disable-key] email:', e.message));
    }
    try { await logAuditEvent(key, 'admin_key_disabled', { reason, notify: !!(notify && meta.email), admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, reason, email_sent: !!(notify && meta.email) });
  } catch (err) { console.error('[admin/disable-key]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// ── POST /admin/delete-account ────────────────────────────────────────────────
api.post('/admin/delete-account', authMiddleware, async (req, res) => {
  const { key, confirm, reason, notify = true } = req.body || {};
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  if (confirm !== 'DELETE') return res.status(400).json({ error: 'confirm_required', message: "Body must include confirm: 'DELETE'" });
  if (!await checkAdminRl('delete_account', 'admin', 50)) return res.status(429).json({ error: 'rate_limited' });
  try {
    const meta = await getAdminKeyMeta(key);
    await eachSector(Object.keys(SECTORS), async s => relayFetch(s, '/v2/admin/keys/revoke', 'POST', { key }, false, ADMIN_TOKEN).catch(() => {}));
    await callRelay('/v2/user/delete-totp', { user_id: key }).catch(() => {});
    for await (const rkey of redis().scanIterator({ MATCH: `paramant:user:session:*`, COUNT: 100 })) {
      const raw = await redis().get(rkey).catch(() => null);
      if (raw) { try { const s = JSON.parse(raw); if (s.user_id === key) await redis().del(rkey); } catch {} }
    }
    for (const pattern of [`paramant:user:meta:${key}`, `paramant:user:totp:${key}`, `paramant:user:totp_active:${key}`, `paramant:user:billing:${key}`]) {
      await redis().del(pattern).catch(() => {});
    }
    const deletedAt = Date.now();
    if (notify && meta.email) {
      emailTemplates.sendEmail(meta.email, emailTemplates.accountDeletionEmail({ email: meta.email, deletedAt, reason: reason || 'admin action' })).catch(e => console.error('[admin/delete-account] email:', e.message));
    }
    await Promise.allSettled(Object.keys(SECTORS).map(s => relayFetch(s, '/v2/reload-users', 'POST', {}, false, ADMIN_TOKEN)));
    try { await logAuditEvent('admin', 'admin_account_deleted', { key_prefix: key.slice(0, 16), email: meta.email, admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({ ok: true, deleted_at: new Date(deletedAt).toISOString(), email_sent: !!(notify && meta.email) });
  } catch (err) { console.error('[admin/delete-account]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// ── GET /admin/user-details/:key (rich version) ───────────────────────────────
api.get('/admin/user-details/:key', authMiddleware, async (req, res) => {
  const { key } = req.params;
  if (!key?.startsWith('pgp_')) return res.status(400).json({ error: 'invalid_key' });
  try {
    const [keysRes, metaRaw, billingRaw, auditEvents] = await Promise.all([
      relayFetch('health', '/v2/admin/keys', 'GET', null, false, ADMIN_TOKEN),
      redis().get(`paramant:user:meta:${key}`).catch(() => null),
      redis().get(`paramant:user:billing:${key}`).catch(() => null),
      getAuditEvents(key, { limit: 20 }),
    ]);
    const k = (keysRes.body?.keys || []).find(k => k.key === key);
    if (!k) return res.status(404).json({ error: 'not_found' });
    let meta = {}; try { if (metaRaw) meta = JSON.parse(metaRaw); } catch {}
    let billing = null; try { if (billingRaw) billing = JSON.parse(billingRaw); } catch {}
    let sessionCount = 0;
    for await (const rkey of redis().scanIterator({ MATCH: 'paramant:user:session:*', COUNT: 100 })) {
      const raw = await redis().get(rkey).catch(() => null);
      if (raw) { try { const s = JSON.parse(raw); if (s.user_id === key) sessionCount++; } catch {} }
    }
    const [totpActive, totpSecret] = await Promise.all([
      redis().get(`paramant:user:totp_active:${key}`).catch(() => null),
      redis().get(`paramant:user:totp:${key}`).catch(() => null),
    ]);
    let totp_status = 'none';
    if (totpActive === 'true') totp_status = 'active';
    else if (totpSecret) totp_status = 'pending';
    try { await logAuditEvent(key, 'admin_user_viewed', { admin_ip: req.headers['x-real-ip'] || 'unknown' }); } catch {}
    res.json({
      key_id: key,
      key_masked: key.slice(0, 8) + '...' + key.slice(-4),
      email: meta.email || k.email || null,
      label: k.label || null,
      plan: k.plan || 'community',
      sectors: k.sectors || [],
      active: k.active !== false,
      revoked_at: k.revoked_at || null,
      created: meta.created_at || k.created || null,
      totp_status,
      active_sessions: sessionCount,
      billing: billing || { plan: k.plan || 'community', stub: true },
      audit_events: auditEvents,
    });
  } catch (err) { console.error('[admin/user-details]', err.message); res.status(500).json({ error: 'internal' }); }
});

// ── POST /admin/preview-email ─────────────────────────────────────────────────
api.post('/admin/preview-email', authMiddleware, async (req, res) => {
  const { type, key, options = {} } = req.body || {};
  const VALID = ['welcome', 'setup', 'reset-confirm', 'billing', 'cancellation', 'deletion'];
  if (!VALID.includes(type)) return res.status(400).json({ error: 'invalid_type', valid: VALID });
  try {
    let meta = { email: 'preview@example.com', label: 'preview', plan: 'pro', sectors: [], active: true };
    if (key?.startsWith('pgp_')) {
      try { const m = await getAdminKeyMeta(key); if (m) Object.assign(meta, m); } catch {}
    }
    const email = options.email || meta.email || 'preview@example.com';
    let tpl;
    const fakeToken = 'preview' + crypto.randomBytes(8).toString('hex');
    if (type === 'welcome') tpl = emailTemplates.welcomeEmail({ apiKey: key || 'pgp_preview00000000', plan: meta.plan, label: meta.label, sectors: meta.sectors });
    else if (type === 'setup') tpl = emailTemplates.setupEmail({ token: fakeToken, requestedAt: Date.now(), requestIP: '0.0.0.0', isReset: options.isReset || false });
    else if (type === 'reset-confirm') tpl = emailTemplates.resetConfirmationEmail({ confirmToken: fakeToken, requestedAt: Date.now(), requestIP: '0.0.0.0' });
    else if (type === 'billing') { const planName = (options.plan || meta.plan || 'pro'); tpl = emailTemplates.billingConfirmationEmail({ planName: planName.charAt(0).toUpperCase()+planName.slice(1), period: 'monthly', amountStr: '€9/mo', stub: true }); }
    else if (type === 'cancellation') { const planName = meta.plan || 'pro'; tpl = emailTemplates.billingCancellationEmail({ planName: planName.charAt(0).toUpperCase()+planName.slice(1), cancelDate: new Date(Date.now()+30*86_400_000).toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'}) }); }
    else if (type === 'deletion') tpl = emailTemplates.accountDeletionEmail({ email, deletedAt: Date.now(), reason: options.reason || 'preview' });
    res.json({ ...tpl, recipient: email });
  } catch (err) { console.error('[admin/preview-email]', err.message); res.status(500).json({ error: 'internal', message: err.message }); }
});

// -- /admin/cli -- web-based debug terminal ------------------------------------
// Security model:
//   - authMiddleware (admin session) required on every route.
//   - Commands are WHITELIST-only (cli-commands.js); no arbitrary shell.
//   - 'mutate' commands require a fresh, valid TOTP per execution.
//   - 30 executions/min/admin (cli-ratelimit.js).
//   - Every execution is audited (cli-audit.js -> redis global audit + relay CT).
//   - spawn() runs handlers with NO shell and a curated env; args are validated
//     and passed positionally so values are never shell-interpreted.

// Forward CLI audit entries to the durable record: the redis global audit log,
// and (best-effort) the relay CT log for a permanent, tamper-evident record.
cliAudit.setForwarder(async (entry) => {
  try { await logAuditEvent(entry.admin_id || 'cli', entry.event, entry); } catch {}
  try {
    await relayFetch('health', '/v2/ct', 'POST', { kind: 'admin_cli', entry }, false, ADMIN_TOKEN);
  } catch { /* CT forwarding is best-effort; redis is the local source of truth */ }
});

// Derive a stable, non-reversible admin identifier from the session id.
function adminIdFromReq(req) {
  const sid = (req.headers['x-session'] || '').trim();
  return 'adm_' + crypto.createHash('sha256').update(sid).digest('hex').slice(0, 12);
}

// Verify a 6-digit TOTP against the relay (same path as admin login MFA).
async function verifyCliTotp(totp) {
  if (!totp || !/^\d{6}$/.test(totp)) return false;
  try {
    const r = await relayFetch('health', '/v2/admin/verify-mfa', 'POST', { totp_code: totp }, false, ADMIN_TOKEN);
    return !!r.body?.ok;
  } catch { return false; }
}

// Curated environment for handler scripts. We do NOT inherit the full process
// env: only PATH/HOME plus paramant-relevant variables, and computed relay
// locators. This bounds what `config show` can ever surface.
function cliChildEnv(cmd) {
  // Delegates to the pure, unit-tested builder (lib/cli-commands.buildChildEnv).
  // Least-privilege: ADMIN_TOKEN is added only for cmd.needsAdminToken; the
  // REDIS_/RESEND_/PARAMANT_ secrets are never broadcast to handler scripts.
  return cliCommands.buildChildEnv(cmd, process.env, SECTORS, ADMIN_TOKEN);
}

// GET /api/admin/cli/commands -- whitelist metadata for completion/help.
api.get('/admin/cli/commands', authMiddleware, (req, res) => {
  const commands = Object.entries(cliCommands.COMMANDS).map(([name, c]) => ({
    name,
    description: c.description,
    class: c.class,
    totp: c.totp,
    args: c.args.map(a => ({ ...a })),
  }));
  res.json({ commands, rate_limit: { limit: cliRate.LIMIT, window_ms: cliRate.WINDOW } });
});

// POST /api/admin/cli/exec -- execute a whitelisted command, stream output (SSE).
// Body: { command, args: {...}, totp? }
api.post('/admin/cli/exec', authMiddleware, async (req, res) => {
  const adminId = adminIdFromReq(req);
  const { command, args = {}, totp } = req.body || {};

  // SSE helpers -- text/event-stream so output streams line-by-line to xterm.
  let sseOpen = false;
  const openSse = () => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();
    sseOpen = true;
  };
  const sse = (event, data) => { if (sseOpen) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); };

  // 1-3. Whitelist lookup.
  const cmd = cliCommands.COMMANDS[command];
  if (!cmd) {
    cliAudit.logCommand('cli_command_denied', { admin_id: adminId, command, reason: 'unknown_command' });
    return res.status(404).json({ error: 'Unknown command' });
  }
  if (cmd.handler === '__help__') {
    return res.status(400).json({ error: 'help is rendered client-side from /commands' });
  }

  // 5. Validate args against the schema.
  const v = cliCommands.validateArgs(cmd, args);
  if (!v.ok) {
    cliAudit.logCommand('cli_command_denied', { admin_id: adminId, command, reason: 'invalid_args', detail: v.error });
    return res.status(400).json({ error: v.error });
  }

  // 4. Mutate commands require a fresh valid TOTP.
  if (cmd.class === 'mutate' || cmd.totp) {
    const ok = await verifyCliTotp(totp);
    if (!ok) {
      cliAudit.logCommand('cli_command_denied', { admin_id: adminId, command, reason: 'totp_required' });
      return res.status(403).json({ error: 'Valid TOTP code required for this command' });
    }
  }

  // 6. Rate limit (30/min/admin).
  if (!cliRate.checkRate(adminId)) {
    cliAudit.logCommand('cli_command_denied', { admin_id: adminId, command, reason: 'rate_limited' });
    return res.status(429).json({ error: 'Rate limit exceeded (30 commands/min)' });
  }

  // Resolve and confine the handler path inside SCRIPTS_DIR.
  const handlerPath = path.resolve(cliCommands.SCRIPTS_DIR, cmd.handler);
  if (!handlerPath.startsWith(cliCommands.SCRIPTS_DIR + path.sep)) {
    return res.status(500).json({ error: 'handler_path_error' });
  }
  const argv = cliCommands.buildArgv(cmd, v.values);

  // 7. Audit start.
  cliAudit.logCommand('cli_command_started', { admin_id: adminId, command, args: v.values });

  // 8-9. Spawn (no shell) and stream stdout/stderr over SSE.
  openSse();
  const started = Date.now();
  let child;
  try {
    child = spawn(handlerPath, argv, {
      cwd: cliCommands.SCRIPTS_DIR,
      env: cliChildEnv(cmd),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    sse('output', { stream: 'stderr', chunk: `[spawn error] ${err.message}\r\n` });
    sse('done', { exit_code: -1, error: 'spawn_failed' });
    cliAudit.logCommand('cli_command_error', { admin_id: adminId, command, error: err.message });
    return res.end();
  }

  // Hard timeout so no command can run away.
  const TIMEOUT_MS = 60_000;
  const killer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, TIMEOUT_MS);

  // Convert bare \n to \r\n so the xterm renderer advances columns correctly.
  const toTerm = s => s.replace(/\r?\n/g, '\r\n');
  child.stdout.on('data', d => sse('output', { stream: 'stdout', chunk: toTerm(d.toString()) }));
  child.stderr.on('data', d => sse('output', { stream: 'stderr', chunk: toTerm(d.toString()) }));

  // 10-11. Client cancel (Ctrl+C closes the stream) -> kill the child.
  let finished = false;
  req.on('close', () => {
    if (!finished) { try { child.kill('SIGKILL'); } catch {} }
  });

  child.on('error', err => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);
    sse('output', { stream: 'stderr', chunk: `[error] ${err.message}\r\n` });
    sse('done', { exit_code: -1 });
    cliAudit.logCommand('cli_command_error', { admin_id: adminId, command, error: err.message });
    res.end();
  });

  child.on('close', (code, signal) => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);
    const duration_ms = Date.now() - started;
    const exit_code = code === null ? -1 : code;
    sse('done', { exit_code, signal: signal || null, duration_ms });
    cliAudit.logCommand('cli_command_completed', { admin_id: adminId, command, exit_code, signal: signal || null, duration_ms });
    res.end();
  });
});

app.use(`${BASE_PATH}/api`, api);
// /cli -- web debug terminal page (served before the SPA wildcard fallback).
app.get(`${BASE_PATH}/cli`, (req, res) => res.sendFile(path.join(__dirname, 'public', 'cli.html')));
// Express 5: named wildcard required (path-to-regexp v8 — bare /* not allowed)
app.get(`${BASE_PATH}/*path`, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

(async () => {
  await initRedis();
  app.use((err, req, res, next) => {
    console.error('[unhandled error]', err.message);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'internal_error' });
  });

  app.listen(PORT, '0.0.0.0', () => console.log(`[PARAMANT-ADMIN] listening on :${PORT}${BASE_PATH || '/'}`));
})().catch((err) => {
  console.error('[boot] startup failed:', err);
  process.exit(1);
});
