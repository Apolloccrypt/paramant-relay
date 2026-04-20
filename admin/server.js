'use strict';
const express = require('express');
const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');
const { initRedis, redis } = require('./lib/redis');
const { logAuditEvent, getAuditEvents } = require('./lib/audit');

const PORT        = parseInt(process.env.PORT || '4200', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const BASE_PATH   = (process.env.BASE_PATH || '').replace(/\/$/, '');

const SECTORS = {
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
  res.json({ ok: Object.values(results).every(r => r.ok), results });
});

// ── Self-service trial key request (public, no auth) ──────────────────────
api.post('/request-key', async (req, res) => {
  const ip = req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  if (!checkTrialIpLimit(ip)) return res.status(429).json({ error: 'Too many requests — try again in a minute' });

  const { email, name, usecase, website } = req.body || {};
  if (website) return res.status(400).json({ error: 'Bad request' });
  if (!email || typeof email !== 'string') return res.status(400).json({ error: 'Email is required' });
  const norm = email.toLowerCase().trim();
  if (!/^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,}$/.test(norm)) return res.status(400).json({ error: 'Enter a valid email address' });

  const now = Date.now();
  const prev = trialEmailTrack.get(norm);
  if (prev && now - prev.lastAt < 7 * 86_400_000) {
    const nextOk = new Date(prev.lastAt + 7 * 86_400_000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long' });
    return res.status(429).json({ error: `A key was already sent to this address. Next request allowed after ${nextOk}.` });
  }

  const key = 'pgp_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(now + 30 * 86_400_000).toISOString().slice(0, 10);
  const keyBody = { key, plan: 'trial', label: `trial:${norm}${usecase ? ':' + usecase : ''}`, max_uploads: 10, expires_at: expiresAt, active: true };

  try {
    await eachSector(Object.keys(SECTORS), async s => {
      const r = await relayFetch(s, '/v2/admin/keys', 'POST', keyBody, false, ADMIN_TOKEN);
      if (r.status !== 200 && r.status !== 201) console.warn(`[trial] sector ${s} returned ${r.status}`);
    });
    const firstName = (typeof name === 'string' ? name.trim() : '').split(/\s+/)[0] || '';
    const sent = await sendTrialEmail(norm, firstName, key);
    if (!sent) return res.status(503).json({ error: 'Email delivery unavailable — contact privacy@paramant.app' });
    trialEmailTrack.set(norm, { lastAt: now });
    const adminApiKey = process.env.RESEND_API_KEY;
    if (adminApiKey) fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'PARAMANT <noreply@paramant.app>',
        to: ['privacy@paramant.app'],
        subject: `[PARAMANT] New trial key — ${norm}`,
        html: `<p><b>Email:</b> ${norm}</p><p><b>Name:</b> ${name || '—'}</p><p><b>Use case:</b> ${usecase || '—'}</p><p><b>Key prefix:</b> ${key.slice(0, 12)}…</p><p><b>Expires:</b> ${expiresAt}</p>`,
      }),
    }).catch(e => console.warn('[trial] admin notify failed:', e.message));
    return res.json({ ok: true, key, email: norm, message: `Key sent to ${norm}` });
  } catch (e) {
    console.error('[trial] error:', e.message);
    return res.status(500).json({ error: 'Could not issue key — contact privacy@paramant.app' });
  }
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
async function callRelay(endpoint, body) {
  const relayUrl = SECTORS.health;
  const res = await fetch(`${relayUrl}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Auth": INTERNAL_TOKEN,
    },
    body: JSON.stringify(body),
    keepalive: false,
  });
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

// Send setup email via Resend
async function sendSetupEmail(email, setupToken, isReset = false) {
  const setupUrl = `${SITE_URL}/auth/setup/${setupToken}`;
  const subject = isReset ? "Reset your Paramant authenticator" : "Complete your Paramant setup";
  const heading = isReset ? "Set up new Paramant authenticator" : "Set up Paramant authenticator";
  const resetNote = isReset
    ? `<p style="color:#b45309;font-size:13px;margin:0 0 16px;background:#fffbeb;border:1px solid #fde68a;padding:10px 14px;border-radius:4px">If you have a previous Paramant entry in your authenticator app, delete it first &mdash; the old entry no longer works.</p>`
    : "";
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Paramant <noreply@paramant.app>",
      to: [email],
      subject,
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f8fafc"><div style="max-width:540px;margin:40px auto;padding:40px;background:#fff;border:1px solid #e2e8f0;font-family:system-ui,sans-serif"><h2 style="color:#0b3a6a;margin:0 0 20px;font-size:18px">${heading}</h2>${resetNote}<p style="color:#475569;margin:0 0 16px">Click below to set up two-factor authentication for your Paramant account.</p><a href="${setupUrl}" style="display:inline-block;background:#0b3a6a;color:#fff;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:12px;letter-spacing:0.1em;text-transform:uppercase;font-weight:700">Complete setup</a><p style="color:#94a3b8;font-size:12px;margin-top:24px">Link expires in 14 days. If you did not request this, ignore this email.</p><hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0"><p style="color:#94a3b8;font-size:11px;margin:0">Paramant &middot; privacy@paramant.app &middot; Hetzner DE &middot; GDPR</p></div></body></html>`,
      text: `${subject}\n\nLink: ${setupUrl}\n\nExpires in 14 days.${isReset ? " If you had a previous authenticator entry for Paramant, delete it first — it no longer works." : ""} If you did not request this, ignore this email.`,
    }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => "")}`);
}


// Send TOTP reset confirmation email (step 1 of two-stage flow)
async function sendResetConfirmEmail(email, confirmToken, maskedIp, requestedAt) {
  const confirmUrl = `${SITE_URL}/auth/reset-confirm/${confirmToken}`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Paramant <noreply@paramant.app>",
      to: [email],
      subject: "Did you request a TOTP reset? — Paramant",
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f8fafc"><div style="max-width:540px;margin:40px auto;padding:40px;background:#fff;border:1px solid #e2e8f0;font-family:system-ui,sans-serif"><h2 style="color:#0b3a6a;margin:0 0 20px;font-size:18px">Confirm authenticator reset</h2><p style="color:#475569;margin:0 0 16px">Someone requested a reset of your Paramant authenticator. If this was you, click below to confirm. You will then receive a second email with a new setup link.</p><a href="${confirmUrl}" style="display:inline-block;background:#0b3a6a;color:#fff;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:12px;letter-spacing:0.1em;text-transform:uppercase;font-weight:700">Confirm reset</a><p style="color:#94a3b8;font-size:12px;margin-top:24px"><b>This link expires in 15 minutes.</b></p><hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0"><p style="color:#94a3b8;font-size:12px;margin:0 0 8px">Request details:</p><p style="color:#94a3b8;font-size:12px;margin:0">Time: ${requestedAt}<br>IP: ${maskedIp}</p><p style="color:#94a3b8;font-size:12px;margin-top:16px">If you did not request this, ignore this email. Your current authenticator will keep working.</p><hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0"><p style="color:#94a3b8;font-size:11px;margin:0">Paramant &middot; privacy@paramant.app &middot; Hetzner DE &middot; GDPR</p></div></body></html>`,
      text: `Confirm authenticator reset\n\nSomeone requested a reset of your Paramant authenticator.\n\nIf this was you, click the link below to confirm. You will then receive a second email with a new setup link.\n\nConfirm: ${confirmUrl}\n\nThis link expires in 15 minutes.\n\nRequest details:\nTime: ${requestedAt}\nIP: ${maskedIp}\n\nIf you did not request this, ignore this email. Your current authenticator will keep working.`,
    }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => "")}`);
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

function setUserCookie(res, token) {
  res.setHeader("Set-Cookie",
    `paramant_user_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
  );
}

function clearUserCookie(res) {
  res.setHeader("Set-Cookie",
    "paramant_user_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );
}

// ── Signup flow ───────────────────────────────────────────────────────────────

// POST /api/user/signup
api.post("/user/signup", async (req, res) => {
  const { email, label, dpa_accepted } = req.body || {};
  if (!email || !dpa_accepted) return res.status(400).json({ error: "missing_fields" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });

  const ip = req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
  const ipKey = `paramant:signup:ratelimit:${ip}`;
  const count = await redis().incr(ipKey);
  if (count === 1) await redis().expire(ipKey, 3600);
  if (count > 3) return res.status(429).json({ error: "rate_limited" });

  const existing = await findUserByEmail(email);
  if (existing) return res.status(409).json({ error: "account_exists" });

  // Create API key via admin relay
  const keyVal = "pgp_" + crypto.randomBytes(32).toString("hex");
  const createRes = await relayFetch("health", "/v2/admin/keys", "POST", {
    key: keyVal,
    email: email.toLowerCase(),
    label: label || null,
    plan: "community",
    active: true,
  }, false, ADMIN_TOKEN);

  if (createRes.status !== 200 && createRes.status !== 201) {
    console.error("[signup] key creation failed:", createRes.status, createRes.body);
    return res.status(500).json({ error: "key_creation_failed" });
  }

  const setupToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:setup_token:${setupToken}`,
    JSON.stringify({ user_id: keyVal, email: email.toLowerCase(), label: label || null }),
    { EX: 14 * 86400 }
  );

  try {
    await sendSetupEmail(email, setupToken);
  } catch (err) {
    console.error("[signup] email failed:", err.message);
    return res.status(500).json({ error: "email_failed", message: "Account created but email failed. Contact privacy@paramant.app." });
  }

  res.json({ success: true, message: "setup_email_sent" });
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
  const otpauth = `otpauth://totp/${issuer}:${encodedEmail}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

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

  await callRelay("/v2/user/activate-totp", { user_id });
  await redis().del(`paramant:user:setup_token:${token}`);

  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id, email, created_at: Date.now(), ip: req.headers["x-real-ip"] || "unknown", ua: req.get("user-agent") || "" }),
    { EX: 3600 }
  );

  setUserCookie(res, sessionToken);

  const codesRes = await callRelay("/v2/user/get-backup-codes-plaintext", { user_id });
  const { backup_codes } = codesRes.ok ? await codesRes.json() : { backup_codes: [] };

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
  if (activeRaw !== "true") return res.status(403).json({ error: "totp_not_configured" });

  const verifyRes = await callRelay("/v2/user/verify-totp", { user_id: user.key, totp });
  if (!verifyRes.ok) return res.status(401).json({ error: "invalid_credentials" });
  const result = await verifyRes.json();
  if (!result.valid) return res.status(401).json({ error: "invalid_credentials" });

  const sessionToken = crypto.randomBytes(32).toString("hex");
  await redis().set(
    `paramant:user:session:${sessionToken}`,
    JSON.stringify({ user_id: user.key, email: user.email, created_at: Date.now(), ip, ua: req.get("user-agent") || "" }),
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
    JSON.stringify({ user_id: user.key, email: user.email, created_at: Date.now(), ip: req.headers["x-real-ip"] || "unknown", ua: req.get("user-agent") || "", via: "backup_code" }),
    { EX: 3600 }
  );

  setUserCookie(res, sessionToken);
  res.json({ success: true, email: user.email });
});


// POST /api/user/auth/request-totp-reset (public — two-stage: sends confirmation first)
api.post("/user/auth/request-totp-reset", async (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== "string") return res.status(400).json({ error: "invalid_request" });
  const norm = email.toLowerCase().trim();

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
    { EX: 900 } // 15 minutes
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
  res.json({ api_key: req.userSession.user_id });
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
      "X-Api-Key": req.userSession.user_id,
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
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Paramant <noreply@paramant.app>',
      to: [email],
      subject: `Paramant plan upgraded to ${planName}`,
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f8fafc"><div style="max-width:540px;margin:40px auto;padding:40px;background:#fff;border:1px solid #e2e8f0;font-family:system-ui,sans-serif"><h2 style="color:#0b3a6a;margin:0 0 20px;font-size:18px">Plan upgraded to ${planName}</h2><p style="color:#475569;margin:0 0 16px">Your Paramant plan has been upgraded. Here are the details:</p><table style="width:100%;border-collapse:collapse;margin-bottom:24px"><tr><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:14px">Plan</td><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;font-weight:600;text-align:right">${planName}</td></tr><tr><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:14px">Billing period</td><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;font-weight:600;text-align:right">${period === 'yearly' ? 'Yearly' : 'Monthly'}</td></tr><tr><td style="padding:10px 0;color:#64748b;font-size:14px">Amount</td><td style="padding:10px 0;font-weight:700;color:#1d4ed8;text-align:right">${amountStr}</td></tr></table><p style="color:#94a3b8;font-size:12px;margin-top:24px">Note: This is a stub confirmation. No real payment was charged. Stripe integration pending.</p><hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0"><p style="color:#94a3b8;font-size:11px;margin:0">Paramant &middot; privacy@paramant.app</p></div></body></html>`,
      text: `Your Paramant plan has been upgraded to ${planName} (${period}). Amount: ${amountStr}. Note: stub checkout — no real charge.`,
    }),
  });
}

async function sendCancellationScheduled(email, plan, cancelAt) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) { console.warn('[billing] RESEND_API_KEY not set'); return; }
  const planName = PLANS.find(p => p.id === plan)?.name || plan;
  const cancelDate = new Date(cancelAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Paramant <noreply@paramant.app>',
      to: [email],
      subject: `Your Paramant plan cancellation is scheduled`,
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f8fafc"><div style="max-width:540px;margin:40px auto;padding:40px;background:#fff;border:1px solid #e2e8f0;font-family:system-ui,sans-serif"><h2 style="color:#0b3a6a;margin:0 0 20px;font-size:18px">Cancellation scheduled</h2><p style="color:#475569;margin:0 0 16px">Your ${planName} plan cancellation has been scheduled. Your plan will downgrade to Community on <strong>${cancelDate}</strong>.</p><p style="color:#475569;margin:0 0 16px">You can continue using all ${planName} features until that date.</p><hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0"><p style="color:#94a3b8;font-size:11px;margin:0">Paramant &middot; privacy@paramant.app</p></div></body></html>`,
      text: `Your ${planName} plan cancellation is scheduled for ${cancelDate}. You retain access until then.`,
    }),
  });
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

  // Reload all relay sectors so in-memory maps stay consistent
  await Promise.allSettled(Object.keys(SECTORS).map(s =>
    relayFetch(s, "/v2/reload-users", "POST", {}, false, ADMIN_TOKEN)
  ));

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
    const users = await telemetry.getUsersWithTotp(relayFetch, ADMIN_TOKEN);
    res.json({
      users,
      counts: {
        total: users.length,
        active: users.filter(u => u.active).length,
        community: users.filter(u => u.plan === "community").length,
        pro: users.filter(u => u.plan === "pro").length,
        enterprise: users.filter(u => u.plan === "enterprise").length,
      },
    });
  } catch (err) { console.error("[admin/users]", err.message); res.status(500).json({ error: "internal" }); }
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
        const r = await relayFetch(s, "/health", "GET", null, false, ADMIN_TOKEN);
        details[s] = r.status === 200 ? r.body : { error: "HTTP " + r.status };
      } catch (e) { details[s] = { error: e.message }; }
    }));
    res.json({ sectors: details });
  } catch (err) { console.error("[admin/relay-detail]", err.message); res.status(500).json({ error: "internal" }); }
});

app.use(`${BASE_PATH}/api`, api);
// Express 5: named wildcard required (path-to-regexp v8 — bare /* not allowed)
app.get(`${BASE_PATH}/*path`, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

(async () => {
  await initRedis();
  app.listen(PORT, '0.0.0.0', () => console.log(`[PARAMANT-ADMIN] listening on :${PORT}${BASE_PATH || '/'}`));
})().catch((err) => {
  console.error('[boot] startup failed:', err);
  process.exit(1);
});
