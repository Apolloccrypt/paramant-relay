'use strict';
const express = require('express');
const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');

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

const sessions = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k); }, 60_000);

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

function authMiddleware(req, res, next) {
  const s = sessions.get((req.headers['x-session'] || '').trim());
  if (!s || s.expires < Date.now()) return res.status(401).json({ error: 'unauthorized' });
  req.sessionToken = s.token || ADMIN_TOKEN;
  next();
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
  // Fix 1: rate limit by IP (proxy-aware — trust X-Forwarded-For behind nginx)
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
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
    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, { expires: Date.now() + 3_600_000, token: ADMIN_TOKEN });
    return res.json({ ok: true, session: sid, expires_in: 3600 });
  } catch (e) {
    // Fix 10: don't leak internal relay address in error response
    console.error('[admin] relay unreachable:', e.message);
    return res.status(502).json({ error: 'Relay unreachable' });
  }
});

api.post('/auth/logout', (req, res) => { sessions.delete((req.headers['x-session'] || '').trim()); res.json({ ok: true }); });
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
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
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

app.use(`${BASE_PATH}/api`, api);
// Express 5: named wildcard required (path-to-regexp v8 — bare /* not allowed)
app.get(`${BASE_PATH}/*path`, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`[PARAMANT-ADMIN] listening on :${PORT}${BASE_PATH || '/'}`));
