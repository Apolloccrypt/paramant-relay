'use strict';
const express = require('express');
const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');

const PORT        = parseInt(process.env.PORT || '4200', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const BASE_PATH   = (process.env.BASE_PATH || '').replace(/\/$/, '');  // e.g. '/admin'

const SECTORS = {
  health:  process.env.RELAY_HEALTH  || 'http://relay-health:3005',
  legal:   process.env.RELAY_LEGAL   || 'http://relay-legal:3002',
  finance: process.env.RELAY_FINANCE || 'http://relay-finance:3003',
  iot:     process.env.RELAY_IOT     || 'http://relay-iot:3004',
};

if (!ADMIN_TOKEN) {
  console.error('[PARAMANT-ADMIN] ADMIN_TOKEN is not set — refusing to start');
  process.exit(1);
}

// ── Session store ─────────────────────────────────────────────────────────────
const sessions = new Map(); // sid → { expires: ms }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k);
}, 60_000);

function authMiddleware(req, res, next) {
  const sid = (req.headers['x-session'] || '').trim();
  const s = sessions.get(sid);
  if (!s || s.expires < Date.now()) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  req.sessionToken = s.token || ADMIN_TOKEN;
  next();
}

// ── HTTP helper ───────────────────────────────────────────────────────────────
function relayFetch(sector, relPath, method, body, rawResponse, tokenOverride) {
  return new Promise((resolve, reject) => {
    const base = SECTORS[sector];
    if (!base) return reject(new Error(`Unknown sector: ${sector}`));
    const url = new URL(relPath, base);
    const payload = body ? JSON.stringify(body) : undefined;
    const tok = tokenOverride || ADMIN_TOKEN;
    const opts = {
      hostname: url.hostname,
      port:     parseInt(url.port) || 80,
      path:     url.pathname + (url.search || ''),
      method:   method || 'GET',
      headers: {
        'Content-Type':  'application/json',
        'X-Admin-Token': tok,
        'Authorization': `Bearer ${tok}`,
      },
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

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '32kb' }));

// Serve static files at BASE_PATH
app.use(BASE_PATH || '/', express.static(path.join(__dirname, 'public')));

const api = express.Router();

// ── Auth ──────────────────────────────────────────────────────────────────────

api.post('/auth/login', async (req, res) => {
  const { token, totp } = req.body || {};
  if (!token) return res.status(401).json({ error: 'Token required' });
  if (!totp || !/^\d{6}$/.test(totp)) {
    return res.status(400).json({ error: 'TOTP code required (6 digits)' });
  }

  // Accept: master ADMIN_TOKEN  OR  enterprise pgp_ key (relay verifies both)
  const isMaster    = token === ADMIN_TOKEN;
  const isEnterprise = token.startsWith('pgp_');
  if (!isMaster && !isEnterprise) {
    return res.status(401).json({ error: 'Invalid token — use your ADMIN_TOKEN or an enterprise pgp_ key' });
  }

  try {
    // Pass the provided token — relay accepts both master token and enterprise keys
    const r = await relayFetch('health', '/v2/admin/verify-mfa', 'POST', { totp_code: totp }, false, token);
    if (!r.body?.ok) return res.status(401).json({ error: 'Invalid TOTP code' });
    const sid = crypto.randomBytes(32).toString('hex');
    // Store which token to use for relay calls in this session
    sessions.set(sid, { expires: Date.now() + 3_600_000, token });
    return res.json({ ok: true, session: sid, expires_in: 3600 });
  } catch (e) {
    return res.status(502).json({ error: `Relay unreachable: ${e.message}` });
  }
});

api.post('/auth/logout', (req, res) => {
  sessions.delete((req.headers['x-session'] || '').trim());
  res.json({ ok: true });
});

api.get('/auth/check', authMiddleware, (req, res) => res.json({ ok: true }));

// ── Keys per sector ───────────────────────────────────────────────────────────

api.get('/sectors/:sector/keys', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/v2/admin/keys', 'GET', null, false, req.sessionToken);
    res.status(r.status).json(r.body);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

api.post('/sectors/:sector/keys', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/v2/admin/keys', 'POST', req.body, false, req.sessionToken);
    res.status(r.status).json(r.body);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

api.post('/sectors/:sector/keys/revoke', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/v2/admin/keys/revoke', 'POST', req.body, false, req.sessionToken);
    res.status(r.status).json(r.body);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

api.post('/sectors/:sector/keys/welcome', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/v2/admin/send-welcome', 'POST', req.body, false, req.sessionToken);
    res.status(r.status).json(r.body);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ── Stats: parse Prometheus text ──────────────────────────────────────────────

function parseMetrics(text) {
  const m = {};
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const sp = line.lastIndexOf(' ');
    if (sp < 0) continue;
    const name = line.slice(0, sp).trim();
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

api.get('/sectors/:sector/health', authMiddleware, async (req, res) => {
  const { sector } = req.params;
  if (!SECTORS[sector]) return res.status(400).json({ error: 'Unknown sector' });
  try {
    const r = await relayFetch(sector, '/health', 'GET', null, false, req.sessionToken);
    res.status(r.status).json(r.body);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ── All-sector overview ───────────────────────────────────────────────────────

api.get('/overview', authMiddleware, async (req, res) => {
  const results = {};
  await Promise.allSettled(
    Object.keys(SECTORS).map(async sector => {
      try {
        const r = await relayFetch(sector, '/metrics', 'GET', null, true, ADMIN_TOKEN);
        results[sector] = { ok: r.status === 200, metrics: parseMetrics(r.text) };
      } catch (e) {
        results[sector] = { ok: false, error: e.message };
      }
    })
  );
  res.json({ ok: true, sectors: results });
});

// ── Cross-sector key endpoints ────────────────────────────────────────────────

// GET /api/keys/all — laad keys van alle sectoren tegelijk
api.get('/keys/all', authMiddleware, async (req, res) => {
  const results = {};
  await Promise.allSettled(
    Object.keys(SECTORS).map(async sector => {
      try {
        const r = await relayFetch(sector, '/v2/admin/keys', 'GET', null, false, req.sessionToken);
        results[sector] = r.status === 200 ? (r.body?.keys || []) : [];
      } catch { results[sector] = []; }
    })
  );
  res.json({ ok: true, sectors: results });
});

// POST /api/keys/all — maak key op ALLE sectoren aan met zelfde label/plan
api.post('/keys/all', authMiddleware, async (req, res) => {
  const results = {};
  await Promise.allSettled(
    Object.keys(SECTORS).map(async sector => {
      try {
        const r = await relayFetch(sector, '/v2/admin/keys', 'POST', req.body, false, req.sessionToken);
        results[sector] = { status: r.status, data: r.body };
      } catch (e) { results[sector] = { status: 502, data: { error: e.message } }; }
    })
  );
  // Succesvolle keys samenvoegen voor de response
  const created = Object.entries(results)
    .filter(([, v]) => v.status === 200 || v.status === 201)
    .map(([sector, v]) => ({ sector, key: v.data?.key }));
  res.json({ ok: created.length > 0, created, results });
});

// POST /api/keys/all/revoke — revoke key op ALLE sectoren
api.post('/keys/all/revoke', authMiddleware, async (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: 'key required' });
  const results = {};
  await Promise.allSettled(
    Object.keys(SECTORS).map(async sector => {
      try {
        const r = await relayFetch(sector, '/v2/admin/keys/revoke', 'POST', { key }, false, req.sessionToken);
        results[sector] = { status: r.status, ok: r.status === 200 };
      } catch (e) { results[sector] = { status: 502, ok: false }; }
    })
  );
  res.json({ ok: true, results });
});

app.use(`${BASE_PATH}/api`, api);

// Catch-all: serve SPA
app.get(`${BASE_PATH}/*`, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[PARAMANT-ADMIN] listening on :${PORT}${BASE_PATH || '/'}`);
});
