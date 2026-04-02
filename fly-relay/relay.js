'use strict';
const http = require('http');
const https = require('https');
const PORT = process.env.PORT || 8080;

const RELAYS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};

let cache = { ts: 0, data: null };

async function fetchOne(name, url) {
  return new Promise(resolve => {
    const req = https.get(url + '/health', { timeout: 5000 }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ name, ok: true, ...JSON.parse(d) }); }
        catch { resolve({ name, ok: false }); }
      });
    });
    req.on('error', () => resolve({ name, ok: false }));
    req.on('timeout', () => { req.destroy(); resolve({ name, ok: false }); });
  });
}

async function getHealth() {
  if (cache.data && Date.now() - cache.ts < 30000) return cache.data;
  const results = await Promise.all(Object.entries(RELAYS).map(([n, u]) => fetchOne(n, u)));
  cache = {
    ts: Date.now(),
    data: {
      status: 'ok',
      version: '1.0.0',
      role: 'edge-gateway',
      region: process.env.FLY_REGION || 'local',
      uptime_s: Math.floor(process.uptime()),
      relays: results,
      online: results.filter(r => r.ok).length,
      total: results.length,
      all_ok: results.every(r => r.ok),
    }
  };
  return cache.data;
}

function proxy(target, req, res) {
  const u = new URL(target);
  const opts = {
    hostname: u.hostname,
    path: u.pathname + (u.search || ''),
    method: req.method,
    headers: { ...req.headers, host: u.hostname, 'x-edge': process.env.FLY_REGION || 'fly' },
  };
  const p = https.request(opts, pr => {
    res.writeHead(pr.statusCode, { ...pr.headers, 'x-edge-region': process.env.FLY_REGION || 'fly' });
    pr.pipe(res);
  });
  p.on('error', e => { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
  req.pipe(p);
}

http.createServer(async (req, res) => {
  res.setHeader('content-type', 'application/json');
  res.setHeader('access-control-allow-origin', 'https://paramant.app');
  res.setHeader('access-control-allow-headers', 'x-api-key,content-type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/health' || p === '/') {
    const d = await getHealth();
    res.writeHead(d.all_ok ? 200 : 206);
    return res.end(JSON.stringify(d));
  }

  if (p === '/status') {
    const d = await getHealth();
    res.writeHead(200);
    return res.end(JSON.stringify({
      online: d.online + '/' + d.total,
      region: d.region,
      relays: d.relays.map(r => ({ name: r.name, ok: r.ok, version: r.version, uptime_s: r.uptime_s }))
    }));
  }

  // Sector routing: /health/v2/... → health relay
  const sector = p.split('/')[1];
  if (RELAYS[sector]) {
    const rest = '/' + p.split('/').slice(2).join('/') + url.search;
    return proxy(RELAYS[sector] + rest, req, res);
  }

  // Default: health relay
  if (p.startsWith('/v2/')) return proxy(RELAYS.health + p + url.search, req, res);

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'not found', edge: process.env.FLY_REGION }));
}).listen(PORT, () => console.log(`Edge Gateway v1.0.0 — port ${PORT} — ${process.env.FLY_REGION || 'local'}`));

process.on('SIGTERM', () => process.exit(0));
