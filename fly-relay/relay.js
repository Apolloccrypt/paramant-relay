'use strict';
const http  = require('http');
const https = require('https');
const net   = require('net');
const PORT  = process.env.PORT || 8080;

// Hetzner origin sector relays — single source of truth for users + blobs
const RELAYS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};

// Sector selection: Host header takes priority, then URL prefix, then default
function pickRelay(req) {
  const host = (req.headers.host || '').toLowerCase();
  for (const s of Object.keys(RELAYS)) {
    if (host.startsWith(s + '.')) return RELAYS[s];
  }
  const seg = (req.url || '/').split('/')[1];
  if (RELAYS[seg]) return RELAYS[seg];
  return RELAYS.health; // default
}

// Strip sector prefix from path if used (/health/v2/... → /v2/...)
function stripSector(pathname) {
  const seg = pathname.split('/')[1];
  if (RELAYS[seg]) return '/' + pathname.split('/').slice(2).join('/');
  return pathname;
}

// ── Health aggregator (cached 30s) ──────────────────────────────────────────
let cache = { ts: 0, data: null };

function fetchOne(name, url) {
  return new Promise(resolve => {
    const r = https.get(url + '/health', { timeout: 5000 }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ name, ok: true, ...JSON.parse(d) }); }
        catch  { resolve({ name, ok: false }); }
      });
    });
    r.on('error',   () => resolve({ name, ok: false }));
    r.on('timeout', () => { r.destroy(); resolve({ name, ok: false }); });
  });
}

async function getHealth() {
  if (cache.data && Date.now() - cache.ts < 30000) return cache.data;
  const relays = await Promise.all(Object.entries(RELAYS).map(([n, u]) => fetchOne(n, u)));
  cache = {
    ts: Date.now(),
    data: {
      status: 'ok', version: '1.1.0', role: 'edge-gateway',
      region: process.env.FLY_REGION || 'local',
      uptime_s: Math.floor(process.uptime()),
      origin: 'hetzner', // pure proxy — all data on Hetzner
      relays,
      online:  relays.filter(r => r.ok).length,
      total:   relays.length,
      all_ok:  relays.every(r => r.ok),
    }
  };
  return cache.data;
}

// ── HTTP proxy (REST + SSE) ──────────────────────────────────────────────────
function proxyHttp(target, req, res) {
  const u = new URL(target);
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const fwd = clientIp ? clientIp.split(',')[0].trim() : '';
  const headers = {
    ...req.headers,
    host: u.hostname,
    'x-forwarded-for': fwd || clientIp,
    'x-forwarded-proto': 'https',
    'x-edge': process.env.FLY_REGION || 'fly',
  };
  delete headers['transfer-encoding']; // avoid chunked confusion
  const opts = { hostname: u.hostname, path: u.pathname + (u.search || ''),
    method: req.method, headers };
  const p = https.request(opts, pr => {
    res.writeHead(pr.statusCode,
      { ...pr.headers, 'x-edge-region': process.env.FLY_REGION || 'fly' });
    pr.pipe(res);
  });
  p.on('error', e => {
    if (!res.headersSent) { res.writeHead(502); }
    res.end(JSON.stringify({ error: 'upstream error', detail: e.message }));
  });
  req.pipe(p);
}

// ── WebSocket proxy (CONNECT tunnel) ────────────────────────────────────────
function proxyWs(target, req, socket, head) {
  const u = new URL(target);
  const port = u.port || 443;
  const upstream = net.createConnection(port, u.hostname, () => {
    const hs = [
      `GET ${u.pathname}${u.search || ''} HTTP/1.1`,
      `Host: ${u.hostname}`,
      `Upgrade: websocket`,
      `Connection: Upgrade`,
      ...Object.entries(req.headers)
        .filter(([k]) => !['host','connection','upgrade'].includes(k.toLowerCase()))
        .map(([k, v]) => `${k}: ${v}`),
      '', '',
    ].join('\r\n');
    upstream.write(hs);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error',   () => upstream.destroy());
}

// ── HTTP server ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin',
    req.headers.origin || 'https://paramant.app');
  res.setHeader('access-control-allow-headers',
    'x-api-key, content-type, x-dsa-signature, authorization, x-did, x-did-signature');
  res.setHeader('access-control-allow-methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, 'http://x');
  const p   = url.pathname;

  if (p === '/health' || p === '/') {
    const d = await getHealth();
    res.setHeader('content-type', 'application/json');
    res.writeHead(d.all_ok ? 200 : 206);
    return res.end(JSON.stringify(d));
  }

  if (p === '/status') {
    const d = await getHealth();
    res.setHeader('content-type', 'application/json');
    res.writeHead(200);
    return res.end(JSON.stringify({
      online: `${d.online}/${d.total}`, region: d.region, origin: 'hetzner',
      relays: d.relays.map(r => ({ name: r.name, ok: r.ok, version: r.version }))
    }));
  }

  const relay  = pickRelay(req);
  const rest   = stripSector(p);
  proxyHttp(relay + rest + url.search, req, res);
});

// WebSocket upgrade → TLS tunnel to Hetzner
server.on('upgrade', (req, socket, head) => {
  const url   = new URL(req.url, 'http://x');
  const relay = pickRelay(req);
  const rest  = stripSector(url.pathname);
  proxyWs(relay + rest + url.search, req, socket, head);
});

server.listen(PORT, () =>
  console.log(`PARAMANT edge-gateway v1.1.0 — port ${PORT} — ${process.env.FLY_REGION || 'local'} → hetzner`));

process.on('SIGTERM', () => process.exit(0));
