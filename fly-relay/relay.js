'use strict';
const http  = require('http');
const https = require('https');
const net   = require('net');
const PORT  = process.env.PORT || 8080;

const RELAYS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};

function pickRelay(req) {
  const host = (req.headers.host || '').toLowerCase();
  for (const s of Object.keys(RELAYS)) { if (host.startsWith(s + '.')) return RELAYS[s]; }
  const seg = (req.url || '/').split('/')[1];
  return RELAYS[seg] || RELAYS.health;
}

function stripSector(pathname) {
  const seg = pathname.split('/')[1];
  return RELAYS[seg] ? '/' + pathname.split('/').slice(2).join('/') : pathname;
}

let cache = { ts: 0, data: null };

function fetchOne(name, url) {
  return new Promise(resolve => {
    const r = https.get(url + '/health', { timeout: 5000 }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve({ name, ok: true, ...JSON.parse(d) }); } catch { resolve({ name, ok: false }); } });
    });
    r.on('error',   () => resolve({ name, ok: false }));
    r.on('timeout', () => { r.destroy(); resolve({ name, ok: false }); });
  });
}

async function getHealth() {
  if (cache.data && Date.now() - cache.ts < 30000) return cache.data;
  const relays = await Promise.all(Object.entries(RELAYS).map(([n, u]) => fetchOne(n, u)));
  cache = { ts: Date.now(), data: {
    status: 'ok', version: '1.1.0', role: 'edge-gateway',
    region: process.env.FLY_REGION || 'local', uptime_s: Math.floor(process.uptime()),
    origin: 'hetzner', relays,
    online: relays.filter(r => r.ok).length, total: relays.length, all_ok: relays.every(r => r.ok),
  }};
  return cache.data;
}

function proxyHttp(target, req, res) {
  const u = new URL(target);
  const fwd = ((req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0]).trim();
  const headers = { ...req.headers, host: u.hostname, 'x-forwarded-for': fwd, 'x-forwarded-proto': 'https', 'x-edge': process.env.FLY_REGION || 'fly' };
  delete headers['transfer-encoding'];
  const opts = { hostname: u.hostname, path: u.pathname + (u.search || ''), method: req.method, headers };
  const p = https.request(opts, pr => {
    res.writeHead(pr.statusCode, { ...pr.headers, 'x-edge-region': process.env.FLY_REGION || 'fly' });
    pr.pipe(res);
  });
  p.on('error', e => { if (!res.headersSent) res.writeHead(502); res.end(JSON.stringify({ error: 'upstream error', detail: e.message })); });
  req.pipe(p);
}

function proxyWs(target, req, socket, head) {
  const u = new URL(target);
  const upstream = net.createConnection(u.port || 443, u.hostname, () => {
    const hs = [
      `GET ${u.pathname}${u.search || ''} HTTP/1.1`, `Host: ${u.hostname}`,
      `Upgrade: websocket`, `Connection: Upgrade`,
      ...Object.entries(req.headers).filter(([k]) => !['host','connection','upgrade'].includes(k.toLowerCase())).map(([k, v]) => `${k}: ${v}`),
      '', '',
    ].join('\r\n');
    upstream.write(hs);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream); upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error',   () => upstream.destroy());
}

const server = http.createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', req.headers.origin || 'https://paramant.app');
  res.setHeader('access-control-allow-headers', 'x-api-key, content-type, x-dsa-signature, authorization, x-did, x-did-signature');
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
    res.setHeader('content-type', 'application/json'); res.writeHead(200);
    return res.end(JSON.stringify({ online: `${d.online}/${d.total}`, region: d.region, origin: 'hetzner', relays: d.relays.map(r => ({ name: r.name, ok: r.ok, version: r.version })) }));
  }
  proxyHttp(pickRelay(req) + stripSector(p) + url.search, req, res);
});

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  proxyWs(pickRelay(req) + stripSector(url.pathname) + url.search, req, socket, head);
});

server.listen(PORT, () => console.log(`PARAMANT edge-gateway v1.1.0 — port ${PORT} — ${process.env.FLY_REGION || 'local'} → hetzner`));
process.on('SIGTERM', () => process.exit(0));
