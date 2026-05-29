'use strict';
// DEV-ONLY single-origin reverse proxy for local passkey testing (ADR R018).
// WebAuthn needs ONE secure origin; localhost counts as secure. This serves the
// website frontend/ and proxies /api/* -> admin and /v2,/ct -> relay, so the
// browser talks to exactly one origin (http://localhost:8080 by default).
// Dependency-free; reuses the project's own static handler. NOT for production
// (prod is nginx in front of the same services) -- touches nothing in deploy/.
const http = require('http');
const path = require('path');
const { createStaticHandler } = require('../relay/lib/static-serve');

const PORT     = parseInt(process.env.DEV_PORT || '8080', 10);
const ADMIN    = process.env.ADMIN_URL || 'http://127.0.0.1:4200';
const RELAY    = process.env.RELAY_URL || 'http://127.0.0.1:3001';
const FRONTEND = path.resolve(__dirname, '..', 'frontend');

const { maybeServeStatic } = createStaticHandler({ serveFrontend: true, frontendRoot: FRONTEND, log: () => {} });

function proxy(req, res, target) {
  const u = new URL(target);
  const upstream = http.request({
    hostname: u.hostname,
    port: u.port || 80,
    path: req.url,
    method: req.method,
    // Force a clean per-hop Host + a dev client IP (admin/relay read x-real-ip).
    headers: { ...req.headers, host: u.host, 'x-real-ip': '127.0.0.1' },
  }, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  upstream.on('error', (e) => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('dev-proxy upstream error (' + target + '): ' + e.message);
  });
  req.pipe(upstream);
}

http.createServer((req, res) => {
  const urlPath = (req.url.split('?')[0]) || '/';
  if (urlPath.startsWith('/api/')) return proxy(req, res, ADMIN);
  if (urlPath.startsWith('/v2/') || urlPath === '/ct' || urlPath.startsWith('/ct/')) return proxy(req, res, RELAY);

  // The token-bearing setup page is a clean URL (/auth/setup/<token>); the
  // static handler only maps extensionless paths to a sibling .html, so rewrite
  // it to the page file. The browser URL is unchanged, so the page still reads
  // its token from location.pathname.
  let staticPath = urlPath;
  if (/^\/auth\/setup\/[^/]+\/?$/.test(urlPath)) staticPath = '/auth/setup.html';

  if (maybeServeStatic(req, res, staticPath)) return;
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('dev-proxy: not found: ' + urlPath);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`[dev-proxy] http://localhost:${PORT}  (frontend=./frontend  /api->${ADMIN}  /v2->${RELAY})`);
});
