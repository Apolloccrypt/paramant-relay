'use strict';
// Optional static frontend serving for plug-and-play self-host installs.
// Off by default: production serves frontend/ via nginx. When SERVE_FRONTEND=true,
// the relay serves frontend assets (/setup, /dashboard, ...) for non-API GET/HEAD
// requests. Read-only: never writes to disk, never intercepts API paths.
//
// Factored into a module (injected config + logger) so the routing and the
// path-traversal guard are unit-testable without booting the relay.

const fs = require('fs');
const path = require('path');

const STATIC_MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
  '.woff': 'font/woff',
  '.txt':  'text/plain; charset=utf-8',
  '.wasm': 'application/wasm',
};

// API surfaces that must never be intercepted by static serving.
function isApiPath(urlPath) {
  return urlPath.startsWith('/v2/') || urlPath.startsWith('/api/') ||
         urlPath.startsWith('/ct/') || urlPath === '/ct' ||
         urlPath === '/health' || urlPath === '/metrics';
}

function createStaticHandler(opts) {
  opts = opts || {};
  const serveFrontend = opts.serveFrontend === true;
  const frontendRoot = path.resolve(opts.frontendRoot || '/app/frontend');
  const log = typeof opts.log === 'function' ? opts.log : function () {};

  // Returns true when the request is fully handled, false to fall through.
  function maybeServeStatic(req, res, urlPath) {
    if (!serveFrontend) return false;
    if (req.method !== 'GET' && req.method !== 'HEAD') return false;
    if (isApiPath(urlPath)) return false;

    // Path-traversal / null-byte guard.
    if (urlPath.indexOf('..') !== -1 || urlPath.indexOf('\0') !== -1) {
      res.writeHead(400, { 'Content-Type': 'text/plain' }); res.end('bad request');
      return true;
    }

    // Map URL -> candidate file under frontendRoot.
    let filePath;
    if (urlPath === '/' || urlPath === '') {
      filePath = path.join(frontendRoot, 'index.html');
    } else if (urlPath.endsWith('/')) {
      filePath = path.join(frontendRoot, urlPath, 'index.html');
    } else {
      filePath = path.join(frontendRoot, urlPath);
      // Extensionless pretty path: try <name>.html (so /setup -> setup.html).
      if (!path.extname(filePath)) {
        const candidate = filePath + '.html';
        try { if (fs.statSync(candidate).isFile()) filePath = candidate; } catch (e) { /* no sibling */ }
      }
    }

    // Confirm the resolved path stays inside frontendRoot.
    const resolved = path.resolve(filePath);
    if (resolved !== frontendRoot && !resolved.startsWith(frontendRoot + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' }); res.end('forbidden');
      return true;
    }

    let stat;
    try { stat = fs.statSync(resolved); } catch (e) { return false; } // not found -> normal 404
    if (!stat.isFile()) return false;

    const ext = path.extname(resolved).toLowerCase();
    const mime = STATIC_MIME[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': stat.size,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
      'X-Content-Type-Options': 'nosniff',
    });
    if (req.method === 'HEAD') { res.end(); return true; }
    fs.createReadStream(resolved).pipe(res);
    log('debug', 'static_served', { path: urlPath, mime });
    return true;
  }

  return { maybeServeStatic, serveFrontend, frontendRoot, STATIC_MIME };
}

module.exports = { createStaticHandler, STATIC_MIME, isApiPath };
