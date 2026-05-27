'use strict';
// Unit test for the opt-in static frontend handler (relay/lib/static-serve.js).
// Run: node relay/test/static-serve.test.js   (no deps, exits non-zero on failure)

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Writable } = require('stream');
const { createStaticHandler } = require('../lib/static-serve');

// -- temp frontend root with a couple of files --
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'paramant-static-'));
fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><title>home</title>');
fs.writeFileSync(path.join(root, 'setup.html'), '<!doctype html><title>setup</title>');
fs.writeFileSync(path.join(root, 'app.js'), 'console.log(1);');
// a file outside the root, to prove traversal cannot reach it
const secretDir = fs.mkdtempSync(path.join(os.tmpdir(), 'paramant-secret-'));
fs.writeFileSync(path.join(secretDir, 'secret.txt'), 'TOP SECRET');

function mockRes() {
  let body = '';
  const r = new Writable({ write(chunk, enc, cb) { body += chunk.toString(); cb(); } });
  r.statusCode = 0; r.headers = null;
  r.writeHead = function (code, headers) { r.statusCode = code; r.headers = headers || {}; return r; };
  r.getBody = function () { return body; };
  return r;
}

function req(method, urlPath) { return { method, url: urlPath }; }

let passed = 0;
function check(name, fn) { fn(); passed++; console.log('  ok -', name); }

// 1. Default off: serveFrontend=false never handles anything.
check('default off does not intercept', () => {
  const h = createStaticHandler({ serveFrontend: false, frontendRoot: root });
  const res = mockRes();
  assert.strictEqual(h.maybeServeStatic(req('GET', '/setup'), res, '/setup'), false);
  assert.strictEqual(res.statusCode, 0);
});

const on = createStaticHandler({ serveFrontend: true, frontendRoot: root });

// 2. API paths are never intercepted (even with serving on).
check('API paths fall through', () => {
  for (const p of ['/v2/setup/apply', '/v2/health/deep', '/api/x', '/ct/log', '/ct', '/health', '/metrics']) {
    const res = mockRes();
    assert.strictEqual(on.maybeServeStatic(req('GET', p), res, p), false, p);
    assert.strictEqual(res.statusCode, 0, p);
  }
});

// 3. Non-GET/HEAD never intercepted.
check('POST falls through', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('POST', '/setup'), res, '/setup'), false);
});

// 4. Pretty path /setup -> setup.html, 200 text/html, body piped.
check('/setup serves setup.html (GET) headers', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('GET', '/setup'), res, '/setup'), true);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
  assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
});

// 5. HEAD serves headers, no body.
check('HEAD /setup sets headers, empty body', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('HEAD', '/setup'), res, '/setup'), true);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.getBody(), '');
});

// 6. Root -> index.html.
check('/ serves index.html', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('HEAD', '/'), res, '/'), true);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
});

// 7. .js mime + cache header.
check('app.js served with js mime + cache', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('HEAD', '/app.js'), res, '/app.js'), true);
  assert.strictEqual(res.headers['Content-Type'], 'application/javascript; charset=utf-8');
  assert.strictEqual(res.headers['Cache-Control'], 'public, max-age=300');
});

// 8. Unknown path -> false (normal 404 fallthrough).
check('unknown path falls through to 404', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('GET', '/nope'), res, '/nope'), false);
  assert.strictEqual(res.statusCode, 0);
});

// 9. Traversal with ".." is rejected with 400, never reaches the secret.
check('traversal blocked (400)', () => {
  const res = mockRes();
  const handled = on.maybeServeStatic(req('GET', '/../../etc/passwd'), res, '/../../etc/passwd');
  assert.strictEqual(handled, true);
  assert.strictEqual(res.statusCode, 400);
  assert.ok(!res.getBody().includes('SECRET'));
});

// 10. Null byte rejected.
check('null byte blocked (400)', () => {
  const res = mockRes();
  assert.strictEqual(on.maybeServeStatic(req('GET', '/setup\0.html'), res, '/setup\0.html'), true);
  assert.strictEqual(res.statusCode, 400);
});

// 11. GET actually pipes the file body (async). Await before cleanup so the
//     read stream finishes before the temp dir is removed.
function getBody() {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    res.on('finish', () => resolve(res.getBody()));
    res.on('error', reject);
    const handled = on.maybeServeStatic(req('GET', '/setup'), res, '/setup');
    assert.strictEqual(handled, true);
  });
}

getBody()
  .then((body) => {
    assert.ok(body.includes('setup'), 'piped body should contain setup.html content');
    passed++;
    console.log('  ok - GET /setup pipes body');
  })
  .finally(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(secretDir, { recursive: true, force: true });
    console.log('\nstatic-serve: ' + passed + ' checks passed');
  });
