// The whole site conf, rendered the way deploy-3.1.sh phase 5e places it, in a
// real nginx. Prodtest 2026-10-05 found production ~600 lines behind
// deploy/nginx-paramant-live.conf, because phase 5c only ever applied seven
// edits by anchor. Two of the missing lines were visible to every visitor:
//   - /api/user/ sat on relay_auth (a login brake), so one /account load got 429
//   - /parashare?t= went to the login page and lost its token
// Phase 5e now copies the rendered conf whole. This suite boots exactly that
// render (deploy/nginx-render.sh, production defaults) with the tracked
// limit_req and security-header snippets, and holds both behaviours plus the
// strict zones on the login doors.
//
// Layout in the container, the same as on the server: a front server stands in
// for Caddy (it forwards Host and X-Forwarded-For to 127.0.0.1:8080, which is
// also the only address the vhost listens on), and an echo server on
// 127.0.0.1:4200 stands in for admin: 401 on the session probe, 200 elsewhere.
//
// Needs docker (nginx:alpine). Without docker the suite skips; the static half
// is tests/nginx-user-limits.test.mjs and the 5e gate in deploy-3.1.sh.
// Run: node --test tests/nginx-volledig-docker.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

function dockerOk() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 15000 }); return true; } catch { return false; }
}

// One request, no redirect following, Host set by hand.
function req(port, p, { method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: p, method, headers: { Host: 'paramant.app' }, agent: false }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location || '' }));
    });
    r.on('error', reject);
    r.setTimeout(10000, () => r.destroy(new Error('timeout ' + p)));
    r.end();
  });
}

const rendered = execFileSync('bash', [path.join(ROOT, 'deploy/nginx-render.sh')], { encoding: 'utf8' });

test('the render for production is the repo conf byte for byte', () => {
  assert.equal(rendered, read('deploy/nginx-paramant-live.conf'),
    'with the production defaults deploy/nginx-render.sh must change nothing, or the server and git drift by design');
});

test('the rendered site conf passes nginx -t and keeps the token, the session zone and the strict doors', { skip: !dockerOk() && 'docker not available', timeout: 240000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-5e-'));
  const name = 'paramant-5e-' + crypto.randomBytes(4).toString('hex');
  t.after(() => {
    spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' });
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const w = (rel, body) => {
    const f = path.join(dir, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o755 });
    fs.writeFileSync(f, body);
    fs.chmodSync(f, 0o644);
  };
  fs.chmodSync(dir, 0o755);
  w('conf/site.conf', rendered);
  w('conf/limit.conf', read('deploy/nginx/snippets/paramant-limit-req.conf'));
  w('snippets/paramant-security-headers.conf', read('deploy/nginx/snippets/paramant-security-headers.conf'));
  for (const p of ['index.html', 'parashare.html', 'get.html', 'en/index.html', 'en/parashare.html', 'en/get.html', '404.html', 'en/404.html']) w('app/' + p, `<p>${p}</p>\n`);
  w('legal/index.html', '<p>legal</p>\n');
  w('conf/nginx.conf', `events {}
http {
  include /etc/nginx/mime.types;
  include /etc/nginx/v/limit.conf;
  include /etc/nginx/v/site.conf;
  # Caddy stand-in: the only door from outside, as on the server.
  server {
    listen 8099;
    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_redirect off;
    }
  }
  # admin stand-in.
  server {
    listen 127.0.0.1:4200;
    location = /admin/api/user/check { return 401; }
    location / { default_type text/plain; return 200 "echo $request_uri\\n"; }
  }
}
`);
  for (const d of ['conf', 'snippets', 'app', 'app/en', 'legal']) fs.chmodSync(path.join(dir, d), 0o755);

  // nginx.conf where the server has it: a relative include (the snippet) is
  // resolved against the directory of the main conf, /etc/nginx.
  const mounts = ['-v', `${dir}/conf:/etc/nginx/v:ro,z`, '-v', `${dir}/conf/nginx.conf:/etc/nginx/nginx.conf:ro,z`,
    '-v', `${dir}/snippets/paramant-security-headers.conf:/etc/nginx/snippets/paramant-security-headers.conf:ro,z`,
    '-v', `${dir}/app:/home/paramant/app:ro,z`, '-v', `${dir}/legal:/home/paramant/app-legal:ro,z`];

  // 1. nginx -t on exactly what 5e writes.
  const syntax = spawnSync('docker', ['run', '--rm', ...mounts, 'nginx:alpine', 'nginx', '-t'], { encoding: 'utf8', timeout: 120000 });
  assert.equal(syntax.status, 0, `nginx -t refused the rendered conf:\n${syntax.stderr}`);
  assert.match(syntax.stderr, /syntax is ok/);

  execFileSync('docker', ['run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8099', ...mounts,
    'nginx:alpine', 'nginx', '-g', 'daemon off;'], { stdio: 'pipe', timeout: 120000 });
  const port = Number(execFileSync('docker', ['port', name, '8099/tcp'], { encoding: 'utf8' }).trim().split('\n')[0].split(':').pop());
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try { await req(port, '/'); up = true; } catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  assert.ok(up, `nginx did not come up:\n${spawnSync('docker', ['logs', name], { encoding: 'utf8' }).stderr}`);

  // 2. The add-in link keeps its token: straight to /get, never to the login page.
  const share = await req(port, '/parashare?t=abc123');
  assert.equal(share.status, 302);
  assert.equal(share.location, 'https://paramant.app/get?t=abc123', '/parashare?t= must hand the token to /get');
  const shareEn = await req(port, '/en/parashare?t=abc123');
  assert.equal(shareEn.status, 302);
  assert.equal(shareEn.location, 'https://paramant.app/en/get?t=abc123', '/en/parashare?t= must hand the token to /en/get');
  // Without a token the send page stays behind the session gate.
  const gated = await req(port, '/parashare');
  assert.equal(gated.status, 302);
  assert.equal(gated.location, 'https://paramant.app/auth/login?next=/parashare');

  // 3. One /account load fires about nine /api/user/ calls; three pages at once
  //    more. Twelve in parallel is the prodtest: 6 x 429 on relay_auth.
  const me = await Promise.all(Array.from({ length: 12 }, () => req(port, '/api/user/me').then((r) => r.status)));
  assert.deepEqual(me.filter((s) => s === 429), [], `12 parallel /api/user/me got 429: ${me.join(' ')}`);
  assert.ok(me.every((s) => s === 200), `the echo upstream should answer every /api/user/me: ${me.join(' ')}`);

  // 4. The login doors keep their brakes. relay_auth is burst 5, relay_login
  //    burst 30: past that, one address gets 429.
  const auth = await Promise.all(Array.from({ length: 12 }, () => req(port, '/api/user/auth/totp', { method: 'POST' }).then((r) => r.status)));
  assert.ok(auth.filter((s) => s === 429).length >= 5, `/api/user/auth/ is no longer on its strict zone: ${auth.join(' ')}`);
  const login = await Promise.all(Array.from({ length: 45 }, () => req(port, '/api/user/login', { method: 'POST' }).then((r) => r.status)));
  assert.ok(login.filter((s) => s === 429).length >= 10, `/api/user/login is no longer on its strict zone: ${login.join(' ')}`);
  const signup = await Promise.all(Array.from({ length: 12 }, () => req(port, '/api/user/signup', { method: 'POST' }).then((r) => r.status)));
  assert.ok(signup.some((s) => s === 429), `/api/user/signup is no longer on its strict zone: ${signup.join(' ')}`);
});
