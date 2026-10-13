// Review #555, H1: the user_session limiter on /api/user/ was keyed on the
// paramant_user_session cookie. A random cookie per request was a fresh
// bucket, and "junk; real" (nginx reads the first, admin the last) was signed
// in and unlimited. This suite boots the real snippet in a real nginx and
// tries both tricks from one address: the limit must still bite.
//
// Needs docker (the nginx:alpine image). Without docker the suite skips; the
// static half of the lock is tests/nginx-user-limits.test.mjs.
// Run: node --test tests/nginx-user-session-omzeiling.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

function dockerOk() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 15000 }); return true; } catch { return false; }
}

// The limit_req line of the live /api/user/ block, as written there.
function liveUserLimit() {
  const conf = read('deploy/nginx-paramant-live.conf');
  const m = /location \/api\/user\/ \{([\s\S]*?)\n\s*\}/.exec(conf);
  assert.ok(m, 'no /api/user/ block in the live conf');
  const lr = /limit_req\s+zone=user_session[^;]*;/.exec(m[1]);
  assert.ok(lr, 'the /api/user/ block sets no user_session limit');
  return lr[0];
}

test('a random or duplicated session cookie does not escape the /api/user/ limit', { skip: !dockerOk() && 'docker not available', timeout: 180000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-h1-'));
  fs.chmodSync(dir, 0o755);
  fs.writeFileSync(path.join(dir, 'limit.conf'), read('deploy/nginx/snippets/paramant-limit-req.conf'));
  fs.writeFileSync(path.join(dir, 'nginx.conf'), `events {}
http {
  include /etc/nginx/h1/limit.conf;
  server {
    listen 8099;
    location /api/user/ {
      ${liveUserLimit()}
      limit_req_status 429;
      # Content phase on purpose: a "return" runs in the rewrite phase,
      # before limit_req, and would never be limited.
      root /usr/share/nginx/html;
    }
  }
}
`);
  for (const f of ['limit.conf', 'nginx.conf']) fs.chmodSync(path.join(dir, f), 0o644);
  const name = 'paramant-h1-' + crypto.randomBytes(4).toString('hex');
  try {
    execFileSync('docker', ['run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8099',
      '-v', `${dir}:/etc/nginx/h1:ro,z`, 'nginx:alpine', 'nginx', '-g', 'daemon off;', '-c', '/etc/nginx/h1/nginx.conf'], { stdio: 'pipe', timeout: 120000 });
    const port = execFileSync('docker', ['port', name, '8099/tcp'], { encoding: 'utf8' }).trim().split('\n')[0].split(':').pop();
    const url = `http://127.0.0.1:${port}/api/user/account`;
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try { await fetch(url, { headers: { Cookie: 'paramant_user_session=probe' + i } }); up = true; } catch { await new Promise((r) => setTimeout(r, 200)); }
    }
    assert.ok(up, 'nginx did not come up');
    // Two hundred requests from one address, each with a different cookie,
    // half of them with a junk cookie in front of a "real" one.
    const reqs = Array.from({ length: 200 }, (_, i) => {
      const junk = 'J' + crypto.randomBytes(8).toString('hex');
      const cookie = i % 2 ? `paramant_user_session=${junk}; paramant_user_session=REAL` : `paramant_user_session=${junk}`;
      return fetch(url, { headers: { Cookie: cookie } }).then((r) => r.status);
    });
    const statuses = await Promise.all(reqs);
    const limited = statuses.filter((s) => s === 429).length;
    assert.ok(limited >= 30, `only ${limited} of 200 requests with fresh cookies were limited: the key follows the cookie`);
  } finally {
    try { execFileSync('docker', ['rm', '-f', name], { stdio: 'pipe' }); } catch { /* gone */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
