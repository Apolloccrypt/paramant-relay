// Spoofed client headers must never reach a relay or the admin panel.
//
// Review of PR #546 (HOOG): deploy/nginx-selfhost.conf gave the two /admin/
// locations one `proxy_set_header X-Paramant-Client-IP ""`. nginx's rule for
// proxy_set_header is all-or-nothing per level: a location that sets ONE
// header inherits NONE from the server block. So X-Real-IP, Host,
// X-Forwarded-For and X-Forwarded-Proto silently fell away on /admin/, and a
// client-sent `X-Real-IP: 6.6.6.6` arrived at admin unchanged. The same had
// long been true for /health, /v2/inbound, /v2/pubkey, /v2/admin and /v2/mfa.
// tests/nginx-user-limits.test.mjs read the location text and stayed green.
//
// Two layers here:
//   1. static, every conf: a real nginx-conf parse with nginx's inheritance
//      rule, so a location is judged on the headers nginx actually sends;
//   2. live, the self-host conf: the file as shipped runs in an nginx:alpine
//      container in front of an echo upstream, and requests carrying spoofed
//      X-Real-IP / X-Forwarded-For / X-Internal-Auth / X-Paramant-Client-IP /
//      X-Verified-Email-Hash go to every proxying location. The upstream must
//      not see one of them. Skipped (not passed) when docker or openssl is
//      missing.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse, proxyLocations } from './helpers/nginx-conf.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// Upstreams that are the relay fleet or the admin panel. 8080 (static site),
// 8090 (imaging viewer) and the Fly proxy read no client address.
const RELAY_OR_ADMIN = /^http:\/\/(127\.0\.0\.1:(300[0-5]|4200)\b|\$relay_upstream$)/;

function problems(loc, { strict }) {
  const h = loc.headers;
  const out = [];
  if (h['x-real-ip'] !== '$remote_addr') out.push(`X-Real-IP ${h['x-real-ip'] === undefined ? 'not set: the client value passes through' : `= ${h['x-real-ip']}`}`);
  for (const k of ['x-internal-auth', 'x-paramant-client-ip', 'x-verified-email-hash']) {
    if (h[k] !== '') out.push(`${k} not blanked`);
  }
  const xff = h['x-forwarded-for'];
  if (xff !== undefined && xff !== '$remote_addr' && xff !== '') out.push(`X-Forwarded-For = ${xff} (appends the client value)`);
  if (strict) {
    if (xff !== '$remote_addr' && xff !== '') out.push('X-Forwarded-For not set');
    if (h.host !== '$host') out.push('Host not set to $host');
    if (h['x-forwarded-proto'] !== '$scheme') out.push('X-Forwarded-Proto not set');
  }
  return out;
}

const CONFS = [
  { file: 'deploy/nginx-selfhost.conf', strict: true },
  { file: 'deploy/nginx-paramant-live.conf', strict: false },
  { file: 'deploy/nginx-paramant-public.conf', strict: false },
];

for (const { file, strict, min = 8 } of CONFS) {
  test(`${file}: every relay/admin location sends the client address and blanks the trust headers`, () => {
    const locs = proxyLocations(parse(read(file))).filter((l) => RELAY_OR_ADMIN.test(l.proxyPass));
    assert.ok(locs.length >= min, `${file}: only ${locs.length} relay-facing locations found, the parser stopped matching`);
    const bad = locs.map((l) => [l, problems(l, { strict })]).filter(([, p]) => p.length)
      .map(([l, p]) => `  [${l.server}] ${l.label} -> ${l.proxyPass}: ${p.join('; ')}`);
    assert.deepEqual(bad, [], `headers a client can forge reach the upstream:\n${bad.join('\n')}`);
  });
}

test('the static check sees the inheritance trap (the PR #546 shape)', () => {
  const broken = `
server {
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Internal-Auth "";
  proxy_set_header X-Paramant-Client-IP "";
  proxy_set_header X-Verified-Email-Hash "";
  location /ok/ { proxy_pass http://127.0.0.1:4200/admin/; }
  location /admin/ { proxy_pass http://127.0.0.1:4200/admin/; proxy_set_header X-Paramant-Client-IP ""; }
}`;
  const locs = proxyLocations(parse(broken));
  const ok = locs.find((l) => l.location[0] === '/ok/');
  const adm = locs.find((l) => l.location[0] === '/admin/');
  assert.deepEqual(problems(ok, { strict: true }), [], 'a location without own headers inherits the server set');
  const p = problems(adm, { strict: true });
  assert.ok(p.some((s) => s.startsWith('X-Real-IP not set')), `the trap must be caught: ${p}`);
  assert.ok(p.includes('x-internal-auth not blanked'));
});

// ── Layer 2: the self-host conf, in a real nginx ─────────────────────────────

const SPOOF = {
  'X-Real-IP': '6.6.6.6',
  'X-Forwarded-For': '6.6.6.6',
  'X-Forwarded-Proto': 'gopher',
  'X-Internal-Auth': 'spoofed-internal-secret',
  'X-Paramant-Client-IP': '6.6.6.6',
  'X-Verified-Email-Hash': 'spoofed-hash',
};

// One request per proxying location of the self-host conf, in conf order.
const SAMPLES = [
  ['/health', '= /health'],
  ['/v2/inbound', '/v2/inbound'],
  ['/v2/pubkey', '~ ^/v2/(pubkey|did)'],
  ['/v2/admin/keys', '~ ^/v2/admin'],
  ['/v2/mfa', '= /v2/mfa'],
  ['/admin/api/user/login', '~ ^/admin/api/(auth/|user/(login|signup|setup/|auth/|account/totp/|account/backup-codes/))'],
  ['/admin/api/user/account', '/admin/'],
  ['/ct/feed', '~ ^/(ct|ct/feed|v2/sth)(/|$)'],
  ['/v2/sign-dpa', '= /v2/sign-dpa'],
  ['/v2/envelopes/x/owner-view', '/'],
];

// The echo upstream: every relay and admin port of the self-host conf, inside
// the same container, answering with the headers it received.
const ECHO = `
server {
  listen 127.0.0.1:3001; listen 127.0.0.1:3002; listen 127.0.0.1:3003; listen 127.0.0.1:3004; listen 127.0.0.1:4200;
  location / {
    default_type application/json;
    return 200 '{"host":"$http_host","xri":"$http_x_real_ip","xff":"$http_x_forwarded_for","xfp":"$http_x_forwarded_proto","xia":"$http_x_internal_auth","xpci":"$http_x_paramant_client_ip","xveh":"$http_x_verified_email_hash"}';
  }
}`;

// The bug, as a second server in the same container, so the harness proves it
// can go red: one header in the location drops the inherited set.
const TRAP = `
server {
  listen 8081;
  proxy_set_header X-Real-IP $remote_addr;
  location /admin/ { proxy_pass http://127.0.0.1:4200/admin/; proxy_set_header X-Paramant-Client-IP ""; }
}`;

function have(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: 'ignore', timeout: 20000 });
  return r.status === 0;
}

function get(port, uri, { tls = true } = {}) {
  return new Promise((resolve, reject) => {
    const mod = tls ? https : http;
    const req = mod.request({ host: '127.0.0.1', port, path: uri, method: 'GET', rejectUnauthorized: false,
      headers: { Host: 'paramant.selfhost.test', ...SPOOF } }, (res) => {
      let body = ''; res.on('data', (c) => { body += c; }); res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject); req.setTimeout(10000, () => req.destroy(new Error('timeout'))); req.end();
  });
}

const dockerOk = have('docker', ['info']) && have('openssl', ['version']);

test('self-host nginx in a container: no spoofed header reaches the upstream', { skip: dockerOk ? false : 'docker or openssl not available' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-hdr-'));
  const confd = path.join(dir, 'conf.d'); const certs = path.join(dir, 'certs');
  fs.mkdirSync(confd); fs.mkdirSync(certs);
  fs.writeFileSync(path.join(confd, 'paramant.conf'), read('deploy/nginx-selfhost.conf'));
  fs.writeFileSync(path.join(confd, 'zz-echo.conf'), ECHO + TRAP);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', path.join(certs, 'key.pem'), '-out', path.join(certs, 'cert.pem')], { stdio: 'ignore' });
  fs.chmodSync(path.join(certs, 'key.pem'), 0o644);
  for (const d of [dir, confd, certs]) fs.chmodSync(d, 0o755);

  const name = `ng-hdr-${process.pid}-${Date.now()}`;
  execFileSync('docker', ['run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::443', '-p', '127.0.0.1::8081',
    '-v', `${confd}:/etc/nginx/conf.d:ro`, '-v', `${certs}:/etc/nginx/certs:ro`, 'nginx:alpine'], { stdio: 'pipe' });
  t.after(() => { spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' }); fs.rmSync(dir, { recursive: true, force: true }); });

  const port = (p) => Number(execFileSync('docker', ['port', name, String(p)]).toString().trim().split('\n')[0].split(':').pop());
  const tlsPort = port(443); const trapPort = port(8081);

  // Wait for nginx to answer (a config error exits the container).
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try { await get(tlsPort, '/ct'); up = true; } catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  if (!up) {
    const logs = spawnSync('docker', ['logs', name], { encoding: 'utf8' });
    assert.fail(`nginx did not come up:\n${logs.stdout}${logs.stderr}`);
  }

  // Every proxying location is sampled once.
  const locs = proxyLocations(parse(read('deploy/nginx-selfhost.conf'))).filter((l) => l.listen.startsWith('443'));
  assert.deepEqual(SAMPLES.map(([, l]) => l).sort(), locs.map((l) => l.location.join(' ')).sort(),
    'SAMPLES must name every proxying location of the self-host conf, add one for the new location');

  const leaks = [];
  for (const [uri, label] of SAMPLES) {
    const r = await get(tlsPort, uri);
    assert.equal(r.status, 200, `${uri} (${label}): ${r.status} ${r.body.slice(0, 200)}`);
    const e = JSON.parse(r.body);
    if (e.xri === SPOOF['X-Real-IP'] || !e.xri) leaks.push(`${label}: X-Real-IP="${e.xri}"`);
    if (e.xff.includes('6.6.6.6') || !e.xff) leaks.push(`${label}: X-Forwarded-For="${e.xff}"`);
    if (e.xri && e.xff && e.xff !== e.xri) leaks.push(`${label}: X-Forwarded-For "${e.xff}" differs from X-Real-IP "${e.xri}"`);
    if (e.xfp !== 'https') leaks.push(`${label}: X-Forwarded-Proto="${e.xfp}"`);
    if (e.host !== 'paramant.selfhost.test') leaks.push(`${label}: Host="${e.host}"`);
    for (const k of ['xia', 'xpci', 'xveh']) if (e[k]) leaks.push(`${label}: ${k}="${e[k]}"`);
  }
  assert.deepEqual(leaks, [], `the upstream saw client-chosen headers:\n  ${leaks.join('\n  ')}`);

  // The harness goes red on the bug: same nginx, the PR #546 shape.
  const trap = JSON.parse((await get(trapPort, '/admin/x', { tls: false })).body);
  assert.equal(trap.xri, '6.6.6.6', 'the trap server must leak, or this harness cannot see the bug');
});
