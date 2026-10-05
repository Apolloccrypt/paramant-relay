// Self-host docs and tools say what they do (fase-1 P10 SELF and P11 ADMIN).
//   SELF-04  deploy/preflight.sh said "All checks passed" on .env.example plus an
//            ADMIN_TOKEN: empty REDIS_PASSWORD, and redis then refuses to start.
//            The docs ran scripts/preflight.sh, which does not exist.
//   SELF-10  the docs' export line broke on MAIL_FROM=PARAMANT <noreply@...>.
//   SELF-14  the docs pointed at the root nginx-selfhost.conf; the tested
//            template is deploy/nginx-selfhost.conf.
//   SELF-19  .env.example left RELAY_SELF_URL_* commented out, so a self-host
//            made from it signed its proofs as a paramant.app host.
//   ADMIN-01-N  the docs promised an admin login with an enterprise pgp_ key;
//               the panel accepts ADMIN_TOKEN only.
//   ADMIN-09-N  the docs listed tabs Relay Monitor, API Keys, Licenses (plk_
//               generator); the panel has Overview, Users, Audit, Billing, Relay.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const docs = read('docs/self-hosting.md');
const example = read('.env.example');

// The host environment with a directory in front of its search path.
function withBin(bin, extra) {
  const e = { ...process.env, ...extra };
  e.PATH = bin + path.delimiter + (e.PATH || '');
  return e;
}

// A scratch dir with .env, and a fake docker on PATH so the check does not
// depend on the machine it runs on. Ports far from anything that listens.
function preflight(envText) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-'));
  const bin = path.join(dir, 'bin'); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'docker'),
    '#!/bin/sh\ncase "$1" in --version) echo "Docker version 29.0.0, build test";; compose) echo "2.40.0";; esac\nexit 0\n', { mode: 0o755 });
  fs.writeFileSync(path.join(dir, '.env'), envText);
  const r = spawnSync('bash', [path.join(ROOT, 'deploy/preflight.sh')], {
    cwd: dir, encoding: 'utf8', input: '',
    env: withBin(bin, { HOME: dir, HTTP_PORT: '47181', HTTPS_PORT: '47182' }),
  });
  fs.rmSync(dir, { recursive: true, force: true });
  return (r.stdout || '') + (r.stderr || '');
}

test('SELF-04 preflight: .env.example plus ADMIN_TOKEN is not "All checks passed"', () => {
  const out = preflight(example + '\nADMIN_TOKEN=' + 'a'.repeat(64) + '\n');
  assert.doesNotMatch(out, /All checks passed/, 'preflight called an .env without REDIS_PASSWORD ready');
  assert.match(out, /REDIS_PASSWORD not set/);
  assert.match(out, /Not your own public URL yet: RELAY_SELF_URL_MAIN/);
});

test('SELF-04 preflight: a complete .env passes', () => {
  const pw = 'b'.repeat(64);
  let env = example
    .replace(/^ADMIN_TOKEN=.*$/m, 'ADMIN_TOKEN=' + 'a'.repeat(64))
    .replace(/^REDIS_PASSWORD=.*$/m, 'REDIS_PASSWORD=' + pw)
    .replace(/^RELAY_REDIS_URL=.*$/m, `RELAY_REDIS_URL=redis://:${pw}@redis:6379`)
    .replace(/^PARAMANT_TOTP_MASTER_KEY=.*$/m, 'PARAMANT_TOTP_MASTER_KEY=' + Buffer.alloc(32, 1).toString('base64'))
    .replace(/^INTERNAL_AUTH_TOKEN=.*$/m, 'INTERNAL_AUTH_TOKEN=' + 'c'.repeat(64))
    .replace(/relay\.example\.org/g, 'relay.mijnbedrijf.nl');
  const out = preflight(env);
  assert.match(out, /All checks passed/, out.slice(-1500));
  env = env.replace(/^RELAY_REDIS_URL=.*$/m, 'RELAY_REDIS_URL=redis://:CHANGE_ME_TO_REDIS_PASSWORD@redis:6379');
  assert.doesNotMatch(preflight(env), /All checks passed/, 'a RELAY_REDIS_URL without the password passed');
});

test('SELF-04 the preflight command in the docs exists', () => {
  const cmds = [...docs.matchAll(/^bash ((?:scripts|deploy)\/preflight\.sh)$/gm)].map((m) => m[1]);
  assert.ok(cmds.length > 0, 'the docs name no preflight command');
  for (const c of cmds) assert.ok(fs.existsSync(path.join(ROOT, c)), `${c} (docs) does not exist`);
});

test('SELF-10 the docs export line works on an .env made from .env.example', () => {
  const block = docs.slice(docs.indexOf('### Add a user'), docs.indexOf('### List all keys'));
  const line = block.split('\n').find((l) => /^export /.test(l));
  assert.ok(line, 'no export line in "Add a user"');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'export-'));
  fs.writeFileSync(path.join(dir, '.env'), example.replace(/^ADMIN_TOKEN=.*$/m, 'ADMIN_TOKEN=tok123'));
  const r = spawnSync('bash', ['-c', `set -e; ${line}; printf %s "$ADMIN_TOKEN"`], { cwd: dir, encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stderr, '', 'the export line complained: ' + r.stderr);
  assert.strictEqual(r.stdout, 'tok123');
  // and the value that broke it is quoted, so a plain `set -a; . ./.env` works too
  const src = spawnSync('bash', ['-c', 'set -a; . ./.env.example; printf %s "$MAIL_FROM"'], { cwd: ROOT, encoding: 'utf8' });
  assert.strictEqual(src.stdout, 'PARAMANT <noreply@paramant.app>', src.stderr);
});

test('SELF-14 the docs point at the nginx template that is tested', () => {
  const refs = [...docs.matchAll(/`((?:deploy\/)?nginx-selfhost\.conf)` in the repo for a hardened/g)].map((m) => m[1]);
  assert.deepStrictEqual(refs, ['deploy/nginx-selfhost.conf']);
});

test('SELF-19 .env.example sets RELAY_SELF_URL_* to a placeholder, not left to the paramant.app default', () => {
  for (const s of ['MAIN', 'HEALTH', 'FINANCE', 'LEGAL', 'IOT']) {
    const m = example.match(new RegExp(`^RELAY_SELF_URL_${s}=(.+)$`, 'm'));
    assert.ok(m, `RELAY_SELF_URL_${s} is not set in .env.example`);
    assert.doesNotMatch(m[1], /paramant\.app/);
  }
});

test('ADMIN-01-N the docs do not promise an admin login with a pgp_ key', () => {
  const sec = docs.slice(docs.indexOf('### Admin Panel'), docs.indexOf('**Set up TOTP:**'));
  assert.ok(sec.length > 100);
  assert.doesNotMatch(sec, /or (an )?enterprise `?pgp_`? key/i);
  assert.match(sec, /ADMIN_TOKEN/);
  // and the code still says the same: only ADMIN_TOKEN logs in
  const server = read('admin/server.js');
  const login = server.slice(server.indexOf("api.post('/auth/login'"), server.indexOf("api.post('/auth/login'") + 4000);
  assert.match(login, /ADMIN_TOKEN/);
  assert.doesNotMatch(login, /startsWith\(['"]pgp_/);
});

test('ADMIN-09-N the docs list the tabs the panel has, and no license generator', () => {
  const sec = docs.slice(docs.indexOf('### Admin Panel'), docs.indexOf('**Set up TOTP:**'));
  const tabs = [...read('admin/public/index.html').matchAll(/data-tab="(\w+)"/g)].map((m) => m[1]);
  assert.ok(tabs.length >= 5);
  for (const t of tabs) assert.match(sec, new RegExp(`\\| ${t[0].toUpperCase() + t.slice(1)} \\|`), `tab ${t} is not in the docs`);
  for (const gone of ['| Relay Monitor |', '| API Keys |', '| Licenses |']) assert.ok(!sec.includes(gone), `docs still list ${gone}`);
  assert.match(sec, /does not generate relay licenses/);
});

test('ADMIN-16-N ADMIN.md names both bodies resend-setup takes', () => {
  const row = read('admin/ADMIN.md').split('\n').find((l) => l.includes('/admin/resend-setup'));
  assert.match(row, /\{ key \}/);
  assert.match(row, /\{ user_id, email \}/);
  const server = read('admin/server.js');
  assert.match(server.slice(server.indexOf("api.post('/admin/resend-setup'")).slice(0, 2500), /req\.body\.key/);
});

test('preflight.sh still parses', () => {
  execFileSync('bash', ['-n', path.join(ROOT, 'deploy/preflight.sh')]);
});
