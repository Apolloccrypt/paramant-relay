// deploy/ops/restore-full-state.sh and backup-full-state.sh, without root, a
// server or a real age: `age` is a stub on PATH that records its arguments and
// passes the bytes through, so what is tested is the scripts' own logic.
//
// restore --inspect used to reset its EXIT trap and leave the whole decrypted
// bundle (relay private keys, redis) in a mktemp dir under /tmp. It now always
// removes it, unless the operator names a directory with --extract-to.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RESTORE = path.join(ROOT, 'deploy/ops/restore-full-state.sh');
const BACKUP = path.join(ROOT, 'deploy/ops/backup-full-state.sh');

function scratch(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ops-${tag}-`));
}

// A fake `age`: -d passes the input through, -r/-R encryption copies input to
// -o. Every call is appended to $AGE_LOG so a test can read the recipients.
function stubAge(dir) {
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'age'), `#!/usr/bin/env bash
echo "$@" >> "$AGE_LOG"
out=""; args=("$@"); last="\${args[-1]}"
for ((i=0;i<\${#args[@]};i++)); do [[ "\${args[$i]}" == "-o" ]] && out="\${args[$((i+1))]}"; done
if [[ -n "$out" ]]; then cat "$last" > "$out"; else cat "$last"; fi
`, { mode: 0o755 });
  return bin;
}

function sha(p) { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }

// A bundle in the layout backup-full-state.sh writes.
function makeBundle(dir, { corrupt = false } = {}) {
  const name = 'paramant-full-20260923-033000';
  const stage = path.join(dir, 'stage', name);
  fs.mkdirSync(path.join(stage, 'relay', 'main'), { recursive: true });
  const id = path.join(stage, 'relay', 'main', 'relay-identity.json');
  fs.writeFileSync(id, '{"sk":"SECRET","pk":"PUB"}');
  const h = corrupt ? '0'.repeat(64) : sha(id);
  fs.writeFileSync(path.join(stage, 'MANIFEST.txt'),
    `# Paramant full-state backup manifest\ntimestamp:   20260923-033000\n${h}  27  relay/main/relay-identity.json\n`);
  const out = path.join(dir, `${name}.tar.gz.age`);
  const r = spawnSync('tar', ['-C', path.join(dir, 'stage'), '-czf', out, name]);
  assert.equal(r.status, 0);
  fs.rmSync(path.join(dir, 'stage'), { recursive: true });
  return out;
}

function runRestore(dir, args) {
  const bin = stubAge(dir);
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(tmp);
  const key = path.join(dir, 'key.txt');
  fs.writeFileSync(key, '# public key: age1test\nAGE-SECRET-KEY-TEST\n');
  const childEnv = { ...process.env, TMPDIR: tmp, KEYFILE: key, AGE_LOG: path.join(dir, 'age.log') };
  childEnv.PATH = `${bin}${path.delimiter}${childEnv.PATH}`;
  const r = spawnSync('bash', [RESTORE, ...args], {
    env: childEnv,
    encoding: 'utf8',
  });
  return { ...r, tmp };
}

test('restore --inspect verifies the bundle and leaves nothing decrypted behind', () => {
  const dir = scratch('inspect');
  try {
    const bundle = makeBundle(dir);
    const r = runRestore(dir, ['--from', bundle, '--inspect']);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /all hashes match/);
    assert.match(r.stdout, /removed now/);
    assert.deepEqual(fs.readdirSync(r.tmp), [], 'the temp dir is empty after --inspect');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('restore --inspect on a bundle that fails its manifest also cleans up', () => {
  const dir = scratch('inspect-bad');
  try {
    const bundle = makeBundle(dir, { corrupt: true });
    const r = runRestore(dir, ['--from', bundle, '--inspect']);
    assert.notEqual(r.status, 0);
    assert.match(r.stdout + r.stderr, /MISMATCH/);
    assert.deepEqual(fs.readdirSync(r.tmp), []);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('restore --inspect --extract-to keeps the bundle there, 0700, and says so loudly', () => {
  const dir = scratch('extract');
  try {
    const bundle = makeBundle(dir);
    const keep = path.join(dir, 'keep');
    const r = runRestore(dir, ['--from', bundle, '--inspect', '--extract-to', keep]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /KEPT at/);
    assert.ok(fs.existsSync(path.join(keep, 'paramant-full-20260923-033000', 'relay', 'main', 'relay-identity.json')));
    assert.equal(fs.statSync(keep).mode & 0o777, 0o700);
    assert.deepEqual(fs.readdirSync(r.tmp), [], 'nothing in the temp dir either');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('restore --extract-to refuses a directory that is not empty, and --confirm', () => {
  const dir = scratch('extract-refuse');
  try {
    const bundle = makeBundle(dir);
    const keep = path.join(dir, 'keep');
    fs.mkdirSync(keep);
    fs.writeFileSync(path.join(keep, 'x'), 'x');
    const r = runRestore(dir, ['--from', bundle, '--inspect', '--extract-to', keep]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not an empty directory/);
    const dir2 = scratch('extract-confirm');
    try {
      const b2 = makeBundle(dir2);
      const r2 = runRestore(dir2, ['--from', b2, '--confirm', '--extract-to', path.join(dir2, 'k')]);
      assert.notEqual(r2.status, 0);
      assert.match(r2.stderr, /only goes with --inspect/);
    } finally { fs.rmSync(dir2, { recursive: true, force: true }); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── backup-full-state.sh ──────────────────────────────────────────────────────

function runBackup(dir, args, env = {}) {
  return spawnSync('bash', [BACKUP, ...args], {
    env: { ...process.env, LOG: '/dev/null', ...env },
    encoding: 'utf8',
  });
}

test('backup --recipients: the server key plus every line of the recipients file', () => {
  const dir = scratch('recip');
  try {
    const key = path.join(dir, 'key.txt');
    fs.writeFileSync(key, '# created: 2026-09-23\n# public key: age1serverkey\nAGE-SECRET-KEY-X\n');
    const rec = path.join(dir, 'recipients.txt');
    fs.writeFileSync(rec, '# offline escrow key, on paper with the owner\nage1escrowkey\n\nage1secondoffline\n');
    const r = runBackup(dir, ['--recipients'], { KEYFILE: key, RECIPIENTS_FILE: rec });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /recipient: age1serverkey/);
    assert.match(r.stdout, /recipient: age1escrowkey/);
    assert.match(r.stdout, /recipient: age1secondoffline/);
    assert.match(r.stdout, /recipients: 3/);
    assert.doesNotMatch(r.stdout, /AGE-SECRET-KEY/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('backup --recipients: one key only is allowed but warns about the missing escrow key', () => {
  const dir = scratch('recip-one');
  try {
    const key = path.join(dir, 'key.txt');
    fs.writeFileSync(key, '# public key: age1serverkey\nAGE-SECRET-KEY-X\n');
    const r = runBackup(dir, ['--recipients'], { KEYFILE: key, RECIPIENTS_FILE: path.join(dir, 'none.txt') });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /recipients: 1/);
    assert.match(r.stdout, /only one recipient/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('backup --recipients: no key anywhere is a hard error', () => {
  const dir = scratch('recip-none');
  try {
    const r = runBackup(dir, ['--recipients'], {
      KEYFILE: path.join(dir, 'nokey.txt'), RECIPIENTS_FILE: path.join(dir, 'none.txt'),
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /no recipients/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('backup --dry-run takes the host paths that exist and names the ones that do not', () => {
  const dir = scratch('host');
  try {
    const relay = path.join(dir, 'relaydata');
    fs.mkdirSync(relay);
    fs.writeFileSync(path.join(relay, 'relay-identity.json'), '{}');
    const envFile = path.join(dir, 'opt', '.env');
    fs.mkdirSync(path.dirname(envFile), { recursive: true });
    fs.writeFileSync(envFile, 'NAME=value\n');
    const nginx = path.join(dir, 'etc', 'nginx');
    fs.mkdirSync(path.join(nginx, 'sites-enabled'), { recursive: true });
    fs.writeFileSync(path.join(nginx, 'sites-enabled', 'a.conf'), 'server {}\n');
    const absent = path.join(dir, 'etc', 'caddy');
    const out = path.join(dir, 'out');
    const r = runBackup(dir, ['--dry-run'], {
      PARAMANT_BACKUP_SOURCES: `main\t${relay}`,
      REDIS_SRC_DIR: path.join(dir, 'noredis'),
      PARAMANT_BACKUP_HOST_PATHS: `${envFile} ${nginx} ${absent}`,
      DRYRUN_OUT: out,
    });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, new RegExp(`host ${absent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: absent`));
    const manifest = fs.readdirSync(out).find((f) => f.endsWith('MANIFEST.txt'));
    const text = fs.readFileSync(path.join(out, manifest), 'utf8');
    assert.match(text, new RegExp(`host${envFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
    assert.match(text, /host\/.*etc\/nginx\/sites-enabled\/a\.conf$/m);
    assert.match(text, /^relay\/main\/relay-identity\.json$|relay\/main\/relay-identity\.json$/m);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the systemd timer runs the backup daily at 03:30 UTC and catches up after downtime', () => {
  const timer = fs.readFileSync(path.join(ROOT, 'deploy/systemd/paramant-backup.timer'), 'utf8');
  const svc = fs.readFileSync(path.join(ROOT, 'deploy/systemd/paramant-backup.service'), 'utf8');
  assert.match(timer, /^OnCalendar=\*-\*-\* 03:30:00 UTC$/m);
  assert.match(timer, /^Persistent=true$/m);
  assert.match(timer, /^Unit=paramant-backup\.service$/m);
  assert.match(timer, /^WantedBy=timers\.target$/m);
  assert.match(svc, /^Type=oneshot$/m);
  assert.match(svc, /^ExecStart=.*\/opt\/paramant-relay\/deploy\/ops\/backup-full-state\.sh$/m);
});
