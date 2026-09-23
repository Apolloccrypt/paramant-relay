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
  const r = spawnSync('bash', [RESTORE, ...args], {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: tmp, KEYFILE: key, AGE_LOG: path.join(dir, 'age.log') },
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
