'use strict';
// The relay identity (ML-DSA-65 keypair) is only ever generated when the file
// does not exist. A file that exists but cannot be read or parsed is an
// identity this relay HAD; replacing it would change the key every receipt and
// signed head was issued under and overwrite the only copy. The relay must stop
// with a loud log line and leave the file as it found it.

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireEngine } = require('./_requires');

const engineOk = requireEngine();

after(killAll);

function scratch(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `relay-ident-${tag}-`));
}

test('a missing identity file is created, and the next boot loads the same key', { skip: !engineOk }, async () => {
  const dir = scratch('enoent');
  try {
    const file = path.join(dir, 'relay-identity.json');
    assert.equal(fs.existsSync(file), false);
    const a = await boot({ dir, captureLog: true });
    assert.match(a.log(), /"msg":"relay_identity_created"/);
    const first = fs.readFileSync(file, 'utf8');
    assert.ok(JSON.parse(first).pk, 'identity file holds a public key');
    await killAll();

    const b = await boot({ dir, captureLog: true });
    assert.match(b.log(), /"msg":"relay_identity_loaded"/);
    assert.doesNotMatch(b.log(), /relay_identity_created/);
    assert.equal(fs.readFileSync(file, 'utf8'), first, 'the key did not change across a restart');
    await killAll();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt identity file stops the relay and is left untouched', { skip: !engineOk }, async () => {
  const dir = scratch('corrupt');
  try {
    const file = path.join(dir, 'relay-identity.json');
    const garbage = '{"sk":"AAAA","pk":';
    fs.writeFileSync(file, garbage, { mode: 0o600 });
    await assert.rejects(boot({ dir }), (e) => {
      assert.match(e.message, /exit=78/);
      assert.match(e.message, /relay_identity_unreadable/);
      return true;
    });
    assert.equal(fs.readFileSync(file, 'utf8'), garbage, 'the broken file was not overwritten');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

test('an unreadable identity file (EACCES) stops the relay and is left untouched',
  { skip: !engineOk || (isRoot && 'root reads any file, EACCES cannot be staged') }, async () => {
    const dir = scratch('eacces');
    const file = path.join(dir, 'relay-identity.json');
    try {
      const content = JSON.stringify({ sk: 'AAAA', pk: 'AAAA', created_at: '2026-01-01T00:00:00Z' });
      fs.writeFileSync(file, content, { mode: 0o600 });
      fs.chmodSync(file, 0o000);
      await assert.rejects(boot({ dir }), (e) => {
        assert.match(e.message, /exit=78/);
        assert.match(e.message, /EACCES/);
        return true;
      });
      fs.chmodSync(file, 0o600);
      assert.equal(fs.readFileSync(file, 'utf8'), content, 'the file was not overwritten');
    } finally {
      try { fs.chmodSync(file, 0o600); } catch (_) {}
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
