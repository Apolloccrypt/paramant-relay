'use strict';
// The CLI example on /docs works, also against your own relay (matrix
// API-36-A). The scripts took --relay only from the five hosted names, so the
// documented send/receive could never be run against a self-host, and /docs
// had to say "use the SDK instead". Now --relay also takes a URL.
//
// This boots the real relay.js and runs scripts/paramant-sender.py and
// scripts/paramant-receiver.py as /docs prints them, with --relay pointed at it.
// Run: node --test relay/test/cli-scripts-roundtrip.test.js
const { test, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_' + 'c'.repeat(64);
const SCRIPTS = path.join(__dirname, '..', '..', 'scripts');
let srv; let checks = 0;

before(async () => {
  srv = await boot({ tag: 'cli-roundtrip', users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'cli@example.test', account_id: 'acct_cli' }] } });
});
after(async () => { await killAll(); summary('cli-scripts-roundtrip', checks); });

const py = (script, args, opts = {}) => spawnSync('python3', [path.join(SCRIPTS, script), ...args], { encoding: 'utf8', timeout: 60_000, ...opts });

test('--relay takes the URL of your own relay, and refuses anything that is not one', () => {
  const bad = py('paramant-sender.py', ['--key', KEY, '--relay', 'http://evil.example', '--text', 'x']);
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /--relay: a sector/);
  checks++;
});

test('the /docs example: send a file, receive it by hash with the transfer secret', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-rt-'));
  const file = path.join(dir, 'scan.dcm');
  const data = crypto.randomBytes(3000);
  fs.writeFileSync(file, data);
  const secret = crypto.randomBytes(32).toString('base64url');
  // '--secret=<value>', not '--secret <value>': one secret in 64 starts with
  // '-', and argparse then reads it as an option ("expected one argument").
  const sent = py('paramant-sender.py', ['--key', KEY, '--relay', srv.base, '--file', file, '--secret=' + secret]);
  assert.equal(sent.status, 0, sent.stdout + sent.stderr);
  const m = (sent.stdout + sent.stderr).match(/--hash ([a-f0-9]{64})/);
  assert.ok(m, 'the sender prints the receive command with the hash: ' + sent.stdout + sent.stderr);
  const out = path.join(dir, 'out');
  fs.mkdirSync(out);
  const got = py('paramant-receiver.py', ['--key', KEY, '--relay', srv.base, '--hash', m[1], '--secret=' + secret, '--output', out]);
  assert.equal(got.status, 0, got.stdout + got.stderr);
  const files = fs.readdirSync(out);
  assert.equal(files.length, 1, 'one file received: ' + got.stdout + got.stderr);
  assert.ok(fs.readFileSync(path.join(out, files[0])).equals(data), 'the received bytes are the file that was sent');
  fs.rmSync(dir, { recursive: true, force: true });
  checks++;
});
