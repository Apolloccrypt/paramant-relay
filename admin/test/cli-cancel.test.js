'use strict';
// ADMIN-46-A: Ctrl+C in /admin/cli must stop the running command.
//
// The web CLI streams a command's output over SSE and the browser aborts the
// fetch on Ctrl+C. The server listened for that on req 'close'. Since Node 16 a
// request emits 'close' as soon as its body has been read, and express.json()
// reads it before the route runs, so the listener was attached to an event that
// had already happened: an aborted command kept running until the 60 s
// watchdog. Nothing in the whitelist ran long enough to show it, until "logs
// ... follow" (docker compose logs --follow) was added.
//
// This boots the real admin with a fake `docker compose` that streams forever
// and records its pid, aborts the stream after the first line, and checks that
// the process is gone (the handler's process group, not only the bash pid).
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

let rc = null; let srv = null; let SID = null; let TMP = null;
const leftovers = [];

before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); } catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": ${e.message}`);
  }
  rc = c;
  TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-cancel-'));
  // paramant-logs.sh first checks that docker exists, then runs $COMPOSE_CMD.
  fs.writeFileSync(path.join(TMP, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.writeFileSync(path.join(TMP, 'fake-compose'),
    '#!/usr/bin/env bash\n' +
    'echo $$ > "$COMPOSE_PIDFILE"\n' +
    'while :; do echo "log line $(date +%s%N)"; sleep 0.1; done\n', { mode: 0o755 });
  const relay = await stubRelay(defaultRelayState([]));
  srv = await boot({
    redisUrl: url, relay,
    env: {
      PATH: `${TMP}:${process.env.PATH}`,
      COMPOSE_CMD: path.join(TMP, 'fake-compose'),
      COMPOSE_PIDFILE: path.join(TMP, 'compose.pid'),
    },
  });
  SID = crypto.randomBytes(16).toString('hex');
  await rc.set(`paramant:admin:session:${SID}`, '1', { EX: 600 });
});

after(async () => {
  for (const pid of leftovers) { try { process.kill(pid, 'SIGKILL'); } catch (_) { /* gone */ } }
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } }
  if (TMP) fs.rmSync(TMP, { recursive: true, force: true });
});

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

test('logs follow streams, and aborting the stream ends the command', async () => {
  if (!srv) return;
  const ac = new AbortController();
  const r = await fetch(`${srv.base}/api/admin/cli/exec`, {
    method: 'POST',
    headers: { 'X-Session': SID, 'Content-Type': 'application/json', Origin: srv.base },
    body: JSON.stringify({ command: 'logs', args: { service: 'relay', tail: 5, follow: 'follow' } }),
    signal: ac.signal,
  });
  if (r.status !== 200) assert.fail(`exec answered ${r.status}: ${await r.text()}`);
  const reader = r.body.getReader();
  let seen = '';
  const t0 = Date.now();
  while (!/log line/.test(seen) && Date.now() - t0 < 10000) {
    const { value, done } = await reader.read();
    if (done) break;
    seen += Buffer.from(value).toString('utf8');
  }
  assert.match(seen, /log line/, 'the follow stream never produced a line: ' + seen.slice(0, 300));
  const pidFile = path.join(TMP, 'compose.pid');
  const pid = Number(fs.readFileSync(pidFile, 'utf8').trim());
  assert.ok(pid > 0);
  leftovers.push(pid);
  assert.ok(alive(pid), 'the command should still be running before the abort');

  ac.abort();
  const deadline = Date.now() + 3000;
  while (alive(pid) && Date.now() < deadline) await new Promise((res) => setTimeout(res, 50));
  assert.ok(!alive(pid), 'Ctrl+C left the command running (it would run until the 60 s watchdog)');
});

test('without follow, logs is still a one-shot tail', async () => {
  if (!srv) return;
  const { COMMANDS, validateArgs, buildArgv } = require('../lib/cli-commands');
  const v = validateArgs(COMMANDS.logs, { service: 'relay', tail: 5 });
  assert.ok(v.ok, v.error);
  assert.deepStrictEqual(buildArgv(COMMANDS.logs, v.values), ['relay', '5', 'no']);
  assert.ok(!validateArgs(COMMANDS.logs, { service: 'relay', follow: '-f' }).ok, 'follow only takes no|follow');
});
